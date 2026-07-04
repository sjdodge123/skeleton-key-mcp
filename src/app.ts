import { access } from "node:fs/promises";
import { BootstrapStore } from "./secrets/bootstrap-store.js";
import { VaultwardenClient } from "./secrets/vaultwarden.js";
import { TargetRegistry } from "./config/registry.js";
import { AuditLog } from "./audit/audit-log.js";
import { OAuthService } from "./oauth/oauth-service.js";
import { CredentialRequestStore } from "./web/credential-requests.js";
import { loadPublicUrl } from "./config/public-url.js";
import { hashBearer, loadBearerHash, saveBearerHash } from "./config/bearer-hash.js";
import { authenticator } from "otplib";
import { timingSafeEqual } from "node:crypto";
import { paths } from "./config/paths.js";

/**
 * Shared runtime state for the whole process: the encrypted bootstrap store, the
 * scoped Vaultwarden client, the target registry, and the audit log. Constructed
 * once at startup and passed to the MCP server and the web/wizard routes.
 */
export class AppState {
  private constructor(
    readonly store: BootstrapStore,
    readonly vault: VaultwardenClient,
    readonly registry: TargetRegistry,
    readonly audit: AuditLog,
    readonly oauth: OAuthService,
    readonly credentialRequests: CredentialRequestStore,
  ) {}

  static async create(): Promise<AppState> {
    const store = await BootstrapStore.open();
    const vault = new VaultwardenClient();
    const registry = await TargetRegistry.load();
    const audit = new AuditLog();
    const oauth = new OAuthService();
    const credentialRequests = new CredentialRequestStore();
    const app = new AppState(store, vault, registry, audit, oauth, credentialRequests);
    app.learnedPublicUrl = await loadPublicUrl();
    app.bearerHash = await loadBearerHash();
    return app;
  }

  /** SHA-256 of the MCP bearer token, so it's verifiable while locked. */
  private bearerHash: string | null = null;

  /**
   * Verify a presented static bearer token. Works while the store is unlocked
   * (compare the token itself) AND while locked (compare against the persisted
   * hash) — so a valid legacy bearer isn't 401'd after a restart. Timing-safe.
   */
  verifyBearer(token: string): boolean {
    if (!token) return false;
    if (!this.store.locked) {
      const expected = this.store.get().mcpBearerToken;
      return !!expected && safeEqualStr(token, expected);
    }
    return !!this.bearerHash && safeEqualStr(hashBearer(token), this.bearerHash);
  }

  /**
   * Ensure the persisted bearer hash matches the current token (backfills older
   * deployments and follows rotation). No-op while locked or if unset. Call after
   * any unlock / bearer generation.
   */
  async ensureBearerHash(): Promise<void> {
    if (this.store.locked) return;
    const token = this.store.get().mcpBearerToken;
    if (!token) return;
    const want = hashBearer(token);
    if (want !== this.bearerHash) {
      await saveBearerHash(want);
      this.bearerHash = want;
    }
  }

  /**
   * Common tail of every store-unlock path (boot key file, deprecated boot
   * passphrase, manual web-UI unlock): re-establish the saved Vaultwarden
   * session, refresh the offline cache best-effort, keep the bearer hash
   * current, and nudge live MCP sessions to re-list tools now the full set is
   * available.
   */
  async postUnlock(): Promise<void> {
    const s = this.store.get();
    if (s.bwServerUrl && s.bwClientId && s.bwClientSecret && s.bwMasterPassword) {
      await this.vault.reestablish({
        serverUrl: s.bwServerUrl,
        clientId: s.bwClientId,
        clientSecret: s.bwClientSecret,
        masterPassword: s.bwMasterPassword,
      });
      // Best-effort sync; safe to fail if Vaultwarden is unreachable (offline cache).
      await this.vault.sync().catch(() => {});
    }
    await this.ensureBearerHash();
    if (!this.locked) this.emitToolsChanged();
  }

  /** Persisted, auto-detected public base URL (set at boot; see server.ts).
   *  Overridden by SKELETON_KEY_PUBLIC_URL. */
  private learnedPublicUrl: string | null = null;

  /** Record the boot-detected public URL (already persisted by the caller). */
  setLearnedPublicUrl(url: string | null): void {
    this.learnedPublicUrl = url;
  }

  /** True once the first-run wizard has completed. Until then the MCP endpoint
   *  stays locked and the web UI serves the wizard. */
  async isSetupComplete(): Promise<boolean> {
    try {
      await access(paths.setupComplete);
      return true;
    } catch {
      return false;
    }
  }

  /** True while credentials are unavailable (fresh boot / container restart)
   *  until the admin unlocks via the web UI. Tools degrade rather than the
   *  endpoint going dark — see `mcpAuth` and the CallTool locked gate. */
  get locked(): boolean {
    return this.store.locked || !this.vault.unlocked;
  }

  /**
   * The pinned public base URL (SKELETON_KEY_PUBLIC_URL) with no trailing slash,
   * or null if unset. This is the ONLY origin we put in user-facing links that
   * ask for a secret (unlock guidance, credential-request links): deriving it
   * from the request `Host` header would let an attacker steer the admin to a
   * forged origin to type their master passphrase or a target credential.
   */
  publicUrl(): string | null {
    const configured = process.env.SKELETON_KEY_PUBLIC_URL;
    if (configured) return configured.replace(/\/$/, "");
    return this.learnedPublicUrl;
  }

  /** Admin web UI URL for "go unlock" guidance, or null if not configured. */
  unlockUrl(): string | null {
    return this.publicUrl();
  }

  /** Single source of truth for the "vault is locked, here's how to fix it"
   *  message shown across MCP tool errors, get_started, and the auth layer. */
  unlockGuidance(): string {
    const url = this.unlockUrl();
    const where = url ? `${url}/` : "the Skeleton Key admin web UI (same host and port as this MCP endpoint)";
    return (
      "🔒 Skeleton Key is locked — the credential vault re-locks whenever the container restarts.\n" +
      `Have the user open ${where} in a browser and enter the master passphrase to unlock, then retry.`
    );
  }

  private readonly toolChangeListeners = new Set<() => void>();

  /** Subscribe to tool-set changes (e.g. a target registered). Returns an unsubscribe fn. */
  onToolsChanged(cb: () => void): () => void {
    this.toolChangeListeners.add(cb);
    return () => this.toolChangeListeners.delete(cb);
  }

  /** Notify subscribers that the available tool set changed, so live MCP sessions can refresh. */
  emitToolsChanged(): void {
    for (const cb of this.toolChangeListeners) cb();
  }

  /**
   * Single source of truth for admin TOTP verification. Fails closed if the
   * store is locked (no secret available). Used by every 2FA-gated action.
   */
  verifyTotp(token: string): boolean {
    const secret = this.store.locked ? undefined : this.store.get().totpSecret;
    if (!secret || !token) return false;
    return authenticator.verify({ token: token.trim(), secret });
  }

  /** Resolve a target's credential from the vault (offline-cache backed). */
  async credentialFor(credentialRef: string) {
    if (!this.vault.unlocked) {
      throw new Error(this.unlockGuidance());
    }
    return this.vault.getCredential(credentialRef);
  }
}

/** Constant-time string compare (avoids leaking length/prefix via timing). */
function safeEqualStr(a: string, b: string): boolean {
  const ab = Buffer.from(a);
  const bb = Buffer.from(b);
  if (ab.length !== bb.length) return false;
  return timingSafeEqual(ab, bb);
}
