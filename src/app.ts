import { access } from "node:fs/promises";
import { BootstrapStore } from "./secrets/bootstrap-store.js";
import { VaultwardenClient } from "./secrets/vaultwarden.js";
import { TargetRegistry } from "./config/registry.js";
import { AuditLog } from "./audit/audit-log.js";
import { OAuthService } from "./oauth/oauth-service.js";
import { authenticator } from "otplib";
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
  ) {}

  static async create(): Promise<AppState> {
    const store = await BootstrapStore.open();
    const vault = new VaultwardenClient();
    const registry = await TargetRegistry.load();
    const audit = new AuditLog();
    const oauth = new OAuthService();
    return new AppState(store, vault, registry, audit, oauth);
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

  private lastSeenOrigin: string | null = null;

  /** Remember the origin a client actually reached us on, as a fallback for
   *  building user-facing links when SKELETON_KEY_PUBLIC_URL isn't set. */
  notePublicOrigin(origin: string): void {
    this.lastSeenOrigin = origin;
  }

  /** Admin web UI URL for "go unlock" guidance, or null if we can't know it. */
  unlockUrl(): string | null {
    const configured = process.env.SKELETON_KEY_PUBLIC_URL;
    if (configured) return configured.replace(/\/$/, "");
    return this.lastSeenOrigin;
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
      const url = this.unlockUrl();
      throw new Error(
        `Vault is locked; cannot resolve credentials. Unlock via the admin web UI${url ? ` at ${url}/` : ""}.`,
      );
    }
    return this.vault.getCredential(credentialRef);
  }
}
