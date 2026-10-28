import { access } from "node:fs/promises";
import { BootstrapStore } from "./secrets/bootstrap-store.js";
import { VaultwardenClient, type GetCredentialOptions } from "./secrets/vaultwarden.js";
import { TargetRegistry } from "./config/registry.js";
import { AuditLog } from "./audit/audit-log.js";
import { OAuthService } from "./oauth/oauth-service.js";
import { CredentialRequestStore } from "./web/credential-requests.js";
import { loadPublicUrl } from "./config/public-url.js";
import { hashBearer, loadBearerHash, saveBearerHash } from "./config/bearer-hash.js";
import { verifyTotpCode } from "./lib/totp.js";
import { AttemptLimiter, PASSPHRASE_LIMITS, RefusalCoalescer, TOTP_LIMITS, type Lockout } from "./lib/attempt-limiter.js";
import { timingSafeEqual } from "node:crypto";
import { paths } from "./config/paths.js";
import { fingerprintValue } from "./lib/fingerprint.js";

/** Outcome of a TOTP check. `retryAfterSeconds` is set when the caller is
 *  locked out (send 429 + Retry-After); a plain failure is a wrong code. */
export type TotpCheck = { ok: true } | { ok: false; retryAfterSeconds?: number };

/** Who is presenting a code or passphrase, and where: the limiter's client
 *  key (see `clientKey`) and the route pattern, for the audit log. */
export interface ClientAttempt {
  client: string;
  via: string;
}

/** Refusals during a lockout are coalesced to one audit entry per window, so a
 *  flood against a locked gate can't bloat audit.sqlite (cf. server.ts). */
const REFUSAL_LOG_THROTTLE_MS = 60_000;

/** One attempt-limited secret: its limiter, its refusal log, and its names. */
interface AuthGate {
  /** Audit tool prefix: `auth.<name>_failed` / `_lockout` / `_refused`. */
  name: "totp" | "passphrase";
  /** For messages: "authenticator code" / "master passphrase". */
  what: string;
  limiter: AttemptLimiter;
  refusals: RefusalCoalescer;
}

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

  /** Why the last vault (re)connect failed — the sanitized `bw` message — or
   *  null once the vault is up. Surfaced by `/api/status` (URLs redacted) so
   *  the admin page can explain a store that unlocked while the vault did not,
   *  instead of leaving the only clue in the container log. */
  vaultError: string | null = null;

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
      try {
        await this.vault.reestablish({
          serverUrl: s.bwServerUrl,
          clientId: s.bwClientId,
          clientSecret: s.bwClientSecret,
          masterPassword: s.bwMasterPassword,
        });
      } catch (err) {
        this.vaultError = err instanceof Error ? err.message : String(err);
        throw err;
      }
      this.vaultError = null;
      // Best-effort sync; safe to fail if Vaultwarden is unreachable (offline cache).
      await this.vault.sync().catch(() => {});
    }
    await this.ensureBearerHash();
    if (!this.locked) this.emitToolsChanged();
  }

  /**
   * Re-point the Vaultwarden client at a different server URL after setup —
   * the repair when the stored URL stops being usable (the Bitwarden CLI now
   * refuses plain http://). Logs the CLI out so `reestablish()` runs `config
   * server` + the API-key login fresh, re-syncs the offline cache, and persists
   * the URL only once the vault is actually unlocked on it (fails closed: a bad
   * URL leaves the stored one untouched). The service-account credentials are
   * the stored ones — nothing secret enters or leaves through this path.
   */
  async changeVaultServer(serverUrl: string): Promise<void> {
    if (this.store.locked) throw new Error("Unlock the store first.");
    const s = this.store.get();
    if (!s.bwClientId || !s.bwClientSecret || !s.bwMasterPassword) {
      throw new Error("The vault has not been connected yet — run the setup wizard.");
    }
    await this.vault.logout();
    try {
      await this.vault.reestablish({
        serverUrl,
        clientId: s.bwClientId,
        clientSecret: s.bwClientSecret,
        masterPassword: s.bwMasterPassword,
      });
      await this.vault.sync();
    } catch (err) {
      this.vaultError = err instanceof Error ? err.message : String(err);
      throw err;
    }
    await this.store.update({ bwServerUrl: serverUrl });
    this.vaultError = null;
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

  /** Brute-force limiter in front of every TOTP verification (in-memory; see TOTP_LIMITS). */
  readonly totpLimiter = new AttemptLimiter(TOTP_LIMITS);
  /** Same for the master passphrase on `/api/store/unlock` (its own budget). */
  readonly passphraseLimiter = new AttemptLimiter(PASSPHRASE_LIMITS);
  private readonly totpGate: AuthGate = { name: "totp", what: "authenticator code", limiter: this.totpLimiter, refusals: new RefusalCoalescer(REFUSAL_LOG_THROTTLE_MS) };
  private readonly passphraseGate: AuthGate = { name: "passphrase", what: "master passphrase", limiter: this.passphraseLimiter, refusals: new RefusalCoalescer(REFUSAL_LOG_THROTTLE_MS) };
  /** One argon2 derivation at a time: a parallel burst can neither outrun the
   *  failure counter nor pin the CPU. */
  private passphraseInFlight = false;

  /**
   * Seconds until `attempt.client` may present a code again, or null when it
   * may now. Never looks at a code. Gates check this before the handler runs;
   * `checkTotp` checks it again before evaluating.
   */
  totpLockout(attempt: ClientAttempt): number | null {
    return this.lockoutOf(this.totpGate, attempt);
  }

  /** `totpLockout` for the master passphrase. */
  passphraseLockout(attempt: ClientAttempt): number | null {
    return this.lockoutOf(this.passphraseGate, attempt);
  }

  /**
   * Single source of truth for admin TOTP verification. Used by every
   * 2FA-gated action. While the client (or everyone) is locked out the code is
   * refused WITHOUT being evaluated, so a lockout reveals nothing about it.
   * Fails closed if the store is locked (no secret available); that, and an
   * empty code, are refused without counting — there was nothing to guess.
   */
  checkTotp(token: string, attempt: ClientAttempt): TotpCheck {
    const retryAfterSeconds = this.totpLockout(attempt);
    if (retryAfterSeconds !== null) return { ok: false, retryAfterSeconds };
    const secret = this.store.locked ? undefined : this.store.get().totpSecret;
    const code = token ? token.trim() : "";
    if (!secret || !code) return { ok: false };
    if (verifyTotpCode(code, secret)) {
      this.totpLimiter.succeed(attempt.client);
      return { ok: true };
    }
    const locked = this.recordFailure(this.totpGate, attempt);
    return locked === null ? { ok: false } : { ok: false, retryAfterSeconds: locked };
  }

  /**
   * Unlock the bootstrap store with the master passphrase, behind its own
   * attempt limiter. Returns a refusal when locked out (the passphrase is not
   * evaluated) or while another unlock is still deriving (`busy`), and null
   * once the store is open. A failed unlock is counted, then rethrown, unless
   * it started a lockout, which is returned as a refusal instead.
   */
  async unlockWithPassphrase(passphrase: string, attempt: ClientAttempt): Promise<{ retryAfterSeconds: number; busy?: true } | null> {
    const retryAfterSeconds = this.passphraseLockout(attempt);
    if (retryAfterSeconds !== null) return { retryAfterSeconds };
    if (this.passphraseInFlight) return { retryAfterSeconds: 1, busy: true };
    this.passphraseInFlight = true;
    try {
      await this.store.unlock(passphrase);
    } catch (err) {
      const locked = this.recordFailure(this.passphraseGate, attempt);
      if (locked !== null) return { retryAfterSeconds: locked };
      throw err;
    } finally {
      this.passphraseInFlight = false;
    }
    this.passphraseLimiter.succeed(attempt.client);
    return null;
  }

  private lockoutOf(gate: AuthGate, attempt: ClientAttempt): number | null {
    const refusal = gate.limiter.blocked(attempt.client);
    if (!refusal) return null;
    const seconds = Math.max(1, Math.ceil(refusal.retryAfterMs / 1000));
    const due = gate.refusals.note(attempt.client);
    if (due) {
      const scope = refusal.scope === "global" ? "global" : "per-client";
      this.auditAuth(
        `auth.${gate.name}_refused`,
        attempt,
        `${due.count} attempt(s) refused during a ${scope} ${gate.name} lockout since the last entry, ` +
          `from ${due.clients}; latest via ${attempt.via}, ${seconds} s left`,
      );
    }
    return seconds;
  }

  /** Count a wrong secret; audit it and any lockout it starts. Returns the
   *  lockout's length in seconds when one started, else null. */
  private recordFailure(gate: AuthGate, attempt: ClientAttempt): number | null {
    const lockouts = gate.limiter.fail(attempt.client);
    this.auditAuth(`auth.${gate.name}_failed`, attempt, `wrong ${gate.what} via ${attempt.via}`);
    for (const l of lockouts) {
      this.auditAuth(`auth.${gate.name}_lockout`, attempt, lockoutDetail(gate, l, attempt));
      // Also to stdout, so `container_logs` names the address even while the
      // lockout keeps the admin out of the audit view.
      const until = new Date(Date.now() + l.durationMs).toISOString();
      console.warn(`[skeleton-key] ${gate.name.toUpperCase()} lockout: ${l.scope} until ${until}, last client ${attempt.client}`);
    }
    if (lockouts.length === 0) return null;
    return Math.ceil(Math.max(...lockouts.map((l) => l.durationMs)) / 1000);
  }

  /** Never carries the secret: `args` is digested, and a digest of a 6-digit
   *  code is trivially reversible, so it stays empty. */
  private auditAuth(tool: string, attempt: ClientAttempt, detail: string): void {
    try {
      this.audit.record({ ts: new Date().toISOString(), tool, target: attempt.client, tier: "auth", args: {}, status: "denied", detail });
    } catch {
      /* audit is best-effort; the refusal stands either way */
    }
  }

  /**
   * Keyed fingerprint (`len=<n> fp=<8 hex>`) of a secret value, for comparing
   * a vault field against what a stack was deployed with — never the value
   * itself. See `src/lib/fingerprint.ts`.
   */
  fingerprint(value: string): Promise<string> {
    return fingerprintValue(this, value);
  }

  /** Resolve a target's credential from the vault (offline-cache backed).
   *  `opts.fresh` syncs first (bounded, best-effort) for deploy-time reads;
   *  `opts.byId` treats `credentialRef` as a pinned item id. */
  async credentialFor(credentialRef: string, opts?: GetCredentialOptions) {
    if (!this.vault.unlocked) {
      throw new Error(this.unlockGuidance());
    }
    return this.vault.getCredential(credentialRef, opts);
  }
}

function lockoutDetail(gate: AuthGate, l: Lockout, attempt: ClientAttempt): string {
  const mins = Math.round(l.durationMs / 60_000);
  const who = l.scope === "global" ? "ALL clients" : `client ${attempt.client}`;
  return `${who} locked out of the ${gate.what} for ${mins} min after ${l.failures} wrong attempts (last via ${attempt.via})`;
}

/** Constant-time string compare (avoids leaking length/prefix via timing). */
function safeEqualStr(a: string, b: string): boolean {
  const ab = Buffer.from(a);
  const bb = Buffer.from(b);
  if (ab.length !== bb.length) return false;
  return timingSafeEqual(ab, bb);
}
