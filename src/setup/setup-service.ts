import { randomBytes } from "node:crypto";
import { writeFile } from "node:fs/promises";
import { generateTotpSecret, totpKeyUri } from "../lib/totp.js";
import QRCode from "qrcode";
import type { AppState, ClientAttempt, TotpCheck } from "../app.js";
import { paths } from "../config/paths.js";
import { UserFacingError } from "../lib/errors.js";
import type { CheckResult } from "../secrets/backend.js";

/**
 * Drives the first-run wizard's stateful steps against the AppState. Each method
 * maps to one wizard action; results are persisted into the bootstrap store so a
 * restart resumes where the user left off.
 */
export class SetupService {
  constructor(private readonly app: AppState) {}

  /**
   * Step: connect the selected secrets backend with the wizard's input (its
   * own schema — Vaultwarden's service account, the age identity, …), persist
   * the settings it returns only once it connected, and run its checks. Also
   * the post-setup connect for a newly selected provider.
   */
  async connectSecrets(input: unknown): Promise<CheckResult[]> {
    const { patch } = await this.app.secretsBackend.setup(input);
    await this.app.store.update(patch);
    await this.app.secretsConnected();
    return this.runChecks();
  }

  /** Step: re-run the backend's scoping/durability checks on demand. */
  async runChecks(): Promise<CheckResult[]> {
    return this.app.secretsBackend.verify(this.app.store.get());
  }

  /** Step: enroll TOTP; returns the otpauth URL + a QR data-URL for display. */
  async beginTotpEnrollment(accountLabel = "skeleton-key"): Promise<{ secret: string; otpauth: string; qrDataUrl: string }> {
    const secret = generateTotpSecret();
    const otpauth = totpKeyUri(accountLabel, "Skeleton Key", secret);
    const qrDataUrl = await QRCode.toDataURL(otpauth);
    // Stored provisionally; only committed once a code is verified.
    await this.app.store.update({ totpSecret: secret });
    return { secret, otpauth, qrDataUrl };
  }

  verifyTotp(token: string, attempt: ClientAttempt): TotpCheck {
    return this.app.checkTotp(token, attempt);
  }

  /** Step: generate (or rotate) the MCP bearer token clients must present. */
  async generateBearerToken(): Promise<string> {
    const token = randomBytes(32).toString("base64url");
    await this.app.store.update({ mcpBearerToken: token });
    // Persist the hash so the bearer stays verifiable while the vault is locked.
    await this.app.ensureBearerHash();
    return token;
  }

  /** Final step: mark setup complete, unlocking the MCP endpoint. */
  async complete(): Promise<void> {
    const s = this.app.store.get();
    const missing: string[] = [];
    if (!this.app.secretsBackend.configured(s)) missing.push(`${this.app.secrets.label} connection`);
    if (!s.mcpBearerToken) missing.push("MCP bearer token");
    if (!s.totpSecret) missing.push("TOTP enrollment");
    if (missing.length > 0) {
      throw new UserFacingError(`Cannot complete setup; still missing: ${missing.join(", ")}.`);
    }
    await writeFile(paths.setupComplete, JSON.stringify({ completedAt: new Date().toISOString() }), {
      mode: 0o600,
    });
  }
}
