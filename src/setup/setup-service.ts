import { randomBytes } from "node:crypto";
import { writeFile } from "node:fs/promises";
import { authenticator } from "otplib";
import QRCode from "qrcode";
import type { AppState } from "../app.js";
import { paths } from "../config/paths.js";
import { verifyScoping, type CheckResult } from "./verify.js";

export interface VaultConnectInput {
  serverUrl: string;
  clientId: string;
  clientSecret: string;
  masterPassword: string;
  collectionName?: string;
}

/**
 * Drives the first-run wizard's stateful steps against the AppState. Each method
 * maps to one wizard action; results are persisted into the bootstrap store so a
 * restart resumes where the user left off.
 */
export class SetupService {
  constructor(private readonly app: AppState) {}

  /** Step: connect + verify the scoped Vaultwarden service account. */
  async connectVault(input: VaultConnectInput): Promise<CheckResult[]> {
    const { vault, store } = this.app;
    await vault.reestablish({
      serverUrl: input.serverUrl,
      clientId: input.clientId,
      clientSecret: input.clientSecret,
      masterPassword: input.masterPassword,
    });
    await vault.sync();

    await store.update({
      bwServerUrl: input.serverUrl,
      bwClientId: input.clientId,
      bwClientSecret: input.clientSecret,
      bwMasterPassword: input.masterPassword,
      bwCollectionName: input.collectionName,
    });

    return verifyScoping(vault, input.collectionName);
  }

  /** Step: re-run the scoping/durability checks on demand. */
  async runChecks(): Promise<CheckResult[]> {
    return verifyScoping(this.app.vault, this.app.store.get().bwCollectionName);
  }

  /** Step: enroll TOTP; returns the otpauth URL + a QR data-URL for display. */
  async beginTotpEnrollment(accountLabel = "skeleton-key"): Promise<{ secret: string; otpauth: string; qrDataUrl: string }> {
    const secret = authenticator.generateSecret();
    const otpauth = authenticator.keyuri(accountLabel, "Skeleton Key", secret);
    const qrDataUrl = await QRCode.toDataURL(otpauth);
    // Stored provisionally; only committed once a code is verified.
    await this.app.store.update({ totpSecret: secret });
    return { secret, otpauth, qrDataUrl };
  }

  verifyTotp(token: string): boolean {
    return this.app.verifyTotp(token);
  }

  /** Step: generate (or rotate) the MCP bearer token clients must present. */
  async generateBearerToken(): Promise<string> {
    const token = randomBytes(32).toString("base64url");
    await this.app.store.update({ mcpBearerToken: token });
    return token;
  }

  /** Final step: mark setup complete, unlocking the MCP endpoint. */
  async complete(): Promise<void> {
    const s = this.app.store.get();
    const missing: string[] = [];
    if (!s.bwClientId) missing.push("Vaultwarden connection");
    if (!s.mcpBearerToken) missing.push("MCP bearer token");
    if (!s.totpSecret) missing.push("TOTP enrollment");
    if (missing.length > 0) {
      throw new Error(`Cannot complete setup; still missing: ${missing.join(", ")}.`);
    }
    await writeFile(paths.setupComplete, JSON.stringify({ completedAt: new Date().toISOString() }), {
      mode: 0o600,
    });
  }
}
