import { access } from "node:fs/promises";
import { BootstrapStore } from "./secrets/bootstrap-store.js";
import { VaultwardenClient } from "./secrets/vaultwarden.js";
import { TargetRegistry } from "./config/registry.js";
import { AuditLog } from "./audit/audit-log.js";
import { OAuthService } from "./oauth/oauth-service.js";
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

  /** Resolve a target's credential from the vault (offline-cache backed). */
  async credentialFor(credentialRef: string) {
    if (!this.vault.unlocked) {
      throw new Error("Vault is locked; cannot resolve credentials.");
    }
    return this.vault.getCredential(credentialRef);
  }
}
