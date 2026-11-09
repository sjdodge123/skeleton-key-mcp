import type { Credential } from "./types.js";
import type { NewSecretItem, ReadOptions, SecretIdentity, SecretItemPatch, SecretsProvider } from "./provider.js";
import { describeVaultFailure, type VaultwardenClient } from "./vaultwarden.js";

/**
 * `SecretsProvider` backed by a scoped Vaultwarden service account, through
 * the `bw` CLI wrapper in `./vaultwarden.ts`. A thin adapter: every call goes
 * straight to the client (looked up per call, so behaviour — including id
 * pinning, trashed-item exclusion, the offline cache, `fresh` re-sync and
 * error sanitizing — is exactly the client's).
 *
 * How it meets the provider security contract (`./provider.ts`):
 *
 * 1. Scoping — the service account is a member of ONE organization holding
 *    ONE collection. Bitwarden encrypts each org under its own key, handed only
 *    to its members, so the account never holds the operator's personal user
 *    key and cannot decrypt personal items: a cryptographic boundary, not an
 *    ACL. The setup wizard checks it (`src/setup/verify.ts`); writes go to the
 *    configured collection only (`collectionName`, never a caller argument).
 * 2. Values in memory only — the `bw` session travels in `BW_SESSION` (never
 *    argv), create/edit payloads go over stdin, and `bw` failures are reduced
 *    to a first-line `VaultCommandError` that never embeds argv.
 * 3. `describeFailure` is `describeVaultFailure`: a fixed class summary, never
 *    the raw stderr line.
 * 4. `resolveItem` refuses ambiguity; trashed items are dropped from every
 *    candidate set; `resolveById` matches the id only.
 * 5. No method takes a collection: writes go to `collectionName`, which the
 *    adapter applies last so nothing a caller spreads in can override it.
 * 6. Offline: reads are served from the `bw` CLI's local encrypted cache, so a
 *    Vaultwarden outage degrades to last-known-good values; `fresh` reads try
 *    a sync bounded by `FRESH_SYNC_TIMEOUT_MS` first. Writes need the server.
 *
 * Connection lifecycle (server URL, API-key login, unlock, logout) stays on
 * the concrete client: it is driven by the Vaultwarden setup wizard and the
 * store-unlock path in `AppState`, not by credential consumers.
 */
export class VaultwardenSecretsProvider implements SecretsProvider {
  readonly kind = "vaultwarden";
  readonly label = "Vaultwarden";

  constructor(
    private readonly client: VaultwardenClient,
    /** The scoped collection writes land in — read at call time from the
     *  bootstrap store, so a reconfigured collection takes effect at once. */
    private readonly collectionName: () => string | undefined = () => undefined,
  ) {}

  get ready(): boolean {
    return this.client.unlocked;
  }

  get(ref: string, opts: ReadOptions = {}): Promise<Credential> {
    return this.client.getCredential(ref, { fresh: opts.fresh });
  }

  resolveById(id: string, opts: ReadOptions = {}): Promise<Credential> {
    return this.client.getCredential(id, { fresh: opts.fresh, byId: true });
  }

  resolveRef(ref: string): Promise<SecretIdentity> {
    return this.client.resolveRef(ref);
  }

  list(): Promise<string[]> {
    return this.client.listItemNames();
  }

  create(item: NewSecretItem): Promise<{ name: string }> {
    return this.client.createLoginItem({ ...item, collectionName: this.collectionName() });
  }

  update(ref: string, patch: SecretItemPatch): Promise<SecretIdentity> {
    return this.client.updateLoginItem(ref, patch);
  }

  delete(ref: string): Promise<{ name: string }> {
    return this.client.deleteItem(ref);
  }

  sync(): Promise<void> {
    return this.client.sync();
  }

  describeFailure(err: unknown): string {
    return describeVaultFailure(err);
  }
}
