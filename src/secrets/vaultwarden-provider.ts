import { z } from "zod";
import type { BootstrapSecrets, Credential } from "./types.js";
import type { NewSecretItem, ReadOptions, SecretIdentity, SecretItemPatch, SecretsProvider } from "./provider.js";
import type { BackendSetupResult, CheckResult, SecretsBackend } from "./backend.js";
import { describeVaultFailure, VaultCommandError, VaultwardenClient } from "./vaultwarden.js";
import { UserFacingError } from "../lib/errors.js";

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
 * Connection lifecycle (server URL, API-key login, unlock, logout) is
 * `VaultwardenBackend` below — the only code that holds the concrete client.
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

/** The Bitwarden CLI refuses plain-http servers, so every URL we accept is https. */
const httpsUrl = z
  .string()
  .url()
  .refine((u) => u.startsWith("https://"), { message: "The Bitwarden CLI only accepts https:// vault URLs." });

const SetupInput = z.object({
  serverUrl: httpsUrl,
  clientId: z.string().min(1),
  clientSecret: z.string().min(1),
  masterPassword: z.string().min(1),
  collectionName: z.string().optional(),
});

/**
 * The Vaultwarden connection lifecycle (`SecretsBackend`): the API-key login
 * and unlock from the bootstrap store, the wizard step that saves them, the
 * org/collection scoping checks, and the server-URL repair. It owns the one
 * `VaultwardenClient` in the process; nothing outside this file reaches it
 * (`src/secrets/provider.test.ts` enforces that).
 */
export class VaultwardenBackend implements SecretsBackend {
  readonly provider: VaultwardenSecretsProvider;

  constructor(
    /** Exposed for tests only (they stub `bw` calls on it); production code
     *  goes through `provider`. */
    readonly client: VaultwardenClient = new VaultwardenClient(),
    collectionName: () => string | undefined = () => undefined,
  ) {
    this.provider = new VaultwardenSecretsProvider(client, collectionName);
  }

  configured(s: Readonly<BootstrapSecrets>): boolean {
    return !!(s.bwServerUrl && s.bwClientId && s.bwClientSecret && s.bwMasterPassword);
  }

  async connect(s: Readonly<BootstrapSecrets>): Promise<void> {
    if (!this.configured(s)) {
      throw new UserFacingError("Vaultwarden hasn't been connected yet — run the setup step.", 409);
    }
    await this.client.reestablish({
      serverUrl: s.bwServerUrl!,
      clientId: s.bwClientId!,
      clientSecret: s.bwClientSecret!,
      masterPassword: s.bwMasterPassword!,
    });
    // Best-effort sync; safe to fail if Vaultwarden is unreachable (offline cache).
    await this.client.sync().catch(() => {});
  }

  async setup(input: unknown): Promise<BackendSetupResult> {
    const i = SetupInput.parse(input ?? {});
    try {
      await this.client.reestablish({
        serverUrl: i.serverUrl,
        clientId: i.clientId,
        clientSecret: i.clientSecret,
        masterPassword: i.masterPassword,
      });
      await this.client.sync();
    } catch (err) {
      // A `bw` failure gets its fixed summary as a 400; anything else is a
      // local fault the route logs as a 500.
      if (err instanceof VaultCommandError) throw new UserFacingError(describeVaultFailure(err));
      throw err;
    }
    return {
      patch: {
        bwServerUrl: i.serverUrl,
        bwClientId: i.clientId,
        bwClientSecret: i.clientSecret,
        bwMasterPassword: i.masterPassword,
        bwCollectionName: i.collectionName,
      },
    };
  }

  verify(s: Readonly<BootstrapSecrets>): Promise<CheckResult[]> {
    return verifyScoping(this.client, s.bwCollectionName);
  }

  /**
   * Re-point the client at a different server URL after setup — the repair
   * when the stored URL stops being usable (the Bitwarden CLI now refuses plain
   * http://). Logs the CLI out so `reestablish()` runs `config server` + the
   * API-key login fresh and re-syncs the offline cache; returns the URL to
   * persist only once the vault is unlocked on it. The service-account
   * credentials are the stored ones — nothing secret enters or leaves here.
   */
  async changeServer(serverUrl: string, s: Readonly<BootstrapSecrets>): Promise<BackendSetupResult> {
    if (!s.bwClientId || !s.bwClientSecret || !s.bwMasterPassword) {
      throw new UserFacingError("The vault has not been connected yet — run the setup wizard.", 409);
    }
    await this.client.logout();
    await this.client.reestablish({
      serverUrl,
      clientId: s.bwClientId,
      clientSecret: s.bwClientSecret,
      masterPassword: s.bwMasterPassword,
    });
    await this.client.sync();
    return { patch: { bwServerUrl: serverUrl } };
  }
}

/**
 * Automated safety checks run by the wizard after the vault connects. They prove
 * the two properties the whole security model rests on: the service account is
 * scoped to a single collection (can't read personal passwords), and reads keep
 * working while the vault is unlocked (durability).
 */
export async function verifyScoping(
  vault: VaultwardenClient,
  expectedCollection?: string,
): Promise<CheckResult[]> {
  const results: CheckResult[] = [];

  // 1. Exactly one organization membership.
  try {
    const orgs = await vault.listOrganizations();
    results.push({
      name: "Single organization membership",
      passed: orgs.length === 1,
      detail:
        orgs.length === 1
          ? `Member of exactly one org: "${orgs[0]!.name}".`
          : `Expected 1 org, found ${orgs.length}: ${orgs.map((o) => o.name).join(", ")}. ` +
            "The service account should belong ONLY to the Skeleton Key org.",
    });
  } catch (err) {
    results.push({ name: "Single organization membership", passed: false, detail: describeVaultFailure(err) });
  }

  // 2. Access limited to the expected collection.
  try {
    const collections = await vault.listCollections();
    const names = collections.map((c) => c.name);
    const scoped =
      collections.length === 1 &&
      (!expectedCollection || names[0] === expectedCollection);
    results.push({
      name: "Scoped to one collection",
      passed: scoped,
      detail: scoped
        ? `Access limited to a single collection: "${names[0]}".`
        : `Expected 1 collection${expectedCollection ? ` ("${expectedCollection}")` : ""}, ` +
          `found ${collections.length}: ${names.join(", ")}.`,
    });
  } catch (err) {
    results.push({ name: "Scoped to one collection", passed: false, detail: describeVaultFailure(err) });
  }

  // 3. At least one item is decryptable (proves the cache is usable).
  try {
    const names = await vault.listItemNames();
    results.push({
      name: "Credentials decryptable from cache",
      passed: names.length > 0,
      detail:
        names.length > 0
          ? `${names.length} credential item(s) available offline.`
          : "No items found. Add your homelab credentials to the collection.",
    });
  } catch (err) {
    // The (pre-setup, unauthenticated) wizard API gets the fixed summary,
    // never the raw `bw` or parser message.
    results.push({ name: "Credentials decryptable from cache", passed: false, detail: describeVaultFailure(err) });
  }

  return results;
}
