import { execFile, spawn } from "node:child_process";
import { mkdir } from "node:fs/promises";
import { promisify } from "node:util";
import type { Credential } from "./types.js";
import { paths } from "../config/paths.js";

const execFileAsync = promisify(execFile);

/** Bitwarden item ids are UUIDs; used to route id-shaped refs to a direct fetch. */
const UUID_RE = /^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$/i;

/**
 * Reduce a `bw` failure to a safe, first-line message. We never surface the
 * original execFile error (its `.message` embeds the full argv, which for some
 * commands contains base64 secret payloads and the session key) — that would
 * leak secrets into the audit log and tool output.
 */
function sanitizeBwError(subcommand: string, err: unknown): Error {
  const stderr = (err as { stderr?: unknown })?.stderr;
  const first = typeof stderr === "string" ? stderr.trim().split("\n")[0] : "";
  return new Error(`bw ${subcommand} failed${first ? `: ${first}` : ""}`);
}

export interface BwStatus {
  status: "unauthenticated" | "locked" | "unlocked";
  serverUrl?: string;
  userEmail?: string;
}

interface BwItem {
  id: string;
  name: string;
  login?: {
    username?: string;
    password?: string;
    uris?: { uri: string }[];
  };
  fields?: { name: string; value: string }[];
  notes?: string;
}

/**
 * Wraps the Bitwarden `bw` CLI against a scoped Vaultwarden service account.
 *
 * Reads (`get`/`list`) are served from the CLI's local *encrypted offline cache*
 * (BITWARDENCLI_APPDATA_DIR), so a Vaultwarden outage does not lock Skeleton Key
 * out — only `sync` contacts the server. The service account is a member of a
 * single org/collection, so it is cryptographically unable to read the user's
 * personal vault.
 */
export class VaultwardenClient {
  private session: string | null = null;

  constructor(private readonly appDataDir: string = paths.bwCacheDir) {}

  get unlocked(): boolean {
    return this.session !== null;
  }

  private env(extra: Record<string, string> = {}): NodeJS.ProcessEnv {
    const env: NodeJS.ProcessEnv = {
      ...process.env,
      BITWARDENCLI_APPDATA_DIR: this.appDataDir,
      ...extra,
    };
    // Pass the session via env, never as an argv `--session` flag, so the
    // long-lived session key never appears in argv / `ps` / error messages.
    if (this.session) env.BW_SESSION = this.session;
    return env;
  }

  private async run(args: string[], extraEnv: Record<string, string> = {}): Promise<string> {
    try {
      const { stdout } = await execFileAsync("bw", args, {
        env: this.env(extraEnv),
        maxBuffer: 16 * 1024 * 1024,
      });
      return stdout.trim();
    } catch (err) {
      throw sanitizeBwError(args[0] ?? "", err);
    }
  }

  /**
   * Run a `bw` command feeding `input` on stdin instead of argv — used for
   * `create item` so the base64 secret payload never lands in the argument list.
   */
  private runWithStdin(args: string[], input: string): Promise<string> {
    return new Promise((resolve, reject) => {
      const child = spawn("bw", args, { env: this.env() });
      let stdout = "";
      let stderr = "";
      child.stdout.on("data", (d) => (stdout += d));
      child.stderr.on("data", (d) => (stderr += d));
      child.on("error", () => reject(new Error(`bw ${args[0] ?? ""} failed to start`)));
      child.on("close", (code) => {
        if (code === 0) resolve(stdout.trim());
        else reject(sanitizeBwError(args[0] ?? "", { stderr }));
      });
      child.stdin.on("error", () => {}); // ignore EPIPE if bw exits early
      child.stdin.end(input);
    });
  }

  async ensureAppDataDir(): Promise<void> {
    await mkdir(this.appDataDir, { recursive: true });
  }

  async status(): Promise<BwStatus> {
    try {
      const out = await this.run(["status"]);
      return JSON.parse(out) as BwStatus;
    } catch {
      return { status: "unauthenticated" };
    }
  }

  async setServer(url: string): Promise<void> {
    await this.ensureAppDataDir();
    await this.run(["config", "server", url]);
  }

  /** Non-interactive login using the service account's personal API key. */
  async loginApiKey(clientId: string, clientSecret: string): Promise<void> {
    await this.run(["login", "--apikey"], {
      BW_CLIENTID: clientId,
      BW_CLIENTSECRET: clientSecret,
    });
  }

  /** Unlock with the service-account master password; caches the session key. */
  async unlock(masterPassword: string): Promise<void> {
    const session = await this.run(["unlock", "--passwordenv", "BW_PASSWORD", "--raw"], {
      BW_PASSWORD: masterPassword,
    });
    if (!session) throw new Error("bw unlock returned an empty session key.");
    this.session = session;
  }

  /**
   * Bring the client to an unlocked state from whatever state `bw` is in. The
   * login/config state persists on disk across restarts, so after a container
   * restart `bw` is typically "logged in but locked" — in that case we must NOT
   * call `bw config server` (it errors with "Logout required...") or re-login;
   * we just unlock. We only set the server + log in when `bw` is unauthenticated
   * (fresh cache). Idempotent and safe to call on every boot/unlock.
   */
  async reestablish(cfg: { serverUrl: string; clientId: string; clientSecret: string; masterPassword: string }): Promise<void> {
    const st = await this.status();
    if (st.status === "unauthenticated") {
      await this.setServer(cfg.serverUrl);
      await this.loginApiKey(cfg.clientId, cfg.clientSecret);
    }
    await this.unlock(cfg.masterPassword);
  }

  /** Refresh the local cache from the server. Requires connectivity. */
  async sync(): Promise<void> {
    this.assertUnlocked();
    await this.run(["sync"]);
  }

  lock(): void {
    this.session = null;
  }

  private assertUnlocked(): void {
    if (!this.session) throw new Error("Vaultwarden client is locked; unlock first.");
  }

  async listOrganizations(): Promise<{ id: string; name: string }[]> {
    this.assertUnlocked();
    const out = await this.run(["list", "organizations"]);
    return JSON.parse(out) as { id: string; name: string }[];
  }

  async listCollections(): Promise<{ id: string; name: string; organizationId: string }[]> {
    this.assertUnlocked();
    const out = await this.run(["list", "collections"]);
    return JSON.parse(out) as { id: string; name: string; organizationId: string }[];
  }

  /**
   * Resolve the org + collection ids to write into. Requires an unambiguous
   * target: the named collection, or the single collection if the account only
   * has one. Refuses to guess when several exist so secrets never land in the
   * wrong (possibly broader) collection.
   */
  async resolveCollection(name?: string): Promise<{ collectionId: string; organizationId: string; name: string }> {
    const cols = await this.listCollections();
    if (name) {
      const col = cols.find((c) => c.name === name);
      if (!col) throw new Error(`Collection "${name}" not found in the scoped vault.`);
      return { collectionId: col.id, organizationId: col.organizationId, name: col.name };
    }
    if (cols.length === 0) throw new Error("No collection is available to write to.");
    if (cols.length > 1) {
      throw new Error(`Ambiguous target: ${cols.length} collections exist — specify which to write to.`);
    }
    const col = cols[0]!;
    return { collectionId: col.id, organizationId: col.organizationId, name: col.name };
  }

  /**
   * Create a Login item in the scoped collection. `fields` become custom fields;
   * mark secrets (private keys, tokens) hidden. Requires connectivity to write
   * the new secret; the payload is fed on stdin (never argv) so it can't leak
   * into `ps` or error messages.
   */
  async createLoginItem(input: {
    name: string;
    username?: string;
    password?: string;
    url?: string;
    notes?: string;
    fields?: { name: string; value: string; hidden?: boolean }[];
    collectionName?: string;
  }): Promise<{ name: string }> {
    this.assertUnlocked();
    // Names double as credentialRefs, which must resolve to exactly one item —
    // so refuse to create a second item with an existing name.
    const existing = await this.listItemNames();
    if (existing.includes(input.name)) {
      throw new Error(`A vault item named "${input.name}" already exists — pick a different name.`);
    }
    const { collectionId, organizationId } = await this.resolveCollection(input.collectionName);
    const item = buildLoginItemJson({ ...input, organizationId, collectionId });
    const encoded = Buffer.from(JSON.stringify(item)).toString("base64");
    await this.runWithStdin(["create", "item"], encoded);
    // The item is written server-side; refreshing the local cache is best-effort
    // so a transient sync failure doesn't make callers retry and duplicate it.
    await this.sync().catch(() => {});
    return { name: input.name };
  }

  private async listItems(search?: string): Promise<BwItem[]> {
    this.assertUnlocked();
    // `--search` bounds the returned set (and how many decrypted credentials we
    // materialize in memory) instead of serializing the whole collection.
    const args = search ? ["list", "items", "--search", search] : ["list", "items"];
    const out = await this.run(args);
    return JSON.parse(out) as BwItem[];
  }

  async listItemNames(): Promise<string[]> {
    return (await this.listItems()).map((i) => i.name);
  }

  /**
   * Resolve a credentialRef to its underlying item, preferring exact name over
   * id over case-insensitive over unique-substring (see `resolveItem`). A ref
   * shaped like a Bitwarden item id is fetched directly (bounded, exact) because
   * `bw list items --search` can't match by id. Otherwise the bounded `--search`
   * fetch is the fast path, with a full-list fallback for the rare miss. Throws
   * with a clear message when nothing / too much matches.
   */
  private async findItem(ref: string): Promise<BwItem> {
    this.assertUnlocked();
    // Name resolution first, on the bounded `--search` set, so an exact (or
    // substring) NAME match always wins over an id match — a ref that happens to
    // be UUID-shaped but is actually an item's name must resolve to that name.
    // `--search` matches names/notes by substring, so it surfaces every exact /
    // case-insensitive / substring name ref; there is no need to fall back to a
    // full `bw list items` (which would decrypt the entire scoped collection).
    const byName = resolveItem(await this.listItems(ref), ref);
    if (byName) return byName;
    // Not found by name: if the ref is a Bitwarden item id (UUID), fetch it
    // directly — `--search` can't match by id, and a single `bw get item` stays
    // bounded to one item.
    if (UUID_RE.test(ref)) {
      try {
        const byId = JSON.parse(await this.run(["get", "item", ref])) as BwItem;
        if (byId?.id === ref) return byId;
      } catch {
        /* not an id we hold */
      }
    }
    throw new Error(`No vault item named "${ref}" in the scoped collection.`);
  }

  /** Resolve a credentialRef to its canonical {id, name} without decrypting the
   *  secret — used to check dependents before deletion. */
  async resolveRef(ref: string): Promise<{ id: string; name: string }> {
    const item = await this.findItem(ref);
    return { id: item.id, name: item.name };
  }

  /** Delete a vault item by credentialRef. Requires connectivity (writes to the
   *  server); the local cache is refreshed best-effort afterwards. */
  async deleteItem(ref: string): Promise<{ name: string }> {
    const item = await this.findItem(ref);
    await this.run(["delete", "item", item.id]);
    await this.sync().catch(() => {});
    return { name: item.name };
  }

  async getCredential(ref: string): Promise<Credential> {
    const item = await this.findItem(ref);
    const fields: Record<string, string> = {};
    for (const f of item.fields ?? []) fields[f.name] = f.value;
    return {
      ref,
      username: item.login?.username,
      password: item.login?.password,
      // A private key / API token is commonly stored in notes or a custom field.
      secret: fields["private_key"] ?? fields["token"] ?? fields["api_key"] ?? item.notes ?? undefined,
      fields,
      uris: (item.login?.uris ?? []).map((u) => u.uri),
    };
  }
}

/**
 * Resolve a credentialRef against a candidate item set (exported for testing).
 * Priority: exact name → item id → unique case-insensitive name. Returns null
 * when nothing matches (so the caller can widen the candidate set and retry);
 * throws only on a genuinely ambiguous match so a ref never silently resolves to
 * the wrong secret.
 */
export function resolveItem<T extends { id: string; name: string }>(candidates: T[], ref: string): T | null {
  const exact = candidates.filter((i) => i.name === ref);
  if (exact.length === 1) return exact[0]!;
  if (exact.length > 1) {
    throw new Error(`${exact.length} vault items are named "${ref}" — rename them so the credentialRef is unique.`);
  }
  const byId = candidates.filter((i) => i.id === ref);
  if (byId.length) return byId[0]!; // ids are unique
  const ci = candidates.filter((i) => i.name.toLowerCase() === ref.toLowerCase());
  if (ci.length === 1) return ci[0]!;
  if (ci.length > 1) {
    throw new Error(`${ci.length} vault items match "${ref}" case-insensitively — rename them so the credentialRef is unique.`);
  }
  // Last resort: a UNIQUE substring match. This preserves the migration path of
  // the old `bw get item <ref>` (which substring-matched), so a pre-existing
  // ref like "pihole" still resolves to item "pihole-ssh" — but only when it's
  // unambiguous. Exact/id/case-insensitive above take priority, so this can't
  // reintroduce the "PiHole vs pihole-ssh" ambiguity that motivated the rewrite.
  const sub = candidates.filter((i) => i.name.toLowerCase().includes(ref.toLowerCase()));
  if (sub.length === 1) return sub[0]!;
  if (sub.length > 1) {
    throw new Error(`${sub.length} vault items match "${ref}" — rename them or use the exact name so the credentialRef is unique.`);
  }
  return null;
}

/** Pure builder for a Bitwarden Login item JSON (exported for testing). */
export function buildLoginItemJson(input: {
  name: string;
  username?: string;
  password?: string;
  url?: string;
  notes?: string;
  fields?: { name: string; value: string; hidden?: boolean }[];
  organizationId: string;
  collectionId: string;
}): Record<string, unknown> {
  return {
    organizationId: input.organizationId,
    collectionIds: [input.collectionId],
    folderId: null,
    type: 1, // login
    name: input.name,
    notes: input.notes ?? null,
    favorite: false,
    reprompt: 0,
    fields: (input.fields ?? []).map((f) => ({ name: f.name, value: f.value, type: f.hidden ? 1 : 0 })),
    login: {
      username: input.username ?? null,
      password: input.password ?? null,
      uris: input.url ? [{ match: null, uri: input.url }] : [],
    },
  };
}
