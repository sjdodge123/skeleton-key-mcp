import { execFile } from "node:child_process";
import { mkdir } from "node:fs/promises";
import { promisify } from "node:util";
import type { Credential } from "./types.js";
import { paths } from "../config/paths.js";

const execFileAsync = promisify(execFile);

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
    return {
      ...process.env,
      BITWARDENCLI_APPDATA_DIR: this.appDataDir,
      ...extra,
    };
  }

  private async run(args: string[], extraEnv: Record<string, string> = {}): Promise<string> {
    const { stdout } = await execFileAsync("bw", args, {
      env: this.env(extraEnv),
      maxBuffer: 16 * 1024 * 1024,
    });
    return stdout.trim();
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

  /** Refresh the local cache from the server. Requires connectivity. */
  async sync(): Promise<void> {
    this.assertUnlocked();
    await this.run(["sync", "--session", this.session!]);
  }

  lock(): void {
    this.session = null;
  }

  private assertUnlocked(): void {
    if (!this.session) throw new Error("Vaultwarden client is locked; unlock first.");
  }

  async listOrganizations(): Promise<{ id: string; name: string }[]> {
    this.assertUnlocked();
    const out = await this.run(["list", "organizations", "--session", this.session!]);
    return JSON.parse(out) as { id: string; name: string }[];
  }

  async listCollections(): Promise<{ id: string; name: string; organizationId: string }[]> {
    this.assertUnlocked();
    const out = await this.run(["list", "collections", "--session", this.session!]);
    return JSON.parse(out) as { id: string; name: string; organizationId: string }[];
  }

  /** Resolve the org + collection ids Skeleton Key writes new items into. */
  async resolveCollection(name?: string): Promise<{ collectionId: string; organizationId: string; name: string }> {
    const cols = await this.listCollections();
    const col = name ? cols.find((c) => c.name === name) : cols[0];
    if (!col) {
      throw new Error(
        name
          ? `Collection "${name}" not found in the scoped vault.`
          : "No collection is available to write to.",
      );
    }
    return { collectionId: col.id, organizationId: col.organizationId, name: col.name };
  }

  /**
   * Create a Login item in the scoped collection. `fields` become custom fields;
   * mark secrets (private keys, tokens) hidden. Requires connectivity (writing a
   * new secret to the server); the local cache is refreshed via sync afterwards.
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
    const { collectionId, organizationId } = await this.resolveCollection(input.collectionName);
    const item = buildLoginItemJson({ ...input, organizationId, collectionId });
    const encoded = Buffer.from(JSON.stringify(item)).toString("base64");
    await this.run(["create", "item", encoded, "--session", this.session!]);
    await this.sync();
    return { name: input.name };
  }

  async listItemNames(): Promise<string[]> {
    this.assertUnlocked();
    const out = await this.run(["list", "items", "--session", this.session!]);
    const items = JSON.parse(out) as BwItem[];
    return items.map((i) => i.name);
  }

  /** Fetch one item by name and map it to a connector-friendly Credential. */
  async getCredential(ref: string): Promise<Credential> {
    this.assertUnlocked();
    const out = await this.run(["get", "item", ref, "--session", this.session!]);
    const item = JSON.parse(out) as BwItem;
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
