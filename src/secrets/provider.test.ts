import { describe, it, expect, vi } from "vitest";
import { existsSync, readFileSync } from "node:fs";
import { execFileSync } from "node:child_process";
import path from "node:path";
import type { AppState } from "../app.js";
import { buildGlobalTools } from "../mcp/builtin-tools.js";
import { CredentialRequestStore } from "../web/credential-requests.js";
import { UserFacingError } from "../lib/errors.js";
import { capabilitiesOf, hasCapability, requireCapability, type SecretsProvider } from "./provider.js";
import { VaultwardenSecretsProvider } from "./vaultwarden-provider.js";
import { VaultCommandError, VaultwardenClient } from "./vaultwarden.js";

vi.mock("../lib/ssh-keygen.js", () => ({ generateSshKey: vi.fn() }));
import { generateSshKey } from "../lib/ssh-keygen.js";

const ID = "11111111-2222-3333-4444-555555555555";
type Item = { id: string; name: string; login?: unknown; fields?: unknown[]; deletedDate?: string | null };

/** An unlocked client over a fixed item set, recording every `bw` argv. */
function fakeClient(items: Item[]): { client: VaultwardenClient; calls: string[][] } {
  const calls: string[][] = [];
  const client = new VaultwardenClient("/unused") as any;
  client.session = "test-session";
  client.run = async (args: string[]) => {
    calls.push(args);
    if (args[0] === "list" && args[1] === "items") {
      const i = args.indexOf("--search");
      return JSON.stringify(i >= 0 ? items.filter((x) => x.name.toLowerCase().includes(args[i + 1]!.toLowerCase())) : items);
    }
    if (args[0] === "get" && args[1] === "item") {
      const found = items.find((x) => x.id === args[2]);
      if (!found) throw new VaultCommandError("bw get failed: Not found.", "get", 1);
      return JSON.stringify(found);
    }
    return "";
  };
  return { client: client as VaultwardenClient, calls };
}

/** A provider with only the required surface: no create/update/delete/sync. */
function readOnlyProvider(): SecretsProvider {
  return {
    kind: "test-ro",
    label: "Read-only Test Vault",
    ready: true,
    get: vi.fn(async (ref: string) => ({ ref, fields: {}, uris: [] })),
    resolveById: vi.fn(async (id: string) => ({ ref: id, fields: {}, uris: [] })),
    resolveRef: vi.fn(async (ref: string) => ({ id: ref, name: ref })),
    list: vi.fn(async () => ["existing"]),
    describeFailure: () => "The test vault failed.",
  };
}

describe("VaultwardenSecretsProvider — delegates without changing behaviour", () => {
  it("get resolves by name and never serves a trashed duplicate", async () => {
    const { client } = fakeClient([
      { id: ID, name: "app-db", login: { password: "live" } },
      { id: "99999999-2222-3333-4444-555555555555", name: "app-db", login: { password: "stale" }, deletedDate: "2026-01-01" },
    ]);
    const p = new VaultwardenSecretsProvider(client);
    expect((await p.get("app-db")).password).toBe("live");
  });

  it("resolveById matches the id only — a name is not an id", async () => {
    const { client, calls } = fakeClient([{ id: ID, name: "app-db", login: { password: "v" } }]);
    const p = new VaultwardenSecretsProvider(client);
    expect((await p.resolveById(ID)).password).toBe("v");
    await expect(p.resolveById("app-db")).rejects.toThrow(/No vault item with id/);
    // The id path is one bounded `bw get item`, never a name search.
    expect(calls.some((c) => c[0] === "list")).toBe(false);
  });

  it("fresh syncs before the read; a plain read does not", async () => {
    const { client, calls } = fakeClient([{ id: ID, name: "app-db" }]);
    const p = new VaultwardenSecretsProvider(client);
    await p.get("app-db");
    expect(calls.some((c) => c[0] === "sync")).toBe(false);
    await p.get("app-db", { fresh: true });
    expect(calls.findIndex((c) => c[0] === "sync")).toBeLessThan(calls.findLastIndex((c) => c[0] === "list"));
    calls.length = 0;
    await p.resolveById(ID, { fresh: true });
    expect(calls.map((c) => c[0])).toEqual(["sync", "get"]);
  });

  it("list returns names only", async () => {
    const { client } = fakeClient([{ id: ID, name: "app-db", login: { password: "v" } }]);
    expect(await new VaultwardenSecretsProvider(client).list()).toEqual(["app-db"]);
  });

  it("create writes to the configured collection, and a caller can't smuggle another", async () => {
    const { client } = fakeClient([]);
    const spy = vi.spyOn(client, "createLoginItem").mockResolvedValue({ name: "n" });
    const p = new VaultwardenSecretsProvider(client, () => "Homelab");
    await p.create({ name: "n", password: "x", collectionName: "Personal" } as never);
    expect(spy).toHaveBeenCalledWith(expect.objectContaining({ name: "n", collectionName: "Homelab" }));
  });

  it("ready follows the client's unlock state", () => {
    const client = new VaultwardenClient("/unused");
    const p = new VaultwardenSecretsProvider(client);
    expect(p.ready).toBe(false);
    (client as any).session = "s";
    expect(p.ready).toBe(true);
    client.lock();
    expect(p.ready).toBe(false);
  });

  it("describeFailure is the fixed class summary, never the raw stderr", () => {
    const p = new VaultwardenSecretsProvider(new VaultwardenClient("/unused"));
    const text = p.describeFailure(new VaultCommandError("bw sync failed: upstream said hunter2", "sync", 1));
    expect(text).not.toContain("hunter2");
  });

  it("implements every optional capability", () => {
    expect(capabilitiesOf(new VaultwardenSecretsProvider(new VaultwardenClient("/unused")))).toEqual(["create", "update", "delete", "sync"]);
  });
});

describe("capability discovery", () => {
  it("a read-only provider reports no optional capabilities", () => {
    const p = readOnlyProvider();
    expect(capabilitiesOf(p)).toEqual([]);
    expect(hasCapability(p, "create")).toBe(false);
  });

  it("requireCapability refuses clearly, naming the provider and what it can't do", () => {
    const p = readOnlyProvider();
    let caught: unknown;
    try {
      requireCapability(p, "delete");
    } catch (e) {
      caught = e;
    }
    expect(caught).toBeInstanceOf(UserFacingError);
    expect((caught as UserFacingError).status).toBe(409);
    expect((caught as Error).message).toContain("Read-only Test Vault");
    expect((caught as Error).message).toContain("cannot delete vault items");
  });

  it("requireCapability returns the method bound to its provider", async () => {
    const { client } = fakeClient([]);
    const spy = vi.spyOn(client, "sync").mockResolvedValue();
    const sync = requireCapability(new VaultwardenSecretsProvider(client), "sync");
    await sync();
    expect(spy).toHaveBeenCalledOnce();
  });
});

describe("write tools on a read-only provider refuse before any side effect", () => {
  const byName = new Map(buildGlobalTools({} as AppState).map((t) => [t.name, t]));
  const appWith = (secrets: SecretsProvider, credentialRequests = new CredentialRequestStore()) =>
    ({ secrets, credentialRequests, publicUrl: () => "https://sk.example.com", registry: { list: () => [] } }) as unknown as AppState;

  it("vault_generate_ssh_key refuses without generating a key", async () => {
    await expect(byName.get("vault_generate_ssh_key")!.run({ name: "k", username: "u", host: "10.0.0.2" }, appWith(readOnlyProvider()))).rejects.toThrow(
      /cannot create vault items/,
    );
    expect(generateSshKey).not.toHaveBeenCalled();
  });

  it("vault_store_login refuses", async () => {
    await expect(byName.get("vault_store_login")!.run({ name: "k", password: "x" }, appWith(readOnlyProvider()))).rejects.toThrow(/cannot create vault items/);
  });

  it("vault_delete_credential refuses before resolving anything", async () => {
    const p = readOnlyProvider();
    await expect(byName.get("vault_delete_credential")!.run({ credentialRef: "existing" }, appWith(p))).rejects.toThrow(/cannot delete vault items/);
    expect(p.resolveRef).not.toHaveBeenCalled();
  });

  it("request_credential refuses before minting a link (create and overwrite)", async () => {
    const tool = byName.get("request_credential")!;
    const store = new CredentialRequestStore();
    const base = { name: "new-item", host: "10.0.0.2", reason: "onboarding", kind: "token" };
    await expect(tool.run(tool.inputSchema.parse(base), appWith(readOnlyProvider(), store))).rejects.toThrow(/cannot create vault items/);
    await expect(tool.run(tool.inputSchema.parse({ ...base, name: "existing", overwrite: true }), appWith(readOnlyProvider(), store))).rejects.toThrow(
      /cannot update vault items in place/,
    );
    expect(store.list()).toEqual([]);
  });

  it("read tools still work on a read-only provider", async () => {
    const out = await byName.get("vault_list_credentials")!.run({}, appWith(readOnlyProvider()));
    expect(out.isError).toBeFalsy();
    expect(out.text).toContain("existing");
  });
});

/**
 * Every credential consumer goes through `AppState.secrets`. The concrete
 * Vaultwarden client (`AppState.vault`, `secrets/vaultwarden.ts`) is reachable
 * only from the files that drive its connection lifecycle, listed here with
 * their reason. Maintainer-owned: this list may shrink, not grow, without review.
 */
const VAULTWARDEN_LIFECYCLE: Record<string, string> = {
  "src/app.ts": "constructs the client and the provider; re-establishes the session on unlock and vault-server repair",
  "src/setup/setup-service.ts": "the first-run wizard connects the Vaultwarden service account",
  "src/setup/verify.ts": "the wizard's org/collection scoping checks are Vaultwarden-specific",
  "src/web/routes.ts": "the setup and vault-server routes summarize Vaultwarden connection failures",
  "src/secrets/vaultwarden-provider.ts": "the adapter itself",
};

describe("secrets provider boundary", () => {
  const repo = path.resolve(import.meta.dirname, "..", "..");
  const files = execFileSync("git", ["ls-files", "src"], { cwd: repo, encoding: "utf8" })
    .split("\n")
    .filter((f) => f.endsWith(".ts") && !f.endsWith(".test.ts") && f !== "src/secrets/vaultwarden.ts");

  it("only lifecycle files reach the concrete Vaultwarden client", () => {
    const bad: string[] = [];
    for (const f of files) {
      if (VAULTWARDEN_LIFECYCLE[f]) continue;
      const text = readFileSync(path.join(repo, f), "utf8");
      if (/from\s+["'][./]*(?:secrets\/)?vaultwarden\.js["']/.test(text)) bad.push(`${f}: imports secrets/vaultwarden.js`);
      // `app.vault`, `a.vault`, `this.app.vault`, `{ vault } = this.app` — but not `app.vaultError`.
      if (/[\w)\]]\.vault\b(?!Error)/.test(text) || /\{\s*vault\b[^}]*\}\s*=/.test(text)) bad.push(`${f}: touches AppState.vault`);
    }
    expect(bad).toEqual([]);
  });

  it("the check isn't vacuous: the lifecycle owner does match it", () => {
    expect(/[\w)\]]\.vault\b(?!Error)/.test(readFileSync(path.join(repo, "src/app.ts"), "utf8"))).toBe(true);
  });

  it("the exception list names only files that exist", () => {
    for (const f of Object.keys(VAULTWARDEN_LIFECYCLE)) expect(existsSync(path.join(repo, f)), f).toBe(true);
  });
});
