import { describe, it, expect } from "vitest";
import { buildLoginItemJson, resolveItem, VaultwardenClient } from "./vaultwarden.js";

type Item = { id: string; name: string; login?: any; fields?: any[]; notes?: string };

/**
 * An unlocked client backed by a fixed item set. `bw list items` is served from
 * that set, honoring `--search <term>` as a case-insensitive name-substring
 * filter (matching the real CLI) so the bounded fast path is exercised — and it
 * asserts getCredential never shells out to `bw get item`.
 */
function clientWithItems(items: Item[]): { client: VaultwardenClient; calls: string[][] } {
  const calls: string[][] = [];
  const client = new VaultwardenClient("/unused") as any;
  client.session = "test-session";
  client.run = async (args: string[]) => {
    calls.push(args);
    if (args[0] === "list" && args[1] === "items") {
      const searchIdx = args.indexOf("--search");
      const filtered =
        searchIdx >= 0
          ? items.filter((i) => i.name.toLowerCase().includes(args[searchIdx + 1]!.toLowerCase()))
          : items;
      return JSON.stringify(filtered);
    }
    if (args[0] === "get" && args[1] === "item") {
      // Mirror `bw get item <id>`: resolve by exact id, else error like the CLI.
      const found = items.find((i) => i.id === args[2]);
      if (!found) throw Object.assign(new Error("bw get failed"), { stderr: "Not found." });
      return JSON.stringify(found);
    }
    return ""; // delete/sync
  };
  return { client: client as VaultwardenClient, calls };
}

describe("getCredential", () => {
  it("resolves by exact name even when another item name overlaps", async () => {
    const { client } = clientWithItems([
      { id: "1", name: "PiHole", login: { username: "pihole", password: "pw" } },
      { id: "2", name: "pihole-ssh", login: { username: "pihole" }, fields: [{ name: "private_key", value: "KEY" }] },
    ]);
    const cred = await client.getCredential("PiHole");
    expect(cred.username).toBe("pihole");
    expect(cred.password).toBe("pw");
    const key = await client.getCredential("pihole-ssh");
    expect(key.secret).toBe("KEY");
  });

  it("resolves a case-mismatched ref when it is unambiguous (old bw behavior)", async () => {
    const { client } = clientWithItems([{ id: "1", name: "PiHole", login: { username: "pihole" } }]);
    const cred = await client.getCredential("pihole");
    expect(cred.username).toBe("pihole");
  });

  it("resolves a UUID-shaped ref with a bounded `bw get item` (no full-collection decrypt)", async () => {
    const uuid = "11111111-2222-3333-4444-555555555555";
    const { client, calls } = clientWithItems([
      { id: uuid, name: "nas1", login: { username: "root" } },
      { id: "0", name: "other" },
    ]);
    const cred = await client.getCredential(uuid);
    expect(cred.username).toBe("root");
    // Fast path used: get item by id, never a full `list items`.
    expect(calls).toContainEqual(["get", "item", uuid]);
    expect(calls.some((c) => c[0] === "list" && c.indexOf("--search") === -1)).toBe(false);
  });

  it("resolves a legacy substring-only ref when unambiguous (migration path)", async () => {
    const { client } = clientWithItems([{ id: "1", name: "pihole-ssh", login: { username: "pihole" } }]);
    const cred = await client.getCredential("pihole"); // 'pihole' is a substring of 'pihole-ssh'
    expect(cred.username).toBe("pihole");
  });

  it("still prefers an exact match over a substring sibling", async () => {
    const { client } = clientWithItems([
      { id: "1", name: "pihole", login: { username: "exact" } },
      { id: "2", name: "pihole-ssh", login: { username: "sibling" } },
    ]);
    const cred = await client.getCredential("pihole");
    expect(cred.username).toBe("exact");
  });

  it("fails clearly when nothing matches", async () => {
    const { client } = clientWithItems([{ id: "1", name: "pihole-ssh" }]);
    await expect(client.getCredential("nope")).rejects.toThrow(/No vault item named "nope"/);
  });

  it("fails clearly on true duplicate names", async () => {
    const { client } = clientWithItems([
      { id: "1", name: "nas" },
      { id: "2", name: "nas" },
    ]);
    await expect(client.getCredential("nas")).rejects.toThrow(/2 vault items are named "nas"/);
  });

  it("does NOT expose freeform notes as a secret, but does expose them as notes (#26)", async () => {
    const { client } = clientWithItems([
      { id: "1", name: "pw-login", login: { username: "u", password: "p" }, notes: "Stored via Skeleton Key credential hand-off. reason" },
    ]);
    const cred = await client.getCredential("pw-login");
    expect(cred.secret).toBeUndefined(); // notes must not become a token/key
    expect(cred.password).toBe("p");
    expect(cred.notes).toContain("hand-off");
  });

  it("uses an explicit token field as the secret (not notes)", async () => {
    const { client } = clientWithItems([{ id: "1", name: "tok", fields: [{ name: "token", value: "T" }], notes: "just a note" }]);
    const cred = await client.getCredential("tok");
    expect(cred.secret).toBe("T");
  });
});

describe("deleteItem", () => {
  it("resolves the ref to its id and deletes by id", async () => {
    const { client, calls } = clientWithItems([
      { id: "1", name: "PiHole" },
      { id: "2", name: "pihole-ssh" },
    ]);
    const { name } = await client.deleteItem("PiHole");
    expect(name).toBe("PiHole");
    // Must delete the exact resolved id, not the overlapping sibling.
    expect(calls).toContainEqual(["delete", "item", "1"]);
    expect(calls).not.toContainEqual(["delete", "item", "2"]);
  });

  it("throws (deletes nothing) when the ref doesn't resolve", async () => {
    const { client, calls } = clientWithItems([{ id: "1", name: "PiHole" }]);
    await expect(client.deleteItem("missing")).rejects.toThrow(/No vault item named "missing"/);
    expect(calls.some((c) => c[0] === "delete")).toBe(false);
  });
});

describe("resolveItem", () => {
  const items = [
    { id: "1", name: "PiHole" },
    { id: "2", name: "pihole-ssh" },
  ];
  it("prefers an exact name match over a substring sibling", () => {
    expect(resolveItem(items, "PiHole")!.id).toBe("1");
    expect(resolveItem(items, "pihole-ssh")!.id).toBe("2");
  });
  it("falls back to item id, then unique case-insensitive name", () => {
    expect(resolveItem(items, "2")!.id).toBe("2");
    expect(resolveItem(items, "pihole")!.id).toBe("1"); // only "PiHole" lowercases to "pihole"
  });
  it("returns null when nothing matches (lets the caller widen the set)", () => {
    expect(resolveItem([{ id: "1", name: "unrelated" }], "missing")).toBeNull();
  });
  it("throws on an ambiguous case-insensitive match", () => {
    expect(() => resolveItem([{ id: "1", name: "NAS" }, { id: "2", name: "nas" }], "Nas")).toThrow(/case-insensitively/);
  });
  it("falls back to a unique substring match (migration path)", () => {
    expect(resolveItem([{ id: "1", name: "pihole-ssh" }], "pihole")!.id).toBe("1");
  });
  it("throws on an ambiguous substring match with no better candidate", () => {
    expect(() => resolveItem([{ id: "1", name: "nas-a" }, { id: "2", name: "nas-b" }], "nas")).toThrow(/rename them/);
  });
});

describe("buildLoginItemJson", () => {
  it("builds a login item scoped to the org collection", () => {
    const item = buildLoginItemJson({
      name: "nas1-ssh",
      username: "skeletonkey",
      url: "ssh://192.168.1.50",
      notes: "managed",
      organizationId: "org-1",
      collectionId: "col-1",
      fields: [
        { name: "private_key", value: "PRIVATE", hidden: true },
        { name: "host", value: "192.168.1.50", hidden: false },
      ],
    }) as any;

    expect(item.type).toBe(1); // login
    expect(item.organizationId).toBe("org-1");
    expect(item.collectionIds).toEqual(["col-1"]);
    expect(item.name).toBe("nas1-ssh");
    expect(item.login.username).toBe("skeletonkey");
    expect(item.login.uris).toEqual([{ match: null, uri: "ssh://192.168.1.50" }]);
    // hidden -> type 1, visible -> type 0
    expect(item.fields).toEqual([
      { name: "private_key", value: "PRIVATE", type: 1 },
      { name: "host", value: "192.168.1.50", type: 0 },
    ]);
  });

  it("omits uris when no url is given and defaults empty fields", () => {
    const item = buildLoginItemJson({ name: "x", organizationId: "o", collectionId: "c" }) as any;
    expect(item.login.uris).toEqual([]);
    expect(item.fields).toEqual([]);
    expect(item.login.username).toBeNull();
  });
});
