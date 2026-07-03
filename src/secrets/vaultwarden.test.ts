import { describe, it, expect } from "vitest";
import { buildLoginItemJson, resolveItem, VaultwardenClient } from "./vaultwarden.js";

type Item = { id: string; name: string; login?: any; fields?: any[] };

/**
 * An unlocked client backed by a fixed item set. `bw list items` is served from
 * that set, honoring `--search <term>` as a case-insensitive name-substring
 * filter (matching the real CLI) so the bounded fast path is exercised — and it
 * asserts getCredential never shells out to `bw get item`.
 */
function clientWithItems(items: Item[]): VaultwardenClient {
  const client = new VaultwardenClient("/unused") as any;
  client.session = "test-session";
  client.run = async (args: string[]) => {
    expect(args[0]).toBe("list");
    expect(args[1]).toBe("items");
    const searchIdx = args.indexOf("--search");
    const filtered =
      searchIdx >= 0
        ? items.filter((i) => i.name.toLowerCase().includes(args[searchIdx + 1]!.toLowerCase()))
        : items;
    return JSON.stringify(filtered);
  };
  return client as VaultwardenClient;
}

describe("getCredential", () => {
  it("resolves by exact name even when another item name overlaps", async () => {
    const client = clientWithItems([
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
    const client = clientWithItems([{ id: "1", name: "PiHole", login: { username: "pihole" } }]);
    const cred = await client.getCredential("pihole");
    expect(cred.username).toBe("pihole");
  });

  it("resolves a ref given as an item id (via the full-list fallback)", async () => {
    const client = clientWithItems([{ id: "abc-123", name: "PiHole", login: { username: "pihole" } }]);
    const cred = await client.getCredential("abc-123");
    expect(cred.username).toBe("pihole");
  });

  it("fails clearly when nothing matches", async () => {
    const client = clientWithItems([{ id: "1", name: "pihole-ssh" }]);
    await expect(client.getCredential("nope")).rejects.toThrow(/No vault item named "nope"/);
  });

  it("fails clearly on true duplicate names", async () => {
    const client = clientWithItems([
      { id: "1", name: "nas" },
      { id: "2", name: "nas" },
    ]);
    await expect(client.getCredential("nas")).rejects.toThrow(/2 vault items are named "nas"/);
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
    expect(resolveItem(items, "missing")).toBeNull();
  });
  it("throws on an ambiguous case-insensitive match", () => {
    expect(() => resolveItem([{ id: "1", name: "NAS" }, { id: "2", name: "nas" }], "Nas")).toThrow(/case-insensitively/);
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
