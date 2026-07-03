import { describe, it, expect } from "vitest";
import { buildLoginItemJson, VaultwardenClient } from "./vaultwarden.js";

/** An unlocked client whose `bw list items` returns the given items. */
function clientWithItems(items: unknown[]): VaultwardenClient {
  const client = new VaultwardenClient("/unused") as any;
  client.session = "test-session";
  client.run = async (args: string[]) => {
    expect(args).toEqual(["list", "items"]); // getCredential must never `bw get item <name>`
    return JSON.stringify(items);
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

  it("fails clearly when no item has that exact name", async () => {
    const client = clientWithItems([{ id: "1", name: "pihole-ssh" }]);
    await expect(client.getCredential("PiHole")).rejects.toThrow(/No vault item named "PiHole"/);
  });

  it("fails clearly on true duplicate names", async () => {
    const client = clientWithItems([
      { id: "1", name: "nas" },
      { id: "2", name: "nas" },
    ]);
    await expect(client.getCredential("nas")).rejects.toThrow(/2 vault items are named "nas"/);
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
