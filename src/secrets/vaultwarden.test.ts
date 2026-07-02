import { describe, it, expect } from "vitest";
import { buildLoginItemJson } from "./vaultwarden.js";

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
