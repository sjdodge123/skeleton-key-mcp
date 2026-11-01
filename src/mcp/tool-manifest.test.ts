import { describe, it, expect } from "vitest";
import { readFileSync } from "node:fs";
import path from "node:path";
import { buildToolManifest, renderToolManifest } from "./tool-manifest.js";

const committed = path.resolve(import.meta.dirname, "..", "..", "tools.manifest.json");

describe("tools.manifest.json", () => {
  it("matches the tools the code declares", () => {
    // If this fails: run `npm run manifest` and commit the result. A maintainer
    // reviews the diff — a new execute tool, or any tier change, shows up here.
    expect(readFileSync(committed, "utf8")).toBe(renderToolManifest());
  });

  it("lists only get_started as callable while the vault is locked", () => {
    const m = buildToolManifest();
    expect(m.global.filter((t) => t.availableWhenLocked).map((t) => t.name)).toEqual(["get_started"]);
  });

  it("gives every execute tool a confirm", () => {
    const m = buildToolManifest();
    const all = [...m.global, ...Object.values(m.connectors).flatMap((c) => c.tools)];
    expect(all.filter((t) => t.tier === "execute" && !t.confirm).map((t) => t.name)).toEqual([]);
  });
});
