import { describe, it, expect, beforeEach, afterEach } from "vitest";
import { mkdtemp, rm } from "node:fs/promises";
import { tmpdir } from "node:os";
import path from "node:path";
import { BootstrapStore } from "./bootstrap-store.js";

let dir: string;
let file: string;

beforeEach(async () => {
  dir = await mkdtemp(path.join(tmpdir(), "skmcp-"));
  file = path.join(dir, "bootstrap.store");
});
afterEach(async () => {
  await rm(dir, { recursive: true, force: true });
});

describe("BootstrapStore", () => {
  it("initializes, persists, and reopens with the right passphrase", async () => {
    const s1 = await BootstrapStore.open(file);
    expect(await s1.exists()).toBe(false);
    await s1.initialize("correct horse battery");
    await s1.update({ mcpBearerToken: "tok-123", bwClientId: "user.abc" });
    expect(s1.get().mcpBearerToken).toBe("tok-123");

    const s2 = await BootstrapStore.open(file);
    expect(await s2.exists()).toBe(true);
    await s2.unlock("correct horse battery");
    expect(s2.get().mcpBearerToken).toBe("tok-123");
    expect(s2.get().bwClientId).toBe("user.abc");
  });

  it("refuses the wrong passphrase", async () => {
    const s = await BootstrapStore.open(file);
    await s.initialize("right-passphrase");
    const s2 = await BootstrapStore.open(file);
    await expect(s2.unlock("wrong-passphrase")).rejects.toThrow(/passphrase|corrupted/i);
  });

  it("throws when reading while locked", async () => {
    const s = await BootstrapStore.open(file);
    await s.initialize("pw-pw-pw-pw");
    s.lock();
    expect(() => s.get()).toThrow(/locked/i);
  });

  it("won't overwrite an existing store", async () => {
    const s = await BootstrapStore.open(file);
    await s.initialize("pw-pw-pw-pw");
    const s2 = await BootstrapStore.open(file);
    await expect(s2.initialize("other")).rejects.toThrow(/already exists/i);
  });
});
