import { describe, it, expect, beforeEach, afterEach, vi } from "vitest";
import { mkdtemp, readFile, rm, writeFile } from "node:fs/promises";
import { tmpdir } from "node:os";
import path from "node:path";
import sodium from "../lib/sodium.js";
import { loadUnlockKey, removeUnlockKey, saveUnlockKey } from "./unlock-key-file.js";

let dir: string;
let file: string;
let errorSpy: ReturnType<typeof vi.spyOn>;

beforeEach(async () => {
  await sodium.ready;
  dir = await mkdtemp(path.join(tmpdir(), "sk-unlock-key-"));
  file = path.join(dir, "unlock-key");
  errorSpy = vi.spyOn(console, "error").mockImplementation(() => {});
});
afterEach(async () => {
  errorSpy.mockRestore();
  await rm(dir, { recursive: true, force: true });
});

describe("unlock key file", () => {
  it("round-trips a key through save/load", async () => {
    const key = sodium.randombytes_buf(sodium.crypto_secretbox_KEYBYTES);
    await saveUnlockKey(file, key);
    const loaded = loadUnlockKey(file);
    expect(loaded).not.toBeNull();
    expect(sodium.to_base64(loaded!)).toBe(sodium.to_base64(key));
    expect(errorSpy).not.toHaveBeenCalled();
  });

  it("returns null silently for a missing file (auto-unlock simply not enrolled)", () => {
    expect(loadUnlockKey(path.join(dir, "nope"))).toBeNull();
    expect(errorSpy).not.toHaveBeenCalled();
  });

  it("logs (without key material) and returns null on malformed contents", async () => {
    await writeFile(file, "not-base64-!!!", "utf8");
    expect(loadUnlockKey(file)).toBeNull();
    expect(errorSpy).toHaveBeenCalledOnce();
    expect(String(errorSpy.mock.calls[0]?.[0])).toContain("malformed");
  });

  it("rejects a key of the wrong length", async () => {
    await writeFile(file, `${sodium.to_base64(sodium.randombytes_buf(16))}\n`, "utf8");
    expect(loadUnlockKey(file)).toBeNull();
    expect(errorSpy).toHaveBeenCalledOnce();
  });

  it("writes owner-only and removeUnlockKey deletes it", async () => {
    const key = sodium.randombytes_buf(sodium.crypto_secretbox_KEYBYTES);
    await saveUnlockKey(file, key);
    // Contents are base64 + newline, nothing else.
    expect(await readFile(file, "utf8")).toMatch(/^[A-Za-z0-9_-]+\n$/);
    expect(await removeUnlockKey(file)).toBe(true);
    expect(loadUnlockKey(file)).toBeNull();
    expect(await removeUnlockKey(file)).toBe(false);
  });
});
