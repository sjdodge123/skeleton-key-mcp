import { describe, it, expect, beforeEach, afterEach } from "vitest";
import { mkdtemp, readFile, rm, writeFile } from "node:fs/promises";
import { tmpdir } from "node:os";
import path from "node:path";
import sodium from "../lib/sodium.js";
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

describe("BootstrapStore auto-unlock keyslot", () => {
  it("enrolls a key that unlocks a fresh handle without the passphrase (and passphrase still works)", async () => {
    const s = await BootstrapStore.open(file);
    await s.initialize("correct horse battery");
    await s.update({ mcpBearerToken: "tok-1" });
    expect(await s.autoUnlockEnabled()).toBe(false);
    const key = await s.enableAutoUnlock();
    expect(key.length).toBe(sodium.crypto_secretbox_KEYBYTES);
    expect(await s.autoUnlockEnabled()).toBe(true);

    const viaKey = await BootstrapStore.open(file);
    await viaKey.unlockWithKey(key);
    expect(viaKey.get().mcpBearerToken).toBe("tok-1");

    const viaPass = await BootstrapStore.open(file);
    await viaPass.unlock("correct horse battery");
    expect(viaPass.get().mcpBearerToken).toBe("tok-1");
  });

  it("keeps the slot working across update() and rejects a wrong key", async () => {
    const s = await BootstrapStore.open(file);
    await s.initialize("correct horse battery");
    const key = await s.enableAutoUnlock();
    await s.update({ mcpBearerToken: "tok-2" });

    const viaKey = await BootstrapStore.open(file);
    await viaKey.unlockWithKey(key);
    expect(viaKey.get().mcpBearerToken).toBe("tok-2");

    const wrong = sodium.randombytes_buf(sodium.crypto_secretbox_KEYBYTES);
    const s2 = await BootstrapStore.open(file);
    await expect(s2.unlockWithKey(wrong)).rejects.toThrow(/does not match/i);
  });

  it("disableAutoUnlock removes the slot; the old key is dead", async () => {
    const s = await BootstrapStore.open(file);
    await s.initialize("correct horse battery");
    const key = await s.enableAutoUnlock();
    await s.disableAutoUnlock();
    expect(await s.autoUnlockEnabled()).toBe(false);

    const s2 = await BootstrapStore.open(file);
    await expect(s2.unlockWithKey(key)).rejects.toThrow(/not enrolled/i);
  });

  it("rolls back the staged slot when persist fails, so memory matches disk", async () => {
    const s = await BootstrapStore.open(file);
    await s.initialize("correct horse battery");
    const { chmod } = await import("node:fs/promises");
    await chmod(dir, 0o500); // read-only dir: the atomic write must fail
    await expect(s.enableAutoUnlock()).rejects.toThrow();
    await chmod(dir, 0o700);
    // The failed enrollment left no trace — a later update() must not
    // resurrect a slot whose key was never handed to the caller.
    await s.update({ mcpBearerToken: "after-failure" });
    expect(await s.autoUnlockEnabled()).toBe(false);
    const reopened = await BootstrapStore.open(file);
    await reopened.unlock("correct horse battery");
    expect(reopened.get().mcpBearerToken).toBe("after-failure");
  });

  it("autoUnlockEnabled() is readable while locked", async () => {
    const s = await BootstrapStore.open(file);
    await s.initialize("correct horse battery");
    await s.enableAutoUnlock();
    s.lock();
    expect(await s.autoUnlockEnabled()).toBe(true);
  });
});

describe("BootstrapStore v1 migration", () => {
  /** Write a store in the legacy SKMCP1 layout (payload directly under the
   *  passphrase-derived key). Interactive KDF limits keep the test fast; the
   *  params are stored in the file, so unlock honors them either way. */
  async function writeV1(passphrase: string, secrets: object): Promise<void> {
    await sodium.ready;
    const salt = sodium.randombytes_buf(sodium.crypto_pwhash_SALTBYTES);
    const opslimit = sodium.crypto_pwhash_OPSLIMIT_INTERACTIVE;
    const memlimit = sodium.crypto_pwhash_MEMLIMIT_INTERACTIVE;
    const key = sodium.crypto_pwhash(
      sodium.crypto_secretbox_KEYBYTES, passphrase, salt, opslimit, memlimit,
      sodium.crypto_pwhash_ALG_ARGON2ID13,
    );
    const nonce = sodium.randombytes_buf(sodium.crypto_secretbox_NONCEBYTES);
    const ciphertext = sodium.crypto_secretbox_easy(
      new TextEncoder().encode(JSON.stringify(secrets)), nonce, key,
    );
    await writeFile(file, JSON.stringify({
      magic: "SKMCP1",
      kdf: { salt: sodium.to_base64(salt), opslimit, memlimit },
      nonce: sodium.to_base64(nonce),
      ciphertext: sodium.to_base64(ciphertext),
    }), { mode: 0o600 });
  }

  it("unlocks a v1 store, migrates it to v2, and keeps both secrets and passphrase", async () => {
    await writeV1("legacy-pass", { mcpBearerToken: "tok-v1", totpSecret: "ABCDEF" });

    const s = await BootstrapStore.open(file);
    await s.unlock("legacy-pass");
    expect(s.get().mcpBearerToken).toBe("tok-v1");
    expect(s.get().totpSecret).toBe("ABCDEF");

    const onDisk = JSON.parse(await readFile(file, "utf8"));
    expect(onDisk.magic).toBe("SKMCP2");
    expect(onDisk.slots.passphrase).toBeDefined();

    // Same passphrase reopens the migrated store; auto-unlock can then be enrolled.
    const s2 = await BootstrapStore.open(file);
    await s2.unlock("legacy-pass");
    const key = await s2.enableAutoUnlock();
    const s3 = await BootstrapStore.open(file);
    await s3.unlockWithKey(key);
    expect(s3.get().mcpBearerToken).toBe("tok-v1");
  });

  it("rejects the wrong passphrase on a v1 store without migrating it", async () => {
    await writeV1("legacy-pass", { mcpBearerToken: "tok-v1" });
    const s = await BootstrapStore.open(file);
    await expect(s.unlock("wrong")).rejects.toThrow(/passphrase|corrupted/i);
    const onDisk = JSON.parse(await readFile(file, "utf8"));
    expect(onDisk.magic).toBe("SKMCP1");
  });

  it("unlockWithKey on a v1 store explains that migration is needed", async () => {
    await writeV1("legacy-pass", {});
    const s = await BootstrapStore.open(file);
    const key = sodium.randombytes_buf(sodium.crypto_secretbox_KEYBYTES);
    await expect(s.unlockWithKey(key)).rejects.toThrow(/predates auto-unlock/i);
  });
});
