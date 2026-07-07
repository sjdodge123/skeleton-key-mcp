import { describe, it, expect, beforeEach, afterEach } from "vitest";
import { mkdtemp, rm } from "node:fs/promises";
import { tmpdir } from "node:os";
import path from "node:path";
import sodium from "../lib/sodium.js";
import { BootstrapStore } from "../secrets/bootstrap-store.js";
import type { AppState } from "../app.js";
import { getOrCreateSnapshotKey, encryptArtifact, decryptArtifact, sha256 } from "./crypto.js";

let dir: string;

beforeEach(async () => {
  dir = await mkdtemp(path.join(tmpdir(), "skmcp-snap-crypto-"));
  await sodium.ready;
});
afterEach(async () => {
  await rm(dir, { recursive: true, force: true });
});

const key = () => sodium.crypto_aead_xchacha20poly1305_ietf_keygen();

describe("snapshot crypto", () => {
  it("round-trips an artifact (and the blob isn't the plaintext)", () => {
    const k = key();
    const pt = Buffer.from("secret backup bytes");
    const blob = encryptArtifact(k, pt, "id/target/artifact");
    expect(blob.equals(pt)).toBe(false);
    expect(decryptArtifact(k, blob, "id/target/artifact").equals(pt)).toBe(true);
  });

  it("fails to decrypt with the wrong key", () => {
    const blob = encryptArtifact(key(), Buffer.from("x"), "a");
    expect(() => decryptArtifact(key(), blob, "a")).toThrow();
  });

  it("fails to decrypt under a different AAD (a blob can't be relocated to another slot)", () => {
    const k = key();
    const blob = encryptArtifact(k, Buffer.from("x"), "id/a/one");
    expect(() => decryptArtifact(k, blob, "id/a/two")).toThrow();
  });

  it("fails to decrypt a tampered ciphertext (AEAD auth)", () => {
    const k = key();
    const blob = encryptArtifact(k, Buffer.from("hello"), "a");
    blob[blob.length - 1] ^= 0x01;
    expect(() => decryptArtifact(k, blob, "a")).toThrow();
  });

  it("uses a fresh nonce per encryption (two encryptions of the same plaintext differ)", () => {
    const k = key();
    expect(encryptArtifact(k, Buffer.from("same"), "a").equals(encryptArtifact(k, Buffer.from("same"), "a"))).toBe(false);
  });

  it("rejects a blob too short to hold a nonce", () => {
    expect(() => decryptArtifact(key(), Buffer.alloc(4), "a")).toThrow(/too short/);
  });

  it("generates the snapshot key once and reuses it (persisted in the store)", async () => {
    const store = await BootstrapStore.open(path.join(dir, "bootstrap.store"));
    await store.initialize("correct horse battery staple");
    const app = { store } as unknown as AppState;

    expect(store.get().snapshotKey).toBeUndefined();
    const k1 = await getOrCreateSnapshotKey(app);
    const persisted = store.get().snapshotKey;
    expect(typeof persisted).toBe("string");
    const k2 = await getOrCreateSnapshotKey(app);
    expect(Buffer.from(k1).equals(Buffer.from(k2))).toBe(true);
    expect(store.get().snapshotKey).toBe(persisted); // unchanged on the second call
  });

  it("sha256 matches the known NIST vector for 'abc'", () => {
    expect(sha256(Buffer.from("abc"))).toBe("ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad");
  });
});
