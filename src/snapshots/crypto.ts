import { createHash } from "node:crypto";
import sodium from "../lib/sodium.js";
import type { AppState } from "../app.js";

/** crypto_aead_xchacha20poly1305_ietf_NPUBBYTES */
const NONCEBYTES = 24;

/**
 * The 32-byte key that encrypts disaster-recovery skeleton artifacts at rest,
 * held inside the (already-encrypted) bootstrap store. Generated lazily on first
 * use. Requires the store unlocked — guaranteed because `form_skeleton` is not
 * `availableWhenLocked` and `store.get()` throws while locked.
 */
export async function getOrCreateSnapshotKey(app: AppState): Promise<Uint8Array> {
  await sodium.ready;
  const existing = app.store.get().snapshotKey;
  if (existing) return sodium.from_base64(existing);
  const key = sodium.crypto_aead_xchacha20poly1305_ietf_keygen();
  await app.store.update({ snapshotKey: sodium.to_base64(key) });
  return key;
}

/**
 * Encrypt one artifact as `nonce(24) || ciphertext(+16 tag)`. `aad` binds the
 * blob to its logical slot (`<id>/<target>/<artifact>`) so a ciphertext can't be
 * relocated to a different slot and still decrypt. Callers must have awaited
 * `sodium.ready` (getOrCreateSnapshotKey does).
 */
export function encryptArtifact(key: Uint8Array, plaintext: Buffer, aad: string): Buffer {
  const nonce = sodium.randombytes_buf(NONCEBYTES);
  const ct = sodium.crypto_aead_xchacha20poly1305_ietf_encrypt(plaintext, aad, null, nonce, key);
  return Buffer.concat([Buffer.from(nonce), Buffer.from(ct)]);
}

/** Inverse of {@link encryptArtifact}; throws if the key/AAD is wrong or the blob was tampered. */
export function decryptArtifact(key: Uint8Array, blob: Buffer, aad: string): Buffer {
  if (blob.length < NONCEBYTES) throw new Error("snapshot artifact too short to decrypt");
  const nonce = blob.subarray(0, NONCEBYTES);
  const ct = blob.subarray(NONCEBYTES);
  return Buffer.from(sodium.crypto_aead_xchacha20poly1305_ietf_decrypt(null, ct, aad, nonce, key));
}

export function sha256(b: Buffer): string {
  return createHash("sha256").update(b).digest("hex");
}
