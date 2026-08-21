import { createHmac } from "node:crypto";
import sodium from "./sodium.js";
import type { AppState } from "../app.js";

/**
 * Keyed value fingerprints — a way to tell whether two secrets are the SAME
 * value without revealing either. Used to compare what landed in the vault with
 * what a stack was deployed with (the coworker-bot migration carried a wrong
 * credential through two vault round-trips and a deploy before anyone noticed;
 * comparing fingerprints would have caught it in seconds).
 *
 * The fingerprint is `len=<n> fp=<8 hex>` where the hex is the prefix of an
 * HMAC-SHA256 under a per-install key held in the encrypted bootstrap store.
 * Keyed (rather than a bare SHA-256 prefix) so that a fingerprint that ends up
 * in a chat transcript can't be used to verify offline guesses of a weak
 * password — without the key, it's just noise. Both sides of every comparison
 * are computed on this box with the same key, so equality still works.
 */
export async function getOrCreateFingerprintKey(app: AppState): Promise<Buffer> {
  await sodium.ready;
  const existing = app.store.get().fingerprintKey;
  if (existing) return Buffer.from(sodium.from_base64(existing));
  const key = sodium.randombytes_buf(32);
  await app.store.update({ fingerprintKey: sodium.to_base64(key) });
  return Buffer.from(key);
}

/** Pure: format one value's fingerprint under `key` (exported for testing). */
export function fingerprintWith(key: Buffer, value: string): string {
  const mac = createHmac("sha256", key).update(value, "utf8").digest("hex").slice(0, 8);
  return `len=${Buffer.byteLength(value, "utf8")} fp=${mac}`;
}

/** Fingerprint `value` under this install's key (requires an unlocked store). */
export async function fingerprintValue(app: AppState, value: string): Promise<string> {
  return fingerprintWith(await getOrCreateFingerprintKey(app), value);
}
