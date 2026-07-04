import fs from "node:fs";
import { unlink, writeFile } from "node:fs/promises";
import sodium from "../lib/sodium.js";

/**
 * The boot auto-unlock key file: base64 of a random 32-byte key that wraps the
 * bootstrap store's data key (see BootstrapStore.enableAutoUnlock). It lives in
 * a host-mounted directory OUTSIDE the data volume — a backup or copy of /data
 * alone must never contain both the encrypted store and its unlock key. The
 * admin's master passphrase is never written here (or anywhere).
 */

/**
 * Load the unlock key at boot. A missing file just means auto-unlock isn't
 * enrolled (returns null silently); any other problem — unreadable file,
 * malformed contents — logs a clear error (never key material) and returns
 * null so boot falls through to manual web-UI unlock.
 */
export function loadUnlockKey(file: string): Uint8Array | null {
  let raw: string;
  try {
    raw = fs.readFileSync(file, "utf8");
  } catch (err) {
    if ((err as NodeJS.ErrnoException).code === "ENOENT") return null;
    console.error(
      `[skeleton-key] Could not read the auto-unlock key file (${file}): ` +
        `${err instanceof Error ? err.message : String(err)}. Unlock via the web UI.`,
    );
    return null;
  }
  try {
    const key = sodium.from_base64(raw.trim());
    if (key.length !== sodium.crypto_secretbox_KEYBYTES) throw new Error("wrong key length");
    return key;
  } catch {
    console.error(
      `[skeleton-key] Auto-unlock key file (${file}) is malformed — expected a base64 32-byte key. ` +
        "Disable and re-enable auto-unlock in the web UI to rewrite it.",
    );
    return null;
  }
}

/** Persist a freshly enrolled unlock key, owner-read/write only. */
export async function saveUnlockKey(file: string, key: Uint8Array): Promise<void> {
  await writeFile(file, `${sodium.to_base64(key)}\n`, { mode: 0o600 });
}

/** Best-effort removal when auto-unlock is disabled. */
export async function removeUnlockKey(file: string): Promise<boolean> {
  try {
    await unlink(file);
    return true;
  } catch {
    return false;
  }
}
