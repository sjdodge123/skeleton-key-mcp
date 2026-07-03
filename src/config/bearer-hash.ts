import { readFile, writeFile, mkdir } from "node:fs/promises";
import path from "node:path";
import { paths } from "./paths.js";
import { sha256hex } from "../lib/hash.js";

/**
 * The static MCP bearer token lives (in the clear) only inside the encrypted
 * bootstrap store, so it can't be verified while the vault is locked. We also
 * persist a SHA-256 *hash* of it here — non-secret, like the OAuth token hashes
 * in oauth.sqlite — so `mcpAuth` can verify a presented bearer after a restart
 * (while locked) and admit it to the banner-only get_started, instead of 401ing
 * a valid client. The token itself is never written here.
 */

export function hashBearer(token: string): string {
  return sha256hex(token);
}

export async function loadBearerHash(file: string = paths.bearerHash): Promise<string | null> {
  try {
    const raw = (await readFile(file, "utf8")).trim();
    return raw || null;
  } catch {
    return null;
  }
}

export async function saveBearerHash(hash: string, file: string = paths.bearerHash): Promise<void> {
  await mkdir(path.dirname(file), { recursive: true });
  await writeFile(file, hash + "\n", { mode: 0o600 });
}
