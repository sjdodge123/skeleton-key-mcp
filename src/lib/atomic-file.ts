import { open, rename } from "node:fs/promises";
import path from "node:path";

/**
 * Durable atomic write: temp file in the same directory → fsync → rename over
 * the target → best-effort fsync of the directory. A crash or power loss at any
 * point leaves either the old complete file or the new complete file — never a
 * truncated one. Used for the bootstrap store and the auto-unlock key file,
 * where a torn write would destroy the only copy of a secret.
 */
export async function writeFileAtomic(file: string, data: string, mode: number): Promise<void> {
  const tmp = `${file}.tmp`;
  const fh = await open(tmp, "w", mode);
  try {
    await fh.writeFile(data);
    await fh.sync();
  } finally {
    await fh.close();
  }
  await rename(tmp, file);
  // Make the rename itself durable. Directory fsync is not supported on every
  // platform/filesystem, so failures here are non-fatal (the data write above
  // is already synced; only the rename could be replayed as the old name).
  try {
    const dir = await open(path.dirname(file), "r");
    try {
      await dir.sync();
    } finally {
      await dir.close();
    }
  } catch {
    /* best-effort */
  }
}
