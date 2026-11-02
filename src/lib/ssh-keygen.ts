import { execFile } from "node:child_process";
import { mkdtemp, readFile, rm } from "node:fs/promises";
import { tmpdir } from "node:os";
import path from "node:path";
import { promisify } from "node:util";

const execFileAsync = promisify(execFile);

export interface GeneratedKey {
  privateKey: string; // OpenSSH-format private key (what ssh2 parses reliably)
  publicKey: string; // "ssh-ed25519 AAAA... comment" — install in authorized_keys
  fingerprint: string; // SHA256:...
}

/**
 * Generate a fresh ed25519 keypair via `ssh-keygen`. We shell out rather than
 * hand-roll the OpenSSH private-key binary format, which is easy to get subtly
 * wrong. Keys are written to a throwaway temp dir, read into memory, and the dir
 * is removed — nothing is left on disk.
 */
export async function generateSshKey(comment: string, passphrase = ""): Promise<GeneratedKey> {
  const dir = await mkdtemp(path.join(tmpdir(), "skmcp-key-"));
  const keyPath = path.join(dir, "id_ed25519");
  try {
    await execFileAsync("ssh-keygen", ["-t", "ed25519", "-N", passphrase, "-C", comment, "-f", keyPath, "-q"]);
    const [privateKey, publicKey, fpOut] = await Promise.all([
      readFile(keyPath, "utf8"),
      readFile(`${keyPath}.pub`, "utf8"),
      execFileAsync("ssh-keygen", ["-lf", `${keyPath}.pub`]).then((r) => r.stdout),
    ]);
    const fingerprint = fpOut.split(/\s+/)[1] ?? fpOut.trim();
    return { privateKey: privateKey.trimEnd() + "\n", publicKey: publicKey.trim(), fingerprint };
  } finally {
    await rm(dir, { recursive: true, force: true });
  }
}
