import { createHash } from "node:crypto";

/**
 * SHA-256 as lowercase hex. Used to store auth secrets (OAuth tokens, the MCP
 * bearer) as non-reversible hashes so they can be verified without keeping the
 * plaintext around. Single definition so the hashing can't drift between call
 * sites.
 */
export function sha256hex(value: string): string {
  return createHash("sha256").update(value).digest("hex");
}
