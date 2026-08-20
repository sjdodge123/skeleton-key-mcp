import { networkInterfaces } from "node:os";
import { readFile, writeFile, mkdir } from "node:fs/promises";
import path from "node:path";
import { paths } from "./paths.js";

/**
 * The "public URL" is the absolute base (e.g. http://192.168.0.20:8787) Skeleton
 * Key puts in front of user-facing links — notably the vault-unlock guidance and
 * the credential hand-off links, both of which ask the user to type a secret.
 *
 * Resolution order (see AppState.publicUrl): SKELETON_KEY_PUBLIC_URL env override
 * → this persisted, auto-detected value → null (host-agnostic guidance). We NEVER
 * derive it from a request `Host` header: those links ask for a passphrase/secret,
 * so an attacker-controlled Host must not be able to steer them (phishing).
 */

function isPrivateIpv4(ip: string): boolean {
  return /^10\./.test(ip) || /^192\.168\./.test(ip) || /^172\.(1[6-9]|2\d|3[01])\./.test(ip);
}

/** Rank so homelab LANs (usually 192.168/16) win over 10/8 and 172.16/12. */
function rank(ip: string): number {
  if (ip.startsWith("192.168.")) return 0;
  if (ip.startsWith("10.")) return 1;
  return 2;
}

/**
 * All non-internal private IPv4 addresses of this host, best (192.168) first.
 * Used for the base-URL guess below and as the SANs of the self-signed TLS
 * certificate. `ifaces` is injectable for testing.
 */
export function detectLanIps(ifaces: ReturnType<typeof networkInterfaces> = networkInterfaces()): string[] {
  const candidates: string[] = [];
  for (const addrs of Object.values(ifaces)) {
    for (const a of addrs ?? []) {
      // Node 18+ reports family as "IPv4"; older/native code may use 4.
      const isV4 = a.family === "IPv4" || (a.family as unknown) === 4;
      if (isV4 && !a.internal && isPrivateIpv4(a.address)) candidates.push(a.address);
    }
  }
  candidates.sort((a, b) => rank(a) - rank(b));
  return [...new Set(candidates)];
}

/**
 * Best-guess LAN base URL from the host's own network interfaces, or null if no
 * private IPv4 is found (e.g. a bridged container with only Docker addresses).
 * `scheme` follows whether the server booted with TLS.
 */
export function detectLanBaseUrl(
  port: number,
  scheme: "http" | "https" = "http",
  ifaces: ReturnType<typeof networkInterfaces> = networkInterfaces(),
): string | null {
  const ip = detectLanIps(ifaces)[0];
  return ip ? `${scheme}://${ip}:${port}` : null;
}

/**
 * Rewrite just the scheme of a persisted base URL (http ↔ https), preserving
 * host and port — used to migrate `data/public-url` when TLS is enabled on an
 * existing deployment (or disabled again). Returns null (leave the value alone;
 * the caller logs) when the input isn't an origin-only absolute http(s) URL
 * with an explicit port: without a port, switching the scheme would silently
 * change the default port (80 ↔ 443), and a hand-edited value with a path
 * would be truncated by the origin rewrite.
 */
export function switchScheme(url: string, scheme: "http" | "https"): string | null {
  try {
    const u = new URL(url);
    if ((u.protocol !== "http:" && u.protocol !== "https:") || !u.port) return null;
    if (u.pathname !== "/" || u.search || u.hash) return null;
    u.protocol = `${scheme}:`;
    return u.origin;
  } catch {
    return null;
  }
}

/** Read the persisted public URL, or null if none has been written. */
export async function loadPublicUrl(file: string = paths.publicUrl): Promise<string | null> {
  try {
    const raw = (await readFile(file, "utf8")).trim();
    return raw || null;
  } catch {
    return null;
  }
}

/** Persist the public URL (non-secret; readable while the vault is locked). */
export async function savePublicUrl(url: string, file: string = paths.publicUrl): Promise<void> {
  await mkdir(path.dirname(file), { recursive: true });
  await writeFile(file, url + "\n", { mode: 0o644 });
}
