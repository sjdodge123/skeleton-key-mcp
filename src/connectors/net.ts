import type { Target } from "./types.js";
import { Agent, fetch as undiciFetch } from "undici";

let insecureAgent: Agent | undefined;

/**
 * fetch() that can skip TLS verification for **this request only** (an opt-in
 * per-target `insecureTLS`), via an undici dispatcher — instead of mutating the
 * process-global `NODE_TLS_REJECT_UNAUTHORIZED`, which would silently disable
 * TLS verification for the whole process (including the bw Vaultwarden sync).
 * Needed for self-signed LAN services (Proxmox :8006, UniFi, Synology, …).
 *
 * The secure path uses Node's global `fetch`. The insecure path MUST use
 * undici's own `fetch` with the Agent from the SAME undici — passing this
 * package's Agent as a `dispatcher` to Node's built-in fetch fails with
 * UND_ERR_INVALID_ARG (its bundled undici rejects a foreign dispatcher).
 */
export function tlsFetch(url: string, init: RequestInit, insecureTLS = false): Promise<Response> {
  if (!insecureTLS) return fetch(url, init);
  insecureAgent ??= new Agent({ connect: { rejectUnauthorized: false } });
  return undiciFetch(url, { ...(init as Record<string, unknown>), dispatcher: insecureAgent }) as unknown as Promise<Response>;
}

/** True only for an RFC1918 (private / LAN) IPv4 literal. The shared answer to
 *  "is this a LAN address I trust enough to send a credential to in clear" —
 *  used by the Pelican and Uptime Kuma transport guards. */
export function isPrivateIPv4(ip: string): boolean {
  const m = /^(\d{1,3})\.(\d{1,3})\.(\d{1,3})\.(\d{1,3})$/.exec(ip);
  if (!m) return false;
  const [a, b, c, d] = [Number(m[1]), Number(m[2]), Number(m[3]), Number(m[4])];
  if ([a, b, c, d].some((n) => n > 255)) return false;
  return a === 10 || (a === 172 && b >= 16 && b <= 31) || (a === 192 && b === 168);
}

/**
 * Derive a base URL for an HTTP(S) target. An explicit `baseUrl` option wins;
 * otherwise the scheme is inferred from the port (`httpsPorts`, default `[443]`)
 * and joined with host[:port]. Shared by the HTTP and Portainer connectors so
 * URL construction lives in one place.
 */
export function deriveBaseUrl(target: Target, opts: { baseUrl?: string; httpsPorts?: number[] } = {}): string {
  if (opts.baseUrl) return opts.baseUrl.replace(/\/$/, "");
  const httpsPorts = opts.httpsPorts ?? [443];
  const scheme = target.port && httpsPorts.includes(target.port) ? "https" : "http";
  // Bracket IPv6 literals so `host:port` is a valid URL (fetch can't parse a bare
  // `fd00::10:9443`).
  const host = target.host.includes(":") && !target.host.startsWith("[") ? `[${target.host}]` : target.host;
  return `${scheme}://${host}${target.port ? `:${target.port}` : ""}`;
}
