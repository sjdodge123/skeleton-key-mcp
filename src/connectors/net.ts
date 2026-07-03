import type { Target } from "./types.js";

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
