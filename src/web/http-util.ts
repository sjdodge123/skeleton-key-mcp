import type { Request } from "express";

/**
 * Origin used to build OAuth discovery metadata and the WWW-Authenticate hint.
 *
 * Prefer an explicit `SKELETON_KEY_PUBLIC_URL` so the issuer can't be steered by
 * a forged Host header. Otherwise fall back to the request's own protocol+host,
 * and deliberately do NOT trust `X-Forwarded-*`: Skeleton Key is reached directly
 * on the LAN, so honoring proxy headers would only add an attacker-controlled input.
 */
export function baseUrl(req: Request): string {
  const configured = process.env.SKELETON_KEY_PUBLIC_URL;
  if (configured) return configured.replace(/\/$/, "");
  return `${req.protocol}://${req.get("host")}`;
}

/**
 * Express query/body values may be a string, an array (duplicated params), or a
 * nested object. Coerce to a single string so downstream string ops can't throw
 * on attacker-supplied `?x=a&x=b`.
 */
export function firstStr(v: unknown): string {
  if (Array.isArray(v)) return typeof v[0] === "string" ? v[0] : "";
  return typeof v === "string" ? v : "";
}
