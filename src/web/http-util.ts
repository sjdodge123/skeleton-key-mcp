import type { Request } from "express";
import type { AppState } from "../app.js";

/**
 * Origin used to build OAuth discovery metadata and the WWW-Authenticate hint.
 *
 * Prefer the pinned/auto-detected public URL (`app.publicUrl()`: the
 * `SKELETON_KEY_PUBLIC_URL` env override, else the LAN address detected on first
 * boot) so the OAuth issuer/authorization endpoints — a TOTP-gated flow — can't
 * be steered by a forged `Host` header. Only when no public URL is known at all
 * do we fall back to the request's own protocol+host. We deliberately do NOT
 * trust `X-Forwarded-*`: Skeleton Key is reached directly on the LAN, so
 * honoring proxy headers would only add an attacker-controlled input.
 */
export function baseUrl(req: Request, app?: AppState): string {
  const pinned = app ? app.publicUrl() : process.env.SKELETON_KEY_PUBLIC_URL?.replace(/\/$/, "") ?? null;
  if (pinned) return pinned;
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
