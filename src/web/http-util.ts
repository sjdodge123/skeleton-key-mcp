import type { Request } from "express";

/**
 * Origin used to build OAuth discovery metadata and the WWW-Authenticate hint.
 *
 * This is MACHINE-facing: the client fetches these URLs and must be able to
 * reach them. An explicit `SKELETON_KEY_PUBLIC_URL` pins the issuer (the
 * security control against a forged `Host`); otherwise we use the request's own
 * protocol+host — the exact address the client reached us on, which is always
 * reachable by that client. We deliberately do NOT use the auto-detected
 * `publicUrl()` here: on a bridged Docker container (the documented default)
 * first-boot detection can only see Docker's internal subnet, so pinning
 * discovery to it would advertise an unreachable address and break OAuth for
 * everyone. (Human-facing, phishing-sensitive links — unlock guidance, the
 * credential hand-off — use `AppState.publicUrl()` instead, which never falls
 * back to `Host`.) We also do NOT trust `X-Forwarded-*`: reached directly on the
 * LAN, honoring proxy headers would only add an attacker-controlled input.
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
