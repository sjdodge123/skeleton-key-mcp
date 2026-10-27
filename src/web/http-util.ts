import type { ErrorRequestHandler, Request } from "express";

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

/**
 * The parsed request body as a plain record. Express 5 leaves `req.body`
 * `undefined` when no body parser matched (no body, or an unexpected
 * Content-Type) where Express 4 defaulted it to `{}`; reading a field off that
 * would throw and surface as a 500. Anything that isn't a plain object (a JSON
 * array, a missing body) reads as empty, so a bodyless POST fails the handler's
 * own validation instead.
 */
export function bodyOf(req: Request): Record<string, unknown> {
  const b: unknown = req.body;
  return b !== null && typeof b === "object" && !Array.isArray(b) ? (b as Record<string, unknown>) : {};
}

/**
 * A named route parameter as a string, or null when it isn't one. Express 5
 * types params as `string | string[]` (wildcard segments are arrays); a plain
 * `:name` is always a string at runtime, but these are request inputs on
 * authenticated routes, so callers narrow and reject rather than cast.
 */
export function paramStr(req: Request, name: string): string | null {
  const v: unknown = req.params[name];
  return typeof v === "string" && v.length > 0 ? v : null;
}

/**
 * Final error handler. Express 5 forwards a rejected async handler here (Express
 * 4 left it an unhandled rejection), and the built-in handler would print the
 * stack outside production. The response carries only a fixed reason for the
 * status: never `err.message` (a body-parser JSON error quotes the request body,
 * which may be a passphrase or TOTP), never a stack, never the request `Host`.
 * Only server faults are logged, and only by error name and code: a message can
 * quote request input (a body, a one-time link id) or a value from upstream.
 * Client errors (malformed body or route param, oversized payload) are not
 * logged at all.
 */
export const errorHandler: ErrorRequestHandler = (err, _req, res, next) => {
  const e = (err ?? {}) as { status?: unknown; statusCode?: unknown; expose?: unknown; name?: unknown; code?: unknown };
  // Only a client error raised by Express itself keeps its status: http-errors
  // from body-parser (malformed or oversized body, marked `expose`) and the
  // router's URIError for a malformed percent-encoded route param (status 400,
  // no `expose`). Anything else is a server fault, even if it carries a
  // `status` from an upstream call — relaying, say, an upstream 401 would read
  // as an auth failure and send MCP clients back into the OAuth flow.
  const raw = typeof e.status === "number" ? e.status : typeof e.statusCode === "number" ? e.statusCode : 500;
  const fromExpress = e.expose === true || (err instanceof URIError && raw === 400);
  const status = fromExpress && raw >= 400 && raw < 500 ? raw : 500;
  if (status >= 500) {
    const code = typeof e.code === "string" || typeof e.code === "number" ? ` (${e.code})` : "";
    console.error(`[skeleton-key] request failed: ${typeof e.name === "string" ? e.name : "Error"}${code}`);
  }
  if (res.headersSent) {
    next(err);
    return;
  }
  res.status(status).json({ error: status >= 500 ? "Internal server error." : status === 413 ? "Request body too large." : "Bad request." });
};
