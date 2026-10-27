import type { NextFunction, Request, RequestHandler, Response } from "express";
import type { AppState, TotpAttempt } from "../app.js";
import { clientKey, RequestLimiter } from "../lib/attempt-limiter.js";

/**
 * HTTP side of the TOTP attempt limiter (`src/lib/attempt-limiter.ts`, owned
 * by `AppState`). Every TOTP-gated route mounts `totpRateLimit` in front of its
 * handler, and the handler verifies through `AppState.checkTotp`, so a client
 * that is locked out is refused before its code is parsed and again before it
 * would be evaluated.
 */

/** The limiter's view of a request: the client key and the route PATTERN —
 *  never the raw path, because a credential link's id is a capability and
 *  must stay out of the audit log. */
export function totpAttempt(req: Request): TotpAttempt {
  const route: unknown = (req.route as { path?: unknown } | undefined)?.path;
  return {
    client: clientKey(req.ip ?? req.socket.remoteAddress),
    via: `${req.method} ${req.baseUrl}${typeof route === "string" ? route : ""}`,
  };
}

function formatWait(seconds: number): string {
  return seconds < 120 ? `${seconds} s` : `${Math.ceil(seconds / 60)} min`;
}

/** The body text of a lockout refusal: the same whatever code was sent. */
export function lockoutMessage(seconds: number): string {
  return `Too many wrong authenticator codes — try again in ${formatWait(seconds)}.`;
}

/** 429 + Retry-After; the caller sends the body in its own format. */
export function refuseLockedOut(res: Response, seconds: number): Response {
  return res.status(429).set("Retry-After", String(seconds));
}

/**
 * Route middleware: while the client (or everyone) is locked out, answer 429
 * with Retry-After before the handler reads the body. `render` sends the body
 * (JSON `{ error }` by default); `skip` lets through requests that carry no
 * code at all, such as a consent "Deny".
 */
export function totpRateLimit(
  app: AppState,
  opts: { render?: (req: Request, res: Response, message: string) => void; skip?: (req: Request) => boolean } = {},
): RequestHandler {
  return function rateLimited(req: Request, res: Response, next: NextFunction): void {
    if (opts.skip?.(req)) return next();
    const seconds = app.totpLockout(totpAttempt(req));
    if (seconds === null) return next();
    refuseLockedOut(res, seconds);
    if (opts.render) opts.render(req, res, lockoutMessage(seconds));
    else res.json({ error: lockoutMessage(seconds) });
  };
}

/** Refused OAuth requests are coalesced to one audit entry per window. */
const OAUTH_LIMIT_LOG_THROTTLE_MS = 10_000;

/**
 * Per-client request limit for an unauthenticated OAuth endpoint (registration,
 * token). These need no secret to call, so this bounds request volume and
 * client-table growth rather than guessing; the budgets sit far above what a
 * real client does (a refresh every token lifetime, a registration per
 * connector install).
 */
export function oauthRateLimit(app: AppState, name: string, max: number, windowMs: number): RequestHandler {
  const limiter = new RequestLimiter(max, windowMs);
  let pending = 0;
  let lastLogAt = 0;
  return function rateLimited(req: Request, res: Response, next: NextFunction): void {
    const client = clientKey(req.ip ?? req.socket.remoteAddress);
    const waitMs = limiter.hit(client);
    if (waitMs === 0) return next();
    const seconds = Math.max(1, Math.ceil(waitMs / 1000));
    pending++;
    const now = Date.now();
    if (now - lastLogAt >= OAUTH_LIMIT_LOG_THROTTLE_MS) {
      try {
        app.audit.record({
          ts: new Date().toISOString(), tool: `oauth.${name}_rate_limited`, target: client, tier: "auth", args: {},
          status: "denied", detail: `${pending} ${name} request(s) over ${max} per ${Math.round(windowMs / 1000)} s refused since the last entry`,
        });
      } catch {
        /* audit is best-effort */
      }
      pending = 0;
      lastLogAt = now;
    }
    res.status(429).set("Retry-After", String(seconds)).json({
      error: "temporarily_unavailable",
      error_description: `Too many requests; retry in ${formatWait(seconds)}.`,
    });
  };
}
