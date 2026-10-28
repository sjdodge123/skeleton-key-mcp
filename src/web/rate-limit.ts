import type { NextFunction, Request, RequestHandler, Response } from "express";
import type { AppState, ClientAttempt } from "../app.js";
import { clientKey, RefusalCoalescer, RequestLimiter } from "../lib/attempt-limiter.js";

/**
 * HTTP side of the attempt limiters (`src/lib/attempt-limiter.ts`, owned by
 * `AppState`). Every TOTP-gated route mounts `totpRateLimit` in front of its
 * handler, and the handler verifies through `AppState.checkTotp`, so a client
 * that is locked out is refused before the handler runs and again before its
 * code would be evaluated. (The body itself is parsed earlier, by the global
 * parsers in server.ts — the point is that neither the handler nor the secret
 * is ever reached.) `/api/store/unlock` does the same with `passphraseRateLimit`
 * and `AppState.unlockWithPassphrase`.
 */

/** The limiter's view of a request: the client key and the route PATTERN —
 *  never the raw path, because a credential link's id is a capability and
 *  must stay out of the audit log. */
export function clientAttempt(req: Request): ClientAttempt {
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
export function lockoutMessage(seconds: number, what = "authenticator codes"): string {
  return `Too many wrong ${what} — try again in ${formatWait(seconds)}.`;
}

/** 429 + Retry-After; the caller sends the body in its own format. */
export function refuseLockedOut(res: Response, seconds: number): Response {
  return res.status(429).set("Retry-After", String(seconds));
}

/**
 * Route middleware: while the client (or everyone) is locked out, answer 429
 * with Retry-After before the handler runs. `render` sends the body (JSON
 * `{ error }` by default); `skip` lets through requests that carry no code at
 * all, such as a consent "Deny".
 */
export function totpRateLimit(
  app: AppState,
  opts: { render?: (req: Request, res: Response, message: string) => void; skip?: (req: Request) => boolean } = {},
): RequestHandler {
  return function rateLimited(req: Request, res: Response, next: NextFunction): void {
    if (opts.skip?.(req)) return next();
    const seconds = app.totpLockout(clientAttempt(req));
    if (seconds === null) return next();
    refuseLockedOut(res, seconds);
    if (opts.render) opts.render(req, res, lockoutMessage(seconds));
    else res.json({ error: lockoutMessage(seconds) });
  };
}

/** `totpRateLimit` for the master passphrase on `/api/store/unlock`. */
export function passphraseRateLimit(app: AppState): RequestHandler {
  return function rateLimited(req: Request, res: Response, next: NextFunction): void {
    const seconds = app.passphraseLockout(clientAttempt(req));
    if (seconds === null) return next();
    refuseLockedOut(res, seconds).json({ error: lockoutMessage(seconds, "passphrases") });
  };
}

/** Refused OAuth requests are coalesced to one audit entry per window. */
const OAUTH_LIMIT_LOG_THROTTLE_MS = 60_000;

/**
 * Per-client request limit for an unauthenticated OAuth endpoint (registration,
 * token). These need no secret to call, so this bounds request volume and
 * client-table growth rather than guessing; the budgets sit far above what a
 * real client does (a refresh every token lifetime, a registration per
 * connector install).
 */
export function oauthRateLimit(app: AppState, name: string, max: number, windowMs: number): RequestHandler {
  const limiter = new RequestLimiter(max, windowMs);
  const refusals = new RefusalCoalescer(OAUTH_LIMIT_LOG_THROTTLE_MS);
  return function rateLimited(req: Request, res: Response, next: NextFunction): void {
    const client = clientKey(req.ip ?? req.socket.remoteAddress);
    const waitMs = limiter.hit(client);
    if (waitMs === 0) return next();
    const seconds = Math.max(1, Math.ceil(waitMs / 1000));
    const due = refusals.note(client);
    if (due) {
      try {
        app.audit.record({
          ts: new Date().toISOString(), tool: `oauth.${name}_rate_limited`, target: client, tier: "auth", args: {},
          status: "denied", detail: `${due.count} ${name} request(s) over ${max} per ${Math.round(windowMs / 1000)} s refused since the last entry, from ${due.clients}`,
        });
      } catch {
        /* audit is best-effort */
      }
    }
    res.status(429).set("Retry-After", String(seconds)).json({
      error: "temporarily_unavailable",
      error_description: `Too many requests; retry in ${formatWait(seconds)}.`,
    });
  };
}
