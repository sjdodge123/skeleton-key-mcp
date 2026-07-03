import type { Request, Response, NextFunction } from "express";
import { timingSafeEqual } from "node:crypto";
import type { AppState } from "../app.js";
import { baseUrl } from "./http-util.js";

function safeEqual(a: string, b: string): boolean {
  const ab = Buffer.from(a);
  const bb = Buffer.from(b);
  if (ab.length !== bb.length) return false;
  return timingSafeEqual(ab, bb);
}

/**
 * Gate the MCP endpoint: setup must be complete, then the request must present
 * either a valid OAuth 2.1 access token (preferred) or the legacy static bearer
 * token. On failure, emit the RFC 9728 `WWW-Authenticate` hint so OAuth-capable
 * clients (Claude) can discover the authorization server and start the browser
 * consent flow automatically. Fails closed throughout.
 *
 * A locked vault does NOT block authenticated clients: sessions still connect
 * and tool calls return actionable "unlock at <url>" errors (see the CallTool
 * locked gate) instead of the endpoint going dark with an opaque 503 that
 * clients render as "failed to reconnect".
 */
export function mcpAuth(app: AppState) {
  return async (req: Request, res: Response, next: NextFunction): Promise<void> => {
    const adminUi = `${baseUrl(req)}/`;
    if (!(await app.isSetupComplete())) {
      res.status(503).json({ error: `Setup not complete. Open ${adminUi} to finish onboarding.` });
      return;
    }
    const header = req.header("authorization") ?? "";
    const token = header.startsWith("Bearer ") ? header.slice(7) : "";

    const challenge = (): void => {
      res
        .status(401)
        .set("WWW-Authenticate", `Bearer resource_metadata="${baseUrl(req)}/.well-known/oauth-protected-resource"`)
        .json({ error: "Missing or invalid credentials." });
    };

    if (!token) {
      challenge();
      return;
    }

    try {
      // 1. OAuth access token (preferred). Verifiable even while the store is
      //    locked — token hashes live in oauth.sqlite, not the bootstrap store.
      if (app.oauth.validateAccessToken(token)) {
        next();
        return;
      }
      // 2. Legacy static bearer token (kept for existing connections). Only
      //    verifiable while the store is unlocked.
      if (!app.store.locked) {
        const expected = app.store.get().mcpBearerToken;
        if (expected && safeEqual(token, expected)) {
          next();
          return;
        }
        challenge();
        return;
      }
      // Store locked and the token isn't a valid OAuth token — it may be the
      // static bearer, which we cannot verify right now. Say so (with the fix)
      // instead of a 401 that would push the client into an OAuth flow that
      // dead-ends: consent needs TOTP, which also needs the unlocked store.
      res.status(503).json({
        error: `Skeleton Key is locked (container restarted?). Open ${adminUi} and enter the master passphrase to unlock, then retry.`,
      });
    } catch {
      // Fail closed on any error (e.g. a transient DB failure) rather than hang.
      challenge();
    }
  };
}
