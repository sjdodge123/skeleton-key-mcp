import type { Request, Response, NextFunction } from "express";
import type { AppState } from "../app.js";
import { baseUrl } from "./http-util.js";

/**
 * Gate the MCP endpoint: setup must be complete, then the request must present
 * either a valid OAuth 2.1 access token (preferred) or the legacy static bearer
 * token. On failure, emit the RFC 9728 `WWW-Authenticate` hint so OAuth-capable
 * clients (Claude) can discover the authorization server and start the browser
 * consent flow automatically. Fails closed throughout.
 *
 * Auth routing is deliberately INDEPENDENT of the vault lock state. A locked
 * vault (post-restart) is enforced at the *tool* layer (only a banner-only
 * get_started runs while locked — see the CallTool locked gate), not here. In
 * particular, an expired access token must still get the 401 challenge so the
 * client silently refreshes (the refresh grant needs only oauth.sqlite and works
 * while locked) instead of a dead 503 — otherwise the endpoint appears to "go
 * dark after a restart", the very bug this path exists to prevent.
 */
export function mcpAuth(app: AppState) {
  return async (req: Request, res: Response, next: NextFunction): Promise<void> => {
    if (!(await app.isSetupComplete())) {
      res.status(503).json({ error: "Setup not complete. Open the Skeleton Key web UI to finish onboarding." });
      return;
    }
    const header = req.header("authorization") ?? "";
    const token = header.startsWith("Bearer ") ? header.slice(7) : "";

    const challenge = (): void => {
      // When locked, hint that unlocking may be the fix (a fresh client can't
      // complete consent until the store is unlocked); include the pinned URL
      // only, never a Host-derived one.
      const url = app.locked ? app.unlockUrl() : null;
      const detail = app.locked
        ? ` Skeleton Key may be locked; ${url ? `unlock at ${url}/` : "unlock it via the web UI"} first.`
        : "";
      res
        .status(401)
        .set("WWW-Authenticate", `Bearer resource_metadata="${baseUrl(req, app)}/.well-known/oauth-protected-resource"`)
        .json({ error: `Missing or invalid credentials.${detail}` });
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
      // 2. Legacy static bearer token (kept for existing connections). Verifiable
      //    while locked too (against the persisted hash), so a valid bearer isn't
      //    401'd after a restart — it's admitted to the banner-only get_started
      //    like an OAuth token, per the locked tool gate.
      if (app.verifyBearer(token)) {
        next();
        return;
      }
      challenge();
    } catch {
      // Fail closed on any error (e.g. a transient DB failure) rather than hang.
      challenge();
    }
  };
}
