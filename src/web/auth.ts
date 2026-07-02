import type { Request, Response, NextFunction } from "express";
import { timingSafeEqual } from "node:crypto";
import type { AppState } from "../app.js";

function safeEqual(a: string, b: string): boolean {
  const ab = Buffer.from(a);
  const bb = Buffer.from(b);
  if (ab.length !== bb.length) return false;
  return timingSafeEqual(ab, bb);
}

function baseUrl(req: Request): string {
  const proto = (req.headers["x-forwarded-proto"] as string) || req.protocol || "http";
  return `${proto}://${req.get("host")}`;
}

/**
 * Gate the MCP endpoint: setup must be complete and the vault unlocked, then the
 * request must present either a valid OAuth 2.1 access token (preferred) or the
 * legacy static bearer token. On failure, emit the RFC 9728 `WWW-Authenticate`
 * hint so OAuth-capable clients (Claude) can discover the authorization server
 * and start the browser consent flow automatically. Fails closed throughout.
 */
export function mcpAuth(app: AppState) {
  return async (req: Request, res: Response, next: NextFunction): Promise<void> => {
    if (!(await app.isSetupComplete())) {
      res.status(503).json({ error: "Setup not complete. Open the web UI to finish onboarding." });
      return;
    }
    if (app.store.locked || !app.vault.unlocked) {
      res.status(503).json({ error: "Vault is locked. Unlock via the web UI." });
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

    // 1. OAuth access token (preferred).
    if (app.oauth.validateAccessToken(token)) {
      next();
      return;
    }
    // 2. Legacy static bearer token (kept for existing connections).
    const expected = app.store.get().mcpBearerToken;
    if (expected && safeEqual(token, expected)) {
      next();
      return;
    }
    challenge();
  };
}
