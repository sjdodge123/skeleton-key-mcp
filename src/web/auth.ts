import type { Request, Response, NextFunction } from "express";
import { timingSafeEqual } from "node:crypto";
import type { AppState } from "../app.js";

function safeEqual(a: string, b: string): boolean {
  const ab = Buffer.from(a);
  const bb = Buffer.from(b);
  if (ab.length !== bb.length) return false;
  return timingSafeEqual(ab, bb);
}

/**
 * Gate the MCP endpoint: setup must be complete, the vault unlocked, and the
 * request must carry the configured bearer token. Fails closed on every check.
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
    const expected = app.store.get().mcpBearerToken;
    const header = req.header("authorization") ?? "";
    const token = header.startsWith("Bearer ") ? header.slice(7) : "";
    if (!expected || !token || !safeEqual(token, expected)) {
      res.status(401).json({ error: "Missing or invalid bearer token." });
      return;
    }
    next();
  };
}
