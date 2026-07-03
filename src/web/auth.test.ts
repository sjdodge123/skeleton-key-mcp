import { describe, it, expect, beforeEach, afterEach, vi } from "vitest";
import type { Request, Response } from "express";
import { mcpAuth } from "./auth.js";
import type { AppState } from "../app.js";

/**
 * mcpAuth behavior matrix. Key property: auth routing is independent of the vault
 * lock state — a locked vault never hard-503s an authenticated client, and an
 * expired/absent token always gets the 401 challenge so the client can silently
 * refresh (which works while locked) instead of the endpoint going dark.
 */

interface FakeOpts {
  setupComplete?: boolean;
  storeLocked?: boolean;
  vaultUnlocked?: boolean;
  bearer?: string;
  oauthToken?: string;
  publicUrl?: string;
}

function fakeApp(opts: FakeOpts): AppState {
  const locked = (opts.storeLocked ?? false) || !(opts.vaultUnlocked ?? true);
  return {
    isSetupComplete: async () => opts.setupComplete ?? true,
    get locked() {
      return locked;
    },
    unlockUrl: () => opts.publicUrl ?? null,
    store: {
      locked: opts.storeLocked ?? false,
      get: () => {
        if (opts.storeLocked) throw new Error("store is locked");
        return { mcpBearerToken: opts.bearer };
      },
    },
    oauth: { validateAccessToken: (t: string) => t === opts.oauthToken },
  } as unknown as AppState;
}

function fakeReq(token?: string): Request {
  return {
    header: (name: string) => (name.toLowerCase() === "authorization" && token ? `Bearer ${token}` : undefined),
    protocol: "http",
    get: (name: string) => (name.toLowerCase() === "host" ? "192.168.0.229:8787" : undefined),
  } as unknown as Request;
}

function fakeRes() {
  const out = { status: 0, body: undefined as any, headers: {} as Record<string, string> };
  const res = {
    status: (code: number) => ((out.status = code), res),
    set: (name: string, value: string) => ((out.headers[name] = value), res),
    json: (body: unknown) => ((out.body = body), res),
  };
  return { res: res as unknown as Response, out };
}

async function run(app: AppState, token?: string) {
  const { res, out } = fakeRes();
  let nexted = false;
  await mcpAuth(app)(fakeReq(token), res, () => {
    nexted = true;
  });
  return { out, nexted };
}

beforeEach(() => {
  // The unlock URL is a property of the fake app; keep the ambient env out of it.
  vi.stubEnv("SKELETON_KEY_PUBLIC_URL", "");
});
afterEach(() => {
  vi.unstubAllEnvs();
});

describe("mcpAuth", () => {
  it("passes a valid OAuth token through even while the vault is locked", async () => {
    const app = fakeApp({ storeLocked: true, vaultUnlocked: false, oauthToken: "good-oauth" });
    const { nexted } = await run(app, "good-oauth");
    expect(nexted).toBe(true);
  });

  it("passes the static bearer when the store is unlocked", async () => {
    const { nexted } = await run(fakeApp({ bearer: "static-token" }), "static-token");
    expect(nexted).toBe(true);
  });

  it("challenges (401) — not 503 — when locked with an expired/invalid token, so the client can refresh", async () => {
    const app = fakeApp({ storeLocked: true, vaultUnlocked: false });
    const { out, nexted } = await run(app, "expired-token");
    expect(nexted).toBe(false);
    expect(out.status).toBe(401);
    expect(out.headers["WWW-Authenticate"]).toContain("oauth-protected-resource");
  });

  it("adds unlock guidance to the challenge when locked and a public URL is pinned", async () => {
    const app = fakeApp({ storeLocked: true, vaultUnlocked: false, publicUrl: "https://sk.lan:8787" });
    const { out } = await run(app, "expired-token");
    expect(out.status).toBe(401);
    expect(out.body.error).toMatch(/locked/i);
    expect(out.body.error).toContain("https://sk.lan:8787/");
  });

  it("does NOT put a Host-derived URL in the unlock guidance", async () => {
    // No public URL pinned → guidance must stay host-agnostic (anti-phishing).
    const app = fakeApp({ storeLocked: true, vaultUnlocked: false });
    const { out } = await run(app, "expired-token");
    expect(out.body.error).not.toContain("192.168.0.229");
  });

  it("401s with the discovery hint on a bad token when unlocked", async () => {
    const { out, nexted } = await run(fakeApp({ bearer: "static-token" }), "wrong");
    expect(nexted).toBe(false);
    expect(out.status).toBe(401);
    expect(out.headers["WWW-Authenticate"]).toContain("oauth-protected-resource");
  });

  it("401s when no token is presented", async () => {
    const { out, nexted } = await run(fakeApp({}));
    expect(nexted).toBe(false);
    expect(out.status).toBe(401);
  });

  it("503s (without a Host-derived URL) until setup completes", async () => {
    const { out, nexted } = await run(fakeApp({ setupComplete: false }), "anything");
    expect(nexted).toBe(false);
    expect(out.status).toBe(503);
    expect(out.body.error).not.toContain("192.168.0.229");
  });
});
