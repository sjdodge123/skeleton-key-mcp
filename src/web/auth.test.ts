import { describe, it, expect } from "vitest";
import type { Request, Response } from "express";
import { mcpAuth } from "./auth.js";
import type { AppState } from "../app.js";

/**
 * mcpAuth behavior matrix, in particular the locked-vault paths: a locked vault
 * must NOT hard-503 authenticated clients (sessions connect; tools degrade with
 * unlock guidance), while an unverifiable static bearer against a locked store
 * gets a 503 whose body says how to recover.
 */

// The URL assertions below exercise the Host-header fallback path.
delete process.env.SKELETON_KEY_PUBLIC_URL;

interface FakeOpts {
  setupComplete?: boolean;
  storeLocked?: boolean;
  vaultUnlocked?: boolean;
  bearer?: string;
  oauthToken?: string;
}

function fakeApp(opts: FakeOpts): AppState {
  return {
    isSetupComplete: async () => opts.setupComplete ?? true,
    store: {
      locked: opts.storeLocked ?? false,
      get: () => {
        if (opts.storeLocked) throw new Error("store is locked");
        return { mcpBearerToken: opts.bearer };
      },
    },
    vault: { unlocked: opts.vaultUnlocked ?? true },
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
    status: (code: number) => {
      out.status = code;
      return res;
    },
    set: (name: string, value: string) => {
      out.headers[name] = value;
      return res;
    },
    json: (body: unknown) => {
      out.body = body;
      return res;
    },
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

describe("mcpAuth", () => {
  it("passes a valid OAuth token through even while the vault is locked", async () => {
    const app = fakeApp({ storeLocked: true, vaultUnlocked: false, oauthToken: "good-oauth" });
    const { nexted } = await run(app, "good-oauth");
    expect(nexted).toBe(true);
  });

  it("passes the static bearer when the store is unlocked", async () => {
    const app = fakeApp({ bearer: "static-token" });
    const { nexted } = await run(app, "static-token");
    expect(nexted).toBe(true);
  });

  it("503s with unlock guidance when the store is locked and the token isn't OAuth", async () => {
    const app = fakeApp({ storeLocked: true, vaultUnlocked: false });
    const { out, nexted } = await run(app, "maybe-the-static-bearer");
    expect(nexted).toBe(false);
    expect(out.status).toBe(503);
    expect(out.body.error).toMatch(/locked/i);
    expect(out.body.error).toContain("http://192.168.0.229:8787/");
  });

  it("401s with the discovery hint on a bad token when unlocked", async () => {
    const app = fakeApp({ bearer: "static-token" });
    const { out, nexted } = await run(app, "wrong");
    expect(nexted).toBe(false);
    expect(out.status).toBe(401);
    expect(out.headers["WWW-Authenticate"]).toContain("oauth-protected-resource");
  });

  it("401s when no token is presented", async () => {
    const { out, nexted } = await run(fakeApp({}));
    expect(nexted).toBe(false);
    expect(out.status).toBe(401);
  });

  it("503s with the wizard URL until setup completes", async () => {
    const { out, nexted } = await run(fakeApp({ setupComplete: false }), "anything");
    expect(nexted).toBe(false);
    expect(out.status).toBe(503);
    expect(out.body.error).toContain("http://192.168.0.229:8787/");
  });
});
