import { describe, it, expect, beforeEach, afterEach, vi } from "vitest";
import { createHash, randomBytes } from "node:crypto";
import { mkdtemp, rm, writeFile } from "node:fs/promises";
import { tmpdir } from "node:os";
import path from "node:path";
import type { Server } from "node:http";
import type { Request } from "express";
import { authenticator } from "otplib";
import type { AppState } from "../app.js";
import { bodyOf, errorHandler, paramStr } from "./http-util.js";

/**
 * The full HTTP app (buildHttpApp) under Express 5: the OAuth 2.1 flow end to
 * end into the stateful MCP endpoint, plus the Express 5 behaviour changes this
 * code had to absorb — `req.body` left undefined when no parser matched,
 * rejected async handlers reaching the error handler, and that error handler
 * never echoing a body, a stack or the request host.
 */

let dir: string;
let app: AppState;
let httpServer: Server;
let root: string;

const TOTP_SECRET = authenticator.generateSecret();
const REDIRECT = "http://127.0.0.1:9/callback";

beforeEach(async () => {
  // Fresh modules per test: config/paths binds the data dir at import time.
  vi.resetModules();
  vi.stubEnv("SKELETON_KEY_PUBLIC_URL", "");
  dir = await mkdtemp(path.join(tmpdir(), "sk-express5-"));
  process.env.SKELETON_KEY_DATA_DIR = dir;
  const { AppState } = await import("../app.js");
  const { paths } = await import("../config/paths.js");
  const { buildHttpApp } = await import("./server.js");
  app = await AppState.create();
  const ex = buildHttpApp(app);
  await new Promise<void>((resolve) => {
    httpServer = ex.listen(0, "127.0.0.1", () => resolve());
  });
  root = `http://127.0.0.1:${(httpServer.address() as { port: number }).port}`;

  // Unlocked store + completed setup + enrolled TOTP: the post-setup state.
  const r = await fetch(`${root}/api/store/init`, {
    method: "POST",
    headers: { "content-type": "application/json" },
    body: JSON.stringify({ passphrase: "wizard-passphrase" }),
  });
  expect(r.status).toBe(200);
  await app.store.update({ totpSecret: TOTP_SECRET });
  await writeFile(paths.setupComplete, JSON.stringify({ completedAt: "test" }), { mode: 0o600 });
});

afterEach(async () => {
  vi.unstubAllEnvs();
  vi.restoreAllMocks();
  httpServer.close();
  app.audit.close();
  app.oauth.close();
  await rm(dir, { recursive: true, force: true });
});

const form = (body: Record<string, string>): RequestInit => ({
  method: "POST",
  headers: { "content-type": "application/x-www-form-urlencoded" },
  body: new URLSearchParams(body).toString(),
  redirect: "manual",
});

const MCP_H = { "content-type": "application/json", accept: "application/json, text/event-stream" };

function parseSse(text: string): any {
  const line = text.split("\n").find((l) => l.startsWith("data:"));
  return JSON.parse(line ? line.slice(5).trim() : text);
}

async function registerClient(): Promise<string> {
  const r = await fetch(`${root}/oauth/register`, {
    method: "POST",
    headers: { "content-type": "application/json" },
    body: JSON.stringify({ client_name: "Claude", redirect_uris: [REDIRECT] }),
  });
  expect(r.status).toBe(201);
  return (await r.json()).client_id;
}

describe("OAuth 2.1 flow end to end into the MCP endpoint", () => {
  it("registers, consents with TOTP, redeems with PKCE, then initializes an MCP session with the access token", async () => {
    const meta = await (await fetch(`${root}/.well-known/oauth-authorization-server`)).json();
    expect(meta.token_endpoint).toBe(`${root}/oauth/token`);

    const client_id = await registerClient();
    const verifier = randomBytes(32).toString("base64url");
    const challenge = createHash("sha256").update(verifier).digest("base64url");

    const q = new URLSearchParams({
      client_id, redirect_uri: REDIRECT, response_type: "code", code_challenge: challenge, code_challenge_method: "S256", state: "xyz",
    });
    const consent = await fetch(`${root}/oauth/authorize?${q}`);
    expect(consent.status).toBe(200);
    expect(await consent.text()).toContain("Authorize an AI agent");

    const decision = await fetch(
      `${root}/oauth/authorize/decision`,
      form({ client_id, redirect_uri: REDIRECT, state: "xyz", code_challenge: challenge, totp: authenticator.generate(TOTP_SECRET), action: "approve" }),
    );
    expect(decision.status).toBe(302);
    const location = new URL(decision.headers.get("location")!);
    expect(`${location.origin}${location.pathname}`).toBe(REDIRECT);
    expect(location.searchParams.get("state")).toBe("xyz");
    const code = location.searchParams.get("code")!;
    expect(code).toBeTruthy();

    const tok = await fetch(
      `${root}/oauth/token`,
      form({ grant_type: "authorization_code", code, client_id, redirect_uri: REDIRECT, code_verifier: verifier }),
    );
    expect(tok.status).toBe(200);
    const tokens = await tok.json();
    expect(tokens.token_type).toBe("Bearer");

    // Without a token the MCP endpoint challenges with the RFC 9728 hint.
    const anon = await fetch(`${root}/mcp`, { method: "POST", headers: MCP_H, body: "{}" });
    expect(anon.status).toBe(401);
    expect(anon.headers.get("www-authenticate")).toContain("/.well-known/oauth-protected-resource");

    const auth = { ...MCP_H, authorization: `Bearer ${tokens.access_token}` };
    const init = await fetch(`${root}/mcp`, {
      method: "POST",
      headers: auth,
      body: JSON.stringify({ jsonrpc: "2.0", id: 1, method: "initialize", params: { protocolVersion: "2024-11-05", capabilities: {}, clientInfo: { name: "t", version: "1" } } }),
    });
    expect(init.status).toBe(200);
    const sid = init.headers.get("mcp-session-id");
    expect(sid).toBeTruthy();
    expect(parseSse(await init.text()).result?.serverInfo).toBeTruthy();

    const SH = { ...auth, "mcp-session-id": sid! };
    await fetch(`${root}/mcp`, { method: "POST", headers: SH, body: JSON.stringify({ jsonrpc: "2.0", method: "notifications/initialized" }) });
    const list = await fetch(`${root}/mcp`, { method: "POST", headers: SH, body: JSON.stringify({ jsonrpc: "2.0", id: 2, method: "tools/list", params: {} }) });
    expect(list.status).toBe(200);
    const names = (parseSse(await list.text()).result?.tools ?? []).map((t: { name: string }) => t.name);
    expect(names).toContain("get_started");

    // Terminating the session needs auth too; with it, the session is gone.
    const anonDel = await fetch(`${root}/mcp`, { method: "DELETE", headers: { ...MCP_H, "mcp-session-id": sid! } });
    expect(anonDel.status).toBe(401);
    const del = await fetch(`${root}/mcp`, { method: "DELETE", headers: SH });
    expect(del.status).toBe(200);
    const stale = await fetch(`${root}/mcp`, { method: "POST", headers: SH, body: JSON.stringify({ jsonrpc: "2.0", id: 3, method: "tools/list", params: {} }) });
    expect(stale.status).toBe(404);
    expect((await stale.json()).error.code).toBe(-32001);

    // Refresh rotates the pair; the old access token is then revocable.
    const refreshed = await fetch(`${root}/oauth/token`, form({ grant_type: "refresh_token", refresh_token: tokens.refresh_token, client_id }));
    expect(refreshed.status).toBe(200);
    const next = await refreshed.json();
    expect(next.access_token).not.toBe(tokens.access_token);

    const revoked = await fetch(`${root}/oauth/revoke`, form({ token: next.access_token }));
    expect(revoked.status).toBe(200);
    const after = await fetch(`${root}/mcp`, {
      method: "POST",
      headers: { ...MCP_H, authorization: `Bearer ${next.access_token}` },
      body: JSON.stringify({ jsonrpc: "2.0", id: 1, method: "initialize", params: { protocolVersion: "2024-11-05", capabilities: {}, clientInfo: { name: "t", version: "1" } } }),
    });
    expect(after.status).toBe(401);

  });

  describe("negative paths", () => {
    const verifier = randomBytes(32).toString("base64url");
    const challenge = createHash("sha256").update(verifier).digest("base64url");
    const decide = (client_id: string, over: Record<string, string>) =>
      fetch(
        `${root}/oauth/authorize/decision`,
        form({ client_id, redirect_uri: REDIRECT, state: "s1", code_challenge: challenge, totp: authenticator.generate(TOTP_SECRET), action: "approve", ...over }),
      );
    const codeFor = async (client_id: string): Promise<string> =>
      new URL((await decide(client_id, {})).headers.get("location")!).searchParams.get("code")!;
    const redeem = (client_id: string, code: string, code_verifier: string) =>
      fetch(`${root}/oauth/token`, form({ grant_type: "authorization_code", code, client_id, redirect_uri: REDIRECT, code_verifier }));

    it("a wrong TOTP re-renders the consent screen and issues no code", async () => {
      const client_id = await registerClient();
      const totp = authenticator.generate(TOTP_SECRET) === "000000" ? "111111" : "000000";
      const r = await decide(client_id, { totp });
      expect(r.status).toBe(200);
      expect(r.headers.get("location")).toBeNull();
      expect(await r.text()).toContain("Invalid authenticator code");
    });

    it("deny redirects with access_denied and echoes the state", async () => {
      const client_id = await registerClient();
      const r = await decide(client_id, { action: "deny" });
      expect(r.status).toBe(302);
      const loc = new URL(r.headers.get("location")!);
      expect(loc.searchParams.get("error")).toBe("access_denied");
      expect(loc.searchParams.get("state")).toBe("s1");
      expect(loc.searchParams.get("code")).toBeNull();
    });

    it("an unregistered redirect_uri on the decision is a 400, never a redirect", async () => {
      const client_id = await registerClient();
      const r = await decide(client_id, { redirect_uri: "http://127.0.0.1:9/elsewhere" });
      expect(r.status).toBe(400);
      expect(r.headers.get("location")).toBeNull();
    });

    it("a PKCE verifier mismatch is invalid_grant", async () => {
      const client_id = await registerClient();
      const code = await codeFor(client_id);
      const r = await redeem(client_id, code, randomBytes(32).toString("base64url"));
      expect(r.status).toBe(400);
      expect((await r.json()).error).toBe("invalid_grant");
    });

    it("a code cannot be redeemed twice", async () => {
      const client_id = await registerClient();
      const code = await codeFor(client_id);
      expect((await redeem(client_id, code, verifier)).status).toBe(200);
      const again = await redeem(client_id, code, verifier);
      expect(again.status).toBe(400);
      expect((await again.json()).error).toBe("invalid_grant");
    });
  });

  it("takes the first value of a duplicated query parameter on the consent screen", async () => {
    const client_id = await registerClient();
    const q = `client_id=${client_id}&client_id=bogus&redirect_uri=${encodeURIComponent(REDIRECT)}&response_type=code&code_challenge=abc&code_challenge_method=S256`;
    const r = await fetch(`${root}/oauth/authorize?${q}`);
    expect(r.status).toBe(200);
    expect(await r.text()).toContain(`value="${client_id}"`);
  });
});

describe("Express 5: a POST no body parser matched (req.body undefined)", () => {
  // text/plain is parsed by neither express.json nor express.urlencoded.
  const plain: RequestInit = { method: "POST", headers: { "content-type": "text/plain" }, body: "hello", redirect: "manual" };

  it("the OAuth token endpoint answers unsupported_grant_type, not a 500", async () => {
    const r = await fetch(`${root}/oauth/token`, plain);
    expect(r.status).toBe(400);
    expect(await r.json()).toEqual({ error: "unsupported_grant_type" });
  });

  it("the OAuth revoke endpoint still answers 200 (RFC 7009)", async () => {
    const r = await fetch(`${root}/oauth/revoke`, { method: "POST", redirect: "manual" });
    expect(r.status).toBe(200);
  });

  it("the TOTP-gated consent decision rejects with 400, not a 500", async () => {
    const r = await fetch(`${root}/oauth/authorize/decision`, plain);
    expect(r.status).toBe(400);
    expect(await r.text()).toBe("Invalid client or redirect_uri");
  });

  it("dynamic client registration rejects with invalid_client_metadata", async () => {
    const r = await fetch(`${root}/oauth/register`, plain);
    expect(r.status).toBe(400);
    expect((await r.json()).error).toBe("invalid_client_metadata");
  });

  it("the credential hand-off form treats it as a stale form (CSRF), and stores nothing", async () => {
    const createLoginItem = vi.fn();
    app.vault.createLoginItem = createLoginItem;
    const req = app.credentialRequests.create({ name: "n", host: "h", kind: "token", reason: "r" });
    const r = await fetch(`${root}/credential/${req.id}`, plain);
    expect(r.status).toBe(403);
    expect(await r.text()).toContain("Expired form");
    expect(createLoginItem).not.toHaveBeenCalled();
    expect(app.credentialRequests.get(req.id)!.status).toBe("pending");
  });

  it("TOTP-gated API routes fail validation with a 400", async () => {
    for (const p of ["/api/oauth/clients/abc/revoke", "/api/audit/recent", "/api/snapshots/abc/download", "/api/store/unlock"]) {
      const r = await fetch(`${root}${p}`, plain);
      expect(r.status, p).toBe(400);
    }
  });

  it("the MCP endpoint answers a JSON-RPC error, not a 500", async () => {
    const r = await fetch(`${root}/mcp`, {
      method: "POST",
      headers: { accept: "application/json, text/event-stream", authorization: `Bearer ${await bearer()}` },
    });
    expect(r.status).toBe(400);
    expect((await r.json()).jsonrpc).toBe("2.0");
  });
});

/** A valid OAuth access token, minted directly (the flow itself is tested above). */
async function bearer(): Promise<string> {
  const client = app.oauth.registerClient({ client_name: "t", redirect_uris: [REDIRECT] });
  const verifier = randomBytes(32).toString("base64url");
  const code = app.oauth.createAuthCode({
    client_id: client.client_id, redirect_uri: REDIRECT, scope: "mcp",
    code_challenge: createHash("sha256").update(verifier).digest("base64url"),
  });
  return app.oauth.redeemAuthCode({ code, client_id: client.client_id, redirect_uri: REDIRECT, code_verifier: verifier }).access_token;
}

describe("Express 5: the final error handler", () => {
  const SECRET = "correct-horse-battery-staple";

  function expectNoLeak(text: string): void {
    expect(text).not.toContain(SECRET);
    expect(text).not.toContain("127.0.0.1");
    expect(text).not.toMatch(/\n\s+at /); // no stack frames
    expect(text).not.toContain("SyntaxError");
  }

  it("a malformed JSON body gets a fixed 400 that never quotes the body", async () => {
    const r = await fetch(`${root}/api/store/unlock`, {
      method: "POST",
      headers: { "content-type": "application/json" },
      body: `{"passphrase": ${SECRET}}`,
    });
    expect(r.status).toBe(400);
    const text = await r.text();
    expect(JSON.parse(text)).toEqual({ error: "Bad request." });
    expectNoLeak(text);
  });

  it("an oversized body gets a fixed 413", async () => {
    const r = await fetch(`${root}/oauth/token`, {
      method: "POST",
      headers: { "content-type": "application/x-www-form-urlencoded" },
      body: `code=${"a".repeat(200_000)}`, // urlencoded's default limit is 100kb
    });
    expect(r.status).toBe(413);
    expect(await r.json()).toEqual({ error: "Request body too large." });
  });

  it("a rejected async handler reaches it as a generic 500 (Express 4 left it unhandled)", async () => {
    const logged = vi.spyOn(console, "error").mockImplementation(() => {});
    app.isSetupComplete = async () => {
      throw new Error(`disk read failed near ${SECRET}`);
    };
    const r = await fetch(`${root}/credential/whatever`);
    expect(r.status).toBe(500);
    const text = await r.text();
    expect(JSON.parse(text)).toEqual({ error: "Internal server error." });
    expectNoLeak(text);
    // Server faults are logged by name only; the message can quote anything.
    expect(logged).toHaveBeenCalledTimes(1);
    expect(String(logged.mock.calls[0]![0])).toBe("[skeleton-key] request failed: Error");
    expect(logged.mock.calls.flat().join(" ")).not.toContain(SECRET);
  });

  it("a malformed percent-encoded route param is a quiet 400 (router URIError), not a logged 500", async () => {
    const logged = vi.spyOn(console, "error").mockImplementation(() => {});
    const link = app.credentialRequests.create({ name: "n", host: "h", kind: "token", reason: "r" });
    for (const [method, p] of [["GET", `/credential/${link.id}%ZZ`], ["GET", "/credential/%ZZ"], ["DELETE", "/api/targets/%ZZ"]] as const) {
      const r = await fetch(`${root}${p}`, { method });
      expect(r.status, p).toBe(400);
      expect(await r.json()).toEqual({ error: "Bad request." });
    }
    // The raw param (here a live one-time link id) must not reach the log.
    expect(logged).not.toHaveBeenCalled();
  });

  it("a rejected MCP auth check answers 500 instead of hanging the request", async () => {
    vi.spyOn(console, "error").mockImplementation(() => {});
    app.isSetupComplete = async () => {
      throw new Error(`boom ${SECRET}`);
    };
    const r = await fetch(`${root}/mcp`, { method: "POST", headers: MCP_H, body: "{}", signal: AbortSignal.timeout(5000) });
    expect(r.status).toBe(500);
    expectNoLeak(await r.text());
  });
});

describe("Express 5: errors past the credential claim", () => {
  it("an unexpected throw after the claim releases the link instead of stranding it", async () => {
    vi.spyOn(console, "error").mockImplementation(() => {});
    Object.defineProperty(app.vault, "unlocked", { value: true, configurable: true });
    const createLoginItem = vi.fn();
    app.vault.createLoginItem = createLoginItem;
    const req = app.credentialRequests.create({
      name: "bot", host: "h", kind: "token", reason: "r",
      verify: { method: "GET", url: "http://127.0.0.1:9/probe", headers: { Authorization: "Bot {{value}}" }, timeoutMs: 1000 },
    });
    const record = app.audit.record.bind(app.audit);
    app.audit.record = (e) => {
      if (e.tool === "credential.verify") throw new Error("SQLITE_FULL");
      return record(e);
    };
    const r = await fetch(`${root}/credential/${req.id}`, form({ formToken: req.formToken, action: "submit", totp: authenticator.generate(TOTP_SECRET), secret: "tok-value" }));
    expect(r.status).toBe(500);
    expect(await r.text()).not.toContain("tok-value");
    expect(createLoginItem).not.toHaveBeenCalled();
    // Still claimable: the retry reaches the form again rather than "Already provided".
    expect(app.credentialRequests.claim(req.id)).toBe(true);
  });
});

describe("credential claim ownership", () => {
  it("a throw after this request released its claim never drops a concurrent submit's claim", async () => {
    vi.spyOn(console, "error").mockImplementation(() => {});
    Object.defineProperty(app.vault, "unlocked", { value: true, configurable: true });
    const req = app.credentialRequests.create({
      name: "bot", host: "h", kind: "token", reason: "r",
      verify: { method: "GET", url: "http://127.0.0.1:9/probe", headers: { Authorization: "Bot {{value}}" }, timeoutMs: 1000 },
    });
    // The probe fails, so the handler releases its claim and renders the form.
    // Simulate the race: right after that release a concurrent submit claims
    // the link, and rendering this request's response then throws.
    const store = app.credentialRequests;
    const release = store.release.bind(store);
    let releases = 0;
    store.release = (id: string) => {
      releases++;
      const out = release(id);
      if (releases === 1) {
        expect(store.claim(id)).toBe(true); // the concurrent submit
        throw new Error("render failed");
      }
      return out;
    };
    const r = await fetch(`${root}/credential/${req.id}`, form({ formToken: req.formToken, action: "submit", totp: authenticator.generate(TOTP_SECRET), secret: "tok-value" }));
    expect(r.status).toBe(500);
    expect(releases).toBe(1); // the catch did not release a second time
    expect(store.claim(req.id)).toBe(false); // the concurrent claim still stands
  });
});

describe("http-util narrowing helpers", () => {
  const req = (over: Partial<Request>): Request => over as Request;

  it("paramStr accepts only a non-empty string", () => {
    expect(paramStr(req({ params: { id: "abc" } }), "id")).toBe("abc");
    expect(paramStr(req({ params: { id: ["a", "b"] } as never }), "id")).toBeNull();
    expect(paramStr(req({ params: { id: "" } }), "id")).toBeNull();
    expect(paramStr(req({ params: {} }), "id")).toBeNull();
  });

  it("bodyOf reads a missing or non-object body as empty", () => {
    expect(bodyOf(req({ body: undefined }))).toEqual({});
    expect(bodyOf(req({ body: null }))).toEqual({});
    expect(bodyOf(req({ body: ["x"] }))).toEqual({});
    expect(bodyOf(req({ body: "x" }))).toEqual({});
    expect(bodyOf(req({ body: { a: "1" } }))).toEqual({ a: "1" });
  });
});

describe("errorHandler", () => {
  function run(err: unknown): { status: number; body: unknown } {
    const out = { status: 0, body: undefined as unknown };
    const res = {
      headersSent: false,
      status(code: number) { out.status = code; return res; },
      json(b: unknown) { out.body = b; return res; },
    };
    errorHandler(err, {} as Request, res as never, () => {});
    return out;
  }

  it("keeps an exposed client error's status (body-parser)", () => {
    expect(run(Object.assign(new Error("Unexpected token"), { status: 400, expose: true, type: "entity.parse.failed" })))
      .toEqual({ status: 400, body: { error: "Bad request." } });
  });

  it("keeps the router's 400 for a malformed route param (URIError, no expose)", () => {
    const logged = vi.spyOn(console, "error").mockImplementation(() => {});
    expect(run(Object.assign(new URIError("Failed to decode param '%ZZ'"), { status: 400 }))).toEqual({ status: 400, body: { error: "Bad request." } });
    expect(logged).not.toHaveBeenCalled();
  });

  it("treats an upstream error carrying a status as a server fault", () => {
    vi.spyOn(console, "error").mockImplementation(() => {});
    // Relaying a 401 would send MCP clients back into the OAuth flow.
    expect(run(Object.assign(new Error("vault said no"), { status: 401 }))).toEqual({ status: 500, body: { error: "Internal server error." } });
    expect(run(Object.assign(new Error("x"), { statusCode: 404 })).status).toBe(500);
    expect(run("a string").status).toBe(500);
  });
});
