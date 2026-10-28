import { describe, it, expect, beforeEach, afterEach, vi } from "vitest";
import { mkdtemp, rm, writeFile } from "node:fs/promises";
import { tmpdir } from "node:os";
import path from "node:path";
import { createHash } from "node:crypto";
import type { Server } from "node:http";
import { generateTotpCode, generateTotpSecret } from "../lib/totp.js";

/**
 * TOTP attempt limiting over real HTTP with a real AppState and the full app
 * (`buildHttpApp`), so every gate is wired exactly as in production. The
 * invariants: wrong codes lead to a lockout; during a lockout even the correct
 * code is refused with the same 429, so nothing about it leaks; the lockout
 * expires; the per-client and global budgets both hold; and no code ever
 * reaches the audit log.
 */

let dir: string;
let app: any;
let httpServer: Server;
let port: number;
let v4: string;
let v6: string;

const TOTP_SECRET = generateTotpSecret();
const code = () => generateTotpCode(TOTP_SECRET);
/** A code that is certainly wrong right now (offset from the current one). */
const wrong = (i = 1) => String((Number(code()) + i) % 1_000_000).padStart(6, "0");
const used: string[] = [];

beforeEach(async () => {
  vi.resetModules();
  dir = await mkdtemp(path.join(tmpdir(), "sk-ratelimit-"));
  process.env.SKELETON_KEY_DATA_DIR = dir;
  vi.stubEnv("SKELETON_KEY_PUBLIC_URL", "");
  vi.stubEnv("SKELETON_KEY_UNLOCK_KEY_FILE", path.join(dir, "unlock-key"));

  const { AppState } = await import("../app.js");
  const { buildHttpApp } = await import("./server.js");
  const { paths } = await import("../config/paths.js");
  app = await AppState.create();
  await app.store.initialize("wizard-passphrase");
  await app.store.update({ totpSecret: TOTP_SECRET });
  await writeFile(paths.setupComplete, JSON.stringify({ completedAt: "test" }), { mode: 0o600 });

  // Dual-stack listen, so 127.0.0.1 and ::1 arrive as two different clients.
  await new Promise<void>((resolve) => {
    httpServer = buildHttpApp(app).listen(0, "::", () => resolve());
  });
  port = (httpServer.address() as { port: number }).port;
  v4 = `http://127.0.0.1:${port}`;
  v6 = `http://[::1]:${port}`;
  used.length = 0;
});

afterEach(async () => {
  vi.useRealTimers();
  vi.unstubAllEnvs();
  httpServer.close();
  app.audit.close();
  app.oauth.close();
  await rm(dir, { recursive: true, force: true });
});

async function audit(totp: string, base = v4): Promise<{ status: number; retryAfter: string | null; json: any }> {
  used.push(totp);
  const r = await fetch(`${base}/api/audit/recent`, {
    method: "POST",
    headers: { "content-type": "application/json" },
    body: JSON.stringify({ totp }),
  });
  return { status: r.status, retryAfter: r.headers.get("retry-after"), json: await r.json().catch(() => ({})) };
}

function form(url: string, body: Record<string, string>): Promise<Response> {
  if (body.totp) used.push(body.totp);
  return fetch(url, {
    method: "POST",
    redirect: "manual",
    headers: { "content-type": "application/x-www-form-urlencoded" },
    body: new URLSearchParams(body).toString(),
  });
}

/** Drain the 5-failure per-client budget from `base`. */
async function lockOut(base = v4): Promise<void> {
  for (let i = 1; i <= 4; i++) expect((await audit(wrong(i), base)).status).toBe(403);
  const fifth = await audit(wrong(5), base);
  expect(fifth.status).toBe(429);
  expect(Number(fifth.retryAfter)).toBe(60);
}

describe("TOTP attempt limiting", () => {
  it("N wrong codes lead to a lockout (429 + Retry-After)", async () => {
    await lockOut();
    const next = await audit(wrong(6));
    expect(next.status).toBe(429);
    expect(Number(next.retryAfter)).toBeGreaterThan(0);
    expect(next.json.error).toMatch(/Too many wrong authenticator codes/);
  });

  it("during a lockout the correct code is refused with the SAME response as a wrong one", async () => {
    await lockOut();
    const right = await audit(code());
    const bad = await audit(wrong(7));
    expect(right.status).toBe(429);
    expect(right).toEqual(bad);
    expect(right.json.entries).toBeUndefined();
  });

  it("refuses without evaluating the code while locked out", async () => {
    await lockOut();
    // The secret is never even read, so no code can have been compared.
    const secretRead = vi.spyOn(app.store, "get");
    const counted = vi.spyOn(app.totpLimiter, "fail");
    await audit(code());
    await audit(wrong(8));
    expect(secretRead).not.toHaveBeenCalled();
    expect(counted).not.toHaveBeenCalled();
    // And in-handler too, should a gate ever be mounted without the middleware.
    expect(app.checkTotp(code(), { client: "127.0.0.1", via: "test" })).toEqual({ ok: false, retryAfterSeconds: expect.any(Number) });
    expect(secretRead).not.toHaveBeenCalled();
  });

  it("the lockout expires", async () => {
    vi.useFakeTimers({ toFake: ["Date"], now: Date.now() });
    await lockOut();
    expect((await audit(code())).status).toBe(429);
    vi.setSystemTime(Date.now() + 61_000);
    const r = await audit(code());
    expect(r.status).toBe(200);
    expect(Array.isArray(r.json.entries)).toBe(true);
  });

  it("a correct code resets the client's counter", async () => {
    for (let i = 1; i <= 4; i++) expect((await audit(wrong(i))).status).toBe(403);
    expect((await audit(code())).status).toBe(200);
    // A fresh per-client budget: four more wrong codes are still only 403s.
    for (let i = 1; i <= 4; i++) expect((await audit(wrong(i))).status).toBe(403);
  });

  it("the per-client budget locks out only that client", async () => {
    await lockOut(v4);
    expect((await audit(code(), v4)).status).toBe(429);
    expect((await audit(code(), v6)).status).toBe(200);
  });

  it("the global budget locks out every client, including ones that never failed", async () => {
    // 10 failures spread over addresses no per-client limit would catch.
    for (let i = 0; i < 10; i++) app.checkTotp(wrong(i + 1), { client: `198.51.100.${i}`, via: "test" });
    const r = await audit(code(), v6);
    expect(r.status).toBe(429);
    expect((await audit(code(), v4)).status).toBe(429);
    expect(app.totpLimiter.blocked("203.0.113.1")?.scope).toBe("global");
  });

  it("covers the wizard's /setup/totp/verify: 429 instead of {valid}", async () => {
    const { rm: remove } = await import("node:fs/promises");
    const { paths } = await import("../config/paths.js");
    await remove(paths.setupComplete); // the route is setup-only
    const verify = async (token: string) => {
      used.push(token);
      const r = await fetch(`${v4}/api/setup/totp/verify`, {
        method: "POST",
        headers: { "content-type": "application/json" },
        body: JSON.stringify({ token }),
      });
      return { status: r.status, json: await r.json() };
    };
    for (let i = 1; i <= 4; i++) expect(await verify(wrong(i))).toEqual({ status: 200, json: { valid: false } });
    expect((await verify(wrong(5))).status).toBe(429);
    const right = await verify(code());
    expect(right.status).toBe(429);
    expect(right.json.valid).toBeUndefined();
  });

  it("a locked-out consent POST for an unknown client gets no consent page", async () => {
    await lockOut();
    const r = await form(`${v4}/oauth/authorize/decision`, { client_id: "bogus", redirect_uri: "https://evil.example/cb", action: "approve", totp: code() });
    expect(r.status).toBe(429);
    const body = await r.text();
    expect(body).not.toMatch(/<form|evil\.example/);
  });

  it("covers the OAuth consent screen: 429 page while locked out, Deny still works", async () => {
    const client = app.oauth.registerClient({ client_name: "Probe", redirect_uris: ["http://localhost:9/cb"] });
    const fields = { client_id: client.client_id, redirect_uri: "http://localhost:9/cb", state: "s", code_challenge: "c" };
    for (let i = 1; i <= 4; i++) {
      const r = await form(`${v4}/oauth/authorize/decision`, { ...fields, action: "approve", totp: wrong(i) });
      expect(r.status).toBe(200);
      expect(await r.text()).toMatch(/Invalid authenticator code/);
    }
    const fifth = await form(`${v4}/oauth/authorize/decision`, { ...fields, action: "approve", totp: wrong(5) });
    expect(fifth.status).toBe(429);
    const right = await form(`${v4}/oauth/authorize/decision`, { ...fields, action: "approve", totp: code() });
    expect(right.status).toBe(429);
    expect(right.headers.get("retry-after")).toBeTruthy();
    expect(right.headers.get("location")).toBeNull(); // no auth code issued
    expect(await right.text()).toMatch(/Too many wrong authenticator codes/);
    const deny = await form(`${v4}/oauth/authorize/decision`, { ...fields, action: "deny" });
    expect(deny.status).toBe(302);
    expect(deny.headers.get("location")).toMatch(/error=access_denied/);
  });

  it("covers the credential hand-off form: 429 before the secret is read", async () => {
    Object.defineProperty(app.vault, "unlocked", { value: true, configurable: true });
    app.vault.createLoginItem = vi.fn();
    await lockOut();
    const req = app.credentialRequests.create({ name: "x", host: "h", reason: "r" });
    const r = await form(`${v4}/credential/${req.id}`, { formToken: req.formToken, totp: code(), secret: "hunter2-hunter2" });
    expect(r.status).toBe(429);
    expect(await r.text()).toMatch(/Too many wrong authenticator codes/);
    expect(app.vault.createLoginItem).not.toHaveBeenCalled();
    expect(app.credentialRequests.get(req.id).status).toBe("pending");
  });

  it("audits failures, lockouts and refusals — and never the code", async () => {
    await lockOut();
    for (let i = 0; i < 20; i++) await audit(i % 2 ? code() : wrong(9));
    const entries = app.audit.recent(1000).filter((e: any) => e.tier === "auth");
    const tools = entries.map((e: any) => e.tool);
    expect(tools.filter((t: string) => t === "auth.totp_failed")).toHaveLength(5);
    expect(tools).toContain("auth.totp_lockout");
    // 21 refusals in one burst coalesce to a single entry (throttled).
    expect(tools.filter((t: string) => t === "auth.totp_refused")).toHaveLength(1);
    expect(entries.every((e: any) => e.target === "127.0.0.1" && e.status === "denied")).toBe(true);
    const emptyDigest = createHash("sha256").update(JSON.stringify({})).digest("hex").slice(0, 32);
    expect(entries.every((e: any) => e.argsDigest === emptyDigest)).toBe(true);
    const dump = JSON.stringify(app.audit.recent(1000));
    for (const c of [...new Set(used), TOTP_SECRET]) expect(dump).not.toContain(c);
  });
});

describe("OAuth endpoint request limits", () => {
  it("/oauth/register allows 20 per 10 minutes per client", async () => {
    const reg = () =>
      fetch(`${v4}/oauth/register`, {
        method: "POST",
        headers: { "content-type": "application/json" },
        body: JSON.stringify({ client_name: "c", redirect_uris: ["http://localhost:9/cb"] }),
      });
    for (let i = 0; i < 20; i++) expect((await reg()).status).toBe(201);
    const over = await reg();
    expect(over.status).toBe(429);
    expect(Number(over.headers.get("retry-after"))).toBeGreaterThan(0);
    expect((await over.json()).error).toBe("temporarily_unavailable");
  });

  it("/oauth/token allows a normal refresh cadence and refuses a flood", async () => {
    const tok = () => form(`${v4}/oauth/token`, { grant_type: "refresh_token", refresh_token: "nope" });
    for (let i = 0; i < 60; i++) expect((await tok()).status).toBe(400); // invalid_grant, not limited
    expect((await tok()).status).toBe(429);
    // Another client is unaffected.
    expect((await form(`${v6}/oauth/token`, { grant_type: "refresh_token", refresh_token: "nope" })).status).toBe(400);
  });
});

describe("every TOTP route is gated twice: middleware AND handler", () => {
  /** Each TOTP-gated route, with a body that gets its handler as far as the
   *  TOTP check. `prep` runs first (returns the path when it's dynamic). */
  const ROUTES: {
    name: string;
    form?: true;
    preSetup?: true;
    path: string | (() => string);
    body: (totp: string) => Record<string, string>;
  }[] = [
    { name: "autounlock status", path: "/api/store/autounlock/status", body: (totp) => ({ totp }) },
    { name: "autounlock enable", path: "/api/store/autounlock/enable", body: (totp) => ({ totp }) },
    { name: "autounlock disable", path: "/api/store/autounlock/disable", body: (totp) => ({ totp }) },
    { name: "vault server", path: "/api/vault/server", body: (totp) => ({ totp, serverUrl: "https://vault.example" }) },
    { name: "setup totp verify", preSetup: true, path: "/api/setup/totp/verify", body: (token) => ({ token }) },
    { name: "audit recent", path: "/api/audit/recent", body: (totp) => ({ totp }) },
    { name: "oauth client revoke", path: "/api/oauth/clients/some-client/revoke", body: (totp) => ({ totp }) },
    { name: "snapshots list", path: "/api/snapshots", body: (totp) => ({ totp }) },
    { name: "credential requests", path: "/api/credential-requests", body: (totp) => ({ totp }) },
    { name: "snapshot download", path: "/api/snapshots/20260101-000000/download", body: (totp) => ({ totp }) },
    {
      name: "oauth consent",
      form: true,
      path: "/oauth/authorize/decision",
      body: (totp) => {
        const c = app.oauth.registerClient({ client_name: "Probe", redirect_uris: ["http://localhost:9/cb"] });
        return { client_id: c.client_id, redirect_uri: "http://localhost:9/cb", state: "s", code_challenge: "c", action: "approve", totp };
      },
    },
    {
      name: "credential link",
      form: true,
      path: "/credential/:id",
      body: (totp) => ({ totp, secret: "hunter2-hunter2" }),
    },
  ];

  async function hit(route: (typeof ROUTES)[number]): Promise<Response> {
    let path = typeof route.path === "string" ? route.path : route.path();
    let body = route.body(code());
    if (route.path === "/credential/:id") {
      const req = app.credentialRequests.create({ name: "x", host: "h", reason: "r" });
      path = `/credential/${req.id}`;
      body = { ...body, formToken: req.formToken };
    }
    if (route.form) return form(`${v4}${path}`, body);
    used.push(code());
    return fetch(`${v4}${path}`, { method: "POST", headers: { "content-type": "application/json" }, body: JSON.stringify(body) });
  }

  beforeEach(() => {
    Object.defineProperty(app.vault, "unlocked", { value: true, configurable: true });
    app.vault.createLoginItem = vi.fn();
    // A global lockout: every client is refused, whatever it sends.
    for (let i = 0; i < 10; i++) app.checkTotp(wrong(i + 1), { client: `198.51.100.${i}`, via: "test" });
  });

  for (const route of ROUTES) {
    it(`${route.name}: 429 + Retry-After from the middleware, and from the handler if the middleware is bypassed`, async () => {
      const { paths } = await import("../config/paths.js");
      const { rm: remove } = await import("node:fs/promises");
      if (route.preSetup) await remove(paths.setupComplete);

      const viaMiddleware = await hit(route);
      expect(viaMiddleware.status).toBe(429);
      expect(Number(viaMiddleware.headers.get("retry-after"))).toBeGreaterThan(0);

      // Let the middleware through once: the handler's own check must still refuse.
      const gate = vi.spyOn(app, "totpLockout").mockImplementationOnce(() => null);
      const viaHandler = await hit(route);
      expect(gate).toHaveBeenCalled();
      expect(viaHandler.status).toBe(429);
      expect(Number(viaHandler.headers.get("retry-after"))).toBeGreaterThan(0);
      gate.mockRestore();
    });
  }

  it("verifyTotpCode is called only from src/app.ts (everything else must go through checkTotp)", async () => {
    const { readdir, readFile } = await import("node:fs/promises");
    const srcDir = path.resolve(__dirname, "..");
    const files = (await readdir(srcDir, { recursive: true })).filter((f) => f.endsWith(".ts") && !f.endsWith(".test.ts"));
    const users: string[] = [];
    for (const f of files) if (/\bverifyTotpCode\b/.test(await readFile(path.join(srcDir, f), "utf8"))) users.push(f.split(path.sep).join("/"));
    expect(users.sort()).toEqual(["app.ts", "lib/totp.ts"]);
  });
});

describe("master passphrase attempt limiting (/api/store/unlock)", () => {
  let unlocks: string[];

  beforeEach(() => {
    // The limiter is under test, not argon2: stub the derivation (each real
    // one is ~1 s of CPU), keeping its contract — throws on a wrong passphrase.
    unlocks = [];
    vi.spyOn(app.store, "unlock").mockImplementation(async (p: unknown) => {
      unlocks.push(String(p));
      if (p !== "wizard-passphrase") throw new Error("Incorrect passphrase or corrupted bootstrap store.");
    });
    app.postUnlock = vi.fn(async () => {});
  });

  const unlock = async (passphrase: string, base = v4) => {
    const r = await fetch(`${base}/api/store/unlock`, {
      method: "POST",
      headers: { "content-type": "application/json" },
      body: JSON.stringify({ passphrase }),
    });
    return { status: r.status, retryAfter: r.headers.get("retry-after"), json: await r.json().catch(() => ({})) };
  };

  it("locks out after 5 wrong passphrases and then refuses the right one WITHOUT deriving", async () => {
    for (let i = 1; i <= 4; i++) expect((await unlock(`wrong-${i}`)).status).toBe(400);
    const fifth = await unlock("wrong-5");
    expect(fifth.status).toBe(429);
    expect(Number(fifth.retryAfter)).toBe(60);
    const right = await unlock("wizard-passphrase");
    expect(right.status).toBe(429);
    expect(right.json.error).toMatch(/Too many wrong passphrases/);
    expect(unlocks).toHaveLength(5); // the sixth never reached the store
    expect((await unlock("wizard-passphrase", v6)).status).toBe(200); // another client is unaffected
  });

  it("has its own budget, separate from TOTP", async () => {
    for (let i = 0; i < 10; i++) app.checkTotp(wrong(i + 1), { client: `198.51.100.${i}`, via: "test" });
    expect((await unlock("wizard-passphrase")).status).toBe(200);
  });

  it("runs one derivation at a time: a parallel attempt is refused as busy", async () => {
    let release!: () => void;
    (app.store.unlock as any).mockImplementationOnce(() => new Promise<void>((r) => (release = r)));
    const first = app.unlockWithPassphrase("wizard-passphrase", { client: "203.0.113.1", via: "test" });
    const second = await app.unlockWithPassphrase("wizard-passphrase", { client: "203.0.113.2", via: "test" });
    expect(second).toEqual({ retryAfterSeconds: 1, busy: true });
    release();
    expect(await first).toBeNull();
  });

  it("audits failures and the lockout, logs the lockout to stdout with the client, and never the passphrase", async () => {
    const warn = vi.spyOn(console, "warn").mockImplementation(() => {});
    for (let i = 1; i <= 5; i++) await unlock(`sekrit-guess-${i}`);
    await unlock("wizard-passphrase");
    const tools = app.audit.recent(100).map((e: any) => e.tool);
    expect(tools.filter((t: string) => t === "auth.passphrase_failed")).toHaveLength(5);
    expect(tools).toContain("auth.passphrase_lockout");
    expect(tools).toContain("auth.passphrase_refused");
    expect(warn).toHaveBeenCalledWith(expect.stringMatching(/^\[skeleton-key\] PASSPHRASE lockout: client until \S+Z, last client 127\.0\.0\.1$/));
    const dump = JSON.stringify(app.audit.recent(100)) + JSON.stringify(warn.mock.calls);
    expect(dump).not.toMatch(/sekrit-guess|wizard-passphrase/);
    warn.mockRestore();
  });
});
