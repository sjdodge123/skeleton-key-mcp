import { describe, it, expect, beforeEach, afterEach, vi } from "vitest";
import express from "express";
import { mkdtemp, rm, writeFile } from "node:fs/promises";
import { tmpdir } from "node:os";
import path from "node:path";
import type { Server } from "node:http";
import { authenticator } from "otplib";

/**
 * The admin activity view: the TOTP-gated audit endpoint (POST /api/audit/recent)
 * and the HTML page (GET /admin/activity). Same real-AppState-over-HTTP harness
 * as the auto-unlock route tests.
 */

let dir: string;
let app: any;
let httpServer: Server;
let base: string;
let root: string;

beforeEach(async () => {
  vi.resetModules();
  dir = await mkdtemp(path.join(tmpdir(), "sk-admin-"));
  process.env.SKELETON_KEY_DATA_DIR = dir;
  vi.stubEnv("SKELETON_KEY_PUBLIC_URL", "");

  const { AppState } = await import("../app.js");
  const { buildApiRouter } = await import("./routes.js");
  const { buildAdminRouter } = await import("./admin-routes.js");
  app = await AppState.create();
  const ex = express();
  ex.use(express.json());
  ex.use("/api", buildApiRouter(app));
  ex.use(buildAdminRouter(app));
  await new Promise<void>((resolve) => {
    httpServer = ex.listen(0, () => resolve());
  });
  const port = (httpServer.address() as { port: number }).port;
  base = `http://127.0.0.1:${port}/api`;
  root = `http://127.0.0.1:${port}`;
});

afterEach(async () => {
  vi.unstubAllEnvs();
  httpServer.close();
  app.audit.close();
  app.oauth.close();
  await rm(dir, { recursive: true, force: true });
});

async function post(p: string, body: unknown): Promise<{ status: number; json: any }> {
  const r = await fetch(base + p, { method: "POST", headers: { "content-type": "application/json" }, body: JSON.stringify(body) });
  return { status: r.status, json: await r.json().catch(() => ({})) };
}
async function initStore(): Promise<void> {
  expect((await post("/store/init", { passphrase: "wizard-passphrase" })).status).toBe(200);
}
async function markSetupComplete(secret: string): Promise<void> {
  await app.store.update({ totpSecret: secret });
  const { paths } = await import("../config/paths.js");
  await writeFile(paths.setupComplete, JSON.stringify({ completedAt: "test" }), { mode: 0o600 });
}

describe("admin activity view", () => {
  it("POST /api/audit/recent is TOTP-gated and returns entries without exposing raw args", async () => {
    await initStore();
    const secret = authenticator.generateSecret();
    await markSetupComplete(secret);
    app.audit.record({
      ts: new Date().toISOString(), tool: "unifi.unifi.get_settings", target: "unifi",
      tier: "read", args: { section: "SENTINELARG" }, status: "ok", detail: "read settings",
    });

    expect((await post("/audit/recent", {})).status).toBe(400); // missing code
    expect((await post("/audit/recent", { totp: "000000" })).status).toBe(403); // wrong code

    const ok = await post("/audit/recent", { totp: authenticator.generate(secret) });
    expect(ok.status).toBe(200);
    expect(Array.isArray(ok.json.entries)).toBe(true);
    const entry = ok.json.entries.find((e: any) => e.tool === "unifi.unifi.get_settings");
    expect(entry).toBeTruthy();
    expect(entry.argsDigest).toMatch(/^[0-9a-f]{32}$/); // hashed, not the raw value
    expect(JSON.stringify(ok.json.entries)).not.toContain("SENTINELARG"); // args never in the clear
  });

  it("refuses while the store is locked", async () => {
    await initStore();
    app.store.lock();
    expect((await post("/audit/recent", { totp: "000000" })).status).toBe(409);
  });

  it("serves the activity page only after setup completes", async () => {
    expect((await fetch(root + "/admin/activity")).status).toBe(404); // pre-setup

    await initStore();
    await markSetupComplete(authenticator.generateSecret());
    const r = await fetch(root + "/admin/activity");
    expect(r.status).toBe(200);
    const html = await r.text();
    expect(html).toContain("Activity log");
    expect(html).toContain("/api/audit/recent"); // the page pulls from the gated endpoint
  });
});
