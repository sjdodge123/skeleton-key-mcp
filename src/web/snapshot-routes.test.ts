import { describe, it, expect, beforeEach, afterEach, vi } from "vitest";
import express from "express";
import { mkdtemp, rm, writeFile } from "node:fs/promises";
import { tmpdir } from "node:os";
import path from "node:path";
import type { Server } from "node:http";
import { authenticator } from "otplib";

// Real-AppState-over-HTTP harness (same shape as admin-routes.test.ts): the temp
// data dir is set BEFORE importing, so paths.snapshotsDir points into it.
let dir: string;
let app: any;
let httpServer: Server;
let base: string;

beforeEach(async () => {
  vi.resetModules();
  dir = await mkdtemp(path.join(tmpdir(), "sk-snap-routes-"));
  process.env.SKELETON_KEY_DATA_DIR = dir;
  vi.stubEnv("SKELETON_KEY_PUBLIC_URL", "");
  const { AppState } = await import("../app.js");
  const { buildApiRouter } = await import("./routes.js");
  app = await AppState.create();
  const ex = express();
  ex.use(express.json());
  ex.use("/api", buildApiRouter(app));
  await new Promise<void>((resolve) => {
    httpServer = ex.listen(0, () => resolve());
  });
  const port = (httpServer.address() as { port: number }).port;
  base = `http://127.0.0.1:${port}/api`;
});
afterEach(async () => {
  vi.unstubAllEnvs();
  httpServer.close();
  app.audit.close();
  app.oauth.close();
  await rm(dir, { recursive: true, force: true });
});

function post(p: string, body: unknown): Promise<Response> {
  return fetch(base + p, { method: "POST", headers: { "content-type": "application/json" }, body: JSON.stringify(body) });
}
async function initAndSetup(): Promise<string> {
  await post("/store/init", { passphrase: "wizard-passphrase" });
  const secret = authenticator.generateSecret();
  await app.store.update({ totpSecret: secret });
  const { paths } = await import("../config/paths.js");
  await writeFile(paths.setupComplete, JSON.stringify({ completedAt: "test" }), { mode: 0o600 });
  return secret;
}
async function makeSkeleton(): Promise<string> {
  const { formSkeleton } = await import("../snapshots/snapshot-service.js");
  const { id } = await formSkeleton(app); // empty registry → all targets skipped, but a valid skeleton is written
  return id;
}

describe("snapshot routes", () => {
  it("POST /api/snapshots is TOTP-gated and returns metadata only", async () => {
    const secret = await initAndSetup();
    const id = await makeSkeleton();
    expect((await post("/snapshots", {})).status).toBe(400); // missing code
    expect((await post("/snapshots", { totp: "000000" })).status).toBe(403); // wrong code
    const ok = await post("/snapshots", { totp: authenticator.generate(secret) });
    expect(ok.status).toBe(200);
    const body = await ok.json();
    expect(body.skeletons.some((s: any) => s.id === id)).toBe(true);
  });

  it("refuses while the store is locked", async () => {
    await initAndSetup();
    app.store.lock();
    expect((await post("/snapshots", { totp: "000000" })).status).toBe(409);
  });

  it("download streams a gzip attachment with a valid TOTP", async () => {
    const secret = await initAndSetup();
    const id = await makeSkeleton();
    const r = await post(`/snapshots/${id}/download`, { totp: authenticator.generate(secret) });
    expect(r.status).toBe(200);
    expect(r.headers.get("content-disposition")).toContain(`skeleton-${id}.tar.gz`);
    const buf = Buffer.from(await r.arrayBuffer());
    expect([buf[0], buf[1]]).toEqual([0x1f, 0x8b]); // gzip magic
  });

  it("rejects a traversal id and 404s an unknown id", async () => {
    const secret = await initAndSetup();
    const bad = await post(`/snapshots/${encodeURIComponent("../etc")}/download`, { totp: authenticator.generate(secret) });
    expect([400, 404]).toContain(bad.status);
    const missing = await post(`/snapshots/nope-missing/download`, { totp: authenticator.generate(secret) });
    expect(missing.status).toBe(404);
  });
});
