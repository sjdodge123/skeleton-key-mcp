import { describe, it, expect, beforeEach, afterEach, vi } from "vitest";
import express from "express";
import { mkdir, mkdtemp, rm, writeFile } from "node:fs/promises";
import { existsSync } from "node:fs";
import { tmpdir } from "node:os";
import path from "node:path";
import type { Server } from "node:http";
import { authenticator } from "otplib";

/**
 * Exercises the /api/store/autounlock endpoints over real HTTP with a real
 * AppState: the pre-setup wizard flow, the post-setup TOTP gate, and the
 * rollback when the key file can't be written. Modules are re-imported per test
 * so SKELETON_KEY_DATA_DIR / SKELETON_KEY_UNLOCK_KEY_FILE take effect.
 */

let dir: string;
let keyFile: string;
let app: any;
let httpServer: Server;
let base: string;

beforeEach(async () => {
  vi.resetModules();
  dir = await mkdtemp(path.join(tmpdir(), "sk-autounlock-"));
  keyFile = path.join(dir, "secrets", "unlock-key");
  await mkdir(path.dirname(keyFile), { recursive: true });
  process.env.SKELETON_KEY_DATA_DIR = dir;
  vi.stubEnv("SKELETON_KEY_UNLOCK_KEY_FILE", keyFile);
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
  base = `http://127.0.0.1:${(httpServer.address() as { port: number }).port}/api`;
});

afterEach(async () => {
  vi.unstubAllEnvs();
  httpServer.close();
  app.audit.close();
  app.oauth.close();
  await rm(dir, { recursive: true, force: true });
});

async function post(p: string, body: unknown): Promise<{ status: number; json: any }> {
  const r = await fetch(base + p, {
    method: "POST",
    headers: { "content-type": "application/json" },
    body: JSON.stringify(body),
  });
  return { status: r.status, json: await r.json().catch(() => ({})) };
}

async function get(p: string): Promise<any> {
  return (await fetch(base + p)).json();
}

async function initStore(): Promise<void> {
  const r = await post("/store/init", { passphrase: "wizard-passphrase" });
  expect(r.status).toBe(200);
}

async function markSetupComplete(withTotpSecret: string): Promise<void> {
  await app.store.update({ totpSecret: withTotpSecret });
  const { paths } = await import("../config/paths.js");
  await writeFile(paths.setupComplete, JSON.stringify({ completedAt: "test" }), { mode: 0o600 });
}

describe("auto-unlock endpoints", () => {
  it("pre-setup (wizard): enable needs no TOTP, writes the key file, and the key boot-unlocks the store", async () => {
    await initStore();
    expect((await get("/store/autounlock")).enabled).toBe(false);

    const r = await post("/store/autounlock/enable", {});
    expect(r.status).toBe(200);
    expect(existsSync(keyFile)).toBe(true);
    const status = await get("/store/autounlock");
    expect(status.enabled).toBe(true);
    expect(status.keyFilePresent).toBe(true);

    // Boot path: the persisted key alone unlocks a fresh store handle.
    const { loadUnlockKey } = await import("../secrets/unlock-key-file.js");
    const { BootstrapStore } = await import("../secrets/bootstrap-store.js");
    const key = loadUnlockKey(keyFile);
    expect(key).not.toBeNull();
    const fresh = await BootstrapStore.open(path.join(dir, "bootstrap.store"));
    await fresh.unlockWithKey(key!);
    expect(fresh.locked).toBe(false);
  });

  it("post-setup: enable and disable are TOTP-gated", async () => {
    await initStore();
    const secret = authenticator.generateSecret();
    await markSetupComplete(secret);

    expect((await post("/store/autounlock/enable", {})).status).toBe(400); // missing code
    expect((await post("/store/autounlock/enable", { totp: "000000" })).status).toBe(403);

    const ok = await post("/store/autounlock/enable", { totp: authenticator.generate(secret) });
    expect(ok.status).toBe(200);
    expect(existsSync(keyFile)).toBe(true);

    expect((await post("/store/autounlock/disable", { totp: "000000" })).status).toBe(403);
    const off = await post("/store/autounlock/disable", { totp: authenticator.generate(secret) });
    expect(off.status).toBe(200);
    expect(off.json.keyFileRemoved).toBe(true);
    expect(existsSync(keyFile)).toBe(false);
    expect((await get("/store/autounlock")).enabled).toBe(false);
  });

  it("rolls the keyslot back when the key file can't be written (no mount)", async () => {
    await initStore();
    vi.stubEnv("SKELETON_KEY_UNLOCK_KEY_FILE", path.join(dir, "not-mounted", "unlock-key"));
    const r = await post("/store/autounlock/enable", {});
    expect(r.status).toBe(400);
    expect(String(r.json.error)).toContain("Mount a writable host directory");
    expect((await get("/store/autounlock")).enabled).toBe(false);
  });

  it("refuses while the store is locked", async () => {
    await initStore();
    app.store.lock();
    expect((await post("/store/autounlock/enable", {})).status).toBe(409);
  });
});
