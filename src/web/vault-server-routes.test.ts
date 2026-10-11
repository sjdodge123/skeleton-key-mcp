import { describe, it, expect, beforeEach, afterEach, vi } from "vitest";
import express from "express";
import { mkdtemp, rm, writeFile } from "node:fs/promises";
import { tmpdir } from "node:os";
import path from "node:path";
import type { Server } from "node:http";
import { authenticator } from "otplib";

/**
 * Exercises `POST /api/vault/server` (re-pointing the Vaultwarden client at a
 * new https:// URL after setup) and the `/store/unlock` + `/status` reporting
 * around a vault that fails to come up — the repair path for the Bitwarden CLI
 * refusing plain-http vault URLs. Real AppState + HTTP; the `bw` CLI is stubbed
 * at the client-method level so no process is spawned.
 */

let dir: string;
let app: any;
let httpServer: Server;
let base: string;

beforeEach(async () => {
  vi.resetModules();
  dir = await mkdtemp(path.join(tmpdir(), "sk-vaultsrv-"));
  process.env.SKELETON_KEY_DATA_DIR = dir;
  vi.stubEnv("SKELETON_KEY_UNLOCK_KEY_FILE", path.join(dir, "no-such-key"));
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
  const r = await fetch(base + p, { method: "POST", headers: { "content-type": "application/json" }, body: JSON.stringify(body) });
  return { status: r.status, json: await r.json().catch(() => ({})) };
}
async function getStatus(): Promise<any> {
  return (await fetch(base + "/status")).json();
}

const TOTP_SECRET = "JBSWY3DPEHPK3PXP";
const OLD_URL = "http://192.168.0.229:5555";
const NEW_URL = "https://vault.example.net";

/** Stub the `bw`-backed client: reestablish succeeds unless the URL matches `refuse`. */
function stubVault(refuse?: RegExp): { logout: number; reestablish: string[]; sync: number } {
  const seen = { logout: 0, reestablish: [] as string[], sync: 0 };
  app.vault.logout = async () => {
    seen.logout += 1;
    app.vault.session = null;
  };
  app.vault.reestablish = async (cfg: { serverUrl: string }) => {
    seen.reestablish.push(cfg.serverUrl);
    if (refuse?.test(cfg.serverUrl)) {
      throw new Error(
        `bw unlock failed: Unable to fetch ServerConfig from ${cfg.serverUrl}/api InsecureUrlNotAllowedError: Insecure URL not allowed. All URLs must use HTTPS.`,
      );
    }
    app.vault.session = "test-session";
  };
  app.vault.sync = async () => {
    seen.sync += 1;
  };
  app.vault.run = async () => "[]"; // scoping checks list orgs/collections
  return seen;
}

async function initConnectedStore(): Promise<void> {
  expect((await post("/store/init", { passphrase: "wizard-passphrase" })).status).toBe(200);
  await app.store.update({
    bwServerUrl: OLD_URL,
    bwClientId: "user.client-id",
    bwClientSecret: "client-secret",
    bwMasterPassword: "master",
    totpSecret: TOTP_SECRET,
  });
}
async function markSetupComplete(): Promise<void> {
  const { paths } = await import("../config/paths.js");
  await writeFile(paths.setupComplete, JSON.stringify({ completedAt: "test" }), { mode: 0o600 });
}

describe("POST /api/vault/server", () => {
  it("refuses while the store is locked", async () => {
    const r = await post("/vault/server", { serverUrl: NEW_URL });
    expect(r.status).toBe(409);
  });

  it("post-setup: needs a valid TOTP and an https:// URL", async () => {
    await initConnectedStore();
    await markSetupComplete();
    const seen = stubVault();
    expect((await post("/vault/server", { serverUrl: NEW_URL })).status).toBe(400); // no totp → zod
    expect((await post("/vault/server", { serverUrl: NEW_URL, totp: "000000" })).status).toBe(403);
    const bad = await post("/vault/server", { serverUrl: "http://192.168.0.229:5556", totp: authenticator.generate(TOTP_SECRET) });
    expect(bad.status).toBe(400);
    expect(bad.json.error).toMatch(/https/);
    expect(seen.reestablish).toEqual([]);
    expect(app.store.get().bwServerUrl).toBe(OLD_URL);
  });

  it("re-points the vault: logout → reestablish on the new URL → sync → persist; status reflects it", async () => {
    await initConnectedStore();
    await markSetupComplete();
    const seen = stubVault();
    app.vaultError = "bw unlock failed: Insecure URL not allowed.";
    const r = await post("/vault/server", { serverUrl: NEW_URL, totp: authenticator.generate(TOTP_SECRET) });
    expect(r.status).toBe(200);
    expect(r.json.ok).toBe(true);
    expect(r.json.vaultUnlocked).toBe(true);
    expect(seen.logout).toBe(1);
    expect(seen.reestablish).toEqual([NEW_URL]);
    expect(seen.sync).toBe(1);
    expect(app.store.get().bwServerUrl).toBe(NEW_URL);
    // The other bootstrap secrets are untouched.
    expect(app.store.get().bwClientId).toBe("user.client-id");
    expect(app.store.get().bwMasterPassword).toBe("master");
    const st = await getStatus();
    expect(st.vaultUnlocked).toBe(true);
    expect(st.vaultError).toBeNull();
    const audit = app.audit.recent(10).find((e: any) => e.tool === "vault.change_server");
    expect(audit?.status).toBe("ok");
    expect(JSON.stringify(audit)).not.toContain("client-secret");
  });

  it("fails closed: a URL the CLI refuses leaves the stored URL untouched and surfaces a redacted vaultError", async () => {
    await initConnectedStore();
    await markSetupComplete();
    stubVault(/vault-broken/);
    const r = await post("/vault/server", { serverUrl: "https://vault-broken.example.net", totp: authenticator.generate(TOTP_SECRET) });
    expect(r.status).toBe(400);
    expect(r.json.error).toMatch(/Insecure URL not allowed/);
    expect(app.store.get().bwServerUrl).toBe(OLD_URL);
    const st = await getStatus();
    expect(st.vaultUnlocked).toBe(false);
    expect(st.vaultError).toMatch(/<vault url>/);
    expect(st.vaultError).not.toMatch(/vault-broken\.example\.net/);
  });

  it("pre-setup (wizard) needs no TOTP", async () => {
    await initConnectedStore();
    const seen = stubVault();
    const r = await post("/vault/server", { serverUrl: NEW_URL });
    expect(r.status).toBe(200);
    expect(seen.reestablish).toEqual([NEW_URL]);
  });
});

describe("POST /api/store/unlock when the vault cannot be re-established", () => {
  it("reports ok:true + vaultUnlocked:false with a redacted error instead of a failed unlock", async () => {
    await initConnectedStore();
    await markSetupComplete();
    stubVault(/^http:/); // the stored plain-http URL is what the CLI refuses
    app.store.lock();
    const r = await post("/store/unlock", { passphrase: "wizard-passphrase" });
    expect(r.status).toBe(200);
    expect(r.json.ok).toBe(true);
    expect(r.json.vaultUnlocked).toBe(false);
    expect(r.json.vaultError).toMatch(/Insecure URL not allowed/);
    expect(r.json.vaultError).not.toMatch(/192\.168\.0\.229/);
    expect(app.store.locked).toBe(false);
    const st = await getStatus();
    expect(st.storeLocked).toBe(false);
    expect(st.vaultUnlocked).toBe(false);
    expect(st.vaultError).toContain("<vault url>");
  });
});
