import { describe, it, expect, beforeEach, afterEach, vi } from "vitest";
import express from "express";
import { mkdtemp, readFile, rm, writeFile } from "node:fs/promises";
import { tmpdir } from "node:os";
import path from "node:path";
import type { Server } from "node:http";
import * as age from "age-encryption";
import { generateTotpCode } from "../lib/totp.js";

/**
 * Provider selection end to end through the web API: the wizard connecting the
 * age-file provider, `/api/status` reporting the selected provider and its
 * capabilities, the post-setup connect after SKELETON_KEY_SECRETS_PROVIDER is
 * switched, and the reconnect retry. The age file is real (tmp dir); nothing
 * reaches the network.
 */

let dir: string;
let ageFile: string;
let app: any;
let httpServer: Server;
let base: string;

const TOTP_SECRET = "JBSWY3DPEHPK3PXP";
const PASS = "wizard-passphrase";

async function boot(provider?: string): Promise<void> {
  vi.resetModules();
  process.env.SKELETON_KEY_DATA_DIR = dir;
  vi.stubEnv("SKELETON_KEY_UNLOCK_KEY_FILE", path.join(dir, "no-such-key"));
  vi.stubEnv("SKELETON_KEY_PUBLIC_URL", "");
  vi.stubEnv("SKELETON_KEY_AGE_FILE", ageFile);
  vi.stubEnv("SKELETON_KEY_SECRETS_PROVIDER", provider ?? "");
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
}

async function shutdown(): Promise<void> {
  if (!app) return;
  httpServer.close();
  app.audit.close();
  app.oauth.close();
  app = undefined;
}

beforeEach(async () => {
  dir = await mkdtemp(path.join(tmpdir(), "sk-provider-"));
  ageFile = path.join(dir, "secrets.age");
});

afterEach(async () => {
  await shutdown();
  vi.unstubAllEnvs();
  vi.restoreAllMocks();
  await rm(dir, { recursive: true, force: true });
});

async function post(p: string, body: unknown): Promise<{ status: number; json: any; text: string }> {
  const r = await fetch(base + p, { method: "POST", headers: { "content-type": "application/json" }, body: JSON.stringify(body) });
  const text = await r.text();
  let json: any = {};
  try {
    json = JSON.parse(text);
  } catch {
    /* not json */
  }
  return { status: r.status, json, text };
}
const status = async (): Promise<any> => (await fetch(base + "/status")).json();
const totp = () => generateTotpCode(TOTP_SECRET);

async function markSetupComplete(): Promise<void> {
  const { paths } = await import("../config/paths.js");
  await writeFile(paths.setupComplete, JSON.stringify({ completedAt: "test" }), { mode: 0o600 });
}

describe("provider selection at boot", () => {
  it("defaults to Vaultwarden, and /api/status names it with its capabilities", async () => {
    await boot();
    const st = await status();
    expect(st.secrets).toEqual({ kind: "vaultwarden", label: "Vaultwarden", capabilities: ["create", "update", "delete", "sync"], configured: null });
  });

  it("an unknown provider fails the boot loudly instead of falling back", async () => {
    vi.resetModules();
    process.env.SKELETON_KEY_DATA_DIR = dir;
    vi.stubEnv("SKELETON_KEY_SECRETS_PROVIDER", "onepassword");
    const { AppState } = await import("../app.js");
    await expect(AppState.create()).rejects.toThrow(/SKELETON_KEY_SECRETS_PROVIDER must be one of/);
  });

  it("a malformed extra age recipient fails the boot", async () => {
    vi.resetModules();
    process.env.SKELETON_KEY_DATA_DIR = dir;
    vi.stubEnv("SKELETON_KEY_SECRETS_PROVIDER", "age-file");
    vi.stubEnv("SKELETON_KEY_AGE_RECIPIENTS", "age1notarecipient");
    const { AppState } = await import("../app.js");
    await expect(AppState.create()).rejects.toThrow(/SKELETON_KEY_AGE_RECIPIENTS entry 1/);
  });
});

describe("first-run wizard with the age-file provider", () => {
  it("connects with a generated identity, persists it in the store, and needs no Vaultwarden fields", async () => {
    await boot("age-file");
    expect((await status()).secrets).toMatchObject({ kind: "age-file", label: "age file", capabilities: ["create", "update", "delete"] });
    expect((await post("/store/init", { passphrase: PASS })).status).toBe(200);
    expect((await status()).secrets.configured).toBe(false);

    const r = await post("/setup/vault", {});
    expect(r.status).toBe(200);
    expect(r.json.checks.every((c: { passed: boolean }) => c.passed)).toBe(true);
    const identity = app.store.get().ageIdentity as string;
    expect(identity).toMatch(/^AGE-SECRET-KEY-1/);
    expect(r.text).not.toContain(identity); // the identity never leaves the store
    expect(r.text).toContain(await age.identityToRecipient(identity)); // the public recipient does

    const st = await status();
    expect(st.vaultUnlocked).toBe(true);
    expect(st.secrets.configured).toBe(true);
    expect(JSON.stringify(st)).not.toContain(identity);

    // A server URL means nothing to the age file.
    const server = await post("/vault/server", { serverUrl: "https://vault.example.net" });
    expect(server.status).toBe(409);
    expect(server.json.error).toMatch(/age file\) has no server URL/);

    // `complete` counts the provider as connected.
    await app.store.update({ mcpBearerToken: "t", totpSecret: TOTP_SECRET });
    expect((await post("/setup/complete", {})).status).toBe(200);
  });

  it("register_target pins a hand-written (id-less) item, and the pin resolves", async () => {
    await boot("age-file");
    await post("/store/init", { passphrase: PASS });
    const identity = await age.generateX25519Identity();
    const e = new age.Encrypter();
    e.addRecipient(await age.identityToRecipient(identity));
    await writeFile(ageFile, age.armor.encode(await e.encrypt(JSON.stringify({ version: 1, items: [{ name: "nas1-ssh", username: "admin", password: "pw" }] }))));
    expect((await post("/setup/vault", { identity })).status).toBe(200);

    const { buildGlobalTools } = await import("../mcp/builtin-tools.js");
    const { targetCredential } = await import("../mcp/tool-registry.js");
    const register = buildGlobalTools(app).find((t) => t.name === "register_target")!;
    const out = await register.run(register.inputSchema.parse({ name: "nas1", type: "ssh", host: "10.0.0.5", credentialRef: "nas1-ssh" }), app);
    expect(out.isError).toBeFalsy();
    const target = app.registry.get("nas1");
    expect(target.credentialId).toMatch(/^[0-9a-f]{8}-[0-9a-f]{4}-5[0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$/);
    expect((await targetCredential(app, target)).password).toBe("pw");
  });

  it("a wrong pasted identity is refused with fixed text, and nothing is saved", async () => {
    await boot("age-file");
    await post("/store/init", { passphrase: PASS });
    const r = await post("/setup/vault", { identity: "AGE-SECRET-KEY-1NOTAREALKEYXXXX" });
    expect(r.status).toBe(400);
    expect(r.json.error).toBe("That is not a valid age identity (expected AGE-SECRET-KEY-1… or AGE-SECRET-KEY-PQ-1…).");
    expect(r.text).not.toContain("NOTAREALKEY");
    expect(app.store.get().ageIdentity).toBeUndefined();
  });

  it("survives a restart: the identity in the store reopens the file on unlock", async () => {
    await boot("age-file");
    await post("/store/init", { passphrase: PASS });
    await post("/setup/vault", {});
    await app.secrets.create({ name: "nas1-ssh", username: "admin", password: "pw" });
    await shutdown();

    await boot("age-file");
    expect((await status()).vaultUnlocked).toBe(false);
    const u = await post("/store/unlock", { passphrase: PASS });
    expect(u.json).toMatchObject({ ok: true, vaultUnlocked: true });
    expect((await app.secrets.get("nas1-ssh")).password).toBe("pw");
  });
});

describe("switching providers on an existing deployment", () => {
  /** A Vaultwarden deployment, set up and complete, then rebooted on age-file. */
  async function switchedDeployment(): Promise<void> {
    await boot();
    await post("/store/init", { passphrase: PASS });
    await app.store.update({
      bwServerUrl: "https://vault.example.net",
      bwClientId: "user.client-id",
      bwClientSecret: "client-secret",
      bwMasterPassword: "master",
      totpSecret: TOTP_SECRET,
      mcpBearerToken: "t",
    });
    await markSetupComplete();
    await shutdown();
    await boot("age-file");
  }

  it("unlocks the store but keeps tools withheld, and says which provider needs connecting", async () => {
    await switchedDeployment();
    const u = await post("/store/unlock", { passphrase: PASS });
    expect(u.json).toMatchObject({ ok: true, vaultUnlocked: false });
    expect(app.locked).toBe(true); // the kill-switch holds
    const st = await status();
    expect(st.secrets).toMatchObject({ kind: "age-file", configured: false });
    expect(st.vaultError).toMatch(/age file, which isn't connected yet/);
  });

  it("connects the new provider after setup behind a fresh TOTP, audited without the input", async () => {
    await switchedDeployment();
    await post("/store/unlock", { passphrase: PASS });
    const operator = await age.generateX25519Identity();
    const recipient = await age.identityToRecipient(operator);
    const e = new age.Encrypter();
    e.addRecipient(recipient);
    await writeFile(ageFile, await e.encrypt(JSON.stringify({ version: 1, items: [{ name: "nas1-ssh", password: "pw" }] })));

    expect((await post("/vault/connect", { identity: operator })).status).toBe(400); // no totp
    expect((await post("/vault/connect", { identity: operator, totp: "000000" })).status).toBe(403);
    expect(app.store.get().ageIdentity).toBeUndefined();

    const r = await post("/vault/connect", { identity: operator, totp: totp() });
    expect(r.status).toBe(200);
    expect(r.json).toMatchObject({ ok: true, vaultUnlocked: true });
    expect(r.text).not.toContain(operator);
    expect(app.locked).toBe(false);
    expect((await status()).vaultError).toBeNull();
    // Targets keep their names: the item resolves by name in the new provider.
    expect((await app.secrets.get("nas1-ssh")).password).toBe("pw");
    // The old provider's settings are left alone (switching back still works).
    expect(app.store.get().bwClientId).toBe("user.client-id");

    const audit = app.audit.recent(20).find((x: any) => x.tool === "vault.connect");
    expect(audit).toMatchObject({ status: "ok", target: "age-file" });
    expect(JSON.stringify(app.audit.recent(50))).not.toContain(operator);

    // Once connected, connect can't be used to re-point it.
    const again = await post("/vault/connect", { identity: await age.generateX25519Identity(), totp: totp() });
    expect(again.status).toBe(409);
    expect(app.store.get().ageIdentity).toBe(operator);
  });

  it("refuses the post-setup connect before setup is complete (the wizard owns that)", async () => {
    await boot("age-file");
    await post("/store/init", { passphrase: PASS });
    const r = await post("/vault/connect", {});
    expect(r.status).toBe(409);
    expect(r.json.error).toMatch(/setup wizard/);
  });
});

describe("POST /api/vault/reconnect", () => {
  it("retries from the saved settings after the age file is fixed, behind TOTP", async () => {
    await boot("age-file");
    await post("/store/init", { passphrase: PASS });
    await post("/setup/vault", {});
    await app.store.update({ totpSecret: TOTP_SECRET, mcpBearerToken: "t" });
    await markSetupComplete();
    const good = await readFile(ageFile);
    await shutdown();

    // Reboot with the file gone: the store unlocks, the provider doesn't.
    await rm(ageFile);
    await boot("age-file");
    const u = await post("/store/unlock", { passphrase: PASS });
    expect(u.json).toMatchObject({ ok: true, vaultUnlocked: false, vaultError: "The age secrets file does not exist (SKELETON_KEY_AGE_FILE)." });

    expect((await post("/vault/reconnect", {})).status).toBe(400); // no totp
    const still = await post("/vault/reconnect", { totp: totp() });
    expect(still.status).toBe(400);
    expect(still.json.error).toBe("The age secrets file does not exist (SKELETON_KEY_AGE_FILE).");

    await writeFile(ageFile, good);
    const r = await post("/vault/reconnect", { totp: totp() });
    expect(r.status).toBe(200);
    expect(r.json).toMatchObject({ ok: true, vaultUnlocked: true });
    expect((await status()).vaultError).toBeNull();
    const rows = app.audit.recent(20).filter((x: any) => x.tool === "vault.reconnect").map((x: any) => x.status);
    expect(rows.sort()).toEqual(["error", "ok"]);
  });

  it("refuses when the provider was never connected", async () => {
    await boot("age-file");
    await post("/store/init", { passphrase: PASS });
    const r = await post("/vault/reconnect", {});
    expect(r.status).toBe(409);
  });
});
