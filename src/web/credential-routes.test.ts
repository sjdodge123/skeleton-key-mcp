import { describe, it, expect, beforeEach, afterEach, vi } from "vitest";
import express from "express";
import { mkdtemp, rm, writeFile } from "node:fs/promises";
import { tmpdir } from "node:os";
import path from "node:path";
import type { Server } from "node:http";
import { authenticator } from "otplib";

/**
 * The credential hand-off form (#18) over real HTTP, with the vault write
 * stubbed. Covers both modes: the original single-secret link and the
 * multi-field link that collects a named SET of values onto ONE vault item.
 * The invariant under test throughout: submitted values reach the vault and
 * nowhere else — not the request store, not the audit log, not a page.
 */

let dir: string;
let app: any;
let httpServer: Server;
let root: string;
let created: any[];

const TOTP_SECRET = authenticator.generateSecret();

beforeEach(async () => {
  vi.resetModules();
  dir = await mkdtemp(path.join(tmpdir(), "sk-cred-"));
  process.env.SKELETON_KEY_DATA_DIR = dir;
  vi.stubEnv("SKELETON_KEY_PUBLIC_URL", "");

  const { AppState } = await import("../app.js");
  const { buildApiRouter } = await import("./routes.js");
  const { buildCredentialRouter } = await import("./credential-routes.js");
  const { paths } = await import("../config/paths.js");
  app = await AppState.create();

  const ex = express();
  ex.use(express.json());
  ex.use(express.urlencoded({ extended: false }));
  ex.use("/api", buildApiRouter(app));
  ex.use(buildCredentialRouter(app));
  await new Promise<void>((resolve) => {
    httpServer = ex.listen(0, () => resolve());
  });
  root = `http://127.0.0.1:${(httpServer.address() as { port: number }).port}`;

  // Unlocked store + completed setup + enrolled TOTP: the state the form needs.
  const r = await fetch(`${root}/api/store/init`, {
    method: "POST",
    headers: { "content-type": "application/json" },
    body: JSON.stringify({ passphrase: "wizard-passphrase" }),
  });
  expect(r.status).toBe(200);
  await app.store.update({ totpSecret: TOTP_SECRET, bwCollectionName: "Homelab" });
  await writeFile(paths.setupComplete, JSON.stringify({ completedAt: "test" }), { mode: 0o600 });

  // Stub the vault: an unlocked client whose createLoginItem records its input.
  created = [];
  Object.defineProperty(app.vault, "unlocked", { value: true, configurable: true });
  app.vault.createLoginItem = vi.fn(async (input: any) => {
    created.push(input);
    return { name: input.name };
  });
});

afterEach(async () => {
  vi.unstubAllEnvs();
  httpServer.close();
  app.audit.close();
  app.oauth.close();
  await rm(dir, { recursive: true, force: true });
});

function postForm(id: string, body: Record<string, string>): Promise<Response> {
  return fetch(`${root}/credential/${id}`, {
    method: "POST",
    headers: { "content-type": "application/x-www-form-urlencoded" },
    body: new URLSearchParams(body).toString(),
  });
}

const FIELDS = [
  { name: "DISCORD_BOT_TOKEN", label: "From the Discord developer portal", secret: true },
  { name: "SXM_USERNAME", secret: false },
  { name: "SXM_PASSWORD", secret: true },
];

describe("credential hand-off — multi-field mode", () => {
  it("renders one input per field, masked only for secret ones", async () => {
    const req = app.credentialRequests.create({ name: "sxm-bot", host: "fly-app", fields: FIELDS, reason: "migrate off fly.io" });
    const html = await (await fetch(`${root}/credential/${req.id}`)).text();
    expect(html).toContain('name="f_DISCORD_BOT_TOKEN"');
    expect(html).toContain('name="f_SXM_USERNAME"');
    expect(html).toContain('name="f_SXM_PASSWORD"');
    expect(html).toContain("From the Discord developer portal"); // label is help text
    expect(html).toMatch(/type="password" name="f_DISCORD_BOT_TOKEN"/);
    expect(html).toMatch(/type="text" name="f_SXM_USERNAME"/); // non-secret stays visible
    expect(html).toContain("3 values");
  });

  it("writes ONE vault item carrying every field, hidden per the field's secret flag", async () => {
    const req = app.credentialRequests.create({ name: "sxm-bot", host: "fly-app", fields: FIELDS, reason: "migrate off fly.io" });
    const res = await postForm(req.id, {
      formToken: req.formToken,
      action: "submit",
      totp: authenticator.generate(TOTP_SECRET),
      f_DISCORD_BOT_TOKEN: "discord-value",
      f_SXM_USERNAME: "sxm-user",
      f_SXM_PASSWORD: "sxm-pass",
    });
    expect(res.status).toBe(200);

    expect(created).toHaveLength(1);
    const item = created[0];
    expect(item.name).toBe("sxm-bot");
    expect(item.collectionName).toBe("Homelab");
    expect(item.fields).toEqual([
      { name: "DISCORD_BOT_TOKEN", value: "discord-value", hidden: true },
      { name: "SXM_USERNAME", value: "sxm-user", hidden: false },
      { name: "SXM_PASSWORD", value: "sxm-pass", hidden: true },
    ]);
    // Not an SSH password login: no login password / ssh:// URI mislabeling.
    expect(item.password).toBeUndefined();
    expect(item.url).toBeUndefined();

    // Success page names the fields, never their values.
    const html = await res.text();
    expect(html).toContain("DISCORD_BOT_TOKEN");
    expect(html).not.toContain("discord-value");
    // Neither does the request store or the audit log.
    expect(JSON.stringify(app.credentialRequests.get(req.id))).not.toContain("discord-value");
    const entries = app.audit.recent(10);
    expect(JSON.stringify(entries)).not.toContain("discord-value");
    expect(entries.some((e: any) => e.tool === "credential.provide")).toBe(true);
  });

  it("promotes a field literally named 'username' to the item's login username", async () => {
    const req = app.credentialRequests.create({
      name: "app-creds",
      host: "fly-app",
      fields: [
        { name: "username", secret: false },
        { name: "API_KEY", secret: true },
      ],
      reason: "migrate",
    });
    await postForm(req.id, {
      formToken: req.formToken,
      action: "submit",
      totp: authenticator.generate(TOTP_SECRET),
      f_username: "svc-account",
      f_API_KEY: "k1",
    });
    expect(created[0].username).toBe("svc-account");
    expect(created[0].fields).toContainEqual({ name: "username", value: "svc-account", hidden: false });
  });

  it("requires every field and stays claimable after the rejection", async () => {
    const req = app.credentialRequests.create({ name: "sxm-bot", host: "fly-app", fields: FIELDS, reason: "migrate" });
    const res = await postForm(req.id, {
      formToken: req.formToken,
      action: "submit",
      totp: authenticator.generate(TOTP_SECRET),
      f_DISCORD_BOT_TOKEN: "discord-value",
      f_SXM_USERNAME: "sxm-user",
    });
    expect(res.status).toBe(400);
    expect(await res.text()).toContain("SXM_PASSWORD");
    expect(created).toHaveLength(0);
    expect(app.credentialRequests.get(req.id).status).toBe("pending");
  });

  it("is TOTP-gated and CSRF-gated like the single-secret form", async () => {
    const req = app.credentialRequests.create({ name: "sxm-bot", host: "fly-app", fields: FIELDS, reason: "migrate" });
    const values = { f_DISCORD_BOT_TOKEN: "a", f_SXM_USERNAME: "b", f_SXM_PASSWORD: "c" };

    const noCsrf = await postForm(req.id, { formToken: "wrong", action: "submit", totp: authenticator.generate(TOTP_SECRET), ...values });
    expect(noCsrf.status).toBe(403);

    const badTotp = await postForm(req.id, { formToken: req.formToken, action: "submit", totp: "000000", ...values });
    expect(badTotp.status).toBe(403);

    expect(created).toHaveLength(0);
    expect(app.credentialRequests.get(req.id).status).toBe("pending");
  });

  it("is single-use — a replay of the same link cannot write a second item", async () => {
    const req = app.credentialRequests.create({ name: "sxm-bot", host: "fly-app", fields: FIELDS, reason: "migrate" });
    const values = { f_DISCORD_BOT_TOKEN: "a", f_SXM_USERNAME: "b", f_SXM_PASSWORD: "c" };
    const body = { formToken: req.formToken, action: "submit", totp: authenticator.generate(TOTP_SECRET), ...values };
    expect((await postForm(req.id, body)).status).toBe(200);
    const replay = await postForm(req.id, body);
    expect(await replay.text()).toContain("Already provided");
    expect(created).toHaveLength(1);
  });
});

describe("credential hand-off — single-secret mode (unchanged)", () => {
  it("still writes a username/password login with an ssh:// URI", async () => {
    const req = app.credentialRequests.create({ name: "nas1", host: "192.168.0.50", kind: "password", username: "root", reason: "onboard nas1" });
    const html = await (await fetch(`${root}/credential/${req.id}`)).text();
    expect(html).toContain('name="secret"');
    expect(html).not.toContain('name="f_');

    const res = await postForm(req.id, {
      formToken: req.formToken,
      action: "submit",
      totp: authenticator.generate(TOTP_SECRET),
      username: "root",
      secret: "hunter2",
    });
    expect(res.status).toBe(200);
    expect(created[0]).toMatchObject({ name: "nas1", username: "root", password: "hunter2", url: "ssh://192.168.0.50" });
    expect(created[0].fields).toEqual([]);
  });

  it("still writes a token as a hidden 'token' custom field", async () => {
    const req = app.credentialRequests.create({ name: "pve-token", host: "192.168.0.10", kind: "token", reason: "onboard proxmox" });
    const res = await postForm(req.id, {
      formToken: req.formToken,
      action: "submit",
      totp: authenticator.generate(TOTP_SECRET),
      secret: "PVEAPIToken=x!y=z",
    });
    expect(res.status).toBe(200);
    expect(created[0].fields).toEqual([{ name: "token", value: "PVEAPIToken=x!y=z", hidden: true }]);
    expect(created[0].url).toBeUndefined();
  });
});
