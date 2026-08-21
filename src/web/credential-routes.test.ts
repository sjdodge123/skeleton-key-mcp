import { describe, it, expect, beforeEach, afterEach, vi } from "vitest";
import express from "express";
import { mkdtemp, rm, writeFile } from "node:fs/promises";
import { tmpdir } from "node:os";
import path from "node:path";
import { createServer, type Server, type Server as HttpServer } from "node:http";
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

// ---------------------------------------------------------------------------
// Hardening after the Discord migration: per-field shape validation, a pre-store
// verification probe, overwrite-in-place, fingerprints, and the pending-links
// admin endpoint. Throughout: submitted values never appear in a page, the
// request store, or the audit log.
// ---------------------------------------------------------------------------

const BOT_TOKEN_PATTERN = "[A-Za-z0-9_-]{20,}\\.[A-Za-z0-9_-]{6}\\.[A-Za-z0-9_-]{20,}";
// Deliberately NOT shaped like a real Discord token (which starts with a base64 app id, "M…"/"N…"),
// so GitHub push protection doesn't mistake the fixture for a leaked secret.
const GOOD_TOKEN = "xxxxxxxxxxxxxxxxxxxxxxxx.GabcDE.abcdefghijklmnopqrstuvwxyz012345";
const CLIENT_SECRET = "abcdefghijklmnopqrstuvwxyz012345"; // 32 chars, no dots — the wrong thing

describe("credential hand-off — per-field validation", () => {
  const fields = [
    {
      name: "DISCORD_BOT_TOKEN",
      secret: true,
      pattern: BOT_TOKEN_PATTERN,
      minLength: 50,
      hint: "Discord Developer Portal → Bot → Reset Token. ~70 chars with two dots — NOT the OAuth2 Client Secret",
    },
    { name: "GUILD_ID", secret: false, pattern: "\\d{17,20}", hint: "Right-click the server → Copy Server ID" },
  ];

  it("renders the hint and pattern/minlength attributes under each constrained input", async () => {
    const req = app.credentialRequests.create({ name: "coworker-bot", host: "discord", fields, reason: "migrate" });
    const html = await (await fetch(`${root}/credential/${req.id}`)).text();
    expect(html).toContain("NOT the OAuth2 Client Secret");
    expect(html).toContain("Copy Server ID");
    expect(html).toMatch(/name="f_DISCORD_BOT_TOKEN"[^>]*minlength="50"/);
    expect(html).toMatch(/name="f_DISCORD_BOT_TOKEN"[^>]*data-pattern=/);
    expect(html).toContain("data-hint-for"); // inline JS check hooks
  });

  it("rejects a value that fails its pattern (400), names the field + hint, never echoes the value, and stays claimable", async () => {
    const req = app.credentialRequests.create({ name: "coworker-bot", host: "discord", fields, reason: "migrate" });
    const res = await postForm(req.id, {
      formToken: req.formToken,
      action: "submit",
      totp: authenticator.generate(TOTP_SECRET),
      f_DISCORD_BOT_TOKEN: CLIENT_SECRET,
      f_GUILD_ID: "123456789012345678",
    });
    expect(res.status).toBe(400);
    const html = await res.text();
    expect(html).toContain("DISCORD_BOT_TOKEN");
    expect(html).toContain("NOT the OAuth2 Client Secret");
    expect(html).not.toContain(CLIENT_SECRET);
    expect(html).not.toContain("123456789012345678"); // even passing values are not echoed
    expect(created).toHaveLength(0);
    expect(app.credentialRequests.get(req.id).status).toBe("pending");
    expect(JSON.stringify(app.audit.recent(10))).not.toContain(CLIENT_SECRET);
  });

  it("accepts values that satisfy their constraints", async () => {
    const req = app.credentialRequests.create({ name: "coworker-bot", host: "discord", fields, reason: "migrate" });
    const res = await postForm(req.id, {
      formToken: req.formToken,
      action: "submit",
      totp: authenticator.generate(TOTP_SECRET),
      f_DISCORD_BOT_TOKEN: GOOD_TOKEN,
      f_GUILD_ID: "123456789012345678",
    });
    expect(res.status).toBe(200);
    expect(created).toHaveLength(1);
    expect(created[0].fields[0]).toEqual({ name: "DISCORD_BOT_TOKEN", value: GOOD_TOKEN, hidden: true });
  });

  it("applies top-level constraints in single-secret mode", async () => {
    const req = app.credentialRequests.create({
      name: "bot-token",
      host: "discord",
      kind: "token",
      constraints: { pattern: BOT_TOKEN_PATTERN, hint: "Bot token, two dots" },
      reason: "migrate",
    });
    const bad = await postForm(req.id, { formToken: req.formToken, action: "submit", totp: authenticator.generate(TOTP_SECRET), secret: CLIENT_SECRET });
    expect(bad.status).toBe(400);
    const html = await bad.text();
    expect(html).toContain("Bot token, two dots");
    expect(html).not.toContain(CLIENT_SECRET);
    expect(created).toHaveLength(0);

    const good = await postForm(req.id, { formToken: req.formToken, action: "submit", totp: authenticator.generate(TOTP_SECRET), secret: GOOD_TOKEN });
    expect(good.status).toBe(200);
    expect(created[0].fields).toEqual([{ name: "token", value: GOOD_TOKEN, hidden: true }]);
  });
});

describe("credential hand-off — pre-store verification probe", () => {
  let probe: HttpServer;
  let probeUrl: string;
  let seen: { method: string; auth: string | undefined; path: string }[];
  let respondWith = 200;

  beforeEach(async () => {
    seen = [];
    respondWith = 200;
    probe = createServer((rq, rs) => {
      seen.push({ method: rq.method!, auth: rq.headers.authorization, path: rq.url! });
      rs.statusCode = respondWith;
      rs.end(respondWith === 200 ? '{"id":"bot"}' : '{"message":"401: Unauthorized","code":0}');
    });
    await new Promise<void>((resolve) => probe.listen(0, "127.0.0.1", () => resolve()));
    probeUrl = `http://127.0.0.1:${(probe.address() as { port: number }).port}/api/v10/users/@me`;
  });
  afterEach(() => probe.close());

  const verify = () => ({ method: "GET" as const, url: probeUrl, headers: { Authorization: "Bot {{value}}" } });

  it("names the probe host prominently on the form", async () => {
    const req = app.credentialRequests.create({ name: "bot", host: "discord", kind: "token", reason: "migrate", verify: verify() });
    const html = await (await fetch(`${root}/credential/${req.id}`)).text();
    expect(html).toContain("will <b>test this value</b> against");
    expect(html).toContain(probeUrl);
  });

  it("passes: probes with the templated secret, then stores and records verification=passed", async () => {
    const req = app.credentialRequests.create({ name: "bot", host: "discord", kind: "token", reason: "migrate", verify: verify() });
    const res = await postForm(req.id, { formToken: req.formToken, action: "submit", totp: authenticator.generate(TOTP_SECRET), secret: GOOD_TOKEN });
    expect(res.status).toBe(200);
    expect(seen).toEqual([{ method: "GET", auth: `Bot ${GOOD_TOKEN}`, path: "/api/v10/users/@me" }]);
    expect(created).toHaveLength(1);
    const stored = app.credentialRequests.get(req.id);
    expect(stored.status).toBe("fulfilled");
    expect(stored.verification).toBe("passed");
    // Audit: host + status only.
    const probeEntry = app.audit.recent(10).find((e: any) => e.tool === "credential.verify");
    expect(probeEntry.status).toBe("ok");
    expect(probeEntry.detail).toContain("HTTP 200");
    expect(JSON.stringify(app.audit.recent(10))).not.toContain(GOOD_TOKEN);
    expect(await res.text()).toContain("verified against 127.0.0.1");
  });

  it("fails: does NOT store, shows 'Verification failed: HTTP 401 from <host>', offers storeAnyway, stays claimable", async () => {
    respondWith = 401;
    const req = app.credentialRequests.create({ name: "bot", host: "discord", kind: "token", reason: "migrate", verify: verify() });
    const res = await postForm(req.id, { formToken: req.formToken, action: "submit", totp: authenticator.generate(TOTP_SECRET), secret: CLIENT_SECRET });
    expect(res.status).toBe(400);
    const html = await res.text();
    expect(html).toContain("Verification failed: HTTP 401 from 127.0.0.1");
    expect(html).toContain('name="storeAnyway"');
    expect(html).not.toContain(CLIENT_SECRET);
    expect(html).not.toContain("Unauthorized"); // response body never echoed
    expect(created).toHaveLength(0);
    expect(app.credentialRequests.get(req.id).status).toBe("pending");
    const probeEntry = app.audit.recent(10).find((e: any) => e.tool === "credential.verify");
    expect(probeEntry.status).toBe("error");
    expect(JSON.stringify(app.audit.recent(10))).not.toContain(CLIENT_SECRET);
  });

  it("storeAnyway overrides a failed probe and records verification=failed", async () => {
    respondWith = 401;
    const req = app.credentialRequests.create({ name: "bot", host: "discord", kind: "token", reason: "migrate", verify: verify() });
    const res = await postForm(req.id, {
      formToken: req.formToken,
      action: "submit",
      totp: authenticator.generate(TOTP_SECRET),
      secret: CLIENT_SECRET,
      storeAnyway: "1",
    });
    expect(res.status).toBe(200);
    expect(await res.text()).toContain("WITHOUT passing verification");
    expect(created).toHaveLength(1);
    expect(app.credentialRequests.get(req.id).verification).toBe("failed");
  });

  it("templates {{FIELD_NAME}} placeholders in multi-field mode", async () => {
    const req = app.credentialRequests.create({
      name: "bot",
      host: "discord",
      fields: [{ name: "DISCORD_BOT_TOKEN", secret: true }, { name: "GUILD_ID", secret: false }],
      reason: "migrate",
      verify: { method: "GET", url: probeUrl, headers: { Authorization: "Bot {{DISCORD_BOT_TOKEN}}", "X-Guild": "{{GUILD_ID}}" } },
    });
    await postForm(req.id, {
      formToken: req.formToken,
      action: "submit",
      totp: authenticator.generate(TOTP_SECRET),
      f_DISCORD_BOT_TOKEN: GOOD_TOKEN,
      f_GUILD_ID: "42",
    });
    expect(seen[0].auth).toBe(`Bot ${GOOD_TOKEN}`);
    expect(app.credentialRequests.get(req.id).verification).toBe("passed");
  });
});

describe("credential hand-off — overwrite an existing item in place", () => {
  it("calls updateLoginItem (not createLoginItem) with the replacement fields and reports 'Updated'", async () => {
    const updates: any[] = [];
    app.vault.updateLoginItem = vi.fn(async (ref: string, patch: any) => {
      updates.push({ ref, patch });
      return { id: "item-id", name: ref };
    });
    const req = app.credentialRequests.create({
      name: "coworker-bot",
      host: "discord",
      fields: [{ name: "DISCORD_BOT_TOKEN", secret: true }],
      reason: "fix wrong token",
      overwrite: true,
    });
    const html = await (await fetch(`${root}/credential/${req.id}`)).text();
    expect(html).toContain("replaces</b> the values of the existing vault item");

    const res = await postForm(req.id, {
      formToken: req.formToken,
      action: "submit",
      totp: authenticator.generate(TOTP_SECRET),
      f_DISCORD_BOT_TOKEN: GOOD_TOKEN,
    });
    expect(res.status).toBe(200);
    expect(await res.text()).toContain("Updated");
    expect(created).toHaveLength(0);
    expect(updates).toEqual([
      { ref: "coworker-bot", patch: { username: undefined, password: undefined, fields: [{ name: "DISCORD_BOT_TOKEN", value: GOOD_TOKEN, hidden: true }] } },
    ]);
    const entry = app.audit.recent(10).find((e: any) => e.tool === "credential.provide");
    expect(entry.detail).toContain("updated");
  });
});

describe("credential hand-off — fingerprints", () => {
  it("records a keyed len/fp fingerprint per stored field on the request (never the value)", async () => {
    const req = app.credentialRequests.create({
      name: "bot",
      host: "discord",
      fields: [{ name: "DISCORD_BOT_TOKEN", secret: true }, { name: "GUILD_ID", secret: false }],
      reason: "migrate",
    });
    await postForm(req.id, {
      formToken: req.formToken,
      action: "submit",
      totp: authenticator.generate(TOTP_SECRET),
      f_DISCORD_BOT_TOKEN: GOOD_TOKEN,
      f_GUILD_ID: "42",
    });
    const stored = app.credentialRequests.get(req.id);
    expect(stored.fingerprints.DISCORD_BOT_TOKEN).toMatch(new RegExp(`^len=${GOOD_TOKEN.length} fp=[0-9a-f]{8}$`));
    expect(stored.fingerprints.GUILD_ID).toMatch(/^len=2 fp=[0-9a-f]{8}$/);
    expect(stored.fingerprints.DISCORD_BOT_TOKEN).toBe(await app.fingerprint(GOOD_TOKEN));
    expect(JSON.stringify(stored)).not.toContain(GOOD_TOKEN);

    // credential_request_status surfaces them.
    const { buildGlobalTools } = await import("../mcp/builtin-tools.js");
    const status = buildGlobalTools(app).find((t) => t.name === "credential_request_status")!;
    const out = await status.run({ id: req.id }, app);
    expect(out.text).toContain(`DISCORD_BOT_TOKEN: ${stored.fingerprints.DISCORD_BOT_TOKEN}`);
    expect(out.text).toContain("Verification: skipped");
    expect(out.text).not.toContain(GOOD_TOKEN);
  });

  it("fingerprints the password in single-secret password mode", async () => {
    const req = app.credentialRequests.create({ name: "nas1", host: "10.0.0.5", kind: "password", username: "root", reason: "onboard" });
    await postForm(req.id, { formToken: req.formToken, action: "submit", totp: authenticator.generate(TOTP_SECRET), username: "root", secret: "hunter2" });
    expect(app.credentialRequests.get(req.id).fingerprints.password).toMatch(/^len=7 fp=[0-9a-f]{8}$/);
  });
});

describe("POST /api/credential-requests (pending links)", () => {
  it("is TOTP-gated and lists pending requests with links built from the public URL, never the Host header", async () => {
    const req = app.credentialRequests.create({ name: "bot", host: "discord", kind: "token", reason: "migrate", ttlMinutes: 45 });
    const done = app.credentialRequests.create({ name: "other", host: "x", kind: "token", reason: "r" });
    app.credentialRequests.claim(done.id);

    const noTotp = await fetch(`${root}/api/credential-requests`, { method: "POST", headers: { "content-type": "application/json" }, body: "{}" });
    expect(noTotp.status).toBe(400);
    const badTotp = await fetch(`${root}/api/credential-requests`, {
      method: "POST",
      headers: { "content-type": "application/json" },
      body: JSON.stringify({ totp: "000000" }),
    });
    expect(badTotp.status).toBe(403);

    const ok = await fetch(`${root}/api/credential-requests`, {
      method: "POST",
      headers: { "content-type": "application/json", host: "evil.example" },
      body: JSON.stringify({ totp: authenticator.generate(TOTP_SECRET) }),
    });
    expect(ok.status).toBe(200);
    const body = await ok.json();
    expect(body.requests).toHaveLength(1); // the fulfilled one is excluded
    const r = body.requests[0];
    expect(r.id).toBe(req.id);
    expect(r.fields).toEqual(["token"]);
    expect(r.link).toBe(`/credential/${req.id}`); // no public URL configured → relative, never the Host header
    expect(r.link).not.toContain("evil.example");
    expect(new Date(r.expiresAt).getTime() - new Date(r.createdAt).getTime()).toBe(45 * 60 * 1000);
    expect(JSON.stringify(body)).not.toContain("formToken");
  });

  it("returns 409 while the store is locked", async () => {
    app.store.lock();
    const res = await fetch(`${root}/api/credential-requests`, {
      method: "POST",
      headers: { "content-type": "application/json" },
      body: JSON.stringify({ totp: "123456" }),
    });
    expect(res.status).toBe(409);
  });
});
