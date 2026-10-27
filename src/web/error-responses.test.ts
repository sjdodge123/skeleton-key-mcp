import { describe, it, expect, beforeEach, afterEach, vi } from "vitest";
import { createHash, randomBytes } from "node:crypto";
import { mkdtemp, rm, writeFile } from "node:fs/promises";
import { tmpdir } from "node:os";
import path from "node:path";
import type { Server } from "node:http";
import { StreamableHTTPServerTransport } from "@modelcontextprotocol/sdk/server/streamableHttp.js";
import { generateTotpCode, generateTotpSecret } from "../lib/totp.js";
import type { AppState } from "../app.js";

/**
 * No thrown message reaches an HTTP response. Each route that used to echo
 * `err.message` is driven with an error whose message carries a secret, and the
 * response (and, where the route logs, the log line) must not contain it — while
 * the known-safe messages (`UserFacingError`, zod issue paths) still get through
 * so the admin UI stays useful. Full app (buildHttpApp), real AppState; the
 * `bw` CLI is stubbed at the client-method level.
 */

let dir: string;
let app: AppState;
let httpServer: Server;
let root: string;
let paths: { setupComplete: string };

const TOTP_SECRET = generateTotpSecret();
const REDIRECT = "http://127.0.0.1:9/callback";
const SECRET = "s3cr3t-hunter2-value";

beforeEach(async () => {
  vi.resetModules();
  vi.stubEnv("SKELETON_KEY_PUBLIC_URL", "");
  dir = await mkdtemp(path.join(tmpdir(), "sk-errresp-"));
  process.env.SKELETON_KEY_DATA_DIR = dir;
  vi.stubEnv("SKELETON_KEY_UNLOCK_KEY_FILE", path.join(dir, "no-such-key"));
  const { AppState } = await import("../app.js");
  ({ paths } = await import("../config/paths.js"));
  const { buildHttpApp } = await import("./server.js");
  app = await AppState.create();
  const ex = buildHttpApp(app);
  await new Promise<void>((resolve) => {
    httpServer = ex.listen(0, "127.0.0.1", () => resolve());
  });
  root = `http://127.0.0.1:${(httpServer.address() as { port: number }).port}`;
  // Unlocked store with TOTP enrolled; setup NOT complete (tests opt in).
  expect((await post("/api/store/init", { passphrase: "wizard-passphrase" })).status).toBe(200);
  await app.store.update({ totpSecret: TOTP_SECRET });
});

afterEach(async () => {
  vi.unstubAllEnvs();
  vi.restoreAllMocks();
  httpServer.close();
  app.audit.close();
  app.oauth.close();
  await rm(dir, { recursive: true, force: true });
});

async function post(p: string, body: unknown): Promise<{ status: number; text: string; json: any }> {
  const r = await fetch(root + p, { method: "POST", headers: { "content-type": "application/json" }, body: JSON.stringify(body) });
  const text = await r.text();
  let json: any = {};
  try {
    json = JSON.parse(text);
  } catch {
    /* html */
  }
  return { status: r.status, text, json };
}

const form = (body: Record<string, string>): RequestInit => ({
  method: "POST",
  headers: { "content-type": "application/x-www-form-urlencoded" },
  body: new URLSearchParams(body).toString(),
  redirect: "manual",
});

async function markSetupComplete(): Promise<void> {
  await writeFile(paths.setupComplete, JSON.stringify({ completedAt: "test" }), { mode: 0o600 });
}

function silenceErrors(): ReturnType<typeof vi.spyOn> {
  return vi.spyOn(console, "error").mockImplementation(() => {});
}

describe("/api (the h() wrapper)", () => {
  it("an unexpected throw is a fixed 500, logged by name only", async () => {
    const logged = silenceErrors();
    app.registry.list = () => {
      throw new Error(`registry read failed near ${SECRET}`);
    };
    const r = await fetch(`${root}/api/targets`);
    expect(r.status).toBe(500);
    const text = await r.text();
    expect(JSON.parse(text)).toEqual({ error: "Internal server error." });
    expect(text).not.toContain(SECRET);
    expect(logged.mock.calls.flat().join(" ")).toBe("[skeleton-key] request failed: Error");
  });

  it("a UserFacingError keeps its message: a wrong passphrase still says so, without echoing it", async () => {
    app.store.lock();
    const r = await post("/api/store/unlock", { passphrase: SECRET });
    expect(r.status).toBe(400);
    expect(r.json).toEqual({ error: "Incorrect passphrase or corrupted bootstrap store." });
  });

  it("unlocking before a store exists is a 409, not a 500", async () => {
    app.store.exists = async () => false;
    const r = await post("/api/store/unlock", { passphrase: "anything" });
    expect(r.status).toBe(409);
    expect(r.json).toEqual({ error: "No store exists yet; initialize it first." });
  });

  it("a validation failure names the fields and our refine text, never the rejected value", async () => {
    const r = await post("/api/setup/vault", { serverUrl: `http://${SECRET}.example.net`, clientSecret: "x", masterPassword: "y" });
    expect(r.status).toBe(400);
    expect(r.json.error).toMatch(/^Invalid request — /);
    expect(r.json.error).toContain("serverUrl: The Bitwarden CLI only accepts https:// vault URLs.");
    expect(r.json.error).toContain("clientId:");
    expect(r.text).not.toContain(SECRET);
  });

  it("an unrecognized key in a strict schema is not echoed", async () => {
    const { clientMessage } = await import("./http-util.js");
    const { z } = await import("zod");
    const parsed = z.object({ a: z.string() }).strict().safeParse({ a: "ok", [SECRET]: 1 });
    expect(parsed.success).toBe(false);
    expect(clientMessage(parsed.error)).toBe("Invalid request — Unrecognized key.");
  });

  it("an unknown connector type lists the known ones instead of reflecting the input", async () => {
    const r = await post("/api/targets", { name: "t", type: SECRET, host: "h" });
    expect(r.status).toBe(400);
    expect(r.json.error).toMatch(/^Unknown connector type; expected one of: .*\bssh\b/);
    expect(r.text).not.toContain(SECRET);
  });
});

describe("vault failures reach the admin as a fixed summary", () => {
  function failReestablish(message: string): void {
    app.vault.logout = async () => {};
    app.vault.reestablish = async () => {
      throw new Error(message);
    };
  }

  it("POST /api/setup/vault classifies a rejected API key", async () => {
    failReestablish(`bw login failed: client_id or client_secret is incorrect. Try again. (${SECRET})`);
    const r = await post("/api/setup/vault", { serverUrl: "https://vault.example.net", clientId: "id", clientSecret: "cs", masterPassword: "mp" });
    expect(r.status).toBe(400);
    expect(r.json).toEqual({ error: "The vault rejected the service account's API key (client id / secret)." });
  });

  it("POST /api/setup/vault names only the bw subcommand for an unclassified failure", async () => {
    failReestablish(`bw unlock failed: upstream replied ${SECRET}`);
    const r = await post("/api/setup/vault", { serverUrl: "https://vault.example.net", clientId: "id", clientSecret: "cs", masterPassword: "mp" });
    expect(r.status).toBe(400);
    expect(r.json).toEqual({ error: "The vault command `bw unlock` failed." });
  });

  it("POST /api/setup/vault: a non-vault fault (local store write) is a logged 500, not a vault message", async () => {
    const logged = silenceErrors();
    app.vault.reestablish = async () => {};
    app.vault.sync = async () => {};
    app.store.update = async () => {
      throw new Error(`EACCES writing near ${SECRET}`);
    };
    const r = await post("/api/setup/vault", { serverUrl: "https://vault.example.net", clientId: "id", clientSecret: "cs", masterPassword: "mp" });
    expect(r.status).toBe(500);
    expect(r.json).toEqual({ error: "Internal server error." });
    expect(logged.mock.calls.flat().join(" ")).not.toContain(SECRET);
  });

  it("the CLI's generic login wording is not pinned on the master password", async () => {
    const { describeVaultFailure } = await import("../secrets/vaultwarden.js");
    expect(describeVaultFailure(new Error("bw login failed: Username or password is incorrect. Try again."))).toBe(
      "The vault rejected the service account's credentials (API key or master password).",
    );
  });

  it("POST /api/vault/server: the response, /api/status and the audit entry all omit the raw message", async () => {
    await app.store.update({ bwServerUrl: "http://192.168.1.20:5555", bwClientId: "id", bwClientSecret: "cs", bwMasterPassword: "mp" });
    failReestablish(`bw unlock failed: request to https://vault.example.net/api failed, reason: getaddrinfo ENOTFOUND ${SECRET}`);
    const r = await post("/api/vault/server", { serverUrl: "https://vault.example.net" });
    expect(r.status).toBe(400);
    expect(r.json).toEqual({ error: "Could not reach the vault server — check the URL and that Vaultwarden is up." });
    const st = await (await fetch(`${root}/api/status`)).text();
    expect(JSON.parse(st).vaultError).toBe("Could not reach the vault server — check the URL and that Vaultwarden is up.");
    expect(st).not.toContain(SECRET);
    expect(JSON.stringify(app.audit.recent(20))).not.toContain(SECRET);
  });

  it("POST /api/store/unlock reports a classified vaultError", async () => {
    await app.store.update({ bwServerUrl: "https://vault.example.net", bwClientId: "id", bwClientSecret: "cs", bwMasterPassword: "mp" });
    failReestablish(`bw unlock failed: Invalid master password. ${SECRET}`);
    app.store.lock();
    const r = await post("/api/store/unlock", { passphrase: "wizard-passphrase" });
    expect(r.status).toBe(200);
    expect(r.json).toMatchObject({ ok: true, vaultUnlocked: false, vaultError: "The vault rejected the service account's master password." });
    expect(r.text).not.toContain(SECRET);
  });
});

describe("credential hand-off: a failed vault write", () => {
  async function submit(): Promise<string> {
    await markSetupComplete();
    Object.defineProperty(app.vault, "unlocked", { value: true, configurable: true });
    const req = app.credentialRequests.create({ name: "bot", host: "h", kind: "token", reason: "r" });
    const r = await fetch(
      `${root}/credential/${req.id}`,
      form({ formToken: req.formToken, action: "submit", totp: generateTotpCode(TOTP_SECRET), secret: "tok-value" }),
    );
    expect(r.status).toBe(400);
    const text = await r.text();
    expect(text).not.toContain("tok-value");
    return text;
  }

  it("shows the bw subcommand, not its stderr", async () => {
    app.vault.createLoginItem = async () => {
      throw new Error(`bw create failed: 422 ${SECRET}`);
    };
    const text = await submit();
    expect(text).toContain("Could not store the credential: The vault command");
    expect(text).toContain("bw create");
    expect(text).not.toContain(SECRET);
  });

  it("keeps a UserFacingError's message (the admin can act on it)", async () => {
    const { UserFacingError } = await import("../lib/errors.js");
    app.vault.createLoginItem = async () => {
      throw new UserFacingError(`A vault item named "bot" already exists — pick a different name.`);
    };
    const text = await submit();
    expect(text).toContain("already exists");
  });
});

describe("OAuth endpoints", () => {
  it("/oauth/token: every refused grant gets the same fixed description", async () => {
    const r = await fetch(`${root}/oauth/token`, form({ grant_type: "refresh_token", refresh_token: SECRET }));
    expect(r.status).toBe(400);
    const body = await r.json();
    expect(body).toEqual({ error: "invalid_grant", error_description: "The authorization code or refresh token is invalid, expired, already used, or does not match this client, redirect URI or PKCE verifier." });
  });

  it("/oauth/token: a store fault is a 500 server_error, not invalid_grant with the message", async () => {
    const logged = silenceErrors();
    app.oauth.refresh = () => {
      throw new Error(`SQLITE_CORRUPT near ${SECRET}`);
    };
    const r = await fetch(`${root}/oauth/token`, form({ grant_type: "refresh_token", refresh_token: "x" }));
    expect(r.status).toBe(500);
    const text = await r.text();
    expect(JSON.parse(text)).toEqual({ error: "server_error" });
    expect(logged.mock.calls.flat().join(" ")).toBe("[skeleton-key] oauth token request failed: Error");
  });

  it("/oauth/register: names the bad field, never the submitted URI", async () => {
    const r = await post("/oauth/register", { client_name: "c", redirect_uris: [`not a url ${SECRET}`] });
    expect(r.status).toBe(400);
    expect(r.json.error).toBe("invalid_client_metadata");
    expect(r.json.error_description).toContain("redirect_uris.0:");
    expect(r.text).not.toContain(SECRET);
  });
});

describe("/mcp", () => {
  it("a transport fault is a fixed JSON-RPC 500, logged by name only", async () => {
    await markSetupComplete();
    const logged = silenceErrors();
    vi.spyOn(StreamableHTTPServerTransport.prototype, "handleRequest").mockRejectedValue(new Error(`transport broke on ${SECRET}`));
    const client = app.oauth.registerClient({ client_name: "t", redirect_uris: [REDIRECT] });
    const verifier = randomBytes(32).toString("base64url");
    const code = app.oauth.createAuthCode({
      client_id: client.client_id, redirect_uri: REDIRECT, scope: "mcp",
      code_challenge: createHash("sha256").update(verifier).digest("base64url"),
    });
    const token = app.oauth.redeemAuthCode({ code, client_id: client.client_id, redirect_uri: REDIRECT, code_verifier: verifier }).access_token;
    const r = await fetch(`${root}/mcp`, {
      method: "POST",
      headers: { "content-type": "application/json", accept: "application/json, text/event-stream", authorization: `Bearer ${token}` },
      body: JSON.stringify({ jsonrpc: "2.0", id: 1, method: "initialize", params: { protocolVersion: "2025-06-18", capabilities: {}, clientInfo: { name: "t", version: "1" } } }),
    });
    expect(r.status).toBe(500);
    const text = await r.text();
    expect(text).not.toContain(SECRET);
    expect(JSON.parse(text).error).toMatchObject({ code: -32603, message: "Internal error." });
    const lines = logged.mock.calls.flat().join(" ");
    expect(lines).toContain("[skeleton-key] mcp request failed: Error");
    expect(lines).not.toContain(SECRET);
  });
});
