import { describe, it, expect, beforeEach, afterEach } from "vitest";
import { mkdtemp, rm } from "node:fs/promises";
import { tmpdir } from "node:os";
import path from "node:path";
import { createHash, randomBytes } from "node:crypto";
import { OAuthService } from "./oauth-service.js";

let dir: string;
let svc: OAuthService;

function pkce(): { verifier: string; challenge: string } {
  const verifier = randomBytes(32).toString("base64url");
  const challenge = createHash("sha256").update(verifier).digest("base64url");
  return { verifier, challenge };
}

beforeEach(async () => {
  dir = await mkdtemp(path.join(tmpdir(), "skmcp-oauth-"));
  svc = new OAuthService(path.join(dir, "oauth.sqlite"));
});
afterEach(async () => {
  svc.close();
  await rm(dir, { recursive: true, force: true });
});

const REDIRECT = "http://localhost:9999/callback";

function register() {
  return svc.registerClient({ client_name: "Test Agent", redirect_uris: [REDIRECT] });
}

describe("OAuthService", () => {
  it("registers a client and completes an authorization-code + PKCE flow", () => {
    const client = register();
    const { verifier, challenge } = pkce();
    const code = svc.createAuthCode({ client_id: client.client_id, redirect_uri: REDIRECT, code_challenge: challenge, scope: "mcp" });
    const tokens = svc.redeemAuthCode({ code, client_id: client.client_id, redirect_uri: REDIRECT, code_verifier: verifier });
    expect(tokens.access_token).toBeTruthy();
    expect(tokens.refresh_token).toBeTruthy();
    expect(svc.validateAccessToken(tokens.access_token)).toMatchObject({ client_id: client.client_id, scope: "mcp" });
  });

  it("rejects a reused authorization code (single-use)", () => {
    const client = register();
    const { verifier, challenge } = pkce();
    const code = svc.createAuthCode({ client_id: client.client_id, redirect_uri: REDIRECT, code_challenge: challenge, scope: "mcp" });
    svc.redeemAuthCode({ code, client_id: client.client_id, redirect_uri: REDIRECT, code_verifier: verifier });
    expect(() => svc.redeemAuthCode({ code, client_id: client.client_id, redirect_uri: REDIRECT, code_verifier: verifier })).toThrow(/already used/i);
  });

  it("rejects a wrong PKCE verifier", () => {
    const client = register();
    const { challenge } = pkce();
    const code = svc.createAuthCode({ client_id: client.client_id, redirect_uri: REDIRECT, code_challenge: challenge, scope: "mcp" });
    expect(() => svc.redeemAuthCode({ code, client_id: client.client_id, redirect_uri: REDIRECT, code_verifier: "wrong-verifier" })).toThrow(/PKCE/i);
  });

  it("rejects redirect_uri or client mismatch", () => {
    const client = register();
    const { verifier, challenge } = pkce();
    const code = svc.createAuthCode({ client_id: client.client_id, redirect_uri: REDIRECT, code_challenge: challenge, scope: "mcp" });
    expect(() => svc.redeemAuthCode({ code, client_id: "someone-else", redirect_uri: REDIRECT, code_verifier: verifier })).toThrow(/client mismatch/i);
  });

  it("rotates the refresh token on use and rejects the old one", () => {
    const client = register();
    const { verifier, challenge } = pkce();
    const code = svc.createAuthCode({ client_id: client.client_id, redirect_uri: REDIRECT, code_challenge: challenge, scope: "mcp" });
    const first = svc.redeemAuthCode({ code, client_id: client.client_id, redirect_uri: REDIRECT, code_verifier: verifier });
    const refreshed = svc.refresh(first.refresh_token); // client_id optional
    expect(svc.validateAccessToken(refreshed.access_token)).toBeTruthy();
    expect(refreshed.refresh_token).not.toBe(first.refresh_token);
    // The presented (now rotated-out) refresh token must no longer work.
    expect(() => svc.refresh(first.refresh_token)).toThrow(/unknown refresh token/i);
  });

  it("rejects a refresh with a mismatched client_id but allows omitting it", () => {
    const client = register();
    const { verifier, challenge } = pkce();
    const code = svc.createAuthCode({ client_id: client.client_id, redirect_uri: REDIRECT, code_challenge: challenge, scope: "mcp" });
    const first = svc.redeemAuthCode({ code, client_id: client.client_id, redirect_uri: REDIRECT, code_verifier: verifier });
    expect(() => svc.refresh(first.refresh_token, "other-client")).toThrow(/client mismatch/i);
    // The token wasn't rotated (the mismatch threw before deletion), so omitting client_id still works.
    expect(svc.refresh(first.refresh_token).access_token).toBeTruthy();
  });

  it("revokes an individual access token (RFC 7009)", () => {
    const client = register();
    const { verifier, challenge } = pkce();
    const code = svc.createAuthCode({ client_id: client.client_id, redirect_uri: REDIRECT, code_challenge: challenge, scope: "mcp" });
    const tokens = svc.redeemAuthCode({ code, client_id: client.client_id, redirect_uri: REDIRECT, code_verifier: verifier });
    expect(svc.validateAccessToken(tokens.access_token)).toBeTruthy();
    expect(svc.revokeToken(tokens.access_token)).toBe(true);
    expect(svc.validateAccessToken(tokens.access_token)).toBeNull();
  });

  it("invalidates all tokens when a client is revoked", () => {
    const client = register();
    const { verifier, challenge } = pkce();
    const code = svc.createAuthCode({ client_id: client.client_id, redirect_uri: REDIRECT, code_challenge: challenge, scope: "mcp" });
    const tokens = svc.redeemAuthCode({ code, client_id: client.client_id, redirect_uri: REDIRECT, code_verifier: verifier });
    expect(svc.validateAccessToken(tokens.access_token)).toBeTruthy();
    svc.revokeClient(client.client_id);
    expect(svc.validateAccessToken(tokens.access_token)).toBeNull();
    expect(() => svc.refresh(tokens.refresh_token, client.client_id)).toThrow();
  });

  it("returns null for an unknown access token", () => {
    expect(svc.validateAccessToken("nope")).toBeNull();
  });
});
