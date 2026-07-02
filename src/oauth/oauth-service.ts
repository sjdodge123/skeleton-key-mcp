import Database from "better-sqlite3";
import { createHash, randomBytes } from "node:crypto";
import { mkdirSync } from "node:fs";
import path from "node:path";
import { paths } from "../config/paths.js";

/**
 * Minimal OAuth 2.1 authorization server for the MCP endpoint.
 *
 * Implements what the MCP authorization spec needs: dynamic client registration
 * (RFC 7591), authorization-code grant with mandatory PKCE (S256), refresh
 * tokens, and token revocation. Tokens and codes are opaque random strings
 * stored only as SHA-256 hashes, so a database leak can't be replayed. Access
 * tokens are short-lived; refresh tokens are long-lived and revocable from the
 * web UI. Consent is gated by the admin TOTP (see oauth-routes).
 */

const AUTH_CODE_TTL_S = 300; // 5 min
const ACCESS_TTL_S = 3600; // 1 hour
const REFRESH_TTL_S = 30 * 24 * 3600; // 30 days

export const OAUTH_SCOPE = "mcp";

function sha256(v: string): string {
  return createHash("sha256").update(v).digest("hex");
}
function token(bytes = 32): string {
  return randomBytes(bytes).toString("base64url");
}
function nowS(): number {
  return Math.floor(Date.now() / 1000);
}

export interface OAuthClient {
  client_id: string;
  client_name: string;
  redirect_uris: string[];
  created_at: number;
}

export interface AccessInfo {
  client_id: string;
  scope: string;
}

export class OAuthService {
  private readonly db: Database.Database;

  constructor(file: string = path.join(paths.dataDir, "oauth.sqlite")) {
    mkdirSync(path.dirname(file), { recursive: true });
    this.db = new Database(file);
    this.db.pragma("journal_mode = WAL");
    this.db.exec(`
      CREATE TABLE IF NOT EXISTS clients (
        client_id TEXT PRIMARY KEY,
        client_name TEXT NOT NULL,
        redirect_uris TEXT NOT NULL,
        created_at INTEGER NOT NULL
      );
      CREATE TABLE IF NOT EXISTS auth_codes (
        code_hash TEXT PRIMARY KEY,
        client_id TEXT NOT NULL,
        redirect_uri TEXT NOT NULL,
        code_challenge TEXT NOT NULL,
        scope TEXT NOT NULL,
        expires_at INTEGER NOT NULL,
        used INTEGER NOT NULL DEFAULT 0
      );
      CREATE TABLE IF NOT EXISTS tokens (
        token_hash TEXT PRIMARY KEY,
        type TEXT NOT NULL,               -- 'access' | 'refresh'
        client_id TEXT NOT NULL,
        scope TEXT NOT NULL,
        expires_at INTEGER NOT NULL,
        created_at INTEGER NOT NULL
      );
    `);
  }

  // --- Dynamic client registration (RFC 7591) ---
  registerClient(input: { client_name?: string; redirect_uris: string[] }): OAuthClient {
    if (!Array.isArray(input.redirect_uris) || input.redirect_uris.length === 0) {
      throw new Error("redirect_uris is required");
    }
    const client: OAuthClient = {
      client_id: `client_${token(16)}`,
      client_name: input.client_name?.slice(0, 200) || "MCP client",
      redirect_uris: input.redirect_uris,
      created_at: nowS(),
    };
    this.db
      .prepare(`INSERT INTO clients (client_id, client_name, redirect_uris, created_at) VALUES (?, ?, ?, ?)`)
      .run(client.client_id, client.client_name, JSON.stringify(client.redirect_uris), client.created_at);
    return client;
  }

  getClient(clientId: string): OAuthClient | undefined {
    const row = this.db.prepare(`SELECT * FROM clients WHERE client_id = ?`).get(clientId) as
      | { client_id: string; client_name: string; redirect_uris: string; created_at: number }
      | undefined;
    if (!row) return undefined;
    return { ...row, redirect_uris: JSON.parse(row.redirect_uris) };
  }

  // --- Authorization code ---
  createAuthCode(input: {
    client_id: string;
    redirect_uri: string;
    code_challenge: string;
    scope: string;
  }): string {
    const code = token();
    this.db
      .prepare(
        `INSERT INTO auth_codes (code_hash, client_id, redirect_uri, code_challenge, scope, expires_at, used)
         VALUES (?, ?, ?, ?, ?, ?, 0)`,
      )
      .run(sha256(code), input.client_id, input.redirect_uri, input.code_challenge, input.scope, nowS() + AUTH_CODE_TTL_S);
    return code;
  }

  /** Exchange an auth code for tokens, verifying PKCE. Single-use. */
  redeemAuthCode(input: {
    code: string;
    client_id: string;
    redirect_uri: string;
    code_verifier: string;
  }): { access_token: string; refresh_token: string; expires_in: number; scope: string } {
    const row = this.db.prepare(`SELECT * FROM auth_codes WHERE code_hash = ?`).get(sha256(input.code)) as
      | { code_hash: string; client_id: string; redirect_uri: string; code_challenge: string; scope: string; expires_at: number; used: number }
      | undefined;
    if (!row) throw new Error("invalid_grant: unknown code");
    // Always burn the code on any redemption attempt.
    this.db.prepare(`UPDATE auth_codes SET used = 1 WHERE code_hash = ?`).run(row.code_hash);
    if (row.used) throw new Error("invalid_grant: code already used");
    if (row.expires_at < nowS()) throw new Error("invalid_grant: code expired");
    if (row.client_id !== input.client_id) throw new Error("invalid_grant: client mismatch");
    if (row.redirect_uri !== input.redirect_uri) throw new Error("invalid_grant: redirect_uri mismatch");
    // PKCE S256 verification.
    const challenge = createHash("sha256").update(input.code_verifier).digest("base64url");
    if (challenge !== row.code_challenge) throw new Error("invalid_grant: PKCE verification failed");
    return this.issueTokens(row.client_id, row.scope);
  }

  private issueTokens(clientId: string, scope: string): { access_token: string; refresh_token: string; expires_in: number; scope: string } {
    const access = token();
    const refresh = token();
    const t = nowS();
    const insert = this.db.prepare(
      `INSERT INTO tokens (token_hash, type, client_id, scope, expires_at, created_at) VALUES (?, ?, ?, ?, ?, ?)`,
    );
    insert.run(sha256(access), "access", clientId, scope, t + ACCESS_TTL_S, t);
    insert.run(sha256(refresh), "refresh", clientId, scope, t + REFRESH_TTL_S, t);
    return { access_token: access, refresh_token: refresh, expires_in: ACCESS_TTL_S, scope };
  }

  /**
   * Refresh grant with rotation: the presented refresh token is invalidated and a
   * new access+refresh pair is issued, so a leaked refresh token stops working the
   * moment the legitimate client next refreshes. `clientId` is optional (OAuth 2.1
   * public clients may omit it on refresh); if supplied it must match.
   */
  refresh(refreshToken: string, clientId?: string): { access_token: string; refresh_token: string; expires_in: number; scope: string } {
    const hash = sha256(refreshToken);
    const row = this.db.prepare(`SELECT * FROM tokens WHERE token_hash = ? AND type = 'refresh'`).get(hash) as
      | { client_id: string; scope: string; expires_at: number }
      | undefined;
    if (!row) throw new Error("invalid_grant: unknown refresh token");
    if (row.expires_at < nowS()) throw new Error("invalid_grant: refresh token expired");
    if (clientId && row.client_id !== clientId) throw new Error("invalid_grant: client mismatch");
    // Rotate: burn the presented refresh token before issuing the new pair.
    this.db.prepare(`DELETE FROM tokens WHERE token_hash = ?`).run(hash);
    return this.issueTokens(row.client_id, row.scope);
  }

  /** Revoke a single access or refresh token (RFC 7009). */
  revokeToken(t: string): boolean {
    return this.db.prepare(`DELETE FROM tokens WHERE token_hash = ?`).run(sha256(t)).changes > 0;
  }

  /** Validate a bearer access token; returns null if invalid/expired. */
  validateAccessToken(accessToken: string): AccessInfo | null {
    const row = this.db.prepare(`SELECT client_id, scope, expires_at FROM tokens WHERE token_hash = ? AND type = 'access'`).get(sha256(accessToken)) as
      | { client_id: string; scope: string; expires_at: number }
      | undefined;
    if (!row || row.expires_at < nowS()) return null;
    return { client_id: row.client_id, scope: row.scope };
  }

  // --- Management (web UI) ---
  listClientsWithTokens(): { client: OAuthClient; activeAccessTokens: number; activeRefreshTokens: number; lastIssued: number | null }[] {
    const clients = this.db.prepare(`SELECT * FROM clients ORDER BY created_at DESC`).all() as {
      client_id: string; client_name: string; redirect_uris: string; created_at: number;
    }[];
    const t = nowS();
    return clients.map((c) => {
      const counts = this.db
        .prepare(`SELECT type, COUNT(*) n, MAX(created_at) last FROM tokens WHERE client_id = ? AND expires_at > ? GROUP BY type`)
        .all(c.client_id, t) as { type: string; n: number; last: number }[];
      const access = counts.find((x) => x.type === "access");
      const refresh = counts.find((x) => x.type === "refresh");
      return {
        client: { ...c, redirect_uris: JSON.parse(c.redirect_uris) },
        activeAccessTokens: access?.n ?? 0,
        activeRefreshTokens: refresh?.n ?? 0,
        lastIssued: Math.max(access?.last ?? 0, refresh?.last ?? 0) || null,
      };
    });
  }

  /** Revoke a client and all its tokens. */
  revokeClient(clientId: string): boolean {
    const info = this.db.prepare(`DELETE FROM tokens WHERE client_id = ?`).run(clientId);
    const c = this.db.prepare(`DELETE FROM clients WHERE client_id = ?`).run(clientId);
    this.db.prepare(`DELETE FROM auth_codes WHERE client_id = ?`).run(clientId);
    return c.changes > 0 || info.changes > 0;
  }

  /** Housekeeping: drop expired codes/tokens. */
  purgeExpired(): void {
    const t = nowS();
    this.db.prepare(`DELETE FROM auth_codes WHERE expires_at < ?`).run(t);
    this.db.prepare(`DELETE FROM tokens WHERE expires_at < ?`).run(t);
  }

  close(): void {
    this.db.close();
  }
}
