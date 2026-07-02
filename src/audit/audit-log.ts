import Database from "better-sqlite3";
import { createHash } from "node:crypto";
import { mkdirSync } from "node:fs";
import path from "node:path";
import { paths } from "../config/paths.js";

export interface AuditEntry {
  id: number;
  ts: string;
  tool: string;
  target: string;
  tier: string;
  argsDigest: string;
  status: "ok" | "error" | "denied";
  detail: string | null;
}

/**
 * Append-only record of every tool invocation. Arguments are stored as a SHA-256
 * digest, never in the clear, so the log can't leak secrets that were passed in.
 */
export class AuditLog {
  private readonly db: Database.Database;

  constructor(file: string = paths.auditDb) {
    mkdirSync(path.dirname(file), { recursive: true });
    this.db = new Database(file);
    this.db.pragma("journal_mode = WAL");
    this.db.exec(`
      CREATE TABLE IF NOT EXISTS audit (
        id         INTEGER PRIMARY KEY AUTOINCREMENT,
        ts         TEXT NOT NULL,
        tool       TEXT NOT NULL,
        target     TEXT NOT NULL,
        tier       TEXT NOT NULL,
        args_digest TEXT NOT NULL,
        status     TEXT NOT NULL,
        detail     TEXT
      );
    `);
  }

  private static digest(args: unknown): string {
    return createHash("sha256").update(JSON.stringify(args ?? null)).digest("hex").slice(0, 32);
  }

  record(params: {
    ts: string;
    tool: string;
    target: string;
    tier: string;
    args: unknown;
    status: AuditEntry["status"];
    detail?: string;
  }): void {
    this.db
      .prepare(
        `INSERT INTO audit (ts, tool, target, tier, args_digest, status, detail)
         VALUES (@ts, @tool, @target, @tier, @argsDigest, @status, @detail)`,
      )
      .run({
        ts: params.ts,
        tool: params.tool,
        target: params.target,
        tier: params.tier,
        argsDigest: AuditLog.digest(params.args),
        status: params.status,
        detail: params.detail ?? null,
      });
  }

  recent(limit = 100): AuditEntry[] {
    return this.db
      .prepare(
        `SELECT id, ts, tool, target, tier, args_digest AS argsDigest, status, detail
         FROM audit ORDER BY id DESC LIMIT ?`,
      )
      .all(limit) as AuditEntry[];
  }

  close(): void {
    this.db.close();
  }
}
