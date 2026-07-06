import { describe, it, expect, beforeEach, afterEach, vi } from "vitest";
import express from "express";
import { mkdtemp, rm } from "node:fs/promises";
import { tmpdir } from "node:os";
import path from "node:path";
import type { Server } from "node:http";
import { AppState } from "../app.js";
import { mountMcp } from "./server.js";

/**
 * Exercises the real stateful MCP endpoint (mountMcp) end-to-end over HTTP with a
 * pass-through auth middleware — in particular the teardown path (DELETE), which
 * a code review caught was infinite-recursing before the fix.
 */

let dir: string;
let app: AppState;
let httpServer: Server;
let handle: { stop: () => void };
let base: string;

beforeEach(async () => {
  // Keep unlock guidance deterministic (host-agnostic) regardless of ambient env.
  vi.stubEnv("SKELETON_KEY_PUBLIC_URL", "");
  dir = await mkdtemp(path.join(tmpdir(), "skmcp-mcp-"));
  process.env.SKELETON_KEY_DATA_DIR = dir;
  app = await AppState.create();
  const ex = express();
  ex.use(express.json());
  handle = mountMcp(ex, app, (_req, _res, next) => next()); // no auth for the test
  await new Promise<void>((resolve) => {
    httpServer = ex.listen(0, () => resolve());
  });
  const port = (httpServer.address() as { port: number }).port;
  base = `http://127.0.0.1:${port}/mcp`;
});

afterEach(async () => {
  vi.unstubAllEnvs();
  handle.stop();
  httpServer.close();
  app.audit.close();
  app.oauth.close();
  await rm(dir, { recursive: true, force: true });
});

const H = { "content-type": "application/json", accept: "application/json, text/event-stream" };

function parseSse(text: string): any {
  const line = text.split("\n").find((l) => l.startsWith("data:"));
  return JSON.parse(line ? line.slice(5).trim() : text);
}

async function initialize(): Promise<string> {
  const r = await fetch(base, {
    method: "POST",
    headers: H,
    body: JSON.stringify({ jsonrpc: "2.0", id: 1, method: "initialize", params: { protocolVersion: "2024-11-05", capabilities: {}, clientInfo: { name: "t", version: "1" } } }),
  });
  const sid = r.headers.get("mcp-session-id");
  await r.text();
  if (!sid) throw new Error("no session id");
  return sid;
}

describe("stateful MCP endpoint", () => {
  it("while locked, tools/list advertises only the banner-only get_started (kill-switch)", async () => {
    // A fresh AppState is locked, so tools/list must not enumerate the rest of
    // the toolset (which would leak target names/types) — only get_started.
    const sid = await initialize();
    const SH = { ...H, "mcp-session-id": sid };
    await fetch(base, { method: "POST", headers: SH, body: JSON.stringify({ jsonrpc: "2.0", method: "notifications/initialized" }) });
    const r = await fetch(base, { method: "POST", headers: SH, body: JSON.stringify({ jsonrpc: "2.0", id: 2, method: "tools/list", params: {} }) });
    const names = (parseSse(await r.text()).result?.tools ?? []).map((t: { name: string }) => t.name);
    expect(names).toContain("get_started");
    expect(names).not.toContain("network_scan");
    expect(names).not.toContain("request_credential");
    expect(names).not.toContain("vault_delete_credential");
  });

  it("tears down cleanly on DELETE without recursing, and forgets the session", async () => {
    const sid = await initialize();
    // DELETE must return promptly (would hang/stack-overflow with the recursion bug).
    const del = await fetch(base, { method: "DELETE", headers: { ...H, "mcp-session-id": sid } });
    expect(del.status).toBeLessThan(500);
    await del.text();
    // The session is gone: a follow-up call with the old id gets a 404, the
    // spec's signal for "re-initialize transparently".
    const r = await fetch(base, { method: "POST", headers: { ...H, "mcp-session-id": sid }, body: JSON.stringify({ jsonrpc: "2.0", id: 3, method: "tools/list", params: {} }) });
    expect(r.status).toBe(404);
    const body = parseSse(await r.text());
    expect(body.error?.code).toBe(-32001);
  });

  it("answers an unknown session id with 404 so clients re-initialize (spec) — GET and POST", async () => {
    // This is what lets a connected client survive a server restart without a
    // manual reconnect: 404 (not 400) triggers transparent re-initialization.
    const g = await fetch(base, { method: "GET", headers: { ...H, "mcp-session-id": "bogus" } });
    expect(g.status).toBe(404);
    const gBody = await g.json();
    expect(gBody.jsonrpc).toBe("2.0");
    expect(gBody.error.code).toBe(-32001);

    const p = await fetch(base, { method: "POST", headers: { ...H, "mcp-session-id": "bogus" }, body: JSON.stringify({ jsonrpc: "2.0", id: 4, method: "tools/list", params: {} }) });
    expect(p.status).toBe(404);
    expect((await p.json()).error.code).toBe(-32001);
  });

  it("records session_init on initialize and session_stale on an unknown session (activity log)", async () => {
    await initialize();
    expect(app.audit.recent().some((e) => e.tool === "mcp.session_init")).toBe(true);
    // A post-restart client hits an unknown session id → we log the re-init signal.
    await fetch(base, { method: "POST", headers: { ...H, "mcp-session-id": "bogus" }, body: JSON.stringify({ jsonrpc: "2.0", id: 99, method: "tools/list", params: {} }) });
    expect(app.audit.recent().some((e) => e.tool === "mcp.session_stale")).toBe(true);
  });

  it("rejects a non-initialize POST without a session", async () => {
    const r = await fetch(base, { method: "POST", headers: H, body: JSON.stringify({ jsonrpc: "2.0", id: 9, method: "tools/list", params: {} }) });
    expect(r.status).toBe(400);
    expect((await r.json()).error.code).toBe(-32000);
  });

  // A fresh AppState is locked (store + vault), which is exactly the post-restart
  // state the locked-vault UX is about.
  describe("while the vault is locked", () => {
    async function callTool(sid: string, name: string, id: number): Promise<{ text: string; isError?: boolean }> {
      const r = await fetch(base, {
        method: "POST",
        headers: { ...H, "mcp-session-id": sid },
        body: JSON.stringify({ jsonrpc: "2.0", id, method: "tools/call", params: { name, arguments: {} } }),
      });
      const result = parseSse(await r.text()).result;
      return { text: result?.content?.[0]?.text ?? "", isError: result?.isError };
    }

    it("short-circuits credential-needing tools with unlock guidance", async () => {
      const sid = await initialize();
      const { text, isError } = await callTool(sid, "vault_list_credentials", 10);
      expect(isError).toBe(true);
      expect(text).toContain("locked");
      expect(text).toContain("master passphrase");
    });

    it("keeps get_started working, leads with how to unlock, and reveals no targets", async () => {
      const sid = await initialize();
      const { text, isError } = await callTool(sid, "get_started", 11);
      expect(isError).toBeFalsy();
      expect(text).toContain("locked");
      expect(text).toContain("master passphrase");
      expect(text).toContain("no targets or tools are available");
    });

    it("withholds list_targets while locked (no enumeration before unlock)", async () => {
      const sid = await initialize();
      const { text, isError } = await callTool(sid, "list_targets", 12);
      expect(isError).toBe(true);
      expect(text).toContain("locked");
    });

    it("withholds network_scan while locked", async () => {
      const sid = await initialize();
      const { isError } = await callTool(sid, "network_scan", 13);
      expect(isError).toBe(true);
    });

    it("returns identical locked guidance for an unknown/per-target tool name (no enumeration)", async () => {
      const sid = await initialize();
      // A name that would reveal a target if the error differed from a real tool's.
      const { text, isError } = await callTool(sid, "ssh.secret-nas.run_command", 15);
      expect(isError).toBe(true);
      expect(text).toContain("locked");
      expect(text).not.toContain("Unknown tool"); // must not distinguish existence
    });

    it("does not echo the request Host into unlock guidance", async () => {
      const sid = await initialize();
      const { text } = await callTool(sid, "vault_list_credentials", 14);
      // No SKELETON_KEY_PUBLIC_URL in tests → guidance stays host-agnostic.
      expect(text).not.toContain("127.0.0.1");
    });
  });
});
