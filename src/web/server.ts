import express from "express";
import { randomUUID } from "node:crypto";
import { StreamableHTTPServerTransport } from "@modelcontextprotocol/sdk/server/streamableHttp.js";
import { isInitializeRequest } from "@modelcontextprotocol/sdk/types.js";
import type { AppState } from "../app.js";
import { buildMcpServer } from "../mcp/server.js";
import { buildApiRouter } from "./routes.js";
import { buildOAuthRouter } from "./oauth-routes.js";
import { buildCredentialRouter } from "./credential-routes.js";
import { buildAdminRouter } from "./admin-routes.js";
import { mcpAuth } from "./auth.js";
import { WIZARD_HTML } from "./ui.js";

interface McpSession {
  transport: StreamableHTTPServerTransport;
  unsubscribe: () => void;
  lastSeen: number;
}

/** Sessions idle longer than this are swept (clients that dropped without DELETE). */
const SESSION_IDLE_MS = 30 * 60 * 1000;
/** Hard cap on concurrent sessions as a backstop against runaway growth. */
const MAX_SESSIONS = 64;

function jsonRpcError(res: express.Response, status: number, code: number, message: string): void {
  res.status(status).json({ jsonrpc: "2.0", error: { code, message }, id: null });
}

/**
 * Mount the stateful MCP endpoint (POST/GET/DELETE /mcp) on `server`, gated by
 * `auth`. Stateful so the server can push `tools/list_changed` when the tool set
 * changes mid-session (e.g. register_target). Exported so tests can mount it
 * with a pass-through auth middleware and exercise the session lifecycle.
 * Returns a handle to stop the idle sweeper.
 */
export function mountMcp(server: express.Express, app: AppState, auth: express.RequestHandler): { stop: () => void } {
  const sessions = new Map<string, McpSession>();

  // Record MCP connection lifecycle into the audit log so the activity view shows
  // connects/reconnects — and so a post-restart client re-initialize is visible
  // (a `session_stale` 404 followed by a fresh `session_init` = the client
  // auto-recovered; silence = it didn't). Best-effort: never let an audit write
  // break the transport.
  //
  // Throttled per event type: an authenticated client can otherwise cheaply
  // hammer the unknown-session→404 path and flood audit.sqlite. For diagnosis one
  // record per burst is enough, so we coalesce to at most one write per type per
  // window — bounding disk growth from this path to a trickle.
  const SESSION_LOG_THROTTLE_MS = 10_000;
  const lastSessionLogAt = new Map<string, number>();
  const logSession = (tool: string, detail: string): void => {
    const now = Date.now();
    if (now - (lastSessionLogAt.get(tool) ?? 0) < SESSION_LOG_THROTTLE_MS) return;
    lastSessionLogAt.set(tool, now);
    try {
      app.audit.record({ ts: new Date().toISOString(), tool, target: "(mcp)", tier: "session", args: {}, status: "ok", detail });
    } catch {
      /* audit is best-effort */
    }
  };

  // Remove a session and its listener. `closeTransport` is false when called
  // FROM the transport's own onclose (the transport is already closing — calling
  // transport.close() again would recurse); true when we initiate teardown.
  const dropSession = (id: string, closeTransport: boolean): void => {
    const s = sessions.get(id);
    if (!s) return;
    sessions.delete(id); // delete first so a re-entrant onclose is a no-op
    s.unsubscribe();
    if (closeTransport) {
      try {
        s.transport.close();
      } catch {
        /* ignore */
      }
    }
  };

  // Sweep sessions that went idle (client dropped without a DELETE); the SDK
  // doesn't fire onclose for a silently-dropped stream, so without this the
  // session + its onToolsChanged listener would leak forever.
  const sweeper = setInterval(() => {
    const cutoff = Date.now() - SESSION_IDLE_MS;
    for (const [id, s] of sessions) if (s.lastSeen < cutoff) dropSession(id, true);
  }, 60 * 1000);
  sweeper.unref();

  server.post("/mcp", auth, async (req, res) => {
    let registeredId: string | undefined;
    try {
      const sid = req.header("mcp-session-id");
      const existing = sid ? sessions.get(sid) : undefined;
      if (existing) {
        existing.lastSeen = Date.now();
        await existing.transport.handleRequest(req, res, req.body);
        return;
      }
      if (!isInitializeRequest(req.body)) {
        // Spec: an unknown/terminated session ID gets 404, which tells the
        // client to transparently re-initialize — without it, every server
        // restart strands connected clients on a dead session until a manual
        // reconnect. A request with no session at all is a plain 400.
        if (sid) {
          logSession("mcp.session_stale", `stale session ${sid.slice(0, 8)}… → 404 (client asked to re-initialize)`);
          jsonRpcError(res, 404, -32001, "Session not found; re-initialize.");
        } else {
          jsonRpcError(res, 400, -32000, "No valid session; send an initialize request first.");
        }
        return;
      }
      if (sessions.size >= MAX_SESSIONS) {
        // Evict the oldest to bound memory.
        const oldest = [...sessions.entries()].sort((a, b) => a[1].lastSeen - b[1].lastSeen)[0];
        if (oldest) dropSession(oldest[0], true);
      }
      // New session.
      const mcp = buildMcpServer(app);
      const transport = new StreamableHTTPServerTransport({
        sessionIdGenerator: () => randomUUID(),
        onsessioninitialized: (id) => {
          registeredId = id;
          // Push tools/list_changed to this session whenever the tool set changes.
          const unsubscribe = app.onToolsChanged(() => {
            mcp.sendToolListChanged().catch((e) =>
              console.error("[skeleton-key] tools/list_changed push failed:", e instanceof Error ? e.message : e),
            );
          });
          sessions.set(id, { transport, unsubscribe, lastSeen: Date.now() });
          logSession("mcp.session_init", `session ${id.slice(0, 8)}… initialized`);
        },
      });
      // Clean up when the transport closes (explicit DELETE or transport-level
      // close). Do NOT call mcp.close() here — Protocol.close() re-closes the
      // transport and would recurse. The Server is released via GC once the
      // session entry and its closures are dropped.
      transport.onclose = () => {
        if (transport.sessionId) dropSession(transport.sessionId, false);
      };
      await mcp.connect(transport);
      await transport.handleRequest(req, res, req.body);
    } catch (err) {
      // If the session was already registered before the throw, don't orphan it.
      if (registeredId) dropSession(registeredId, true);
      if (!res.headersSent) {
        jsonRpcError(res, 500, -32603, err instanceof Error ? err.message : String(err));
      }
    }
  });

  // GET opens the server→client SSE stream; DELETE terminates the session.
  const bySession = async (req: express.Request, res: express.Response): Promise<void> => {
    const sid = req.header("mcp-session-id");
    const session = sid ? sessions.get(sid) : undefined;
    if (!session) {
      // 404 for a stale/unknown session (client should re-initialize), 400 when
      // the header is missing entirely.
      if (sid) jsonRpcError(res, 404, -32001, "Session not found; re-initialize.");
      else jsonRpcError(res, 400, -32000, "Missing Mcp-Session-Id.");
      return;
    }
    session.lastSeen = Date.now();
    await session.transport.handleRequest(req, res);
  };
  server.get("/mcp", auth, bySession);
  server.delete("/mcp", auth, bySession);

  return { stop: () => clearInterval(sweeper) };
}

/**
 * Single Express app serving three things on one LAN-bound port:
 *   /mcp   — the MCP Streamable HTTP endpoint (OAuth/bearer-authed, stateful)
 *   /api   — wizard + admin REST API
 *   /      — the setup wizard UI
 */
export function buildHttpApp(app: AppState): express.Express {
  const server = express();
  server.use(express.json({ limit: "4mb" }));
  // OAuth token/consent requests are form-encoded.
  server.use(express.urlencoded({ extended: false }));

  // OAuth 2.1 authorization server (discovery, registration, consent, token).
  server.use(buildOAuthRouter(app));

  // Secure credential hand-off pages (TOTP-gated; secrets go browser→vault).
  server.use(buildCredentialRouter(app));

  // Admin activity view (TOTP-gated audit log — the transparency surface).
  server.use(buildAdminRouter(app));

  // MCP endpoint (stateful — see mountMcp).
  mountMcp(server, app, mcpAuth(app));

  server.use("/api", buildApiRouter(app));

  // Wizard UI (also lands here post-setup; a full admin console replaces it later).
  server.get("/", (_req, res) => {
    res.type("html").send(WIZARD_HTML);
  });

  server.get("/healthz", (_req, res) => res.json({ ok: true }));

  return server;
}
