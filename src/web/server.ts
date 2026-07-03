import express from "express";
import { randomUUID } from "node:crypto";
import { StreamableHTTPServerTransport } from "@modelcontextprotocol/sdk/server/streamableHttp.js";
import { isInitializeRequest } from "@modelcontextprotocol/sdk/types.js";
import type { AppState } from "../app.js";
import { buildMcpServer } from "../mcp/server.js";
import { buildApiRouter } from "./routes.js";
import { buildOAuthRouter } from "./oauth-routes.js";
import { mcpAuth } from "./auth.js";
import { WIZARD_HTML } from "./ui.js";

interface McpSession {
  transport: StreamableHTTPServerTransport;
  mcp: ReturnType<typeof buildMcpServer>;
  unsubscribe: () => void;
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

  // MCP endpoint. Stateful so the server can push `tools/list_changed` when the
  // tool set changes mid-session (e.g. register_target) — the new tools then
  // appear in the client without a reconnect. Sessions are keyed by the
  // Mcp-Session-Id header the transport assigns on initialize.
  const sessions = new Map<string, McpSession>();

  server.post("/mcp", mcpAuth(app), async (req, res) => {
    try {
      const sid = req.header("mcp-session-id");
      const existing = sid ? sessions.get(sid) : undefined;
      if (existing) {
        await existing.transport.handleRequest(req, res, req.body);
        return;
      }
      if (!isInitializeRequest(req.body)) {
        res.status(400).json({
          jsonrpc: "2.0",
          error: { code: -32000, message: "No valid session; send an initialize request first." },
          id: null,
        });
        return;
      }
      // New session.
      const mcp = buildMcpServer(app);
      const transport = new StreamableHTTPServerTransport({
        sessionIdGenerator: () => randomUUID(),
        onsessioninitialized: (id) => {
          // Push tools/list_changed to this session whenever the tool set changes.
          const unsubscribe = app.onToolsChanged(() => {
            mcp.sendToolListChanged().catch(() => {});
          });
          sessions.set(id, { transport, mcp, unsubscribe });
        },
      });
      transport.onclose = () => {
        const id = transport.sessionId;
        if (id) {
          sessions.get(id)?.unsubscribe();
          sessions.delete(id);
        }
        mcp.close();
      };
      await mcp.connect(transport);
      await transport.handleRequest(req, res, req.body);
    } catch (err) {
      if (!res.headersSent) {
        res.status(500).json({ error: err instanceof Error ? err.message : String(err) });
      }
    }
  });

  // GET opens the server→client SSE stream; DELETE terminates the session.
  const bySession = async (req: express.Request, res: express.Response): Promise<void> => {
    const sid = req.header("mcp-session-id");
    const session = sid ? sessions.get(sid) : undefined;
    if (!session) {
      res.status(400).json({ error: "Unknown or missing Mcp-Session-Id." });
      return;
    }
    await session.transport.handleRequest(req, res);
  };
  server.get("/mcp", mcpAuth(app), bySession);
  server.delete("/mcp", mcpAuth(app), bySession);

  server.use("/api", buildApiRouter(app));

  // Wizard UI (also lands here post-setup; a full admin console replaces it later).
  server.get("/", (_req, res) => {
    res.type("html").send(WIZARD_HTML);
  });

  server.get("/healthz", (_req, res) => res.json({ ok: true }));

  return server;
}
