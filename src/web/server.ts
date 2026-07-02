import express from "express";
import { StreamableHTTPServerTransport } from "@modelcontextprotocol/sdk/server/streamableHttp.js";
import type { AppState } from "../app.js";
import { buildMcpServer } from "../mcp/server.js";
import { buildApiRouter } from "./routes.js";
import { mcpAuth } from "./auth.js";
import { WIZARD_HTML } from "./ui.js";

/**
 * Single Express app serving three things on one LAN-bound port:
 *   /mcp   — the MCP Streamable HTTP endpoint (bearer-authed, stateless)
 *   /api   — wizard + admin REST API
 *   /      — the setup wizard UI
 */
export function buildHttpApp(app: AppState): express.Express {
  const server = express();
  server.use(express.json({ limit: "4mb" }));

  // MCP endpoint. Stateless: a fresh Server+transport per request keeps the
  // dynamic tool set correct and avoids session bookkeeping for a single user.
  server.post("/mcp", mcpAuth(app), async (req, res) => {
    const mcp = buildMcpServer(app);
    const transport = new StreamableHTTPServerTransport({ sessionIdGenerator: undefined });
    res.on("close", () => {
      transport.close();
      mcp.close();
    });
    try {
      await mcp.connect(transport);
      await transport.handleRequest(req, res, req.body);
    } catch (err) {
      if (!res.headersSent) {
        res.status(500).json({ error: err instanceof Error ? err.message : String(err) });
      }
    }
  });

  // Streamable HTTP GET/DELETE are unused in stateless mode.
  server.get("/mcp", (_req, res) => res.status(405).json({ error: "Method not allowed (stateless)." }));
  server.delete("/mcp", (_req, res) => res.status(405).json({ error: "Method not allowed (stateless)." }));

  server.use("/api", buildApiRouter(app));

  // Wizard UI (also lands here post-setup; a full admin console replaces it later).
  server.get("/", (_req, res) => {
    res.type("html").send(WIZARD_HTML);
  });

  server.get("/healthz", (_req, res) => res.json({ ok: true }));

  return server;
}
