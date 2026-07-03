import { Server } from "@modelcontextprotocol/sdk/server/index.js";
import {
  CallToolRequestSchema,
  ListToolsRequestSchema,
  type Tool,
} from "@modelcontextprotocol/sdk/types.js";
import { zodToJsonSchema } from "zod-to-json-schema";
import type { AppState } from "../app.js";
import { resolveTools, findTool } from "./tool-registry.js";
import { annotationsFor, confirmationText, EXECUTE_DISABLED } from "./approval.js";

/**
 * Sent to the client on connect (MCP `instructions`), so a freshly-connected
 * session understands what Skeleton Key is and how to onboard without the user
 * having to remember the right prompts.
 */
const SERVER_INSTRUCTIONS = [
  "Skeleton Key gives you audited access to the user's self-hosted homelab: read logs, run approved commands, and manage services across their machines.",
  "",
  "Getting started — if the user hasn't set up targets yet, offer to onboard them (call `get_started` for live status). The typical flow, all conversational:",
  "1. `network_scan` (pass their LAN subnet, e.g. '192.168.0', when asked) to map services.",
  "2. `vault_generate_ssh_key` to create + store an SSH key for a host, then give the user the returned public key to install (they must install it — you cannot).",
  "3. `register_target` to add the host so its per-target tools appear.",
  "4. `vault_validate_ssh` to confirm access works.",
  "",
  "Tool tiers: 'read' tools are safe; 'execute' tools change state and require the user's approval. Private keys are stored in the vault and never returned — never ask the user to paste one. Credentials come from a scoped vault; you cannot see their personal passwords.",
].join("\n");

/**
 * Build the MCP server. Tools are resolved dynamically on every `tools/list` and
 * `tools/call`, so the set reflects whatever targets are currently registered.
 */
export function buildMcpServer(app: AppState): Server {
  const server = new Server(
    { name: "skeleton-key", version: "0.1.0" },
    { capabilities: { tools: { listChanged: true } }, instructions: SERVER_INSTRUCTIONS },
  );

  server.setRequestHandler(ListToolsRequestSchema, async () => {
    const tools: Tool[] = resolveTools(app).map((resolved) => {
      const ann = annotationsFor(resolved);
      return {
        name: resolved.qualifiedName,
        description: resolved.description,
        inputSchema: zodToJsonSchema(resolved.inputSchema, {
          $refStrategy: "none",
        }) as Tool["inputSchema"],
        annotations: {
          title: resolved.targetName ? `${resolved.targetName}: ${resolved.qualifiedName}` : resolved.qualifiedName,
          readOnlyHint: ann.readOnlyHint,
          destructiveHint: ann.destructiveHint,
        },
      };
    });
    return { tools };
  });

  server.setRequestHandler(CallToolRequestSchema, async (req) => {
    const { name, arguments: rawArgs } = req.params;
    const resolved = findTool(app, name);
    const ts = new Date().toISOString();

    if (!resolved) {
      return { content: [{ type: "text", text: `Unknown tool: ${name}` }], isError: true };
    }

    const auditTarget = resolved.targetName ?? "(global)";

    // Validate input against the tool's schema.
    const parsed = resolved.inputSchema.safeParse(rawArgs ?? {});
    if (!parsed.success) {
      app.audit.record({
        ts, tool: name, target: auditTarget, tier: resolved.tier,
        args: rawArgs, status: "error", detail: "input validation failed",
      });
      return {
        content: [{ type: "text", text: `Invalid input: ${parsed.error.message}` }],
        isError: true,
      };
    }

    // Locked gate: without credentials most tools can only fail — short-circuit
    // with recovery guidance instead of surfacing a raw connector error. While
    // locked, only a banner-only get_started runs (availableWhenLocked); every
    // other tool (incl. list_targets/network_scan) is withheld so a leaked token
    // can't enumerate targets or scan the LAN before the admin unlocks.
    if (app.locked && !resolved.availableWhenLocked) {
      app.audit.record({
        ts, tool: name, target: auditTarget, tier: resolved.tier,
        args: parsed.data, status: "denied", detail: "vault locked",
      });
      return { content: [{ type: "text", text: app.unlockGuidance() }], isError: true };
    }

    // Approval gate for state-changing tools.
    if (resolved.tier === "execute" && EXECUTE_DISABLED) {
      app.audit.record({
        ts, tool: name, target: auditTarget, tier: resolved.tier,
        args: parsed.data, status: "denied", detail: "execute globally disabled",
      });
      return {
        content: [{ type: "text", text: "Execute tools are disabled on this server (SKELETON_KEY_DISABLE_EXECUTE=1)." }],
        isError: true,
      };
    }

    try {
      const result = await resolved.invoke(parsed.data);
      app.audit.record({
        ts, tool: name, target: auditTarget, tier: resolved.tier,
        args: parsed.data, status: result.isError ? "error" : "ok",
        detail: resolved.tier === "execute" ? confirmationText(resolved, parsed.data) : undefined,
      });
      return { content: [{ type: "text", text: result.text }], isError: result.isError };
    } catch (err) {
      const message = err instanceof Error ? err.message : String(err);
      app.audit.record({
        ts, tool: name, target: auditTarget, tier: resolved.tier,
        args: parsed.data, status: "error", detail: message,
      });
      return { content: [{ type: "text", text: `Tool failed: ${message}` }], isError: true };
    }
  });

  return server;
}
