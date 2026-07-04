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
  "1. `network_scan` (pass their LAN subnet, e.g. '192.168.0', when asked) to map services. If the scan finds the network's router/gateway (e.g. UniFi), recommend onboarding IT first — its API names every device on the LAN, which identifies the scan's anonymous SSH/HTTP entries and makes the rest of onboarding much easier.",
  "2. Obtain a credential WITHOUT secrets passing through the chat:",
  "   - Password / API token: `request_credential` returns a one-time, TOTP-gated web link the user opens to type the secret straight into the vault; poll `credential_request_status` until it's 'fulfilled'.",
  "   - SSH key: `vault_generate_ssh_key` stores the private key and returns the public key. If you already have a working credential for the host you can install it via that host's `run_command`; otherwise give the user the one-liner to install it themselves.",
  "3. `register_target` to add the host so its per-target tools appear.",
  "4. `vault_validate_ssh` to confirm SSH access works.",
  "",
  "Managing credentials: `update_target` re-points a host at a new credentialRef (e.g. upgrade password → key), `vault_delete_credential` retires an old item.",
  "",
  "Never ask the user to paste a password, token, or private key into the chat — always route secrets through `request_credential` or the web UI. Tool tiers: 'read' tools are safe; 'execute' tools change state and require the user's approval. Credentials come from a scoped vault; you cannot see their personal passwords.",
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
    // Mirror the CallTool locked gate: while locked, advertise only the tools
    // that actually run (banner-only get_started). Otherwise per-target tool
    // names — and thus registered target names/types — would be enumerable via
    // tools/list before the admin unlocks, defeating the kill-switch.
    const resolved = app.locked ? resolveTools(app).filter((t) => t.availableWhenLocked) : resolveTools(app);
    const tools: Tool[] = resolved.map((resolved) => {
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

    // Locked gate FIRST — before we distinguish unknown/known tools or validate
    // args. While locked, anything that isn't a banner-only availableWhenLocked
    // tool returns the SAME unlock guidance, whether the tool exists or not, so a
    // leaked token can't probe tool/target names via "Unknown tool" vs schema
    // errors vs locked guidance (tools/list is gated the same way).
    if (app.locked && !resolved?.availableWhenLocked) {
      app.audit.record({
        ts, tool: name, target: resolved?.targetName ?? "(global)", tier: resolved?.tier ?? "read",
        args: rawArgs, status: "denied", detail: "vault locked",
      });
      return { content: [{ type: "text", text: app.unlockGuidance() }], isError: true };
    }

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
