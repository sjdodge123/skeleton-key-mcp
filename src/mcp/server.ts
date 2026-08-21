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
  "   - Password / API token: `request_credential` returns a one-time, TOTP-gated web link the user opens to type the secret straight into the vault; poll `credential_request_status` until it's 'fulfilled'. Pass `fields` to collect a whole set of values on one link (e.g. an app's env secrets), stored as fields of one vault item. When you know a value's shape, say so: per-field `pattern`/`minLength`/`hint` (e.g. a Discord bot token is ~70 chars with two dots — NOT the 32-char OAuth2 client secret) make the form refuse a wrong value, and `verify` (a templated HTTP probe such as GET discord.com/api/v10/users/@me with `Authorization: Bot {{DISCORD_BOT_TOKEN}}`) tests it live before it is stored. To fix a wrong value already in the vault use `overwrite: true` on the same name instead of inventing new names. If the user can't see the link, every open request is listed at <publicUrl>/admin/credentials; `ttlMinutes` lengthens the link's life.",
  "   - SSH key: `vault_generate_ssh_key` stores the private key and returns the public key. If you already have a working credential for the host you can install it via that host's `run_command`; otherwise give the user the one-liner to install it themselves.",
  "3. `register_target` to add the host so its per-target tools appear.",
  "4. `vault_validate_ssh` to confirm SSH access works.",
  "",
  "Managing credentials: `update_target` re-points a host at a new credentialRef (e.g. upgrade password → key), `vault_delete_credential` retires an old item.",
  "",
  "Deploying apps: a Portainer target can stand up a new app with `create_stack` (full compose file referencing a published image). Non-secret settings go in `env`; secrets go in `secretEnv` as vault item references — the server resolves them at deploy time, so values never enter the chat. Verify with `container_inspect` and `container_logs`; `remove_stack` can delete only stacks Skeleton Key created. `create_stack`/`update_stack` report a keyed fingerprint (`len=… fp=…`) per injected secret and `container_inspect` shows one per env var — compare them with the fingerprints `credential_request_status` reported for the vault item to prove the RIGHT value was deployed, without ever seeing it.",
  "",
  "Before risky changes: `form_skeleton` starts an encrypted config snapshot of every target as a BACKGROUND job and returns a job id — poll `skeleton_status`; never re-call `form_skeleton` because a call seemed slow (a second call while one runs just returns the same job).",
  "",
  "Never ask the user to paste a password, token, or private key into the chat — always route secrets through `request_credential` or the web UI. Tool tiers: 'read' tools are safe; 'execute' tools change state and require the user's approval. Credentials come from a scoped vault; you cannot see their personal passwords.",
].join("\n");

/**
 * Build the MCP server. Tools are resolved dynamically on every `tools/list` and
 * `tools/call`, so the set reflects whatever targets are currently registered.
 */
/**
 * How often a long-running tool call emits a `notifications/progress` heartbeat
 * (when the client asked for progress via `_meta.progressToken`). Keeps client
 * idle timeouts from firing on slow `run_command` / `create_stack` calls.
 */
export const PROGRESS_HEARTBEAT_MS = 5_000;

export function buildMcpServer(app: AppState, opts: { heartbeatMs?: number } = {}): Server {
  const heartbeatMs = opts.heartbeatMs ?? PROGRESS_HEARTBEAT_MS;
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

  server.setRequestHandler(CallToolRequestSchema, async (req, extra) => {
    const { name, arguments: rawArgs } = req.params;
    const progressToken = req.params._meta?.progressToken;
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

    // Progress heartbeats: while the tool runs, tell a client that asked for
    // progress (via `_meta.progressToken`) that we're still alive every few
    // seconds, so its idle timeout doesn't give up on a slow command. Note: the
    // server cannot see the CLIENT's own approval prompt — the client asks the
    // human BEFORE the request is ever sent — so "pending approval" is not
    // something we can signal here; this only covers the server-side run time.
    // A failed notification send (client gone, stream closed) is ignored: it
    // must never surface as the tool's result.
    let heartbeat: NodeJS.Timeout | undefined;
    if (progressToken !== undefined) {
      const startedAt = Date.now();
      heartbeat = setInterval(() => {
        const seconds = Math.round((Date.now() - startedAt) / 1000);
        void extra
          .sendNotification({ method: "notifications/progress", params: { progressToken, progress: seconds, message: `${name} still running (${seconds}s)…` } })
          .catch(() => {});
      }, heartbeatMs);
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
    } finally {
      if (heartbeat) clearInterval(heartbeat);
    }
  });

  return server;
}
