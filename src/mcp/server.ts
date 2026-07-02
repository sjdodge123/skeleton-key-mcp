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
 * Build the MCP server. Tools are resolved dynamically on every `tools/list` and
 * `tools/call`, so the set reflects whatever targets are currently registered.
 */
export function buildMcpServer(app: AppState): Server {
  const server = new Server(
    { name: "skeleton-key", version: "0.1.0" },
    { capabilities: { tools: { listChanged: true } } },
  );

  server.setRequestHandler(ListToolsRequestSchema, async () => {
    const tools: Tool[] = resolveTools(app).map((resolved) => {
      const ann = annotationsFor(resolved);
      return {
        name: resolved.qualifiedName,
        description: resolved.tool.description,
        inputSchema: zodToJsonSchema(resolved.tool.inputSchema, {
          $refStrategy: "none",
        }) as Tool["inputSchema"],
        annotations: {
          title: `${resolved.target.name}: ${resolved.tool.name}`,
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

    const { tool, target } = resolved;

    // Validate input against the tool's schema.
    const parsed = tool.inputSchema.safeParse(rawArgs ?? {});
    if (!parsed.success) {
      app.audit.record({
        ts, tool: name, target: target.name, tier: tool.tier,
        args: rawArgs, status: "error", detail: "input validation failed",
      });
      return {
        content: [{ type: "text", text: `Invalid input: ${parsed.error.message}` }],
        isError: true,
      };
    }

    // Approval gate for state-changing tools.
    if (tool.tier === "execute") {
      if (EXECUTE_DISABLED) {
        app.audit.record({
          ts, tool: name, target: target.name, tier: tool.tier,
          args: parsed.data, status: "denied", detail: "execute globally disabled",
        });
        return {
          content: [{ type: "text", text: "Execute tools are disabled on this server (SKELETON_KEY_DISABLE_EXECUTE=1)." }],
          isError: true,
        };
      }
    }

    // Resolve credentials lazily; only tools that need them pay the cost.
    const ctx = {
      target,
      getCredential: async () => {
        if (!target.credentialRef) {
          throw new Error(`Target '${target.name}' has no credentialRef configured.`);
        }
        return app.credentialFor(target.credentialRef);
      },
    };

    try {
      const result = await tool.run(parsed.data, ctx);
      app.audit.record({
        ts, tool: name, target: target.name, tier: tool.tier,
        args: parsed.data, status: result.isError ? "error" : "ok",
        detail: tool.tier === "execute" ? confirmationText(resolved, parsed.data) : undefined,
      });
      return { content: [{ type: "text", text: result.text }], isError: result.isError };
    } catch (err) {
      const message = err instanceof Error ? err.message : String(err);
      app.audit.record({
        ts, tool: name, target: target.name, tier: tool.tier,
        args: parsed.data, status: "error", detail: message,
      });
      return { content: [{ type: "text", text: `Tool failed: ${message}` }], isError: true };
    }
  });

  return server;
}
