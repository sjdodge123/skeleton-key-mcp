import type { z } from "zod";
import type { AppState } from "../app.js";
import type { ToolResult, ToolTier } from "../connectors/types.js";
import { getConnector } from "../connectors/index.js";
import { buildGlobalTools } from "./builtin-tools.js";

/**
 * A tool resolved for invocation. Both per-target connector tools and global
 * builtin tools are normalized to this shape, with everything they need already
 * bound into `invoke`, so the MCP handler treats them uniformly.
 */
export interface ResolvedTool {
  /** Fully-qualified name. Per-target: `${type}.${name}.${tool}`; global: the tool name. */
  qualifiedName: string;
  description: string;
  tier: ToolTier;
  inputSchema: z.ZodTypeAny;
  /** Target name for audit, or null for global tools. */
  targetName: string | null;
  /** Confirmation text for execute-tier tools. */
  confirm?: (input: unknown) => string | undefined;
  invoke: (input: unknown) => Promise<ToolResult>;
}

/**
 * Compose the live tool set: global vault/registry tools (always available once
 * unlocked) plus the per-target tools for every registered target. With zero
 * targets the global onboarding tools are still present, which is what lets
 * Claude bootstrap a network from scratch.
 */
export function resolveTools(app: AppState): ResolvedTool[] {
  const resolved: ResolvedTool[] = [];

  for (const g of buildGlobalTools(app)) {
    resolved.push({
      qualifiedName: g.name,
      description: g.description,
      tier: g.tier,
      inputSchema: g.inputSchema,
      targetName: null,
      confirm: g.confirm,
      invoke: (input) => g.run(input, app),
    });
  }

  for (const target of app.registry.list()) {
    const connector = getConnector(target.type);
    if (!connector) continue; // unknown type in config — skip rather than crash
    for (const tool of connector.buildTools(target)) {
      resolved.push({
        qualifiedName: `${target.type}.${target.name}.${tool.name}`,
        description: tool.description,
        tier: tool.tier,
        inputSchema: tool.inputSchema,
        targetName: target.name,
        confirm: tool.confirm ? (input) => tool.confirm!(input, target) : undefined,
        invoke: (input) =>
          tool.run(input, {
            target,
            getCredential: async () => {
              if (!target.credentialRef) {
                throw new Error(`Target '${target.name}' has no credentialRef configured.`);
              }
              return app.credentialFor(target.credentialRef);
            },
          }),
      });
    }
  }

  return resolved;
}

export function findTool(app: AppState, qualifiedName: string): ResolvedTool | undefined {
  return resolveTools(app).find((r) => r.qualifiedName === qualifiedName);
}
