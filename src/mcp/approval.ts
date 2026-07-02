import type { ResolvedTool } from "./tool-registry.js";

/**
 * The approval gate makes `execute` tools legible to the human in the loop.
 *
 * In v1 the actual yes/no prompt is delegated to the MCP client (Claude Code /
 * Desktop shows a permission prompt), so the gate's job here is to (a) surface a
 * precise confirmation string via tool annotations and (b) flag execute calls so
 * they are always audited. A future phase adds a server-side web-UI approval
 * queue; `EXECUTE_DISABLED` provides a blunt kill-switch until then.
 */
export const EXECUTE_DISABLED = process.env.SKELETON_KEY_DISABLE_EXECUTE === "1";

export interface Annotations {
  readOnlyHint: boolean;
  destructiveHint: boolean;
}

export function annotationsFor(resolved: ResolvedTool): Annotations {
  const isRead = resolved.tier === "read";
  return { readOnlyHint: isRead, destructiveHint: !isRead };
}

export function confirmationText(resolved: ResolvedTool, input: unknown): string | undefined {
  if (resolved.tier !== "execute") return undefined;
  return resolved.confirm?.(input);
}
