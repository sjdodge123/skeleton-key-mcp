import type { AppState } from "../app.js";
import type { ConnectorTool, Target } from "../connectors/types.js";
import { getConnector } from "../connectors/index.js";

export interface ResolvedTool {
  /** Fully-qualified, target-namespaced name, e.g. "ssh.nas1.tail_log". */
  qualifiedName: string;
  target: Target;
  tool: ConnectorTool;
}

/**
 * Compose the live tool set from the registered targets × their connector tools.
 * With zero targets this returns nothing — tools appear only as the user
 * registers services, which is what makes Skeleton Key portable.
 */
export function resolveTools(app: AppState): ResolvedTool[] {
  const resolved: ResolvedTool[] = [];
  for (const target of app.registry.list()) {
    const connector = getConnector(target.type);
    if (!connector) continue; // unknown type in config — skip rather than crash
    for (const tool of connector.buildTools(target)) {
      resolved.push({
        qualifiedName: `${target.type}.${target.name}.${tool.name}`,
        target,
        tool,
      });
    }
  }
  return resolved;
}

export function findTool(app: AppState, qualifiedName: string): ResolvedTool | undefined {
  return resolveTools(app).find((r) => r.qualifiedName === qualifiedName);
}
