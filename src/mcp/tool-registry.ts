import type { z } from "zod";
import type { AppState } from "../app.js";
import type { Credential, ProtectedHost, Target, ToolResult, ToolTier } from "../connectors/types.js";
import { getConnector } from "../connectors/index.js";
import { buildGlobalTools, type GlobalTool } from "./builtin-tools.js";

// The global tool set never changes for a given app, so build it once. Only the
// per-target tools are recomposed from the live registry on each resolve.
const globalToolsCache = new WeakMap<AppState, GlobalTool[]>();
function getGlobalTools(app: AppState): GlobalTool[] {
  let tools = globalToolsCache.get(app);
  if (!tools) {
    tools = buildGlobalTools(app);
    globalToolsCache.set(app, tools);
  }
  return tools;
}

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
  /** Callable while the vault is locked (needs no credentials). Connector tools
   *  never are; locked calls short-circuit with unlock guidance instead. */
  availableWhenLocked: boolean;
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

  for (const g of getGlobalTools(app)) {
    resolved.push({
      qualifiedName: g.name,
      description: g.description,
      tier: g.tier,
      inputSchema: g.inputSchema,
      targetName: null,
      availableWhenLocked: g.availableWhenLocked ?? false,
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
        availableWhenLocked: false,
        confirm: tool.confirm ? (input) => tool.confirm!(input, target) : undefined,
        invoke: (input) =>
          tool.run(input, {
            target,
            getCredential: () => targetCredential(app, target),
            // Any vault item by name, for tools that inject a *different* item's
            // secret than the target's own (see ToolContext.resolveCredential).
            // Same in-memory, lazy path as getCredential — nothing is cached here.
            resolveCredential: (ref: string, opts?: { fresh?: boolean }) => app.credentialFor(ref, opts),
            fingerprint: (value: string) => app.fingerprint(value),
            // Control-plane hosts no network change may point at (see
            // ToolContext.protectedHosts). Recomputed per call so a target
            // registered a moment ago is already protected.
            protectedHosts: () => protectedHosts(app),
          }),
      });
    }
  }

  return resolved;
}

/**
 * The hosts that make up Skeleton Key's own control plane, which a connector's
 * network change (today: a UniFi port-forward) must never expose or redirect.
 *
 * Derived, never hardcoded, from three live sources so a host move is picked up
 * on the next call:
 *  - every registered target whose type fronts the control plane (`portainer`
 *    manages the containers, `unifi` is the gateway itself) — on a typical
 *    deployment the Portainer host is also the Docker host running Skeleton Key
 *    and Vaultwarden, which is why one entry covers all three;
 *  - Skeleton Key's own advertised origin (`SKELETON_KEY_PUBLIC_URL` /
 *    boot-detected LAN URL), for the case where it does NOT share that host;
 *  - the Vaultwarden server the bootstrap store is pointed at.
 *
 * Comparison is a literal host match, so a target registered by hostname is not
 * matched by its IP (and vice-versa). That is a documented limitation, not a
 * safety claim: the deny-list is defense-in-depth on top of the RFC1918 check
 * and the approval gate, never the only thing standing between a caller and a
 * bad forward.
 */
export function protectedHosts(app: AppState): ProtectedHost[] {
  const out: ProtectedHost[] = [];
  for (const t of app.registry.list()) {
    if (t.type === "portainer") out.push({ host: t.host, why: `Portainer / container host (target '${t.name}')` });
    else if (t.type === "unifi") out.push({ host: t.host, why: `the UniFi gateway itself (target '${t.name}')` });
  }
  const hostOf = (url: string | null | undefined): string | null => {
    if (!url) return null;
    try {
      return new URL(url).hostname || null;
    } catch {
      return null;
    }
  };
  const self = hostOf(app.publicUrl());
  if (self) out.push({ host: self, why: "the Skeleton Key server itself" });
  // Best-effort: the store throws while locked, and an execute tool can't run
  // then anyway — so a miss here can never widen a live deny-list.
  let vault: string | null = null;
  try {
    vault = hostOf(app.store.get().bwServerUrl);
  } catch {
    /* locked or unset — the registry entries above still apply */
  }
  if (vault) out.push({ host: vault, why: "Vaultwarden (the credential store)" });

  const seen = new Set<string>();
  return out.filter((p) => p.host && !seen.has(p.host.toLowerCase()) && seen.add(p.host.toLowerCase()));
}

/**
 * Resolve a target's own credential, preferring the pinned immutable item id
 * over the human-facing name. Why: during a migration a vault item was renamed
 * mid-cleanup and the next deploy resolved the NAME from a stale cache, serving
 * the wrong value. The id can't be hijacked by a rename or a same-named
 * duplicate. If the pinned item is gone (deleted and recreated under the same
 * name), fall back to the name and re-pin the new id best-effort so the next
 * call is stable again. The returned `ref` is always the name the target was
 * registered with, so callers/logs never see a bare UUID.
 */
export async function targetCredential(app: AppState, target: Target): Promise<Credential> {
  const ref = target.credentialRef;
  if (!ref) throw new Error(`Target '${target.name}' has no credentialRef configured.`);
  if (target.credentialId) {
    try {
      const cred = await app.credentialFor(target.credentialId, { byId: true });
      return { ...cred, ref };
    } catch (e) {
      // A locked vault is not "the item is gone" — surface the unlock guidance
      // rather than hammering the name path (which would fail the same way).
      if (app.locked) throw e;
    }
  }
  const cred = await app.credentialFor(ref);
  await repinCredentialId(app, target).catch(() => {});
  return cred;
}

/** Best-effort: persist the id the name currently resolves to (missing or stale pin). */
async function repinCredentialId(app: AppState, target: Target): Promise<void> {
  if (!target.credentialRef) return;
  const { id } = await app.vault.resolveRef(target.credentialRef);
  if (id === target.credentialId) return;
  const current = app.registry.get(target.name);
  if (!current || current.credentialRef !== target.credentialRef) return; // target changed under us
  await app.registry.upsert({ ...current, credentialId: id });
}

export function findTool(app: AppState, qualifiedName: string): ResolvedTool | undefined {
  return resolveTools(app).find((r) => r.qualifiedName === qualifiedName);
}
