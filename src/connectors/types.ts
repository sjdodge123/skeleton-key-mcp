import type { z } from "zod";
import type { Credential } from "../secrets/types.js";

export type { Credential } from "../secrets/types.js";

/**
 * A tool's tier decides how it is handled by the approval gate.
 * - `read`  — inspects state only; safe to run freely.
 * - `execute` — changes state; must produce a confirmation string and is audited.
 */
export type ToolTier = "read" | "execute";

/** A registered service instance the user wants Skeleton Key to reach. */
export interface Target {
  /** Stable, user-facing name, unique across the registry (e.g. "nas1"). */
  name: string;
  /** Connector type this target is served by (e.g. "ssh", "http"). */
  type: string;
  host: string;
  port?: number;
  /**
   * Name of the Vaultwarden item holding this target's credentials.
   * The registry stores this reference only — never the secret itself.
   */
  credentialRef?: string;
  /**
   * Immutable Vaultwarden item id the `credentialRef` resolved to when it was
   * attached. Credential reads prefer this over the name, so renaming or
   * recreating an item can't make a target silently pick up a different value.
   * Falls back to the name (and re-pins) when the id is gone. Not a secret.
   */
  credentialId?: string;
  /** Connector-specific options, validated against the connector's configSchema. */
  options?: Record<string, unknown>;
}

/**
 * A host the control plane depends on, which a network change must never be
 * pointed at. `why` is human text naming what it protects, so a refusal reads
 * "…is Portainer (target 'nas229pt')" rather than a bare IP.
 */
export interface ProtectedHost {
  /** Hostname or IP as registered/configured — compared literally. */
  host: string;
  /** What lives there, for the refusal message. */
  why: string;
}

/** Runtime context handed to a tool when it executes. */
export interface ToolContext {
  target: Target;
  /** Resolves the target's credential from the vault (offline-cache backed). */
  getCredential: () => Promise<Credential>;
  /**
   * Resolves ANY vault item by name — for tools that must inject a credential
   * other than the target's own (e.g. Portainer's `secretEnv`, which puts an
   * app's DB password into a stack's environment without it ever transiting the
   * chat/MCP channel). Lazy and in-memory only, like `getCredential`.
   *
   * Optional because non-MCP call sites (e.g. the snapshot service) build a
   * ToolContext with only the target's own credential; a tool that needs it must
   * fail with a clear error when it is absent, never silently skip the value.
   *
   * `fresh: true` syncs the vault first (bounded, best-effort) so the value
   * can't come from a stale offline cache — required for anything about to be
   * injected into a deploy.
   */
  resolveCredential?: (ref: string, opts?: { fresh?: boolean }) => Promise<Credential>;
  /**
   * Keyed fingerprint of a secret value (`len=<n> fp=<8 hex>`, see
   * `src/lib/fingerprint.ts`) — lets a tool report WHICH value it deployed
   * (comparable against the vault's) without ever echoing the value. Optional
   * like `resolveCredential`; tools must degrade to no fingerprint when absent.
   */
  fingerprint?: (value: string) => Promise<string>;
  /**
   * Hosts that a network change must never be pointed at — Skeleton Key's own
   * control plane. Assembled by the tool registry from the LIVE target registry
   * (so moving a host is picked up automatically instead of being hardcoded),
   * plus Skeleton Key's own public URL and its Vaultwarden server, neither of
   * which is a registered target.
   *
   * Optional for the same reason as `resolveCredential` — non-MCP call sites
   * (the snapshot service) build a minimal context. But unlike those, a tool
   * that needs this must **fail closed** when it is absent: a deny-list that
   * silently evaluates to empty is worse than no deny-list at all.
   */
  protectedHosts?: () => ProtectedHost[];
}

export interface ToolResult {
  /** Human/agent-readable text result. */
  text: string;
  isError?: boolean;
}

/**
 * One captured backup artifact from a connector's `snapshot()`. `data` is
 * PLAINTEXT — it is encrypted at rest by the snapshot service. A backup
 * necessarily CONTAINS SECRETS, so an artifact's bytes must never reach a
 * ToolResult, the manifest, the audit log, or the model context; the only
 * plaintext egress is the TOTP-gated download.
 */
export interface SnapshotArtifact {
  /** Filename-safe leaf, e.g. "settings.json", "backup.unf", "teleporter.tar.gz". */
  name: string;
  data: Buffer;
  /** Human context recorded in the manifest — must contain NO secret. */
  note?: string;
}

/** A single tool a connector exposes for a given target. */
export interface ConnectorTool {
  /** Short name, unique within the connector (e.g. "tail_log"). Namespaced by
   *  target at registration time -> `${target.name}.${name}`. */
  name: string;
  description: string;
  tier: ToolTier;
  /** JSON-schema-able input shape (zod). */
  inputSchema: z.ZodTypeAny;
  /**
   * For `execute` tools: a one-line human summary of exactly what will happen,
   * used by the approval gate / permission prompt. Omitted for `read` tools.
   */
  confirm?: (input: unknown, target: Target) => string;
  run: (input: unknown, ctx: ToolContext) => Promise<ToolResult>;
}

/**
 * A connector is an adapter for a *type* of service. It declares the config a
 * target of its type needs and produces the tools bound to a given target.
 * Connectors hold no target state themselves — they are instantiated per target
 * by the registry, which is what keeps Skeleton Key portable across networks.
 */
export interface Connector {
  type: string;
  /** Human label for the wizard/UI (e.g. "SSH host", "Synology DSM"). */
  label: string;
  /** Validates a Target.options blob for this connector type. */
  configSchema: z.ZodTypeAny;
  /** Whether this connector needs a credentialRef to function. */
  requiresCredential: boolean;
  /** Build the tool set for one target. */
  buildTools: (target: Target) => ConnectorTool[];
  /**
   * Optional: capture disaster-recovery backup artifacts for one target (config
   * exports + cheap native backups). Optional so connectors that don't implement
   * it (e.g. the generic `http` connector) don't break. Artifacts are PLAINTEXT
   * and may contain secrets — the snapshot service encrypts them at rest.
   */
  snapshot?: (ctx: ToolContext) => Promise<SnapshotArtifact[]>;
}
