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
  /** Connector-specific options, validated against the connector's configSchema. */
  options?: Record<string, unknown>;
}

/** Runtime context handed to a tool when it executes. */
export interface ToolContext {
  target: Target;
  /** Resolves the target's credential from the vault (offline-cache backed). */
  getCredential: () => Promise<Credential>;
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
