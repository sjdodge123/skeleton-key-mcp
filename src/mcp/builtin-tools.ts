import { z } from "zod";
import type { AppState } from "../app.js";
import type { ToolResult, ToolTier, Target } from "../connectors/types.js";
import { generateSshKey } from "../connectors/ssh-keygen.js";
import { scanLan } from "../discovery/scan.js";
import { getConnector, registerableType } from "../connectors/index.js";
import { runSsh, shellQuote } from "../connectors/ssh-exec.js";
import { startSkeletonJob, waitForSkeletonJob, getSkeletonJob, describeSkeletonJob } from "../snapshots/jobs.js";
import { DEFAULT_TTL_MINUTES, MAX_TTL_MINUTES, MIN_TTL_MINUTES, safeHost } from "../web/credential-requests.js";
import { compileFullMatch, DEFAULT_VERIFY_TIMEOUT_MS, MAX_VERIFY_TIMEOUT_MS, templatePlaceholders, validateVerifyUrl } from "../web/credential-verify.js";

/** Safe, filename-like identifier for vault item names (they double as credentialRefs). */
const safeName = z.string().regex(/^[A-Za-z0-9][A-Za-z0-9._-]*$/, "Use letters, digits, dot, dash, underscore.");

/**
 * Env-var style name for one field of a multi-field credential request. It
 * becomes both the form input name and the Vaultwarden custom-field name, so it
 * stays deliberately narrow (no spaces, dots, dashes, or leading digits).
 */
const credentialFieldName = z
  .string()
  .max(64)
  .regex(/^[A-Za-z][A-Za-z0-9_]*$/, "Use an env-var style name: a letter, then letters/digits/underscores (e.g. DISCORD_BOT_TOKEN).");

/** Backstop so one link can't ask for an unbounded wall of inputs. */
const MAX_REQUEST_FIELDS = 10;
/** Upper bound on a value's declared length (and the longest value the form accepts). */
const MAX_VALUE_LENGTH = 4096;

/**
 * Shape constraints the agent can attach to a value. These exist because the
 * Discord migration stored a Client Secret where a Bot Token was expected and
 * the form had no way to refuse it — when the agent KNOWS the expected shape
 * it should say so, and the form + server reject a mismatch before anything
 * reaches the vault.
 */
const constraintShape = {
  pattern: z
    .string()
    .max(200)
    .optional()
    .refine((p) => p === undefined || compileFullMatch(p) !== null, "pattern must be a valid regular expression.")
    .describe("Regex the value must FULLY match (applied as ^(?:pattern)$), e.g. '[\\\\w-]{24,28}\\\\.[\\\\w-]{6}\\\\.[\\\\w-]{27,}' for a Discord bot token."),
  minLength: z.number().int().min(0).max(MAX_VALUE_LENGTH).optional().describe("Minimum value length."),
  maxLength: z.number().int().min(1).max(MAX_VALUE_LENGTH).optional().describe(`Maximum value length (cap ${MAX_VALUE_LENGTH}).`),
  hint: z
    .string()
    .max(500)
    .optional()
    .describe(
      "Human text shown under the input: what the value looks like AND where to get it, e.g. 'Discord Developer Portal → Bot → Reset Token. ~70 chars with two dots — NOT the OAuth2 Client Secret'.",
    ),
};

const verifySchema = z
  .object({
    method: z.enum(["GET", "POST"]).default("GET"),
    url: z
      .string()
      .max(2048)
      .describe("https URL to probe (plain http only for RFC1918/localhost LAN hosts). The submitted value IS SENT to this host — it is shown to the user."),
    headers: z
      .record(z.string().max(100), z.string().max(MAX_VALUE_LENGTH))
      .optional()
      .describe("Request headers. Values may contain {{value}} (single-secret mode) or {{FIELD_NAME}} (multi-field) placeholders, e.g. { Authorization: 'Bot {{value}}' }."),
    expectStatus: z.array(z.number().int().min(100).max(599)).max(20).optional().describe("Acceptable HTTP statuses. Default: any 2xx."),
    timeoutMs: z.number().int().min(500).max(MAX_VERIFY_TIMEOUT_MS).optional().describe(`Probe timeout, default ${DEFAULT_VERIFY_TIMEOUT_MS}ms, cap ${MAX_VERIFY_TIMEOUT_MS}ms.`),
  })
  .describe(
    "Optional pre-store verification: after the user submits, Skeleton Key sends the value(s) to this URL and only stores them if the status is acceptable. " +
      "A failed probe lets the user re-enter the value or explicitly 'store anyway'. Pass this whenever the credential has a cheap authenticated endpoint " +
      "(Discord: GET https://discord.com/api/v10/users/@me with Authorization 'Bot {{value}}').",
  );

const requestCredentialSchema = z
  .object({
    name: safeName.describe("Vault item name to create (also the future credentialRef). With `overwrite: true`, the EXISTING item of this name to re-fill."),
    host: z.string().describe("Host/IP (or app/service) the credential is for."),
    kind: z
      .enum(["password", "token"])
      .optional()
      .describe("Single-secret mode: password = username/password login; token = API token/key. Omit when passing `fields`."),
    reason: z.string().describe("Short reason shown to the user, e.g. 'SSH access to onboard nas1'."),
    username: z.string().optional().describe("Remote username, for password logins."),
    ...constraintShape,
    fields: z
      .array(
        z.object({
          name: credentialFieldName.describe("Field name, env-var style, e.g. 'DISCORD_BOT_TOKEN'. Becomes the vault custom-field name."),
          label: z.string().max(200).optional().describe("Optional help text shown next to the input (never a value)."),
          secret: z.boolean().optional().describe("Masked input + hidden vault field type. Defaults to true."),
          ...constraintShape,
        }),
      )
      .min(1)
      .max(MAX_REQUEST_FIELDS)
      .optional()
      .describe(
        `Multi-field mode: collect this named SET of values (max ${MAX_REQUEST_FIELDS}) on ONE vault item, one input per field on a single link. ` +
          "A field named 'username' also becomes the item's login username. Replaces `kind`. Each field accepts pattern/minLength/maxLength/hint.",
      ),
    verify: verifySchema.optional(),
    overwrite: z
      .boolean()
      .optional()
      .describe(
        "Re-fill an EXISTING vault item of this `name` instead of refusing the duplicate: listed fields/password are REPLACED by name, the item keeps its id and other fields. " +
          "Use this to fix a wrong value rather than minting '-v2' names. Without it a duplicate name is refused.",
      ),
    ttlMinutes: z
      .number()
      .int()
      .min(MIN_TTL_MINUTES)
      .max(MAX_TTL_MINUTES)
      .optional()
      .describe(`How long the link stays valid (${MIN_TTL_MINUTES}–${MAX_TTL_MINUTES} min). Default: SKELETON_KEY_CREDENTIAL_TTL_MINUTES or ${DEFAULT_TTL_MINUTES}.`),
  })
  .superRefine((v, ctx) => {
    if (v.fields && v.kind) {
      ctx.addIssue({ code: z.ZodIssueCode.custom, path: ["kind"], message: "Pass either `kind` (single secret) or `fields` (multi-field), not both." });
    }
    if (!v.fields && !v.kind) {
      ctx.addIssue({ code: z.ZodIssueCode.custom, path: ["kind"], message: "Pass `kind` (single secret) or `fields` (multi-field)." });
    }
    const seen = new Set<string>();
    for (const f of v.fields ?? []) {
      if (seen.has(f.name)) {
        ctx.addIssue({ code: z.ZodIssueCode.custom, path: ["fields"], message: `Duplicate field name '${f.name}'.` });
      }
      seen.add(f.name);
    }
    const checkLengths = (c: { minLength?: number; maxLength?: number }, path: (string | number)[]) => {
      if (c.minLength !== undefined && c.maxLength !== undefined && c.minLength > c.maxLength) {
        ctx.addIssue({ code: z.ZodIssueCode.custom, path, message: "minLength must not exceed maxLength." });
      }
    };
    checkLengths(v, ["minLength"]);
    v.fields?.forEach((f, i) => checkLengths(f, ["fields", i, "minLength"]));
    if (v.fields && (v.pattern || v.minLength !== undefined || v.maxLength !== undefined || v.hint)) {
      ctx.addIssue({ code: z.ZodIssueCode.custom, path: ["pattern"], message: "Top-level pattern/minLength/maxLength/hint apply to single-secret mode; put them on each entry of `fields`." });
    }
    if (v.verify) {
      const urlError = validateVerifyUrl(v.verify.url);
      if (urlError) ctx.addIssue({ code: z.ZodIssueCode.custom, path: ["verify", "url"], message: urlError });
      const allowed = new Set(v.fields ? v.fields.map((f) => f.name) : ["value"]);
      for (const p of templatePlaceholders(v.verify.headers)) {
        if (!allowed.has(p)) {
          ctx.addIssue({
            code: z.ZodIssueCode.custom,
            path: ["verify", "headers"],
            message: `Unknown placeholder {{${p}}} — use ${v.fields ? "a requested field name" : "{{value}}"}.`,
          });
        }
      }
    }
  });

/** Lines describing each field's constraints/hint for the tool result, so the agent can relay them. */
function describeConstraints(i: RequestCredentialInput): string[] {
  const one = (label: string, c: { pattern?: string; minLength?: number; maxLength?: number; hint?: string }): string | null => {
    const bits: string[] = [];
    if (c.hint) bits.push(c.hint);
    if (c.minLength !== undefined || c.maxLength !== undefined) bits.push(`length ${c.minLength ?? 0}–${c.maxLength ?? "∞"}`);
    if (c.pattern) bits.push(`pattern /${c.pattern}/`);
    return bits.length ? `  • ${label}: ${bits.join("; ")}` : null;
  };
  const lines = i.fields ? i.fields.map((f) => one(f.name, f)) : [one("value", i)];
  return lines.filter((l): l is string => l !== null);
}

type RequestCredentialInput = z.infer<typeof requestCredentialSchema>;

/**
 * Global MCP tools that operate on the vault and registry themselves rather than
 * a single target. These make onboarding conversational: Claude can generate and
 * store SSH keys, validate them, map the LAN, and register targets — so once the
 * scoped collection and first connection exist, the rest is driven by chat.
 */
export interface GlobalTool {
  name: string;
  description: string;
  tier: ToolTier;
  inputSchema: z.ZodTypeAny;
  /** Still callable while the vault is locked (needs no credentials). Locked
   *  calls to every other tool short-circuit with unlock guidance. */
  availableWhenLocked?: boolean;
  confirm?: (input: unknown) => string;
  run: (input: unknown, app: AppState) => Promise<ToolResult>;
}

const ok = (text: string): ToolResult => ({ text });
const err = (text: string): ToolResult => ({ text, isError: true });

export function buildGlobalTools(app: AppState): GlobalTool[] {
  return [
    {
      name: "get_started",
      description: "Show onboarding status and the recommended next step. Call this when a session starts or the user asks what they can do.",
      tier: "read",
      inputSchema: z.object({}),
      // The one tool that runs while locked — but then it reveals nothing about
      // the homelab (no target list), only how to unlock. A leaked token used
      // before the admin unlocks must not be able to enumerate targets here.
      availableWhenLocked: true,
      run: async (_input, a) => {
        if (a.locked) {
          return ok(
            `${a.unlockGuidance()}\n\n` +
              "Until then, no targets or tools are available. Once unlocked, call get_started again to see what's registered.",
          );
        }
        const targets = a.registry.list();
        if (targets.length === 0) {
          return ok(
            "No targets are registered yet — nothing to manage until you add some.\n\n" +
              "Recommended onboarding (offer to do this with the user):\n" +
              "1. network_scan (ask for their LAN subnet, e.g. '192.168.0') to map services. If it finds the router/gateway (e.g. UniFi), start there — its API names every other device on the network, so the rest of the scan stops being anonymous IPs.\n" +
              "2. Get a credential for the host, WITHOUT asking for secrets in chat:\n" +
              "   • Need a password/API token? Call request_credential → hand the user the one-time link → poll credential_request_status. " +
              "Several secrets for one app (e.g. env vars for a migration)? Pass `fields` so one link collects them all onto one vault item.\n" +
              "   • SSH host you already have access to? Call vault_generate_ssh_key, then either install the returned key via that host's run_command (if you already have a working credential) or give the user the one-liner to install it themselves.\n" +
              "3. register_target to add the host so its tools appear.\n" +
              "4. vault_validate_ssh (for ssh) to confirm access.\n\n" +
              "Managing existing creds: update_target re-points a host at a new credentialRef (e.g. password → key); vault_delete_credential retires an old item.",
          );
        }
        const lines = targets.map((t) => `- ${t.name} (${t.type}) → ${t.host}`);
        return ok(
          `${targets.length} target(s) registered:\n${lines.join("\n")}\n\n` +
            "Their per-target tools (e.g. ssh.<name>.tail_log) are available. " +
            "Use network_scan to find more, or list_targets / vault_list_credentials to review.",
        );
      },
    },
    {
      name: "vault_generate_ssh_key",
      description:
        "Generate a dedicated ed25519 SSH keypair and store the PRIVATE key in the scoped Vaultwarden collection as a Login item. Returns the PUBLIC key and the authorized_keys line to install on the target host. The private key is never returned.",
      tier: "execute",
      inputSchema: z.object({
        name: safeName.describe("Vault item name (also the credentialRef you'll register the target with), e.g. 'nas1-ssh'."),
        username: z.string().describe("The remote SSH user this key logs in as, e.g. 'skeletonkey'."),
        host: z.string().describe("Target host/IP the key is for (stored for reference)."),
        url: z.string().optional().describe("Optional URL/URI to store on the item."),
        passphrase: z.string().optional().describe("Optional passphrase to encrypt the private key."),
      }),
      confirm: (input) => {
        const i = input as { name: string; username: string; host: string };
        return `Generate an ed25519 SSH key and store it in the vault as '${i.name}' (user ${i.username} @ ${i.host})`;
      },
      run: async (input, a) => {
        const i = input as { name: string; username: string; host: string; url?: string; passphrase?: string };
        const key = await generateSshKey(`skeleton-key:${i.name}`, i.passphrase ?? "");
        const fields = [
          { name: "private_key", value: key.privateKey, hidden: true },
          { name: "host", value: i.host, hidden: false },
          ...(i.passphrase ? [{ name: "key_passphrase", value: i.passphrase, hidden: true }] : []),
        ];
        await a.vault.createLoginItem({
          name: i.name,
          username: i.username,
          url: i.url ?? `ssh://${i.host}`,
          notes: "SSH key managed by Skeleton Key. Private key in the 'private_key' field.",
          fields,
          collectionName: a.store.get().bwCollectionName,
        });
        return ok(
          `Stored SSH key as vault item "${i.name}" (credentialRef).\n` +
            `Fingerprint: ${key.fingerprint}\n\n` +
            `Install this on ${i.host} for user ${i.username} — append to ~${i.username}/.ssh/authorized_keys:\n\n${key.publicKey}\n\n` +
            // shellQuote (single quotes) so a copy-pasted one-liner can't run command substitution.
            `One-liner (run on the target):\n  mkdir -p ~/.ssh && echo ${shellQuote(key.publicKey)} >> ~/.ssh/authorized_keys && chmod 600 ~/.ssh/authorized_keys\n\n` +
            `The private key was stored in the vault and intentionally not shown here. Validate with vault_validate_ssh once installed.`,
        );
      },
    },
    {
      name: "vault_store_login",
      description: "Store an arbitrary login (username/password and/or token) with an optional URL in the scoped Vaultwarden collection.",
      tier: "execute",
      inputSchema: z.object({
        name: safeName,
        username: z.string().optional(),
        password: z.string().optional(),
        token: z.string().optional().describe("An API token/key; stored as a hidden 'token' field."),
        url: z.string().optional(),
        notes: z.string().optional(),
      }),
      confirm: (input) => `Store a login named '${(input as { name: string }).name}' in the vault`,
      run: async (input, a) => {
        const i = input as { name: string; username?: string; password?: string; token?: string; url?: string; notes?: string };
        await a.vault.createLoginItem({
          name: i.name,
          username: i.username,
          password: i.password,
          url: i.url,
          notes: i.notes,
          fields: i.token ? [{ name: "token", value: i.token, hidden: true }] : [],
          collectionName: a.store.get().bwCollectionName,
        });
        return ok(`Stored login "${i.name}" in the vault (credentialRef).`);
      },
    },
    {
      name: "vault_list_credentials",
      description: "List the item names available in the scoped Vaultwarden collection (no secret values).",
      tier: "read",
      inputSchema: z.object({}),
      run: async (_input, a) => {
        const names = await a.vault.listItemNames();
        return ok(names.length ? `Vault items:\n- ${names.join("\n- ")}` : "No items in the scoped collection yet.");
      },
    },
    {
      name: "vault_validate_ssh",
      description: "Validate a stored SSH credential by connecting to the host and running a harmless command (id + hostname). Use after installing a generated public key.",
      tier: "read",
      inputSchema: z.object({
        host: z.string(),
        port: z.number().int().positive().optional(),
        username: z.string().optional().describe("Override the SSH user; defaults to the one stored on the item."),
        credentialRef: z.string().describe("Vault item name holding the key."),
      }),
      run: async (input, a) => {
        const i = input as { host: string; port?: number; username?: string; credentialRef: string };
        const cred = await a.credentialFor(i.credentialRef);
        if (i.username) cred.username = i.username;
        const target: Target = { name: "validate", type: "ssh", host: i.host, port: i.port };
        try {
          const r = await runSsh(target, cred, "id && hostname");
          return r.code === 0
            ? ok(`✅ SSH to ${i.host} works as ${cred.username ?? "(default)"}:\n${r.stdout}`)
            : err(`SSH connected but command exited ${r.code}:\n${r.stderr || r.stdout}`);
        } catch (e) {
          return err(`❌ SSH validation failed: ${e instanceof Error ? e.message : String(e)}`);
        }
      },
    },
    {
      name: "network_scan",
      description: "Scan the LAN for known homelab services (Synology, Proxmox, UniFi, Home Assistant, Portainer, Pi-hole, SSH). Returns suggestions to confirm; nothing is registered automatically.",
      tier: "read",
      inputSchema: z.object({
        subnet: z.string().optional().describe("First three octets of your LAN, e.g. '192.168.0'. Needed when running in a bridged container. Blank = auto-detect."),
      }),
      run: async (input, _a) => {
        const i = input as { subnet?: string };
        const services = await scanLan(i.subnet ? { subnets: [i.subnet] } : {});
        if (!services.length) return ok("No services detected. In a bridged container, pass your real subnet (e.g. '192.168.0').");
        const lines = services.map((s) => {
          const registerType = registerableType(s.connectorType, s.port, s.confidence);
          // Only call out a genuinely-missing connector. When a bespoke connector
          // DOES exist but the detection was downgraded for low confidence, the
          // "(likely — verify)" suffix already explains the http fallback.
          const note =
            registerType === s.connectorType || getConnector(s.connectorType)
              ? ""
              : ` (no bespoke ${s.connectorType} connector yet)`;
          // Flag lower-confidence guesses so they're taken with a grain of salt.
          const conf = s.confidence === "confirmed" ? "" : s.confidence === "likely" ? "  (likely — verify)" : "  (open port, unidentified)";
          return `- ${s.host}:${s.port}  →  ${s.label}${conf}  [register_target type: ${registerType}]${note}`;
        });
        const confirmed = services.filter((s) => s.confidence === "confirmed").length;
        // The gateway is the network's own inventory: once registered, its API
        // names every device on the LAN, turning the scan's anonymous SSH/HTTP
        // entries into identified hosts. Worth calling out as the first target.
        const gateway = services.find((s) => s.connectorType === "unifi" && s.confidence === "confirmed");
        const gatewayTip = gateway
          ? `💡 Recommended first target: the router/gateway (${gateway.label} at ${gateway.host}). Registering it first lets its API name every device on the network, identifying the anonymous entries above. For UniFi: register as http with options {auth: "header", headerName: "X-API-Key", insecureTLS: true} and an API key from the Network app's Integrations panel (plug icon).\n\n`
          : "";
        return ok(
          `Discovered ${services.length} service(s) (${confirmed} confirmed by fingerprint):\n${lines.join("\n")}\n\n` +
            gatewayTip +
            "Register any with register_target using the shown type.",
        );
      },
    },
    {
      name: "register_target",
      description: "Register a service as a target so its tools become available. type is a connector (ssh, http, ...); credentialRef is a vault item name.",
      tier: "execute",
      inputSchema: z.object({
        name: safeName,
        type: z.string().describe("Connector type, e.g. 'ssh' or 'http'."),
        host: z.string(),
        port: z.number().int().positive().optional(),
        credentialRef: z.string().optional().describe("Vault item name holding this target's credentials."),
        options: z.record(z.unknown()).optional(),
      }),
      confirm: (input) => {
        const i = input as { name: string; type: string; host: string };
        return `Register target '${i.name}' (${i.type} @ ${i.host})`;
      },
      run: async (input, a) => {
        const i = input as { name: string; type: string; host: string; port?: number; credentialRef?: string; options?: Record<string, unknown> };
        const connector = getConnector(i.type);
        if (!connector) return err(`Unknown connector type '${i.type}'.`);
        try {
          connector.configSchema.parse(i.options ?? {});
        } catch (e) {
          return err(`Invalid options for '${i.type}': ${e instanceof Error ? e.message : String(e)}`);
        }
        if (connector.requiresCredential && !i.credentialRef) {
          return err(`Connector '${i.type}' requires a credentialRef (a vault item name).`);
        }
        // Pin the vault item's immutable id alongside the name, so a later
        // rename / recreate can't silently re-point this target (and a typo'd
        // ref is caught now, not on first use).
        let credentialId: string | undefined;
        if (i.credentialRef) {
          try {
            credentialId = (await a.vault.resolveRef(i.credentialRef)).id;
          } catch (e) {
            return err(`credentialRef '${i.credentialRef}' didn't resolve: ${e instanceof Error ? e.message : String(e)}`);
          }
        }
        const target: Target = { name: i.name, type: i.type, host: i.host, port: i.port, credentialRef: i.credentialRef, credentialId, options: i.options };
        await a.registry.upsert(target);
        // Tell live sessions the tool set changed so the new per-target tools
        // appear without reconnecting.
        a.emitToolsChanged();
        // Best-effort tool count against the full target; never fail the (already
        // persisted) registration just because counting threw.
        let count = "";
        try {
          count = ` ${connector.buildTools(target).length} tools are now available for it.`;
        } catch { /* ignore */ }
        return ok(`Registered '${i.name}' (${i.type} @ ${i.host}).${count} Tools are namespaced ${i.type}.${i.name}.*`);
      },
    },
    {
      name: "vault_delete_credential",
      description:
        "Delete an item from the scoped vault by credentialRef (e.g. retire an old password after upgrading a host to SSH keys). Refuses if a registered target still references it, unless force=true.",
      tier: "execute",
      inputSchema: z.object({
        credentialRef: z.string().describe("Vault item name (or id) to delete."),
        force: z.boolean().optional().describe("Delete even if a registered target still references it."),
      }),
      confirm: (input) => `Delete vault item '${(input as { credentialRef: string }).credentialRef}' — any target still using it will lose access`,
      run: async (input, a) => {
        const i = input as { credentialRef: string; force?: boolean };
        // Resolve the ref to its canonical identity FIRST, so the dependency
        // guard can't be bypassed by passing an id or a differently-cased ref
        // than the targets stored (deleteItem resolves fuzzily — the guard must
        // match the same way, or we'd delete a still-referenced item unguarded).
        const resolved = await a.vault.resolveRef(i.credentialRef);
        const exact = new Set([i.credentialRef, resolved.name, resolved.id]);
        // A target depends on this item iff its credentialRef RESOLVES to it.
        // A cheap exact-identity check first; otherwise resolve the target's ref
        // and compare ids — precise for case-insensitive and unique-substring
        // refs, without the false positives a plain substring test would give
        // (e.g. ref "ssh" must not look like a dependent of item "pihole-ssh").
        const dependents: string[] = [];
        for (const t of a.registry.list()) {
          if (!t.credentialRef) continue;
          // A pinned id is the strongest evidence: that target reads THIS item
          // regardless of what its name currently resolves to.
          if (exact.has(t.credentialRef) || t.credentialId === resolved.id) {
            dependents.push(t.name);
            continue;
          }
          try {
            if ((await a.vault.resolveRef(t.credentialRef)).id === resolved.id) dependents.push(t.name);
          } catch {
            /* ref no longer resolves — not a dependent of this item */
          }
        }
        if (dependents.length && !i.force) {
          return err(
            `Refusing to delete '${resolved.name}': still used by target(s) ${dependents.join(", ")}. ` +
              "Re-point them first (update_target) or pass force=true.",
          );
        }
        const { name } = await a.vault.deleteItem(i.credentialRef);
        const warn = dependents.length ? ` Warning: ${dependents.join(", ")} referenced it and will fail until re-pointed.` : "";
        return ok(`Deleted vault item "${name}".${warn}`);
      },
    },
    {
      name: "update_target",
      description:
        "Update a registered target's credentialRef (and optionally host/port/options) — e.g. re-point a host from a password login to a generated SSH key. A new credentialRef must resolve to an existing vault item.",
      tier: "execute",
      inputSchema: z.object({
        name: safeName,
        credentialRef: z.string().optional().describe("New vault item name to use for this target."),
        host: z.string().optional(),
        port: z.number().int().positive().optional(),
        options: z.record(z.unknown()).optional(),
      }),
      confirm: (input) => {
        const i = input as { name: string; credentialRef?: string };
        return `Update target '${i.name}'${i.credentialRef ? ` → credential '${i.credentialRef}'` : ""}`;
      },
      run: async (input, a) => {
        const i = input as { name: string; credentialRef?: string; host?: string; port?: number; options?: Record<string, unknown> };
        const existing = a.registry.get(i.name);
        if (!existing) return err(`No target named '${i.name}'. Use register_target to add it, or list_targets to see names.`);
        // Verify the new ref resolves before committing, so a typo can't brick a
        // working target — and pin the item's immutable id while we're at it.
        // Without a new ref the existing name + pinned id are kept as-is.
        let credentialId = existing.credentialId;
        if (i.credentialRef) {
          try {
            credentialId = (await a.vault.resolveRef(i.credentialRef)).id;
          } catch (e) {
            return err(`credentialRef '${i.credentialRef}' didn't resolve: ${e instanceof Error ? e.message : String(e)}`);
          }
        }
        const merged: Target = {
          ...existing,
          credentialRef: i.credentialRef ?? existing.credentialRef,
          credentialId,
          host: i.host ?? existing.host,
          port: i.port ?? existing.port,
          // Shallow-MERGE options (don't replace): a caller changing one option
          // must not silently drop others — notably the SSH command allow/deny
          // guard (options.denyPatterns), a load-bearing safety control.
          options: i.options ? { ...existing.options, ...i.options } : existing.options,
        };
        await a.registry.upsert(merged);
        a.emitToolsChanged();
        return ok(
          `Updated '${i.name}' (${merged.type} @ ${merged.host}${merged.port ? ":" + merged.port : ""})` +
            `${merged.credentialRef ? ` [cred: ${merged.credentialRef}]` : ""}.`,
        );
      },
    },
    {
      name: "request_credential",
      description:
        "Ask the user to provide credentials for a host WITHOUT them passing through the chat. Returns a one-time, TOTP-gated web link; the user types the value(s) in their browser and they are stored straight in the vault. " +
        "Single-secret mode: pass `kind` (password or token). Multi-field mode: pass `fields` to collect a NAMED SET of values (e.g. an app's env secrets DISCORD_BOT_TOKEN / SXM_USERNAME / SXM_PASSWORD) onto ONE vault item — each becomes a custom field of that name. " +
        "WHENEVER you know what the value should look like, pass `pattern`/`minLength`/`maxLength` and a `hint` naming the shape AND where to get it (per field, or top-level in single-secret mode) — the form refuses a non-matching value before it reaches the vault. " +
        "When the credential has a cheap authenticated endpoint, pass `verify` so the value is tested against it BEFORE being stored (the user sees the host and can override a failure). " +
        "To fix a wrong value already in the vault, pass `overwrite: true` to re-fill the existing item instead of inventing a new name. " +
        "Poll credential_request_status to know when it's done (it reports the verification outcome and a keyed fingerprint per stored value), then register_target with the item name.",
      tier: "execute",
      inputSchema: requestCredentialSchema,
      confirm: (input) => {
        const i = input as RequestCredentialInput;
        const what = i.fields?.length ? ` for ${i.fields.length} field(s): ${i.fields.map((f) => f.name).join(", ")}` : "";
        const overwrite = i.overwrite ? ` — this REPLACES the values of existing vault item '${i.name}'` : "";
        const verify = i.verify ? ` — the submitted value(s) will be SENT to ${safeHost(i.verify.url)} to verify before storing` : "";
        return `Create a one-time credential-request link for '${i.name}' (${i.host})${what}${overwrite}${verify}`;
      },
      run: async (input, a) => {
        const i = input as RequestCredentialInput;
        const names = await a.vault.listItemNames();
        const exists = names.includes(i.name);
        if (exists && !i.overwrite) {
          return err(`A vault item named '${i.name}' already exists — pass overwrite: true to re-fill it in place, or pick a different name.`);
        }
        if (!exists && i.overwrite) {
          return err(`overwrite: true but no vault item named '${i.name}' exists — drop overwrite to create it.`);
        }
        const fields = i.fields?.map((f) => ({
          name: f.name,
          label: f.label,
          secret: f.secret ?? true,
          pattern: f.pattern,
          minLength: f.minLength,
          maxLength: f.maxLength,
          hint: f.hint,
        }));
        const constraints =
          !fields && (i.pattern || i.minLength !== undefined || i.maxLength !== undefined || i.hint)
            ? { pattern: i.pattern, minLength: i.minLength, maxLength: i.maxLength, hint: i.hint }
            : undefined;
        const request = a.credentialRequests.create({
          name: i.name,
          host: i.host,
          username: i.username,
          kind: fields ? undefined : i.kind,
          constraints,
          fields,
          reason: i.reason,
          verify: i.verify,
          overwrite: i.overwrite,
          ttlMinutes: i.ttlMinutes,
        });
        const base = a.publicUrl();
        const link = `${base ?? ""}/credential/${request.id}`;
        const shown = base ? link : `${link}  (open on your Skeleton Key host; set SKELETON_KEY_PUBLIC_URL for absolute links)`;
        const asks = fields ? `these ${fields.length} value(s) — ${fields.map((f) => f.name).join(", ")} —` : `the ${i.kind}`;
        const ttlMin = Math.round(request.ttlMs / 60_000);
        const hints = describeConstraints(i);
        return ok(
          `Ask the user to open this one-time link and enter ${asks} for ${i.host} — you will not see ${fields ? "the values" : "the value"}:\n\n${shown}\n\n` +
            `If the link doesn't render in your chat UI, open ${base ?? ""}/admin/credentials to find it.\n\n` +
            (hints.length ? `Tell the user what to enter:\n${hints.join("\n")}\n\n` : "") +
            (i.verify ? `Before storing, Skeleton Key will test the value(s) against ${safeHost(i.verify.url)}; a failed probe lets the user retry or store anyway.\n\n` : "") +
            (i.overwrite ? `This REPLACES the listed values on the existing vault item '${i.name}' (same item id).\n\n` : "") +
            `The link is TOTP-gated and expires in ${ttlMin} minutes (at ${new Date(request.expiresAt).toISOString()}). After they submit, call credential_request_status with id "${request.id}"; ` +
            `once it reports 'fulfilled', register the target with credentialRef '${i.name}'` +
            `${fields ? ` (all ${fields.length} values live on that one item as custom fields)` : ""}.`,
        );
      },
    },
    {
      name: "credential_request_status",
      description:
        "Check whether a credential-request link (from request_credential) has been completed. Returns pending, fulfilled, expired, or declined. " +
        "When fulfilled it also reports the verification outcome (passed/failed/skipped) and a keyed fingerprint (len + hash prefix, not the value) per stored field — compare these against what a deployed stack reports to catch a wrong value.",
      tier: "read",
      inputSchema: z.object({ id: z.string().describe("The request id returned by request_credential.") }),
      run: async (input, a) => {
        const i = input as { id: string };
        const request = a.credentialRequests.get(i.id);
        if (!request) return err(`No credential request with id '${i.id}' (it may have expired and been evicted). Create a new one with request_credential.`);
        switch (request.status) {
          case "fulfilled": {
            // Field NAMES + fingerprints only — the values are in the vault and never surface here.
            const names = request.fields?.map((f) => f.name);
            const fps = Object.entries(request.fingerprints ?? {}).map(([k, v]) => `  ${k}: ${v}`);
            const verification =
              request.verification === "passed"
                ? `Verification: passed against ${safeHost(request.verify!.url)}.`
                : request.verification === "failed"
                  ? `Verification: FAILED against ${safeHost(request.verify!.url)} — the user chose to store anyway; treat the value as unconfirmed.`
                  : "Verification: skipped (no verify spec).";
            return ok(
              `✅ fulfilled — credential '${request.fulfilledName}' is in the vault` +
                `${names?.length ? ` with ${names.length} field(s): ${names.join(", ")}` : ""}${request.overwrite ? " (existing item updated in place)" : ""}. ` +
                `${verification}\n` +
                (fps.length ? `Fingerprints (len + keyed hash prefix — not the value):\n${fps.join("\n")}\n` : "") +
                `Register the target with credentialRef '${request.fulfilledName}'.`,
            );
          }
          case "pending":
            return ok(
              `⏳ pending — the user hasn't submitted the credential for '${request.name}' yet (link valid until ${new Date(request.expiresAt).toISOString()}). ` +
                `Ask them to open the link, or check again shortly. If the link didn't render, they can find it at ${a.publicUrl() ?? ""}/admin/credentials.`,
            );
          case "expired":
            return ok(`⌛ expired — the link for '${request.name}' timed out. Create a new one with request_credential.`);
          case "declined":
            return err(`🚫 declined — the user cancelled the request for '${request.name}'.`);
        }
      },
    },
    {
      name: "list_targets",
      description: "List the currently registered targets.",
      tier: "read",
      inputSchema: z.object({}),
      run: async (_input, a) => {
        const targets = a.registry.list();
        if (!targets.length) return ok("No targets registered yet. Use network_scan then register_target.");
        // The pinned id is shown as a short suffix so a "same name, different
        // item" situation is visible at a glance without drowning the line.
        const credOf = (t: Target) =>
          t.credentialRef ? ` [cred: ${t.credentialRef}${t.credentialId ? ` · id ${t.credentialId.slice(0, 8)}…` : ""}]` : "";
        const lines = targets.map((t) => `- ${t.name} (${t.type}) → ${t.host}${t.port ? ":" + t.port : ""}${credOf(t)}`);
        return ok(`Registered targets:\n${lines.join("\n")}`);
      },
    },
    {
      name: "form_skeleton",
      description:
        "Snapshot every registered target's configuration to an ENCRYPTED disaster-recovery skeleton on the Skeleton Key host " +
        "(config exports + cheap native backups: Pi-hole teleporter, UniFi .unf, a triggered Home Assistant backup). " +
        "Artifact bytes never leave the box here; pull a skeleton off-box via the TOTP-gated web download. " +
        "Runs in the BACKGROUND (it can take minutes): returns a job id immediately — poll `skeleton_status` for progress and the final summary. " +
        "If a job is already running, this returns THAT job instead of starting another (so never retry it on a timeout — call skeleton_status). " +
        "Pass `waitSeconds` to wait inline for a small setup that finishes quickly.",
      tier: "execute",
      inputSchema: z.object({
        waitSeconds: z
          .number()
          .int()
          .min(0)
          .max(90)
          .default(0)
          .describe("Wait up to this many seconds (0–90) for the job to finish before returning; on completion the summary is returned inline. Default 0 (return at once)."),
      }),
      confirm: () =>
        "Snapshot every registered target's config to an encrypted on-box skeleton (triggers native backups on Pi-hole / UniFi / Home Assistant)",
      run: async (input, a) => {
        const { waitSeconds } = input as { waitSeconds: number };
        const { job, started } = startSkeletonJob(a);
        if (!started) {
          return ok(
            `A skeleton job is ALREADY running (${job.id}) — not starting another (that would trigger a second round of native backups).\n` +
              `${describeSkeletonJob(job)}`,
          );
        }
        const settled = await waitForSkeletonJob(a, job, waitSeconds * 1000);
        if (settled.status === "failed") return err(`form_skeleton failed: ${settled.error}`);
        if (settled.status === "done") return ok(describeSkeletonJob(settled));
        return ok(
          `Started skeleton job ${job.id} in the background (${job.progress.targetsTotal} target(s)). ` +
            `Poll skeleton_status (optionally with id '${job.id}') until it reports done; it returns the summary then. ` +
            "Do not call form_skeleton again while it runs.",
        );
      },
    },
    {
      name: "skeleton_status",
      description:
        "Report the status of a background `form_skeleton` job: running/done/failed, elapsed seconds, per-target progress, and on completion the skeleton id + summary (or the error). " +
        "Omit `id` for the most recent job. Poll this instead of re-calling form_skeleton.",
      tier: "read",
      inputSchema: z.object({
        id: z.string().optional().describe("Job id returned by form_skeleton. Omit for the most recent job."),
      }),
      run: async (input, a) => {
        const { id } = input as { id?: string };
        const job = getSkeletonJob(a, id);
        if (!job) return err(id ? `No skeleton job '${id}' (jobs live in memory; a server restart forgets them).` : "No skeleton job has run since this server started. Call form_skeleton to begin one.");
        const text = describeSkeletonJob(job);
        return job.status === "failed" ? err(text) : ok(text);
      },
    },
  ];
}
