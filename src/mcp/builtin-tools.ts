import { z } from "zod";
import type { AppState } from "../app.js";
import type { ToolResult, ToolTier, Target } from "../connectors/types.js";
import { generateSshKey } from "../connectors/ssh-keygen.js";
import { scanLan } from "../discovery/scan.js";
import { getConnector, registerableType } from "../connectors/index.js";
import { runSsh, shellQuote } from "../connectors/ssh-exec.js";

/** Safe, filename-like identifier for vault item names (they double as credentialRefs). */
const safeName = z.string().regex(/^[A-Za-z0-9][A-Za-z0-9._-]*$/, "Use letters, digits, dot, dash, underscore.");

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
              "1. network_scan (ask for their LAN subnet, e.g. '192.168.0') to map services.\n" +
              "2. Get a credential for the host, WITHOUT asking for secrets in chat:\n" +
              "   • Need a password/API token? Call request_credential → hand the user the one-time link → poll credential_request_status.\n" +
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
          const note = registerType === s.connectorType ? "" : ` (no bespoke ${s.connectorType} connector yet)`;
          // Flag lower-confidence guesses so they're taken with a grain of salt.
          const conf = s.confidence === "confirmed" ? "" : s.confidence === "likely" ? "  (likely — verify)" : "  (open port, unidentified)";
          return `- ${s.host}:${s.port}  →  ${s.label}${conf}  [register_target type: ${registerType}]${note}`;
        });
        const confirmed = services.filter((s) => s.confidence === "confirmed").length;
        return ok(
          `Discovered ${services.length} service(s) (${confirmed} confirmed by fingerprint):\n${lines.join("\n")}\n\n` +
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
        const target = { name: i.name, type: i.type, host: i.host, port: i.port, credentialRef: i.credentialRef, options: i.options };
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
          if (exact.has(t.credentialRef)) {
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
        if (i.credentialRef) {
          // Verify the new ref resolves before committing, so a typo can't brick a working target.
          try {
            await a.credentialFor(i.credentialRef);
          } catch (e) {
            return err(`credentialRef '${i.credentialRef}' didn't resolve: ${e instanceof Error ? e.message : String(e)}`);
          }
        }
        const merged = {
          ...existing,
          credentialRef: i.credentialRef ?? existing.credentialRef,
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
        "Ask the user to provide a credential (password or API token) for a host WITHOUT it passing through the chat. Returns a one-time, TOTP-gated web link; the user enters the secret in their browser and it is stored straight in the vault. Poll credential_request_status to know when it's done, then register_target with the item name.",
      tier: "execute",
      inputSchema: z.object({
        name: safeName.describe("Vault item name to create (also the future credentialRef)."),
        host: z.string().describe("Host/IP the credential is for."),
        kind: z.enum(["password", "token"]).describe("password = username/password login; token = API token/key."),
        reason: z.string().describe("Short reason shown to the user, e.g. 'SSH access to onboard nas1'."),
        username: z.string().optional().describe("Remote username, for password logins."),
      }),
      confirm: (input) => {
        const i = input as { name: string; host: string };
        return `Create a one-time credential-request link for '${i.name}' (${i.host})`;
      },
      run: async (input, a) => {
        const i = input as { name: string; host: string; kind: "password" | "token"; reason: string; username?: string };
        const names = await a.vault.listItemNames();
        if (names.includes(i.name)) return err(`A vault item named '${i.name}' already exists — pick a different name.`);
        const request = a.credentialRequests.create({ name: i.name, host: i.host, username: i.username, kind: i.kind, reason: i.reason });
        const base = a.publicUrl();
        const link = `${base ?? ""}/credential/${request.id}`;
        const shown = base ? link : `${link}  (open on your Skeleton Key host; set SKELETON_KEY_PUBLIC_URL for absolute links)`;
        return ok(
          `Ask the user to open this one-time link and enter the ${i.kind} for ${i.host} — you will not see the value:\n\n${shown}\n\n` +
            `The link is TOTP-gated and expires in 15 minutes. After they submit, call credential_request_status with id "${request.id}"; ` +
            `once it reports 'fulfilled', register the target with credentialRef '${i.name}'.`,
        );
      },
    },
    {
      name: "credential_request_status",
      description: "Check whether a credential-request link (from request_credential) has been completed. Returns pending, fulfilled, expired, or declined.",
      tier: "read",
      inputSchema: z.object({ id: z.string().describe("The request id returned by request_credential.") }),
      run: async (input, a) => {
        const i = input as { id: string };
        const request = a.credentialRequests.get(i.id);
        if (!request) return err(`No credential request with id '${i.id}' (it may have expired and been evicted). Create a new one with request_credential.`);
        switch (request.status) {
          case "fulfilled":
            return ok(`✅ fulfilled — credential '${request.fulfilledName}' is in the vault. Register the target with credentialRef '${request.fulfilledName}'.`);
          case "pending":
            return ok(`⏳ pending — the user hasn't submitted the credential for '${request.name}' yet. Ask them to open the link, or check again shortly.`);
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
        const lines = targets.map((t) => `- ${t.name} (${t.type}) → ${t.host}${t.port ? ":" + t.port : ""}${t.credentialRef ? ` [cred: ${t.credentialRef}]` : ""}`);
        return ok(`Registered targets:\n${lines.join("\n")}`);
      },
    },
  ];
}
