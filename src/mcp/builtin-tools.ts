import { z } from "zod";
import type { AppState } from "../app.js";
import type { ToolResult, ToolTier, Target } from "../connectors/types.js";
import { generateSshKey } from "../connectors/ssh-keygen.js";
import { scanLan } from "../discovery/scan.js";
import { getConnector } from "../connectors/index.js";
import { runSsh } from "../connectors/ssh-exec.js";

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
  confirm?: (input: unknown) => string;
  run: (input: unknown, app: AppState) => Promise<ToolResult>;
}

const ok = (text: string): ToolResult => ({ text });
const err = (text: string): ToolResult => ({ text, isError: true });

export function buildGlobalTools(app: AppState): GlobalTool[] {
  return [
    {
      name: "vault_generate_ssh_key",
      description:
        "Generate a dedicated ed25519 SSH keypair and store the PRIVATE key in the scoped Vaultwarden collection as a Login item. Returns the PUBLIC key and the authorized_keys line to install on the target host. The private key is never returned.",
      tier: "execute",
      inputSchema: z.object({
        name: z.string().describe("Vault item name (also the credentialRef you'll register the target with), e.g. 'nas1-ssh'."),
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
        });
        return ok(
          `Stored SSH key as vault item "${i.name}" (credentialRef).\n` +
            `Fingerprint: ${key.fingerprint}\n\n` +
            `Install this on ${i.host} for user ${i.username} — append to ~${i.username}/.ssh/authorized_keys:\n\n${key.publicKey}\n\n` +
            `One-liner (run on the target):\n  echo ${JSON.stringify(key.publicKey)} >> ~/.ssh/authorized_keys && chmod 600 ~/.ssh/authorized_keys\n\n` +
            `The private key was stored in the vault and intentionally not shown here. Validate with vault_validate_ssh once installed.`,
        );
      },
    },
    {
      name: "vault_store_login",
      description: "Store an arbitrary login (username/password and/or token) with an optional URL in the scoped Vaultwarden collection.",
      tier: "execute",
      inputSchema: z.object({
        name: z.string(),
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
        const lines = services.map((s) => `- ${s.host}:${s.port}  →  ${s.label} (type: ${s.connectorType})`);
        return ok(`Discovered ${services.length} service(s):\n${lines.join("\n")}\n\nRegister any with register_target.`);
      },
    },
    {
      name: "register_target",
      description: "Register a service as a target so its tools become available. type is a connector (ssh, http, ...); credentialRef is a vault item name.",
      tier: "execute",
      inputSchema: z.object({
        name: z.string(),
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
        await a.registry.upsert({ name: i.name, type: i.type, host: i.host, port: i.port, credentialRef: i.credentialRef, options: i.options });
        const toolCount = connector.buildTools({ name: i.name, type: i.type, host: i.host }).length;
        return ok(`Registered '${i.name}'. ${toolCount} tools are now available for it (e.g. ${i.type}.${i.name}.*).`);
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
