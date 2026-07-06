import { z } from "zod";
import type { Connector, ConnectorTool, Credential, Target, ToolContext, ToolResult } from "./types.js";
import { tlsFetch } from "./net.js";

/**
 * Proxmox VE connector — inspect a PVE node/cluster and control guest (VM / LXC)
 * power state, over the PVE REST API (`/api2/json`).
 *
 * Auth: an **API token** is preferred (Datacenter → Permissions → API Tokens):
 * sent as `Authorization: PVEAPIToken=<user@realm!tokenid>=<secret>`. The token id
 * comes from a `token_id` field (or a `user@realm!tokenid`-shaped username) and the
 * secret from a `token_secret` field, the item secret, or the password. A plain
 * username + password is the fallback: it exchanges them for a ticket
 * (`/access/ticket`) and sends `PVEAuthCookie` + a `CSRFPreventionToken` on writes.
 *
 * Read tools list nodes/guests/tasks and read status + task logs. The one execute
 * tool, `guest_power`, starts/stops/shuts-down/reboots a specific VM or container
 * — looked up by vmid so the approval prompt can name it exactly — and every call
 * is audited. Destructive lifecycle ops (delete, snapshot rollback, migrate) are
 * intentionally out of v1.
 */

const REQUEST_TIMEOUT_MS = 20_000;

const optionsSchema = z
  .object({
    /** Base URL; if omitted, host/port form the URL (8006/443 ⇒ https). */
    baseUrl: z.string().url().optional(),
    /** Default node for node-scoped reads (e.g. list_tasks) when none is given. */
    node: z.string().optional(),
    /** Skip TLS verification for THIS target only. Defaults **off** (secure): this
     *  connector sends credentials (API token, or a username/password ticket +
     *  CSRF), so it must not silently trust any cert. Proxmox ships a self-signed
     *  cert on :8006, so a target using that must OPT IN by setting this true — an
     *  informed choice accepting LAN-MITM exposure, not a silent default. Scoped
     *  per-request via an undici dispatcher, never process-global. */
    insecureTLS: z.boolean().default(false),
  })
  .default({});

type Options = z.infer<typeof optionsSchema>;

function options(target: Target): Options {
  return optionsSchema.parse(target.options ?? {});
}

/**
 * The PVE base URL — always HTTPS. This connector sends credentials (API token or
 * a username/password ticket), so plaintext HTTP is refused outright (fail closed):
 * a naked `deriveBaseUrl` would emit `http://host` when the port is omitted or the
 * port isn't a known-https one. An explicit `baseUrl` option must be `https://`;
 * otherwise the scheme is forced https and an omitted port defaults to PVE's 8006.
 */
export function baseUrl(target: Target): string {
  const opt = options(target).baseUrl;
  if (opt) {
    if (!/^https:\/\//i.test(opt)) {
      throw new Error("Proxmox baseUrl must be https:// — this connector sends credentials, so plaintext HTTP is refused.");
    }
    return opt.replace(/\/$/, "");
  }
  // Bracket IPv6 literals so host:port is a valid URL.
  const host = target.host.includes(":") && !target.host.startsWith("[") ? `[${target.host}]` : target.host;
  return `https://${host}:${target.port ?? 8006}`;
}

/** A complete `PVEAPIToken` value: `user@realm!tokenid=secret`, no whitespace. */
const FULL_TOKEN = /^[^\s@!=]+@[^\s@!=]+![^\s@!=]+=\S+$/;

/** The full `PVEAPIToken` value (`<user@realm!tokenid>=<secret>`) from the
 *  credential, or undefined if this is a username/password credential. Accepts a
 *  complete token from any common slot — `api_token`, the generic hidden `token`
 *  field, the item secret, or the password (so a Proxmox token onboarded via the
 *  safe `request_credential(kind:"token")` flow, which lands in `cred.secret`,
 *  works) — as long as it has the `user@realm!tokenid=secret` shape. Otherwise a
 *  split `token_id` + `token_secret`/secret, or a `!`-bearing username, forms it.
 *  Exported for testing. */
export function pveTokenFrom(cred: Credential): string | undefined {
  for (const cand of [cred.fields["api_token"], cred.fields["token"], cred.secret, cred.password]) {
    if (cand && FULL_TOKEN.test(cand)) return cand;
  }
  const id = cred.fields["token_id"] ?? (cred.username?.includes("!") ? cred.username : undefined);
  const secret = cred.fields["token_secret"] ?? cred.secret ?? cred.password ?? undefined;
  if (id && secret) return `${id}=${secret}`;
  return undefined;
}

/** A PVE node name — a hostname, so a bounded charset. Guards a user-supplied
 *  node before it's placed in a URL path. */
const NODE_NAME = /^[a-zA-Z0-9._-]+$/;

/** Recognize a TLS/certificate verification failure (undici wraps it as the
 *  `cause` of a "fetch failed" TypeError) so we can suggest the insecureTLS
 *  opt-in instead of surfacing an opaque error. */
function isTlsError(e: unknown): boolean {
  const code = (e as { cause?: { code?: string } })?.cause?.code ?? (e as { code?: string })?.code ?? "";
  if (/CERT|SELF_SIGNED|SSL|TLS|UNABLE_TO_VERIFY/i.test(code)) return true;
  const msg = e instanceof Error ? `${e.message} ${((e as { cause?: { message?: string } }).cause?.message) ?? ""}` : "";
  return /certificate|self.signed|self signed|tls|ssl/i.test(msg);
}

const GUEST_ACTIONS = ["start", "stop", "shutdown", "reboot"] as const;
type GuestAction = (typeof GUEST_ACTIONS)[number];

/** Extract and validate the node from a task UPID (`UPID:<node>:…`) so it can be
 *  used in a path. Throws on a malformed UPID. Exported for testing. */
export function upidNode(upid: string): string {
  if (!upid.startsWith("UPID:")) throw new Error("Not a Proxmox task UPID (must start with 'UPID:').");
  const node = upid.split(":")[1];
  if (!node || !NODE_NAME.test(node)) throw new Error("UPID has no valid node segment.");
  return node;
}

function humanBytes(n?: number): string {
  if (!n || n < 0) return "?";
  const u = ["B", "K", "M", "G", "T"];
  let i = 0;
  let v = n;
  while (v >= 1024 && i < u.length - 1) {
    v /= 1024;
    i++;
  }
  const s = v >= 10 || i === 0 ? String(Math.round(v)) : v.toFixed(1).replace(/\.0$/, "");
  return `${s}${u[i]}`;
}
function humanUptime(seconds?: number): string {
  if (!seconds || seconds < 0) return "?";
  const d = Math.floor(seconds / 86400);
  const h = Math.floor((seconds % 86400) / 3600);
  const m = Math.floor((seconds % 3600) / 60);
  return d > 0 ? `${d}d${h}h` : h > 0 ? `${h}h${m}m` : `${m}m`;
}
function pct(fraction?: number): string {
  return fraction === undefined || fraction < 0 ? "?" : `${Math.round(fraction * 100)}%`;
}

interface PveNode {
  node?: string;
  status?: string;
  cpu?: number;
  maxcpu?: number;
  mem?: number;
  maxmem?: number;
  uptime?: number;
}
interface PveResource {
  vmid?: number;
  name?: string;
  node?: string;
  type?: string; // "qemu" | "lxc"
  status?: string;
  cpu?: number;
  mem?: number;
  maxmem?: number;
  uptime?: number;
  template?: number;
}
interface PveTask {
  upid?: string;
  type?: string;
  status?: string;
  node?: string;
  user?: string;
  starttime?: number;
  endtime?: number;
  id?: string;
}

export function summarizeNodes(nodes: PveNode[]): string {
  if (!nodes.length) return "No nodes.";
  return nodes
    .map((n) => `- ${n.node ?? "?"} [${n.status ?? "?"}] cpu ${pct(n.cpu)} mem ${humanBytes(n.mem)}/${humanBytes(n.maxmem)} up ${humanUptime(n.uptime)}`)
    .join("\n");
}

export function summarizeGuests(rs: PveResource[]): string {
  const guests = rs.filter((r) => r.vmid !== undefined).sort((a, b) => (a.vmid ?? 0) - (b.vmid ?? 0));
  if (!guests.length) return "No VMs or containers.";
  return guests
    .map((g) => {
      const kind = g.type === "lxc" ? "CT" : "VM";
      const tmpl = g.template ? " (template)" : "";
      return `- ${g.vmid} ${g.name ?? "(unnamed)"} [${g.status ?? "?"}] ${kind} on ${g.node ?? "?"} cpu ${pct(g.cpu)} mem ${humanBytes(g.mem)}/${humanBytes(g.maxmem)}${tmpl}`;
    })
    .join("\n");
}

export function summarizeTasks(tasks: PveTask[]): string {
  if (!tasks.length) return "No recent tasks.";
  return tasks
    .map((t) => {
      const done = t.endtime ? (t.status ?? "?") : "running";
      const who = t.user ?? "?";
      return `- ${t.type ?? "?"}${t.id ? ` ${t.id}` : ""} [${done}] by ${who}  ${t.upid ?? ""}`.trimEnd();
    })
    .join("\n");
}

/** PVE client bound to one target — resolves auth lazily (token or ticket). */
class Proxmox {
  private ticket: string | null = null;
  private csrf: string | null = null;

  constructor(
    private readonly target: Target,
    private readonly cred: Credential,
  ) {}

  private get base(): string {
    return baseUrl(this.target);
  }
  private get insecure(): boolean {
    return options(this.target).insecureTLS;
  }

  /** Exchange username/password for a PVE ticket + CSRF token (cached). */
  private async ensureTicket(): Promise<void> {
    if (this.ticket) return;
    const res = await this.request(
      "POST",
      "/access/ticket",
      { form: { username: this.cred.username ?? "", password: this.cred.password ?? "" }, noAuth: true },
    );
    if (!res.ok) throw new Error(`Proxmox login failed: HTTP ${res.status}.`);
    const data = (res.json as { data?: { ticket?: string; CSRFPreventionToken?: string } })?.data;
    if (!data?.ticket) throw new Error("Proxmox login returned no ticket.");
    this.ticket = data.ticket;
    this.csrf = data.CSRFPreventionToken ?? null;
  }

  private async authHeaders(mutating: boolean): Promise<Record<string, string>> {
    const token = pveTokenFrom(this.cred);
    if (token) return { Authorization: `PVEAPIToken=${token}` };
    if (this.cred.username && this.cred.password) {
      await this.ensureTicket();
      const headers: Record<string, string> = { Cookie: `PVEAuthCookie=${this.ticket}` };
      if (mutating && this.csrf) headers["CSRFPreventionToken"] = this.csrf;
      return headers;
    }
    throw new Error(
      "Proxmox target needs an API token — store the FULL token 'user@realm!tokenid=<secret>' (e.g. via request_credential), or split it into 'token_id' + 'token_secret' fields — or a username + password.",
    );
  }

  /** One `/api2/json` call, time-bounded. `form` sends urlencoded (for the ticket
   *  endpoint); `body` sends JSON. */
  private async request(
    method: string,
    path: string,
    opts: { body?: unknown; form?: Record<string, string>; noAuth?: boolean } = {},
  ): Promise<{ ok: boolean; status: number; statusText: string; json?: unknown; text: string }> {
    const mutating = method !== "GET";
    const headers: Record<string, string> = { Accept: "application/json" };
    if (!opts.noAuth) Object.assign(headers, await this.authHeaders(mutating));
    let body: string | undefined;
    if (opts.form) {
      headers["Content-Type"] = "application/x-www-form-urlencoded";
      body = new URLSearchParams(opts.form).toString();
    } else if (opts.body !== undefined) {
      headers["Content-Type"] = "application/json";
      body = JSON.stringify(opts.body);
    }
    const controller = new AbortController();
    const timer = setTimeout(() => controller.abort(), REQUEST_TIMEOUT_MS);
    try {
      const res = await tlsFetch(`${this.base}/api2/json${path}`, { method, headers, body, signal: controller.signal }, this.insecure);
      const text = await res.text();
      let json: unknown;
      try {
        json = text ? JSON.parse(text) : undefined;
      } catch {
        /* non-JSON body */
      }
      return { ok: res.ok, status: res.status, statusText: res.statusText, json, text };
    } catch (e) {
      if (e instanceof Error && e.name === "AbortError") {
        const suffix = mutating ? " — OUTCOME UNKNOWN: the action may already have started. Check task_log / guest_status before retrying." : "";
        throw new Error(`Proxmox request timed out after ${REQUEST_TIMEOUT_MS}ms (${method} ${path}).${suffix}`);
      }
      // A TLS-verification failure (the secure default) is otherwise an opaque
      // "fetch failed" — point the user at the self-signed opt-in.
      if (isTlsError(e)) {
        throw new Error("Proxmox TLS verification failed. If this PVE uses a self-signed cert, register the target with option insecureTLS: true (accepts LAN-MITM exposure).");
      }
      throw e;
    } finally {
      clearTimeout(timer);
    }
  }

  private ensureOk(res: { ok: boolean; status: number; text: string }, path: string): void {
    if (!res.ok) throw new Error(`HTTP ${res.status} on ${path}: ${res.text.slice(0, 300)}`);
  }

  private async getData<T>(path: string): Promise<T> {
    const res = await this.request("GET", path);
    this.ensureOk(res, path);
    return (res.json as { data?: T })?.data as T;
  }

  private async defaultNode(): Promise<string> {
    const opt = options(this.target).node;
    if (opt) return opt;
    const nodes = (await this.getData<PveNode[]>("/nodes")) ?? [];
    const online = nodes.find((n) => n.status === "online") ?? nodes[0];
    if (!online?.node) throw new Error("No Proxmox nodes found.");
    return online.node;
  }

  async listNodes(): Promise<string> {
    return summarizeNodes((await this.getData<PveNode[]>("/nodes")) ?? []);
  }

  async listGuests(): Promise<string> {
    return summarizeGuests((await this.getData<PveResource[]>("/cluster/resources?type=vm")) ?? []);
  }

  async nodeStatus(node?: string): Promise<string> {
    const n = node ?? (await this.defaultNode());
    if (!NODE_NAME.test(n)) throw new Error(`Invalid node name '${n}'.`);
    const s = (await this.getData<Record<string, unknown>>(`/nodes/${encodeURIComponent(n)}/status`)) ?? {};
    const mem = s["memory"] as { used?: number; total?: number } | undefined;
    const cpu = typeof s["cpu"] === "number" ? (s["cpu"] as number) : undefined;
    const load = Array.isArray(s["loadavg"]) ? (s["loadavg"] as unknown[]).join(", ") : "?";
    const uptime = typeof s["uptime"] === "number" ? (s["uptime"] as number) : undefined;
    const kver = (s["kversion"] as string) ?? (s["pveversion"] as string) ?? "";
    return `Node ${n}: cpu ${pct(cpu)}  mem ${humanBytes(mem?.used)}/${humanBytes(mem?.total)}  load ${load}  up ${humanUptime(uptime)}${kver ? `\n${kver}` : ""}`;
  }

  /** Resolve a vmid to its node + guest type via the cluster resource list, so
   *  callers only need the (cluster-unique) vmid and the approval prompt can name
   *  the guest. */
  private async findGuest(vmid: number): Promise<{ node: string; type: "qemu" | "lxc"; name: string }> {
    const rs = (await this.getData<PveResource[]>("/cluster/resources?type=vm")) ?? [];
    const g = rs.find((r) => r.vmid === vmid);
    if (!g) throw new Error(`No VM/CT with vmid ${vmid} in the cluster — use list_guests to see them.`);
    const type = g.type === "lxc" ? "lxc" : g.type === "qemu" ? "qemu" : undefined;
    if (!type || !g.node || !NODE_NAME.test(g.node)) {
      throw new Error(`Guest ${vmid} has an unexpected shape (type=${g.type}, node=${g.node}); refusing to act.`);
    }
    return { node: g.node, type, name: g.name ?? String(vmid) };
  }

  async guestStatus(vmid: number): Promise<string> {
    const { node, type, name } = await this.findGuest(vmid);
    const s = (await this.getData<Record<string, unknown>>(`/nodes/${encodeURIComponent(node)}/${type}/${vmid}/status/current`)) ?? {};
    const status = (s["status"] as string) ?? "?";
    const cpu = typeof s["cpu"] === "number" ? (s["cpu"] as number) : undefined;
    const mem = typeof s["mem"] === "number" ? (s["mem"] as number) : undefined;
    const maxmem = typeof s["maxmem"] === "number" ? (s["maxmem"] as number) : undefined;
    const uptime = typeof s["uptime"] === "number" ? (s["uptime"] as number) : undefined;
    const kind = type === "lxc" ? "CT" : "VM";
    return `${kind} ${vmid} (${name}) on ${node}: ${status}  cpu ${pct(cpu)}  mem ${humanBytes(mem)}/${humanBytes(maxmem)}  up ${humanUptime(uptime)}`;
  }

  async listTasks(node: string | undefined, limit: number): Promise<string> {
    const n = node ?? (await this.defaultNode());
    if (!NODE_NAME.test(n)) throw new Error(`Invalid node name '${n}'.`);
    const tasks = (await this.getData<PveTask[]>(`/nodes/${encodeURIComponent(n)}/tasks?limit=${limit}`)) ?? [];
    return summarizeTasks(tasks);
  }

  async taskLog(upid: string, limit: number): Promise<string> {
    const node = upidNode(upid);
    const lines = (await this.getData<{ n?: number; t?: string }[]>(`/nodes/${encodeURIComponent(node)}/tasks/${encodeURIComponent(upid)}/log?limit=${limit}`)) ?? [];
    const text = lines.map((l) => l.t ?? "").join("\n");
    return text.trim() ? text.slice(0, 16_000) : "(no task output)";
  }

  async guestPower(vmid: number, expectedName: string, expectedNode: string, action: GuestAction): Promise<ToolResult> {
    const { node, type, name } = await this.findGuest(vmid);
    // Safety gate for a destructive op: the approval named a specific guest
    // (name + node from the caller's observed list_guests), so re-verify the LIVE
    // guest at this vmid still matches BOTH before acting. Catches a vmid whose
    // current name or node differs from what was approved. (A same-node/same-name
    // recreation is the irreducible residual — the cluster resource list carries
    // no stable per-guest UUID — but any observable drift is refused.)
    const eqName = name.trim().toLowerCase() === expectedName.trim().toLowerCase();
    const eqNode = node.trim().toLowerCase() === expectedNode.trim().toLowerCase();
    if (!eqName || !eqNode) {
      return {
        text: `Refused: vmid ${vmid} is currently '${name}' on node '${node}', not '${expectedName}' on '${expectedNode}' — aborted to avoid acting on the wrong guest (stale vmid?). Re-check with list_guests.`,
        isError: true,
      };
    }
    const path = `/nodes/${encodeURIComponent(node)}/${type}/${vmid}/status/${action}`;
    const res = await this.request("POST", path);
    if (!res.ok) {
      return { text: `Proxmox ${action} on ${type} ${vmid} (${name}) failed: HTTP ${res.status} ${res.statusText}\n${res.text.slice(0, 500)}`, isError: true };
    }
    const upid = typeof (res.json as { data?: unknown })?.data === "string" ? ((res.json as { data: string }).data) : "";
    const kind = type === "lxc" ? "CT" : "VM";
    return {
      text: `Proxmox ${action} started on ${kind} ${vmid} (${name}) on node ${node}.${upid ? ` Task ${upid} — read it with task_log.` : ""} Confirm with guest_status.`,
    };
  }
}

async function withClient<T>(ctx: ToolContext, fn: (p: Proxmox) => Promise<T>): Promise<T> {
  const cred = await ctx.getCredential();
  return fn(new Proxmox(ctx.target, cred));
}

function run(fn: (p: Proxmox, input: any) => Promise<string>) {
  return async (input: unknown, ctx: ToolContext): Promise<ToolResult> => {
    try {
      return { text: await withClient(ctx, (p) => fn(p, input)) };
    } catch (e) {
      return { text: `Proxmox error: ${e instanceof Error ? e.message : String(e)}`, isError: true };
    }
  };
}

/** For an execute tool whose body already returns a ToolResult (so it can flag an
 *  ambiguous outcome), wrapping only the thrown-error path. */
function runResult(fn: (p: Proxmox, input: any) => Promise<ToolResult>) {
  return async (input: unknown, ctx: ToolContext): Promise<ToolResult> => {
    try {
      return await withClient(ctx, (p) => fn(p, input));
    } catch (e) {
      return { text: `Proxmox error: ${e instanceof Error ? e.message : String(e)}`, isError: true };
    }
  };
}

function buildTools(target: Target): ConnectorTool[] {
  return [
    {
      name: "list_nodes",
      description: `List Proxmox nodes on ${target.name} with status, CPU/memory use, and uptime.`,
      tier: "read",
      inputSchema: z.object({}),
      run: run((p) => p.listNodes()),
    },
    {
      name: "list_guests",
      description: `List all VMs and containers on ${target.name} (vmid, name, status, type, node, CPU/mem). Use the vmid with guest_power / guest_status.`,
      tier: "read",
      inputSchema: z.object({}),
      run: run((p) => p.listGuests()),
    },
    {
      name: "node_status",
      description: `Show a Proxmox node's detailed status on ${target.name} (CPU, memory, load, uptime, kernel). Defaults to the first online node.`,
      tier: "read",
      inputSchema: z.object({ node: z.string().optional().describe("Node name; omit for the default/first online node.") }),
      run: run((p, i) => p.nodeStatus(i.node)),
    },
    {
      name: "guest_status",
      description: `Show the current status of one VM or container on ${target.name} by vmid (running/stopped, CPU, memory, uptime).`,
      tier: "read",
      inputSchema: z.object({ vmid: z.number().int().positive().describe("The guest's vmid (see list_guests).") }),
      run: run((p, i) => p.guestStatus(i.vmid)),
    },
    {
      name: "list_tasks",
      description: `List recent Proxmox tasks on ${target.name} (type, status, user, UPID). Read a task's log with task_log.`,
      tier: "read",
      inputSchema: z.object({
        node: z.string().optional().describe("Node name; omit for the default/first online node."),
        limit: z.number().int().positive().max(500).default(50),
      }),
      run: run((p, i) => p.listTasks(i.node, i.limit)),
    },
    {
      name: "task_log",
      description: `Read a Proxmox task's log on ${target.name} by its UPID (from list_tasks or a guest_power result).`,
      tier: "read",
      inputSchema: z.object({
        upid: z.string().describe("The task UPID (starts with 'UPID:')."),
        limit: z.number().int().positive().max(2000).default(200),
      }),
      run: run((p, i) => p.taskLog(i.upid, i.limit)),
    },
    {
      name: "guest_power",
      description:
        `Change a VM or container's power state on ${target.name}: 'start', 'shutdown' (graceful ACPI/CT shutdown), ` +
        `'reboot', or 'stop' (HARD stop — pulls the virtual power, may lose unsaved data). Identify the guest by vmid, name, ` +
        `AND node (all from list_guests); name+node are shown in the approval and re-verified against the live guest before ` +
        `acting, so a vmid whose current name/node differs from what you saw is refused rather than power-cycled.`,
      tier: "execute",
      inputSchema: z.object({
        vmid: z.number().int().positive().describe("The guest's vmid (see list_guests)."),
        name: z.string().min(1).describe("The guest's name (from list_guests) — shown in the approval and verified before acting."),
        node: z.string().min(1).describe("The guest's node (from list_guests) — shown in the approval and verified before acting."),
        action: z.enum(GUEST_ACTIONS).describe("start | shutdown | reboot | stop (stop is a hard power-off)."),
      }),
      confirm: (input, t) => {
        const i = input as { vmid: number; name: string; node: string; action: GuestAction };
        const hard = i.action === "stop" ? " — HARD stop (pulls power; use 'shutdown' for graceful)" : "";
        return `Proxmox: ${i.action} guest ${i.vmid} "${i.name}" on node ${i.node} (${t.name})${hard}`;
      },
      run: runResult((p, i) => p.guestPower(i.vmid, i.name, i.node, i.action)),
    },
  ];
}

export const proxmoxConnector: Connector = {
  type: "proxmox",
  label: "Proxmox VE",
  configSchema: optionsSchema,
  requiresCredential: true,
  buildTools,
};
