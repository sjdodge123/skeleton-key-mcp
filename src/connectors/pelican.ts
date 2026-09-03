import { z } from "zod";
import type { Connector, ConnectorTool, Credential, SnapshotArtifact, Target, ToolContext, ToolResult } from "./types.js";
import { deriveBaseUrl, tlsFetch } from "./net.js";

/**
 * Pelican Panel connector — inventory, provisioning, power and schedules for a
 * game-server panel, so a server can be stood up conversationally.
 *
 * **Two APIs, two keys, one vault item.** Pelican splits its surface in half and
 * the halves are not interchangeable (verified against the panel's own
 * `routes/api-application.php` / `routes/api-client.php` on 1.0.0-beta35):
 *  - **Application API** (`/api/application`, `papp_` key) — eggs, nodes,
 *    allocations, users, and server *creation*. It has no power and no schedule
 *    endpoints at all.
 *  - **Client API** (`/api/client`, `pacc_` key) — power, startup variables,
 *    schedules and per-server allocations. A client key acts *as its user*, so
 *    that user must own (or be a subuser on) every server managed here.
 *
 * Each tool declares which half it needs and the key is chosen by that, never by
 * fallback: handing the client key to an application endpoint fails in confusing
 * ways, and the reverse silently acts as the wrong principal. Keys are matched to
 * their API by their `papp_`/`pacc_` prefix and a mismatch is refused up front —
 * the same class of mistake as the Discord client-secret-vs-bot-token mix-up.
 *
 * **Route binding is not uniform.** Application routes bind `{server:id}` (the
 * numeric id); client routes bind `{server:uuid}`, whose `resolveRouteBinding`
 * accepts *either* the full UUID or the short identifier. So an id from
 * `list_servers` is not automatically usable on both halves — the summaries
 * print all three and each tool documents which it wants.
 *
 * **Responses carry secrets.** A server's `container.environment` holds egg
 * variables — RCON passwords, admin passwords, server passwords — and a node
 * carries its `daemon_token`. Everything is key-name redacted on the way out.
 */

const optionsSchema = z
  .object({
    /** Panel base URL; if omitted, host/port form it (443/8443 ⇒ https, else http). */
    baseUrl: z.string().url().optional(),
    /**
     * The dedicated Pelican user id that owns servers created here. Required by
     * `create_server` — the plan's rule is that Claude's servers are owned by a
     * purpose-made panel user, never the admin's personal account, so a stray
     * client key can never reach the admin's own servers.
     */
    ownerUserId: z.number().int().positive().optional(),
    /** Skip TLS verification for THIS target only (self-signed LAN panel). */
    insecureTLS: z.boolean().default(false),
  })
  .default({});

type Options = z.infer<typeof optionsSchema>;

function options(target: Target): Options {
  return optionsSchema.parse(target.options ?? {});
}

export function baseUrl(target: Target): string {
  return deriveBaseUrl(target, { baseUrl: options(target).baseUrl, httpsPorts: [443, 8443] });
}

/** Which half of the Pelican API a call belongs to. */
export type PelicanApi = "application" | "client";

/** Key prefixes Pelican issues, per API half. */
const KEY_PREFIX: Record<PelicanApi, string> = { application: "papp_", client: "pacc_" };

/**
 * Pick the key for one API half. Candidates are gathered from the explicitly
 * named fields first, then the item's generic secret/password — but every
 * candidate is filtered by the REQUIRED PREFIX, so a `pacc_` value sitting in an
 * `application_key` field (or in the item secret) can never be sent to the
 * application API. Returns undefined when no candidate matches; the caller turns
 * that into an actionable error naming the field to fix. Exported for testing.
 */
export function keyFor(cred: Credential, api: PelicanApi): string | undefined {
  const named =
    api === "application"
      ? [cred.fields["application_key"], cred.fields["app_key"], cred.fields["papp_key"]]
      : [cred.fields["client_key"], cred.fields["pacc_key"]];
  // The bare secret/password is a last resort and only when its prefix says
  // which half it belongs to — a single-key item still works for its own API.
  for (const cand of [...named, cred.secret, cred.password]) {
    if (typeof cand === "string" && cand.startsWith(KEY_PREFIX[api])) return cand;
  }
  return undefined;
}

/** The error a missing/mis-prefixed key produces — names the field and the
 *  expected prefix so the fix is obvious without ever echoing a value. */
export function missingKeyError(api: PelicanApi): Error {
  const field = api === "application" ? "application_key" : "client_key";
  return new Error(
    `This Pelican target has no usable ${api} API key. Store it as the vault field '${field}' — it must start with '${KEY_PREFIX[api]}'. ` +
      `(The ${api === "application" ? "Application" : "Client"} API is the only half with ${api === "application" ? "eggs/nodes/allocations and server creation" : "power, startup and schedules"}; the other key will not work here.)`,
  );
}

/** Field names whose VALUES are secret in a Pelican payload. Egg/server
 *  environment variables are user-named, so match the families broadly:
 *  passwords, tokens, keys, secrets, and Pelican's own `daemon_token`. */
const SECRET_KEY = /pass(word|wd|phrase)?|token|secret|_key\b|apikey|api_key|private|credential|rcon/i;

/** Deep key-name redaction, structured (not regex-on-JSON) so a value
 *  containing a quote can't truncate the mask. Exported for testing. */
export function redactSecrets(value: unknown): unknown {
  if (Array.isArray(value)) return value.map(redactSecrets);
  if (value && typeof value === "object") {
    const out: Record<string, unknown> = {};
    for (const [k, v] of Object.entries(value as Record<string, unknown>)) {
      out[k] = SECRET_KEY.test(k) ? "[redacted]" : redactSecrets(v);
    }
    return out;
  }
  return value;
}

/** Best-effort masking of an already-stringified error body — a backstop only;
 *  prefer redactSecrets on structured data. Exported for testing. */
export function scrubSecrets(s: string): string {
  return s.replace(/"([A-Za-z0-9_]*?)"(\s*:\s*)"[^"]*"/g, (m, key: string, sep: string) =>
    SECRET_KEY.test(key) ? `"${key}"${sep}"[redacted]"` : m,
  );
}

/** True only for an RFC1918 (private / LAN) IPv4 literal. Exported for testing. */
export function isPrivateIPv4(ip: string): boolean {
  const m = /^(\d{1,3})\.(\d{1,3})\.(\d{1,3})\.(\d{1,3})$/.exec(ip);
  if (!m) return false;
  const [a, b, c, d] = [Number(m[1]), Number(m[2]), Number(m[3]), Number(m[4])];
  if ([a, b, c, d].some((n) => n > 255)) return false;
  return a === 10 || (a === 172 && b >= 16 && b <= 31) || (a === 192 && b === 168);
}

/**
 * A Pelican API key is a bearer credential, so it may only cross the wire in
 * clear on a LAN we control. Panels commonly serve plain http on the LAN (this
 * one binds 443 to loopback only), so http is allowed for an RFC1918 host and
 * refused for anything routable — the same posture as the PKGM Basic-auth rule
 * in the plan. Exported for testing.
 */
export function assertTransportOk(base: string): void {
  let url: URL;
  try {
    url = new URL(base);
  } catch {
    throw new Error(`Invalid Pelican panel URL '${base}'.`);
  }
  if (url.protocol === "https:") return;
  if (url.protocol !== "http:") throw new Error(`Unsupported Pelican panel scheme '${url.protocol}' — use http (LAN only) or https.`);
  if (!isPrivateIPv4(url.hostname) && url.hostname !== "localhost") {
    throw new Error(
      `Refusing to send a Pelican API key over plain http to '${url.hostname}' — that host is not a private LAN address. Use https, or set the target's baseUrl to the panel's LAN IP.`,
    );
  }
}

// --- Response shapes (Fractal envelopes: {object, data:[{attributes}]}) -------

interface Egg {
  id: number;
  name?: string;
  author?: string;
  description?: string;
  docker_image?: string;
  docker_images?: Record<string, string> | string[];
  [k: string]: unknown;
}
interface Node {
  id: number;
  name?: string;
  fqdn?: string;
  scheme?: string;
  memory?: number;
  memory_overallocate?: number;
  disk?: number;
  allocated_resources?: { memory?: number; disk?: number };
  [k: string]: unknown;
}
interface Allocation {
  id: number;
  ip?: string;
  alias?: string | null;
  port?: number;
  assigned?: boolean;
  [k: string]: unknown;
}
interface PanelUser {
  id: number;
  username?: string;
  email?: string;
  root_admin?: boolean;
  [k: string]: unknown;
}
interface Server {
  id: number;
  uuid?: string;
  identifier?: string;
  name?: string;
  description?: string;
  status?: string | null;
  suspended?: boolean;
  node?: number;
  egg?: number;
  allocation?: number;
  limits?: Record<string, unknown>;
  [k: string]: unknown;
}
interface Schedule {
  id: number;
  name?: string;
  cron?: { day_of_week?: string; day_of_month?: string; month?: string; hour?: string; minute?: string };
  is_active?: boolean;
  is_processing?: boolean;
  only_when_online?: boolean;
  last_run_at?: string | null;
  next_run_at?: string | null;
  relationships?: { tasks?: { data?: { attributes?: ScheduleTask }[] } };
  [k: string]: unknown;
}
interface ScheduleTask {
  id: number;
  action?: string;
  payload?: string;
  time_offset?: number;
  sequence_id?: number;
  continue_on_failure?: boolean;
}

// --- Summarizers (whitelisted fields; exported for testing) ------------------

export function summarizeEggs(eggs: Egg[]): string {
  if (!eggs.length) return "No eggs.";
  return eggs
    .map((e) => `- [${e.id}] ${e.name ?? "(unnamed)"}${e.author ? ` by ${e.author}` : ""}`)
    .join("\n");
}

export function summarizeNodes(nodes: Node[]): string {
  if (!nodes.length) return "No nodes.";
  return nodes
    .map((n) => {
      const memUsed = n.allocated_resources?.memory ?? 0;
      const diskUsed = n.allocated_resources?.disk ?? 0;
      return `- [${n.id}] ${n.name ?? "(unnamed)"} ${n.fqdn ?? "?"}  mem ${memUsed}/${n.memory ?? "?"}MiB  disk ${diskUsed}/${n.disk ?? "?"}MiB`;
    })
    .join("\n");
}

/** Free allocations first — that is what a provisioning step needs. */
export function summarizeAllocations(allocs: Allocation[]): string {
  if (!allocs.length) return "No allocations on this node.";
  const free = allocs.filter((a) => !a.assigned);
  const used = allocs.filter((a) => a.assigned);
  const line = (a: Allocation) => `  [${a.id}] ${a.ip ?? "?"}:${a.port ?? "?"}${a.alias ? ` (${a.alias})` : ""}`;
  const parts = [`FREE (${free.length}):`, ...free.map(line)];
  if (used.length) parts.push(`ASSIGNED (${used.length}):`, ...used.map(line));
  return parts.join("\n");
}

/** Minimal user view — enough to identify the dedicated panel user whose id
 *  becomes the target's `ownerUserId`, and nothing more. */
export function summarizeUsers(users: PanelUser[]): string {
  if (!users.length) return "No users.";
  return users
    .map((u) => `- [${u.id}] ${u.username ?? "(unnamed)"} <${u.email ?? "?"}>${u.root_admin ? "  ADMIN" : ""}`)
    .join("\n");
}

export function summarizeServers(servers: Server[]): string {
  if (!servers.length) return "No servers.";
  return servers
    .map((s) => {
      const flags = [s.suspended ? "SUSPENDED" : null, s.status ? String(s.status) : null].filter(Boolean).join(" ");
      return `- [${s.id}] ${s.name ?? "(unnamed)"} identifier=${s.identifier ?? "?"} uuid=${s.uuid ?? "?"} node=${s.node ?? "?"} egg=${s.egg ?? "?"}${flags ? `  ${flags}` : ""}`;
    })
    .join("\n");
}

/** Render a schedule's cron in the familiar 5-field order. */
export function cronOf(s: Schedule): string {
  const c = s.cron ?? {};
  return `${c.minute ?? "*"} ${c.hour ?? "*"} ${c.day_of_month ?? "*"} ${c.month ?? "*"} ${c.day_of_week ?? "*"}`;
}

export function summarizeSchedules(schedules: Schedule[]): string {
  if (!schedules.length) return "No schedules.";
  return schedules
    .map((s) => {
      const tasks = (s.relationships?.tasks?.data ?? [])
        .map((t) => t.attributes)
        .filter((t): t is ScheduleTask => !!t)
        .map((t) => `${t.action}${t.payload ? `:${t.payload}` : ""}@+${t.time_offset ?? 0}s [task ${t.id}]`);
      return (
        `- [${s.id}] ${s.name ?? "(unnamed)"}  cron '${cronOf(s)}'  ${s.is_active === false ? "INACTIVE" : "active"}` +
        `${s.only_when_online ? " only-when-online" : ""}` +
        `${s.next_run_at ? `  next ${s.next_run_at}` : ""}` +
        `${tasks.length ? `\n    tasks: ${tasks.join(", ")}` : "\n    tasks: (none — this schedule does nothing)"}`
      );
    })
    .join("\n");
}

/** Power signals Pelican accepts (SendPowerRequest: in:start,stop,restart,kill). */
export const POWER_SIGNALS = ["start", "stop", "restart", "kill"] as const;

/** Schedule task actions Pelican accepts (StoreTaskRequest). */
export const TASK_ACTIONS = ["command", "power", "backup", "delete_files"] as const;

/** One cron field — Pelican validates server-side, this catches obvious junk
 *  before a round-trip. Exported for testing. */
export function assertCronField(name: string, value: string): void {
  if (!/^[0-9*,\-/]+$/.test(value)) {
    throw new Error(`Invalid cron ${name} '${value}' — only digits and * , - / are allowed.`);
  }
}

/** Pelican client bound to one target. */
class Pelican {
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

  /** One API call against the named half. The key is chosen by `api` and never
   *  falls back to the other half's key. */
  private async request(
    api: PelicanApi,
    path: string,
    opts: { method?: string; body?: unknown; query?: Record<string, string | number> } = {},
  ): Promise<{ ok: boolean; status: number; json?: unknown; text: string }> {
    assertTransportOk(this.base);
    const key = keyFor(this.cred, api);
    if (!key) throw missingKeyError(api);

    const qs = opts.query
      ? `?${Object.entries(opts.query)
          .map(([k, v]) => `${encodeURIComponent(k)}=${encodeURIComponent(String(v))}`)
          .join("&")}`
      : "";
    const headers: Record<string, string> = {
      // Pelican redirects a non-JSON request to the web login, so Accept is not
      // optional — without it an unauthenticated call 302s instead of 401ing.
      Accept: "application/json",
      Authorization: `Bearer ${key}`,
    };
    if (opts.body !== undefined) headers["Content-Type"] = "application/json";
    const res = await tlsFetch(
      `${this.base}/api/${api}${path}${qs}`,
      { method: opts.method ?? "GET", headers, body: opts.body !== undefined ? JSON.stringify(opts.body) : undefined },
      this.insecure,
    );
    const text = await res.text();
    let json: unknown;
    try {
      json = text ? JSON.parse(text) : undefined;
    } catch {
      /* non-JSON body */
    }
    return { ok: res.ok, status: res.status, json, text };
  }

  /** Throw on an HTTP error, surfacing Pelican's `{errors:[{detail}]}` envelope
   *  (scrubbed) rather than a bare status. */
  private ensureOk(res: { ok: boolean; status: number; json?: unknown; text: string }, path: string): void {
    if (res.ok) return;
    const errs = (res.json as { errors?: { detail?: string; code?: string }[] })?.errors;
    const detail = errs?.map((e) => e.detail ?? e.code).filter(Boolean).join("; ");
    throw new Error(`Pelican HTTP ${res.status} on ${path}: ${scrubSecrets(detail || res.text).slice(0, 400)}`);
  }

  /** Unwrap a Fractal list, following pagination so a long allocation list is
   *  complete rather than silently truncated at the first page. */
  private async list<T>(api: PelicanApi, path: string, query: Record<string, string | number> = {}): Promise<T[]> {
    const out: T[] = [];
    let page = 1;
    for (;;) {
      const res = await this.request(api, path, { query: { ...query, page, per_page: 100 } });
      this.ensureOk(res, path);
      const body = res.json as {
        data?: { attributes?: T }[];
        meta?: { pagination?: { current_page?: number; total_pages?: number } };
      };
      for (const row of body?.data ?? []) if (row?.attributes) out.push(row.attributes);
      const pag = body?.meta?.pagination;
      if (!pag || !pag.total_pages || (pag.current_page ?? page) >= pag.total_pages) return out;
      page += 1;
      if (page > 50) return out; // hard stop; no realistic panel exceeds this
    }
  }

  private async item<T>(api: PelicanApi, path: string, query: Record<string, string | number> = {}): Promise<T> {
    const res = await this.request(api, path, { query });
    this.ensureOk(res, path);
    return ((res.json as { attributes?: T })?.attributes ?? {}) as T;
  }

  // --- reads ---------------------------------------------------------------

  async listEggs(): Promise<string> {
    return summarizeEggs(await this.list<Egg>("application", "/eggs"));
  }

  async listNodes(): Promise<string> {
    return summarizeNodes(await this.list<Node>("application", "/nodes"));
  }

  async listAllocations(nodeId: number): Promise<string> {
    return summarizeAllocations(await this.list<Allocation>("application", `/nodes/${nodeId}/allocations`));
  }

  async listUsers(): Promise<string> {
    return summarizeUsers(await this.list<PanelUser>("application", "/users"));
  }

  async listServers(): Promise<string> {
    return summarizeServers(await this.list<Server>("application", "/servers"));
  }

  /** Full detail for one server, by numeric APPLICATION id. Redacted — the
   *  container block carries egg environment variables (RCON/admin passwords). */
  async serverDetails(id: number): Promise<string> {
    const s = await this.item<Server>("application", `/servers/${id}`);
    return JSON.stringify(redactSecrets(s), null, 1).slice(0, 6000);
  }

  /** Live resource usage, by client ref (short identifier or full UUID). */
  async serverResources(ref: string): Promise<string> {
    const r = await this.item<{ current_state?: string; is_suspended?: boolean; resources?: Record<string, number> }>(
      "client",
      `/servers/${encodeURIComponent(ref)}/resources`,
    );
    const u = r.resources ?? {};
    const mb = (b?: number) => (typeof b === "number" ? `${Math.round(b / 1048576)}MiB` : "?");
    return (
      `state=${r.current_state ?? "?"}${r.is_suspended ? " SUSPENDED" : ""}  cpu=${u.cpu_absolute ?? "?"}%  ` +
      `mem=${mb(u.memory_bytes)}  disk=${mb(u.disk_bytes)}  net rx/tx=${mb(u.network_rx_bytes)}/${mb(u.network_tx_bytes)}  uptime=${u.uptime ?? 0}ms`
    );
  }

  async listSchedules(ref: string): Promise<string> {
    return summarizeSchedules(
      await this.list<Schedule>("client", `/servers/${encodeURIComponent(ref)}/schedules`, { include: "tasks" }),
    );
  }

  // --- resolution helpers --------------------------------------------------

  /** Resolve an egg by numeric id or exact name; refuses an ambiguous name. */
  private async resolveEgg(ref: string): Promise<Egg> {
    const eggs = await this.list<Egg>("application", "/eggs");
    if (/^\d+$/.test(ref)) {
      const byId = eggs.find((e) => e.id === Number(ref));
      if (!byId) throw new Error(`No Pelican egg with id ${ref}. Use list_eggs.`);
      return byId;
    }
    const matches = eggs.filter((e) => (e.name ?? "").toLowerCase() === ref.trim().toLowerCase());
    if (!matches.length) throw new Error(`No Pelican egg named '${ref}'. Use list_eggs to see the exact names.`);
    if (matches.length > 1) throw new Error(`Egg name '${ref}' is ambiguous (ids ${matches.map((m) => m.id).join(", ")}); pass the id.`);
    return matches[0]!;
  }

  /** Resolve an allocation by id or "ip:port", scanning every node. Refuses one
   *  that is already assigned — reusing it would move another server's port. */
  private async resolveAllocation(ref: string): Promise<{ alloc: Allocation; nodeId: number }> {
    const nodes = await this.list<Node>("application", "/nodes");
    const found: { alloc: Allocation; nodeId: number }[] = [];
    for (const n of nodes) {
      for (const a of await this.list<Allocation>("application", `/nodes/${n.id}/allocations`)) {
        if (/^\d+$/.test(ref) ? a.id === Number(ref) : `${a.ip}:${a.port}` === ref.trim()) found.push({ alloc: a, nodeId: n.id });
      }
    }
    if (!found.length) throw new Error(`No Pelican allocation matching '${ref}'. Use list_allocations on the node.`);
    if (found.length > 1) {
      throw new Error(`'${ref}' matches allocations on ${found.length} nodes (ids ${found.map((f) => f.alloc.id).join(", ")}); pass the allocation id.`);
    }
    const hit = found[0]!;
    if (hit.alloc.assigned) {
      throw new Error(`Allocation ${hit.alloc.ip}:${hit.alloc.port} [${hit.alloc.id}] is already assigned to a server; pick a FREE one from list_allocations.`);
    }
    return hit;
  }

  // --- executes ------------------------------------------------------------

  /** Create a server owned by the target's dedicated `ownerUserId`. */
  async createServer(input: {
    name: string;
    egg: string;
    allocation: string;
    memory?: number;
    disk?: number;
    cpu?: number;
    swap?: number;
    io?: number;
    databases?: number;
    backups?: number;
    allocations?: number;
    environment?: Record<string, string | number | boolean>;
    dockerImage?: string;
    startup?: string;
    description?: string;
    startOnCompletion?: boolean;
  }): Promise<string> {
    const owner = options(this.target).ownerUserId;
    if (!owner) {
      throw new Error(
        "This Pelican target has no 'ownerUserId' option, so create_server can't set an owner. Register/update the target with the dedicated panel user's id — servers must never be owned by the admin's personal account.",
      );
    }
    const egg = await this.resolveEgg(input.egg);
    const { alloc } = await this.resolveAllocation(input.allocation);

    const body = {
      name: input.name.trim(),
      description: input.description ?? "",
      user: owner,
      egg: egg.id,
      // `environment` is `present|array` — always send it, even empty, or the
      // request fails validation before it reaches the egg's own variable rules.
      environment: input.environment ?? {},
      ...(input.dockerImage ? { docker_image: input.dockerImage } : {}),
      ...(input.startup ? { startup: input.startup } : {}),
      limits: {
        memory: input.memory ?? 4096,
        swap: input.swap ?? 0,
        disk: input.disk ?? 10240,
        io: input.io ?? 500,
        cpu: input.cpu ?? 0,
      },
      feature_limits: {
        databases: input.databases ?? 0,
        allocations: input.allocations ?? 1,
        backups: input.backups ?? 1,
      },
      allocation: { default: alloc.id },
      start_on_completion: input.startOnCompletion ?? false,
    };
    const path = "/servers";
    const res = await this.request("application", path, { method: "POST", body });
    this.ensureOk(res, path);
    const created: Partial<Server> = (res.json as { attributes?: Server })?.attributes ?? {};
    return (
      `Created Pelican server '${created.name ?? input.name}' [id ${created.id ?? "?"}] identifier=${created.identifier ?? "?"} uuid=${created.uuid ?? "?"} ` +
      `on egg '${egg.name ?? egg.id}', allocation ${alloc.ip}:${alloc.port} [${alloc.id}], owner user ${owner}. ` +
      `The panel installs it in the background — poll server_resources (or list_servers) until it leaves 'installing'. ` +
      `Use the identifier/uuid (not the numeric id) for power, startup and schedule tools.`
    );
  }

  /** Send a power signal via the Client API. */
  async powerAction(ref: string, signal: string): Promise<string> {
    const path = `/servers/${encodeURIComponent(ref)}/power`;
    const res = await this.request("client", path, { method: "POST", body: { signal } });
    this.ensureOk(res, path);
    return (
      `Sent '${signal}'${signal === "kill" ? " (UNGRACEFUL — the process was terminated, not asked to stop)" : ""} to Pelican server '${ref}' on ${this.target.name}. ` +
      `Power changes are asynchronous — confirm with server_resources.`
    );
  }

  /** Set one or more egg startup variables. The route takes ONE variable per
   *  call (`PUT /startup/variable`), so a multi-variable change is a sequence of
   *  writes: they are applied in order and the result names exactly which ones
   *  landed, so a partial failure is recoverable rather than ambiguous. */
  async updateStartupVariables(ref: string, variables: Record<string, string | number | boolean>): Promise<string> {
    const keys = Object.keys(variables);
    if (!keys.length) throw new Error("update_startup_variables needs at least one variable.");
    const done: string[] = [];
    for (const key of keys) {
      const path = `/servers/${encodeURIComponent(ref)}/startup/variable`;
      const res = await this.request("client", path, { method: "PUT", body: { key, value: String(variables[key]) } });
      if (!res.ok) {
        const partial = done.length ? ` Already applied: ${done.join(", ")} — those are NOT rolled back.` : "";
        try {
          this.ensureOk(res, path);
        } catch (e) {
          throw new Error(`${e instanceof Error ? e.message : String(e)} (failed on variable '${key}').${partial}`);
        }
      }
      done.push(key);
    }
    return (
      `Set ${done.length} startup variable(s) on Pelican server '${ref}': ${done.join(", ")} (values not echoed). ` +
      `Most eggs only read startup variables at boot — restart the server for them to take effect.`
    );
  }

  /** Create a schedule, optionally with the power task that makes it do
   *  something. A schedule with no task is inert, which is a classic silent
   *  failure for "server hours", so the tool creates both in one step. */
  async createSchedule(input: {
    server: string;
    name: string;
    minute: string;
    hour: string;
    dayOfMonth?: string;
    month?: string;
    dayOfWeek?: string;
    isActive?: boolean;
    onlyWhenOnline?: boolean;
    action?: string;
    payload?: string;
  }): Promise<string> {
    const cron = {
      minute: input.minute,
      hour: input.hour,
      day_of_month: input.dayOfMonth ?? "*",
      month: input.month ?? "*",
      day_of_week: input.dayOfWeek ?? "*",
    };
    for (const [k, v] of Object.entries(cron)) assertCronField(k, v);

    const path = `/servers/${encodeURIComponent(input.server)}/schedules`;
    const res = await this.request("client", path, {
      method: "POST",
      body: {
        name: input.name.trim(),
        is_active: input.isActive ?? true,
        only_when_online: input.onlyWhenOnline ?? false,
        ...cron,
      },
    });
    this.ensureOk(res, path);
    const sched = (res.json as { attributes?: Schedule })?.attributes ?? ({} as Schedule);
    let taskNote = " No task attached — this schedule does nothing until you add one.";
    if (input.action) {
      const tPath = `${path}/${sched.id}/tasks`;
      const tRes = await this.request("client", tPath, {
        method: "POST",
        body: { action: input.action, payload: input.payload ?? "", time_offset: 0, continue_on_failure: false },
      });
      if (!tRes.ok) {
        return (
          `Created Pelican schedule '${sched.name ?? input.name}' [${sched.id}] on '${input.server}' (cron '${cronOf({ id: 0, cron })}'), ` +
          `but attaching the ${input.action} task FAILED (HTTP ${tRes.status}) — the schedule exists and is inert. Add the task or delete the schedule.`
        );
      }
      taskNote = ` Task '${input.action}${input.payload ? `:${input.payload}` : ""}' attached.`;
    }
    return (
      `Created Pelican schedule '${sched.name ?? input.name}' [${sched.id}] on server '${input.server}' — cron '${cronOf({ id: 0, cron })}', ` +
      `${input.isActive === false ? "INACTIVE" : "active"}.${taskNote} Delete with delete_schedule.`
    );
  }

  /** Update a schedule (the panel's update route is POST, not PUT/PATCH). Reads
   *  the current schedule first so unspecified cron fields keep their value —
   *  the endpoint replaces the whole cron, so a naive partial write would silently
   *  reset the omitted fields to '*' and run the job far more often. */
  async updateSchedule(input: {
    server: string;
    schedule: number;
    name?: string;
    minute?: string;
    hour?: string;
    dayOfMonth?: string;
    month?: string;
    dayOfWeek?: string;
    isActive?: boolean;
    onlyWhenOnline?: boolean;
  }): Promise<string> {
    const base = `/servers/${encodeURIComponent(input.server)}/schedules`;
    const current = await this.item<Schedule>("client", `${base}/${input.schedule}`);
    if (!current?.id) throw new Error(`No Pelican schedule ${input.schedule} on server '${input.server}'. Use list_schedules.`);

    const cur = current.cron ?? {};
    const cron = {
      minute: input.minute ?? cur.minute ?? "*",
      hour: input.hour ?? cur.hour ?? "*",
      day_of_month: input.dayOfMonth ?? cur.day_of_month ?? "*",
      month: input.month ?? cur.month ?? "*",
      day_of_week: input.dayOfWeek ?? cur.day_of_week ?? "*",
    };
    for (const [k, v] of Object.entries(cron)) assertCronField(k, v);

    const body = {
      name: input.name ?? current.name ?? "",
      is_active: input.isActive ?? current.is_active ?? true,
      only_when_online: input.onlyWhenOnline ?? current.only_when_online ?? false,
      ...cron,
    };
    const path = `${base}/${input.schedule}`;
    const res = await this.request("client", path, { method: "POST", body });
    this.ensureOk(res, path);
    return (
      `Updated Pelican schedule [${input.schedule}] on '${input.server}': ` +
      `cron '${cronOf(current)}' → '${cronOf({ id: 0, cron })}', ` +
      `name '${current.name ?? ""}' → '${body.name}', active ${current.is_active !== false} → ${body.is_active}. ` +
      `Revert by calling update_schedule with the prior values above.`
    );
  }

  async deleteSchedule(input: { server: string; schedule: number; expectName: string }): Promise<string> {
    const base = `/servers/${encodeURIComponent(input.server)}/schedules`;
    const current = await this.item<Schedule>("client", `${base}/${input.schedule}`);
    if (!current?.id) throw new Error(`No Pelican schedule ${input.schedule} on server '${input.server}'. Use list_schedules.`);
    if ((current.name ?? "").trim() !== input.expectName.trim()) {
      throw new Error(
        `Refusing to delete schedule ${input.schedule} — it is named '${current.name}', but you said '${input.expectName}'. Re-run list_schedules and confirm which schedule you mean.`,
      );
    }
    const path = `${base}/${input.schedule}`;
    const res = await this.request("client", path, { method: "DELETE" });
    this.ensureOk(res, path);
    return `Deleted Pelican schedule '${current.name}' [${input.schedule}] (cron '${cronOf(current)}') on server '${input.server}'. Recreate with create_schedule.`;
  }

  /** Assign an additional allocation from the node's free pool. The client route
   *  takes no arguments — the panel picks a free allocation and the server's
   *  `feature_limits.allocations` caps how many it may hold. */
  async assignAllocation(ref: string): Promise<string> {
    const path = `/servers/${encodeURIComponent(ref)}/network/allocations`;
    const res = await this.request("client", path, { method: "POST" });
    this.ensureOk(res, path);
    const a: Partial<Allocation> = (res.json as { attributes?: Allocation })?.attributes ?? {};
    return (
      `Assigned allocation ${a.ip ?? "?"}:${a.port ?? "?"} [${a.id ?? "?"}] to Pelican server '${ref}'. ` +
      `The panel chose it from the node's free pool (this route takes no port argument). ` +
      `To expose it publicly, add a UniFi port-forward to that exact IP:port.`
    );
  }

  /** Disaster-recovery snapshot: the inventory needed to rebuild the panel's
   *  server layout. Redacted — environment variables carry game passwords. */
  async snapshot(): Promise<SnapshotArtifact[]> {
    const arts: SnapshotArtifact[] = [];
    const servers = await this.list<Server>("application", "/servers");
    arts.push({
      name: "servers.json",
      data: Buffer.from(JSON.stringify(redactSecrets(servers), null, 1)),
      note: "Pelican servers (env vars redacted)",
    });
    arts.push({
      name: "nodes.json",
      data: Buffer.from(JSON.stringify(redactSecrets(await this.list<Node>("application", "/nodes")), null, 1)),
      note: "Pelican nodes (daemon tokens redacted)",
    });
    arts.push({
      name: "eggs.json",
      data: Buffer.from(JSON.stringify(redactSecrets(await this.list<Egg>("application", "/eggs")), null, 1)),
      note: "Pelican eggs",
    });
    // Schedules are per-server and client-keyed; best-effort so a client key that
    // doesn't own every server still yields the application-side inventory above.
    try {
      const scheds: Record<string, unknown> = {};
      for (const s of servers) {
        if (!s.identifier) continue;
        scheds[s.identifier] = await this.list<Schedule>("client", `/servers/${s.identifier}/schedules`, { include: "tasks" });
      }
      arts.push({ name: "schedules.json", data: Buffer.from(JSON.stringify(scheds, null, 1)), note: "per-server schedules" });
    } catch {
      /* client key may not own every server; inventory above is still captured */
    }
    return arts;
  }
}

async function withClient<T>(ctx: ToolContext, fn: (p: Pelican) => Promise<T>): Promise<T> {
  const cred = await ctx.getCredential();
  return fn(new Pelican(ctx.target, cred));
}

const ok = (text: string): ToolResult => ({ text });

function run(fn: (p: Pelican, input: any) => Promise<string>) {
  return async (input: unknown, ctx: ToolContext): Promise<ToolResult> => {
    try {
      return ok(await withClient(ctx, (p) => fn(p, input)));
    } catch (e) {
      return { text: `Pelican error: ${e instanceof Error ? e.message : String(e)}`, isError: true };
    }
  };
}

/** Client-API tools take this ref; application tools take the numeric id. */
const SERVER_REF = z
  .string()
  .describe("Server short identifier or full UUID (from list_servers) — NOT the numeric application id.");

function buildTools(target: Target): ConnectorTool[] {
  const owner = options(target).ownerUserId;
  return [
    {
      name: "list_eggs",
      description: `List Pelican eggs (game/server templates) on ${target.name} with their ids — create_server takes an egg id or exact name. Pelican has no nests; eggs are a flat list.`,
      tier: "read",
      inputSchema: z.object({}),
      run: run((p) => p.listEggs()),
    },
    {
      name: "list_nodes",
      description: `List Pelican nodes on ${target.name} (id, name, FQDN, allocated vs total memory/disk). Node ids are what list_allocations takes.`,
      tier: "read",
      inputSchema: z.object({}),
      run: run((p) => p.listNodes()),
    },
    {
      name: "list_allocations",
      description:
        `List a Pelican node's IP:port allocations on ${target.name}, FREE ones first. This is the authoritative source for a game ` +
        `server's LAN address and port — use it to pick create_server's allocation, and to fill in a UniFi port-forward's destination.`,
      tier: "read",
      inputSchema: z.object({ node: z.number().int().positive().describe("Node id from list_nodes.") }),
      run: run((p, i) => p.listAllocations(i.node)),
    },
    {
      name: "list_users",
      description:
        `List Pelican panel users on ${target.name} (id, username, email, admin flag). Use this to find the id of the dedicated ` +
        `non-admin user that owns Claude's servers — that id is the target's 'ownerUserId' option, which create_server requires.`,
      tier: "read",
      inputSchema: z.object({}),
      run: run((p) => p.listUsers()),
    },
    {
      name: "list_servers",
      description:
        `List Pelican servers on ${target.name}. Prints all three identities per server: the numeric id (for server_details), and the ` +
        `short identifier + uuid (for every power/startup/schedule tool, which use the Client API).`,
      tier: "read",
      inputSchema: z.object({}),
      run: run((p) => p.listServers()),
    },
    {
      name: "server_details",
      description: `Full configuration of one Pelican server on ${target.name}, by NUMERIC id from list_servers. Egg environment variables (RCON/admin/server passwords) are redacted.`,
      tier: "read",
      inputSchema: z.object({ id: z.number().int().positive().describe("Numeric application server id from list_servers.") }),
      run: run((p, i) => p.serverDetails(i.id)),
    },
    {
      name: "server_resources",
      description: `Live state and resource usage (power state, CPU, memory, disk, uptime) for one Pelican server on ${target.name}. Use this to confirm a power action or watch an install finish.`,
      tier: "read",
      inputSchema: z.object({ server: SERVER_REF }),
      run: run((p, i) => p.serverResources(i.server)),
    },
    {
      name: "list_schedules",
      description:
        `List a Pelican server's schedules on ${target.name} with their cron expression, active flag and attached tasks. ` +
        `A schedule with no tasks does nothing — this is how "server hours" are enforced, so check the tasks line.`,
      tier: "read",
      inputSchema: z.object({ server: SERVER_REF }),
      run: run((p, i) => p.listSchedules(i.server)),
    },
    {
      name: "create_server",
      description:
        `Provision a new game server on ${target.name}. Takes an egg (id or exact name from list_eggs) and a FREE allocation ` +
        `(id or 'ip:port' from list_allocations — an already-assigned one is refused). The owner is fixed to the target's dedicated ` +
        `panel user${owner ? ` (user ${owner})` : " — set the target's ownerUserId option first"}, never the admin's account. ` +
        `The panel installs the server asynchronously; poll server_resources until it leaves 'installing'.`,
      tier: "execute",
      inputSchema: z.object({
        name: z.string().min(1).describe("Server name, e.g. 'valheim'."),
        egg: z.string().describe("Egg id or exact name from list_eggs."),
        allocation: z.string().describe("Allocation id, or 'ip:port' from list_allocations. Must be FREE."),
        memory: z.number().int().min(0).optional().describe("Memory limit MiB (default 4096; 0 = unlimited)."),
        disk: z.number().int().min(0).optional().describe("Disk limit MiB (default 10240; 0 = unlimited)."),
        cpu: z.number().int().min(0).optional().describe("CPU limit % (default 0 = unlimited)."),
        swap: z.number().int().optional().describe("Swap MiB (default 0)."),
        io: z.number().int().optional().describe("Block IO weight (default 500)."),
        databases: z.number().int().min(0).optional().describe("Database limit (default 0)."),
        backups: z.number().int().min(0).optional().describe("Backup limit (default 1)."),
        allocations: z.number().int().min(1).optional().describe("Max allocations this server may hold (default 1)."),
        environment: z.record(z.union([z.string(), z.number(), z.boolean()])).optional().describe("Egg variables, e.g. {SERVER_NAME:'x'}. Required ones come from the egg."),
        dockerImage: z.string().optional().describe("Override the egg's default docker image."),
        startup: z.string().optional().describe("Override the egg's startup command."),
        description: z.string().optional(),
        startOnCompletion: z.boolean().optional().describe("Start the server once installation finishes. Default false."),
      }),
      confirm: (input, t) => {
        const i = input as { name: string; egg: string; allocation: string };
        const o = options(t).ownerUserId;
        return `Create Pelican server '${i.name}' (egg '${i.egg}', allocation ${i.allocation}, owner user ${o ?? "?"}) on ${t.name}`;
      },
      run: run((p, i) => p.createServer(i)),
    },
    {
      name: "power_action",
      description:
        `Start, stop, restart or kill a Pelican server on ${target.name}. 'kill' terminates the process ungracefully and can lose ` +
        `unsaved world state — prefer 'stop'. Power changes are asynchronous; confirm with server_resources.`,
      tier: "execute",
      inputSchema: z.object({
        server: SERVER_REF,
        signal: z.enum(POWER_SIGNALS).describe("start | stop | restart | kill"),
      }),
      confirm: (input, t) => {
        const i = input as { server: string; signal: string };
        const label = i.signal === "kill" ? "KILL (ungraceful — may lose unsaved state)" : i.signal.toUpperCase();
        return `${label} Pelican server '${i.server}' on ${t.name}`;
      },
      run: run((p, i) => p.powerAction(i.server, i.signal)),
    },
    {
      name: "update_startup_variables",
      description:
        `Set egg startup variables on a Pelican server on ${target.name}. The panel's route takes one variable per call, so several ` +
        `are applied in sequence and the result names exactly which landed — a partial failure is reported, not hidden. Values are ` +
        `never echoed back. Most eggs read these only at boot, so restart afterwards.`,
      tier: "execute",
      inputSchema: z.object({
        server: SERVER_REF,
        variables: z.record(z.union([z.string(), z.number(), z.boolean()])).describe("Variable name → value, e.g. {SERVER_NAME:'x', MAX_PLAYERS:10}."),
      }),
      confirm: (input, t) => {
        const i = input as { server: string; variables: Record<string, unknown> };
        // Names only — a startup variable's VALUE is frequently a password.
        return `Set startup variables [${Object.keys(i.variables ?? {}).join(", ")}] on Pelican server '${i.server}' on ${t.name} (values not shown)`;
      },
      run: run((p, i) => p.updateStartupVariables(i.server, i.variables)),
    },
    {
      name: "create_schedule",
      description:
        `Create a cron schedule on a Pelican server on ${target.name} — this is how "server hours" are enforced. Pass an action ` +
        `(usually 'power' with payload 'start' or 'stop') and the task is attached in the same call, because a schedule with no ` +
        `task is inert and looks like it worked. Cron fields are the standard 5.`,
      tier: "execute",
      inputSchema: z.object({
        server: SERVER_REF,
        name: z.string().min(1).describe("Schedule name, e.g. 'nightly stop'."),
        minute: z.string().describe("Cron minute, e.g. '0'."),
        hour: z.string().describe("Cron hour, e.g. '2'."),
        dayOfMonth: z.string().optional().describe("Default '*'."),
        month: z.string().optional().describe("Default '*'."),
        dayOfWeek: z.string().optional().describe("Default '*'."),
        isActive: z.boolean().optional().describe("Default true."),
        onlyWhenOnline: z.boolean().optional().describe("Only run when the server is online. Default false."),
        action: z.enum(TASK_ACTIONS).optional().describe("Task to attach: power | command | backup | delete_files."),
        payload: z.string().optional().describe("Task payload — for 'power': start | stop | restart | kill."),
      }),
      confirm: (input, t) => {
        const i = input as Record<string, string | undefined>;
        const cron = `${i.minute} ${i.hour} ${i.dayOfMonth ?? "*"} ${i.month ?? "*"} ${i.dayOfWeek ?? "*"}`;
        const task = i.action ? `${i.action}${i.payload ? `:${i.payload}` : ""}` : "no task (inert)";
        return `Create Pelican schedule '${i.name}' (cron '${cron}', ${task}) on server '${i.server}' on ${t.name}`;
      },
      run: run((p, i) => p.createSchedule(i)),
    },
    {
      name: "update_schedule",
      description:
        `Change a Pelican schedule on ${target.name}. The panel replaces the whole cron on update, so this reads the current ` +
        `schedule and preserves any field you don't pass — otherwise omitted fields would silently reset to '*' and the job would ` +
        `run far more often. The result reports prior → new so you can revert. Does not touch the schedule's tasks.`,
      tier: "execute",
      inputSchema: z.object({
        server: SERVER_REF,
        schedule: z.number().int().positive().describe("Schedule id from list_schedules."),
        name: z.string().min(1).optional(),
        minute: z.string().optional(),
        hour: z.string().optional(),
        dayOfMonth: z.string().optional(),
        month: z.string().optional(),
        dayOfWeek: z.string().optional(),
        isActive: z.boolean().optional().describe("Enable/disable without deleting."),
        onlyWhenOnline: z.boolean().optional(),
      }),
      confirm: (input, t) => {
        const i = input as Record<string, unknown>;
        const changes = ["name", "minute", "hour", "dayOfMonth", "month", "dayOfWeek", "isActive", "onlyWhenOnline"]
          .filter((k) => i[k] !== undefined)
          .map((k) => `${k} → ${JSON.stringify(i[k])}`)
          .join(", ");
        return `Update Pelican schedule [${String(i.schedule)}] on server '${String(i.server)}' on ${t.name} (${changes || "no change"})`;
      },
      run: run((p, i) => p.updateSchedule(i)),
    },
    {
      name: "delete_schedule",
      description:
        `Delete a Pelican schedule on ${target.name}. Echo back the schedule's name — it is verified against the live schedule ` +
        `first, so a stale id is refused rather than deleting the wrong one (and the approval prompt is legible without a lookup). ` +
        `Deleting a "server hours" schedule means the server stops being turned off automatically.`,
      tier: "execute",
      inputSchema: z.object({
        server: SERVER_REF,
        schedule: z.number().int().positive().describe("Schedule id from list_schedules."),
        expectName: z.string().describe("The schedule's current name, exactly as list_schedules shows it."),
      }),
      confirm: (input, t) => {
        const i = input as { server: string; schedule: number; expectName: string };
        return `Delete Pelican schedule '${i.expectName}' [${i.schedule}] on server '${i.server}' on ${t.name} — it will stop running`;
      },
      run: run((p, i) => p.deleteSchedule(i)),
    },
    {
      name: "assign_allocation",
      description:
        `Give a Pelican server an additional IP:port from its node's free pool on ${target.name}. The panel's route takes no port ` +
        `argument — it picks a free one and the result reports which. The server's allocation feature-limit caps how many it can ` +
        `hold. Run list_allocations afterwards if you need to port-forward the new address.`,
      tier: "execute",
      inputSchema: z.object({ server: SERVER_REF }),
      confirm: (input, t) => `Assign an additional allocation to Pelican server '${(input as { server: string }).server}' on ${t.name} (the panel picks a free IP:port)`,
      run: run((p, i) => p.assignAllocation(i.server)),
    },
  ];
}

export const pelicanConnector: Connector = {
  type: "pelican",
  label: "Pelican Panel (game servers)",
  configSchema: optionsSchema,
  requiresCredential: true,
  buildTools,
  snapshot: (ctx) => withClient(ctx, (p) => p.snapshot()),
};
