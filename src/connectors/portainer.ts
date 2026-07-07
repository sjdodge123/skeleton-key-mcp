import { z } from "zod";
import type { Connector, ConnectorTool, Credential, SnapshotArtifact, Target, ToolContext, ToolResult } from "./types.js";
import { deriveBaseUrl, tlsFetch } from "./net.js";

/**
 * Portainer connector — manage Docker through a Portainer CE/BE instance.
 *
 * Auth uses a Portainer **API key** (created in Portainer under "My account →
 * Access tokens"), stored as the credential's `token`/`api_key` field and sent
 * as `X-API-Key`. A username/password credential is also supported: it exchanges
 * them for a short-lived JWT via `/api/auth`. We deliberately read the API key
 * from an explicit field (not the notes-derived `secret`) so a password login's
 * freeform notes can't be mistaken for a key.
 *
 * Read tools inspect endpoints/containers/stacks and fetch logs and compose
 * files. Execute tools start/stop/restart containers and redeploy a stack with
 * an edited compose file — the latter is what lets Skeleton Key change its own
 * (or any) stack's environment and recreate it.
 */

const optionsSchema = z
  .object({
    /** Base URL; if omitted, host/port form the URL (9443/443 ⇒ https, else http). */
    baseUrl: z.string().url().optional(),
    /** Docker environment ("endpoint") id for container ops. Auto-detected if unset. */
    endpointId: z.number().int().positive().optional(),
    /** Skip TLS verification for THIS target only (self-signed Portainer on :9443).
     *  Per-request via an undici dispatcher, never process-global. */
    insecureTLS: z.boolean().default(false),
  })
  .default({});

type Options = z.infer<typeof optionsSchema>;

function options(target: Target): Options {
  return optionsSchema.parse(target.options ?? {});
}

export function baseUrl(target: Target): string {
  return deriveBaseUrl(target, { baseUrl: options(target).baseUrl, httpsPorts: [443, 9443] });
}

/** The API key from an explicit credential field (never the notes-derived secret). */
export function apiKeyFrom(cred: Credential): string | undefined {
  return cred.fields["api_key"] ?? cred.fields["token"] ?? undefined;
}

/** Portainer client bound to one target — resolves auth lazily per call. */
class Portainer {
  private jwt: string | null = null;

  constructor(
    private readonly target: Target,
    private readonly cred: Credential,
  ) {}

  private get base(): string {
    return baseUrl(this.target);
  }

  private async authHeaders(): Promise<Record<string, string>> {
    const apiKey = apiKeyFrom(this.cred);
    if (apiKey) return { "X-API-Key": apiKey };
    if (this.cred.username && this.cred.password) {
      this.jwt ??= await this.login(this.cred.username, this.cred.password);
      return { Authorization: `Bearer ${this.jwt}` };
    }
    throw new Error(
      "Portainer target needs an API key (store it as a 'token'), or a username + password. See Portainer → My account → Access tokens.",
    );
  }

  private async login(username: string, password: string): Promise<string> {
    const res = await this.fetch("/api/auth", { method: "POST", body: { username, password }, noAuth: true });
    if (!res.ok) throw new Error(`Portainer login failed: HTTP ${res.status}`);
    const jwt = (res.json as { jwt?: string })?.jwt;
    if (!jwt) throw new Error("Portainer login returned no token.");
    return jwt;
  }

  /** One HTTP call. `raw` returns the body as a Buffer (for log streams). */
  private async fetch(
    path: string,
    opts: { method?: string; body?: unknown; noAuth?: boolean; raw?: boolean } = {},
  ): Promise<{ ok: boolean; status: number; json?: unknown; text: string; buf?: Buffer }> {
    const headers: Record<string, string> = { Accept: "application/json" };
    if (!opts.noAuth) Object.assign(headers, await this.authHeaders());
    if (opts.body !== undefined) headers["Content-Type"] = "application/json";
    const res = await tlsFetch(
      `${this.base}${path}`,
      { method: opts.method ?? "GET", headers, body: opts.body !== undefined ? JSON.stringify(opts.body) : undefined },
      options(this.target).insecureTLS,
    );
    if (opts.raw) {
      const buf = Buffer.from(await res.arrayBuffer());
      return { ok: res.ok, status: res.status, text: "", buf };
    }
    const text = await res.text();
    let json: unknown;
    try {
      json = text ? JSON.parse(text) : undefined;
    } catch {
      /* non-JSON body */
    }
    return { ok: res.ok, status: res.status, json, text };
  }

  private async get<T>(path: string): Promise<T> {
    const res = await this.fetch(path);
    if (!res.ok) throw new Error(`HTTP ${res.status} on ${path}: ${res.text.slice(0, 300)}`);
    return res.json as T;
  }

  /** The Docker environment id for container ops (option, else the best endpoint). */
  private async endpointId(): Promise<number> {
    const opt = options(this.target).endpointId;
    if (opt) return opt;
    const endpoints = await this.get<{ Id: number; Type?: number; Status?: number }[]>("/api/endpoints");
    if (!endpoints.length) throw new Error("No Portainer endpoints found; set endpointId in the target options.");
    // Prefer a running (Status 1) Docker environment (Type 1 local / 2 agent) over
    // blindly taking the first, which may be down or a non-Docker (k8s/edge) env.
    const up = endpoints.filter((e) => e.Status === 1);
    const dockerUp = up.filter((e) => e.Type === 1 || e.Type === 2);
    return (dockerUp[0] ?? up[0] ?? endpoints[0]!).Id;
  }

  async listEndpoints(): Promise<string> {
    const eps = await this.get<{ Id: number; Name: string; Type: number; Status: number }[]>("/api/endpoints");
    if (!eps.length) return "No endpoints.";
    return eps.map((e) => `- #${e.Id} ${e.Name} (status ${e.Status === 1 ? "up" : "down"})`).join("\n");
  }

  async listContainers(all: boolean): Promise<string> {
    const eid = await this.endpointId();
    const cs = await this.get<DockerContainer[]>(`/api/endpoints/${eid}/docker/containers/json?all=${all ? 1 : 0}`);
    return summarizeContainers(cs);
  }

  async containerLogs(ref: string, tail: number): Promise<string> {
    const eid = await this.endpointId();
    const q = `stdout=1&stderr=1&tail=${tail}&timestamps=0`;
    const res = await this.fetch(`/api/endpoints/${eid}/docker/containers/${encodeURIComponent(ref)}/logs?${q}`, { raw: true });
    if (!res.ok) throw new Error(`HTTP ${res.status} fetching logs for '${ref}'.`);
    return demuxDockerLogs(res.buf ?? Buffer.alloc(0)) || "(no output)";
  }

  async containerAction(ref: string, action: "start" | "stop" | "restart"): Promise<string> {
    const eid = await this.endpointId();
    const res = await this.fetch(`/api/endpoints/${eid}/docker/containers/${encodeURIComponent(ref)}/${action}`, { method: "POST" });
    // Docker returns 204 on success, 304 if already in the desired state.
    if (!res.ok && res.status !== 304) throw new Error(`HTTP ${res.status} on ${action} '${ref}': ${res.text.slice(0, 300)}`);
    return `Container '${ref}' ${action}${action === "stop" ? "p" : ""}ed${res.status === 304 ? " (already in that state)" : ""}.`;
  }

  async listStacks(): Promise<string> {
    const ss = await this.get<PortainerStack[]>("/api/stacks");
    if (!ss.length) return "No stacks.";
    return ss.map((s) => `- #${s.Id} ${s.Name} (endpoint ${s.EndpointId}, ${s.Status === 1 ? "active" : "inactive"})`).join("\n");
  }

  async stackFile(id: number): Promise<string> {
    const f = await this.get<{ StackFileContent: string }>(`/api/stacks/${id}/file`);
    return f.StackFileContent;
  }

  async updateStack(id: number, stackFileContent: string, pullImage: boolean): Promise<string> {
    // Preserve the stack's substitution env + endpoint; only the compose changes.
    const cur = await this.get<PortainerStack>(`/api/stacks/${id}`);
    const res = await this.fetch(`/api/stacks/${id}?endpointId=${cur.EndpointId}`, {
      method: "PUT",
      body: { stackFileContent, env: cur.Env ?? [], prune: false, pullImage },
    });
    if (!res.ok) throw new Error(`HTTP ${res.status} updating stack #${id}: ${res.text.slice(0, 400)}`);
    return `Stack '${cur.Name}' (#${id}) redeployed with the updated compose file.`;
  }

  /**
   * Run a command inside a container (Docker exec via Portainer): create an exec
   * instance, then start it and demux the multiplexed output. `argv` is exact
   * argument tokens (no shell) — many images (e.g. watchtower) have no /bin/sh.
   */
  async exec(ref: string, argv: string[]): Promise<string> {
    const eid = await this.endpointId();
    const created = await this.fetch(`/api/endpoints/${eid}/docker/containers/${encodeURIComponent(ref)}/exec`, {
      method: "POST",
      body: { AttachStdout: true, AttachStderr: true, Cmd: argv },
    });
    if (!created.ok) throw new Error(`HTTP ${created.status} creating exec on '${ref}': ${created.text.slice(0, 300)}`);
    const execId = (created.json as { Id?: string })?.Id;
    if (!execId) throw new Error(`Portainer returned no exec id for '${ref}'.`);
    const started = await this.fetch(`/api/endpoints/${eid}/docker/exec/${execId}/start`, {
      method: "POST",
      body: { Detach: false, Tty: false },
      raw: true,
    });
    if (!started.ok) throw new Error(`HTTP ${started.status} starting exec on '${ref}'.`);
    return demuxDockerLogs(started.buf ?? Buffer.alloc(0)) || "(no output)";
  }

  /** Disaster-recovery snapshot: environments, stacks + their full compose files,
   *  and every container's inspect JSON (which may embed env-var secrets — a
   *  backup by design, encrypted at rest by the snapshot service). Per-item
   *  failures are skipped so one bad stack/container doesn't abort the target. */
  async snapshot(): Promise<SnapshotArtifact[]> {
    const arts: SnapshotArtifact[] = [];
    const jsonArt = (name: string, value: unknown, note?: string): SnapshotArtifact => ({
      name,
      data: Buffer.from(JSON.stringify(value, null, 2), "utf8"),
      ...(note ? { note } : {}),
    });
    const safe = (s: string) => s.replace(/^\//, "").replace(/[^a-zA-Z0-9._-]/g, "_") || "unnamed";
    const eid = await this.endpointId();

    arts.push(jsonArt("endpoints.json", await this.get<unknown[]>("/api/endpoints"), "Portainer environments"));

    const stacks = await this.get<PortainerStack[]>("/api/stacks");
    arts.push(jsonArt("stacks.json", stacks, "stack metadata"));
    for (const s of stacks) {
      try {
        const content = await this.stackFile(s.Id);
        // Include the endpoint id so a same-named stack on two endpoints can't collide.
        arts.push({ name: `stack-${s.EndpointId}-${safe(s.Name)}.compose.yml`, data: Buffer.from(content, "utf8"), note: `compose for stack #${s.Id}` });
      } catch {
        /* skip a stack whose compose file can't be read */
      }
    }

    const containers = await this.get<{ Id: string; Names?: string[] }[]>(`/api/endpoints/${eid}/docker/containers/json?all=1`);
    arts.push(jsonArt("containers.json", containers, "container list"));
    for (const c of containers) {
      try {
        const inspect = await this.get<unknown>(`/api/endpoints/${eid}/docker/containers/${encodeURIComponent(c.Id)}/json`);
        arts.push(jsonArt(`container-${safe(c.Names?.[0] ?? c.Id)}.inspect.json`, inspect, "container config (may contain env secrets)"));
      } catch {
        /* skip an un-inspectable container */
      }
    }
    return arts;
  }
}

/** Split a command line into exact argv tokens on whitespace (no shell / no
 *  quoting — minimal images have no shell). Exported for testing. */
export function toArgv(command: string): string[] {
  return command.trim().split(/\s+/).filter(Boolean);
}

interface DockerContainer {
  Names?: string[];
  Image?: string;
  State?: string;
  Status?: string;
}
interface PortainerStack {
  Id: number;
  Name: string;
  EndpointId: number;
  Status?: number;
  Env?: { name: string; value: string }[];
}

/** Compact one-line-per-container summary (exported for testing). */
export function summarizeContainers(cs: DockerContainer[]): string {
  if (!cs.length) return "No containers.";
  return cs
    .map((c) => {
      const name = (c.Names?.[0] ?? "").replace(/^\//, "") || "(unnamed)";
      return `- ${name}  [${c.State ?? "?"}]  ${c.Image ?? ""}  ${c.Status ?? ""}`.trimEnd();
    })
    .join("\n");
}

/**
 * Docker's log endpoint multiplexes stdout/stderr into frames prefixed with an
 * 8-byte header ([stream, 0,0,0, size×4 BE]) when the container has no TTY. Strip
 * the headers; if the stream doesn't look framed (TTY containers send raw bytes),
 * return it as-is. Exported for testing.
 */
export function demuxDockerLogs(buf: Buffer): string {
  // A valid frame header at offset o: 8 bytes available, stream ∈ {0,1,2}, and
  // the three reserved bytes are zero.
  const isHeader = (o: number): boolean =>
    o + 8 <= buf.length && buf[o]! <= 2 && buf[o + 1] === 0 && buf[o + 2] === 0 && buf[o + 3] === 0;
  // TTY containers send raw bytes (no framing): if the start isn't a header, raw.
  if (!isHeader(0)) return buf.toString("utf8");
  const parts: string[] = [];
  let i = 0;
  while (i < buf.length) {
    // Validate EVERY frame's header and require it to fit exactly within the
    // buffer. Any truncation/malformation (a short trailing header, an oversized
    // size, nonzero reserved bytes) means the stream isn't cleanly framed, so
    // return the raw bytes rather than silently dropping or half-parsing them.
    if (!isHeader(i)) return buf.toString("utf8");
    const size = buf.readUInt32BE(i + 4);
    if (i + 8 + size > buf.length) return buf.toString("utf8");
    parts.push(buf.toString("utf8", i + 8, i + 8 + size));
    i += 8 + size;
  }
  return parts.join("");
}

async function withClient<T>(ctx: ToolContext, fn: (p: Portainer) => Promise<T>): Promise<T> {
  const cred = await ctx.getCredential();
  return fn(new Portainer(ctx.target, cred));
}

const ok = (text: string): ToolResult => ({ text });

function run(fn: (p: Portainer, input: any) => Promise<string>) {
  return async (input: unknown, ctx: ToolContext): Promise<ToolResult> => {
    try {
      return ok(await withClient(ctx, (p) => fn(p, input)));
    } catch (e) {
      return { text: `Portainer error: ${e instanceof Error ? e.message : String(e)}`, isError: true };
    }
  };
}

function buildTools(target: Target): ConnectorTool[] {
  return [
    {
      name: "list_endpoints",
      description: `List Portainer Docker environments (endpoints) on ${target.name}, with their ids.`,
      tier: "read",
      inputSchema: z.object({}),
      run: run((p) => p.listEndpoints()),
    },
    {
      name: "list_containers",
      description: `List containers on ${target.name} (name, state, image).`,
      tier: "read",
      inputSchema: z.object({ all: z.boolean().default(true).describe("Include stopped containers.") }),
      run: run((p, i) => p.listContainers(i.all)),
    },
    {
      name: "container_logs",
      description: `Tail a container's logs on ${target.name}.`,
      tier: "read",
      inputSchema: z.object({
        container: z.string().describe("Container name or id."),
        lines: z.number().int().positive().max(2000).default(200),
      }),
      run: run((p, i) => p.containerLogs(i.container, i.lines)),
    },
    {
      name: "list_stacks",
      description: `List Portainer stacks on ${target.name} (id, name, endpoint).`,
      tier: "read",
      inputSchema: z.object({}),
      run: run((p) => p.listStacks()),
    },
    {
      name: "get_stack_file",
      description: `Get a stack's compose file content on ${target.name} (edit it, then update_stack to redeploy).`,
      tier: "read",
      inputSchema: z.object({ stackId: z.number().int().positive() }),
      run: run((p, i) => p.stackFile(i.stackId)),
    },
    {
      name: "restart_container",
      description: `Restart a container on ${target.name}.`,
      tier: "execute",
      inputSchema: z.object({ container: z.string().describe("Container name or id.") }),
      confirm: (input, t) => `Restart container '${(input as { container: string }).container}' on ${t.name}`,
      run: run((p, i) => p.containerAction(i.container, "restart")),
    },
    {
      name: "stop_container",
      description: `Stop a container on ${target.name}.`,
      tier: "execute",
      inputSchema: z.object({ container: z.string().describe("Container name or id.") }),
      confirm: (input, t) => `Stop container '${(input as { container: string }).container}' on ${t.name}`,
      run: run((p, i) => p.containerAction(i.container, "stop")),
    },
    {
      name: "start_container",
      description: `Start a container on ${target.name}.`,
      tier: "execute",
      inputSchema: z.object({ container: z.string().describe("Container name or id.") }),
      confirm: (input, t) => `Start container '${(input as { container: string }).container}' on ${t.name}`,
      run: run((p, i) => p.containerAction(i.container, "start")),
    },
    {
      name: "update_stack",
      description:
        `Redeploy a Portainer stack on ${target.name} with a new compose file (e.g. after adding an environment variable). ` +
        `Get the current file with get_stack_file, edit it, then pass the full new content here. Recreates the stack's containers.`,
      tier: "execute",
      inputSchema: z.object({
        stackId: z.number().int().positive(),
        stackFileContent: z.string().describe("The FULL new compose file content (not a diff)."),
        pullImage: z.boolean().default(false).describe("Re-pull images on redeploy."),
      }),
      confirm: (input, t) => `Redeploy Portainer stack #${(input as { stackId: number }).stackId} on ${t.name} with an edited compose file`,
      run: run((p, i) => p.updateStack(i.stackId, i.stackFileContent, i.pullImage)),
    },
    {
      name: "exec_container",
      description:
        `Run a command inside a container on ${target.name} (Docker exec). ` +
        `Command is split into exact argv tokens on whitespace — no shell, no quoting (many images have no /bin/sh). ` +
        `E.g. trigger a scoped Watchtower update: container 'watchtower', command '/watchtower --run-once skeleton-key'.`,
      tier: "execute",
      inputSchema: z.object({
        container: z.string().describe("Container name or id."),
        command: z.string().describe("Command with arguments, split on whitespace (no shell)."),
      }),
      confirm: (input, t) => {
        const i = input as { container: string; command: string };
        return `Exec '${i.command}' inside container '${i.container}' on ${t.name}`;
      },
      run: run((p, i) => p.exec(i.container, toArgv(i.command))),
    },
  ];
}

export const portainerConnector: Connector = {
  type: "portainer",
  label: "Portainer (Docker)",
  configSchema: optionsSchema,
  requiresCredential: true,
  buildTools,
  snapshot: (ctx) => withClient(ctx, (p) => p.snapshot()),
};
