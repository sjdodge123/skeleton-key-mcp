import { z } from "zod";
import type { Connector, ConnectorTool, Credential, Target, ToolContext } from "./types.js";

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
    /** Base URL; if omitted, host/port form the URL (9443 ⇒ https, else http). */
    baseUrl: z.string().url().optional(),
    /** Docker environment ("endpoint") id for container ops. Auto-detected if unset. */
    endpointId: z.number().int().positive().optional(),
    /** Skip TLS verification for a self-signed Portainer cert (e.g. on :9443). */
    insecureTLS: z.boolean().default(false),
  })
  .default({});

type Options = z.infer<typeof optionsSchema>;

function options(target: Target): Options {
  return optionsSchema.parse(target.options ?? {});
}

export function baseUrl(target: Target): string {
  const opts = options(target);
  if (opts.baseUrl) return opts.baseUrl.replace(/\/$/, "");
  const scheme = target.port === 9443 || target.port === 443 ? "https" : "http";
  return `${scheme}://${target.host}${target.port ? `:${target.port}` : ""}`;
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
    if (options(this.target).insecureTLS) process.env.NODE_TLS_REJECT_UNAUTHORIZED = "0";
    const headers: Record<string, string> = { Accept: "application/json" };
    if (!opts.noAuth) Object.assign(headers, await this.authHeaders());
    if (opts.body !== undefined) headers["Content-Type"] = "application/json";
    const res = await fetch(`${this.base}${path}`, {
      method: opts.method ?? "GET",
      headers,
      body: opts.body !== undefined ? JSON.stringify(opts.body) : undefined,
    });
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

  /** The Docker environment id for container ops (option, else the first endpoint). */
  private async endpointId(): Promise<number> {
    const opt = options(this.target).endpointId;
    if (opt) return opt;
    const endpoints = await this.get<{ Id: number }[]>("/api/endpoints");
    if (!endpoints.length) throw new Error("No Portainer endpoints found; set endpointId in the target options.");
    return endpoints[0]!.Id;
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

  async stackName(id: number): Promise<string> {
    try {
      return (await this.get<PortainerStack>(`/api/stacks/${id}`)).Name;
    } catch {
      return `#${id}`;
    }
  }
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
  const looksFramed = buf.length >= 8 && buf[0]! <= 2 && buf[1] === 0 && buf[2] === 0 && buf[3] === 0;
  if (!looksFramed) return buf.toString("utf8");
  const parts: string[] = [];
  let i = 0;
  while (i + 8 <= buf.length) {
    const stream = buf[i]!;
    const size = buf.readUInt32BE(i + 4);
    // A malformed/oversized frame means it wasn't really framed — bail to raw.
    if (stream > 2 || i + 8 + size > buf.length + 4) return buf.toString("utf8");
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
type ToolResult = { text: string; isError?: boolean };

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
      run: run((p, i) => p.listContainers(i.all ?? true)),
    },
    {
      name: "container_logs",
      description: `Tail a container's logs on ${target.name}.`,
      tier: "read",
      inputSchema: z.object({
        container: z.string().describe("Container name or id."),
        lines: z.number().int().positive().max(2000).default(200),
      }),
      run: run((p, i) => p.containerLogs(i.container, i.lines ?? 200)),
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
      run: run((p, i) => p.updateStack(i.stackId, i.stackFileContent, i.pullImage ?? false)),
    },
  ];
}

export const portainerConnector: Connector = {
  type: "portainer",
  label: "Portainer (Docker)",
  configSchema: optionsSchema,
  requiresCredential: true,
  buildTools,
};
