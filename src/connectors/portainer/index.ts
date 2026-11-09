import { z } from "zod";
import * as yaml from "js-yaml";
import type { Connector, ConnectorTool, Credential, SnapshotArtifact, Target, ToolContext, ToolResult } from "../types.js";
import { deriveBaseUrl, tlsFetch } from "../shared/net.js";
// Vault-backed secret injection lives in one place now that Pelican needs it too.
import { resolveSecretRefs, secretFingerprintBlock, type SecretRef, type Fingerprinter } from "../shared/secret-refs.js";
export { pickCredentialField, secretFingerprintBlock, type Fingerprinter } from "../shared/secret-refs.js";
/** A `secretEnv` request: put vault item `credentialRef`'s value into var `name`. */
export type SecretEnvRef = SecretRef;
/** Resolve `secretEnv` entries through the vault (see ../shared/secret-refs.ts). */
export const resolveSecretEnv = (ctx: import("../types.js").ToolContext, refs: SecretEnvRef[] | undefined) => resolveSecretRefs(ctx, refs, "secretEnv");
import { checkCommand, type CommandPolicyOptions } from "../shared/command-policy.js";

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
 * files. Execute tools create/redeploy/remove stacks and start/stop/restart
 * containers — which is what lets Skeleton Key stand up a migrated app (compose
 * + public image) and change its own (or any) stack's environment.
 *
 * SECRETS: stack environments routinely need real secrets (DB passwords, API
 * tokens). Those are supplied as `secretEnv` — a list of {var, vault item} pairs
 * resolved through the vault at call time — so a secret never transits the chat
 * channel or the model context. The resolved values go to Portainer and NOWHERE
 * else: not into confirm text, tool results, or error messages. Correspondingly,
 * anything that reads env back out (`list_stacks`, `container_inspect`) reports
 * variable NAMES with redacted values.
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
    /** Extra denied command patterns for `exec_container` on this target. */
    denyPatterns: z.array(z.string()).optional(),
    /** If set, `exec_container` only runs commands matching one of these. */
    allowPatterns: z.array(z.string()).optional(),
  })
  .prefault({});

type Options = z.infer<typeof optionsSchema>;

function options(target: Target): Options {
  return optionsSchema.parse(target.options ?? {});
}

/** Command guardrails for `exec_container`, mirroring the SSH connector. */
export function policyFor(target: Target): CommandPolicyOptions {
  const opts = options(target);
  return { deny: opts.denyPatterns, allow: opts.allowPatterns };
}

export function baseUrl(target: Target): string {
  return deriveBaseUrl(target, { baseUrl: options(target).baseUrl, httpsPorts: [443, 9443] });
}

/** The API key from an explicit credential field (never the notes-derived secret). */
export function apiKeyFrom(cred: Credential): string | undefined {
  return cred.fields["api_key"] ?? cred.fields["token"] ?? undefined;
}

/** One stack environment variable as Portainer's API models it. */
export interface EnvEntry {
  name: string;
  value: string;
}

/**
 * Durable marker written into the compose file of every stack Skeleton Key
 * creates. `remove_stack` refuses anything without it, so a human-authored
 * stack can never be deleted through this connector — the marker lives in the
 * stack file itself, so it survives restarts, reinstalls, and edits made here.
 */
export const MANAGED_MARKER = "# x-skeleton-key-managed: true";

export function hasManagedMarker(compose: string): boolean {
  return /^\s*#\s*x-skeleton-key-managed:\s*true\s*$/im.test(compose);
}

/** Prepend the managed marker unless the compose file already carries one. */
export function ensureManagedMarker(compose: string): string {
  if (hasManagedMarker(compose)) return compose;
  return `${MANAGED_MARKER}\n${compose}`;
}

/** Best-effort list of images a compose file references (for the confirm text).
 *  Deliberately naive — it informs the approval prompt, it does not gate it. */
export function composeImages(compose: string): string[] {
  const found: string[] = [];
  for (const line of compose.split(/\r?\n/)) {
    if (/^\s*#/.test(line)) continue; // commented-out service
    const m = /^\s*image:\s*["']?([^"'#\s]+)/.exec(line);
    if (m?.[1] && !found.includes(m[1])) found.push(m[1]);
  }
  return found;
}

/** Expand compose `${VAR}`, `${VAR:-default}`, `${VAR-default}`, `$VAR` and `$$`
 *  against the stack's substitution env, the way Compose does (unset → ""). */
export function interpolateCompose(value: string, vars: Map<string, string>): string {
  return value.replace(/\$\$|\$\{([A-Za-z_][A-Za-z0-9_]*)(?:(:?-)([^}]*))?\}|\$([A-Za-z_][A-Za-z0-9_]*)/g, (m, braced, op, def, bare) => {
    if (m === "$$") return "$";
    const name = (braced ?? bare) as string;
    const v = vars.get(name);
    if (op === ":-") return v ? v : (def as string);
    if (op === "-") return v !== undefined ? v : (def as string);
    return v ?? "";
  });
}

/** What one compose service's `environment:` would set. `envFile` marks a
 *  service that also loads an env_file, whose contents we cannot see. */
export interface DeclaredEnv {
  env: Map<string, string>;
  envFile: boolean;
}

/**
 * The environment each service of a compose file would get, after `${VAR}`
 * substitution from the stack's env. Handles both the map and the list form; a
 * bare `KEY` (or `KEY:` with no value) takes the substitution value and is
 * left out when that is unset, as Compose does.
 */
export function composeServiceEnv(compose: string, stackEnv: EnvEntry[]): Map<string, DeclaredEnv> {
  const vars = new Map(stackEnv.map((e) => [e.name, e.value]));
  const doc = yaml.load(compose) as { services?: Record<string, { environment?: unknown; env_file?: unknown }> } | undefined;
  const out = new Map<string, DeclaredEnv>();
  for (const [service, def] of Object.entries(doc?.services ?? {})) {
    const env = new Map<string, string>();
    const put = (key: string, raw: unknown) => {
      if (raw === null || raw === undefined) {
        const v = vars.get(key);
        if (v !== undefined) env.set(key, v);
      } else {
        env.set(key, interpolateCompose(String(raw), vars));
      }
    };
    const e = def?.environment;
    if (Array.isArray(e)) {
      for (const item of e) {
        const str = String(item);
        const i = str.indexOf("=");
        if (i < 0) put(str, null);
        else put(str.slice(0, i), str.slice(i + 1));
      }
    } else if (e && typeof e === "object") {
      for (const [k, v] of Object.entries(e as Record<string, unknown>)) put(k, v);
    }
    out.set(service, { env, envFile: def?.env_file !== undefined });
  }
  return out;
}

/** One environment variable a redeploy would change. */
export interface EnvDrift {
  name: string;
  /** changed: both set, values differ · container-only: set on the running
   *  container but nowhere in the stack file or image, so a redeploy drops it ·
   *  stack-only: the stack file sets it, the running container doesn't have it. */
  kind: "changed" | "container-only" | "stack-only";
  running?: string;
  declared?: string;
}

/**
 * Compare a running container's env with what its stack file would set.
 * Variables the image itself defines (PATH, NODE_VERSION, …) are not drift
 * unless the container overrides them.
 */
export function envDrift(declared: DeclaredEnv, running: EnvEntry[], imageEnv: EnvEntry[]): EnvDrift[] {
  const out: EnvDrift[] = [];
  const image = new Map(imageEnv.map((e) => [e.name, e.value]));
  const seen = new Set<string>();
  for (const { name, value } of running) {
    seen.add(name);
    const want = declared.env.get(name);
    if (want !== undefined) {
      if (want !== value) out.push({ name, kind: "changed", running: value, declared: want });
    } else if (image.get(name) !== value && !declared.envFile) {
      out.push({ name, kind: "container-only", running: value });
    }
  }
  for (const [name, value] of declared.env) {
    if (!seen.has(name)) out.push({ name, kind: "stack-only", declared: value });
  }
  return out;
}

/** Stack names Portainer accepts, restricted to a shape that is also safe to
 *  interpolate into a URL/compose project name. */
export const STACK_NAME_RE = /^[a-z0-9][a-z0-9_.-]{0,62}$/;

/**
 * Replace every occurrence of a resolved secret with `<redacted>`. Belt and
 * braces for text we did not author — a Portainer error body may echo the
 * request — so a secret cannot ride out on an error path.
 */
export function redactSecrets(text: string, values: string[]): string {
  let out = text;
  for (const v of values) {
    if (v && v.length >= 4) out = out.split(v).join("<redacted>");
  }
  return out;
}

/** Env with every value redacted; names are preserved (they are not secret). */
export function redactEnv(env: EnvEntry[] | undefined): EnvEntry[] {
  return (env ?? []).map((e) => ({ name: e.name, value: "<redacted>" }));
}

/** Merge env lists by variable name — later lists win, first-seen order kept. */
export function mergeEnv(...lists: (EnvEntry[] | undefined)[]): EnvEntry[] {
  const merged = new Map<string, string>();
  for (const list of lists) for (const e of list ?? []) merged.set(e.name, e.value);
  return [...merged].map(([name, value]) => ({ name, value }));
}

/**
 * Annotate env entries as `NAME=<redacted> (len=<n> fp=<hex>)` — the value is
 * fingerprinted here in-process and NEVER emitted. A fingerprint can be
 * compared with the vault's (credential_request_status) to tell whether a
 * deployed/running secret is the SAME value without revealing either. Without
 * a fingerprinter the plain `<redacted>` form is returned — never a value.
 * A fingerprint failure degrades to the plain form the same way.
 */
export async function annotateEnv(env: EnvEntry[] | undefined, fp?: Fingerprinter): Promise<string[]> {
  const out: string[] = [];
  for (const e of env ?? []) {
    let tag = "";
    if (fp) {
      try {
        tag = ` (${await fp(e.value)})`;
      } catch {
        /* no fingerprint — still never the value */
      }
    }
    out.push(`${e.name}=<redacted>${tag}`);
  }
  return out;
}

/** Split Docker's `NAME=value` env strings into entries (a line with no '=' has an empty value). */
export function parseDockerEnv(env: string[] | undefined): EnvEntry[] {
  return (env ?? []).map((kv) => {
    const i = kv.indexOf("=");
    return i < 0 ? { name: kv, value: "" } : { name: kv.slice(0, i), value: kv.slice(i + 1) };
  });
}

/** One line per drifted variable: container, name and kind, with keyed
 *  fingerprints of the running and stack-file values. Never a value. */
async function describeDrift(drift: [string, EnvDrift][], fp?: Fingerprinter): Promise<string> {
  const tag = async (v: string | undefined) => {
    if (v === undefined) return "unset";
    if (!fp) return "set";
    try {
      return await fp(v);
    } catch {
      return "set";
    }
  };
  const lines: string[] = [];
  for (const [container, d] of drift) {
    lines.push(`- ${container}: ${d.name} (${d.kind}) — running ${await tag(d.running)}, stack file ${await tag(d.declared)}`);
  }
  return lines.join("\n");
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

  /** With a fingerprinter, each stack's env is annotated with per-value
   *  fingerprints (values still redacted) so it can be compared with the vault. */
  async listStacks(fp?: Fingerprinter): Promise<string> {
    const ss = await this.get<PortainerStack[]>("/api/stacks");
    const envLines = new Map<number, string[]>();
    for (const s of ss) envLines.set(s.Id, await annotateEnv(s.Env, fp));
    return summarizeStacks(ss, envLines);
  }

  async stackFile(id: number): Promise<string> {
    const f = await this.get<{ StackFileContent: string }>(`/api/stacks/${id}/file`);
    return f.StackFileContent;
  }

  /** Create a standalone (compose) stack from file content. `env` is the FINAL
   *  environment — plain vars already merged with resolved secretEnv values. */
  async createStack(name: string, composeContent: string, env: EnvEntry[]): Promise<string> {
    if (!STACK_NAME_RE.test(name)) {
      throw new Error(`Invalid stack name '${name}'. Use lowercase letters, digits, '.', '-' or '_' (max 63, must start alphanumeric).`);
    }
    const eid = await this.endpointId();
    const stackFileContent = ensureManagedMarker(composeContent);
    const res = await this.fetch(`/api/stacks/create/standalone/string?endpointId=${eid}`, {
      method: "POST",
      body: { name, stackFileContent, env, fromAppTemplate: false },
    });
    if (!res.ok) {
      // Scrub any secret Portainer echoed back before the message escapes.
      throw new Error(`HTTP ${res.status} creating stack '${name}': ${redactSecrets(res.text.slice(0, 400), env.map((e) => e.value))}`);
    }
    const created = res.json as { Id?: number; Name?: string; EndpointId?: number } | undefined;
    const vars = env.map((e) => e.name).join(", ");
    return (
      `Stack '${created?.Name ?? name}' created (#${created?.Id ?? "?"}) on endpoint ${created?.EndpointId ?? eid}, marked skeleton-key managed.` +
      (env.length ? ` ${env.length} environment variable(s) set: ${vars} (values not shown).` : "")
    );
  }

  async updateStack(id: number, stackFileContent: string, pullImage: boolean, env: EnvEntry[], secretEnv: EnvEntry[]): Promise<string> {
    // Preserve the stack's substitution env + endpoint; only the compose changes.
    // Precedence, later wins: current stack Env < new plain env < secretEnv.
    const cur = await this.get<PortainerStack>(`/api/stacks/${id}`);
    const merged = mergeEnv(cur.Env ?? [], env, secretEnv);
    const res = await this.fetch(`/api/stacks/${id}?endpointId=${cur.EndpointId}`, {
      method: "PUT",
      body: { stackFileContent, env: merged, prune: false, pullImage },
    });
    if (!res.ok) {
      // Scrub every merged value, not just the new secretEnv ones — the stack's
      // carried-forward Env may hold secrets injected by an earlier create/update.
      throw new Error(`HTTP ${res.status} updating stack #${id}: ${redactSecrets(res.text.slice(0, 400), merged.map((e) => e.value))}`);
    }
    const added = [...env, ...secretEnv].map((e) => e.name);
    return (
      `Stack '${cur.Name}' (#${id}) redeployed with the updated compose file.` +
      (added.length ? ` Environment updated: ${[...new Set(added)].join(", ")} (values not shown).` : "")
    );
  }

  /** Re-pull a stack's images and redeploy it with its compose file and
   *  environment exactly as they are — the update path for a stack that tracks
   *  a moving tag such as `:latest`. Nothing the caller sends reaches the
   *  compose file or env, so this is safe on human-authored stacks too.
   *
   *  It refuses first when the redeploy would change a running container's
   *  environment (a value edited on the container but never in the stack file
   *  would silently revert), unless `allowEnvDrift` is set. */
  async updateStackImages(id: number, expectedName: string, allowEnvDrift: boolean, fp?: Fingerprinter): Promise<string> {
    const cur = await this.get<PortainerStack>(`/api/stacks/${id}`);
    if (cur.Name !== expectedName) {
      throw new Error(`Refusing to update stack #${id}: it is named '${cur.Name}', not '${expectedName}'. Re-check the id with list_stacks.`);
    }
    const file = await this.stackFile(id);
    const env = cur.Env ?? [];
    const drift = await this.stackEnvDrift(cur, file).catch((err: unknown) => {
      if (allowEnvDrift) return null;
      throw new Error(
        `Could not compare stack '${cur.Name}' (#${id}) with its running containers (${err instanceof Error ? err.message : String(err)}), ` +
          `so nothing was redeployed. Pass allowEnvDrift: true to redeploy without the check.`,
      );
    });
    const report = drift?.length ? await describeDrift(drift, fp) : "";
    if (report && !allowEnvDrift) {
      throw new Error(
        `Refusing to redeploy stack '${cur.Name}' (#${id}): its stack file would change the environment of the running container(s):\n${report}\n` +
          `A "changed" or "container-only" variable was most likely edited on the container directly and never saved to the stack file, ` +
          `so this redeploy would silently undo it. Fix the stack file first (get_stack_file, then update_stack), or pass allowEnvDrift: true ` +
          `to redeploy anyway and take the stack file's values. Nothing was changed.`,
      );
    }
    const res = await this.fetch(`/api/stacks/${id}?endpointId=${cur.EndpointId}`, {
      method: "PUT",
      body: { stackFileContent: file, env, prune: false, pullImage: true },
    });
    if (!res.ok) {
      throw new Error(`HTTP ${res.status} updating images of stack #${id}: ${redactSecrets(res.text.slice(0, 400), env.map((e) => e.value))}`);
    }
    const images = composeImages(file);
    const changed = report ? ` Environment drift was allowed, so these now follow the stack file:\n${report}` : "";
    const unchecked = drift === null ? " The environment comparison could not run and was skipped (allowEnvDrift)." : "";
    return (
      `Stack '${cur.Name}' (#${id}) redeployed with freshly pulled images${images.length ? ` (${images.join(", ")})` : ""}; ` +
      `compose file and stack environment unchanged.${changed}${unchecked}`
    );
  }

  /** Every env difference between a stack's running containers and what its
   *  stack file would give them, as `[container, drift]` pairs. */
  private async stackEnvDrift(stack: PortainerStack, file: string): Promise<[string, EnvDrift][]> {
    const declared = composeServiceEnv(file, stack.Env ?? []);
    const eid = stack.EndpointId;
    const filters = encodeURIComponent(JSON.stringify({ label: [`com.docker.compose.project=${stack.Name}`] }));
    const containers = await this.get<DockerContainer[]>(`/api/endpoints/${eid}/docker/containers/json?all=1&filters=${filters}`);
    const out: [string, EnvDrift][] = [];
    for (const c of containers) {
      const service = c.Labels?.["com.docker.compose.service"];
      const want = service ? declared.get(service) : undefined;
      if (!want || !c.Id) continue;
      const inspect = await this.get<DockerInspect>(`/api/endpoints/${eid}/docker/containers/${encodeURIComponent(c.Id)}/json`);
      const image = inspect.Image
        ? await this.get<{ Config?: { Env?: string[] } }>(`/api/endpoints/${eid}/docker/images/${encodeURIComponent(inspect.Image)}/json`)
        : undefined;
      const name = (inspect.Name ?? c.Names?.[0] ?? service ?? c.Id).replace(/^\//, "");
      for (const d of envDrift(want, parseDockerEnv(inspect.Config?.Env), parseDockerEnv(image?.Config?.Env))) out.push([name, d]);
    }
    return out;
  }

  /** Delete a stack and its containers. Guarded: only stacks carrying the
   *  skeleton-key managed marker in their compose file can be removed. */
  async removeStack(id: number, expectedName: string): Promise<string> {
    const cur = await this.get<PortainerStack>(`/api/stacks/${id}`);
    if (cur.Name !== expectedName) {
      throw new Error(`Refusing to delete stack #${id}: it is named '${cur.Name}', not '${expectedName}'. Re-check the id with list_stacks.`);
    }
    const file = await this.stackFile(id);
    if (!hasManagedMarker(file)) {
      throw new Error(
        `Refusing to delete stack '${cur.Name}' (#${id}): its compose file has no '${MANAGED_MARKER}' marker, so it was not created by Skeleton Key. ` +
          `Delete it from the Portainer UI if that is really intended.`,
      );
    }
    const res = await this.fetch(`/api/stacks/${id}?endpointId=${cur.EndpointId}`, { method: "DELETE" });
    if (!res.ok) throw new Error(`HTTP ${res.status} deleting stack #${id}: ${res.text.slice(0, 300)}`);
    return `Stack '${cur.Name}' (#${id}) deleted from endpoint ${cur.EndpointId}, along with its containers. Volumes and bind mounts were NOT deleted.`;
  }

  /** Curated container inspect — env values redacted (stack secrets land there).
   *  With a fingerprinter, each env entry also carries `(len=.. fp=..)` so a
   *  running container's secrets can be compared with the vault's. */
  async containerInspect(ref: string, fp?: Fingerprinter): Promise<string> {
    const eid = await this.endpointId();
    const raw = await this.get<unknown>(`/api/endpoints/${eid}/docker/containers/${encodeURIComponent(ref)}/json`);
    const curated = curateInspect(raw);
    if (fp) curated.env = await annotateEnv(parseDockerEnv((raw as DockerInspect | undefined)?.Config?.Env), fp);
    return JSON.stringify(curated, null, 2);
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
  Id?: string;
  Names?: string[];
  Labels?: Record<string, string>;
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
 * One line per stack, plus its environment variable NAMES with values redacted.
 * Portainer's stack JSON carries `Env` values in the clear (vault-injected
 * secretEnv among them), so nothing here may echo a value. Exported for testing.
 */
export function summarizeStacks(ss: PortainerStack[], envLines?: Map<number, string[]>): string {
  if (!ss.length) return "No stacks.";
  return ss
    .map((s) => {
      const head = `- #${s.Id} ${s.Name} (endpoint ${s.EndpointId}, ${s.Status === 1 ? "active" : "inactive"})`;
      // Pre-annotated (fingerprinted, still redacted) lines if the caller built
      // them; otherwise the plain redacted form. Never a value either way.
      const env = envLines?.get(s.Id) ?? redactEnv(s.Env).map((e) => `${e.name}=${e.value}`);
      return env.length ? `${head}\n    env: ${env.join(", ")}` : head;
    })
    .join("\n");
}

/** Shape of the fields we read out of a Docker container inspect. */
interface DockerInspect {
  Id?: string;
  Name?: string;
  Image?: string;
  RestartCount?: number;
  State?: {
    Status?: string;
    Running?: boolean;
    ExitCode?: number;
    StartedAt?: string;
    Health?: { Status?: string; FailingStreak?: number; Log?: { ExitCode?: number; Output?: string; End?: string }[] };
  };
  Config?: { Image?: string; Env?: string[]; Labels?: Record<string, string> };
  HostConfig?: { NetworkMode?: string; RestartPolicy?: { Name?: string; MaximumRetryCount?: number } };
  Mounts?: { Type?: string; Source?: string; Destination?: string; RW?: boolean }[];
  NetworkSettings?: { Ports?: Record<string, { HostIp?: string; HostPort?: string }[] | null> };
}

/**
 * Curate a container inspect down to what is useful for debugging a migrated
 * app, with every environment variable VALUE redacted — a container's env is
 * exactly where stack secrets end up, so only names leave this function.
 * Exported for testing.
 */
export function curateInspect(raw: unknown): Record<string, unknown> {
  const d = (raw ?? {}) as DockerInspect;
  const state = d.State ?? {};
  const health = state.Health;
  return {
    name: (d.Name ?? "").replace(/^\//, "") || undefined,
    image: d.Config?.Image,
    imageDigest: d.Image,
    state: {
      status: state.Status,
      running: state.Running,
      exitCode: state.ExitCode,
      startedAt: state.StartedAt,
      restartCount: d.RestartCount,
      ...(health
        ? {
            health: health.Status,
            healthFailingStreak: health.FailingStreak,
            // Last few probe outputs — trimmed; a health probe prints app output,
            // not env, so this is safe to surface.
            healthLog: (health.Log ?? []).slice(-3).map((l) => ({ exitCode: l.ExitCode, end: l.End, output: (l.Output ?? "").trim().slice(0, 400) })),
          }
        : {}),
    },
    restartPolicy: d.HostConfig?.RestartPolicy?.Name
      ? { name: d.HostConfig.RestartPolicy.Name, maximumRetryCount: d.HostConfig.RestartPolicy.MaximumRetryCount }
      : undefined,
    networkMode: d.HostConfig?.NetworkMode,
    ports: Object.entries(d.NetworkSettings?.Ports ?? {}).map(([container, binds]) => ({
      container,
      published: (binds ?? []).map((b) => `${b.HostIp ?? ""}:${b.HostPort ?? ""}`.replace(/^:/, "")),
    })),
    mounts: (d.Mounts ?? []).map((m) => ({ type: m.Type, source: m.Source, destination: m.Destination, rw: m.RW })),
    labels: d.Config?.Labels ?? {},
    // NAMES ONLY. Never the values.
    env: (d.Config?.Env ?? []).map((kv) => `${kv.split("=", 1)[0]}=<redacted>`),
  };
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

function run(fn: (p: Portainer, input: any, ctx: ToolContext) => Promise<string>) {
  return async (input: unknown, ctx: ToolContext): Promise<ToolResult> => {
    try {
      return ok(await withClient(ctx, (p) => fn(p, input, ctx)));
    } catch (e) {
      return { text: `Portainer error: ${e instanceof Error ? e.message : String(e)}`, isError: true };
    }
  };
}

/** Shared zod pieces for the stack env inputs. */
const envEntrySchema = z.object({
  name: z.string().regex(/^[A-Za-z_][A-Za-z0-9_]*$/, "Environment variable name."),
  value: z.string(),
});
const secretEnvSchema = z.object({
  name: z.string().regex(/^[A-Za-z_][A-Za-z0-9_]*$/, "Environment variable name."),
  credentialRef: z.string().min(1).describe("Name of the Vaultwarden item holding the secret."),
  field: z
    .string()
    .optional()
    .describe("Which part of the item: username|password|secret|notes, or a custom field name. Default: password, else secret, else the 'token' field."),
});
const SECRET_ENV_DOC =
  "Secrets pulled from the vault at call time: [{name, credentialRef, field?}]. The value never appears in chat, results, or logs. " +
  "Wins over `env` on a name collision. Never paste a secret into `env` — store it in the vault and reference it here.";

/** Confirm-text fragment naming the variables (never values) an input will set. */
function envNamesFor(i: { env?: EnvEntry[]; secretEnv?: SecretEnvRef[] }): string {
  const plain = (i.env ?? []).map((e) => e.name);
  const secret = (i.secretEnv ?? []).map((e) => `${e.name}←vault:${e.credentialRef}${e.field ? `.${e.field}` : ""}`);
  const all = [...plain, ...secret];
  return all.length ? `; environment: ${all.join(", ")}` : "";
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
      description: `List Portainer stacks on ${target.name} (id, name, endpoint, environment variable names — values are redacted, each tagged with a keyed length+fingerprint you can compare against the vault's).`,
      tier: "read",
      inputSchema: z.object({}),
      run: run((p, _i, ctx) => p.listStacks(ctx.fingerprint)),
    },
    {
      name: "container_inspect",
      description:
        `Inspect a container on ${target.name}: image + digest, state and health, restart policy, mounts, network mode, published ports, ` +
        `labels, and environment variable NAMES (values are redacted; each carries a keyed length+fingerprint comparable with credential_request_status). Use this to debug a container that won't start or keeps restarting.`,
      tier: "read",
      inputSchema: z.object({ container: z.string().describe("Container name or id.") }),
      run: run((p, i, ctx) => p.containerInspect(i.container, ctx.fingerprint)),
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
      name: "create_stack",
      description:
        `Create a new Portainer stack on ${target.name} from a compose file (standalone/Docker Compose). ` +
        `Use this to stand up an app being migrated onto this host — the compose file should reference an already-published image (e.g. GHCR). ` +
        `Non-secret settings go in \`env\`; passwords/tokens go in \`secretEnv\` and are read from the vault, never typed in chat. ` +
        `The stack is marked skeleton-key managed so remove_stack can later delete it.`,
      tier: "execute",
      inputSchema: z.object({
        name: z.string().regex(STACK_NAME_RE, "Lowercase letters, digits, '.', '-' or '_'; must start alphanumeric (max 63)."),
        composeContent: z.string().min(1).describe("The FULL compose file content."),
        env: z.array(envEntrySchema).optional().describe("Non-secret stack environment variables. Never put a secret here."),
        secretEnv: z.array(secretEnvSchema).optional().describe(SECRET_ENV_DOC),
      }),
      confirm: (input, t) => {
        const i = input as { name: string; composeContent: string; env?: EnvEntry[]; secretEnv?: SecretEnvRef[] };
        const images = composeImages(i.composeContent);
        return (
          `Create Portainer stack '${i.name}' on ${t.name} from a compose file` +
          (images.length ? ` (images: ${images.join(", ")})` : "") +
          envNamesFor(i)
        );
      },
      run: run(async (p, i, ctx) => {
        const secret = await resolveSecretEnv(ctx, i.secretEnv);
        const result = await p.createStack(i.name, i.composeContent, mergeEnv(i.env, secret));
        return result + (await secretFingerprintBlock(secret, ctx.fingerprint));
      }),
    },
    {
      name: "update_stack",
      description:
        `Redeploy a Portainer stack on ${target.name} with a new compose file (e.g. after adding an environment variable). ` +
        `Get the current file with get_stack_file, edit it, then pass the full new content here. Recreates the stack's containers. ` +
        `The stack's existing environment is carried forward; \`env\` adds/overrides non-secret vars and \`secretEnv\` injects vault values.`,
      tier: "execute",
      inputSchema: z.object({
        stackId: z.number().int().positive(),
        stackFileContent: z.string().describe("The FULL new compose file content (not a diff)."),
        pullImage: z.boolean().default(false).describe("Re-pull images on redeploy."),
        env: z.array(envEntrySchema).optional().describe("Non-secret env vars to add/override. Existing vars are kept. Never put a secret here."),
        secretEnv: z.array(secretEnvSchema).optional().describe(SECRET_ENV_DOC),
      }),
      confirm: (input, t) => {
        const i = input as { stackId: number; env?: EnvEntry[]; secretEnv?: SecretEnvRef[] };
        return `Redeploy Portainer stack #${i.stackId} on ${t.name} with an edited compose file${envNamesFor(i)}`;
      },
      run: run(async (p, i, ctx) => {
        const secret = await resolveSecretEnv(ctx, i.secretEnv);
        const result = await p.updateStack(i.stackId, i.stackFileContent, i.pullImage, i.env ?? [], secret);
        return result + (await secretFingerprintBlock(secret, ctx.fingerprint));
      }),
    },
    {
      name: "update_stack_images",
      description:
        `Update a Portainer stack on ${target.name} to the newest images for the tags it already uses: re-pull and redeploy, ` +
        `with its compose file and environment left exactly as they are (use update_stack to change those). Works on any stack, ` +
        `including one Skeleton Key did not create. It first compares each running container's environment with what the stack ` +
        `file would set, and refuses (changing nothing) when a redeploy would alter or drop a variable — e.g. one edited on the ` +
        `container but never saved to the stack file; fix the stack file, or pass allowEnvDrift: true to take its values anyway. ` +
        `If the stack runs Skeleton Key itself, this call drops while the server restarts — do not retry it; wait ~30 s and call ` +
        `get_started to confirm the new version.`,
      tier: "execute",
      inputSchema: z.object({
        stackId: z.number().int().positive(),
        stackName: z.string().min(1).describe("The stack's name, as shown by list_stacks. Verified against the id before redeploying."),
        allowEnvDrift: z
          .boolean()
          .optional()
          .describe("Redeploy even when the stack file would change a running container's environment. Default false: refuse and report the drift."),
      }),
      confirm: (input, t) => {
        const i = input as { stackId: number; stackName: string; allowEnvDrift?: boolean };
        return (
          `Pull the newest images and redeploy Portainer stack '${i.stackName}' (#${i.stackId}) on ${t.name} — ` +
          `recreates its containers; compose file and stack environment unchanged` +
          (i.allowEnvDrift ? `; ALLOWING environment drift: running containers take the stack file's values` : "")
        );
      },
      run: run((p, i, ctx) => p.updateStackImages(i.stackId, i.stackName, i.allowEnvDrift ?? false, ctx.fingerprint)),
    },
    {
      name: "remove_stack",
      description:
        `Delete a Portainer stack on ${target.name} and its containers. Only works on stacks Skeleton Key created ` +
        `(their compose file carries the '${MANAGED_MARKER}' marker) — pre-existing, human-authored stacks are refused. ` +
        `Volumes and bind mounts are left in place.`,
      tier: "execute",
      inputSchema: z.object({
        stackId: z.number().int().positive(),
        stackName: z.string().min(1).describe("The stack's name, as shown by list_stacks. Verified against the id before deleting."),
      }),
      confirm: (input, t) => {
        const i = input as { stackId: number; stackName: string };
        const eid = options(t).endpointId;
        return (
          `Delete Portainer stack '${i.stackName}' (#${i.stackId}) on ${t.name}${eid ? ` (endpoint ${eid})` : ""} — ` +
          `removes the stack and its containers. Volumes and bind mounts are NOT deleted`
        );
      },
      run: run((p, i) => p.removeStack(i.stackId, i.stackName)),
    },
    {
      name: "exec_container",
      description:
        `Run a command inside a container on ${target.name} (Docker exec). ` +
        `Command is split into exact argv tokens on whitespace — no shell, no quoting (many images have no /bin/sh). ` +
        `E.g. trigger a scoped Watchtower update: container 'watchtower', command '/watchtower --run-once skeleton-key'. ` +
        `Destructive commands are refused by policy.`,
      tier: "execute",
      inputSchema: z.object({
        container: z.string().describe("Container name or id."),
        command: z.string().describe("Command with arguments, split on whitespace (no shell)."),
      }),
      confirm: (input, t) => {
        const i = input as { container: string; command: string };
        return `Exec '${i.command}' inside container '${i.container}' on ${t.name}`;
      },
      run: (input, ctx) => {
        const i = input as { container: string; command: string };
        // Same guardrails as SSH: an approved exec is still refused if it matches
        // a destructive pattern. A container shell is a shell.
        const verdict = checkCommand(i.command, policyFor(ctx.target));
        if (!verdict.allowed) return Promise.resolve({ text: `Refused: ${verdict.reason}`, isError: true });
        return run((p) => p.exec(i.container, toArgv(i.command)))(input, ctx);
      },
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
