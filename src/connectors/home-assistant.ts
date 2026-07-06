import { z } from "zod";
import type { Connector, ConnectorTool, Credential, Target, ToolContext, ToolResult } from "./types.js";
import { deriveBaseUrl, tlsFetch } from "./net.js";

/**
 * Home Assistant connector — read state/logbook and make audited service calls
 * over the HA REST API with a long-lived access token.
 *
 * Auth: a HA **long-lived access token** (Profile → Security → Long-lived access
 * tokens) sent as `Authorization: Bearer <token>`, fetched from the vault at call
 * time. HA tokens carry the creating user's rights and have no per-token scope,
 * so the Owner token already suffices for services/backups.
 *
 * Why a bespoke connector instead of the generic `http` one: the generic
 * `http.request` tool declares its `body` as an untyped `z.unknown()`, whose JSON
 * schema is `{}` (no `type`). An MCP client serializes an untyped structured value
 * as a **JSON string**, so the connector's `JSON.stringify(body)` double-encodes
 * it — HA then receives a JSON *string* where it expects an object and rejects the
 * request (a bare aiohttp `400: Bad Request` for a service call, or
 * `"Template data should be a JSON object."` for `/api/template`). Diagnosed live
 * 2026-07-06: GET worked, every POST-with-body 400'd, an unauthenticated `curl`
 * with a correctly single-encoded body reached HA's auth check (401) — proving HA
 * was fine and the body was double-encoded on our side. This connector fixes that
 * at the root: service data is a **typed object** in the schema (so the client
 * sends a real object) AND is normalized + `JSON.stringify`'d exactly once before
 * the POST. See memory `ha-http-post-400-bug`.
 */

const optionsSchema = z
  .object({
    /** Base URL; if omitted, host/port form the URL (443/8443 ⇒ https, else http;
     *  HA's default 8123 is plain http). */
    baseUrl: z.string().url().optional(),
    /** Skip TLS verification for THIS target only — for a self-signed cert when HA
     *  is fronted by https on the LAN. Per-request via an undici dispatcher, never
     *  process-global. Default off (the common case is plain http on :8123). */
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

/** The long-lived token: an explicit `token`/`api_key` field, else the item's
 *  secret, else its password. Never the freeform notes (see Credential.secret). */
export function tokenFrom(cred: Credential): string | undefined {
  return cred.fields["token"] ?? cred.fields["api_key"] ?? cred.secret ?? cred.password ?? undefined;
}

/**
 * Coerce a service-data value into a plain JSON object, or throw. Accepts an
 * object directly and — defensively — a JSON string (in case a client still
 * transmits the typed object as a string), so a service call can never silently
 * double-encode. Rejects arrays, scalars, and unparseable strings loudly rather
 * than shipping HA a body it will reject with an opaque 400. Exported for testing.
 */
export function normalizeServiceData(data: unknown): Record<string, unknown> {
  if (data === undefined || data === null) return {};
  let value = data;
  if (typeof value === "string") {
    const trimmed = value.trim();
    if (trimmed === "") return {};
    try {
      value = JSON.parse(trimmed);
    } catch {
      throw new Error("service data must be a JSON object; got a string that isn't valid JSON.");
    }
  }
  if (typeof value !== "object" || value === null || Array.isArray(value)) {
    throw new Error(`service data must be a JSON object, not ${Array.isArray(value) ? "an array" : typeof value}.`);
  }
  return value as Record<string, unknown>;
}

/** Field-name fragments that mark a service-data value as sensitive (a backup
 *  password, an access token, a lock PIN/code, …). Redacted from the human
 *  approval prompt + audit detail so the confirmation names the payload without
 *  echoing a secret into the audit trail (audit args are hashed; the `detail` is
 *  not). `pin`/`code`/`otp` are matched on separators (`_`/`-`/start/end) rather
 *  than `\b` — `_` is a regex word char, so `\bcode\b` would MISS `alarm_code`,
 *  `user_pin`, `access_code`, `pin_code`. Over-redacting a benign `postal_code`
 *  is an accepted, safe trade for never leaking a lock/alarm secret. */
const SECRET_DATA_KEY = /pass(word|wd|phrase|code)?|token|secret|api[_-]?key|credential|private[_-]?key|(^|[_-])(pin|code|otp)([_-]|$)/i;

/** Deep-copy `value`, masking any property whose KEY looks secret — at every
 *  nesting level, through arrays too. Service data can nest (e.g. notify `data`,
 *  hassio `input`), so a shallow pass would leak `{"data":{"token":"…"}}`.
 *  Recursion is depth-bounded so a pathological payload can't blow the stack. */
function redactDeep(value: unknown, depth = 0): unknown {
  if (depth > 8) return "…";
  if (Array.isArray(value)) return value.map((v) => redactDeep(v, depth + 1));
  if (value && typeof value === "object") {
    const out: Record<string, unknown> = {};
    for (const [k, v] of Object.entries(value as Record<string, unknown>)) {
      out[k] = SECRET_DATA_KEY.test(k) ? "[redacted]" : redactDeep(v, depth + 1);
    }
    return out;
  }
  return value;
}

/** Per-value and total budgets for the approval/audit rendering. Bounded so a
 *  giant payload can't bloat the audit detail — but bounded *without hiding
 *  fields*: every top-level key is named (see renderServiceData). */
const CONFIRM_PER_VALUE = 160;
const CONFIRM_TOTAL = 700;

/**
 * Deterministic, secret-redacted rendering of service data for the approval
 * prompt + audit detail, so a human approves the ACTUAL payload — not just the
 * service name (a generic execute tool could otherwise smuggle destructive fields
 * behind a vague "Call service …"). Guarantees: redaction is recursive (nested
 * keys + arrays); EVERY top-level key is accounted for — an individual oversized
 * value is truncated with a visible `…`, and if the whole thing exceeds budget
 * the remaining keys are listed by name (`+N more: …`) rather than silently
 * dropped. Non-throwing: an object is rendered; a JSON string is parsed first;
 * anything else is shown truncated. Exported for testing. Key-based like the
 * UniFi connector's redactSecrets — a secret in a non-secret-NAMED value is out
 * of scope (impractical to detect generally). */
export function renderServiceData(data: unknown): string {
  let obj: Record<string, unknown> | undefined;
  if (data && typeof data === "object" && !Array.isArray(data)) {
    obj = data as Record<string, unknown>;
  } else if (typeof data === "string" && data.trim()) {
    try {
      const parsed = JSON.parse(data);
      if (parsed && typeof parsed === "object" && !Array.isArray(parsed)) obj = parsed as Record<string, unknown>;
      else return ""; // parsed to a non-object; the callService path renders nothing meaningful
    } catch {
      return data.length > CONFIRM_PER_VALUE ? `${data.slice(0, CONFIRM_PER_VALUE - 1)}…` : data;
    }
  }
  if (!obj) return "";
  const redacted = redactDeep(obj) as Record<string, unknown>;
  const keys = Object.keys(redacted);
  if (!keys.length) return "";
  const parts: string[] = [];
  let used = 1; // opening brace
  let i = 0;
  for (; i < keys.length; i++) {
    const k = keys[i]!;
    let vstr = JSON.stringify(redacted[k]) ?? "null";
    if (vstr.length > CONFIRM_PER_VALUE) vstr = `${vstr.slice(0, CONFIRM_PER_VALUE - 1)}…`;
    const piece = `${JSON.stringify(k)}:${vstr}`;
    // Always render at least the first key; stop before blowing the budget, but
    // NAME whatever remains so no field is silently hidden from the approver.
    if (parts.length > 0 && used + piece.length + 1 > CONFIRM_TOTAL) break;
    parts.push(piece);
    used += piece.length + 1;
  }
  const remainder = i < keys.length ? `${parts.length ? "," : ""}+${keys.length - i} more: ${keys.slice(i).join(", ")}` : "";
  return `{${parts.join(",")}${remainder}}`;
}

/** Canonicalize a request path for security matching, WITHOUT the URL parser —
 *  `new URL("//api/webhook", base)` would treat `api` as the authority (host) and
 *  drop it, so `//api/webhook/x` and `/%2fapi/webhook/x` would evade the guard.
 *  Instead: (1) percent-decode to a fixed point (bounded — a malformed escape
 *  stops the loop and leaves a `%` the caller fails closed on) so encoded slashes,
 *  dots, and letters become literal; (2) drop any query/fragment; (3) normalize as
 *  PURE PATH DATA — split on `/`, drop empty segments (collapsing `//`, leading,
 *  and trailing slashes) and `.`, and pop on `..`. So `//api/webhook/x`,
 *  `/api//webhook/x`, `/%2fapi/webhook/x`, `/api/%77ebhook/x`,
 *  `/api/foo/%252e%252e/webhook/x`, and `/api/webhook%2Fx` all reduce to the same
 *  `api/webhook/x` form. */
function canonicalizePath(path: string): string {
  let p = path;
  for (let i = 0; i < 8; i++) {
    let decoded: string;
    try {
      decoded = decodeURIComponent(p);
    } catch {
      break; // malformed %-escape; leave the residual `%` for the fail-closed check
    }
    if (decoded === p) break; // fully decoded
    p = decoded;
  }
  p = p.split(/[?#]/)[0] ?? p; // routing ignores query/fragment
  const out: string[] = [];
  for (const seg of p.split("/")) {
    if (seg === "" || seg === ".") continue; // collapse //, leading/trailing /, and .
    if (seg === "..") {
      out.pop();
      continue;
    }
    out.push(seg);
  }
  return out.join("/");
}

/** True if a path is unsafe for the read-only ha_get: it targets an HA webhook
 *  (/api/webhook/<id>) — the one documented GET-with-side-effects surface (can
 *  fire automations) — OR it can't be fully canonicalized. Canonicalizes first so
 *  percent-encoded / dot-segment variants can't slip past, then FAILS CLOSED: a
 *  path that still holds a percent-escape after the decode cap (a >6-layer
 *  encoding like `%2525…77ebhook`, or a malformed escape) is treated as unsafe,
 *  because another decode by HA/a proxy could still form `webhook`, `/`, or a dot
 *  segment. Exported for testing. */
export function isWebhookPath(path: string): boolean {
  const canon = canonicalizePath(path);
  if (canon.includes("%")) return true; // residual encoding we couldn't resolve — deny
  return /(^|\/)api\/webhook(\/|$)/i.test(canon);
}

/** Zod for a service-data dict: a real object in the JSON schema (so the client
 *  sends an object, not a string — the root cause of the old double-encoded 400),
 *  but tolerant of a stringified object at runtime via preprocess. A test asserts
 *  the emitted JSON schema really is `type: object`. */
export const serviceData = z
  .preprocess((v) => {
    if (typeof v !== "string") return v;
    const t = v.trim();
    if (t === "") return undefined;
    try {
      return JSON.parse(t);
    } catch {
      return v; // leave it to fail validation with a clear message
    }
  }, z.record(z.string(), z.unknown()))
  .optional()
  .describe('Service data as a JSON object, e.g. {"entity_id":"light.kitchen","brightness":128}. Omit for services that take none.');

interface HAState {
  entity_id: string;
  state: string;
  attributes?: { friendly_name?: string; [k: string]: unknown };
  last_changed?: string;
}
interface LogbookEntry {
  when?: string;
  name?: string;
  message?: string;
  entity_id?: string;
  state?: string;
  domain?: string;
}

const STATES_CAP = 300;
const LOGBOOK_CAP = 200;

/** One line per entity: `entity_id = state (friendly_name)`. Optional substring
 *  filter on the entity id (there are often hundreds of entities). */
export function summarizeStates(states: HAState[], filter?: string): string {
  const needle = filter?.toLowerCase();
  const matched = needle ? states.filter((s) => s.entity_id.toLowerCase().includes(needle)) : states;
  if (!matched.length) {
    return needle ? `No entities match '${filter}' (of ${states.length} total).` : "No entities.";
  }
  const shown = matched.slice(0, STATES_CAP);
  const lines = shown.map((s) => {
    const fn = s.attributes?.friendly_name;
    return `- ${s.entity_id} = ${s.state}${fn ? `  (${fn})` : ""}`;
  });
  const header = needle
    ? `${matched.length} ent/ ${states.length} total matching '${filter}':`
    : `${states.length} entities:`;
  const more = matched.length > shown.length ? `\n… ${matched.length - shown.length} more (narrow with 'filter').` : "";
  return `${header}\n${lines.join("\n")}${more}`;
}

export function summarizeLogbook(entries: LogbookEntry[]): string {
  if (!entries.length) return "No logbook entries in range.";
  const shown = entries.slice(-LOGBOOK_CAP);
  const lines = shown.map((e) => {
    const who = e.entity_id || e.name || e.domain || "?";
    const what = e.message ?? e.state ?? "";
    return `- ${e.when ?? "?"}  ${who}${what ? `: ${what}` : ""}`;
  });
  const more = entries.length > shown.length ? `(showing last ${shown.length} of ${entries.length})\n` : "";
  return `${more}${lines.join("\n")}`;
}

/** Request bounds (see HomeAssistant.request). The timeout covers connect + body
 *  read; the byte caps stop a slow/huge/streaming endpoint from buffering an
 *  unbounded response. The default is generous enough for a large /api/states
 *  dump; ha_get uses a tight cap since it only surfaces the first 20 KB anyway. */
const REQUEST_TIMEOUT_MS = 20_000;
const DEFAULT_MAX_BYTES = 6_000_000;
const RAW_GET_MAX_BYTES = 262_144;

/** Read a fetch Response body up to `maxBytes`, stopping early (and reporting
 *  `truncated`) rather than buffering an unbounded/streaming response — the cap
 *  is enforced DURING the read, not after. Falls back to `res.text()` when the
 *  body isn't a readable stream (e.g. a test stub). */
async function readBounded(
  res: { body?: ReadableStream<Uint8Array> | null; text(): Promise<string> },
  maxBytes: number,
): Promise<{ text: string; truncated: boolean }> {
  const body = res.body;
  if (!body || typeof body.getReader !== "function") {
    const text = await res.text();
    return text.length > maxBytes ? { text: text.slice(0, maxBytes), truncated: true } : { text, truncated: false };
  }
  const reader = body.getReader();
  const chunks: Buffer[] = [];
  let total = 0;
  let truncated = false;
  try {
    for (;;) {
      const { done, value } = await reader.read();
      if (done) break;
      if (value && value.byteLength) {
        chunks.push(Buffer.from(value.buffer, value.byteOffset, value.byteLength));
        total += value.byteLength;
        if (total >= maxBytes) {
          truncated = true;
          break;
        }
      }
    }
  } finally {
    try {
      await reader.cancel();
    } catch {
      /* already closed/aborted */
    }
  }
  return { text: Buffer.concat(chunks).toString("utf8"), truncated };
}

/** HA REST client bound to one target. Holds no long-lived state; the token is
 *  read from the resolved credential per construction. */
class HomeAssistant {
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

  /** One REST call. `body`, when present, is JSON-encoded EXACTLY ONCE with
   *  `Content-Type: application/json` — the whole point of this connector. The
   *  request is bounded two ways so an arbitrary path (ha_get) or a slow/huge
   *  endpoint can't wedge or OOM the MCP call: an AbortController timeout covers
   *  connect + body read, and the body is read through a streaming byte cap
   *  (`maxBytes`) that stops early rather than buffering an unbounded response. */
  private async request(
    method: string,
    path: string,
    opts: { body?: unknown; maxBytes?: number } = {},
  ): Promise<{ ok: boolean; status: number; statusText: string; json?: unknown; text: string; truncated: boolean }> {
    const token = tokenFrom(this.cred);
    if (!token) {
      throw new Error("Home Assistant target needs a long-lived token (store it as the item's secret/password, or a 'token' field).");
    }
    const headers: Record<string, string> = { Accept: "application/json", Authorization: `Bearer ${token}` };
    if (opts.body !== undefined) headers["Content-Type"] = "application/json";
    const url = `${this.base}${path.startsWith("/") ? path : `/${path}`}`;
    const controller = new AbortController();
    const timer = setTimeout(() => controller.abort(), REQUEST_TIMEOUT_MS);
    try {
      const res = await tlsFetch(
        url,
        { method, headers, body: opts.body !== undefined ? JSON.stringify(opts.body) : undefined, signal: controller.signal },
        this.insecure,
      );
      const { text, truncated } = await readBounded(res, opts.maxBytes ?? DEFAULT_MAX_BYTES);
      let json: unknown;
      if (!truncated) {
        try {
          json = text ? JSON.parse(text) : undefined;
        } catch {
          /* non-JSON body (e.g. an error page) */
        }
      }
      return { ok: res.ok, status: res.status, statusText: res.statusText, json, text, truncated };
    } catch (e) {
      if (e instanceof Error && e.name === "AbortError") {
        // A GET timeout is a clean no-op. A non-GET timeout is AMBIGUOUS: HA may
        // have already accepted and applied the request before the response
        // completed, so a blind retry could repeat a non-idempotent action
        // (backup, restart, update.install, unlock). Say so explicitly.
        const idempotent = method === "GET" || method === "HEAD";
        const suffix = idempotent
          ? ""
          : " — OUTCOME UNKNOWN: Home Assistant may have already applied this request. Verify state before retrying (the action may not be idempotent).";
        throw new Error(`Home Assistant request timed out after ${REQUEST_TIMEOUT_MS}ms (${method} ${path}).${suffix}`);
      }
      throw e;
    } finally {
      clearTimeout(timer);
    }
  }

  /** Raw GET passthrough for endpoints without a dedicated tool (e.g.
   *  /api/config, /api/history/period). Read-tier, so it must stay side-effect
   *  free: HA webhooks (/api/webhook/<id>) can be configured to fire automations
   *  on GET, which would let this read tool change state — those are refused.
   *  Actions go through ha_call_service (execute-tier, approval-gated). */
  async getRaw(path: string): Promise<ToolResult> {
    if (isWebhookPath(path)) {
      return {
        text: "Refused: this path is an /api/webhook endpoint (can fire automations) or could not be safely canonicalized, so it's not allowed from the read-only ha_get. Use ha_call_service (execute) for actions.",
        isError: true,
      };
    }
    const res = await this.request("GET", path, { maxBytes: RAW_GET_MAX_BYTES });
    const note = res.truncated ? "\n… (response truncated)" : "";
    return { text: `HTTP ${res.status} ${res.statusText}\n${res.text.slice(0, 20_000)}${note}`, isError: !res.ok };
  }

  async states(entity?: string, filter?: string): Promise<ToolResult> {
    if (entity) {
      const res = await this.request("GET", `/api/states/${encodeURIComponent(entity)}`);
      if (!res.ok) return { text: `HTTP ${res.status} ${res.statusText}\n${res.text.slice(0, 4_000)}`, isError: true };
      if (res.truncated) {
        return { text: `HA state for '${entity}' was unexpectedly large and got truncated; inspect via ha_get.`, isError: true };
      }
      return { text: JSON.stringify(res.json ?? res.text, null, 2).slice(0, 8_000) };
    }
    const res = await this.request("GET", "/api/states");
    if (!res.ok) return { text: `HTTP ${res.status} ${res.statusText}\n${res.text.slice(0, 4_000)}`, isError: true };
    // A truncated or non-array 2xx MUST NOT summarize as "No entities" — that
    // false empty-state could drive a wrong automation decision. Fail loudly.
    if (res.truncated) {
      return { text: "HA /api/states was too large to read fully; query a single 'entity' to narrow it (a substring 'filter' still fetches the full list, so it won't help here).", isError: true };
    }
    if (!Array.isArray(res.json)) {
      return { text: `Unexpected /api/states response (not a JSON array): ${res.text.slice(0, 500)}`, isError: true };
    }
    return { text: summarizeStates(res.json as HAState[], filter) };
  }

  async logbook(entity?: string, start?: string, end?: string): Promise<ToolResult> {
    // /api/logbook/<start> narrows the period; the entity + end_time are query
    // params. (HA has no /api/error_log on this instance — 404 — so the logbook
    // is the log surface reachable over REST.)
    let path = "/api/logbook";
    if (start) path += `/${encodeURIComponent(start)}`;
    const q = new URLSearchParams();
    if (entity) q.set("entity", entity);
    if (end) q.set("end_time", end);
    const qs = q.toString();
    if (qs) path += `?${qs}`;
    const res = await this.request("GET", path);
    if (!res.ok) return { text: `HTTP ${res.status} ${res.statusText}\n${res.text.slice(0, 4_000)}`, isError: true };
    // Same false-empty-state hazard as states(): a truncated/non-array 2xx is an
    // error, not "No logbook entries".
    if (res.truncated) {
      return { text: "HA logbook response was too large to read fully; narrow it with 'entity' and/or a tighter 'start'/'end' window.", isError: true };
    }
    if (!Array.isArray(res.json)) {
      return { text: `Unexpected /api/logbook response (not a JSON array): ${res.text.slice(0, 500)}`, isError: true };
    }
    return { text: summarizeLogbook(res.json as LogbookEntry[]) };
  }

  /** Call a HA service: POST /api/services/<domain>/<service> with the service
   *  data as the JSON *object* body. This is the corrected path the generic http
   *  connector got wrong. Returns a short summary of the entities HA changed. */
  async callService(domain: string, service: string, data?: unknown): Promise<ToolResult> {
    const body = normalizeServiceData(data);
    const res = await this.request("POST", `/api/services/${encodeURIComponent(domain)}/${encodeURIComponent(service)}`, { body });
    if (!res.ok) {
      const detail = res.text.trim() || res.statusText;
      return { text: `HA service ${domain}.${service} failed: HTTP ${res.status} ${res.statusText}\n${detail.slice(0, 4_000)}`, isError: true };
    }
    // A service call returns the ARRAY of states it changed (often []). A 2xx that
    // is truncated or NOT an array (a proxy/login HTML page, response-shape drift)
    // must not be reported as a clean "OK / no change" — the write may have been
    // applied, so flag it as ambiguous rather than hiding the uncertainty behind a
    // success for a possibly non-idempotent service.
    if (res.truncated) {
      return { text: `HA service ${domain}.${service} returned HTTP ${res.status} but the response was too large to read fully — OUTCOME UNKNOWN: the call may already have been applied. Verify state before retrying.`, isError: true };
    }
    if (!Array.isArray(res.json)) {
      return { text: `HA service ${domain}.${service} returned HTTP ${res.status} with an unexpected (non-array) body — OUTCOME UNKNOWN: the call may already have been applied. Verify state before retrying. Body: ${res.text.slice(0, 500)}`, isError: true };
    }
    const changed = res.json as HAState[];
    const ids = changed.map((s) => s.entity_id).filter(Boolean);
    const summary = ids.length ? ` Changed ${ids.length}: ${ids.slice(0, 30).join(", ")}${ids.length > 30 ? " …" : ""}.` : " No state change reported.";
    return { text: `HA service ${domain}.${service} OK (HTTP ${res.status}).${summary}` };
  }

  /** Create a backup via the core `backup` integration's `create_automatic`
   *  service (the service this HAOS instance actually exposes — `backup.create`
   *  does not exist here; the supervisor `hassio.backup_full` is the alternative
   *  for a full supervisor backup, reachable via ha_call_service). */
  async backup(): Promise<ToolResult> {
    const res = await this.callService("backup", "create_automatic", {});
    if (res.isError) return res;
    return { text: `Home Assistant backup started via backup.create_automatic on ${this.target.name}. Check Settings → System → Backups for completion.` };
  }
}

async function withClient<T>(ctx: ToolContext, fn: (ha: HomeAssistant) => Promise<T>): Promise<T> {
  const cred = await ctx.getCredential();
  return fn(new HomeAssistant(ctx.target, cred));
}

/** Wrap a tool body so any thrown error becomes a clean isError result. */
function run(fn: (ha: HomeAssistant, input: any) => Promise<ToolResult>) {
  return async (input: unknown, ctx: ToolContext): Promise<ToolResult> => {
    try {
      return await withClient(ctx, (ha) => fn(ha, input));
    } catch (e) {
      return { text: `Home Assistant error: ${e instanceof Error ? e.message : String(e)}`, isError: true };
    }
  };
}

function buildTools(target: Target): ConnectorTool[] {
  return [
    {
      name: "ha_states",
      description:
        `Read Home Assistant entity states on ${target.name}. Give 'entity' (e.g. 'sun.sun' or ` +
        `'update.home_assistant_core_update') for one entity's full state+attributes, or omit it for a summary of all ` +
        `entities; 'filter' substring-matches entity ids (there are often hundreds).`,
      tier: "read",
      inputSchema: z.object({
        entity: z.string().optional().describe("A single entity_id for its full state; omit for all."),
        filter: z.string().optional().describe("Substring to match entity ids when listing all, e.g. 'update' or 'media_player'."),
      }),
      run: run((ha, i) => ha.states(i.entity, i.filter)),
    },
    {
      name: "ha_get",
      description:
        `Raw authenticated GET against the Home Assistant REST API on ${target.name} (e.g. /api/config, ` +
        `/api/history/period, /api/states/<id>). Read-only escape hatch for endpoints without a dedicated tool; ` +
        `/api/webhook paths are refused (they can fire automations — use ha_call_service for actions).`,
      tier: "read",
      inputSchema: z.object({ path: z.string().describe("API path, e.g. /api/config") }),
      run: run((ha, i) => ha.getRaw(i.path)),
    },
    {
      name: "ha_logbook",
      description:
        `Read the Home Assistant logbook on ${target.name} (state changes / automation triggers). Optional 'entity' ` +
        `to filter to one entity, and 'start'/'end' ISO timestamps to bound the period (default: recent).`,
      tier: "read",
      inputSchema: z.object({
        entity: z.string().optional().describe("Filter to a single entity_id."),
        start: z.string().optional().describe("ISO start timestamp, e.g. 2026-07-06T00:00:00+00:00."),
        end: z.string().optional().describe("ISO end timestamp."),
      }),
      run: run((ha, i) => ha.logbook(i.entity, i.start, i.end)),
    },
    {
      name: "ha_call_service",
      description:
        `Call a Home Assistant service on ${target.name}: POST /api/services/<domain>/<service> with 'data' as the ` +
        `service-data object. Examples: homeassistant.update_entity {"entity_id":"sun.sun"}; ` +
        `light.turn_on {"entity_id":"light.kitchen","brightness":128}; update.install {"entity_id":"update.home_assistant_core_update"}. ` +
        `The data is sent as a single JSON object (the fix for the generic connector's double-encoded 400).`,
      tier: "execute",
      inputSchema: z.object({
        domain: z.string().describe("Service domain, e.g. 'light', 'homeassistant', 'update'."),
        service: z.string().describe("Service name, e.g. 'turn_on', 'update_entity', 'install'."),
        data: serviceData,
      }),
      confirm: (input, t) => {
        const i = input as { domain: string; service: string; data?: unknown };
        const d = i.data && typeof i.data === "object" ? (i.data as Record<string, unknown>) : undefined;
        const ent = d?.["entity_id"];
        const on = ent ? ` on ${Array.isArray(ent) ? ent.join(", ") : String(ent)}` : "";
        // Render the FULL (secret-redacted) payload so the approval + audit detail
        // reflect exactly what will run, not just the service name.
        const rendered = renderServiceData(i.data);
        const dataClause = rendered ? ` — data: ${rendered}` : "";
        return `Call Home Assistant service ${i.domain}.${i.service}${on}${dataClause} (${t.name})`;
      },
      run: run((ha, i) => ha.callService(i.domain, i.service, i.data)),
    },
    {
      name: "ha_backup",
      description:
        `Create a Home Assistant backup on ${target.name} via the core backup integration (backup.create_automatic). ` +
        `For a full supervisor backup instead, use ha_call_service with domain 'hassio' service 'backup_full'.`,
      tier: "execute",
      inputSchema: z.object({}),
      confirm: (_input, t) => `Create a Home Assistant backup (backup.create_automatic) on ${t.name}`,
      run: run((ha) => ha.backup()),
    },
  ];
}

export const homeAssistantConnector: Connector = {
  type: "home-assistant",
  label: "Home Assistant",
  configSchema: optionsSchema,
  requiresCredential: true,
  buildTools,
};
