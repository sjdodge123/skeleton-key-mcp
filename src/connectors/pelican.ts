import { z } from "zod";
import yaml from "js-yaml";
import type { Connector, ConnectorTool, Credential, SnapshotArtifact, Target, ToolContext, ToolResult } from "./types.js";
import { deriveBaseUrl, tlsFetch } from "./net.js";
import { runSsh, looksLikeSudoPasswordFailure, sudoHint, type SshExecResult } from "./ssh-exec.js";
import { checkCommand } from "./command-policy.js";
import { resolveSecretRefs, secretFingerprintBlock, describeSecretRef, type SecretRef, type SecretValue } from "./secret-refs.js";

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
    /**
     * Name of the registered **ssh** target for the machine the panel is
     * installed on. Required by `panel_version` and `panel_upgrade`: Pelican
     * exposes no version or upgrade endpoint on ANY of its API surfaces
     * (application, client, web, remote) — it reads its own version from
     * `config/app.php` and checks GitHub in the browser — so those two are
     * necessarily host-level work rather than API calls.
     */
    sshTarget: z.string().optional(),
    /** Where the panel is installed on that host. Must be an absolute path with
     *  no shell metacharacters — it is interpolated into fixed commands. */
    panelPath: z.string().default("/var/www/pelican"),
    /** Unix user that owns the panel files; artisan/composer run as this user so
     *  the upgrade cannot leave root-owned files the webserver can't write. */
    panelUser: z.string().default("www-data"),
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

// --- Allocation port parsing -------------------------------------------------

/** Pelican's own bounds, from AssignmentService (PORT_FLOOR / PORT_CEIL). */
export const PORT_FLOOR = 1024;
export const PORT_CEIL = 65535;

/**
 * Skeleton Key's cap on ONE create_allocations call. The panel's own limit is
 * 1000 ports *per range* and it will happily expand a CIDR across that range, so
 * a slip like ports '1024-65535' would insert tens of thousands of rows in a
 * single transaction. Nothing a game server needs comes close to this, and the
 * error tells you to split the call, so the cap costs nothing and removes the
 * only way this tool could make a mess that is tedious to undo.
 */
export const MAX_PORTS_PER_CALL = 256;

/** Pelican's range syntax, mirrored exactly: BOTH endpoints must be 4-5 digits,
 *  which is why '999-2000' is not a valid range to the panel. */
const PORT_RANGE_RE = /^(\d{4,5})-(\d{4,5})$/;

/**
 * Validate and expand port specs ('2456', '2456-2458') into concrete ports.
 *
 * The rules mirror the panel's AssignmentService so a bad spec fails here with a
 * legible message instead of coming back as an opaque 500 — and, more
 * importantly, expanding locally is what lets the caller pre-check for ports
 * that already exist. Exported for testing.
 */
export function expandPorts(ports: string[]): number[] {
  if (!ports.length) throw new Error("create_allocations needs at least one port.");
  // Collected into a Set as we go, and the cap is checked on every insertion.
  // Expanding everything first and checking afterwards would mean the guard runs
  // only after the work it exists to prevent — the `ports` array itself has no
  // length bound, so a few thousand wide ranges would exhaust the heap inside
  // the expansion loop and never reach the check.
  const seen = new Set<number>();
  const add = (port: number): void => {
    seen.add(port);
    if (seen.size > MAX_PORTS_PER_CALL) {
      throw new Error(
        `That asks for more than ${MAX_PORTS_PER_CALL} distinct ports; this tool caps a single call at ${MAX_PORTS_PER_CALL}. ` +
          `Split it into smaller calls — and double-check the range, because a game server normally needs a handful of ports, not hundreds.`,
      );
    }
  };
  for (const raw of ports) {
    const spec = String(raw).trim();
    const range = PORT_RANGE_RE.exec(spec);
    if (range) {
      const start = Number(range[1]);
      const end = Number(range[2]);
      if (end < start) throw new Error(`Invalid port range '${spec}' — the end port is below the start port.`);
      if (start < PORT_FLOOR || end > PORT_CEIL) {
        throw new Error(`Port range '${spec}' is outside Pelican's allowed range ${PORT_FLOOR}-${PORT_CEIL}.`);
      }
      for (let p = start; p <= end; p += 1) add(p);
      continue;
    }
    if (!/^\d+$/.test(spec)) {
      throw new Error(
        `Invalid port '${spec}' — use a single port like '2456', or a range like '2456-2458'. ` +
          `Pelican requires BOTH endpoints of a range to be 4-5 digits, so '999-2000' is not a valid range to it.`,
      );
    }
    const port = Number(spec);
    if (port < PORT_FLOOR || port > PORT_CEIL) {
      throw new Error(`Port ${port} is outside Pelican's allowed range ${PORT_FLOOR}-${PORT_CEIL}.`);
    }
    add(port);
  }
  return [...seen].sort((a, b) => a - b);
}

/** A single literal IPv4 — CIDR is deliberately refused, see the tool description. */
const IPV4_RE = /^(\d{1,3})\.(\d{1,3})\.(\d{1,3})\.(\d{1,3})$/;

/** Validate the allocation IP. Exported for testing. */
export function assertAllocationIp(ip: string): string {
  const trimmed = ip.trim();
  const m = IPV4_RE.exec(trimmed);
  if (!m || [m[1], m[2], m[3], m[4]].some((n) => Number(n) > 255)) {
    throw new Error(
      `create_allocations takes one literal IPv4 address (e.g. '192.168.0.48'), not '${ip}'. ` +
        `Pelican also accepts a CIDR block here and expands it across every port, which multiplies into thousands of ` +
        `allocations from a single call — so this tool refuses CIDR. Use the node's own IP, exactly as list_allocations prints it.`,
    );
  }
  return trimmed;
}

// --- Egg import parsing ------------------------------------------------------

/** `meta.version` values Pelican's importer recognises (EggImporterService::parse
 *  plus Egg::EXPORT_VERSION). Anything else is rejected as "not recognized". */
export const EGG_FORMAT_VERSIONS = ["PTDL_v1", "PTDL_v2", "PLCN_v1", "PLCN_v2", "PLCN_v3"] as const;

/** Only the fields the import guardrail needs — never the whole egg. */
export interface ParsedEgg {
  uuid?: string;
  name?: string;
  author?: string;
  version: string;
  variableCount: number;
}

/**
 * Parse an egg export locally, purely so the import can be checked BEFORE it is
 * sent. Three things are worth catching here rather than at the panel:
 *
 *  - **The uuid**, because Pelican's importer treats a known uuid as "update this
 *    egg in place" — it overwrites the egg and deletes every variable the import
 *    doesn't mention. That is invisible in the request and irreversible, so the
 *    uuid has to be read before the POST, not after.
 *  - **meta.version**, which the panel rejects with a flat "file format is not
 *    recognized" that doesn't say what it got.
 *  - **variables**, which the importer dereferences with `count()` and no guard —
 *    an egg without it produces a 500 rather than a validation error.
 *
 * Accepts JSON or YAML: the panel parses the raw body as YAML (JSON being valid
 * YAML), and eggs are published in both. Exported for testing.
 */
export function parseEggContent(content: string): ParsedEgg {
  const text = content.trim();
  if (!text) throw new Error("The egg content is empty.");
  let parsed: unknown;
  try {
    // JSON first — it is the common case and gives far better errors than the
    // YAML parser does on a malformed JSON document.
    parsed = JSON.parse(text);
  } catch {
    try {
      parsed = yaml.load(text);
    } catch (e) {
      throw new Error(`Could not parse the egg as JSON or YAML: ${e instanceof Error ? e.message : String(e)}`);
    }
  }
  if (!parsed || typeof parsed !== "object" || Array.isArray(parsed)) {
    throw new Error("That content is not an egg object. An egg export is a JSON/YAML object with 'meta', 'name' and 'variables'.");
  }
  const obj = parsed as Record<string, unknown>;
  const meta = (obj.meta ?? {}) as Record<string, unknown>;
  const version = typeof meta.version === "string" ? meta.version : "";
  if (!(EGG_FORMAT_VERSIONS as readonly string[]).includes(version)) {
    throw new Error(
      `The egg's meta.version is '${version || "(missing)"}', which Pelican's importer does not accept — it takes ${EGG_FORMAT_VERSIONS.join(", ")}. ` +
        `This usually means the file isn't a Pelican/Pterodactyl egg export (a GitHub HTML page or a README will land here too).`,
    );
  }
  if (!Array.isArray(obj.variables)) {
    throw new Error(
      "The egg has no 'variables' array. Pelican's importer reads it without a guard, so this would fail as a server error rather than a validation message. Re-export the egg from a panel.",
    );
  }
  return {
    uuid: typeof obj.uuid === "string" ? obj.uuid : undefined,
    name: typeof obj.name === "string" ? obj.name : undefined,
    author: typeof obj.author === "string" ? obj.author : undefined,
    version,
    variableCount: obj.variables.length,
  };
}

/** Largest egg body accepted from a URL — real eggs are a few KiB; the install
 *  script is the only large part. Enforced WHILE reading, not after. */
export const MAX_EGG_BYTES = 2 * 1024 * 1024;

/** Redirect hops allowed when fetching an egg. Every hop is re-validated. */
export const MAX_EGG_REDIRECTS = 5;

/**
 * IPv4 literals an outbound fetch must never reach. This is deliberately NOT
 * `isPrivateIPv4`: that one answers "is this a LAN address I trust enough to send
 * a bearer token to in clear", and RFC1918 is the right answer there. This one
 * answers the opposite question — "could this address reach something inside the
 * trust boundary" — and for that, RFC1918 alone is nowhere near enough: loopback,
 * link-local (cloud metadata lives at 169.254.169.254), CGNAT and the
 * multicast/reserved space are all local reach. Exported for testing.
 */
export function isBlockedFetchIPv4(ip: string): boolean {
  const m = /^(\d{1,3})\.(\d{1,3})\.(\d{1,3})\.(\d{1,3})$/.exec(ip);
  if (!m) return false;
  const [a, b, c] = [Number(m[1]), Number(m[2]), Number(m[3])];
  if ([a, b, c, Number(m[4])].some((n) => n > 255)) return false;
  return (
    a === 0 || // "this network" / 0.0.0.0
    a === 127 || // loopback
    a === 10 || // RFC1918
    (a === 172 && b >= 16 && b <= 31) ||
    (a === 192 && b === 168) ||
    (a === 169 && b === 254) || // link-local, incl. 169.254.169.254 metadata
    (a === 100 && b >= 64 && b <= 127) || // CGNAT
    (a === 192 && b === 0 && (c === 0 || c === 2)) || // IETF protocol assignments / TEST-NET-1
    (a === 198 && b >= 18 && b <= 19) || // benchmarking
    (a === 198 && b === 51 && c === 100) || // TEST-NET-2
    (a === 203 && b === 0 && c === 113) || // TEST-NET-3
    a >= 224 // multicast, reserved (240/4), broadcast
  );
}

/**
 * IPv6 literals an outbound fetch must never reach: loopback/unspecified, the
 * whole `::/96` special block (which is where IPv4-mapped and IPv4-compatible
 * addresses live, and `::ffff:127.0.0.1` must not be a way around the v4 rules),
 * unique-local, link-local, site-local and multicast. Exported for testing.
 */
export function isBlockedFetchIPv6(addr: string): boolean {
  const a = addr.toLowerCase();
  if (!a.includes(":")) return false;
  if (a.startsWith("::")) {
    // `::ffff:1.2.3.4` embeds a v4 address — decide it by the v4 rules so the
    // mapped form can't smuggle loopback past this check.
    const mapped = /^::ffff:(\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})$/.exec(a);
    if (mapped) return isBlockedFetchIPv4(mapped[1]!);
    return true; // ::, ::1, and the rest of the special ::/96 block
  }
  const first = a.split(":")[0] ?? "";
  if (!/^[0-9a-f]{1,4}$/.test(first)) return false;
  const v = parseInt(first, 16);
  const hi = v >> 8;
  if (hi === 0xfc || hi === 0xfd) return true; // unique-local fc00::/7
  if ((v & 0xffc0) === 0xfe80) return true; // link-local fe80::/10
  if ((v & 0xffc0) === 0xfec0) return true; // site-local (deprecated) fec0::/10
  if (hi === 0xff) return true; // multicast
  return false;
}

/** Hostnames that resolve inside the network by convention rather than by literal
 *  address. Name-based, so it is a backstop, not the whole guard. */
function isLocalHostname(host: string): boolean {
  return host === "localhost" || host.endsWith(".localhost") || host.endsWith(".local") || host.endsWith(".internal") || host.endsWith(".home.arpa");
}

/**
 * Guard the egg source URL. Skeleton Key does the fetch, so an attacker-supplied
 * URL would be a request made from INSIDE the LAN — the classic SSRF shape. The
 * rule is the mirror image of `assertTransportOk`: that one allows plain http
 * only to a private address, this one allows only https to a PUBLIC one.
 * Exported for testing.
 */
export function assertEggSourceUrl(raw: string): URL {
  let url: URL;
  try {
    url = new URL(raw.trim());
  } catch {
    throw new Error(`Invalid egg URL '${raw}'.`);
  }
  if (url.protocol !== "https:") {
    throw new Error(`Refusing to fetch an egg over '${url.protocol}' — use https so the egg can't be swapped in transit.`);
  }
  const host = url.hostname.replace(/^\[|\]$/g, "").toLowerCase();
  if (isBlockedFetchIPv4(host) || isBlockedFetchIPv6(host) || isLocalHostname(host)) {
    throw new Error(
      `Refusing to fetch an egg from '${url.hostname}' — that address is loopback, private, link-local or otherwise inside the network. ` +
        `This tool fetches from inside your network, so it is restricted to public https sources (e.g. raw.githubusercontent.com). ` +
        `Paste the egg via 'content' instead.`,
    );
  }
  return url;
}

/**
 * Read a response body, enforcing the size cap **while reading** rather than
 * after. `await res.text()` would buffer the whole thing first, so a cap applied
 * to the result bounds nothing: the memory has already been spent by the time it
 * is consulted. The declared Content-Length is rejected up front when it is
 * already over, and the stream is cancelled the moment the running total
 * exceeds the cap.
 */
async function readCappedBody(res: Response, href: string): Promise<string> {
  const tooBig = (n: number | string) =>
    new Error(`The file at ${href} is ${n} bytes, larger than the ${MAX_EGG_BYTES}-byte limit for an egg. Check the URL points at an egg export.`);

  const declared = Number(res.headers.get("content-length"));
  if (Number.isFinite(declared) && declared > MAX_EGG_BYTES) throw tooBig(declared);

  const body = res.body as AsyncIterable<Uint8Array> | null | undefined;
  // No streamable body (a test double, or a runtime without one) — fall back to
  // buffering, but still measure BYTES: `string.length` counts UTF-16 code
  // units, so a multibyte install script would undercount against a byte limit.
  if (!body || typeof (body as any)[Symbol.asyncIterator] !== "function") {
    const text = await res.text();
    if (Buffer.byteLength(text, "utf8") > MAX_EGG_BYTES) throw tooBig(Buffer.byteLength(text, "utf8"));
    return text;
  }

  const chunks: Buffer[] = [];
  let total = 0;
  for await (const chunk of body) {
    const buf = Buffer.from(chunk);
    total += buf.byteLength;
    if (total > MAX_EGG_BYTES) {
      try {
        await (res.body as ReadableStream | null)?.cancel();
      } catch {
        /* already closed */
      }
      throw tooBig(`over ${MAX_EGG_BYTES}`);
    }
    chunks.push(buf);
  }
  return Buffer.concat(chunks).toString("utf8");
}

/**
 * Fetch an egg export from a public https URL, size- and time-bounded.
 *
 * Redirects are followed BY HAND (`redirect: "manual"`) so every hop passes
 * `assertEggSourceUrl` again. The default `redirect: "follow"` would check only
 * the URL the caller supplied and then quietly follow a 302 anywhere — including
 * back to plain http, or to a LAN address the guard exists to refuse — which
 * makes validating the first URL worth nothing.
 */
export async function fetchEggFromUrl(raw: string): Promise<string> {
  let url = assertEggSourceUrl(raw);
  for (let hop = 0; ; hop += 1) {
    let res: Response;
    try {
      res = await fetch(url.href, {
        headers: { Accept: "application/json, application/yaml, text/plain, */*" },
        redirect: "manual",
        signal: AbortSignal.timeout(15_000),
      });
    } catch (e) {
      throw new Error(`Could not fetch the egg from ${url.href}: ${e instanceof Error ? e.message : String(e)}`);
    }

    if (res.status >= 300 && res.status < 400) {
      const location = res.headers.get("location");
      if (!location) throw new Error(`Could not fetch the egg from ${url.href}: HTTP ${res.status} with no Location header.`);
      if (hop >= MAX_EGG_REDIRECTS) {
        throw new Error(`Could not fetch the egg from ${raw}: more than ${MAX_EGG_REDIRECTS} redirects.`);
      }
      let next: URL;
      try {
        next = new URL(location, url); // relative Location is legal
      } catch {
        throw new Error(`Could not fetch the egg from ${url.href}: HTTP ${res.status} with an unusable Location '${location}'.`);
      }
      // The whole point: re-run the guard on the hop we are about to take.
      url = assertEggSourceUrl(next.href);
      continue;
    }

    if (!res.ok) throw new Error(`Could not fetch the egg from ${url.href}: HTTP ${res.status}.`);
    return readCappedBody(res, url.href);
  }
}

// --- Panel host (SSH) --------------------------------------------------------

/**
 * A path safe to interpolate into a fixed shell command: absolute, and made only
 * of characters that cannot end a word or start a new one. This is what lets the
 * upgrade steps claim "no caller input is interpolated" — `panelPath` comes from
 * the target's options (operator-set, via register/update_target), and even then
 * it has to survive this. Exported for testing.
 */
export function assertSafePath(path: string, field: string): string {
  const trimmed = path.trim();
  if (!/^\/[A-Za-z0-9._\-/]*$/.test(trimmed) || trimmed.includes("..")) {
    throw new Error(
      `The Pelican target's '${field}' must be an absolute path made of letters, digits, dot, dash, underscore and '/' (got '${path}'). ` +
        `It is interpolated into shell commands run on the panel host, so anything else is refused.`,
    );
  }
  return trimmed.replace(/\/+$/, "");
}

/** Same idea for the unix user the panel runs as. Exported for testing. */
export function assertSafeUser(user: string, field: string): string {
  const trimmed = user.trim();
  if (!/^[A-Za-z_][A-Za-z0-9._-]*$/.test(trimmed)) {
    throw new Error(`The Pelican target's '${field}' must be a plain unix username (got '${user}').`);
  }
  return trimmed;
}

/** The panel's host, resolved from the target's `sshTarget` option. */
interface PanelHost {
  target: Target;
  cred: Credential;
  path: string;
  user: string;
}

/**
 * Resolve the SSH target that hosts the panel.
 *
 * This is the one place a connector reaches another target, so the checks are
 * deliberately strict and each failure says exactly what to fix: the option must
 * be set, the name must resolve, and the resolved target must actually be of
 * type `ssh`. That last check matters — without it, a typo'd name pointing at,
 * say, the UniFi target would have this connector trying to open a shell on the
 * gateway.
 */
async function panelHost(ctx: ToolContext): Promise<PanelHost> {
  const opts = options(ctx.target);
  const name = opts.sshTarget;
  if (!name) {
    throw new Error(
      `This Pelican target has no 'sshTarget' option, so there is no host to run this on. Pelican has no version or upgrade endpoint on ` +
        `any API half, so both are host-level operations. Fix with update_target: set sshTarget to the name of the registered ssh target ` +
        `for the machine the panel is installed on (see list_targets).`,
    );
  }
  if (!ctx.resolveTarget || !ctx.resolveCredential) {
    throw new Error("This call site cannot resolve other targets, so panel host operations are unavailable here.");
  }
  const host = ctx.resolveTarget(name);
  if (!host) throw new Error(`This Pelican target's sshTarget is '${name}', but no target by that name is registered. Check list_targets.`);
  if (host.type !== "ssh") {
    throw new Error(
      `This Pelican target's sshTarget is '${name}', which is a '${host.type}' target, not 'ssh'. Refusing to run shell commands against it — ` +
        `point sshTarget at the ssh target for the panel's host.`,
    );
  }
  if (!host.credentialRef) throw new Error(`The ssh target '${name}' has no credential attached, so it cannot be used to reach the panel host.`);
  const cred = await ctx.resolveCredential(host.credentialRef);
  return { target: host, cred, path: assertSafePath(opts.panelPath, "panelPath"), user: assertSafeUser(opts.panelUser, "panelUser") };
}

/**
 * Run one FIXED command on the panel host.
 *
 * **On the guardrail this does and does not honor.** The SSH target's own
 * command ALLOWLIST is not applied: the upgrade is inherently a sequence of
 * compound root commands (`cd … && sudo -u www-data php artisan …`) that a
 * read-only allowlist refuses by design, and routing it through `run_command`
 * would just be the same commands with less review. What it keeps is
 * `DEFAULT_DENY` — the destructive patterns (`rm -rf`, `mkfs`, `dd of=/dev/…`,
 * reboot) are still refused here, so a mistake in a step cannot turn into one of
 * those. Everything executed comes from the fixed constants below; no caller
 * input reaches a command, and the two interpolated option values are validated
 * by `assertSafePath` / `assertSafeUser` first.
 */
async function runOnPanelHost(host: PanelHost, command: string, timeoutMs?: number): Promise<SshExecResult> {
  const verdict = checkCommand(command);
  if (!verdict.allowed) throw new Error(`Refusing to run this panel-host command — ${verdict.reason}`);
  return runSsh(host.target, host.cred, command, timeoutMs ? { timeoutMs } : {});
}

/** Parse `'version' => '1.0.0-beta35',` out of the panel's config/app.php. */
export function parsePanelVersion(configLine: string): string | undefined {
  const m = /['"]version['"]\s*=>\s*['"]([^'"]+)['"]/.exec(configLine);
  return m?.[1];
}

/**
 * Compare two Pelican versions well enough to say "behind / same / ahead".
 * Pelican tags look like `v1.0.0-beta38`; compare numeric components left to
 * right, then the prerelease number. Returns -1/0/1, or undefined when the shape
 * is unrecognised — in which case the caller must say "could not compare"
 * rather than guess, because claiming "up to date" wrongly is the bad failure.
 * Exported for testing.
 */
export function compareVersions(a: string, b: string): number | undefined {
  const parse = (v: string) => {
    const m = /^v?(\d+)\.(\d+)\.(\d+)(?:-([A-Za-z]+)\.?(\d+))?$/.exec(v.trim());
    if (!m) return undefined;
    return {
      nums: [Number(m[1]), Number(m[2]), Number(m[3])],
      // No prerelease outranks any prerelease: 1.0.0 > 1.0.0-beta38.
      pre: m[4] ? { tag: m[4].toLowerCase(), num: Number(m[5]) } : undefined,
    };
  };
  const pa = parse(a);
  const pb = parse(b);
  if (!pa || !pb) return undefined;
  for (let i = 0; i < 3; i += 1) {
    if (pa.nums[i]! !== pb.nums[i]!) return pa.nums[i]! < pb.nums[i]! ? -1 : 1;
  }
  if (!pa.pre && !pb.pre) return 0;
  if (!pa.pre) return 1;
  if (!pb.pre) return -1;
  if (pa.pre.tag !== pb.pre.tag) return undefined; // alpha vs beta — don't guess
  if (pa.pre.num === pb.pre.num) return 0;
  return pa.pre.num < pb.pre.num ? -1 : 1;
}

/** Latest released panel version, from the same source the panel's own banner
 *  uses. Best-effort: a failure here must not break the installed-version read. */
export async function latestPanelRelease(): Promise<{ tag?: string; error?: string }> {
  try {
    const res = await fetch("https://api.github.com/repos/pelican-dev/panel/releases/latest", {
      headers: { Accept: "application/vnd.github+json" },
      signal: AbortSignal.timeout(10_000),
    });
    if (!res.ok) return { error: `GitHub answered HTTP ${res.status}` };
    const body = (await res.json()) as { tag_name?: string };
    return body?.tag_name ? { tag: body.tag_name } : { error: "GitHub returned no tag_name" };
  } catch (e) {
    return { error: e instanceof Error ? e.message : String(e) };
  }
}

/** One step of the upgrade. `command` is a template over the validated
 *  `{path}` / `{user}` only — never over caller input. */
interface UpgradeStep {
  name: string;
  command: string;
  timeoutMs?: number;
  /** Output worth quoting back in the result (version checks, migration tail). */
  capture?: boolean;
}

/**
 * The upgrade, as Pelican documents it for a bare-metal install, as an explicit
 * reviewable list rather than one opaque blob. Each step runs on its own so a
 * failure names the step it died on, and the panel is left in maintenance mode
 * with the reason rather than half-upgraded and serving.
 *
 * `artisan` and `composer` run as the panel user, never root, so the upgrade
 * cannot leave root-owned files the webserver then can't write — the classic way
 * a "successful" upgrade bricks the panel afterwards.
 */
export const PANEL_UPGRADE_STEPS: UpgradeStep[] = [
  { name: "maintenance-mode", command: 'cd {path} && sudo -n -u {user} php artisan down' },
  {
    name: "download-release",
    command: 'cd {path} && sudo -n -u {user} curl -sSL -o /tmp/pelican-panel.tar.gz https://github.com/pelican-dev/panel/releases/latest/download/panel.tar.gz',
    timeoutMs: 300_000,
  },
  { name: "extract", command: 'cd {path} && sudo -n -u {user} tar -xzf /tmp/pelican-panel.tar.gz', timeoutMs: 180_000 },
  { name: "fix-permissions", command: 'cd {path} && sudo -n chmod -R 755 storage bootstrap/cache' },
  {
    name: "composer-install",
    command: 'cd {path} && sudo -n -u {user} composer install --no-dev --optimize-autoloader --no-interaction',
    timeoutMs: 600_000,
    capture: true,
  },
  { name: "migrate", command: 'cd {path} && sudo -n -u {user} php artisan migrate --seed --force', timeoutMs: 600_000, capture: true },
  { name: "clear-caches", command: 'cd {path} && sudo -n -u {user} php artisan optimize:clear' },
  { name: "restart-queue", command: 'cd {path} && sudo -n -u {user} php artisan queue:restart' },
  { name: "exit-maintenance", command: 'cd {path} && sudo -n -u {user} php artisan up' },
];

/** Fill a step template with the already-validated path/user. */
function renderStep(command: string, host: PanelHost): string {
  return command.replaceAll("{path}", host.path).replaceAll("{user}", host.user);
}

// --- Response shapes (Fractal envelopes: {object, data:[{attributes}]}) -------

interface Egg {
  id: number;
  /** Stable identity across panels — what `import_egg` matches to detect that an
   *  import would OVERWRITE an existing egg rather than create a new one. */
  uuid?: string;
  name?: string;
  author?: string;
  description?: string;
  docker_image?: string;
  docker_images?: Record<string, string> | string[];
  [k: string]: unknown;
}
/** One egg variable, as the panel's EggVariableTransformer returns it (a raw
 *  model `toArray()`). `default_value` is the value the panel uses when a server
 *  does not override it — the thing `create_server` must not drop. */
interface EggVariable {
  env_variable: string;
  name?: string;
  default_value?: string | null;
  user_editable?: boolean;
  user_viewable?: boolean;
  rules?: string | string[];
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
  /** Owner's user id — decides whether the CLIENT key can act on this server. */
  user?: number;
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

/**
 * Build the COMPLETE environment for a server from the egg's variables plus
 * whatever the caller supplied.
 *
 * **Why this has to exist.** Pelican treats the `environment` map as the whole
 * truth: any egg variable the request omits is stored as an empty string, and
 * `EnvironmentService` resolves values with `server_value ?? default_value` —
 * `??` catches null but NOT `""`, so a stored blank permanently beats the egg's
 * default. Passing a partial environment therefore does not mean "use defaults
 * for the rest", it means "blank the rest", and nothing in the API says so. A
 * Valheim server provisioned that way installed with `+app_update ""`, fetched
 * no game files, and crash-looped on boot.
 *
 * A name that is not one of the egg's variables is refused rather than passed
 * through, because Pelican would accept and ignore it — a typo'd variable would
 * silently do nothing while looking like it had been set.
 *
 * Returns the full map plus the names that fell back to defaults, so the caller
 * can say what it filled in. Values are never echoed (they include passwords).
 * Exported for testing.
 */
export function buildEnvironment(
  variables: EggVariable[],
  supplied: Record<string, string | number | boolean> = {},
): { environment: Record<string, string>; defaulted: string[] } {
  const known = new Map(variables.map((v) => [v.env_variable, v]));
  const unknown = Object.keys(supplied).filter((k) => !known.has(k));
  if (unknown.length) {
    throw new Error(
      `This egg has no variable named ${unknown.map((u) => `'${u}'`).join(", ")}. Its variables are: ${[...known.keys()].join(", ")}. ` +
        `Pelican would accept an unknown name and ignore it, so a typo would look like it worked — hence the refusal.`,
    );
  }
  const environment: Record<string, string> = {};
  const defaulted: string[] = [];
  for (const [name, variable] of known) {
    if (Object.prototype.hasOwnProperty.call(supplied, name)) {
      environment[name] = String(supplied[name]);
    } else {
      environment[name] = variable.default_value == null ? "" : String(variable.default_value);
      defaulted.push(name);
    }
  }
  return { environment, defaulted };
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

/**
 * `reachable` is the set of identifiers the CLIENT key can actually act on (from
 * GET /api/client). Annotating here is what stops the two-API split from being a
 * trap: the Application key lists every server on the panel, but power, startup
 * and schedule tools all go through the Client key and silently 404 on anything
 * its user doesn't own. Pass null when that lookup failed, so the line says
 * "unknown" rather than falsely claiming no access.
 */
export function summarizeServers(servers: Server[], reachable?: Set<string> | null): string {
  if (!servers.length) return "No servers.";
  const lines = servers.map((s) => {
    const flags = [s.suspended ? "SUSPENDED" : null, s.status ? String(s.status) : null].filter(Boolean).join(" ");
    let access = "";
    if (reachable === null) access = "  client=unknown";
    else if (reachable) {
      const ok = (s.identifier && reachable.has(s.identifier)) || (s.uuid && reachable.has(s.uuid));
      access = ok ? "  client=YES" : `  client=NO (owned by user ${s.user ?? "?"})`;
    }
    return `- [${s.id}] ${s.name ?? "(unnamed)"} identifier=${s.identifier ?? "?"} uuid=${s.uuid ?? "?"} node=${s.node ?? "?"} egg=${s.egg ?? "?"}${flags ? `  ${flags}` : ""}${access}`;
  });
  if (reachable && ![...servers].some((s) => (s.identifier && reachable.has(s.identifier)) || (s.uuid && reachable.has(s.uuid)))) {
    lines.push(
      "",
      "NOTE: client=NO on every server — the client key's user owns none of them, so power_action, update_startup_variables,",
      "server_resources and all schedule tools will 404. That is a panel permission, not a fault: make that user the owner, or",
      "add them as a subuser. Servers created by create_server are owned by the target's ownerUserId and will be reachable.",
    );
  }
  return lines.join("\n");
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
    /** Present for MCP tool calls; absent for the snapshot service, which needs
     *  no vault-backed injection. Guarded at each use, never assumed. */
    private readonly ctx?: ToolContext,
  ) {}

  /**
   * Resolve vault-backed variable values. The VALUES returned here are for the
   * outbound Pelican request body only — never a ToolResult, an error, or the
   * audit log. See secret-refs.ts for the invariant.
   */
  private async secrets(refs: SecretRef[] | undefined, label: string): Promise<SecretValue[]> {
    if (!refs?.length) return [];
    if (!this.ctx) throw new Error(`Vault-backed '${label}' is unavailable at this call site.`);
    return resolveSecretRefs(this.ctx, refs, label);
  }

  /** `NAME: len=… fp=…` lines for what was injected — never the values. */
  private fingerprints(secrets: SecretValue[]): Promise<string> {
    return secretFingerprintBlock(secrets, this.ctx?.fingerprint);
  }

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
    opts: { method?: string; body?: unknown; rawBody?: string; query?: Record<string, string | number> } = {},
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
    // `rawBody` goes over the wire verbatim. The egg import route reads
    // `$request->getContent()` — the egg document IS the body, not a field in a
    // JSON envelope — so it must not be re-serialized.
    const payload = opts.rawBody !== undefined ? opts.rawBody : opts.body !== undefined ? JSON.stringify(opts.body) : undefined;
    if (payload !== undefined) headers["Content-Type"] = "application/json";
    const res = await tlsFetch(
      `${this.base}/api/${api}${path}${qs}`,
      { method: opts.method ?? "GET", headers, body: payload },
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
  private ensureOk(res: { ok: boolean; status: number; json?: unknown; text: string }, path: string, api?: PelicanApi): void {
    if (res.ok) return;
    const errs = (res.json as { errors?: { detail?: string; code?: string }[] })?.errors;
    const detail = errs?.map((e) => e.detail ?? e.code).filter(Boolean).join("; ");
    // A Client-API 404 on a server path almost never means "no such server" — it
    // means the client key's user neither owns it nor is a subuser on it, so the
    // panel hides it entirely. Without this hint the failure looks like a bad id,
    // and list_servers (Application API) cheerfully shows the server, which makes
    // it look like a bug in Skeleton Key rather than a panel permission.
    const hint =
      api === "client" && res.status === 404 && path.startsWith("/servers/")
        ? ` — the Client API only sees servers its key's user OWNS or is a subuser on. Run list_servers: it marks which servers this key can act on, and names each owner. Fix by making that user the server's owner or adding them as a subuser in the panel.`
        : "";
    throw new Error(`Pelican HTTP ${res.status} on ${path}: ${scrubSecrets(detail || res.text).slice(0, 400)}${hint}`);
  }

  /** Unwrap a Fractal list, following pagination so a long allocation list is
   *  complete rather than silently truncated at the first page. */
  private async list<T>(api: PelicanApi, path: string, query: Record<string, string | number> = {}): Promise<T[]> {
    const out: T[] = [];
    let page = 1;
    for (;;) {
      const res = await this.request(api, path, { query: { ...query, page, per_page: 100 } });
      this.ensureOk(res, path, api);
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
    this.ensureOk(res, path, api);
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
    const servers = await this.list<Server>("application", "/servers");
    // Best-effort: a missing/invalid client key must not break the application-side
    // inventory, so a failure here degrades to "unknown" rather than throwing.
    let reachable: Set<string> | null = null;
    try {
      const mine = await this.list<Server>("client", "");
      reachable = new Set(mine.flatMap((m) => [m.identifier, m.uuid].filter((x): x is string => !!x)));
    } catch {
      /* no client key, or it can't list — annotate as unknown */
    }
    return summarizeServers(servers, reachable);
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

  /**
   * An egg's variables, with their defaults. **Fails closed**: if the API does
   * not return the `variables` include at all, this throws rather than yielding
   * an empty list — an empty list would make `buildEnvironment` produce an empty
   * environment, which is exactly the blank-out bug it exists to prevent. An egg
   * that genuinely has no variables returns an empty `data` array, which is fine
   * and distinguishable.
   */
  private async eggVariables(eggId: number): Promise<EggVariable[]> {
    const path = `/eggs/${eggId}`;
    const res = await this.request("application", path, { query: { include: "variables" } });
    this.ensureOk(res, path);
    const attrs = (res.json as { attributes?: { relationships?: { variables?: { data?: { attributes?: EggVariable }[] } } } })?.attributes;
    const rel = attrs?.relationships?.variables;
    if (!rel || !Array.isArray(rel.data)) {
      throw new Error(
        `Could not read egg ${eggId}'s variables — the panel did not return the 'variables' include. Refusing to continue: without the ` +
          `defaults, every variable not named explicitly would be stored EMPTY, which silently breaks the install (blank appid, blank library path).`,
      );
    }
    return rel.data.map((r) => r.attributes).filter((v): v is EggVariable => !!v && typeof v.env_variable === "string");
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

  /**
   * Create allocations (IP:port rows) on a node, so a new server has a port to
   * bind. This is the step that unblocks provisioning a game the panel has never
   * hosted: `create_server` can only take an allocation that already exists.
   *
   * Two things shape the implementation:
   *  - The route answers **204 with an empty body**, so it tells you nothing
   *    about what it made. The ids are re-read afterwards, otherwise the result
   *    could not name the allocations the caller now needs for `create_server`.
   *  - The table has a unique index on (node, ip, port) and the service does a
   *    plain insert, so re-creating an existing allocation is a 500, not a
   *    friendly conflict. The clash is checked first and reported by port.
   */
  async createAllocations(input: { node: number; ip: string; ports: string[]; alias?: string }): Promise<string> {
    const ip = assertAllocationIp(input.ip);
    const ports = expandPorts(input.ports);
    const path = `/nodes/${input.node}/allocations`;

    const before = await this.list<Allocation>("application", path);
    const clash = before.filter((a) => a.ip === ip && ports.includes(Number(a.port)));
    if (clash.length) {
      throw new Error(
        `Node ${input.node} already has ${clash.length} of those allocations: ${clash.map((a) => `${a.ip}:${a.port} [${a.id}]${a.assigned ? " (assigned)" : " (free)"}`).join(", ")}. ` +
          `Pelican has a unique index on (node, ip, port) and inserts without checking, so sending these again fails as a server error. ` +
          `Drop those ports from the call, or just use the existing allocations — a FREE one is already usable by create_server.`,
      );
    }

    const res = await this.request("application", path, {
      method: "POST",
      // Ports are sent as strings: the panel validates `ports.*` as `string` and
      // parses ranges out of them itself.
      body: { ip, ports: ports.map(String), ...(input.alias ? { alias: input.alias } : {}) },
    });
    this.ensureOk(res, path);

    const after = await this.list<Allocation>("application", path);
    const created = after.filter((a) => a.ip === ip && ports.includes(Number(a.port)));
    const missing = ports.filter((p) => !created.some((a) => Number(a.port) === p));
    return (
      `Created ${created.length} allocation(s) on Pelican node ${input.node}: ${created.map((a) => `${a.ip}:${a.port} [${a.id}]`).join(", ") || "(none reported)"}` +
      `${input.alias ? ` with alias '${input.alias}'` : ""}. ` +
      `${missing.length ? `WARNING: ${missing.length} requested port(s) are still missing after the call (${missing.join(", ")}) — re-run list_allocations. ` : ""}` +
      `Pass one of these ids (or its 'ip:port') to create_server, and remember a UDP game also needs a UniFi port-forward to the same address.`
    );
  }

  /**
   * Import an egg (a game's server template) so a game the panel has never
   * hosted can be provisioned.
   *
   * **The overwrite trap.** Pelican's importer keys on the egg's uuid:
   * `Egg::where('uuid',$uuid)->first() ?? new Egg()`. A uuid that already exists
   * is not a conflict — the existing egg is rewritten in place, and every
   * variable the import doesn't mention is DELETED. Nothing in the request says
   * "update", and a server built on that egg keeps running against a template
   * that silently changed underneath it. So the uuid is read from the content
   * first and a match is refused unless the caller explicitly asked to
   * overwrite, with the affected servers named in the refusal.
   */
  async importEgg(input: { url?: string; content?: string; overwrite?: boolean }): Promise<string> {
    if ((input.url ? 1 : 0) + (input.content ? 1 : 0) !== 1) {
      throw new Error("import_egg takes exactly one of 'url' (a public https egg export) or 'content' (the egg JSON/YAML itself).");
    }
    const content = input.content ?? (await fetchEggFromUrl(input.url!));
    const parsed = parseEggContent(content);

    const eggs = await this.list<Egg>("application", "/eggs");
    const existing = parsed.uuid
      ? eggs.find((e) => typeof e.uuid === "string" && e.uuid.toLowerCase() === parsed.uuid!.toLowerCase())
      : undefined;

    if (existing && !input.overwrite) {
      // Name the blast radius: which servers are built on the egg about to be
      // rewritten. Best-effort — a listing failure must not mask the refusal.
      let inUse = "";
      try {
        const servers = await this.list<Server>("application", "/servers");
        const users = servers.filter((s) => s.egg === existing.id);
        if (users.length) inUse = ` ${users.length} server(s) are built on it: ${users.map((s) => `'${s.name}' [${s.id}]`).join(", ")}.`;
      } catch {
        inUse = " (could not check which servers use it)";
      }
      throw new Error(
        `Refusing to import: this egg's uuid (${parsed.uuid}) already exists on the panel as '${existing.name ?? "(unnamed)"}' [id ${existing.id}]. ` +
          `Pelican would OVERWRITE that egg in place and DELETE any variable this file doesn't contain — there is no undo.${inUse} ` +
          `If replacing it is genuinely what you want, call import_egg again with overwrite: true. To add it alongside the existing egg instead, edit the file's 'uuid' to a new one first.`,
      );
    }

    const path = "/eggs/import";
    const res = await this.request("application", path, { method: "POST", rawBody: content });
    this.ensureOk(res, path);
    const egg: Partial<Egg> = (res.json as { attributes?: Egg })?.attributes ?? {};
    const verb = existing ? "OVERWROTE existing" : "Imported new";
    return (
      `${verb} Pelican egg '${egg.name ?? parsed.name ?? "(unnamed)"}' [id ${egg.id ?? existing?.id ?? "?"}] uuid=${egg.uuid ?? parsed.uuid ?? "(generated)"} ` +
      `(format ${parsed.version}, ${parsed.variableCount} variable(s))${parsed.author ? ` by ${parsed.author}` : ""} on ${this.target.name}. ` +
      `${existing ? "Variables not present in the imported file were removed; servers on this egg keep their own values but may need a reinstall to match the new template. " : ""}` +
      `Use this egg id with create_server — run list_eggs to confirm, and check the egg's required variables before provisioning.`
    );
  }

  /** Create a server owned by the target's dedicated `ownerUserId`. */
  async createServer(input: {
    name: string;
    egg: string;
    allocation: string;
    additionalAllocations?: string[];
    memory?: number;
    disk?: number;
    cpu?: number;
    swap?: number;
    io?: number;
    databases?: number;
    backups?: number;
    allocations?: number;
    environment?: Record<string, string | number | boolean>;
    secretEnvironment?: SecretRef[];
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

    // Secrets (a game's server/RCON password) come from the vault, never from
    // the caller — resolved here, used in the body below, and never reported.
    const secrets = await this.secrets(input.secretEnvironment, "secretEnvironment");
    const supplied: Record<string, string | number | boolean> = { ...(input.environment ?? {}) };
    for (const s of secrets) supplied[s.name] = s.value; // a secret wins a name collision

    // The egg's own variables decide the environment. Sending only what the
    // caller named would blank every other variable — see buildEnvironment.
    const { environment, defaulted } = buildEnvironment(await this.eggVariables(egg.id), supplied);

    // Extra ports (a game's query port, RCON, …). Pelican accepts these at
    // creation as `allocation.additional`; the alternative route takes no port
    // argument and picks from the free pool at random, which is no good when a
    // specific port is what the game needs.
    const additional: number[] = [];
    for (const ref of input.additionalAllocations ?? []) {
      const { alloc: extra } = await this.resolveAllocation(ref);
      if (extra.id === alloc.id) throw new Error(`Allocation '${ref}' is already the default allocation; list it only once.`);
      if (additional.includes(extra.id)) throw new Error(`Allocation '${ref}' is listed twice in additionalAllocations.`);
      additional.push(extra.id);
    }
    const allocationLimit = input.allocations ?? 1 + additional.length;
    if (allocationLimit < 1 + additional.length) {
      throw new Error(
        `allocations is ${allocationLimit} but this server needs ${1 + additional.length} (the default plus ${additional.length} additional). ` +
          `Raise it, or pass fewer additionalAllocations.`,
      );
    }

    const body = {
      name: input.name.trim(),
      description: input.description ?? "",
      user: owner,
      egg: egg.id,
      // `environment` is `present|array` — always send it, even empty, or the
      // request fails validation before it reaches the egg's own variable rules.
      environment,
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
        allocations: allocationLimit,
        backups: input.backups ?? 1,
      },
      allocation: { default: alloc.id, ...(additional.length ? { additional } : {}) },
      start_on_completion: input.startOnCompletion ?? false,
    };
    const path = "/servers";
    const res = await this.request("application", path, { method: "POST", body });
    this.ensureOk(res, path);
    const created: Partial<Server> = (res.json as { attributes?: Server })?.attributes ?? {};
    return (
      `Created Pelican server '${created.name ?? input.name}' [id ${created.id ?? "?"}] identifier=${created.identifier ?? "?"} uuid=${created.uuid ?? "?"} ` +
      `on egg '${egg.name ?? egg.id}', allocation ${alloc.ip}:${alloc.port} [${alloc.id}]` +
      `${additional.length ? ` plus ${additional.length} additional allocation(s) [${additional.join(", ")}]` : ""}, owner user ${owner}. ` +
      `${defaulted.length ? `${defaulted.length} egg variable(s) took their default: ${defaulted.join(", ")} (values not echoed). ` : "Every egg variable was supplied explicitly. "}` +
      `${secrets.length ? `${secrets.length} variable(s) were filled from the vault: ${secrets.map((s) => s.name).join(", ")}. ` : ""}` +
      `The panel installs it in the background — poll server_resources (or list_servers) until it leaves 'installing'. ` +
      `Use the identifier/uuid (not the numeric id) for power, startup and schedule tools.` +
      (await this.fingerprints(secrets))
    );
  }

  /**
   * Update a server's startup settings through the APPLICATION API, which the
   * panel runs at admin level — the only route that can write a variable the egg
   * marks `user_editable: false` (a game's appid, library path, console filter).
   * The Client API's per-variable route answers HTTP 400 "read-only" for those,
   * so this is the repair path when such a variable is wrong or blank.
   *
   * The route takes `environment` as the WHOLE map and replaces it, which is the
   * same shape that blanks variables on create. So this reads the server's
   * current environment and the egg's defaults and sends a complete, merged set:
   *  - a variable the caller names takes the caller's value;
   *  - one currently holding a real value keeps it;
   *  - one currently BLANK falls back to the egg's default, which repairs a
   *    server damaged by an earlier partial write. Those are reported by name.
   */
  async updateServerStartup(input: {
    id: number;
    variables?: Record<string, string | number | boolean>;
    secretVariables?: SecretRef[];
    startup?: string;
    dockerImage?: string;
    skipScripts?: boolean;
  }): Promise<string> {
    const server = await this.item<Server>("application", `/servers/${input.id}`);
    if (!server?.id) throw new Error(`No Pelican server with id ${input.id}. Use list_servers — this tool takes the NUMERIC id, not the identifier.`);
    const eggId = Number(server.egg);
    if (!Number.isFinite(eggId)) throw new Error(`Pelican server ${input.id} has no egg id; cannot resolve its variables.`);

    const variables = await this.eggVariables(eggId);
    const current = ((server.container as { environment?: Record<string, unknown> } | undefined)?.environment ?? {}) as Record<string, unknown>;

    const secrets = await this.secrets(input.secretVariables, "secretVariables");
    const supplied: Record<string, string | number | boolean> = { ...(input.variables ?? {}) };
    for (const s of secrets) supplied[s.name] = s.value; // a secret wins a name collision
    // Reuse buildEnvironment for the unknown-name check and the default fill…
    const { environment } = buildEnvironment(variables, supplied);
    // …then let any real current value win over the default, so this is a
    // partial update rather than a reset. A BLANK current value deliberately
    // does not win — that is the damage being repaired.
    const healed: string[] = [];
    for (const variable of variables) {
      const name = variable.env_variable;
      if (Object.prototype.hasOwnProperty.call(supplied, name)) continue;
      const live = current[name];
      if (typeof live === "string" && live !== "") {
        environment[name] = live;
      } else if (environment[name] !== "") {
        healed.push(name); // was blank, now restored to the egg's default
      }
    }

    const path = `/servers/${input.id}/startup`;
    const res = await this.request("application", path, {
      method: "PATCH",
      body: {
        egg: eggId, // required by the route; send the CURRENT egg so this never migrates the server
        environment,
        skip_scripts: input.skipScripts ?? false,
        ...(input.startup ? { startup: input.startup } : {}),
        ...(input.dockerImage ? { image: input.dockerImage } : {}),
      },
    });
    this.ensureOk(res, path);

    const changed = Object.keys(supplied);
    return (
      `Updated startup on Pelican server '${server.name ?? input.id}' [${input.id}] via the admin API. ` +
      `${changed.length ? `Set: ${changed.join(", ")} (values not echoed). ` : "No variable values were changed. "}` +
      `${secrets.length ? `${secrets.length} of those came from the vault: ${secrets.map((s) => s.name).join(", ")}. ` : ""}` +
      `${healed.length ? `Restored ${healed.length} blank variable(s) to the egg's default: ${healed.join(", ")}. ` : ""}` +
      `${input.startup ? "Startup command replaced. " : ""}${input.dockerImage ? `Docker image set to ${input.dockerImage}. ` : ""}` +
      `Variables are read at boot, and a changed appid or library path only takes effect after a REINSTALL — restart alone is not enough.` +
      (await this.fingerprints(secrets))
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
  async updateStartupVariables(
    ref: string,
    variables: Record<string, string | number | boolean> = {},
    secretRefs?: SecretRef[],
  ): Promise<string> {
    const secrets = await this.secrets(secretRefs, "secretVariables");
    const merged: Record<string, string | number | boolean> = { ...variables };
    for (const s of secrets) merged[s.name] = s.value; // a secret wins a name collision
    const keys = Object.keys(merged);
    if (!keys.length) throw new Error("update_startup_variables needs at least one variable (or one secretVariables entry).");
    const done: string[] = [];
    for (const key of keys) {
      const path = `/servers/${encodeURIComponent(ref)}/startup/variable`;
      const res = await this.request("client", path, { method: "PUT", body: { key, value: String(merged[key]) } });
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
      `${secrets.length ? `${secrets.length} of those came from the vault: ${secrets.map((s) => s.name).join(", ")}. ` : ""}` +
      `Most eggs only read startup variables at boot — restart the server for them to take effect.` +
      (await this.fingerprints(secrets))
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

/** Installed version + latest release, for the panel's own host. */
async function panelVersion(ctx: ToolContext): Promise<string> {
  const host = await panelHost(ctx);
  const cmd = `grep -m1 "'version'" ${host.path}/config/app.php`;
  const res = await runOnPanelHost(host, cmd);
  if (res.code !== 0) {
    throw new Error(
      `Could not read ${host.path}/config/app.php on '${host.target.name}' (exit ${res.code}): ${res.stderr.trim().slice(0, 200)}. ` +
        `Check the target's 'panelPath' option points at the panel install.`,
    );
  }
  const installed = parsePanelVersion(res.stdout);
  if (!installed) {
    throw new Error(`Read ${host.path}/config/app.php but found no version line in it. The install may be laid out differently than expected.`);
  }

  const latest = await latestPanelRelease();
  if (!latest.tag) {
    return (
      `Pelican panel ${host.target.name === ctx.target.name ? "" : `(host '${host.target.name}') `}is running **${installed}**. ` +
      `Could not reach GitHub for the latest release (${latest.error}), so I can't say whether that is current.`
    );
  }
  const cmp = compareVersions(installed, latest.tag);
  const verdict =
    cmp === undefined
      ? `Could not compare '${installed}' with '${latest.tag}' — the version shapes differ, so check by hand rather than trusting a guess.`
      : cmp < 0
        ? `An upgrade is available. Run panel_upgrade (it takes the current version as confirmation).`
        : cmp === 0
          ? `That is the latest release.`
          : `Installed is NEWER than the latest release — likely a pre-release or a local build.`;
  return `Pelican panel on host '${host.target.name}': installed **${installed}**, latest released **${latest.tag}**. ${verdict}`;
}

/**
 * Back up the panel database before an upgrade, because `migrate` is the step
 * with no undo. The engine is read from `.env`'s DB_CONNECTION — only that one
 * line, never the whole file, which holds the app key and DB password.
 *
 * For MySQL/MariaDB the dump sources `.env` **on the panel host** inside the
 * remote shell, so the password is expanded there and never crosses the wire,
 * the audit log, or the model context — the command text contains variable
 * names only.
 */
async function backupPanelDatabase(host: PanelHost): Promise<string> {
  const detect = await runOnPanelHost(host, `grep -m1 '^DB_CONNECTION=' ${host.path}/.env`);
  const engine = (detect.stdout.split("=")[1] ?? "").trim().toLowerCase().replace(/["']/g, "");
  const stamp = "$(date +%Y%m%d-%H%M%S)";

  let command: string;
  let where: string;
  if (engine === "sqlite") {
    where = `${host.path}/storage/pelican-db-backup-<timestamp>.sqlite`;
    command = `cd ${host.path} && sudo -n -u ${host.user} cp database/database.sqlite storage/pelican-db-backup-${stamp}.sqlite`;
  } else if (engine === "mysql" || engine === "mariadb") {
    where = `${host.path}/storage/pelican-db-backup-<timestamp>.sql`;
    command =
      `cd ${host.path} && sudo -n -u ${host.user} bash -c 'set -a; . ./.env; set +a; ` +
      `mysqldump --no-tablespaces -h "$DB_HOST" -P "\${DB_PORT:-3306}" -u "$DB_USERNAME" -p"$DB_PASSWORD" "$DB_DATABASE" ` +
      `> storage/pelican-db-backup-${stamp}.sql'`;
  } else {
    throw new Error(
      `Refusing to upgrade: could not determine the panel's database engine from ${host.path}/.env (DB_CONNECTION='${engine || "unset"}'). ` +
        `Only sqlite, mysql and mariadb are handled here, and 'migrate' has no undo — take a backup yourself before upgrading.`,
    );
  }

  const res = await runOnPanelHost(host, command, 600_000);
  if (res.code !== 0) {
    const hint = looksLikeSudoPasswordFailure(res.stderr) ? ` ${sudoHint("php", host.cred.username ?? "<ssh-user>")}` : "";
    throw new Error(`Refusing to upgrade: the ${engine} database backup FAILED (exit ${res.code}): ${res.stderr.trim().slice(0, 300)}.${hint}`);
  }
  return where;
}

/** Run the documented upgrade, stopping at the first failing step. */
async function panelUpgrade(ctx: ToolContext, input: { expectVersion: string; skipBackup?: boolean }): Promise<string> {
  const host = await panelHost(ctx);

  // Stale-id guard, same shape as delete_schedule: the caller says which version
  // it believes is installed, and a mismatch means its picture is out of date.
  const before = await runOnPanelHost(host, `grep -m1 "'version'" ${host.path}/config/app.php`);
  const installed = parsePanelVersion(before.stdout);
  if (!installed) throw new Error(`Could not read the installed version from ${host.path}/config/app.php; refusing to upgrade blind.`);
  if (installed !== input.expectVersion.trim()) {
    throw new Error(
      `Refusing to upgrade: you said the panel is on '${input.expectVersion}', but it is actually on '${installed}'. ` +
        `Run panel_version and re-confirm — a stale picture is exactly when an upgrade goes wrong.`,
    );
  }

  const backupAt = input.skipBackup ? null : await backupPanelDatabase(host);

  const done: string[] = [];
  const notes: string[] = [];
  for (const step of PANEL_UPGRADE_STEPS) {
    const res = await runOnPanelHost(host, renderStep(step.command, host), step.timeoutMs);
    if (res.code !== 0) {
      const hint = looksLikeSudoPasswordFailure(res.stderr) ? ` ${sudoHint("php", host.cred.username ?? "<ssh-user>")}` : "";
      throw new Error(
        `Panel upgrade FAILED at step '${step.name}' (exit ${res.code}): ${res.stderr.trim().slice(0, 400)}.${hint} ` +
          `Steps completed: ${done.join(", ") || "none"}. ` +
          `${done.includes("maintenance-mode") && !done.includes("exit-maintenance") ? `The panel is still in MAINTENANCE MODE — it will not serve until 'php artisan up' runs in ${host.path}. ` : ""}` +
          `${backupAt ? `The pre-upgrade database backup is at ${backupAt}. ` : "No database backup was taken (skipBackup was set). "}` +
          `Fix the cause on the host, then re-run panel_upgrade.`,
      );
    }
    if (step.capture && res.stdout.trim()) notes.push(`${step.name}: ${res.stdout.trim().split("\n").slice(-3).join(" | ").slice(0, 200)}`);
    done.push(step.name);
  }

  const after = await runOnPanelHost(host, `grep -m1 "'version'" ${host.path}/config/app.php`);
  const now = parsePanelVersion(after.stdout) ?? "(unreadable)";
  return (
    `Upgraded the Pelican panel on host '${host.target.name}': **${installed} → ${now}**. ` +
    `${now === installed ? "WARNING: the version did not change — the release may already have been installed, or the extract step did not replace the files. " : ""}` +
    `All ${done.length} steps completed (${done.join(", ")}), and the panel is out of maintenance mode. ` +
    `${backupAt ? `Pre-upgrade database backup: ${backupAt}. ` : "No database backup was taken. "}` +
    `${notes.length ? `Notes — ${notes.join("; ")}. ` : ""}` +
    `Verify with panel_version and by loading the panel; if anything looks wrong, the backup above is the rollback point.`
  );
}

async function withClient<T>(ctx: ToolContext, fn: (p: Pelican) => Promise<T>): Promise<T> {
  const cred = await ctx.getCredential();
  return fn(new Pelican(ctx.target, cred, ctx));
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

/**
 * A vault-backed variable value. This is the ONLY way to set a game's password,
 * RCON password or API token: the tools take no secret values, so nothing
 * sensitive ever enters the chat/MCP channel or the model context. Mirrors
 * Portainer's `secretEnv`.
 */
const secretVariableSchema = z.object({
  name: z.string().regex(/^[A-Za-z_][A-Za-z0-9_]*$/, "Egg variable name, e.g. PASSWORD."),
  credentialRef: z.string().min(1).describe("Name of the Vaultwarden item holding the secret."),
  field: z
    .string()
    .optional()
    .describe("Which part of the item: username|password|secret|notes, or a custom field name. Default: password, else secret, else the 'token' field."),
});
const SECRET_VARS_DOC =
  "Variables whose values are read from the vault at call time: [{name, credentialRef, field?}]. The value never appears in chat, " +
  "results, audit logs or the model context — only a keyed fingerprint you can compare with the vault's. Wins over a same-named plain " +
  "variable. NEVER put a password in the plain variables map; use request_credential to get it into the vault, then reference it here.";

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
        `short identifier + uuid (for every power/startup/schedule tool, which use the Client API). Each server is also marked ` +
        `client=YES/NO — the Client API only sees servers its key's user owns or is a subuser on, so a client=NO server will 404 ` +
        `on power, startup, resources and schedules even though it is listed here.`,
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
      name: "panel_version",
      description:
        `Report the Pelican panel's installed version on ${target.name} and the latest released version. Pelican has NO version endpoint ` +
        `on any API half, so the installed version is read from config/app.php over SSH — this needs the target's 'sshTarget' option ` +
        `pointing at the registered ssh target for the panel's host. The latest release comes from the same GitHub endpoint the panel's ` +
        `own "update available" banner uses.`,
      tier: "read",
      inputSchema: z.object({}),
      run: async (_input, ctx) => {
        try {
          return ok(await panelVersion(ctx));
        } catch (e) {
          return { text: `Pelican error: ${e instanceof Error ? e.message : String(e)}`, isError: true };
        }
      },
    },
    {
      name: "panel_upgrade",
      description:
        `Upgrade the Pelican panel itself on ${target.name} to the latest release. This is HOST-LEVEL work over SSH (the panel has no ` +
        `upgrade endpoint), so it needs the target's 'sshTarget' option. Run panel_version first and pass its installed version as ` +
        `expectVersion — a mismatch is refused. It takes a database backup, then runs Pelican's documented sequence: maintenance mode, ` +
        `download, extract, composer install, migrate, clear caches, restart queue, up. artisan/composer run as the panel user, never ` +
        `root. On any failure it STOPS, names the step, and leaves the panel in maintenance mode rather than half-upgraded and serving.`,
      tier: "execute",
      inputSchema: z.object({
        expectVersion: z.string().min(1).describe("The currently installed version, exactly as panel_version reports it. A mismatch aborts."),
        skipBackup: z
          .boolean()
          .optional()
          .describe("Skip the pre-upgrade database backup. Default false. 'migrate' has no undo, so only set this if you have your own backup."),
      }),
      confirm: (input, t) => {
        const i = input as { expectVersion: string; skipBackup?: boolean };
        const o = options(t);
        return (
          `UPGRADE the Pelican panel itself on host '${o.sshTarget ?? "(no sshTarget set)"}' from ${i.expectVersion} to the latest release ` +
          `(${o.panelPath}) — runs database migrations, takes the panel down during the upgrade` +
          `${i.skipBackup ? ", and SKIPS the database backup" : ""}`
        );
      },
      run: async (input, ctx) => {
        try {
          return ok(await panelUpgrade(ctx, input as { expectVersion: string; skipBackup?: boolean }));
        } catch (e) {
          return { text: `Pelican error: ${e instanceof Error ? e.message : String(e)}`, isError: true };
        }
      },
    },
    {
      name: "create_allocations",
      description:
        `Create IP:port allocations on a Pelican node on ${target.name}. create_server can only use an allocation that already ` +
        `exists, so this is the step that makes room for a game the panel has never hosted (e.g. Valheim's 2456-2458/udp). Takes ` +
        `the node's own literal IPv4 and a list of ports — single ('2456') or ranges ('2456-2458', both endpoints 4-5 digits). ` +
        `Ports already present on the node are refused up front, because Pelican inserts without checking and a duplicate is a ` +
        `server error. The panel returns no content, so the new allocation ids are read back and reported.`,
      tier: "execute",
      inputSchema: z.object({
        node: z.number().int().positive().describe("Node id from list_nodes."),
        ip: z.string().describe("The node's literal IPv4, exactly as list_allocations prints it (e.g. '192.168.0.48'). CIDR is refused."),
        ports: z
          .array(z.string())
          .min(1)
          // Bounded here too: a spec yields at least one port, so more specs than
          // the cap can never be valid, and the schema rejects it before any
          // expansion runs at all.
          .max(MAX_PORTS_PER_CALL)
          .describe(`Ports: '2456' or '2456-2458'. Range endpoints must be 4-5 digits. ${PORT_FLOOR}-${PORT_CEIL}, max ${MAX_PORTS_PER_CALL} per call.`),
        alias: z.string().max(255).optional().describe("Optional display alias for these allocations, e.g. 'valheim'."),
      }),
      confirm: (input, t) => {
        const i = input as { node: number; ip: string; ports: string[]; alias?: string };
        let count: string;
        try {
          count = `${expandPorts(i.ports).length} port(s)`;
        } catch {
          count = "an invalid port list";
        }
        return `Create allocations on Pelican node ${i.node} on ${t.name}: ${i.ip} ports ${i.ports.join(", ")} (${count})${i.alias ? ` alias '${i.alias}'` : ""}`;
      },
      run: run((p, i) => p.createAllocations(i)),
    },
    {
      name: "import_egg",
      description:
        `Import an egg (a game's server template) onto ${target.name}, so create_server can provision a game the panel does not ` +
        `yet have. Give either a public https 'url' to an egg export (e.g. a raw GitHub link — LAN/http URLs are refused) or the ` +
        `egg JSON/YAML itself as 'content'. IMPORTANT: Pelican keys imports on the egg's uuid, and an existing uuid means it ` +
        `REWRITES that egg in place and deletes any variable the file omits — so a uuid already on the panel is refused unless ` +
        `you pass overwrite: true, and the refusal names the servers built on it. Run list_eggs afterwards to get the egg id.`,
      tier: "execute",
      inputSchema: z.object({
        url: z.string().optional().describe("Public https URL of an egg export (JSON or YAML). Exactly one of url/content."),
        content: z.string().optional().describe("The egg export itself, as JSON or YAML text. Exactly one of url/content."),
        overwrite: z
          .boolean()
          .optional()
          .describe("Allow replacing an existing egg with the same uuid (destructive: drops variables the file omits). Default false."),
      }),
      confirm: (input, t) => {
        const i = input as { url?: string; content?: string; overwrite?: boolean };
        const src = i.url ? `from ${i.url}` : "from supplied content";
        return i.overwrite
          ? `Import egg ${src} into ${t.name}, OVERWRITING any existing egg with the same uuid (its variables not in the file are deleted)`
          : `Import a new egg ${src} into ${t.name}`;
      },
      run: run((p, i) => p.importEgg(i)),
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
        additionalAllocations: z
          .array(z.string())
          .optional()
          .describe(
            "Extra FREE allocations to attach at creation (ids or 'ip:port'), e.g. a game's query port. Use this rather than assign_allocation, which takes no port argument and picks from the free pool at random.",
          ),
        memory: z.number().int().min(0).optional().describe("Memory limit MiB (default 4096; 0 = unlimited)."),
        disk: z.number().int().min(0).optional().describe("Disk limit MiB (default 10240; 0 = unlimited)."),
        cpu: z.number().int().min(0).optional().describe("CPU limit % (default 0 = unlimited)."),
        swap: z.number().int().optional().describe("Swap MiB (default 0)."),
        io: z.number().int().optional().describe("Block IO weight (default 500)."),
        databases: z.number().int().min(0).optional().describe("Database limit (default 0)."),
        backups: z.number().int().min(0).optional().describe("Backup limit (default 1)."),
        allocations: z.number().int().min(1).optional().describe("Max allocations this server may hold (default: 1 + additionalAllocations)."),
        environment: z
          .record(z.union([z.string(), z.number(), z.boolean()]))
          .optional()
          .describe("Egg variables to override, e.g. {SERVER_NAME:'x'}. Anything you omit takes the EGG'S DEFAULT — you do not need to list them all, and an unknown name is refused."),
        secretEnvironment: z.array(secretVariableSchema).optional().describe(SECRET_VARS_DOC),
        dockerImage: z.string().optional().describe("Override the egg's default docker image."),
        startup: z.string().optional().describe("Override the egg's startup command."),
        description: z.string().optional(),
        startOnCompletion: z.boolean().optional().describe("Start the server once installation finishes. Default false."),
      }),
      confirm: (input, t) => {
        const i = input as { name: string; egg: string; allocation: string; secretEnvironment?: SecretRef[] };
        const o = options(t).ownerUserId;
        const fromVault = (i.secretEnvironment ?? []).map(describeSecretRef);
        return (
          `Create Pelican server '${i.name}' (egg '${i.egg}', allocation ${i.allocation}, owner user ${o ?? "?"}) on ${t.name}` +
          (fromVault.length ? `, with ${fromVault.join(", ")}` : "")
        );
      },
      run: run((p, i) => p.createServer(i)),
    },
    {
      name: "update_server_startup",
      description:
        `Set a Pelican server's startup variables on ${target.name} through the ADMIN (application) API, by NUMERIC server id. ` +
        `Unlike update_startup_variables — which goes through the Client API and answers HTTP 400 'read-only' for variables the egg ` +
        `marks user_editable:false (a game's appid, library path, console filter) — this route runs at admin level and can write them. ` +
        `It is a partial update: variables you don't name keep their current value, EXCEPT ones currently blank, which are restored to ` +
        `the egg's default and reported (that repairs a server damaged by an earlier partial write). Can also replace the startup ` +
        `command or docker image. A changed appid or library path needs a REINSTALL, not just a restart.`,
      tier: "execute",
      inputSchema: z.object({
        id: z.number().int().positive().describe("Numeric application server id from list_servers (NOT the short identifier)."),
        variables: z
          .record(z.union([z.string(), z.number(), z.boolean()]))
          .optional()
          .describe("Variable name → value. Unknown names are refused. Omitted variables keep their current value."),
        secretVariables: z.array(secretVariableSchema).optional().describe(SECRET_VARS_DOC),
        startup: z.string().optional().describe("Replace the startup command. Omit to leave it alone."),
        dockerImage: z.string().optional().describe("Replace the docker image. Omit to leave it alone."),
        skipScripts: z.boolean().optional().describe("Skip the egg's install script on the next install. Default false."),
      }),
      confirm: (input, t) => {
        const i = input as { id: number; variables?: Record<string, unknown>; secretVariables?: SecretRef[]; startup?: string; dockerImage?: string };
        // Names only — a startup variable's VALUE is frequently a password.
        const names = [...Object.keys(i.variables ?? {}), ...(i.secretVariables ?? []).map(describeSecretRef)];
        const parts = [
          names.length ? `variables [${names.join(", ")}]` : null,
          i.startup ? "a new startup command" : null,
          i.dockerImage ? `image ${i.dockerImage}` : null,
        ].filter(Boolean);
        return `Set ${parts.join(" + ") || "nothing"} on Pelican server [${i.id}] on ${t.name} via the admin API (can write read-only variables; values not shown)`;
      },
      run: run((p, i) => p.updateServerStartup(i)),
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
        variables: z
          .record(z.union([z.string(), z.number(), z.boolean()]))
          .optional()
          .describe("Non-secret variable name → value, e.g. {SERVER_NAME:'x', MAX_PLAYERS:10}."),
        secretVariables: z.array(secretVariableSchema).optional().describe(SECRET_VARS_DOC),
      }),
      confirm: (input, t) => {
        const i = input as { server: string; variables?: Record<string, unknown>; secretVariables?: SecretRef[] };
        // Names only — a startup variable's VALUE is frequently a password. A
        // vault-backed one names its ITEM too, so the approval says where the
        // secret comes from without revealing it.
        const names = [...Object.keys(i.variables ?? {}), ...(i.secretVariables ?? []).map(describeSecretRef)];
        return `Set startup variables [${names.join(", ")}] on Pelican server '${i.server}' on ${t.name} (values not shown)`;
      },
      run: run((p, i) => p.updateStartupVariables(i.server, i.variables, i.secretVariables)),
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
