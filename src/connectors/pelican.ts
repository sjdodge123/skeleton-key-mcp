import { z } from "zod";
import yaml from "js-yaml";
import type { Connector, ConnectorTool, Credential, SnapshotArtifact, Target, ToolContext, ToolResult } from "./types.js";
import { deriveBaseUrl, tlsFetch, isPrivateIPv4 } from "./net.js";
import { runSsh, MAX_SSH_TIMEOUT_MS, type SshExecResult } from "./ssh-exec.js";
import { checkCommand } from "./command-policy.js";
import { resolveSecretRefs, secretFingerprintBlock, describeSecretRef, type SecretRef, type SecretValue } from "./secret-refs.js";
import { withKuma, monitorsForServer, MANAGED_PELICAN_TAG, type ServerIdentity } from "./uptime-kuma-client.js";
import { kumaConnectOptions, resumeExactly, resumeUnconditionally } from "./uptime-kuma.js";
import {
  HELPER_PATH,
  HOST_STATUS_COMMAND,
  currentPhpRequirementCommand,
  helperCommand,
  parseHostStatus,
  parseUpgradeResult,
  hostStatusProblem,
  classifyHelperFailure,
  helperFailureText,
  composerPhpRequirement,
  fetchReleasePhpRequirement,
  latestWingsRelease,
  phpSatisfies,
  phpVersionFor,
  assertPhpVersionArg,
  assertWingsTag,
  assertReleaseTag,
  runtimeReport,
  sshUserOf,
  compareVersions,
  phpPackagePolicyCommand,
  parseAptPolicy,
  servingPhpMinor,
  type AptPolicy,
  type HostStatus,
} from "./pelican-host.js";
export { compareVersions } from "./pelican-host.js";

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
     * installed on. Required by `panel_version`, `panel_upgrade`,
     * `panel_prepare_runtime` and `wings_update`: Pelican
     * exposes no version or upgrade endpoint on ANY of its API surfaces
     * (application, client, web, remote) — it reads its own version from
     * `config/app.php` and checks GitHub in the browser — so those two are
     * necessarily host-level work rather than API calls.
     */
    sshTarget: z.string().optional(),
    /** Where the panel is installed on that host. Must be an absolute path with
     *  no shell metacharacters — it is interpolated into fixed commands. */
    panelPath: z.string().default("/var/www/pelican"),
    /**
     * Name of the registered **uptime-kuma** target whose monitors watch this
     * panel's game servers — for `power_action`'s `suppressMonitors` (the
     * white-glove rule). Optional: with exactly one uptime-kuma target
     * registered it is found automatically; this disambiguates when there are
     * several.
     */
    monitorsTarget: z.string().optional(),
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

// `isPrivateIPv4` moved to net.ts (the Uptime Kuma transport guard shares it);
// re-exported so existing imports and tests keep working.
export { isPrivateIPv4 };

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
  return assertPublicHttpsUrl(raw, {
    what: "an egg",
    verb: "fetch",
    why: "This tool fetches from inside your network, so it is restricted to public https sources (e.g. raw.githubusercontent.com). Paste the egg via 'content' instead.",
  });
}

/**
 * The one rule behind every URL Skeleton Key (or a daemon it drives) fetches
 * from inside the LAN: https, and a public host — never loopback, private,
 * link-local or a local-only name. The messages are parameterized so each
 * caller can say who makes the request and what to do instead.
 */
function assertPublicHttpsUrl(raw: string, msg: { what: string; verb: string; why: string }): URL {
  let url: URL;
  try {
    url = new URL(raw.trim());
  } catch {
    throw new Error(`Invalid ${msg.what} URL '${raw}'.`);
  }
  if (url.protocol !== "https:") {
    throw new Error(`Refusing to ${msg.verb} ${msg.what} over '${url.protocol}' — use https so it can't be swapped in transit.`);
  }
  const host = url.hostname.replace(/^\[|\]$/g, "").toLowerCase();
  if (isInsideNetworkHost(host)) {
    throw new Error(
      `Refusing to ${msg.verb} ${msg.what} from '${url.hostname}' — that address is loopback, private, link-local or otherwise inside the network. ${msg.why}`,
    );
  }
  return url;
}

// --- Files (client API) ------------------------------------------------------

/** True when a hostname/IP literal points inside the network — loopback,
 *  private, link-local, or a local-only name — the set an in-LAN fetch refuses. */
function isInsideNetworkHost(host: string): boolean {
  return isBlockedFetchIPv4(host) || isBlockedFetchIPv6(host) || isLocalHostname(host);
}

/**
 * A path inside a server's volume, for the client file routes. Wings resolves
 * every path against the volume root and refuses escapes itself; refusing `..`,
 * `.` and control characters HERE keeps a cryptic daemon error out of the loop
 * and keeps the approval prompt honest about what will be touched. Backslashes
 * are allowed on purpose: a Thunderstore zip built on Windows carries entries
 * like `plugins\Jotunn.dll`, which Wings extracts as ONE file with that literal
 * name, and the only way to fix it is to rename it by that name. Exported for
 * testing.
 */
export function assertVolumePath(path: string, field: string, opts: { allowRoot?: boolean } = {}): string {
  const trimmed = path.trim();
  const inner = trimmed.replace(/^\/+|\/+$/g, "");
  if (inner === "") {
    if (opts.allowRoot) return "/";
    throw new Error(`'${field}' must name a file or directory inside the server, not the volume root.`);
  }
  // eslint-disable-next-line no-control-regex
  if (/[\u0000-\u001f\u007f]/.test(trimmed)) throw new Error(`'${field}' contains control characters.`);
  for (const seg of inner.split("/")) {
    if (seg === "..") throw new Error(`'${field}' must stay inside the server's volume — '..' is refused (got '${path}').`);
    if (seg === "." || seg === "") throw new Error(`'${field}' has an empty or '.' path segment (got '${path}').`);
  }
  return trimmed;
}

/** Glob characters mean nothing to Wings, but refusing them keeps a stray `*`
 *  from reading as "everything" in an approval prompt. Exported for testing. */
export function assertExactName(name: string, field: string): string {
  if (/[*?[\]]/.test(name)) throw new Error(`'${field}' must be an exact name, not a pattern (got '${name}').`);
  return name;
}

/**
 * Guard a pull URL. The download is made by the WINGS DAEMON, from inside the
 * LAN, so this is the same SSRF shape as `assertEggSourceUrl`: public https
 * only. Wings also refuses URLs that resolve to internal addresses; this just
 * says so before any request is made. Exported for testing.
 */
export function assertPullUrl(raw: string): URL {
  return assertPublicHttpsUrl(raw, {
    what: "a download",
    verb: "pull",
    why: "The download is made by the Wings daemon from inside your LAN, so it is restricted to public https sources (e.g. thunderstore.io).",
  });
}

const FILE_READ_DEFAULT_BYTES = 64 * 1024;
/** Hard cap on what read_file returns — a log can be megabytes; the model context is not where it goes. */
export const FILE_READ_MAX_BYTES = 256 * 1024;
/** write_file is for config files; anything bigger is a download, not a chat payload. */
export const FILE_WRITE_MAX_BYTES = 512 * 1024;
/** How pull_file watches a download land. `appearWithinMs` is how long a file
 *  may take to show up at all — Wings creates it before streaming, so a long
 *  absence means the download never started (a Wings-side refusal that the
 *  panel reported as a generic error). Mutable so tests don't wait. */
export const FILE_PULL_POLL = { intervalMs: 2000, maxWaitMs: 180_000, appearWithinMs: 30_000 };

const pauseMs = (ms: number): Promise<void> => new Promise((resolve) => setTimeout(resolve, ms));

/** One entry of the panel's `files/list` (FileObjectTransformer). */
interface FileObject {
  name: string;
  mode?: string;
  size?: number;
  is_file?: boolean;
  is_symlink?: boolean;
  mimetype?: string;
  modified_at?: string;
}

/** Directory listing, folders first. Exported for testing. */
export function summarizeFiles(dir: string, files: FileObject[]): string {
  if (!files.length) return `${dir}: (empty)`;
  const isDir = (f: FileObject) => f.is_file === false;
  const sorted = [...files].sort((a, b) => Number(!isDir(a)) - Number(!isDir(b)) || a.name.localeCompare(b.name));
  const MAX = 400;
  const lines = sorted.slice(0, MAX).map((f) => {
    const when = (f.modified_at ?? "").slice(0, 16).replace("T", " ");
    return isDir(f)
      ? `  ${"<dir>".padStart(10)}  ${when}  ${f.name}/`
      : `  ${String(f.size ?? 0).padStart(10)}  ${when}  ${f.name}${f.is_symlink ? "  (symlink)" : ""}`;
  });
  const more = files.length > MAX ? `\n  … ${files.length - MAX} more entries (list a subdirectory instead)` : "";
  return `${dir} — ${files.length} entries (bytes, modified, name):\n${lines.join("\n")}${more}`;
}

const SECRET_LINE_KEY = "(?:pass(?:word|wd|phrase)?|token|secret|api[_-]?key|private[_-]?key|credential)";
/** `key = value`, `key: value` — a secret-named key alone on the left, allowing a
 *  comment marker (a commented-out password is still a password) and a shell
 *  `export` / batch `set` prefix. */
const KV_LINE = new RegExp(
  `^(\\s*(?:[#;]+\\s*|//\\s*)?(?:(?:export|set)\\s+)?["']?[A-Za-z0-9_.-]*${SECRET_LINE_KEY}[A-Za-z0-9_.-]*["']?\\s*[=:]\\s*)(.+)$`,
  "i",
);
/** `-password x`, `--token=x`, `+sv_password x`, `-rconpassword x` — a start
 *  script's or cvar list's command line. */
const FLAG_ARG = new RegExp(`((?:^|\\s)[-+]{1,2}[A-Za-z0-9_.]*${SECRET_LINE_KEY}(?:=|\\s+))("[^"]*"|'[^']*'|\\S+)`, "gi");

/**
 * Mask secret-looking values in file text before it reaches the model context.
 * A server's files are where its passwords live — a game's `-password "x"` in a
 * start script, `rcon_password=` in a cfg, a token in a `.env` — and a read tool
 * must not become the channel that leaks them into chat. A heuristic by nature:
 * it masks the value after a secret-named `key=` / `key:`, and the argument
 * after a `-password` / `--token`-style flag; everything else passes untouched.
 * Exported for testing.
 */
export function redactFileLines(text: string): string {
  return text
    .split("\n")
    .map((line) => line.replace(KV_LINE, (_m, pre: string) => `${pre}[redacted]`).replace(FLAG_ARG, (_m, pre: string) => `${pre}[redacted]`))
    .join("\n");
}

/**
 * The panel proxies file calls to Wings with a 15-second timeout
 * (`panel.guzzle.timeout`, verified in the live config). A foreground pull that
 * outlives it comes back as a daemon connection error even though Wings keeps
 * downloading — so that one shape is "still running", not "failed".
 *
 * Telling the two apart needs the envelope's `code`, not its text: the live
 * panel's Handler renders any non-HTTP exception as a 500 whose `detail` is the
 * generic "An unexpected error was encountered…" and whose `code` is the
 * exception's class name — `ConnectionException` for a timeout (Laravel's HTTP
 * client could not get an answer), `RequestException` when Wings DID answer,
 * with an error (bad URL, internal address, disk limit). The latter is a real
 * failure and must surface at once. Exported for testing.
 */
export function looksLikeDaemonTimeout(res: { ok: boolean; status: number; json?: unknown; text: string }): boolean {
  if (res.ok) return false;
  const codes = ((res.json as { errors?: { code?: string }[] })?.errors ?? []).map((e) => e.code ?? "");
  if (codes.some((c) => /RequestException/i.test(c))) return false;
  if (codes.some((c) => /ConnectionException/i.test(c))) return true;
  return res.status === 502 || res.status === 504 || /timed? ?out|cURL error 28|could not establish a connection|E_CONN/i.test(res.text);
}

/** What `Pelican.request` hands back. `headers` is the live response header
 *  bag: the pull path needs it, because the panel's throttle answer carries
 *  `Retry-After` / `X-RateLimit-Reset` and nothing else says when to retry. */
interface PelicanResponse {
  ok: boolean;
  status: number;
  json?: unknown;
  text: string;
  headers: Pick<Headers, "get">;
}

/** The panel's default `ResourceLimit::FilePull` budget — config/http.php
 *  `file_pull` / `file_pull_period`, env APP_API_FILE_PULL_RATELIMIT and
 *  APP_API_FILE_PULL_RATELIMIT_PERIOD. Per user, so one client key shares it
 *  across every server it reaches. */
export const FILE_PULL_RATE_LIMIT = { pulls: 5, minutes: 10 };

/**
 * Explain a 429 from `files/pull`. Laravel's throttle rejects a request BEFORE
 * counting it, so hammering the route does not push the window out — the only
 * cure is to wait, and the sixth pull in a batch is the usual way to find this
 * out. Whatever the panel says about when (`Retry-After` in seconds,
 * `X-RateLimit-Reset` as a unix timestamp) is passed along, and so is its
 * configured ceiling (`X-RateLimit-Limit`), since an operator may have raised
 * it above the default. Header values are panel-controlled numbers, not
 * secrets, but are still bounded. Exported for testing.
 */
export function filePullThrottleMessage(res: { headers: Pick<Headers, "get"> }, path: string): string {
  const header = (name: string): string | undefined => res.headers.get(name)?.trim().slice(0, 64) || undefined;
  const retryAfter = header("retry-after");
  const reset = header("x-ratelimit-reset");
  const limit = header("x-ratelimit-limit");
  const when: string[] = [];
  // Retry-After is seconds from Laravel; HTTP also allows a date, passed through as-is.
  if (retryAfter) when.push(`Retry-After: ${/^\d+$/.test(retryAfter) ? `${retryAfter}s` : retryAfter}`);
  if (reset) {
    const epoch = Number(reset);
    const iso = Number.isInteger(epoch) && epoch > 0 ? ` (${new Date(epoch * 1000).toISOString()})` : "";
    when.push(`X-RateLimit-Reset: ${reset}${iso}`);
  }
  return (
    `Pelican HTTP 429 on ${path}: the panel throttles file pulls to ${FILE_PULL_RATE_LIMIT.pulls} per ${FILE_PULL_RATE_LIMIT.minutes} minutes per user by default ` +
    `(APP_API_FILE_PULL_RATELIMIT / APP_API_FILE_PULL_RATELIMIT_PERIOD in the panel's .env${limit ? `; this panel reports a limit of ${limit}` : ""}). ` +
    `Rejected attempts are not counted, so retrying does not extend the window — wait for it to pass. ` +
    (when.length
      ? `The panel says: ${when.join(", ")}. `
      : `The panel did not say when the window resets; it opened with the first pull of the current batch. `) +
    `Nothing was downloaded by this call. Plan installs in groups of at most ${FILE_PULL_RATE_LIMIT.pulls} pulls.`
  );
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
  feature_limits?: Record<string, unknown>;
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
/** The build fields `update_server_build` can change, by the panel's names. */
const BUILD_LIMIT_KEYS = ["memory", "swap", "disk", "io", "cpu", "threads"] as const;
const BUILD_FEATURE_KEYS = ["databases", "allocations", "backups"] as const;
type BuildLimitsInput = { memory?: number; swap?: number; disk?: number; io?: number; cpu?: number; threads?: string | null };
type BuildFeatureLimitsInput = { databases?: number; allocations?: number; backups?: number };
type UpdateServerBuildInput = { id: number; limits?: BuildLimitsInput; featureLimits?: BuildFeatureLimitsInput; oomKiller?: boolean };

/** Refuse a key this tool doesn't know. The panel would ignore it and the
 *  caller would believe the change landed. */
function assertKnownKeys(label: string, obj: unknown, known: readonly string[]): void {
  if (!obj || typeof obj !== "object") return;
  const unknown = Object.keys(obj).filter((k) => !known.includes(k));
  if (unknown.length) {
    throw new Error(`Unknown ${label} field(s) ${unknown.map((k) => `'${k}'`).join(", ")} — known: ${known.join(", ")}.`);
  }
}

/** The `path → value` pairs a build update names, in the panel's field names —
 *  shared by the confirm text and the prior → new report so they agree. */
function buildChanges(input: UpdateServerBuildInput): [string, unknown][] {
  const out: [string, unknown][] = [];
  for (const [k, v] of Object.entries(input.limits ?? {})) if (v !== undefined) out.push([`limits.${k}`, v]);
  for (const [k, v] of Object.entries(input.featureLimits ?? {})) if (v !== undefined) out.push([`feature_limits.${k}`, v]);
  if (input.oomKiller !== undefined) out.push(["oom_killer", input.oomKiller]);
  return out;
}

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
    opts: { method?: string; body?: unknown; rawBody?: string; query?: Record<string, string | number>; contentType?: string; signal?: AbortSignal } = {},
  ): Promise<PelicanResponse> {
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
    if (payload !== undefined) headers["Content-Type"] = opts.contentType ?? "application/json";
    const res = await tlsFetch(
      `${this.base}/api/${api}${path}${qs}`,
      { method: opts.method ?? "GET", headers, body: payload, ...(opts.signal ? { signal: opts.signal } : {}) },
      this.insecure,
    );
    const text = await res.text();
    let json: unknown;
    try {
      json = text ? JSON.parse(text) : undefined;
    } catch {
      /* non-JSON body */
    }
    return { ok: res.ok, status: res.status, json, text, headers: res.headers };
  }

  /** Throw on an HTTP error, surfacing Pelican's `{errors:[{detail}]}` envelope
   *  (scrubbed) rather than a bare status. */
  private ensureOk(res: { ok: boolean; status: number; json?: unknown; text: string }, path: string, api?: PelicanApi): void {
    if (res.ok) return;
    const errs = (res.json as { errors?: { detail?: string; code?: string }[] })?.errors;
    // The panel renders any non-HTTP exception with a generic detail and puts the
    // only real information — the exception class — in `code`; surface it then.
    const detail = errs
      ?.map((e) => (e.code && e.detail && /^An unexpected error was encountered/i.test(e.detail) ? `${e.code}: ${e.detail}` : (e.detail ?? e.code)))
      .filter(Boolean)
      .join("; ");
    // A Client-API 404 on a server path almost never means "no such server" — it
    // means the client key's user neither owns it nor is a subuser on it, so the
    // panel hides it entirely. Without this hint the failure looks like a bad id,
    // and list_servers (Application API) cheerfully shows the server, which makes
    // it look like a bug in Skeleton Key rather than a panel permission.
    const hint =
      api === "client" && res.status === 404 && path.includes("/files/")
        ? ` — no such file or directory on the server (list_files to check the path), or the client key's user does not own this server (list_servers marks which it can act on).`
        : api === "client" && res.status === 404 && path.startsWith("/servers/")
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

  private async item<T>(api: PelicanApi, path: string, query: Record<string, string | number> = {}, signal?: AbortSignal): Promise<T> {
    const res = await this.request(api, path, { query, ...(signal ? { signal } : {}) });
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

  /** One server by client ref — its display name and identities, which is how
   *  its Uptime Kuma monitors are matched (name + `managed:pelican` tag, or a
   *  tag naming the identifier/uuid). */
  async clientServer(ref: string): Promise<ServerIdentity> {
    const s = await this.item<{ name?: string; identifier?: string; uuid?: string }>("client", `/servers/${encodeURIComponent(ref)}`);
    return { name: s.name ?? ref, identifier: s.identifier, uuid: s.uuid };
  }

  private resources(ref: string, signal?: AbortSignal): Promise<{ current_state?: string; is_suspended?: boolean; resources?: Record<string, number> }> {
    return this.item("client", `/servers/${encodeURIComponent(ref)}/resources`, {}, signal);
  }

  /** Just the power state and process uptime — what a power-action wait polls.
   *  Bounded by `timeoutMs`: a hung read must not hold paused monitors past the
   *  caller's own deadline. */
  async currentState(ref: string, timeoutMs = 15_000): Promise<{ state?: string; uptimeMs?: number }> {
    const r = await this.resources(ref, AbortSignal.timeout(Math.max(1, timeoutMs)));
    const up = r.resources?.uptime;
    return { state: r.current_state, uptimeMs: typeof up === "number" ? up : undefined };
  }

  /** Live resource usage, by client ref (short identifier or full UUID). */
  async serverResources(ref: string): Promise<string> {
    const r = await this.resources(ref);
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

  /** GET one server by NUMERIC id on the application half, turning the panel's
   *  bare 404 into the "wrong kind of id" message the caller can act on. */
  private async applicationServer(id: number): Promise<Server> {
    const path = `/servers/${id}`;
    const res = await this.request("application", path);
    const notFound = `No Pelican server with id ${id}. Use list_servers — this tool takes the NUMERIC id, not the identifier.`;
    if (res.status === 404) throw new Error(notFound);
    this.ensureOk(res, path, "application");
    const server = (res.json as { attributes?: Server })?.attributes;
    if (!server?.id) throw new Error(notFound);
    return server;
  }

  /**
   * Change a server's build — resource limits, feature limits (backups,
   * databases, allocations) and the OOM killer — through the APPLICATION API,
   * by NUMERIC id. Pelican's `PATCH /servers/{id}/build` wants the WHOLE build
   * on every call (verified against the panel's
   * UpdateServerBuildConfigurationRequest and BuildModificationService on main
   * and v1.0.0-beta35): `feature_limits` is `required`, each `limits.*` is
   * `required_with:limits`, and the service writes `database_limit` /
   * `allocation_limit` / `backup_limit` with a default of 0 — so a request
   * naming only `backups` would silently ZERO the other two. This reads the
   * server, merges the caller's fields over the current values and sends the
   * complete body, then reports prior → new so the change can be reverted. A
   * current value the panel does not return fails the call closed rather than
   * being guessed.
   *
   * Field names follow the request, not the GET: the OOM switch is a top-level
   * boolean `oom_killer`; the `limits.oom_disabled` the GET also returns is its
   * deprecated inverse and is not accepted on write.
   */
  async updateServerBuild(input: UpdateServerBuildInput): Promise<string> {
    // Unknown fields are refused BEFORE any request is made.
    assertKnownKeys("update_server_build", input, ["id", "limits", "featureLimits", "oomKiller"]);
    assertKnownKeys("limits", input.limits, BUILD_LIMIT_KEYS);
    assertKnownKeys("featureLimits", input.featureLimits, BUILD_FEATURE_KEYS);
    const wanted = buildChanges(input);
    if (!wanted.length) throw new Error("update_server_build needs at least one field to change: limits.*, featureLimits.* or oomKiller.");

    const server = await this.applicationServer(input.id);
    const curLimits = (server.limits ?? {}) as Record<string, unknown>;
    const curFeature = (server.feature_limits ?? {}) as Record<string, unknown>;
    /** A current numeric value the full payload must carry. Missing ⇒ fail
     *  closed: the route replaces every limit, and the service writes a missing
     *  feature limit as 0. */
    const reported = (path: string, v: unknown): number => {
      const n = typeof v === "number" ? v : typeof v === "string" && v.trim() !== "" ? Number(v) : NaN;
      if (!Number.isFinite(n)) {
        throw new Error(
          `The panel did not report '${path}' for server ${input.id}, so the full build cannot be rebuilt safely — refusing to guess, ` +
            `because the build route replaces every limit and writes a missing feature limit as 0. Check server_details.`,
        );
      }
      return n;
    };

    const limits: Record<string, number | string | null> = {};
    for (const k of ["memory", "swap", "disk", "io", "cpu"] as const) limits[k] = input.limits?.[k] ?? reported(`limits.${k}`, curLimits[k]);
    // threads is CPU pinning ('0-1,3') or null, and null is a real value (clear
    // the pinning) — so presence, not nullish-ness, decides whether it was set.
    const curThreads = typeof curLimits.threads === "string" && curLimits.threads !== "" ? curLimits.threads : null;
    limits.threads = input.limits && "threads" in input.limits ? (input.limits.threads ?? null) : curThreads;

    const feature: Record<string, number> = {};
    for (const k of BUILD_FEATURE_KEYS) feature[k] = input.featureLimits?.[k] ?? reported(`feature_limits.${k}`, curFeature[k]);

    const curOom =
      typeof curLimits.oom_killer === "boolean" ? curLimits.oom_killer : typeof curLimits.oom_disabled === "boolean" ? !curLimits.oom_disabled : undefined;
    const oomKiller = input.oomKiller ?? curOom;

    // The primary allocation is part of the build: re-send the current one so it
    // never moves. Pelican allows a server with no allocation — then the key is
    // omitted (its rule is sometimes|nullable) rather than invented.
    const allocation = typeof server.allocation === "number" ? server.allocation : undefined;

    const body = {
      ...(allocation !== undefined ? { allocation } : {}),
      ...(oomKiller !== undefined ? { oom_killer: oomKiller } : {}),
      limits,
      feature_limits: feature,
    };
    const path = `/servers/${input.id}/build`;
    const res = await this.request("application", path, { method: "PATCH", body });
    this.ensureOk(res, path, "application");

    const fmt = (v: unknown): string => (v === undefined ? "?" : v === null ? "null" : String(v));
    const priorOf = (p: string): unknown =>
      p === "oom_killer" ? curOom : p === "limits.threads" ? curThreads : p.startsWith("limits.") ? curLimits[p.slice("limits.".length)] : curFeature[p.slice("feature_limits.".length)];
    const diff = wanted.map(([p, next]) => {
      const prior = fmt(priorOf(p));
      return `${p} ${prior} → ${fmt(next)}${prior === fmt(next) ? " (unchanged)" : ""}`;
    });
    const sent =
      `allocation=${allocation ?? "none"}, oom_killer=${fmt(oomKiller)}, ` +
      `limits ${Object.entries(limits).map(([k, v]) => `${k}=${fmt(v)}`).join(" ")}, ` +
      `feature_limits ${Object.entries(feature).map(([k, v]) => `${k}=${v}`).join(" ")}`;
    return (
      `Updated build on Pelican server '${server.name ?? input.id}' [${input.id}] via the admin API: ${diff.join("; ")}. ` +
      `Revert by calling update_server_build with the prior values above. ` +
      `The full build was re-sent so nothing else moved: ${sent}. ` +
      `Feature limits apply at once — a scheduled backup task rotates out the oldest backup once the limit is reached, and lowering it deletes nothing by itself. ` +
      `Resource limits are synced to Wings, which adjusts a running container in place where Docker allows; restart if server_resources still shows the old limit.`
    );
  }

  /** Send a power signal via the Client API. */
  async powerAction(ref: string, signal: string): Promise<string> {
    const path = `/servers/${encodeURIComponent(ref)}/power`;
    const res = await this.request("client", path, { method: "POST", body: { signal }, signal: AbortSignal.timeout(30_000) });
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
  // --- files (client API) --------------------------------------------------

  private filesPath(ref: string, op: string): string {
    return `/servers/${encodeURIComponent(ref)}/files/${op}`;
  }

  private listDir(ref: string, directory: string): Promise<FileObject[]> {
    return this.list<FileObject>("client", this.filesPath(ref, "list"), { directory });
  }

  async listFiles(ref: string, directory = "/"): Promise<string> {
    const dir = assertVolumePath(directory, "directory", { allowRoot: true });
    return summarizeFiles(dir, await this.listDir(ref, dir));
  }

  async readFile(ref: string, file: string, opts: { tail?: number; maxBytes?: number } = {}): Promise<string> {
    const f = assertVolumePath(file, "file");
    const path = this.filesPath(ref, "contents");
    const res = await this.request("client", path, { query: { file: f } });
    this.ensureOk(res, path, "client");
    if (res.text.includes("\u0000")) return `'${f}' is binary (${Buffer.byteLength(res.text, "utf8")} bytes); not shown.`;
    // Redact on the WHOLE text, before any cut: a tail or byte cap that lands
    // mid-line would otherwise strip the `password =` the mask keys on and hand
    // back the rest of the value.
    let text = redactFileLines(res.text);
    let note = "";
    if (opts.tail && opts.tail > 0) {
      const lines = text.split("\n");
      if (lines.length > opts.tail) {
        text = lines.slice(-opts.tail).join("\n");
        note = ` (last ${opts.tail} of ${lines.length} lines)`;
      }
    }
    const cap = Math.min(Math.max(opts.maxBytes ?? FILE_READ_DEFAULT_BYTES, 1024), FILE_READ_MAX_BYTES);
    const buf = Buffer.from(text, "utf8");
    if (buf.length > cap) {
      text = (opts.tail ? buf.subarray(-cap) : buf.subarray(0, cap)).toString("utf8");
      note += ` (truncated to ${cap} of ${buf.length} bytes${opts.tail ? ", from the end" : ""}; use tail/maxBytes to see more)`;
    }
    return `${f}${note}:\n${text}`;
  }

  async writeFile(ref: string, file: string, content: string): Promise<string> {
    const f = assertVolumePath(file, "file");
    const bytes = Buffer.byteLength(content, "utf8");
    if (bytes > FILE_WRITE_MAX_BYTES) {
      throw new Error(`Content is ${bytes} bytes; write_file caps at ${FILE_WRITE_MAX_BYTES}. Put large files on the server with pull_file instead.`);
    }
    const path = this.filesPath(ref, "write");
    const res = await this.request("client", path, { method: "POST", query: { file: f }, rawBody: content, contentType: "text/plain" });
    this.ensureOk(res, path, "client");
    return `Wrote ${bytes} bytes to '${f}' on Pelican server '${ref}' on ${this.target.name}.`;
  }

  async createFolder(ref: string, root: string, name: string): Promise<string> {
    const r = assertVolumePath(root, "root", { allowRoot: true });
    const n = assertExactName(assertVolumePath(name, "name"), "name");
    const path = this.filesPath(ref, "create-folder");
    const res = await this.request("client", path, { method: "POST", body: { root: r, name: n } });
    this.ensureOk(res, path, "client");
    return `Created folder '${n}' under '${r}' on Pelican server '${ref}' on ${this.target.name}.`;
  }

  /**
   * Ask Wings to download a URL into the volume, and don't report success until
   * the file is actually there. The request is made in the foreground so a
   * small file completes within the call; a large one outlives the panel's
   * daemon timeout (see `looksLikeDaemonTimeout`), in which case the listing is
   * polled until the size matches `expectedBytes` — or, without one, stops
   * changing. The size check doubles as an integrity check when the caller knows
   * the exact byte count of what it expects. A 429 is the panel's per-user
   * pull throttle and is reported as such (`filePullThrottleMessage`) rather
   * than as a bare status — nothing was downloaded, so there is no file to watch.
   */
  async pullFile(input: { server: string; url: string; directory?: string; filename: string; expectedBytes?: number }): Promise<string> {
    const url = assertPullUrl(input.url);
    const dir = assertVolumePath(input.directory ?? "/", "directory", { allowRoot: true });
    const name = assertExactName(assertVolumePath(input.filename, "filename"), "filename");
    if (name.includes("/")) throw new Error("'filename' is a bare file name; put the folder in 'directory'.");
    const path = this.filesPath(input.server, "pull");
    const res = await this.request("client", path, {
      method: "POST",
      body: { url: url.href, directory: dir, filename: name, use_header: false, foreground: true },
    });
    let how = "completed within the call";
    let panelError: string | undefined;
    if (!res.ok) {
      if (res.status === 429) throw new Error(filePullThrottleMessage(res, path));
      if (!looksLikeDaemonTimeout(res)) this.ensureOk(res, path, "client");
      panelError = scrubSecrets(res.text).slice(0, 300);
      how = "outlived the panel's 15s daemon timeout, so the listing was watched until it landed";
    }
    const landed = await this.waitForFile(input.server, dir, name, { expectedBytes: input.expectedBytes, settled: res.ok, panelError });
    const size = landed.size ?? 0;
    const check =
      input.expectedBytes !== undefined
        ? `${size} bytes — matches the expected size`
        : res.ok
          ? `${size} bytes (pass expectedBytes to verify an exact byte count)`
          : `${size} bytes — size stable across two polls (pass expectedBytes to verify an exact byte count)`;
    return `Pulled ${url.href} to '${dir === "/" ? "" : dir}/${name}' on Pelican server '${input.server}' on ${this.target.name}: ${check}. The download ${how}.`;
  }

  /**
   * Watch a pulled file land. `settled` means the panel answered 2xx to a
   * FOREGROUND pull, i.e. Wings finished before replying, so the first sighting
   * is final and no stability polls are spent; otherwise the download is still
   * running and the size must match `expectedBytes` or hold still across two
   * polls. A file that never appears within `appearWithinMs` is a download that
   * never started — reported with the panel's original error, if there was one,
   * rather than after the full wait.
   */
  private async waitForFile(
    ref: string,
    dir: string,
    name: string,
    opts: { expectedBytes?: number; settled: boolean; panelError?: string },
  ): Promise<FileObject> {
    const { expectedBytes, settled, panelError } = opts;
    const started = Date.now();
    let last: FileObject | undefined;
    let stable = 0;
    for (;;) {
      const entry = (await this.listDir(ref, dir)).find((f) => f.name === name);
      if (entry) {
        const size = entry.size ?? 0;
        if (expectedBytes !== undefined) {
          if (size === expectedBytes) return entry;
          if (size > expectedBytes || settled) {
            throw new Error(`'${name}' landed at ${size} bytes but ${expectedBytes} were expected — wrong file or a changed upstream. Delete it before retrying.`);
          }
        } else if (settled || (last && (last.size ?? 0) === size && size > 0 && ++stable >= 2)) {
          return entry;
        }
        last = entry;
      }
      const elapsed = Date.now() - started;
      if (!entry && !last && elapsed > FILE_PULL_POLL.appearWithinMs) {
        throw new Error(
          `'${name}' never appeared in '${dir}' within ${Math.round(FILE_PULL_POLL.appearWithinMs / 1000)}s — the download did not start. ` +
            `${panelError ? `The panel's error was: ${panelError}. ` : ""}Check the URL (Wings refuses ones that resolve inside the network) and the server's disk limit.`,
        );
      }
      if (elapsed > FILE_PULL_POLL.maxWaitMs) {
        throw new Error(
          `'${name}' did not finish landing in '${dir}' within ${Math.round(FILE_PULL_POLL.maxWaitMs / 1000)}s` +
            `${last ? ` (last seen at ${last.size ?? 0} bytes${expectedBytes !== undefined ? ` of ${expectedBytes}` : ""})` : ""}. ` +
            `Check list_files; Wings may still be downloading, or the download failed on its side.`,
        );
      }
      await pauseMs(FILE_PULL_POLL.intervalMs);
    }
  }

  async decompressFile(ref: string, root: string, file: string): Promise<string> {
    const r = assertVolumePath(root, "root", { allowRoot: true });
    const f = assertExactName(assertVolumePath(file, "file"), "file");
    const path = this.filesPath(ref, "decompress");
    const res = await this.request("client", path, { method: "POST", body: { root: r, file: f } });
    this.ensureOk(res, path, "client");
    const after = await this.listDir(ref, r);
    return (
      `Extracted '${f}' into '${r}' on Pelican server '${ref}' on ${this.target.name}. The archive itself is kept — delete_files to remove it.\n` +
      summarizeFiles(r, after)
    );
  }

  async renameFiles(ref: string, root: string, files: { from: string; to: string }[]): Promise<string> {
    const r = assertVolumePath(root, "root", { allowRoot: true });
    if (!files.length) throw new Error("'files' is empty — nothing to move.");
    const moves = files.map((m, i) => ({
      from: assertExactName(assertVolumePath(m.from, `files[${i}].from`), `files[${i}].from`),
      to: assertExactName(assertVolumePath(m.to, `files[${i}].to`), `files[${i}].to`),
    }));
    const path = this.filesPath(ref, "rename");
    const res = await this.request("client", path, { method: "PUT", body: { root: r, files: moves } });
    this.ensureOk(res, path, "client");
    return `Moved ${moves.length} item(s) under '${r}' on Pelican server '${ref}' on ${this.target.name}:\n${moves.map((m) => `  ${m.from} -> ${m.to}`).join("\n")}`;
  }

  async deleteFiles(ref: string, root: string, files: string[]): Promise<string> {
    const r = assertVolumePath(root, "root", { allowRoot: true });
    if (!files.length) throw new Error("'files' is empty — nothing to delete.");
    const names = files.map((f, i) => assertExactName(assertVolumePath(f, `files[${i}]`), `files[${i}]`));
    const path = this.filesPath(ref, "delete");
    const res = await this.request("client", path, { method: "POST", body: { root: r, files: names } });
    this.ensureOk(res, path, "client");
    return `Deleted ${names.length} item(s) under '${r}' on Pelican server '${ref}' on ${this.target.name}: ${names.join(", ")}. There is no trash — this is permanent.`;
  }

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

/** The fixed read of the installed version from config/app.php. */
function versionCommand(host: PanelHost): string {
  return `grep -m1 "'version'" ${host.path}/config/app.php`;
}

async function readInstalledVersion(host: PanelHost): Promise<string> {
  const res = await runOnPanelHost(host, versionCommand(host));
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
  return installed;
}

/**
 * The host runtime picture through the root helper (or the unprivileged fallback
 * when it is missing / sudo refuses). Never throws for a helper problem — the
 * problem text names the exact fix (install snippet or the one sudoers line).
 */
async function readHostStatus(host: PanelHost): Promise<{ status: HostStatus; problem?: string }> {
  const res = await runOnPanelHost(host, HOST_STATUS_COMMAND, 60_000);
  const status = parseHostStatus(res.stdout);
  return { status, problem: hostStatusProblem(res, status, sshUserOf(host.cred)) };
}

/** The installed panel's own PHP constraint (its composer.json `require.php`). */
async function readCurrentPhpRequirement(host: PanelHost): Promise<string | undefined> {
  const res = await runOnPanelHost(host, currentPhpRequirementCommand(host.path));
  return res.code === 0 ? composerPhpRequirement(res.stdout) : undefined;
}

/** The apt picture of the php-fpm package serving the panel (best-effort, unprivileged). */
async function readPhpPackagePolicy(host: PanelHost, status: HostStatus): Promise<{ phpVersion: string; policy: AptPolicy } | undefined> {
  const phpVersion = servingPhpMinor(status);
  if (!phpVersion) return undefined;
  const res = await runOnPanelHost(host, phpPackagePolicyCommand(phpVersion));
  return { phpVersion, policy: parseAptPolicy(res.stdout) };
}

/**
 * Installed version + latest release + the host runtime picture (PHP, the nginx
 * socket, Wings, the helper) so the whole upgrade story is one read. The runtime
 * part is best-effort: a missing helper or a denied sudo is REPORTED with the fix,
 * never fatal, so the version read keeps working on a host without the helper.
 */
async function panelVersion(ctx: ToolContext): Promise<string> {
  const host = await panelHost(ctx);
  const installed = await readInstalledVersion(host);

  const latest = await latestPanelRelease();
  let headline: string;
  if (!latest.tag) {
    headline =
      `Pelican panel on host '${host.target.name}' is running **${installed}**. ` +
      `Could not reach GitHub for the latest release (${latest.error}), so I can't say whether that is current.`;
  } else {
    const cmp = compareVersions(installed, latest.tag);
    const verdict =
      cmp === undefined
        ? `Could not compare '${installed}' with '${latest.tag}' — the version shapes differ, so check by hand rather than trusting a guess.`
        : cmp < 0
          ? `An upgrade is available. Run panel_upgrade (it takes the current version as confirmation) once the PHP requirement below is met.`
          : cmp === 0
            ? `That is the latest release.`
            : `Installed is NEWER than the latest release — likely a pre-release or a local build.`;
    headline = `Pelican panel on host '${host.target.name}': installed **${installed}**, latest released **${latest.tag}**. ${verdict}`;
  }

  const { status, problem } = await readHostStatus(host);
  const current = await readCurrentPhpRequirement(host);
  const phpPackage = await readPhpPackagePolicy(host, status);
  const release = latest.tag ? await fetchReleasePhpRequirement(latest.tag) : { error: "latest release unknown" };
  const wingsLatest = await latestWingsRelease();
  const runtime = runtimeReport({
    status,
    helperProblem: problem,
    phpPackage,
    installedPanel: installed,
    currentPhpRequirement: current,
    releaseTag: latest.tag,
    releasePhpRequirement: release.php,
    releaseRequirementError: release.error,
    latestWingsTag: wingsLatest.tag,
    latestWingsError: wingsLatest.error,
  });
  return `${headline}\n${runtime}`;
}

/**
 * Refuse to start an upgrade whose target release the host's PHP cannot run,
 * and surface the helper/sudo state. Every failure to establish the requirement
 * fails closed — starting blind is exactly how the panel ends up in maintenance
 * mode with a dead composer step.
 */
async function assertRuntimeReady(host: PanelHost, tag: string): Promise<{ status: HostStatus; problem?: string }> {
  const req = await fetchReleasePhpRequirement(tag);
  if (!req.php) {
    throw new Error(`Refusing to upgrade: could not read the PHP requirement of ${tag} (${req.error}). Starting blind is how the panel ends up in maintenance mode with a failed composer install.`);
  }
  const { status, problem } = await readHostStatus(host);
  if (!status.phpCli) throw new Error(`Refusing to upgrade: could not read the host's PHP version${problem ? ` — ${problem}` : ""}.`);
  const sat = phpSatisfies(req.php, status.phpCli);
  if (sat === undefined) {
    throw new Error(`Refusing to upgrade: cannot interpret the PHP constraint '${req.php}' of ${tag} against the installed PHP ${status.phpCli}; check by hand.`);
  }
  if (!sat) {
    const want = phpVersionFor(req.php);
    throw new Error(
      `Refusing to upgrade: ${tag} requires PHP ${req.php}, but host '${host.target.name}' runs PHP ${status.phpCli} — composer install would fail AFTER the panel is already in maintenance mode. ` +
        `Run panel_prepare_runtime${want ? ` with phpVersion '${want}'` : ""} first (it installs that PHP release, switches the panel's php-fpm socket and the CLI default), then re-run panel_upgrade.`,
    );
  }
  return { status, problem };
}

/**
 * Upgrade the panel through the root helper's `panel-upgrade`, so the WHOLE
 * documented sequence runs under the one sudoers rule (no per-step `sudo -u`).
 * Here: the stale-picture guard, the target tag (latest unless `release` pins
 * one), the PHP gate on that tag's composer.json, the helper pre-flight, then ONE
 * fixed command. The helper re-checks the installed version, downloads and
 * verifies the tarball, runs composer's platform check on the new lock file
 * BEFORE maintenance mode, backs up the database, and stops at the first failed
 * step — reporting which, and whether the panel was left in maintenance mode.
 */
async function panelUpgrade(ctx: ToolContext, input: { expectVersion: string; skipBackup?: boolean; release?: string }): Promise<string> {
  const host = await panelHost(ctx);
  const user = sshUserOf(host.cred);

  const installed = await readInstalledVersion(host);
  if (installed !== input.expectVersion.trim()) {
    throw new Error(
      `Refusing to upgrade: you said the panel is on '${input.expectVersion}', but it is actually on '${installed}'. ` +
        `Run panel_version and re-confirm — a stale picture is exactly when an upgrade goes wrong.`,
    );
  }

  let tag: string;
  if (input.release) {
    tag = assertReleaseTag(input.release);
  } else {
    const latest = await latestPanelRelease();
    if (!latest.tag) {
      throw new Error(`Refusing to upgrade: could not determine the latest release from GitHub (${latest.error}). Pass 'release' to pin a tag, or retry when GitHub is reachable.`);
    }
    tag = latest.tag;
  }
  if (installed === tag.slice(1)) return `Nothing to do: the panel on host '${host.target.name}' is already on ${tag}.`;

  const { problem } = await assertRuntimeReady(host, tag);
  if (problem) throw new Error(`Cannot upgrade: ${problem}`);

  let res: SshExecResult;
  try {
    res = await runOnPanelHost(host, helperCommand("panel-upgrade", installed, tag, input.skipBackup), MAX_SSH_TIMEOUT_MS);
  } catch (e) {
    const msg = e instanceof Error ? e.message : String(e);
    if (/timed out/i.test(msg)) {
      throw new Error(
        `The SSH session timed out after ${MAX_SSH_TIMEOUT_MS / 60_000} minutes while the helper was still upgrading. The helper ignores a dropped session and ` +
          `finishes on its own — do NOT re-run panel_upgrade yet. Wait a few minutes, then run panel_version; the run log is under /var/log/skeleton-key/ on '${host.target.name}'.`,
      );
    }
    throw e;
  }

  const result = parseUpgradeResult(res.stdout);
  if (res.code !== 0) {
    const kind = classifyHelperFailure(res);
    if (kind === "missing" || kind === "sudo" || (kind === "refused" && !result.failedStep)) {
      throw new Error(`Panel upgrade did not start — ${helperFailureText(kind, user, res, "panel-upgrade")}`);
    }
    const tail = res.stderr.trim().split("\n").slice(-6).join(" | ").slice(0, 600);
    throw new Error(
      `Panel upgrade to ${tag} FAILED at step '${result.failedStep ?? "unknown"}' on '${host.target.name}': ${tail || "(no detail)"}. ` +
        `Steps completed: ${result.stepsDone.join(", ") || "none"}. ` +
        `${result.maintenance ? `The panel is still in MAINTENANCE MODE — it will not serve until 'php artisan up' runs in ${host.path}. ` : "The panel was not taken down. "}` +
        `${result.dbBackup === "skipped" ? "No database backup was taken (skipBackup was set). " : result.dbBackup ? `The pre-upgrade database backup is at ${result.dbBackup}. ` : ""}` +
        `${result.log ? `Full step output: ${result.log} on the host. ` : ""}` +
        `Fix the cause, then re-run panel_upgrade.`,
    );
  }
  if (result.alreadyCurrent) return `Nothing to do: the panel on host '${host.target.name}' is already on ${tag}.`;

  const now = result.after ?? "(unreadable)";
  return (
    `Upgraded the Pelican panel on host '${host.target.name}': **${installed} → ${now}**. ` +
    `${now === installed ? "WARNING: the version did not change — check the extract step in the run log. " : ""}` +
    `Steps completed (${result.stepsDone.length}): ${result.stepsDone.join(", ")}; the panel is out of maintenance mode. ` +
    `${result.dbBackup === "skipped" ? "No database backup was taken. " : result.dbBackup ? `Pre-upgrade database backup: ${result.dbBackup}. ` : ""}` +
    `${result.log ? `Run log: ${result.log} on the host. ` : ""}` +
    `Verify with panel_version and by loading the panel; if anything looks wrong, the backup above is the rollback point. If Wings is behind, run wings_update next.`
  );
}

/**
 * Switch the panel host's PHP runtime through the root helper, after proving
 * (1) the requested PHP satisfies the target release's composer.json, (2) the
 * INSTALLED panel can still run on it — the runtime switches now, the code only
 * at panel_upgrade — and (3) the helper is installed and sudo-able. Only then is
 * the single fixed command `sudo -n <helper> php-prepare '<8.N>'` sent.
 */
async function panelPrepareRuntime(ctx: ToolContext, input: { phpVersion: string; release?: string; patchUpdate?: boolean }): Promise<string> {
  const phpVersion = assertPhpVersionArg(input.phpVersion);
  if (input.patchUpdate) {
    if (input.release) throw new Error(`patchUpdate patches the PHP release already serving the panel; 'release' does not apply to it — pass one or the other.`);
    return panelPatchRuntime(ctx, phpVersion);
  }
  const host = await panelHost(ctx);
  const user = sshUserOf(host.cred);

  let tag: string;
  if (input.release) {
    tag = assertReleaseTag(input.release);
  } else {
    const latest = await latestPanelRelease();
    if (!latest.tag) throw new Error(`Could not determine the latest panel release (${latest.error}); pass 'release' explicitly.`);
    tag = latest.tag;
  }
  const req = await fetchReleasePhpRequirement(tag);
  if (!req.php) throw new Error(`Could not read the PHP requirement of ${tag} (${req.error}); refusing to change the runtime without it.`);
  const forRelease = phpSatisfies(req.php, `${phpVersion}.0`);
  if (forRelease === undefined) throw new Error(`Cannot interpret the PHP constraint '${req.php}' of ${tag}; check by hand.`);
  if (!forRelease) {
    const want = phpVersionFor(req.php);
    throw new Error(`Refusing: PHP ${phpVersion} does not satisfy ${tag}'s requirement '${req.php}'${want ? `; the lowest 8.x that does is ${want}` : ""}.`);
  }

  const { status, problem } = await readHostStatus(host);
  const cliOk = !!status.phpCli && phpSatisfies(req.php, status.phpCli) === true;
  const socketOk = !!status.nginxSocket && status.nginxSocket.includes(`/php${phpVersion}-fpm.sock`);
  if (cliOk && socketOk) {
    return (
      `Nothing to do: host '${host.target.name}' already runs PHP ${status.phpCli}, which satisfies ${tag}'s requirement '${req.php}', ` +
      `and nginx already uses ${status.nginxSocket}. Proceed with panel_upgrade.`
    );
  }

  const current = await readCurrentPhpRequirement(host);
  if (!current) {
    throw new Error(
      `Refusing: could not read the installed panel's own PHP requirement from ${host.path}/composer.json, so I can't tell whether it would keep running on PHP ${phpVersion}. Check the target's 'panelPath'.`,
    );
  }
  const currentOk = phpSatisfies(current, `${phpVersion}.0`);
  if (currentOk === undefined) throw new Error(`Refusing: cannot interpret the installed panel's PHP constraint '${current}'; check by hand.`);
  if (!currentOk) {
    throw new Error(
      `Refusing: the installed panel declares PHP ${current} and would stop working on PHP ${phpVersion} BEFORE the upgrade replaces its code. ` +
        `Upgrade in two hops through a release whose composer.json allows both, or do this one by hand.`,
    );
  }

  if (problem) throw new Error(`Cannot prepare the runtime: ${problem}`);
  const res = await runOnPanelHost(host, helperCommand("php-prepare", phpVersion), 600_000);
  if (res.code !== 0) {
    throw new Error(`php-prepare ${phpVersion} FAILED on '${host.target.name}' — ${helperFailureText(classifyHelperFailure(res), user, res, "php-prepare")}`);
  }
  const after = parseHostStatus(res.stdout);
  return (
    `Prepared the PHP runtime on host '${host.target.name}' for ${tag} (requires PHP ${req.php}): PHP CLI now **${after.phpCli ?? "(unreadable)"}**` +
    `${after.phpDefault ? ` (default php${after.phpDefault})` : ""}, nginx fastcgi socket ${after.nginxSocket ?? "(unreadable)"}` +
    `${after.phpFpmActive.length ? `, php-fpm active: ${after.phpFpmActive.join(", ")}` : ""}. ` +
    `The previous PHP release stays installed as the rollback point (nginx site backups end in .bak-skeleton-key). Next: panel_upgrade with expectVersion = the installed version.`
  );
}

/**
 * Same-minor PHP patch update (e.g. 8.4.26 → 8.4.27 for a security fix) through
 * the SAME fixed `php-prepare '<8.N>'` — the helper's `apt-get update` + `apt-get
 * install php<8.N>-*` upgrades the installed packages, and its CLI-default /
 * nginx-socket steps are no-ops when nothing switches. Refused unless <8.N> is
 * the release already serving the panel: a patch never switches the runtime, so
 * the release-requirement gates of a switch do not apply.
 */
async function panelPatchRuntime(ctx: ToolContext, phpVersion: string): Promise<string> {
  const host = await panelHost(ctx);
  const user = sshUserOf(host.cred);
  const { status, problem } = await readHostStatus(host);
  if (problem) throw new Error(`Cannot patch the runtime: ${problem}`);
  const serving = servingPhpMinor(status);
  if (!serving) throw new Error(`Refusing: could not tell which PHP release serves the panel on '${host.target.name}' (no nginx socket, CLI default or CLI version read).`);
  if (serving !== phpVersion) {
    throw new Error(
      `Refusing: patchUpdate only patches the PHP release already serving the panel, which is ${serving} on '${host.target.name}', not ${phpVersion}. ` +
        `Switching releases is a runtime change — run panel_prepare_runtime without patchUpdate for that.`,
    );
  }
  const before = await readPhpPackagePolicy(host, status);

  const res = await runOnPanelHost(host, helperCommand("php-prepare", phpVersion), 600_000);
  if (res.code !== 0) {
    throw new Error(`php-prepare ${phpVersion} (patch update) FAILED on '${host.target.name}' — ${helperFailureText(classifyHelperFailure(res), user, res, "php-prepare")}`);
  }
  const after = parseHostStatus(res.stdout);
  const was = status.phpCli ?? before?.policy.installed ?? "(unreadable)";
  const now = after.phpCli ?? "(unreadable)";
  return (
    `Patch-updated PHP ${phpVersion} on host '${host.target.name}': PHP CLI **${was} → ${now}**` +
    `${after.phpFpmActive.length ? `, php-fpm active: ${after.phpFpmActive.join(", ")}` : ""}, nginx fastcgi socket ${after.nginxSocket ?? "(unreadable)"}. ` +
    `${was === now ? `The version did not change — after apt-get update there was no newer php${phpVersion} package in the configured sources. ` : ""}` +
    `php${phpVersion}-fpm and nginx were restarted; run panel_version to confirm the package now matches the apt candidate.`
  );
}

/**
 * Update the Wings binary through the root helper. The stale-picture guard is the
 * installed Wings version (read by the helper — the panel's node API carries no
 * daemon version, and `wings version` is not executable by the SSH user).
 */
async function wingsUpdate(ctx: ToolContext, input: { expectVersion: string; tag: string }): Promise<string> {
  const tag = assertWingsTag(input.tag);
  const host = await panelHost(ctx);
  const user = sshUserOf(host.cred);

  const { status, problem } = await readHostStatus(host);
  if (problem) throw new Error(`Cannot update Wings: ${problem}`);
  if (!status.wings) {
    throw new Error(`Cannot update Wings: the host helper reported no Wings version — is Wings installed at /usr/local/bin/wings on '${host.target.name}'?`);
  }
  const expect = input.expectVersion.trim().replace(/^v/, "");
  if (status.wings !== expect) {
    throw new Error(
      `Refusing to update Wings: you said it is on '${input.expectVersion}', but host '${host.target.name}' runs '${status.wings}'. Run panel_version and re-confirm.`,
    );
  }
  if (status.wings === tag.slice(1)) {
    return `Nothing to do: Wings on '${host.target.name}' is already ${status.wings}${status.wingsActive ? ` (service ${status.wingsActive})` : ""}.`;
  }

  const res = await runOnPanelHost(host, helperCommand("wings-update", tag), 300_000);
  if (res.code !== 0) {
    const rolledBack = /rolled back/i.test(res.stderr) ? " The previous binary was restored." : "";
    throw new Error(`wings-update ${tag} FAILED on '${host.target.name}' — ${helperFailureText(classifyHelperFailure(res), user, res, "wings-update")}${rolledBack}`);
  }
  const after = parseHostStatus(res.stdout);

  // Lockstep note — informational only, never blocks the result.
  let note = "";
  try {
    const panel = await readInstalledVersion(host);
    const c = compareVersions(panel, tag);
    if (c !== undefined && c < 0) note = ` Note: the panel is on ${panel}, behind Wings ${tag} — Pelican ships them in lockstep, so run panel_upgrade too.`;
  } catch {
    /* the Wings update already succeeded; the panel version is just context */
  }
  return (
    `Updated Wings on host '${host.target.name}': **${status.wings} → ${after.wings ?? "(unreadable)"}**${after.wingsActive ? ` (service ${after.wingsActive})` : ""}. ` +
    `The previous binary is kept at /usr/local/bin/wings.prev. Running game servers were not stopped; consoles reconnect on their own.${note}`
  );
}

// --- White-glove power actions ---------------------------------------------------
//
// The owner's game servers are watched by Uptime Kuma monitors that post
// "X is DOWN / UP" to Discord. A deliberate bounce (test boot, mod install,
// world swap) therefore pages the channel unless the monitors are paused first.
// The **white-glove rule**: a MANUAL power action on a monitored server pauses
// its monitors, acts, waits until the server reports the expected state, and
// resumes them — in every case, including failure, because a monitor left
// paused is a blind spot nobody asked for. Scheduled starts/stops (Pelican
// schedules) run inside the panel, never through this tool, and must not be
// suppressed: those alerts are the feature. See docs/ARCHITECTURE.md.

/** Poll cadence/bounds for confirming a power action's end state. Exported (mutable) for testing. */
export const POWER_WAIT = { intervalMs: 3000, defaultSeconds: 180, maxSeconds: 900 };

/** The state server_resources should report once a signal has taken effect. */
export function expectedStateFor(signal: string): "running" | "offline" {
  return signal === "start" || signal === "restart" ? "running" : "offline";
}

export interface PowerWaitOutcome {
  reached: boolean;
  state?: string;
  elapsedMs: number;
  /** Distinct states seen, in order — the result shows the path taken. */
  observed: string[];
}

/**
 * Wait for the expected state. A restart is the subtle one: the server is
 * `running` both before and after, so "running" alone proves nothing — it must
 * either have been seen leaving `running` (stopping/starting/offline) or come
 * back with a process uptime shorter than this wait, which only a fresh process
 * has. Read errors are treated as transient and polling continues until the
 * deadline. Exported for testing.
 */
export async function waitForPowerState(
  read: (remainingMs: number) => Promise<{ state?: string; uptimeMs?: number }>,
  signal: string,
  seconds: number,
): Promise<PowerWaitOutcome> {
  const want = expectedStateFor(signal);
  const started = Date.now();
  const deadline = started + seconds * 1000;
  const observed: string[] = [];
  let sawTransition = false;
  for (;;) {
    let cur: { state?: string; uptimeMs?: number } = {};
    try {
      cur = await read(Math.max(1, deadline - Date.now()));
    } catch {
      /* transient — keep polling until the deadline */
    }
    const st = cur.state;
    if (st && observed[observed.length - 1] !== st) observed.push(st);
    if (st && st !== "running") sawTransition = true;
    const elapsedMs = Date.now() - started;
    if (st === want) {
      const fresh = cur.uptimeMs !== undefined && cur.uptimeMs < elapsedMs;
      if (signal !== "restart" || sawTransition || fresh) return { reached: true, state: st, elapsedMs, observed };
    }
    if (Date.now() >= deadline) return { reached: false, state: st, elapsedMs, observed };
    await new Promise((r) => setTimeout(r, Math.max(1, Math.min(POWER_WAIT.intervalMs, deadline - Date.now()))));
  }
}

/**
 * The Uptime Kuma target whose monitors watch this panel's servers. An explicit
 * `monitorsTarget` option wins; otherwise the ONE registered uptime-kuma target
 * is used, and several is an error asking the operator to choose — never a
 * silent pick. Fails closed when nothing is registered: the rule is "no pause,
 * no test", so the action is refused rather than run noisily.
 */
async function monitorsTargetFor(ctx: ToolContext): Promise<{ target: Target; cred: Credential }> {
  const opts = options(ctx.target);
  if (!ctx.resolveCredential) throw new Error("This call site cannot resolve other targets' credentials, so suppressMonitors is unavailable here.");
  let t: Target | undefined;
  if (opts.monitorsTarget) {
    if (!ctx.resolveTarget) throw new Error("This call site cannot resolve other targets, so suppressMonitors is unavailable here.");
    t = ctx.resolveTarget(opts.monitorsTarget);
    if (!t) throw new Error(`This Pelican target's monitorsTarget is '${opts.monitorsTarget}', but no target by that name is registered. Check list_targets.`);
  } else {
    if (!ctx.targetsOfType) throw new Error("This call site cannot look up targets by type, so suppressMonitors is unavailable here.");
    const all = ctx.targetsOfType("uptime-kuma");
    if (all.length === 0) {
      throw new Error(
        `suppressMonitors was requested but no uptime-kuma target is registered, so nothing could be silenced. The white-glove rule says a monitored game server is ` +
          `not bounced without suppression, so this refuses rather than proceeding noisily. Register the Uptime Kuma instance (register_target type 'uptime-kuma'), ` +
          `or — only if this server is genuinely unmonitored — run power_action without suppressMonitors.`,
      );
    }
    if (all.length > 1) {
      throw new Error(
        `Several uptime-kuma targets are registered (${all.map((x) => x.name).join(", ")}) — set this Pelican target's 'monitorsTarget' option (update_target) to the one that watches its servers.`,
      );
    }
    t = all[0]!;
  }
  if (t.type !== "uptime-kuma") {
    throw new Error(`This Pelican target's monitorsTarget is '${t.name}', which is a '${t.type}' target, not 'uptime-kuma'. Refusing to log in to it.`);
  }
  if (!t.credentialRef) throw new Error(`The uptime-kuma target '${t.name}' has no credential attached, so its monitors cannot be paused.`);
  return { target: t, cred: await ctx.resolveCredential(t.credentialRef) };
}

type Named = { id: number; name: string };
type ResumeReport = Awaited<ReturnType<typeof resumeExactly>>;

/** Resume on a FRESH session (the pause session is long closed and the wait may
 *  have outlived a connection). Never throws: a failure is reported as monitors
 *  still paused, which the result then puts first. */
async function safeResume(kopts: ReturnType<typeof kumaConnectOptions>, paused: Named[]): Promise<ResumeReport> {
  if (!paused.length) return { resumed: [], already: [], missing: [], failed: [] };
  try {
    return await withKuma(kopts, (s) => resumeExactly(s, paused));
  } catch (e) {
    const why = e instanceof Error ? e.message : String(e);
    return { resumed: [], already: [], missing: [], failed: paused.map((m) => `[${m.id}] ${m.name}: ${why}`) };
  }
}

interface PowerInput {
  server: string;
  signal: (typeof POWER_SIGNALS)[number];
  suppressMonitors?: boolean;
  waitSeconds?: number;
}

/** pause → act → verify → ALWAYS resume. Exported for testing. */
export async function whiteGlovePowerAction(ctx: ToolContext, p: Pelican, input: PowerInput): Promise<ToolResult> {
  const seconds = Math.min(input.waitSeconds ?? POWER_WAIT.defaultSeconds, POWER_WAIT.maxSeconds);
  const kuma = await monitorsTargetFor(ctx);
  const kopts = kumaConnectOptions(kuma.target, kuma.cred);
  const server = await p.clientServer(input.server);
  const who = `Pelican server '${server.name}' (${server.identifier ?? input.server}) on ${ctx.target.name}`;
  const nameOf = (xs: Named[]): string => xs.map((m) => `${m.name} [${m.id}]`).join(", ");

  // 1. Pause. Nothing has happened to the server yet, so a failure here rolls
  //    back what was paused and refuses — "no pause, no test".
  const paused: Named[] = [];
  const alreadyPaused: Named[] = [];
  await withKuma(kopts, async (s) => {
    const { matched, unmatchedSameName } = monitorsForServer(await s.monitors(), server);
    if (!matched.length) {
      const same = unmatchedSameName[0];
      const hint = same
        ? ` A monitor named '${same.name}' [${same.id}] exists but lacks the '${MANAGED_PELICAN_TAG}' tag — add it (or a tag naming this server, e.g. 'server:${server.identifier ?? server.name}') to opt it in.`
        : ` Name the monitor '${server.name}' and tag it '${MANAGED_PELICAN_TAG}', or tag it with the server identifier (e.g. 'server:${server.identifier ?? server.name}').`;
      throw new Error(
        `No monitor on Uptime Kuma target '${kuma.target.name}' matches ${who}, so nothing would be silenced — refusing to send '${input.signal}' with suppressMonitors.${hint} ` +
          `If this server is genuinely unmonitored, run power_action without suppressMonitors.`,
      );
    }
    for (const m of matched) {
      if (!m.active) {
        alreadyPaused.push({ id: m.id, name: m.name });
        continue;
      }
      try {
        await s.pause(m.id);
        paused.push({ id: m.id, name: m.name });
      } catch (e) {
        // Undo what WE paused, unconditionally — not via the cached list, which
        // on Kuma 2.x may not yet reflect the pauses — and refuse.
        const back = await resumeUnconditionally(s, paused);
        const lead = back.failed.length ? `MONITORS STILL PAUSED on ${kuma.target.name}: ${back.failed.join("; ")}. Resume them now with that target's resume_monitor. ` : "";
        throw new Error(
          `${lead}Could not pause monitor '${m.name}' [${m.id}] on ${kuma.target.name}: ${e instanceof Error ? e.message : String(e)}. The '${input.signal}' was NOT sent.` +
            (back.resumed.length ? ` Rolled back: resumed ${nameOf(back.resumed)}.` : ""),
        );
      }
    }
  });

  // 2. Act, 3. verify — then 4. ALWAYS resume, whatever happened in 2 or 3.
  let action = "";
  let wait: PowerWaitOutcome | undefined;
  let failure: unknown;
  let back!: ResumeReport;
  try {
    action = await p.powerAction(input.server, input.signal);
    // Each read is capped at 15 s and never past the deadline, so a hung
    // panel cannot hold the monitors paused beyond `waitSeconds`.
    wait = await waitForPowerState((remainingMs) => p.currentState(input.server, Math.min(15_000, remainingMs)), input.signal, seconds);
  } catch (e) {
    failure = e;
  } finally {
    back = await safeResume(kopts, paused);
  }

  const stillPaused = back.failed.length > 0;
  const lines: string[] = [];
  if (stillPaused) {
    lines.push(`MONITORS STILL PAUSED on ${kuma.target.name}: ${back.failed.join("; ")}. Resume them now with that target's resume_monitor — never leave them paused.`);
  }
  lines.push(`White-glove ${input.signal} of ${who}:`);
  lines.push(
    `  1. Paused ${paused.length} Uptime Kuma monitor${paused.length === 1 ? "" : "s"} on ${kuma.target.name}: ${nameOf(paused) || "none (every matching monitor was already paused)"}.` +
      (alreadyPaused.length ? ` Already paused, left alone: ${nameOf(alreadyPaused)}.` : ""),
  );
  if (failure) lines.push(`  2. The action FAILED: ${failure instanceof Error ? failure.message : String(failure)}`);
  else lines.push(`  2. ${action}`);
  if (wait) {
    const path = wait.observed.join(" → ") || "no state read";
    lines.push(
      wait.reached
        ? `  3. Server reached '${wait.state}' after ${Math.round(wait.elapsedMs / 1000)}s (observed: ${path}).`
        : `  3. WARNING: server did NOT reach '${expectedStateFor(input.signal)}' within ${seconds}s (last state '${wait.state ?? "unknown"}', observed: ${path}). ` +
            `Do not re-send the power action blindly — check server_resources and the console first.`,
    );
  }
  lines.push(
    `  4. Resumed: ${nameOf(back.resumed) || "nothing to resume"}.` +
      (back.already.length ? ` Already active: ${nameOf(back.already)}.` : "") +
      (back.missing.length ? ` Gone from Kuma: ${nameOf(back.missing)}.` : ""),
  );
  if (!failure && wait?.reached && !stillPaused) {
    lines.push(
      expectedStateFor(input.signal) === "offline"
        ? `The server is now intentionally offline with its monitors active again, so Kuma will report it DOWN on the next check. For a planned outage, open a window with the ${kuma.target.name} 'maintenance' tool instead and end it when the server is back.`
        : "Notifications stayed quiet for the whole bounce.",
    );
  }
  return { text: lines.join("\n"), isError: Boolean(failure) || stillPaused };
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
        `own "update available" banner uses. Also reports the host runtime the upgrade depends on — PHP version vs the release's ` +
        `composer.json requirement, the panel's nginx php-fpm socket, the Wings version vs its latest release, and whether the root ` +
        `helper for panel_prepare_runtime / wings_update is installed (with the exact install steps if not).`,
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
        `Upgrade the Pelican panel itself on ${target.name} to the latest release (or a pinned 'release' tag). HOST-LEVEL work over SSH through ` +
        `the root-owned helper ${HELPER_PATH} and its ONE sudoers rule — never general sudo; the target's 'sshTarget' option names the host. ` +
        `Run panel_version first and pass its installed version as expectVersion — a mismatch is refused, as is a release whose PHP ` +
        `requirement (from its composer.json) the host does not meet (run panel_prepare_runtime first). The helper then downloads + ` +
        `checksum-verifies panel.tar.gz, runs composer's platform check on the NEW lock file BEFORE maintenance mode, takes a database ` +
        `backup, and runs Pelican's documented sequence — maintenance mode, extract, permissions, composer install, migrate, clear caches, ` +
        `restart queue, up — with artisan/composer as the panel user, never root. On any failure it STOPS, names the step, and leaves the ` +
        `panel in maintenance mode rather than half-upgraded and serving; step output is logged under /var/log/skeleton-key/ on the host.`,
      tier: "execute",
      inputSchema: z.object({
        expectVersion: z.string().min(1).describe("The currently installed version, exactly as panel_version reports it. A mismatch aborts."),
        release: z
          .string()
          .optional()
          .describe("Panel release tag to install, e.g. 'v1.0.0-rc.1'. Default: the latest release. Its composer.json decides the PHP gate."),
        skipBackup: z
          .boolean()
          .optional()
          .describe("Skip the pre-upgrade database backup. Default false. 'migrate' has no undo, so only set this if you have your own backup."),
      }),
      confirm: (input, t) => {
        const i = input as { expectVersion: string; skipBackup?: boolean; release?: string };
        const o = options(t);
        return (
          `UPGRADE the Pelican panel itself on host '${o.sshTarget ?? "(no sshTarget set)"}' from ${i.expectVersion} to ${i.release ?? "the latest release"} ` +
          `(${o.panelPath}) — runs database migrations, takes the panel down during the upgrade` +
          `${i.skipBackup ? ", and SKIPS the database backup" : ""}; runs the root helper ${HELPER_PATH} via sudo -n and nothing else`
        );
      },
      run: async (input, ctx) => {
        try {
          return ok(await panelUpgrade(ctx, input as { expectVersion: string; skipBackup?: boolean; release?: string }));
        } catch (e) {
          return { text: `Pelican error: ${e instanceof Error ? e.message : String(e)}`, isError: true };
        }
      },
    },
    {
      name: "panel_prepare_runtime",
      description:
        `Install and switch the PHP runtime on ${target.name}'s panel host ahead of a panel upgrade whose release raised the PHP floor ` +
        `(v1.0.0-rc.1 needs PHP 8.4). HOST-LEVEL work over SSH through the root-owned helper ${HELPER_PATH} and ONE sudoers rule for it — ` +
        `never general sudo; a missing helper or a denied sudo returns the exact install steps. Run panel_version first: it reports the ` +
        `release's PHP requirement and the phpVersion to pass. This tool fetches the release's composer.json, refuses a phpVersion that does ` +
        `not satisfy it, refuses if the INSTALLED panel could not run on that PHP (the runtime switches now, the code only at panel_upgrade), ` +
        `and is a no-op when the host already meets it — unless patchUpdate is set, which re-runs the helper on the PHP release already ` +
        `serving the panel to pull a same-minor patch (security) release. On the host: ppa:ondrej/php if missing, php<ver> + fpm/cli/gd/mysql/mbstring/bcmath/` +
        `xml/curl/zip/intl/sqlite3, the CLI default, the panel site's fastcgi_pass socket (only in nginx files that mention the panel root), ` +
        `nginx -t, then restart php-fpm + nginx. The previous PHP release stays installed as the rollback point.`,
      tier: "execute",
      inputSchema: z.object({
        phpVersion: z
          .string()
          .regex(/^8\.\d{1,2}$/, "a PHP 8 major.minor, e.g. 8.4")
          .describe("PHP major.minor to install and switch to, e.g. '8.4' — the version panel_version says the release requires."),
        release: z
          .string()
          .optional()
          .describe("Panel release tag to prepare for, e.g. 'v1.0.0-rc.1'. Default: the latest release, which is what panel_upgrade installs."),
        patchUpdate: z
          .boolean()
          .optional()
          .describe(
            "Apply a same-minor PHP patch release (e.g. 8.4.26 → 8.4.27, how PHP security fixes ship) even though the requirement is already met. " +
              "phpVersion must be the release already serving the panel; 'release' does not apply. panel_version says when the php-fpm package is behind apt.",
          ),
      }),
      confirm: (input, t) => {
        const i = input as { phpVersion: string; release?: string; patchUpdate?: boolean };
        const o = options(t);
        if (i.patchUpdate) {
          return (
            `PATCH-UPDATE PHP ${i.phpVersion} on Pelican host '${o.sshTarget ?? "(no sshTarget set)"}': apt-get update, then upgrade php${i.phpVersion} ` +
            `and Pelican's extensions to the newest ${i.phpVersion}.x in the configured sources, and restart php${i.phpVersion}-fpm + nginx ` +
            `(no runtime switch); runs the root helper ${HELPER_PATH} via sudo -n and nothing else`
          );
        }
        return (
          `PREPARE the PHP runtime on Pelican host '${o.sshTarget ?? "(no sshTarget set)"}': install PHP ${i.phpVersion} (ppa:ondrej/php + ` +
          `Pelican's extensions), make it the CLI default, switch the panel's nginx fastcgi socket to php${i.phpVersion}-fpm and restart ` +
          `php-fpm + nginx — for panel release ${i.release ?? "latest"}; runs the root helper ${HELPER_PATH} via sudo -n and nothing else`
        );
      },
      run: async (input, ctx) => {
        try {
          return ok(await panelPrepareRuntime(ctx, input as { phpVersion: string; release?: string; patchUpdate?: boolean }));
        } catch (e) {
          return { text: `Pelican error: ${e instanceof Error ? e.message : String(e)}`, isError: true };
        }
      },
    },
    {
      name: "wings_update",
      description:
        `Update the Wings daemon binary on ${target.name}'s panel host to a GitHub release tag. HOST-LEVEL work through the root-owned ` +
        `helper ${HELPER_PATH} (sudo -n for that script only): it downloads wings_linux_<arch> + checksums.txt for the tag, verifies the ` +
        `SHA-256, swaps /usr/local/bin/wings atomically (previous kept as .prev), restarts the wings unit and rolls back if it does not come ` +
        `up. Running game servers keep running; consoles reconnect. Run panel_version first and pass the installed Wings version as ` +
        `expectVersion (a mismatch is refused) and the tag it reports as latest. Pelican ships panel and Wings in lockstep — update Wings ` +
        `AFTER panel_upgrade reaches the matching release.`,
      tier: "execute",
      inputSchema: z.object({
        expectVersion: z.string().min(1).describe("Installed Wings version exactly as panel_version reports it (e.g. '1.0.0-beta22'). A mismatch aborts."),
        tag: z.string().min(1).describe("Wings release tag to install, e.g. 'v1.0.0-rc.1' (panel_version reports the latest)."),
      }),
      confirm: (input, t) => {
        const i = input as { expectVersion: string; tag: string };
        const o = options(t);
        return (
          `UPDATE the Wings daemon on Pelican host '${o.sshTarget ?? "(no sshTarget set)"}' from ${i.expectVersion} to ${i.tag} — replaces ` +
          `/usr/local/bin/wings (checksum-verified) and restarts the wings service; runs the root helper ${HELPER_PATH} via sudo -n and nothing else`
        );
      },
      run: async (input, ctx) => {
        try {
          return ok(await wingsUpdate(ctx, input as { expectVersion: string; tag: string }));
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
      name: "update_server_build",
      description:
        `Change a Pelican server's build on ${target.name} through the ADMIN (application) API, by NUMERIC server id: resource limits ` +
        `(memory, swap, disk, io, cpu, threads), feature limits (how many backups, databases and allocations it may hold) and the OOM ` +
        `killer. The panel's build route demands the WHOLE build every time and writes any feature limit it isn't sent as 0, so this ` +
        `is a read-merge-write: the server is read first, only the fields you pass change, everything else is re-sent as it is, and ` +
        `the result reports prior → new so you can revert. Unknown fields are refused. Lowering the backup limit is how a scheduled ` +
        `backup is told how many to keep — it rotates out the oldest once the limit is reached — and deletes nothing by itself.`,
      tier: "execute",
      inputSchema: z
        .object({
          id: z.number().int().positive().describe("Numeric application server id from list_servers (NOT the short identifier)."),
          limits: z
            .object({
              memory: z.number().int().min(0).optional().describe("Memory limit MiB (0 = unlimited)."),
              swap: z.number().int().min(-1).optional().describe("Swap MiB (0 = none, -1 = unlimited)."),
              disk: z.number().int().min(0).optional().describe("Disk limit MiB (0 = unlimited)."),
              io: z.number().int().min(0).max(1000).optional().describe("Block IO weight, 0–1000."),
              cpu: z.number().int().min(0).optional().describe("CPU limit % (100 = one core; 0 = unlimited)."),
              threads: z.string().regex(/^[0-9,-]+$/).nullable().optional().describe("CPU pinning, e.g. '0-1,3'; null clears it."),
            })
            .strict()
            .optional()
            .describe("Resource limits to change. Any you omit keep their current value."),
          featureLimits: z
            .object({
              databases: z.number().int().min(0).optional().describe("How many databases the server may have."),
              allocations: z.number().int().min(0).optional().describe("How many allocations (ports) the server may hold."),
              backups: z.number().int().min(0).optional().describe("How many backups the server may keep; a scheduled backup rotates out the oldest once this is reached."),
            })
            .strict()
            .optional()
            .describe("Feature limits to change. Any you omit keep their current value."),
          oomKiller: z.boolean().optional().describe("Enable the container's OOM killer. Omit to leave it alone."),
        })
        .strict(),
      confirm: (input, t) => {
        const i = input as UpdateServerBuildInput;
        const fields = buildChanges(i).map(([p, v]) => `${p}=${v === null ? "null" : String(v)}`);
        return `Change build of Pelican server [${i.id}] on ${t.name}: ${fields.join(", ") || "nothing"} (every other build field is re-sent unchanged)`;
      },
      run: run((p, i) => p.updateServerBuild(i)),
    },
    {
      name: "power_action",
      description:
        `Start, stop, restart or kill a Pelican server on ${target.name}. 'kill' terminates the process ungracefully and can lose ` +
        `unsaved world state — prefer 'stop'. Power changes are asynchronous; confirm with server_resources. ` +
        `WHITE-GLOVE RULE — pass suppressMonitors:true for any MANUAL (out-of-schedule) action on a server that Uptime Kuma monitors: it finds the registered ` +
        `uptime-kuma target, pauses every monitor matching this server (tag '${MANAGED_PELICAN_TAG}' + the server's name, or a tag naming the server), performs the action, ` +
        `waits up to waitSeconds (default ${POWER_WAIT.defaultSeconds}) for server_resources to report the expected state, and resumes the monitors in every case ` +
        `including failure — so Discord never gets 'DOWN/UP' posts for a deliberate bounce. It refuses, and sends nothing, when no uptime-kuma target or no matching ` +
        `monitor exists. Scheduled starts/stops run inside the panel and are never suppressed — those alerts are the feature.`,
      tier: "execute",
      inputSchema: z.object({
        server: SERVER_REF,
        signal: z.enum(POWER_SIGNALS).describe("start | stop | restart | kill"),
        suppressMonitors: z
          .boolean()
          .optional()
          .describe("White-glove: pause this server's Uptime Kuma monitors around the action and resume them after. Required for manual actions on monitored game servers; never for scheduled ones."),
        waitSeconds: z
          .number()
          .int()
          .min(1)
          .max(POWER_WAIT.maxSeconds)
          .optional()
          .describe(`With suppressMonitors: how long to wait for the expected state before resuming the monitors anyway (default ${POWER_WAIT.defaultSeconds}).`),
      }),
      confirm: (input, t) => {
        const i = input as PowerInput;
        const label = i.signal === "kill" ? "KILL (ungraceful — may lose unsaved state)" : i.signal.toUpperCase();
        const glove = i.suppressMonitors
          ? ` — white-glove: pause its matching Uptime Kuma monitors first, resume them once it reports '${expectedStateFor(i.signal)}' (or on failure)`
          : "";
        return `${label} Pelican server '${i.server}' on ${t.name}${glove}`;
      },
      run: async (input, ctx) => {
        const i = input as PowerInput;
        if (!i.suppressMonitors) return run((p, x) => p.powerAction(x.server, x.signal))(input, ctx);
        try {
          return await withClient(ctx, (p) => whiteGlovePowerAction(ctx, p, i));
        } catch (e) {
          return { text: `Pelican error: ${e instanceof Error ? e.message : String(e)}`, isError: true };
        }
      },
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
    // --- files (client API) ------------------------------------------------
    {
      name: "list_files",
      description:
        `List a directory inside a Pelican server's volume on ${target.name} (folders first; size in bytes). Paths are relative ` +
        `to the server's root, e.g. '/' or '/BepInEx/plugins'. This is how you check what a game server actually has on disk — ` +
        `its mods, configs, logs and saves — without shell access to the node.`,
      tier: "read",
      inputSchema: z.object({
        server: SERVER_REF,
        directory: z.string().optional().describe("Directory to list, relative to the server root. Default '/'."),
      }),
      run: run((p, i) => p.listFiles(i.server, i.directory)),
    },
    {
      name: "read_file",
      description:
        `Read a text file from a Pelican server's volume on ${target.name} — a config, a log, a start script. Capped at ` +
        `${FILE_READ_DEFAULT_BYTES} bytes by default (${FILE_READ_MAX_BYTES} max) and the panel refuses files over 4 MiB; for a ` +
        `big log pass 'tail' to get its last N lines. Values on secret-named lines (password=, token:, -password x) are masked ` +
        `before the text comes back — a file read must never be how a game password reaches the chat. Binary files are refused.`,
      tier: "read",
      inputSchema: z.object({
        server: SERVER_REF,
        file: z.string().min(1).describe("File path relative to the server root, e.g. '/BepInEx/LogOutput.log'."),
        tail: z.number().int().positive().max(5000).optional().describe("Return only the last N lines."),
        maxBytes: z.number().int().positive().optional().describe(`Byte cap for the returned text (1024–${FILE_READ_MAX_BYTES}).`),
      }),
      run: run((p, i) => p.readFile(i.server, i.file, { tail: i.tail, maxBytes: i.maxBytes })),
    },
    {
      name: "write_file",
      description:
        `Write a text file into a Pelican server's volume on ${target.name}, creating or REPLACING it — for config files ` +
        `(a BepInEx cfg, a mod's policy file, a start script). Capped at ${FILE_WRITE_MAX_BYTES} bytes; larger files go in with ` +
        `pull_file. Never put a secret in 'content' — a game's password belongs in a vault-backed startup variable.`,
      tier: "execute",
      inputSchema: z.object({
        server: SERVER_REF,
        file: z.string().min(1).describe("File path relative to the server root."),
        content: z.string().describe("The complete new contents of the file."),
      }),
      confirm: (input, t) => {
        const i = input as { server: string; file: string; content: string };
        return `Write ${Buffer.byteLength(i.content, "utf8")} bytes to '${i.file}' on Pelican server '${i.server}' on ${t.name} (replaces the file if it exists; contents not shown)`;
      },
      run: run((p, i) => p.writeFile(i.server, i.file, i.content)),
    },
    {
      name: "create_folder",
      description: `Create a folder inside a Pelican server's volume on ${target.name}. 'name' may be nested (e.g. 'BepInEx/plugins/Jotunn'); parents are created.`,
      tier: "execute",
      inputSchema: z.object({
        server: SERVER_REF,
        root: z.string().optional().describe("Directory to create it under. Default '/'."),
        name: z.string().min(1).describe("Folder name or relative path to create."),
      }),
      confirm: (input, t) => {
        const i = input as { server: string; root?: string; name: string };
        return `Create folder '${i.name}' under '${i.root ?? "/"}' on Pelican server '${i.server}' on ${t.name}`;
      },
      run: run((p, i) => p.createFolder(i.server, i.root ?? "/", i.name)),
    },
    {
      name: "pull_file",
      description:
        `Have the Wings daemon download a public https URL straight into a Pelican server's volume on ${target.name} — the way ` +
        `to get a mod zip, a plugin or a world file onto a game server without shell access. The file lands owned by the server's ` +
        `own user. Only public https sources are accepted (the daemon fetches from inside your LAN, so a private address is ` +
        `refused). The call waits for the download; pass 'expectedBytes' (the exact size of the file you expect, e.g. from ` +
        `downloading it yourself first) and the result is only reported as success when the landed size matches. Then ` +
        `decompress_file to unpack it and rename_files to move pieces into place. The panel throttles this route to ` +
        `${FILE_PULL_RATE_LIMIT.pulls} pulls per ${FILE_PULL_RATE_LIMIT.minutes} minutes per user by default, and a rejected attempt does ` +
        `not extend the window — plan a mod install in groups of at most ${FILE_PULL_RATE_LIMIT.pulls} pulls and let the window pass ` +
        `before the next group (a 429 names the limit and, when the panel sends them, the Retry-After / X-RateLimit-Reset values).`,
      tier: "execute",
      inputSchema: z.object({
        server: SERVER_REF,
        url: z.string().url().describe("Public https URL to download, e.g. a thunderstore.io package download link."),
        directory: z.string().optional().describe("Directory to download into, relative to the server root. Default '/'."),
        filename: z.string().min(1).describe("File name to save as (required — many download URLs end in a version, not a name)."),
        expectedBytes: z.number().int().positive().optional().describe("Exact expected size in bytes; the pull is verified against it."),
      }),
      confirm: (input, t) => {
        const i = input as { server: string; url: string; directory?: string; filename: string; expectedBytes?: number };
        return `Download ${i.url} to '${(i.directory ?? "/").replace(/\/$/, "")}/${i.filename}' on Pelican server '${i.server}' on ${t.name} (the Wings daemon fetches it${i.expectedBytes ? `; expecting ${i.expectedBytes} bytes` : ""})`;
      },
      run: run((p, i) => p.pullFile(i)),
    },
    {
      name: "decompress_file",
      description:
        `Extract an archive (zip, tar, tar.gz) already inside a Pelican server's volume on ${target.name}, in place, into 'root'. ` +
        `Files already there with the same names are overwritten. The archive is kept. The result lists 'root' afterwards so ` +
        `you can see the layout the archive produced before moving anything.`,
      tier: "execute",
      inputSchema: z.object({
        server: SERVER_REF,
        root: z.string().optional().describe("Directory containing the archive and receiving its contents. Default '/'."),
        file: z.string().min(1).describe("Archive file name, relative to 'root'."),
      }),
      confirm: (input, t) => {
        const i = input as { server: string; root?: string; file: string };
        return `Extract '${i.file}' into '${i.root ?? "/"}' on Pelican server '${i.server}' on ${t.name} (may overwrite same-named files)`;
      },
      run: run((p, i) => p.decompressFile(i.server, i.root ?? "/", i.file)),
    },
    {
      name: "rename_files",
      description:
        `Rename or MOVE files and folders inside a Pelican server's volume on ${target.name}. Each 'from'/'to' is relative to ` +
        `'root' and 'to' may point into another folder, so this is how an extracted mod's DLL gets from a staging folder into ` +
        `BepInEx/plugins. An existing destination is refused by the daemon, never overwritten — delete it first if you mean to.`,
      tier: "execute",
      inputSchema: z.object({
        server: SERVER_REF,
        root: z.string().optional().describe("Directory both sides are relative to. Default '/'."),
        files: z
          .array(z.object({ from: z.string().min(1), to: z.string().min(1) }))
          .min(1)
          .max(100)
          .describe("Moves to perform, in order: [{from, to}]."),
      }),
      confirm: (input, t) => {
        const i = input as { server: string; root?: string; files: { from: string; to: string }[] };
        const shown = i.files.slice(0, 8).map((m) => `${m.from} -> ${m.to}`);
        const more = i.files.length > 8 ? ` (+${i.files.length - 8} more)` : "";
        return `Move ${i.files.length} item(s) under '${i.root ?? "/"}' on Pelican server '${i.server}' on ${t.name}: ${shown.join("; ")}${more}`;
      },
      run: run((p, i) => p.renameFiles(i.server, i.root ?? "/", i.files)),
    },
    {
      name: "delete_files",
      description:
        `PERMANENTLY delete files or folders inside a Pelican server's volume on ${target.name} — there is no trash. Names are ` +
        `exact (no patterns) and relative to 'root'; the volume root itself is refused. Meant for cleaning up a downloaded ` +
        `archive or a staging folder; think twice before pointing it at a game's save directory.`,
      tier: "execute",
      inputSchema: z.object({
        server: SERVER_REF,
        root: z.string().optional().describe("Directory the names are relative to. Default '/'."),
        files: z.array(z.string().min(1)).min(1).max(100).describe("Exact file/folder names to delete."),
      }),
      confirm: (input, t) => {
        const i = input as { server: string; root?: string; files: string[] };
        return `PERMANENTLY delete [${i.files.join(", ")}] under '${i.root ?? "/"}' on Pelican server '${i.server}' on ${t.name} (no trash)`;
      },
      run: run((p, i) => p.deleteFiles(i.server, i.root ?? "/", i.files)),
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
