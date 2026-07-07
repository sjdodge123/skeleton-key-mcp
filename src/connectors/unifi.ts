import { z } from "zod";
import type { Connector, ConnectorTool, Credential, SnapshotArtifact, Target, ToolContext, ToolResult } from "./types.js";
import { deriveBaseUrl, tlsFetch } from "./net.js";

/**
 * UniFi connector — read a UniFi OS gateway (UDM / Cloud Gateway family) and make
 * *surgical* network changes without ever surfacing secrets.
 *
 * Auth: a UniFi OS **API key** (created in the UniFi UI → Control Plane →
 * Integrations) sent as `X-API-Key` is preferred; a username + password login is
 * the fallback (UniFi OS `/api/auth/login` → `TOKEN` cookie + `X-CSRF-Token`,
 * legacy controller `/api/login`). The classic Network API is reached under
 * `/proxy/network` on UniFi OS and at the root on a self-hosted controller; which
 * one the target speaks is auto-detected (per the connector-portability rule) and
 * cached per client.
 *
 * Why a bespoke connector instead of the generic `http` one: the UniFi
 * `networkconf` objects embed WireGuard/OpenVPN **private keys**, so a naive
 * read-modify-write to toggle a setting round-trips that key material through the
 * model context. Here every read is field-whitelisted and the IPv6 toggle does
 * its read-modify-write **entirely server-side**, returning only a redacted
 * summary — key material never reaches a tool result.
 */

const optionsSchema = z
  .object({
    /** Base URL; if omitted, host/port form the URL (443/8443 ⇒ https, else http). */
    baseUrl: z.string().url().optional(),
    /** UniFi site name (the API's short id, not the display name). */
    site: z.string().default("default"),
    /** Skip TLS verification for THIS target only — UniFi OS ships a self-signed
     *  cert and this is LAN-only, so default on. Per-request via an undici
     *  dispatcher, never process-global. */
    insecureTLS: z.boolean().default(true),
  })
  .default({});

type Options = z.infer<typeof optionsSchema>;

function options(target: Target): Options {
  return optionsSchema.parse(target.options ?? {});
}

export function baseUrl(target: Target): string {
  return deriveBaseUrl(target, { baseUrl: options(target).baseUrl, httpsPorts: [443, 8443] });
}

/** The API key from an explicit credential field, else the item's secret. Never
 *  the freeform notes (see Credential.secret) and never the password — a
 *  password belongs to the login flow, not the header. */
export function apiKeyFrom(cred: Credential): string | undefined {
  return cred.fields["api_key"] ?? cred.fields["token"] ?? cred.secret ?? undefined;
}

/** Field-name fragments that mark a value as secret in a UniFi config object.
 *  This is a DENYLIST, so it fails open on an unrecognized field — the families
 *  below were widened after `get_settings` was observed leaking a gateway API
 *  token, an SSH password *hash*, the mgmt key, an IPS/UTM token, and a bare
 *  `psk`, none of which the original `password|_psk|x_secret` set caught. Match
 *  the secret families broadly: any `*_key` (word-boundary, so benign label
 *  fields literally named `key` — e.g. lighting/ID keys — stay visible), any
 *  `token`/`secret`/`passwd`/`password`/`psk`, plus explicit key/cert material. */
const SECRET_KEY =
  /private|_key\b|passphrase|passwd|password|psk|pre_shared|secret|token|wireguard|openvpn|x_ca|cert|credential/i;

/** Maps a high-level gateway feature to the UniFi setting group + field(s) that
 *  toggle it. Keeps the execute tool constrained to known, meaningful switches
 *  rather than arbitrary setting writes — so the approval prompt is specific and
 *  a bug can't silently rewrite an unrelated setting. */
const FEATURE_SPECS: Record<string, { key: string; fields?: string[]; path?: [string, string]; label: string }> = {
  dpi: { key: "dpi", fields: ["enabled"], label: "DPI / Traffic Identification" },
  upnp: { key: "usg", fields: ["upnp_enabled"], label: "UPnP" },
  offload: { key: "usg", fields: ["offload_sch", "offload_accounting", "offload_l2_blocking"], label: "hardware offload" },
  geoip: { key: "usg_geo", path: ["ip_filtering", "enabled"], label: "GeoIP country firewall" },
};

export const GATEWAY_FEATURES = Object.keys(FEATURE_SPECS) as [string, ...string[]];

/** Human label for a feature (e.g. "hardware offload"), for the approval prompt. */
export function featureLabel(feature: string): string {
  return FEATURE_SPECS[feature]?.label ?? feature;
}

/** The exact setting fields a feature toggles, as `key.field` (or
 *  `key.parent.child`), so the execute confirmation names precisely what changes. */
export function featureFields(feature: string): string[] {
  const spec = FEATURE_SPECS[feature];
  if (!spec) return [];
  return spec.path ? [`${spec.key}.${spec.path.join(".")}`] : (spec.fields ?? []).map((f) => `${spec.key}.${f}`);
}

/** Best-effort redaction of secret-looking fields in a raw JSON *string* (server
 *  error bodies we can't reliably parse). Prefer redactSecrets for structured
 *  data — this regex can be defeated by an escaped quote inside a value, so it's
 *  only a backstop on already-truncated error text. Exported for testing. */
export function scrubSecrets(s: string): string {
  return s.replace(/"([A-Za-z0-9_]*?)"(\s*:\s*)"[^"]*"/g, (m, key: string, sep: string) =>
    SECRET_KEY.test(key) ? `"${key}"${sep}"[redacted]"` : m,
  );
}

/** Deep-copy `value`, replacing any property whose KEY looks secret with
 *  "[redacted]". Structured redaction (vs regex-on-JSON) so a secret value that
 *  contains a quote can't truncate the mask and leak its tail. Exported for
 *  testing. */
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

/** True only for an RFC1918 (private / LAN) IPv4 literal. `set_remote_logging`
 *  requires this so the gateway's logs can only ever be streamed to a LAN
 *  collector we control — never an off-LAN sink (the project is LAN-only, and a
 *  crash-log stream is sensitive). Exported for testing. */
export function isPrivateIPv4(ip: string): boolean {
  const m = /^(\d{1,3})\.(\d{1,3})\.(\d{1,3})\.(\d{1,3})$/.exec(ip);
  if (!m) return false;
  const a = Number(m[1]);
  const b = Number(m[2]);
  const c = Number(m[3]);
  const d = Number(m[4]);
  if ([a, b, c, d].some((n) => n > 255)) return false;
  return a === 10 || (a === 172 && b >= 16 && b <= 31) || (a === 192 && b === 168);
}

function humanUptime(seconds?: number): string {
  if (!seconds || seconds < 0) return "?";
  const d = Math.floor(seconds / 86400);
  const h = Math.floor((seconds % 86400) / 3600);
  const m = Math.floor((seconds % 3600) / 60);
  return d > 0 ? `${d}d${h}h` : h > 0 ? `${h}h${m}m` : `${m}m`;
}

interface UniFiDevice {
  name?: string;
  model?: string;
  type?: string;
  mac?: string;
  ip?: string;
  state?: number;
  uptime?: number;
  version?: string;
  previous_firmware?: string;
  upgradable?: boolean;
}
interface UniFiClient {
  name?: string;
  hostname?: string;
  mac?: string;
  ip?: string;
  is_wired?: boolean;
  ap_mac?: string;
  network?: string;
}
interface UniFiNetwork {
  _id: string;
  name?: string;
  purpose?: string;
  enabled?: boolean;
  vlan_enabled?: boolean;
  vlan?: number;
  ip_subnet?: string;
  ipv6_interface_type?: string;
  ipv6_ra_enabled?: boolean;
  [k: string]: unknown;
}

/** state 1 = connected/adopted; anything else is offline/pending. */
export function summarizeDevices(ds: UniFiDevice[]): string {
  if (!ds.length) return "No devices.";
  return ds
    .map((d) => {
      const fw = d.version ?? "?";
      const was = d.previous_firmware && d.previous_firmware !== d.version ? ` (was ${d.previous_firmware})` : "";
      const name = d.name || d.model || d.mac || "(unnamed)";
      return `- ${name} [${d.state === 1 ? "online" : "offline"}] up ${humanUptime(d.uptime)}  fw ${fw}${was}  ${d.ip ?? ""} ${d.mac ?? ""}`.trimEnd();
    })
    .join("\n");
}

export function summarizeClients(cs: UniFiClient[]): string {
  if (!cs.length) return "No active clients.";
  return cs
    .map((c) => {
      const name = c.name || c.hostname || "(unnamed)";
      const link = c.is_wired ? "wired" : `wifi${c.ap_mac ? ` via ${c.ap_mac}` : ""}`;
      return `- ${name}  ${c.ip ?? "?"}  ${c.mac ?? "?"}  ${link}`.trimEnd();
    })
    .join("\n");
}

/** Whitelisted fields only — the full object carries VPN keys, so it never
 *  leaves the process. */
export function summarizeNetworks(ns: UniFiNetwork[]): string {
  if (!ns.length) return "No networks.";
  return ns
    .map((n) => {
      const v6 = n.ipv6_interface_type ?? "none";
      const vlan = n.vlan_enabled && n.vlan ? ` vlan=${n.vlan}` : "";
      const off = n.enabled === false ? " (disabled)" : "";
      return `- ${n.name ?? "(unnamed)"} [${n._id}] purpose=${n.purpose ?? "?"} ipv6=${v6}${vlan}${off}`;
    })
    .join("\n");
}

/** UniFi client bound to one target — resolves auth + API prefix lazily, once. */
class UniFi {
  private cookie: string | null = null;
  private csrf: string | null = null;
  private prefix: string | null = null; // "/proxy/network" (UniFi OS) or "" (legacy)

  constructor(
    private readonly target: Target,
    private readonly cred: Credential,
  ) {}

  private get base(): string {
    return baseUrl(this.target);
  }
  private get site(): string {
    return options(this.target).site;
  }
  private get insecure(): boolean {
    return options(this.target).insecureTLS;
  }

  /** Log in with username/password, capturing the session cookie + CSRF token and
   *  learning whether this is a UniFi OS device (`/api/auth/login`) or a legacy
   *  controller (`/api/login`). */
  private async login(username: string, password: string): Promise<void> {
    for (const [path, prefix] of [
      ["/api/auth/login", "/proxy/network"],
      ["/api/login", ""],
    ] as const) {
      const res = await tlsFetch(
        `${this.base}${path}`,
        { method: "POST", headers: { "Content-Type": "application/json" }, body: JSON.stringify({ username, password, rememberMe: false }) },
        this.insecure,
      );
      if (res.status === 404) continue; // not this flavor; try the next
      if (!res.ok) throw new Error(`UniFi login failed: HTTP ${res.status}`);
      // Keep ALL session cookies, not just `TOKEN` — UniFi OS uses `TOKEN`, a
      // legacy controller uses `unifises`, so a TOKEN-only filter would drop the
      // legacy cookie and leave later calls unauthenticated while we think we're
      // logged in. Fail loudly if the login set no cookie at all.
      const setCookies = res.headers.getSetCookie?.() ?? (res.headers.get("set-cookie") ? [res.headers.get("set-cookie")!] : []);
      const pairs = setCookies.map((c) => c.split(";")[0]?.trim()).filter((p): p is string => Boolean(p));
      if (!pairs.length) throw new Error("UniFi login succeeded but returned no session cookie.");
      this.cookie = pairs.join("; ");
      this.csrf = res.headers.get("x-csrf-token") ?? res.headers.get("x-updated-csrf-token") ?? null;
      this.prefix = prefix;
      return;
    }
    throw new Error("UniFi login endpoint not found (tried UniFi OS and legacy controller).");
  }

  /** Ensure we have auth + a resolved API prefix. API key skips login and probes
   *  the prefix via `/self`; username/password learns the prefix at login. */
  private async ensureReady(): Promise<void> {
    if (this.prefix !== null) return;
    const apiKey = apiKeyFrom(this.cred);
    // An API key is authoritative when present — stale username/password fields
    // left on the same vault item must not silently divert to the weaker login
    // branch (and authenticate as the wrong principal).
    if (apiKey) {
      for (const prefix of ["/proxy/network", ""]) {
        const res = await tlsFetch(`${this.base}${prefix}/api/s/${this.site}/self`, { headers: { "X-API-Key": apiKey } }, this.insecure);
        if (res.ok) {
          this.prefix = prefix;
          return;
        }
      }
      this.prefix = "/proxy/network"; // default to UniFi OS; the real call will surface any auth error
      return;
    }
    if (this.cred.username && this.cred.password) {
      await this.login(this.cred.username, this.cred.password);
      return;
    }
    throw new Error("UniFi target needs an API key (store it as 'api_key' or the item's secret), or a username + password.");
  }

  private async authHeaders(mutating: boolean): Promise<Record<string, string>> {
    const apiKey = apiKeyFrom(this.cred);
    const headers: Record<string, string> = { Accept: "application/json" };
    if (apiKey) {
      headers["X-API-Key"] = apiKey;
    } else {
      if (this.cookie) headers["Cookie"] = this.cookie;
      if (mutating && this.csrf) headers["X-CSRF-Token"] = this.csrf;
    }
    return headers;
  }

  /** One Network API call. `path` is relative to the site API root. */
  private async api(
    path: string,
    opts: { method?: string; body?: unknown } = {},
  ): Promise<{ ok: boolean; status: number; json?: unknown; text: string }> {
    await this.ensureReady();
    const mutating = (opts.method ?? "GET") !== "GET";
    const headers = await this.authHeaders(mutating);
    if (opts.body !== undefined) headers["Content-Type"] = "application/json";
    const url = `${this.base}${this.prefix}/api/s/${this.site}${path}`;
    const res = await tlsFetch(
      url,
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

  /** Throw on an HTTP error OR a UniFi `{ meta: { rc: 'error' } }` envelope — the
   *  controller returns HTTP 200 with rc='error' on validation/permission/site
   *  failures, so an HTTP-only check would report a failed write as a success.
   *  Error text is scrubbed of key material before it can reach an exception. */
  private ensureOk(res: { ok: boolean; status: number; json?: unknown; text: string }, path: string): void {
    if (!res.ok) throw new Error(`HTTP ${res.status} on ${path}: ${scrubSecrets(res.text).slice(0, 300)}`);
    const meta = (res.json as { meta?: { rc?: string; msg?: string } })?.meta;
    if (meta?.rc && meta.rc !== "ok") {
      throw new Error(`UniFi API error on ${path}: ${scrubSecrets(meta.msg ?? meta.rc).slice(0, 200)}`);
    }
  }

  private async getData<T>(path: string): Promise<T[]> {
    const res = await this.api(path);
    this.ensureOk(res, path);
    return ((res.json as { data?: T[] })?.data ?? []) as T[];
  }

  async listDevices(): Promise<string> {
    return summarizeDevices(await this.getData<UniFiDevice>("/stat/device"));
  }
  async listClients(): Promise<string> {
    return summarizeClients(await this.getData<UniFiClient>("/stat/sta"));
  }
  async listNetworks(): Promise<string> {
    return summarizeNetworks(await this.getData<UniFiNetwork>("/rest/networkconf"));
  }

  /** Read the site/gateway settings groups (`/rest/setting`) — each object has a
   *  `key` (e.g. 'dpi', 'usg', 'mgmt'). Used to inspect what's actually enabled
   *  (DPI/Traffic Identification, UPnP, hardware offload). These objects can
   *  carry RADIUS/portal secrets, so the whole body is scrubbed before output. */
  async getSettings(section?: string): Promise<string> {
    const settings = await this.getData<Record<string, unknown> & { key?: string }>("/rest/setting");
    const want = section
      ? settings.filter((s) => (s.key ?? "").toLowerCase().includes(section.toLowerCase()))
      : settings;
    if (!want.length) {
      const keys = settings.map((s) => s.key ?? "?").join(", ");
      return section ? `No settings section matching '${section}'. Available: ${keys}` : "No settings.";
    }
    return want
      .map((s) => {
        const { key, _id, site_id, ...rest } = s as Record<string, unknown>;
        return `[${(key as string) ?? "?"}] ${JSON.stringify(redactSecrets(rest)).slice(0, 1500)}`;
      })
      .join("\n\n");
  }

  /** Surgically set a network's IPv6 mode. Reads the full networkconf object,
   *  flips only the IPv6 fields, and PUTs it back — all server-side. The object
   *  (which embeds VPN private keys) is never returned; the result reports only
   *  the network name and the before/after mode. */
  async setNetworkIpv6(networkRef: string, mode: "none" | "pd" | "slaac"): Promise<string> {
    const nets = await this.getData<UniFiNetwork>("/rest/networkconf");
    const net = nets.find((n) => n._id === networkRef || n.name?.toLowerCase() === networkRef.toLowerCase());
    if (!net) throw new Error(`No UniFi network named or id'd '${networkRef}'. Use list_networks to see options.`);
    const prev = net.ipv6_interface_type ?? "none";
    // Couple RA to the mode: a disable sets ipv6_ra_enabled=false, so a later
    // enable MUST set it back true — otherwise the mode looks restored but
    // clients get no router advertisements and still have no working IPv6.
    const updated: UniFiNetwork = { ...net, ipv6_interface_type: mode, ipv6_ra_enabled: mode !== "none" };
    const path = `/rest/networkconf/${net._id}`;
    const res = await this.api(path, { method: "PUT", body: updated });
    this.ensureOk(res, path);
    return `IPv6 on UniFi network '${net.name ?? net._id}' set to '${mode}' (RA ${mode !== "none" ? "on" : "off"}, was '${prev}'). Restore with mode='${prev}'.`;
  }

  /** Enable/disable a known gateway feature (DPI, UPnP, hardware offload, GeoIP)
   *  via a server-side read-modify-write of its setting group. The group object
   *  (which can carry RADIUS/portal secrets) is never returned — only the feature
   *  name and before/after state. */
  async setGatewayFeature(feature: string, enabled: boolean): Promise<string> {
    const spec = FEATURE_SPECS[feature];
    if (!spec) throw new Error(`Unknown gateway feature '${feature}'.`);
    const grp = (await this.getData<Record<string, unknown> & { key?: string; _id?: string }>("/rest/setting")).find(
      (g) => g.key === spec.key,
    );
    if (!grp?._id) throw new Error(`UniFi has no '${spec.key}' setting group, so ${spec.label} can't be toggled on this gateway.`);

    const updated: Record<string, unknown> = { ...grp };
    let prevDesc: string; // per-field prior state, so the audit trail supports a restore
    if (spec.path) {
      const [parentKey, childKey] = spec.path;
      const parent = grp[parentKey];
      // Fail closed on schema drift: only flip an EXISTING boolean inside an
      // existing plain object. Forcing the field onto a missing/array/scalar
      // parent would write a setting shape the controller never had.
      if (!parent || typeof parent !== "object" || Array.isArray(parent) || typeof (parent as Record<string, unknown>)[childKey] !== "boolean") {
        throw new Error(`UniFi ${spec.label} isn't in the expected shape (${spec.key}.${parentKey}.${childKey}) on this gateway; refusing to write.`);
      }
      prevDesc = `'${String((parent as Record<string, unknown>)[childKey])}'`;
      updated[parentKey] = { ...(parent as Record<string, unknown>), [childKey]: enabled };
    } else {
      // Same fail-closed invariant as the nested path: only flip fields that
      // already exist as booleans — never fabricate a field the controller/model
      // didn't expose (partial offload support, version drift).
      const bad = spec.fields!.filter((f) => typeof grp[f] !== "boolean");
      if (bad.length) {
        throw new Error(
          `UniFi ${spec.label} isn't in the expected shape on this gateway (missing/non-boolean: ${bad.map((f) => `${spec.key}.${f}`).join(", ")}); refusing to write.`,
        );
      }
      // Capture EVERY toggled field's prior value (not just the first), so a
      // mixed starting state (e.g. offload part-on) is recorded accurately and
      // the operator can restore it.
      prevDesc =
        spec.fields!.length === 1
          ? `'${String(grp[spec.fields![0]!])}'`
          : spec.fields!.map((f) => `${f}=${String(grp[f])}`).join(", ");
      for (const f of spec.fields!) updated[f] = enabled;
    }

    // Best-effort concurrency handling — NOT a guarantee. UniFi's classic API has
    // no conditional (CAS/ETag) write, only a full-group PUT, so a truly
    // simultaneous sibling edit cannot be fully prevented. We re-read and abort on
    // any drift already visible before writing (catching the common case); a
    // sibling change landing in the final re-read→PUT window is an accepted,
    // documented residual — the tool is approval-gated and every write is audited.
    const fresh = (await this.getData<Record<string, unknown> & { _id?: string }>("/rest/setting")).find((g) => g._id === grp._id);
    if (!fresh || JSON.stringify(fresh) !== JSON.stringify(grp)) {
      throw new Error(`UniFi '${spec.key}' settings changed under us (concurrent edit); aborted to avoid clobbering other fields — retry.`);
    }

    const path = `/rest/setting/${spec.key}/${grp._id}`;
    const res = await this.api(path, { method: "PUT", body: updated });
    this.ensureOk(res, path);

    // Post-write verification — the backstop for the irreducible final-window
    // race. Re-read and confirm OUR field(s) actually hold the new value; if a
    // concurrent full-group write landed right after ours and reverted them, we
    // report that rather than a phantom success. (Only our boolean fields are
    // checked, so server-side normalization of other fields can't false-positive.)
    const after = (await this.getData<Record<string, unknown> & { _id?: string }>("/rest/setting")).find((g) => g._id === grp._id);
    const held = spec.path
      ? !!after && typeof after[spec.path[0]] === "object" && after[spec.path[0]] !== null && (after[spec.path[0]] as Record<string, unknown>)[spec.path[1]] === enabled
      : !!after && spec.fields!.every((f) => after[f] === enabled);
    if (!held) {
      throw new Error(`UniFi ${spec.label} did not hold after the write (a concurrent settings change may have reverted it); retry and check the UniFi UI.`);
    }

    return `UniFi ${spec.label} set to ${enabled ? "ENABLED" : "DISABLED"} on ${this.target.name} (was ${prevDesc}).`;
  }

  /** Point the gateway's off-box logging at a LAN collector we control, so a
   *  crash-reboot no longer wipes the evidence. Writes the `rsyslogd` setting
   *  group: userspace remote syslog (`ip`/`enabled`) and/or kernel **netconsole**
   *  (`netconsole_*`), which fires at the crash instant before userspace dies.
   *  Same server-side read-modify-write with fail-closed schema checks,
   *  concurrency abort, and post-write verification as setGatewayFeature. The
   *  group carries no key material, but the result is redacted as a matter of
   *  course. `enabled:false` clears the targets, restoring local-only logging. */
  async setRemoteLogging(opts: {
    enabled: boolean;
    host?: string;
    mode?: "both" | "syslog" | "netconsole";
    syslogPort?: number;
    netconsolePort?: number;
  }): Promise<string> {
    const mode = opts.mode ?? "both";
    const doSyslog = mode === "both" || mode === "syslog";
    const doNet = mode === "both" || mode === "netconsole";

    if (opts.enabled && !opts.host) {
      throw new Error("set_remote_logging needs a collector 'host' (e.g. 192.168.0.32) when enabling.");
    }
    // LAN-only: the gateway's crash-log stream may only ever go to an RFC1918
    // collector, never a routable/off-LAN sink (defense-in-depth vs. a bad host).
    if (opts.host && !isPrivateIPv4(opts.host)) {
      throw new Error(`Invalid collector host '${opts.host}' — expected a private LAN IPv4 (e.g. 192.168.0.32).`);
    }
    const portStr = (name: string, v: number | undefined, dflt: number): string => {
      const n = v ?? dflt;
      if (!Number.isInteger(n) || n < 1 || n > 65535) throw new Error(`Invalid ${name} '${v}' — expected 1..65535.`);
      return String(n);
    };
    // Validate every input BEFORE the network round-trip, so a bad port can't
    // cost a GET/PUT.
    const syslogPortStr = doSyslog && opts.enabled ? portStr("syslogPort", opts.syslogPort, 514) : undefined;
    const netconsolePortStr = doNet && opts.enabled ? portStr("netconsolePort", opts.netconsolePort, 6666) : undefined;

    const grp = (await this.getData<Record<string, unknown> & { key?: string; _id?: string }>("/rest/setting")).find(
      (g) => g.key === "rsyslogd",
    );
    if (!grp?._id) throw new Error("UniFi has no 'rsyslogd' (remote logging) setting group on this gateway.");

    // Fail closed on schema drift — require EVERY field the write will touch to
    // already exist with the expected type, so version drift can't make us invent
    // a setting shape. Includes the enable-only fields (port/this_controller/
    // netconsole_port) so the invariant actually holds for them too.
    const need: Array<[string, string]> = [];
    if (doSyslog) {
      need.push(["ip", "string"], ["enabled", "boolean"]);
      if (opts.enabled) need.push(["port", "string"], ["this_controller", "boolean"]);
    }
    if (doNet) {
      need.push(["netconsole_enabled", "boolean"], ["netconsole_host", "string"]);
      if (opts.enabled) need.push(["netconsole_port", "string"]);
    }
    const bad = need.filter(([f, t]) => typeof grp[f] !== t);
    if (bad.length) {
      throw new Error(
        `UniFi 'rsyslogd' isn't in the expected shape on this gateway (missing/wrong-type: ${bad.map(([f]) => f).join(", ")}); refusing to write.`,
      );
    }

    const prev: Record<string, unknown> = {};
    const updated: Record<string, unknown> = { ...grp };
    if (doSyslog) {
      prev.ip = grp.ip;
      prev.enabled = grp.enabled;
      updated.ip = opts.enabled ? opts.host : "";
      updated.enabled = opts.enabled;
      if (opts.enabled) {
        updated.this_controller = true; // include the gateway's own logs
        updated.port = syslogPortStr;
      }
    }
    if (doNet) {
      prev.netconsole_enabled = grp.netconsole_enabled;
      prev.netconsole_host = grp.netconsole_host;
      updated.netconsole_enabled = opts.enabled;
      updated.netconsole_host = opts.enabled ? opts.host : "";
      if (opts.enabled) updated.netconsole_port = netconsolePortStr;
    }

    // Best-effort concurrency handling (UniFi has no CAS/ETag write) — abort on
    // any drift visible before writing; the residual final-window race is caught
    // by the post-write verification below. Same contract as setGatewayFeature.
    const fresh = (await this.getData<Record<string, unknown> & { _id?: string }>("/rest/setting")).find((g) => g._id === grp._id);
    if (!fresh || JSON.stringify(fresh) !== JSON.stringify(grp)) {
      throw new Error("UniFi 'rsyslogd' settings changed under us (concurrent edit); aborted to avoid clobbering other fields — retry.");
    }

    const path = `/rest/setting/rsyslogd/${grp._id}`;
    const res = await this.api(path, { method: "PUT", body: updated });
    this.ensureOk(res, path);

    // Post-write verification — re-read and confirm OUR fields hold, so a
    // concurrent write that reverted them is reported rather than a phantom success.
    const after = (await this.getData<Record<string, unknown> & { _id?: string }>("/rest/setting")).find((g) => g._id === grp._id);
    // Verify the boolean toggles (enabled / netconsole_enabled — the real source
    // of truth for whether logging is active) strictly; treat cleared string
    // targets as null/undefined/"" equivalent so a server-side normalization of a
    // blanked host can't throw a phantom failure (matches setGatewayFeature's
    // boolean-only contract while still checking the targets when present).
    const held =
      !!after &&
      Object.keys(prev).every((f) =>
        typeof updated[f] === "boolean" ? after[f] === updated[f] : (after[f] ?? "") === (updated[f] ?? ""),
      );
    if (!held) {
      throw new Error("UniFi remote logging did not hold after the write (a concurrent settings change may have reverted it); retry and check the UniFi UI.");
    }

    const changed = Object.keys(prev)
      .map((f) => `${f}: ${JSON.stringify(prev[f])} → ${JSON.stringify(updated[f])}`)
      .join(", ");
    if (!opts.enabled) {
      return `UniFi remote logging DISABLED on ${this.target.name} (targets cleared). Changed ${changed}.`;
    }
    // Report the ports the gateway actually stored (post-write re-read), not the
    // requested values, in case it normalized them.
    const targets = [
      doSyslog ? `syslog→${opts.host}:${after?.port ?? updated.port}` : null,
      doNet ? `netconsole→${opts.host}:${after?.netconsole_port ?? updated.netconsole_port}` : null,
    ]
      .filter(Boolean)
      .join(", ");
    // "CONFIGURED", not "streaming": the PUT persisted the target, but this write
    // can't confirm the collector is actually receiving (esp. netconsole/UDP).
    return `UniFi remote logging CONFIGURED on ${this.target.name} (${targets}) — persisted to the gateway; confirm the collector is receiving (delivery isn't verified by this write). Changed ${changed}. Revert with enabled=false.`;
  }

  /** Force a device to re-provision (`POST /cmd/devmgr {cmd:'force-provision'}`).
   *  A `/rest/setting` PUT only updates the controller DB; the device keeps
   *  running its previously-generated config until it provisions — so a settings
   *  write (set_remote_logging, set_gateway_feature) can verify-succeed yet never
   *  take effect on the datapath. This re-applies the stored config. Defaults to
   *  the gateway (identified positively by device role/model — NOT by IP, since a
   *  gateway's stat/device `ip` is often its WAN address); `deviceRef` (name / MAC
   *  / IP) targets another device. Refuses an ambiguous match rather than guessing.
   *  Re-applies in place — normally no reboot, but can briefly blip the gateway. */
  async forceProvision(deviceRef?: string): Promise<string> {
    const devices = await this.getData<UniFiDevice>("/stat/device");
    if (!devices.length) throw new Error("UniFi returned no devices to provision.");
    const isGateway = (d: UniFiDevice) => d.type === "ugw" || d.type === "udm" || /gateway|udm|ucg|udr|uxg/i.test(d.model ?? "");

    let dev: UniFiDevice;
    if (deviceRef) {
      const q = deviceRef.toLowerCase();
      const matches = devices.filter((d) => d.mac?.toLowerCase() === q || d.name?.toLowerCase() === q || d.ip === deviceRef);
      if (!matches.length) throw new Error(`No UniFi device matching '${deviceRef}'. Use list_devices to see options.`);
      if (matches.length > 1) {
        throw new Error(`'${deviceRef}' is ambiguous — matches ${matches.map((m) => `${m.name ?? m.model ?? "?"}/${m.mac ?? "?"}`).join(", ")}. Pass an exact MAC.`);
      }
      dev = matches[0]!;
    } else {
      // Default = the gateway, identified POSITIVELY by role/model. A UniFi site
      // has exactly one gateway; if more than one gateway-class device turns up we
      // refuse and ask for an explicit ref rather than blipping the wrong one.
      const gateways = devices.filter(isGateway);
      if (!gateways.length) throw new Error("Couldn't identify a gateway device to provision; pass an explicit device name/MAC (see list_devices).");
      if (gateways.length > 1) {
        throw new Error(`Multiple gateway-class devices found (${gateways.map((g) => g.name ?? g.model ?? g.mac).join(", ")}); pass an explicit device name/MAC.`);
      }
      dev = gateways[0]!;
    }
    if (!dev.mac) throw new Error(`UniFi device '${dev.name ?? deviceRef}' has no MAC address; can't provision it.`);

    const path = "/cmd/devmgr";
    const res = await this.api(path, { method: "POST", body: { cmd: "force-provision", mac: dev.mac } });
    this.ensureOk(res, path);
    return `Force-provisioned UniFi ${dev.name ?? dev.model ?? dev.mac} (${dev.mac}) on ${this.target.name} — the device re-applies its stored config (allow ~30–60s). Confirm the intended change actually took effect.`;
  }

  /** Disaster-recovery snapshot: scrubbed settings/networks/devices as a
   *  human-readable reference, plus the authoritative native `.unf` backup
   *  (which DOES contain secrets — encrypted at rest by the snapshot service).
   *  The `.unf` fetch is best-effort; the reference exports always land. */
  async snapshot(): Promise<SnapshotArtifact[]> {
    const arts: SnapshotArtifact[] = [];
    arts.push({ name: "settings.txt", data: Buffer.from(await this.getSettings()), note: "scrubbed settings reference" });
    arts.push({ name: "networks.txt", data: Buffer.from(await this.listNetworks()), note: "networks (VPN keys stripped)" });
    arts.push({ name: "devices.txt", data: Buffer.from(await this.listDevices()), note: "adopted devices" });
    try {
      // POST /cmd/backup makes the controller write a .unf and returns its URL
      // (shape verified live; coded defensively). The /dl/backup path is outside
      // the site-API root and binary, so fetch it raw with the same auth headers.
      const res = await this.api("/cmd/backup", { method: "POST", body: { cmd: "backup" } });
      this.ensureOk(res, "/cmd/backup");
      const url = (res.json as { data?: { url?: string }[] })?.data?.[0]?.url;
      if (typeof url === "string" && url) {
        const dl = await tlsFetch(`${this.base}${this.prefix}${url}`, { headers: await this.authHeaders(false) }, this.insecure);
        if (dl.ok) {
          const buf = Buffer.from(await dl.arrayBuffer());
          if (buf.length) arts.push({ name: "backup.unf", data: buf, note: "UniFi native backup (contains secrets)" });
        }
      }
    } catch {
      /* .unf is best-effort; the scrubbed references above still captured */
    }
    return arts;
  }
}

async function withClient<T>(ctx: ToolContext, fn: (u: UniFi) => Promise<T>): Promise<T> {
  const cred = await ctx.getCredential();
  return fn(new UniFi(ctx.target, cred));
}

const ok = (text: string): ToolResult => ({ text });

function run(fn: (u: UniFi, input: any) => Promise<string>) {
  return async (input: unknown, ctx: ToolContext): Promise<ToolResult> => {
    try {
      return ok(await withClient(ctx, (u) => fn(u, input)));
    } catch (e) {
      return { text: `UniFi error: ${e instanceof Error ? e.message : String(e)}`, isError: true };
    }
  };
}

function buildTools(target: Target): ConnectorTool[] {
  return [
    {
      name: "list_devices",
      description: `List UniFi devices on ${target.name} with online state, uptime, and firmware (current + previous) — the forensics view for spotting a gateway/AP reboot.`,
      tier: "read",
      inputSchema: z.object({}),
      run: run((u) => u.listDevices()),
    },
    {
      name: "list_clients",
      description: `List active clients on ${target.name} (name, IP, MAC, wired/wifi) — use to find a host's MAC/IP, e.g. Home Assistant.`,
      tier: "read",
      inputSchema: z.object({}),
      run: run((u) => u.listClients()),
    },
    {
      name: "list_networks",
      description: `List UniFi networks on ${target.name} (id, name, purpose, IPv6 mode, VLAN). VPN key material is stripped from the output.`,
      tier: "read",
      inputSchema: z.object({}),
      run: run((u) => u.listNetworks()),
    },
    {
      name: "get_settings",
      description:
        `Read UniFi site/gateway settings on ${target.name} — e.g. DPI/Traffic Identification, UPnP, hardware offload. ` +
        `Optional 'section' filters by setting key (e.g. 'dpi', 'usg'); omit to list every section. Secret fields (RADIUS/portal/keys) are redacted.`,
      tier: "read",
      inputSchema: z.object({
        section: z.string().optional().describe("Filter by setting key, e.g. 'dpi' or 'usg'. Omit to list all sections."),
      }),
      run: run((u, i) => u.getSettings(i.section)),
    },
    {
      name: "set_network_ipv6",
      description:
        `Set the IPv6 mode of a UniFi network on ${target.name} ('none' disables IPv6, 'pd' = prefix delegation, 'slaac'). ` +
        `The read-modify-write happens server-side so VPN private keys are never exposed; the result reports the previous mode so you can restore it.`,
      tier: "execute",
      inputSchema: z.object({
        network: z.string().describe("Network name (e.g. 'Default') or its id."),
        mode: z.enum(["none", "pd", "slaac"]).describe("'none' disables IPv6 on the network."),
      }),
      confirm: (input, t) => {
        const i = input as { network: string; mode: string };
        return `Set IPv6 to '${i.mode}' on UniFi network '${i.network}' (${t.name})`;
      },
      run: run((u, i) => u.setNetworkIpv6(i.network, i.mode)),
    },
    {
      name: "set_gateway_feature",
      description:
        `Enable or disable a UniFi gateway feature on ${target.name}: 'dpi' (Traffic Identification), 'upnp', ` +
        `'offload' (hardware offload), or 'geoip' (country firewall). Surgical server-side read-modify-write — ` +
        `VPN/portal secrets never surface — and it reports the prior state so you can revert. ` +
        `The change hits the controller DB; run force_provision to make the gateway actually apply it.`,
      tier: "execute",
      inputSchema: z.object({
        feature: z.enum(GATEWAY_FEATURES).describe("dpi | upnp | offload | geoip"),
        enabled: z.boolean().describe("true = enable, false = disable"),
      }),
      confirm: (input, t) => {
        const i = input as { feature: string; enabled: boolean };
        return (
          `${i.enabled ? "Enable" : "Disable"} UniFi ${featureLabel(i.feature)} (${featureFields(i.feature).join(", ")}) on ${t.name}` +
          ` — rewrites the whole settings group; avoid editing UniFi settings at the same time`
        );
      },
      run: run((u, i) => u.setGatewayFeature(i.feature, i.enabled)),
    },
    {
      name: "set_remote_logging",
      description:
        `Stream ${target.name}'s off-box logs to a LAN collector so a crash-reboot doesn't wipe the evidence — ` +
        `configures the gateway's rsyslogd group for userspace remote syslog and/or kernel netconsole (which fires ` +
        `at the crash instant). Surgical server-side read-modify-write; the collector must be a private LAN IPv4 and ` +
        `reachable from the gateway (this write persists the target but can't confirm delivery — verify the collector ` +
        `is receiving). Reports prior state so you can revert with enabled=false. ` +
        `Run force_provision afterward — the gateway won't start forwarding until it re-provisions.`,
      tier: "execute",
      inputSchema: z.object({
        enabled: z.boolean().describe("true = stream logs to host; false = clear the syslog + netconsole targets (revert)."),
        host: z.string().optional().describe("Collector's private LAN IPv4 (e.g. 192.168.0.32). Required when enabled=true."),
        mode: z.enum(["both", "syslog", "netconsole"]).optional().describe("Which channel(s) to configure. Default 'both'."),
        syslogPort: z.number().int().optional().describe("Remote syslog UDP port (default 514)."),
        netconsolePort: z.number().int().optional().describe("Netconsole UDP port (default 6666)."),
      }),
      confirm: (input, t) => {
        const i = input as { enabled: boolean; host?: string; mode?: string };
        const ch = i.mode ?? "both";
        return i.enabled
          ? `Enable UniFi remote logging (${ch}) → ${i.host} on ${t.name} — rewrites the rsyslogd settings group`
          : `Disable UniFi remote logging (clear syslog + netconsole targets) on ${t.name} — rewrites the rsyslogd settings group`;
      },
      run: run((u, i) => u.setRemoteLogging(i)),
    },
    {
      name: "force_provision",
      description:
        `Force a UniFi device on ${target.name} to re-provision (re-apply its stored config) so a settings change actually ` +
        `takes effect on the device — a set_gateway_feature / set_remote_logging write only updates the controller DB until ` +
        `the device provisions. Defaults to the gateway; pass 'device' (name/MAC/IP) to target another. Re-applies config in ` +
        `place (normally no reboot) but may briefly blip the gateway.`,
      tier: "execute",
      inputSchema: z.object({
        device: z.string().optional().describe("Device name, MAC, or IP to provision. Omit to target the gateway."),
      }),
      confirm: (input, t) => {
        const i = input as { device?: string };
        return `Force-provision UniFi ${i.device ?? "gateway"} on ${t.name} — re-applies stored config; may briefly blip the gateway`;
      },
      run: run((u, i) => u.forceProvision(i.device)),
    },
  ];
}

export const unifiConnector: Connector = {
  type: "unifi",
  label: "UniFi (network)",
  configSchema: optionsSchema,
  requiresCredential: true,
  buildTools,
  snapshot: (ctx) => withClient(ctx, (u) => u.snapshot()),
};
