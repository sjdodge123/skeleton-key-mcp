import { z } from "zod";
import type { Connector, ConnectorTool, Credential, Target, ToolContext, ToolResult } from "./types.js";
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

/** Field-name fragments that mark a value as secret in a UniFi config object. */
const SECRET_KEY = /private_key|wireguard|openvpn|passphrase|password|_psk|pre_shared|x_ca|x_secret|radius_secret/i;

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
  ];
}

export const unifiConnector: Connector = {
  type: "unifi",
  label: "UniFi (network)",
  configSchema: optionsSchema,
  requiresCredential: true,
  buildTools,
};
