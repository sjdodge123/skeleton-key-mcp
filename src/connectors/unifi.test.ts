import { describe, it, expect, vi, afterEach } from "vitest";
import { unifiConnector, baseUrl, apiKeyFrom, scrubSecrets, summarizeDevices, summarizeNetworks } from "./unifi.js";
import type { Credential, Target, ToolContext } from "./types.js";

const WG_KEY = "aVeryPrivateWireguardKey1234567890AB=";

function target(options: Record<string, unknown> = {}, port = 443): Target {
  // insecureTLS:false so tlsFetch uses the (stubbable) global fetch.
  return { name: "unifi", type: "unifi", host: "10.0.0.1", port, credentialRef: "unifi-apikey", options: { insecureTLS: false, ...options } };
}
function cred(partial: Partial<Credential>): Credential {
  return { ref: "unifi-apikey", fields: {}, uris: [], ...partial };
}
function ctx(c: Credential, t: Target = target()): ToolContext {
  return { target: t, getCredential: async () => c };
}
function tool(name: string, t: Target = target()) {
  return unifiConnector.buildTools(t).find((x) => x.name === name)!;
}

/** fetch mock: match by (url, init) and reply with a body + optional headers. */
function mockFetch(routes: { match: (url: string, init: any) => boolean; reply: { status?: number; json?: unknown; headers?: Record<string, string | string[]> } }[]) {
  const calls: { url: string; init: any }[] = [];
  const fn = vi.fn(async (url: string, init: any) => {
    calls.push({ url, init });
    const route = routes.find((r) => r.match(url, init));
    if (!route) throw new Error(`no mock route for ${init?.method ?? "GET"} ${url}`);
    const status = route.reply.status ?? 200;
    const h = route.reply.headers ?? {};
    return {
      ok: status >= 200 && status < 300,
      status,
      statusText: "",
      headers: {
        get: (k: string) => {
          const v = h[k.toLowerCase()] ?? h[k];
          return v === undefined ? null : Array.isArray(v) ? v.join(", ") : v;
        },
        getSetCookie: () => {
          const v = h["set-cookie"];
          return v === undefined ? [] : Array.isArray(v) ? v : [v];
        },
      },
      text: async () => (route.reply.json !== undefined ? JSON.stringify(route.reply.json) : ""),
    } as any;
  });
  vi.stubGlobal("fetch", fn);
  return calls;
}

afterEach(() => vi.restoreAllMocks());

describe("pure helpers", () => {
  it("baseUrl picks https on 443/8443", () => {
    expect(baseUrl(target({}, 443))).toBe("https://10.0.0.1:443");
    expect(baseUrl(target({}, 8443))).toBe("https://10.0.0.1:8443");
    expect(baseUrl(target({ baseUrl: "https://unifi.lan/" }, 443))).toBe("https://unifi.lan");
  });

  it("apiKeyFrom prefers explicit fields, then the secret, never the password", () => {
    expect(apiKeyFrom(cred({ fields: { api_key: "k1" } }))).toBe("k1");
    expect(apiKeyFrom(cred({ fields: { token: "k2" } }))).toBe("k2");
    expect(apiKeyFrom(cred({ secret: "k3" }))).toBe("k3");
    expect(apiKeyFrom(cred({ password: "pw", username: "u" }))).toBeUndefined();
  });

  it("scrubSecrets redacts key-material fields and leaves others intact", () => {
    const raw = JSON.stringify({ name: "Default", x_wireguard_private_key: WG_KEY, ipv6_interface_type: "pd" });
    const out = scrubSecrets(raw);
    expect(out).not.toContain(WG_KEY);
    expect(out).toContain('"name":"Default"');
    expect(out).toContain('"ipv6_interface_type":"pd"');
  });

  it("summarizeDevices flags a firmware change and offline state", () => {
    const out = summarizeDevices([{ name: "UCG", state: 1, uptime: 90000, version: "5.1.19", previous_firmware: "5.1.15", ip: "10.0.0.1", mac: "aa" }]);
    expect(out).toContain("UCG [online]");
    expect(out).toContain("fw 5.1.19 (was 5.1.15)");
    expect(summarizeDevices([{ name: "AP", state: 0 }])).toContain("[offline]");
  });

  it("summarizeNetworks whitelists fields — no VPN keys leak", () => {
    const out = summarizeNetworks([{ _id: "n1", name: "Default", purpose: "corporate", ipv6_interface_type: "pd", x_wireguard_private_key: WG_KEY } as any]);
    expect(out).toContain("Default [n1]");
    expect(out).toContain("ipv6=pd");
    expect(out).not.toContain(WG_KEY);
  });
});

describe("API-key auth + redaction", () => {
  it("list_networks sends X-API-Key, probes the UniFi OS prefix, and never surfaces key material", async () => {
    const calls = mockFetch([
      { match: (u) => u.includes("/proxy/network/api/s/default/self"), reply: { json: { data: [{}] } } },
      {
        match: (u) => u.includes("/proxy/network/api/s/default/rest/networkconf"),
        reply: { json: { data: [{ _id: "n1", name: "Default", purpose: "corporate", ipv6_interface_type: "pd", x_wireguard_private_key: WG_KEY }] } },
      },
    ]);
    const res = await tool("list_networks").run({}, ctx(cred({ fields: { api_key: "KEY123" } })));
    expect(res.isError).toBeFalsy();
    expect(res.text).toContain("Default [n1]");
    expect(res.text).not.toContain(WG_KEY);
    // API key header present on every call; never a Cookie.
    expect(calls.every((c) => c.init.headers["X-API-Key"] === "KEY123")).toBe(true);
    expect(calls.some((c) => "Cookie" in c.init.headers)).toBe(false);
  });
});

describe("set_network_ipv6 (surgical write)", () => {
  it("flips only the IPv6 fields, preserves the key in the PUT, and keeps it out of the result", async () => {
    const netObj = { _id: "n1", name: "Default", purpose: "corporate", ipv6_interface_type: "pd", ipv6_ra_enabled: true, x_wireguard_private_key: WG_KEY };
    const calls = mockFetch([
      { match: (u) => u.includes("/self"), reply: { json: { data: [{}] } } },
      { match: (u, i) => u.includes("/rest/networkconf") && (i?.method ?? "GET") === "GET", reply: { json: { data: [netObj] } } },
      { match: (u, i) => u.includes("/rest/networkconf/n1") && i?.method === "PUT", reply: { json: { data: [netObj] } } },
    ]);
    const res = await tool("set_network_ipv6").run({ network: "default", mode: "none" }, ctx(cred({ fields: { api_key: "KEY123" } })));

    expect(res.isError).toBeFalsy();
    expect(res.text).toBe("IPv6 on UniFi network 'Default' set to 'none' (RA off, was 'pd'). Restore with mode='pd'.");
    expect(res.text).not.toContain(WG_KEY);

    const put = calls.find((c) => c.init.method === "PUT")!;
    const body = JSON.parse(put.init.body);
    expect(body.ipv6_interface_type).toBe("none"); // flipped
    expect(body.ipv6_ra_enabled).toBe(false); // RA off when disabling
    expect(body.purpose).toBe("corporate"); // untouched
    expect(body.x_wireguard_private_key).toBe(WG_KEY); // preserved server-side, not clobbered
  });

  it("errors clearly when the network is not found", async () => {
    mockFetch([
      { match: (u) => u.includes("/self"), reply: { json: { data: [{}] } } },
      { match: (u) => u.includes("/rest/networkconf"), reply: { json: { data: [{ _id: "n1", name: "Default" }] } } },
    ]);
    const res = await tool("set_network_ipv6").run({ network: "Guest", mode: "none" }, ctx(cred({ fields: { api_key: "KEY123" } })));
    expect(res.isError).toBe(true);
    expect(res.text).toContain("No UniFi network");
  });

  it("re-enables RA when the mode is not 'none' (so a restore actually advertises IPv6)", async () => {
    const netObj = { _id: "n1", name: "Default", ipv6_interface_type: "none", ipv6_ra_enabled: false };
    const calls = mockFetch([
      { match: (u) => u.includes("/self"), reply: { json: { data: [{}] } } },
      { match: (u, i) => u.includes("/rest/networkconf") && (i?.method ?? "GET") === "GET", reply: { json: { data: [netObj] } } },
      { match: (u, i) => u.includes("/rest/networkconf/n1") && i?.method === "PUT", reply: { json: { meta: { rc: "ok" }, data: [netObj] } } },
    ]);
    const res = await tool("set_network_ipv6").run({ network: "Default", mode: "pd" }, ctx(cred({ fields: { api_key: "KEY123" } })));
    expect(res.isError).toBeFalsy();
    const body = JSON.parse(calls.find((c) => c.init.method === "PUT")!.init.body);
    expect(body.ipv6_interface_type).toBe("pd");
    expect(body.ipv6_ra_enabled).toBe(true);
  });

  it("reports a UniFi envelope error (HTTP 200 + meta.rc='error') as a failure, not a success", async () => {
    const netObj = { _id: "n1", name: "Default", ipv6_interface_type: "pd" };
    mockFetch([
      { match: (u) => u.includes("/self"), reply: { json: { data: [{}] } } },
      { match: (u, i) => u.includes("/rest/networkconf") && (i?.method ?? "GET") === "GET", reply: { json: { data: [netObj] } } },
      { match: (u, i) => u.includes("/rest/networkconf/n1") && i?.method === "PUT", reply: { status: 200, json: { meta: { rc: "error", msg: "api.err.NoPermission" } } } },
    ]);
    const res = await tool("set_network_ipv6").run({ network: "Default", mode: "none" }, ctx(cred({ fields: { api_key: "KEY123" } })));
    expect(res.isError).toBe(true);
    expect(res.text).toContain("api.err.NoPermission");
  });
});

describe("auth selection", () => {
  it("prefers the API key even when stale username/password are also on the item", async () => {
    const calls = mockFetch([
      { match: (u) => u.includes("/self"), reply: { json: { data: [{}] } } },
      { match: (u) => u.includes("/rest/networkconf"), reply: { json: { data: [{ _id: "n1", name: "Default" }] } } },
    ]);
    const res = await tool("list_networks").run({}, ctx(cred({ fields: { api_key: "KEY123" }, username: "stale", password: "old" })));
    expect(res.isError).toBeFalsy();
    expect(calls.every((c) => c.init.headers["X-API-Key"] === "KEY123")).toBe(true);
    expect(calls.some((c) => /\/api\/(auth\/)?login/.test(c.url))).toBe(false); // never logged in
  });
});

describe("username/password login", () => {
  it("logs in via UniFi OS, captures the TOKEN cookie + CSRF, and sends them on a mutating call", async () => {
    const netObj = { _id: "n1", name: "Default", ipv6_interface_type: "pd" };
    const calls = mockFetch([
      {
        match: (u, i) => u.endsWith("/api/auth/login") && i?.method === "POST",
        reply: { json: { meta: { rc: "ok" } }, headers: { "set-cookie": ["TOKEN=jwt.abc; Path=/; HttpOnly"], "x-csrf-token": "csrf-xyz" } },
      },
      { match: (u, i) => u.includes("/rest/networkconf") && (i?.method ?? "GET") === "GET", reply: { json: { data: [netObj] } } },
      { match: (u, i) => u.includes("/rest/networkconf/n1") && i?.method === "PUT", reply: { json: { data: [netObj] } } },
    ]);
    const res = await tool("set_network_ipv6").run({ network: "Default", mode: "slaac" }, ctx(cred({ username: "admin", password: "pw" })));
    expect(res.isError).toBeFalsy();

    const put = calls.find((c) => c.init.method === "PUT")!;
    expect(put.init.headers["Cookie"]).toBe("TOKEN=jwt.abc");
    expect(put.init.headers["X-CSRF-Token"]).toBe("csrf-xyz"); // CSRF only on the mutating call
    // Data calls go through the UniFi OS prefix learned at login.
    expect(put.url).toContain("/proxy/network/api/s/default/");
  });

  it("falls back to the legacy controller and keeps its non-TOKEN session cookie", async () => {
    const netObj = { _id: "n1", name: "Default", ipv6_interface_type: "pd" };
    const calls = mockFetch([
      { match: (u) => u.endsWith("/api/auth/login"), reply: { status: 404 } }, // not UniFi OS
      {
        match: (u, i) => u.endsWith("/api/login") && i?.method === "POST",
        reply: { json: { meta: { rc: "ok" } }, headers: { "set-cookie": ["unifises=sess123; Path=/; HttpOnly", "csrf_token=ct9; Path=/"] } },
      },
      { match: (u, i) => u.includes("/rest/networkconf") && (i?.method ?? "GET") === "GET", reply: { json: { data: [netObj] } } },
      { match: (u, i) => u.includes("/rest/networkconf/n1") && i?.method === "PUT", reply: { json: { meta: { rc: "ok" }, data: [netObj] } } },
    ]);
    const res = await tool("set_network_ipv6").run({ network: "Default", mode: "none" }, ctx(cred({ username: "admin", password: "pw" })));
    expect(res.isError).toBeFalsy();
    const put = calls.find((c) => c.init.method === "PUT")!;
    expect(put.init.headers["Cookie"]).toContain("unifises=sess123"); // legacy cookie preserved
    expect(put.url).toContain("/api/s/default/"); // legacy prefix (no /proxy/network)
    expect(put.url).not.toContain("/proxy/network");
  });
});
