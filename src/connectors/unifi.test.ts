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

describe("get_settings", () => {
  const settings = [
    { key: "dpi", _id: "d1", site_id: "s", enabled: true, fingerprinting_enabled: true },
    { key: "usg", _id: "u1", site_id: "s", upnp_enabled: false, radius_secret: "SUPERSECRET", x_ssh_password: "pw123" },
  ];
  function mock() {
    return mockFetch([
      { match: (u) => u.includes("/self"), reply: { json: { data: [{}] } } },
      { match: (u) => u.includes("/rest/setting"), reply: { json: { data: settings } } },
    ]);
  }

  it("filters by section and drops noise/ids", async () => {
    mock();
    const res = await tool("get_settings").run({ section: "dpi" }, ctx(cred({ fields: { api_key: "KEY123" } })));
    expect(res.isError).toBeFalsy();
    expect(res.text).toContain("[dpi]");
    expect(res.text).toContain('"enabled":true');
    expect(res.text).not.toContain("[usg]"); // section filter excludes it
    expect(res.text).not.toContain("d1"); // _id stripped
  });

  it("lists all sections and redacts secret fields", async () => {
    mock();
    const res = await tool("get_settings").run({}, ctx(cred({ fields: { api_key: "KEY123" } })));
    expect(res.text).toContain("[dpi]");
    expect(res.text).toContain("[usg]");
    expect(res.text).toContain('"upnp_enabled":false');
    expect(res.text).not.toContain("SUPERSECRET"); // radius_secret redacted
    expect(res.text).not.toContain("pw123"); // x_ssh_password redacted
  });

  it("redacts a secret whose value contains a quote (regex-on-JSON would leak the tail)", async () => {
    mockFetch([
      { match: (u) => u.includes("/self"), reply: { json: { data: [{}] } } },
      { match: (u) => u.includes("/rest/setting"), reply: { json: { data: [{ key: "usg", x_ssh_password: 'ab"cd"LEAKTAIL' }] } } },
    ]);
    const res = await tool("get_settings").run({ section: "usg" }, ctx(cred({ fields: { api_key: "KEY123" } })));
    expect(res.text).toContain('"x_ssh_password":"[redacted]"');
    expect(res.text).not.toContain("LEAKTAIL"); // structured redaction masks the whole value
  });

  it("reports available sections when the filter matches nothing", async () => {
    mock();
    const res = await tool("get_settings").run({ section: "nope" }, ctx(cred({ fields: { api_key: "KEY123" } })));
    expect(res.text).toContain("No settings section matching 'nope'");
    expect(res.text).toContain("dpi");
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

describe("set_gateway_feature (surgical toggle)", () => {
  // Stateful mock: a successful PUT updates the in-memory settings so a
  // subsequent GET (the post-write verification read) reflects it.
  function mock(settings: any[], putKey: string, putId: string, putReply: { status?: number; json?: unknown } = { json: { meta: { rc: "ok" } } }) {
    const state: any[] = settings.map((s) => ({ ...s }));
    const calls: { url: string; init: any }[] = [];
    vi.stubGlobal(
      "fetch",
      vi.fn(async (url: string, init: any) => {
        calls.push({ url, init });
        const method = init?.method ?? "GET";
        let status = 200;
        let json: unknown = {};
        if (url.includes("/self")) {
          json = { data: [{}] };
        } else if (url.includes(`/rest/setting/${putKey}/${putId}`) && method === "PUT") {
          status = putReply.status ?? 200;
          json = putReply.json ?? {};
          const rc = (json as { meta?: { rc?: string } })?.meta?.rc;
          if (status >= 200 && status < 300 && rc !== "error") {
            const idx = state.findIndex((s) => s._id === putId);
            if (idx >= 0) state[idx] = JSON.parse(init.body);
          }
        } else if (url.includes("/rest/setting") && method === "GET") {
          json = { data: state };
        }
        return {
          ok: status >= 200 && status < 300,
          status,
          statusText: "",
          headers: { get: () => null, getSetCookie: () => [] },
          text: async () => JSON.stringify(json),
        } as any;
      }),
    );
    return calls;
  }

  it("disables DPI by flipping the top-level enabled field", async () => {
    const calls = mock([{ key: "dpi", _id: "d1", enabled: true, fingerprintingEnabled: false }], "dpi", "d1");
    const res = await tool("set_gateway_feature").run({ feature: "dpi", enabled: false }, ctx(cred({ fields: { api_key: "K" } })));
    expect(res.isError).toBeFalsy();
    expect(res.text).toContain("DPI / Traffic Identification set to DISABLED");
    expect(res.text).toContain("was 'true'");
    const body = JSON.parse(calls.find((c) => c.init.method === "PUT")!.init.body);
    expect(body.enabled).toBe(false);
    expect(body.fingerprintingEnabled).toBe(false); // untouched
  });

  it("toggles the nested GeoIP ip_filtering.enabled without disturbing siblings", async () => {
    const usgGeo = { key: "usg_geo", _id: "g1", ip_filtering: { action: "block", countries: "CN,RU", enabled: true, traffic_direction: "both" } };
    const calls = mock([usgGeo], "usg_geo", "g1");
    const res = await tool("set_gateway_feature").run({ feature: "geoip", enabled: false }, ctx(cred({ fields: { api_key: "K" } })));
    expect(res.isError).toBeFalsy();
    const body = JSON.parse(calls.find((c) => c.init.method === "PUT")!.init.body);
    expect(body.ip_filtering.enabled).toBe(false);
    expect(body.ip_filtering.countries).toBe("CN,RU"); // siblings preserved
  });

  it("disables all hardware-offload fields at once", async () => {
    const usg = { key: "usg", _id: "u1", offload_sch: true, offload_accounting: true, offload_l2_blocking: true, upnp_enabled: false };
    const calls = mock([usg], "usg", "u1");
    await tool("set_gateway_feature").run({ feature: "offload", enabled: false }, ctx(cred({ fields: { api_key: "K" } })));
    const body = JSON.parse(calls.find((c) => c.init.method === "PUT")!.init.body);
    expect(body.offload_sch).toBe(false);
    expect(body.offload_accounting).toBe(false);
    expect(body.offload_l2_blocking).toBe(false);
    expect(body.upnp_enabled).toBe(false); // untouched
  });

  it("errors when the setting group for the feature is absent", async () => {
    mock([{ key: "dpi", _id: "d1", enabled: true }], "usg_geo", "g1");
    const res = await tool("set_gateway_feature").run({ feature: "geoip", enabled: false }, ctx(cred({ fields: { api_key: "K" } })));
    expect(res.isError).toBe(true);
    expect(res.text).toContain("no 'usg_geo' setting group");
  });

  it("surfaces a meta.rc='error' envelope on the PUT as a failure", async () => {
    mock([{ key: "dpi", _id: "d1", enabled: true }], "dpi", "d1", { status: 200, json: { meta: { rc: "error", msg: "api.err.NoSiteContext" } } });
    const res = await tool("set_gateway_feature").run({ feature: "dpi", enabled: false }, ctx(cred({ fields: { api_key: "K" } })));
    expect(res.isError).toBe(true);
    expect(res.text).toContain("api.err.NoSiteContext");
  });

  it("fails closed on GeoIP schema drift (missing ip_filtering) instead of writing", async () => {
    const calls = mock([{ key: "usg_geo", _id: "g1" }], "usg_geo", "g1"); // no ip_filtering object
    const res = await tool("set_gateway_feature").run({ feature: "geoip", enabled: false }, ctx(cred({ fields: { api_key: "K" } })));
    expect(res.isError).toBe(true);
    expect(res.text).toContain("expected shape");
    expect(calls.some((c) => c.init.method === "PUT")).toBe(false); // never wrote
  });

  it("fails closed when GeoIP ip_filtering.enabled is not a boolean", async () => {
    mock([{ key: "usg_geo", _id: "g1", ip_filtering: { enabled: "yes" } }], "usg_geo", "g1");
    const res = await tool("set_gateway_feature").run({ feature: "geoip", enabled: true }, ctx(cred({ fields: { api_key: "K" } })));
    expect(res.isError).toBe(true);
    expect(res.text).toContain("expected shape");
  });

  it("fails closed when a top-level feature field is missing/non-boolean (no fabrication)", async () => {
    // usg is missing offload_accounting — the offload toggle must refuse, not invent it.
    const calls = mock([{ key: "usg", _id: "u1", offload_sch: true, offload_l2_blocking: true }], "usg", "u1");
    const res = await tool("set_gateway_feature").run({ feature: "offload", enabled: false }, ctx(cred({ fields: { api_key: "K" } })));
    expect(res.isError).toBe(true);
    expect(res.text).toContain("expected shape");
    expect(res.text).toContain("usg.offload_accounting"); // names the offending field
    expect(calls.some((c) => c.init.method === "PUT")).toBe(false); // never wrote
  });

  it("aborts without writing if the setting group changed between the read and the write", async () => {
    let getN = 0;
    const v1 = { key: "usg", _id: "u1", upnp_enabled: false, sibling: "A" };
    const v2 = { key: "usg", _id: "u1", upnp_enabled: false, sibling: "B" }; // a sibling changed concurrently
    const calls: any[] = [];
    vi.stubGlobal(
      "fetch",
      vi.fn(async (url: string, init: any) => {
        calls.push({ url, init });
        const method = init?.method ?? "GET";
        let json: unknown = {};
        if (url.includes("/self")) json = { data: [{}] };
        else if (url.includes("/rest/setting") && method === "GET") json = { data: [getN++ === 0 ? v1 : v2] };
        else if (method === "PUT") json = { meta: { rc: "ok" } };
        return { ok: true, status: 200, statusText: "", headers: { get: () => null, getSetCookie: () => [] }, text: async () => JSON.stringify(json) } as any;
      }),
    );
    const res = await tool("set_gateway_feature").run({ feature: "upnp", enabled: true }, ctx(cred({ fields: { api_key: "K" } })));
    expect(res.isError).toBe(true);
    expect(res.text).toContain("changed under us");
    expect(calls.some((c) => (c.init?.method ?? "GET") === "PUT")).toBe(false); // never wrote
  });

  it("execute confirmation names the exact fields and warns about the full-group rewrite", () => {
    const c = tool("set_gateway_feature").confirm!;
    const offload = c({ feature: "offload", enabled: false }, target());
    expect(offload).toContain("Disable UniFi hardware offload (usg.offload_sch, usg.offload_accounting, usg.offload_l2_blocking) on unifi");
    expect(offload).toContain("rewrites the whole settings group");
    expect(c({ feature: "geoip", enabled: true }, target())).toContain("Enable UniFi GeoIP country firewall (usg_geo.ip_filtering.enabled) on unifi");
  });

  it("errors if the change doesn't hold after the write (post-write revert detected)", async () => {
    // GET always reports enabled:true (a concurrent writer keeps reverting), yet PUT 'succeeds'.
    const calls: any[] = [];
    vi.stubGlobal(
      "fetch",
      vi.fn(async (url: string, init: any) => {
        calls.push({ url, init });
        const method = init?.method ?? "GET";
        let json: unknown = {};
        if (url.includes("/self")) json = { data: [{}] };
        else if (url.includes("/rest/setting") && method === "GET") json = { data: [{ key: "dpi", _id: "d1", enabled: true }] };
        else if (method === "PUT") json = { meta: { rc: "ok" } };
        return { ok: true, status: 200, statusText: "", headers: { get: () => null, getSetCookie: () => [] }, text: async () => JSON.stringify(json) } as any;
      }),
    );
    const res = await tool("set_gateway_feature").run({ feature: "dpi", enabled: false }, ctx(cred({ fields: { api_key: "K" } })));
    expect(res.isError).toBe(true);
    expect(res.text).toContain("did not hold");
    expect(calls.some((c) => c.init.method === "PUT")).toBe(true); // it did attempt the write
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
