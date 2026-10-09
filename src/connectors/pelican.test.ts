import { describe, it, expect, vi, afterEach } from "vitest";
import {
  pelicanConnector,
  baseUrl,
  keyFor,
  redactSecrets,
  scrubSecrets,
  isPrivateIPv4,
  assertTransportOk,
  assertCronField,
  expandPorts,
  assertAllocationIp,
  assertEggSourceUrl,
  assertSafePath,
  assertSafeUser,
  compareVersions,
  parsePanelVersion,
  PANEL_UPGRADE_STEPS,
  fetchEggFromUrl,
  parseEggContent,
  MAX_PORTS_PER_CALL,
  MAX_EGG_BYTES,
  summarizeEggs,
  summarizeNodes,
  summarizeAllocations,
  summarizeServers,
  summarizeSchedules,
  cronOf,
  assertVolumePath,
  assertExactName,
  assertPullUrl,
  redactFileLines,
  summarizeFiles,
  FILE_PULL_POLL,
  FILE_READ_MAX_BYTES,
  FILE_WRITE_MAX_BYTES,
  looksLikeDaemonTimeout,
} from "./pelican.js";
import type { Credential, Target, ToolContext } from "./types.js";
import { checkCommand } from "./command-policy.js";

const APP = "papp_ApplicationKeySecret123";
const CLI = "pacc_ClientKeySecret456";
const RCON = "sup3r-secret-rcon";

function target(options: Record<string, unknown> = {}, port?: number): Target {
  return { name: "pelican-panel", type: "pelican", host: "192.168.0.48", port, credentialRef: "pelican-panel", options };
}
function cred(partial: Partial<Credential> = {}): Credential {
  return { ref: "pelican-panel", fields: { application_key: APP, client_key: CLI }, uris: [], ...partial };
}
function ctx(c: Credential = cred(), t: Target = target({ ownerUserId: 7 })): ToolContext {
  return { target: t, getCredential: async () => c };
}
function tool(name: string, t: Target = target({ ownerUserId: 7 })) {
  return pelicanConnector.buildTools(t).find((x) => x.name === name)!;
}

/** Fractal list envelope. */
const list = (attrs: unknown[], page = 1, totalPages = 1) => ({
  object: "list",
  data: attrs.map((a) => ({ object: "x", attributes: a })),
  meta: { pagination: { current_page: page, total_pages: totalPages } },
});
const item = (attrs: unknown) => ({ object: "x", attributes: attrs });

type MockReply = { status?: number; json?: unknown; text?: string; headers?: Record<string, string> };
function mockFetch(routes: { match: (url: string, init: any) => boolean; reply: MockReply | (() => MockReply) }[]) {
  const calls: { url: string; init: any }[] = [];
  const fn = vi.fn(async (url: string, init: any) => {
    calls.push({ url, init });
    const route = routes.find((r) => r.match(url, init));
    if (!route) throw new Error(`no mock route for ${init?.method ?? "GET"} ${url}`);
    const reply = typeof route.reply === "function" ? route.reply() : route.reply;
    const status = reply.status ?? 200;
    const hdrs = Object.fromEntries(Object.entries(reply.headers ?? {}).map(([k, v]) => [k.toLowerCase(), v]));
    return {
      ok: status >= 200 && status < 300,
      status,
      statusText: "",
      headers: { get: (name: string) => hdrs[name.toLowerCase()] ?? null, getSetCookie: () => [] },
      text: async () => reply.text ?? (reply.json !== undefined ? JSON.stringify(reply.json) : ""),
    } as any;
  });
  vi.stubGlobal("fetch", fn);
  return calls;
}
const writes = (calls: { init: any }[]) => calls.filter((c) => (c.init?.method ?? "GET") !== "GET");
const authOn = (c: { init: any }) => c.init.headers.Authorization as string;

afterEach(() => vi.restoreAllMocks());

describe("key selection (the two-key trap)", () => {
  it("picks each half's key by its required prefix", () => {
    expect(keyFor(cred(), "application")).toBe(APP);
    expect(keyFor(cred(), "client")).toBe(CLI);
  });

  it("REFUSES a correctly-named field holding the other half's key", () => {
    // The exact mix-up this connector exists to prevent: a pacc_ key pasted into
    // application_key must not be sent to the Application API.
    const swapped = cred({ fields: { application_key: CLI, client_key: APP } });
    expect(keyFor(swapped, "application")).toBeUndefined();
    expect(keyFor(swapped, "client")).toBeUndefined();
  });

  it("never falls back to the other half's key when one is missing", () => {
    expect(keyFor(cred({ fields: { client_key: CLI } }), "application")).toBeUndefined();
    expect(keyFor(cred({ fields: { application_key: APP } }), "client")).toBeUndefined();
  });

  it("accepts a single-key item via secret/password, routed by prefix", () => {
    expect(keyFor(cred({ fields: {}, secret: APP }), "application")).toBe(APP);
    expect(keyFor(cred({ fields: {}, secret: APP }), "client")).toBeUndefined();
    expect(keyFor(cred({ fields: {}, password: CLI }), "client")).toBe(CLI);
  });

  it("a tool needing the missing key errors with the field name and prefix, and never calls out", async () => {
    const calls = mockFetch([{ match: () => true, reply: { json: list([]) } }]);
    const res = await tool("list_eggs").run({}, ctx(cred({ fields: { client_key: CLI } })));
    expect(res.isError).toBe(true);
    expect(res.text).toContain("application_key");
    expect(res.text).toContain("papp_");
    expect(res.text).not.toContain(CLI);
    expect(calls).toHaveLength(0);
  });
});

describe("transport guard", () => {
  it("allows https anywhere and http only on the LAN", () => {
    expect(() => assertTransportOk("https://panel.example.com")).not.toThrow();
    expect(() => assertTransportOk("http://192.168.0.48")).not.toThrow();
    expect(() => assertTransportOk("http://10.1.2.3:8080")).not.toThrow();
    expect(() => assertTransportOk("http://localhost:8080")).not.toThrow();
    expect(() => assertTransportOk("http://panel.example.com")).toThrow(/not a private LAN address/);
    expect(() => assertTransportOk("http://8.8.8.8")).toThrow(/not a private LAN address/);
    expect(() => assertTransportOk("ftp://192.168.0.48")).toThrow(/Unsupported/);
  });

  it("refuses to send a key over plain http to a routable host, before any call", async () => {
    const calls = mockFetch([{ match: () => true, reply: { json: list([]) } }]);
    const t: Target = { name: "p", type: "pelican", host: "panel.example.com", options: { baseUrl: "http://panel.example.com" } };
    const res = await pelicanConnector.buildTools(t).find((x) => x.name === "list_eggs")!.run({}, { target: t, getCredential: async () => cred() });
    expect(res.isError).toBe(true);
    expect(res.text).toContain("not a private LAN address");
    expect(calls).toHaveLength(0);
  });

  it("baseUrl picks http for the LAN panel and https on 443/8443", () => {
    expect(baseUrl(target({}, 80))).toBe("http://192.168.0.48:80");
    expect(baseUrl(target({}, 443))).toBe("https://192.168.0.48:443");
    expect(baseUrl(target({ baseUrl: "http://192.168.0.48/" }))).toBe("http://192.168.0.48");
  });
});

describe("redaction", () => {
  it("redacts egg environment secrets and node daemon tokens, keeping benign fields", () => {
    const out = JSON.stringify(
      redactSecrets({
        name: "valheim",
        daemon_token: "TOKEN123",
        container: { environment: { SERVER_NAME: "fun", SERVER_PASSWORD: "hunter2", RCON_PASSWORD: RCON, MAX_PLAYERS: 10 } },
      }),
    );
    for (const s of ["TOKEN123", "hunter2", RCON]) expect(out).not.toContain(s);
    expect(out).toContain('"SERVER_NAME":"fun"');
    expect(out).toContain('"MAX_PLAYERS":10');
  });

  it("scrubSecrets masks a raw error body", () => {
    expect(scrubSecrets(JSON.stringify({ rcon_password: RCON, detail: "nope" }))).not.toContain(RCON);
    expect(scrubSecrets(JSON.stringify({ detail: "nope" }))).toContain('"detail":"nope"');
  });

  it("isPrivateIPv4 accepts RFC1918 only", () => {
    for (const ip of ["10.0.0.1", "172.16.0.1", "192.168.0.48"]) expect(isPrivateIPv4(ip)).toBe(true);
    for (const ip of ["8.8.8.8", "172.32.0.1", "999.1.1.1", "nope", ""]) expect(isPrivateIPv4(ip)).toBe(false);
  });
});

describe("summarizers", () => {
  it("summarizeAllocations puts FREE first and labels assigned ones", () => {
    const out = summarizeAllocations([
      { id: 1, ip: "192.168.0.48", port: 2456, assigned: true },
      { id: 2, ip: "192.168.0.48", port: 2457, assigned: false },
    ]);
    expect(out.indexOf("FREE (1)")).toBeLessThan(out.indexOf("ASSIGNED (1)"));
    expect(out).toContain("[2] 192.168.0.48:2457");
  });

  it("summarizeServers prints all three identities", () => {
    const out = summarizeServers([{ id: 3, uuid: "u-1", identifier: "abc123", name: "valheim", node: 1, egg: 5 }]);
    expect(out).toContain("[3] valheim");
    expect(out).toContain("identifier=abc123");
    expect(out).toContain("uuid=u-1");
  });

  it("summarizeServers marks which servers the CLIENT key can act on", () => {
    const servers = [
      { id: 1, uuid: "u-1", identifier: "aaa", name: "mine", user: 3 },
      { id: 2, uuid: "u-2", identifier: "bbb", name: "theirs", user: 1 },
    ];
    const out = summarizeServers(servers, new Set(["aaa"]));
    expect(out).toContain("mine identifier=aaa uuid=u-1 node=? egg=?  client=YES");
    expect(out).toContain("client=NO (owned by user 1)");
    expect(out).not.toContain("NOTE: client=NO on every server"); // at least one reachable
  });

  it("summarizeServers warns loudly when the client key reaches NOTHING", () => {
    const out = summarizeServers([{ id: 2, uuid: "u-2", identifier: "bbb", name: "theirs", user: 1 }], new Set());
    expect(out).toContain("client=NO (owned by user 1)");
    expect(out).toContain("NOTE: client=NO on every server");
    expect(out).toContain("will 404");
  });

  it("summarizeServers says 'unknown' rather than falsely claiming no access", () => {
    const out = summarizeServers([{ id: 2, identifier: "bbb", name: "x", user: 1 }], null);
    expect(out).toContain("client=unknown");
    expect(out).not.toContain("client=NO");
  });

  it("summarizeSchedules renders cron and calls out a task-less schedule", () => {
    const withTask = summarizeSchedules([
      {
        id: 9,
        name: "nightly stop",
        is_active: true,
        cron: { minute: "0", hour: "2", day_of_month: "*", month: "*", day_of_week: "*" },
        relationships: { tasks: { data: [{ attributes: { id: 4, action: "power", payload: "stop", time_offset: 0 } }] } },
      },
    ]);
    expect(withTask).toContain("cron '0 2 * * *'");
    expect(withTask).toContain("power:stop@+0s [task 4]");

    const inert = summarizeSchedules([{ id: 10, name: "empty", is_active: false, cron: { minute: "0", hour: "3" } }]);
    expect(inert).toContain("INACTIVE");
    expect(inert).toContain("(none — this schedule does nothing)");
  });

  it("empty summaries are explicit", () => {
    expect(summarizeEggs([])).toBe("No eggs.");
    expect(summarizeNodes([])).toBe("No nodes.");
    expect(summarizeAllocations([])).toBe("No allocations on this node.");
  });

  it("cronOf defaults missing fields to *", () => {
    expect(cronOf({ id: 1, cron: { minute: "5" } })).toBe("5 * * * *");
  });

  it("assertCronField rejects junk", () => {
    expect(() => assertCronField("hour", "*/6")).not.toThrow();
    expect(() => assertCronField("hour", "2-4,6")).not.toThrow();
    expect(() => assertCronField("hour", "every hour")).toThrow(/Invalid cron hour/);
  });
});

describe("reads use the right API half and follow pagination", () => {
  it("list_eggs sends the application key to /api/application/eggs", async () => {
    const calls = mockFetch([{ match: (u) => u.includes("/api/application/eggs"), reply: { json: list([{ id: 1, name: "Valheim", author: "a@b" }]) } }]);
    const res = await tool("list_eggs").run({}, ctx());
    expect(res.text).toContain("[1] Valheim");
    expect(authOn(calls[0]!)).toBe(`Bearer ${APP}`);
    expect(calls[0]!.init.headers.Accept).toBe("application/json"); // else the panel 302s to the web login
  });

  it("list_schedules sends the CLIENT key to /api/client and asks for tasks", async () => {
    const calls = mockFetch([{ match: (u) => u.includes("/api/client/servers/abc123/schedules"), reply: { json: list([]) } }]);
    await tool("list_schedules").run({ server: "abc123" }, ctx());
    expect(authOn(calls[0]!)).toBe(`Bearer ${CLI}`);
    expect(calls[0]!.url).toContain("include=tasks");
  });

  it("follows pagination instead of truncating at page 1", async () => {
    const calls = mockFetch([
      { match: (u) => u.includes("page=1&"), reply: { json: list([{ id: 1, ip: "192.168.0.48", port: 2456, assigned: false }], 1, 2) } },
      { match: (u) => u.includes("page=2&"), reply: { json: list([{ id: 2, ip: "192.168.0.48", port: 2457, assigned: false }], 2, 2) } },
    ]);
    const res = await tool("list_allocations").run({ node: 1 }, ctx());
    expect(res.text).toContain("FREE (2)");
    expect(calls).toHaveLength(2);
  });

  it("server_details redacts environment secrets", async () => {
    mockFetch([{ match: (u) => u.includes("/api/application/servers/3"), reply: { json: item({ id: 3, name: "v", container: { environment: { RCON_PASSWORD: RCON } } }) } }]);
    const res = await tool("server_details").run({ id: 3 }, ctx());
    expect(res.text).not.toContain(RCON);
    expect(res.text).toContain("[redacted]");
  });

  it("surfaces Pelican's error envelope rather than a bare status", async () => {
    mockFetch([{ match: () => true, reply: { status: 403, json: { errors: [{ code: "AccessDenied", detail: "This action is unauthorized." }] } } }]);
    const res = await tool("list_eggs").run({}, ctx());
    expect(res.isError).toBe(true);
    expect(res.text).toContain("This action is unauthorized.");
  });
});

describe("list_users", () => {
  it("surfaces the ids needed to pick ownerUserId, flagging admins", async () => {
    mockFetch([{ match: (u) => u.includes("/api/application/users"), reply: { json: list([{ id: 1, username: "jake", email: "j@x", root_admin: true }, { id: 7, username: "skeleton-key", email: "sk@x" }]) } }]);
    const res = await tool("list_users").run({}, ctx());
    expect(res.text).toContain("[7] skeleton-key");
    expect(res.text).toContain("[1] jake <j@x>  ADMIN");
  });
});

describe("client-API access visibility", () => {
  it("list_servers cross-references the client key and annotates each server", async () => {
    mockFetch([
      { match: (u) => u.includes("/api/application/servers"), reply: { json: list([{ id: 1, identifier: "aaa", uuid: "u-1", name: "mine", user: 3 }, { id: 2, identifier: "bbb", uuid: "u-2", name: "theirs", user: 1 }]) } },
      { match: (u) => u.includes("/api/client"), reply: { json: list([{ id: 1, identifier: "aaa", uuid: "u-1" }]) } },
    ]);
    const res = await tool("list_servers").run({}, ctx());
    expect(res.text).toContain("mine identifier=aaa");
    expect(res.text).toContain("client=YES");
    expect(res.text).toContain("client=NO (owned by user 1)");
  });

  it("degrades to client=unknown when the client key can't list, without failing the read", async () => {
    mockFetch([
      { match: (u) => u.includes("/api/application/servers"), reply: { json: list([{ id: 1, identifier: "aaa", name: "x", user: 1 }]) } },
      { match: (u) => u.includes("/api/client"), reply: { status: 401, json: { errors: [{ detail: "Unauthenticated." }] } } },
    ]);
    const res = await tool("list_servers").run({}, ctx());
    expect(res.isError).toBeFalsy(); // application inventory still returned
    expect(res.text).toContain("client=unknown");
  });

  it("a client 404 on a server path explains the ownership requirement", async () => {
    mockFetch([{ match: (u) => u.includes("/api/client/servers/"), reply: { status: 404, json: { errors: [{ detail: "The requested resource does not exist on this server." }] } } }]);
    const res = await tool("server_resources").run({ server: "f83cc148" }, ctx());
    expect(res.isError).toBe(true);
    expect(res.text).toContain("only sees servers its key's user OWNS or is a subuser on");
    expect(res.text).toContain("subuser");
  });

  it("does NOT add the ownership hint to an application-side 404", async () => {
    mockFetch([{ match: (u) => u.includes("/api/application/servers/"), reply: { status: 404, json: { errors: [{ detail: "Not found" }] } } }]);
    const res = await tool("server_details").run({ id: 999 }, ctx());
    expect(res.isError).toBe(true);
    expect(res.text).not.toContain("subuser");
  });
});

describe("create_server", () => {
  const eggs = list([{ id: 5, name: "Valheim" }]);
  const nodes = list([{ id: 1, name: "n1" }]);
  const allocs = list([
    { id: 11, ip: "192.168.0.48", port: 2456, assigned: false },
    { id: 12, ip: "192.168.0.48", port: 2500, assigned: true },
  ]);
  /** The egg's variables, with the defaults create_server must fill in. */
  const eggWithVars = item({
    id: 5,
    name: "Valheim",
    relationships: {
      variables: {
        data: [
          { attributes: { env_variable: "SERVER_NAME", default_value: "My Server", user_editable: true } },
          { attributes: { env_variable: "SRCDS_APPID", default_value: "896660", user_editable: false } },
          { attributes: { env_variable: "LD_LIBRARY_PATH", default_value: "./linux64", user_editable: false } },
          { attributes: { env_variable: "PASSWORD", default_value: "secret", user_editable: true } },
          { attributes: { env_variable: "SRCDS_BETAID", default_value: null, user_editable: true } },
        ],
      },
    },
  });

  function mock(storeReply: { status?: number; json?: unknown } = { json: item({ id: 9, name: "valheim", identifier: "abc123", uuid: "u-9" }) }) {
    return mockFetch([
      { match: (u, i) => u.includes("/servers") && i?.method === "POST", reply: storeReply },
      // Must come before the generic /eggs route — this is the variables lookup.
      { match: (u) => /\/eggs\/\d+/.test(u), reply: { json: eggWithVars } },
      { match: (u) => u.includes("/eggs"), reply: { json: eggs } },
      { match: (u) => u.includes("/allocations"), reply: { json: allocs } },
      { match: (u) => u.includes("/nodes"), reply: { json: nodes } },
    ]);
  }

  it("resolves egg by name and allocation by ip:port, and posts the full required body", async () => {
    const calls = mock();
    const res = await tool("create_server").run({ name: "valheim", egg: "Valheim", allocation: "192.168.0.48:2456" }, ctx());
    expect(res.isError).toBeFalsy();
    expect(res.text).toContain("identifier=abc123");
    expect(res.text).toContain("owner user 7");
    const post = writes(calls)[0]!;
    expect(authOn(post)).toBe(`Bearer ${APP}`);
    const body = JSON.parse(post.init.body);
    expect(body).toMatchObject({ name: "valheim", user: 7, egg: 5, allocation: { default: 11 } });
    expect(body.limits).toMatchObject({ memory: 4096, disk: 10240, cpu: 0 });
    expect(body.feature_limits).toMatchObject({ databases: 0, allocations: 1, backups: 1 });
  });

  // The bug this guards: Pelican stores an empty string for every variable the
  // request omits, and EnvironmentService resolves `server_value ?? default` —
  // `??` does not catch "", so the blank wins over the egg's default forever. A
  // real Valheim server provisioned this way ran `+app_update ""`, downloaded no
  // game files and crash-looped.
  it("sends EVERY egg variable, filling omitted ones from the egg's defaults", async () => {
    const calls = mock();
    const res = await tool("create_server").run(
      { name: "valheim", egg: "Valheim", allocation: "192.168.0.48:2456", environment: { SERVER_NAME: "Jake's server" } },
      ctx(),
    );
    expect(res.isError).toBeFalsy();
    const body = JSON.parse(writes(calls)[0]!.init.body);
    expect(body.environment).toEqual({
      SERVER_NAME: "Jake's server", // caller's value wins
      SRCDS_APPID: "896660", // read-only default — the one that broke the install
      LD_LIBRARY_PATH: "./linux64",
      PASSWORD: "secret",
      SRCDS_BETAID: "", // a null default becomes an empty string, as the panel expects
    });
    // Names are reported so the operator can see what was assumed; values are not.
    expect(res.text).toContain("SRCDS_APPID");
    expect(res.text).not.toContain("secret");
  });

  it("refuses an unknown variable name rather than letting Pelican silently ignore it", async () => {
    const calls = mock();
    const res = await tool("create_server").run(
      { name: "valheim", egg: "Valheim", allocation: "192.168.0.48:2456", environment: { SREVER_NAME: "typo" } },
      ctx(),
    );
    expect(res.isError).toBe(true);
    expect(res.text).toContain("'SREVER_NAME'");
    expect(writes(calls)).toHaveLength(0);
  });

  it("FAILS CLOSED when the panel does not return the variables include", async () => {
    // An empty variable list would produce an empty environment — i.e. blank out
    // every variable — so this must refuse rather than guess.
    const calls = mockFetch([
      { match: (u, i) => u.includes("/servers") && i?.method === "POST", reply: { json: item({ id: 9 }) } },
      { match: (u) => /\/eggs\/\d+/.test(u), reply: { json: item({ id: 5, name: "Valheim" }) } }, // no relationships
      { match: (u) => u.includes("/eggs"), reply: { json: eggs } },
      { match: (u) => u.includes("/allocations"), reply: { json: allocs } },
      { match: (u) => u.includes("/nodes"), reply: { json: nodes } },
    ]);
    const res = await tool("create_server").run({ name: "v", egg: "Valheim", allocation: "192.168.0.48:2456" }, ctx());
    expect(res.isError).toBe(true);
    expect(res.text).toMatch(/variables.*include|stored EMPTY/);
    expect(writes(calls)).toHaveLength(0);
  });

  it("attaches additional allocations at creation and raises the allocation limit to fit", async () => {
    const calls = mockFetch([
      { match: (u, i) => u.includes("/servers") && i?.method === "POST", reply: { json: item({ id: 9, identifier: "abc123" }) } },
      { match: (u) => /\/eggs\/\d+/.test(u), reply: { json: eggWithVars } },
      { match: (u) => u.includes("/eggs"), reply: { json: eggs } },
      {
        match: (u) => u.includes("/allocations"),
        reply: {
          json: list([
            { id: 11, ip: "192.168.0.48", port: 2456, assigned: false },
            { id: 12, ip: "192.168.0.48", port: 2457, assigned: false },
          ]),
        },
      },
      { match: (u) => u.includes("/nodes"), reply: { json: nodes } },
    ]);
    const res = await tool("create_server").run(
      { name: "valheim", egg: "Valheim", allocation: "192.168.0.48:2456", additionalAllocations: ["192.168.0.48:2457"] },
      ctx(),
    );
    expect(res.isError).toBeFalsy();
    const body = JSON.parse(writes(calls)[0]!.init.body);
    expect(body.allocation).toEqual({ default: 11, additional: [12] });
    expect(body.feature_limits.allocations).toBe(2); // default + 1, without being asked
  });

  it("refuses an additional allocation that is also the default", async () => {
    const calls = mock();
    const res = await tool("create_server").run(
      { name: "v", egg: "Valheim", allocation: "192.168.0.48:2456", additionalAllocations: ["192.168.0.48:2456"] },
      ctx(),
    );
    expect(res.isError).toBe(true);
    expect(res.text).toMatch(/already the default allocation/);
    expect(writes(calls)).toHaveLength(0);
  });

  it("refuses an allocation that is already assigned", async () => {
    const calls = mock();
    const res = await tool("create_server").run({ name: "x", egg: "5", allocation: "192.168.0.48:2500" }, ctx());
    expect(res.isError).toBe(true);
    expect(res.text).toContain("already assigned");
    expect(writes(calls)).toHaveLength(0);
  });

  it("errors clearly on an unknown egg, without creating anything", async () => {
    const calls = mock();
    const res = await tool("create_server").run({ name: "x", egg: "Minecraft", allocation: "192.168.0.48:2456" }, ctx());
    expect(res.isError).toBe(true);
    expect(res.text).toContain("No Pelican egg named 'Minecraft'");
    expect(writes(calls)).toHaveLength(0);
  });

  it("FAILS CLOSED when the target has no ownerUserId (never falls back to an admin account)", async () => {
    const calls = mock();
    const t = target({}); // no ownerUserId
    const res = await pelicanConnector
      .buildTools(t)
      .find((x) => x.name === "create_server")!
      .run({ name: "x", egg: "Valheim", allocation: "192.168.0.48:2456" }, { target: t, getCredential: async () => cred() });
    expect(res.isError).toBe(true);
    expect(res.text).toContain("ownerUserId");
    expect(calls).toHaveLength(0);
  });

  it("confirm text matches the plan's canonical format exactly", () => {
    expect(
      tool("create_server").confirm!({ name: "valheim", egg: "Valheim", allocation: "192.168.0.48:2456" }, target({ ownerUserId: 7 })),
    ).toBe("Create Pelican server 'valheim' (egg 'Valheim', allocation 192.168.0.48:2456, owner user 7) on pelican-panel");
  });
});

describe("power_action", () => {
  it("POSTs the signal with the client key", async () => {
    const calls = mockFetch([{ match: (u) => u.includes("/api/client/servers/abc123/power"), reply: { json: {} } }]);
    const res = await tool("power_action").run({ server: "abc123", signal: "stop" }, ctx());
    expect(res.isError).toBeFalsy();
    expect(JSON.parse(calls[0]!.init.body)).toEqual({ signal: "stop" });
    expect(authOn(calls[0]!)).toBe(`Bearer ${CLI}`);
  });

  it("spells out that kill is ungraceful, in both the confirm and the result", async () => {
    mockFetch([{ match: () => true, reply: { json: {} } }]);
    expect(tool("power_action").confirm!({ server: "abc123", signal: "kill" }, target({ ownerUserId: 7 }))).toBe(
      "KILL (ungraceful — may lose unsaved state) Pelican server 'abc123' on pelican-panel",
    );
    expect(tool("power_action").confirm!({ server: "abc123", signal: "stop" }, target({ ownerUserId: 7 }))).toContain("STOP Pelican server");
    const res = await tool("power_action").run({ server: "abc123", signal: "kill" }, ctx());
    expect(res.text).toContain("UNGRACEFUL");
  });
});

describe("update_startup_variables", () => {
  it("applies each variable in its own PUT and never echoes a value", async () => {
    const calls = mockFetch([{ match: (u) => u.includes("/startup/variable"), reply: { json: {} } }]);
    const res = await tool("update_startup_variables").run({ server: "abc123", variables: { SERVER_NAME: "fun", SERVER_PASSWORD: "hunter2" } }, ctx());
    expect(res.isError).toBeFalsy();
    expect(calls).toHaveLength(2);
    expect(calls.every((c) => c.init.method === "PUT")).toBe(true);
    expect(JSON.parse(calls[0]!.init.body)).toEqual({ key: "SERVER_NAME", value: "fun" });
    expect(res.text).toContain("SERVER_NAME, SERVER_PASSWORD");
    expect(res.text).not.toContain("hunter2");
  });

  it("reports which variables already landed when one fails part-way", async () => {
    let n = 0;
    vi.stubGlobal("fetch", vi.fn(async () => {
      n += 1;
      const bad = n === 2;
      return {
        ok: !bad,
        status: bad ? 422 : 200,
        statusText: "",
        headers: { get: () => null, getSetCookie: () => [] },
        text: async () => JSON.stringify(bad ? { errors: [{ detail: "Bad variable." }] } : {}),
      } as any;
    }));
    const res = await tool("update_startup_variables").run({ server: "abc123", variables: { A: "1", B: "2", C: "3" } }, ctx());
    expect(res.isError).toBe(true);
    expect(res.text).toContain("failed on variable 'B'");
    expect(res.text).toContain("Already applied: A");
    expect(res.text).toContain("NOT rolled back");
  });

  it("confirm names the variables but never their values", () => {
    const c = tool("update_startup_variables").confirm!({ server: "abc123", variables: { SERVER_PASSWORD: "hunter2" } }, target({ ownerUserId: 7 }));
    expect(c).toContain("[SERVER_PASSWORD]");
    expect(c).toContain("values not shown");
    expect(c).not.toContain("hunter2");
  });
});

describe("update_server_startup (the admin-API repair path)", () => {
  const eggVars = item({
    id: 5,
    relationships: {
      variables: {
        data: [
          { attributes: { env_variable: "SERVER_NAME", default_value: "My Server", user_editable: true } },
          { attributes: { env_variable: "SRCDS_APPID", default_value: "896660", user_editable: false } },
          { attributes: { env_variable: "LD_LIBRARY_PATH", default_value: "./linux64", user_editable: false } },
          { attributes: { env_variable: "WORLD", default_value: "Dedicated", user_editable: true } },
        ],
      },
    },
  });
  /** A server damaged by a partial write: the read-only vars are blank. */
  const damaged = item({
    id: 125,
    name: "Valheim",
    egg: 5,
    container: { environment: { SERVER_NAME: "Valheim", WORLD: "Dedicated", SRCDS_APPID: "", LD_LIBRARY_PATH: "" } },
  });
  const routes = () => [
    { match: (u: string, i: any) => u.includes("/startup") && i?.method === "PATCH", reply: { json: item({ id: 125 }) } },
    { match: (u: string) => /\/eggs\/\d+/.test(u), reply: { json: eggVars } },
    { match: (u: string) => /\/servers\/\d+/.test(u), reply: { json: damaged } },
  ];

  it("uses the APPLICATION key — the client key's per-variable route 400s on read-only vars", async () => {
    const calls = mockFetch(routes());
    const res = await tool("update_server_startup").run({ id: 125, variables: { SRCDS_APPID: "896660" } }, ctx());
    expect(res.isError).toBeFalsy();
    const patch = writes(calls)[0]!;
    expect(patch.url).toContain("/api/application/servers/125/startup");
    expect(authOn(patch)).toBe(`Bearer ${APP}`);
    expect(patch.init.method).toBe("PATCH");
  });

  it("sends the COMPLETE environment and keeps current values for variables it wasn't given", async () => {
    // The route replaces `environment` wholesale, so a partial send would blank
    // everything else — the very bug this tool exists to repair.
    const calls = mockFetch(routes());
    await tool("update_server_startup").run({ id: 125, variables: { WORLD: "Midgard" } }, ctx());
    const body = JSON.parse(writes(calls)[0]!.init.body);
    expect(body.environment).toEqual({
      WORLD: "Midgard", // the caller's change
      SERVER_NAME: "Valheim", // current value preserved, not reset to the egg default
      SRCDS_APPID: "896660", // was BLANK → healed from the egg default
      LD_LIBRARY_PATH: "./linux64", // was BLANK → healed
    });
    expect(body.egg).toBe(5); // current egg — must never migrate the server
    expect(body.skip_scripts).toBe(false);
  });

  it("reports which blank variables it healed, and never echoes values", async () => {
    mockFetch(routes());
    const res = await tool("update_server_startup").run({ id: 125, variables: { SERVER_NAME: "hunter2" } }, ctx());
    expect(res.text).toContain("SRCDS_APPID");
    expect(res.text).toContain("LD_LIBRARY_PATH");
    expect(res.text).not.toContain("hunter2");
    expect(res.text).toMatch(/REINSTALL/);
  });

  it("refuses an unknown variable name", async () => {
    const calls = mockFetch(routes());
    const res = await tool("update_server_startup").run({ id: 125, variables: { NOT_A_VAR: "x" } }, ctx());
    expect(res.isError).toBe(true);
    expect(res.text).toContain("'NOT_A_VAR'");
    expect(writes(calls)).toHaveLength(0);
  });

  it("confirm names the variables and flags that this path can write read-only ones", () => {
    expect(tool("update_server_startup").confirm!({ id: 125, variables: { SRCDS_APPID: "896660" } }, target({ ownerUserId: 7 }))).toBe(
      "Set variables [SRCDS_APPID] on Pelican server [125] on pelican-panel via the admin API (can write read-only variables; values not shown)",
    );
  });
});

describe("schedules", () => {
  it("create_schedule attaches the power task in the same call", async () => {
    const calls = mockFetch([
      { match: (u, i) => u.endsWith("/schedules") && i?.method === "POST", reply: { json: item({ id: 9, name: "nightly stop" }) } },
      { match: (u) => u.includes("/schedules/9/tasks"), reply: { json: item({ id: 4 }) } },
    ]);
    const res = await tool("create_schedule").run(
      { server: "abc123", name: "nightly stop", minute: "0", hour: "2", action: "power", payload: "stop" },
      ctx(),
    );
    expect(res.isError).toBeFalsy();
    expect(res.text).toContain("cron '0 2 * * *'");
    expect(res.text).toContain("Task 'power:stop' attached");
    expect(JSON.parse(calls[0]!.init.body)).toMatchObject({ name: "nightly stop", minute: "0", hour: "2", day_of_month: "*", is_active: true });
    expect(JSON.parse(calls[1]!.init.body)).toMatchObject({ action: "power", payload: "stop", time_offset: 0 });
  });

  it("warns loudly when a schedule is created with no task (inert)", async () => {
    mockFetch([{ match: (u, i) => u.endsWith("/schedules") && i?.method === "POST", reply: { json: item({ id: 9, name: "x" }) } }]);
    const res = await tool("create_schedule").run({ server: "abc123", name: "x", minute: "0", hour: "2" }, ctx());
    expect(res.text).toContain("No task attached — this schedule does nothing");
  });

  it("reports a schedule that was created but whose task failed to attach", async () => {
    mockFetch([
      { match: (u, i) => u.endsWith("/schedules") && i?.method === "POST", reply: { json: item({ id: 9, name: "x" }) } },
      { match: (u) => u.includes("/tasks"), reply: { status: 422, json: { errors: [{ detail: "bad" }] } } },
    ]);
    const res = await tool("create_schedule").run({ server: "abc123", name: "x", minute: "0", hour: "2", action: "power", payload: "stop" }, ctx());
    expect(res.text).toContain("attaching the power task FAILED");
    expect(res.text).toContain("the schedule exists and is inert");
  });

  it("rejects a junk cron field before any network call", async () => {
    const calls = mockFetch([{ match: () => true, reply: { json: item({ id: 1 }) } }]);
    const res = await tool("create_schedule").run({ server: "abc123", name: "x", minute: "0", hour: "every hour" }, ctx());
    expect(res.isError).toBe(true);
    expect(res.text).toContain("Invalid cron hour");
    expect(calls).toHaveLength(0);
  });

  it("update_schedule preserves cron fields the caller didn't pass", async () => {
    const current = { id: 9, name: "nightly stop", is_active: true, only_when_online: false, cron: { minute: "0", hour: "2", day_of_month: "*", month: "*", day_of_week: "1-5" } };
    const calls = mockFetch([
      { match: (u, i) => u.includes("/schedules/9") && (i?.method ?? "GET") === "GET", reply: { json: item(current) } },
      { match: (u, i) => u.includes("/schedules/9") && i?.method === "POST", reply: { json: item({ ...current, cron: { ...current.cron, hour: "4" } }) } },
    ]);
    const res = await tool("update_schedule").run({ server: "abc123", schedule: 9, hour: "4" }, ctx());
    expect(res.isError).toBeFalsy();
    const body = JSON.parse(writes(calls)[0]!.init.body);
    // The whole cron is replaced by the panel, so day_of_week MUST be carried over
    // or the job would silently start running every day.
    expect(body).toMatchObject({ minute: "0", hour: "4", day_of_week: "1-5", name: "nightly stop" });
    expect(res.text).toContain("cron '0 2 * * 1-5' → '0 4 * * 1-5'");
  });

  it("delete_schedule verifies the echoed name and refuses a mismatch", async () => {
    const calls = mockFetch([
      { match: (u, i) => u.includes("/schedules/9") && (i?.method ?? "GET") === "GET", reply: { json: item({ id: 9, name: "nightly stop", cron: { minute: "0", hour: "2" } }) } },
      { match: (u, i) => u.includes("/schedules/9") && i?.method === "DELETE", reply: { json: {} } },
    ]);
    const bad = await tool("delete_schedule").run({ server: "abc123", schedule: 9, expectName: "morning start" }, ctx());
    expect(bad.isError).toBe(true);
    expect(bad.text).toContain("it is named 'nightly stop'");
    expect(writes(calls)).toHaveLength(0);

    const good = await tool("delete_schedule").run({ server: "abc123", schedule: 9, expectName: "nightly stop" }, ctx());
    expect(good.isError).toBeFalsy();
    expect(writes(calls).some((c) => c.init.method === "DELETE")).toBe(true);
  });

  it("schedule confirm texts name the server, cron and task", () => {
    const t = target({ ownerUserId: 7 });
    expect(tool("create_schedule").confirm!({ server: "abc123", name: "nightly stop", minute: "0", hour: "2", action: "power", payload: "stop" }, t)).toBe(
      "Create Pelican schedule 'nightly stop' (cron '0 2 * * *', power:stop) on server 'abc123' on pelican-panel",
    );
    expect(tool("create_schedule").confirm!({ server: "abc123", name: "x", minute: "0", hour: "2" }, t)).toContain("no task (inert)");
    expect(tool("delete_schedule").confirm!({ server: "abc123", schedule: 9, expectName: "nightly stop" }, t)).toBe(
      "Delete Pelican schedule 'nightly stop' [9] on server 'abc123' on pelican-panel — it will stop running",
    );
  });
});

describe("assign_allocation", () => {
  it("POSTs with no body and reports the IP:port the panel chose", async () => {
    const calls = mockFetch([{ match: (u) => u.includes("/network/allocations"), reply: { json: item({ id: 12, ip: "192.168.0.48", port: 2457 }) } }]);
    const res = await tool("assign_allocation").run({ server: "abc123" }, ctx());
    expect(res.text).toContain("192.168.0.48:2457");
    expect(calls[0]!.init.method).toBe("POST");
    expect(calls[0]!.init.body).toBeUndefined();
  });
});

describe("port expansion (mirrors the panel's AssignmentService)", () => {
  it("expands single ports and ranges, de-duplicated and sorted", () => {
    expect(expandPorts(["2458", "2456-2457", "2456"])).toEqual([2456, 2457, 2458]);
  });

  it("refuses a range whose endpoints are not 4-5 digits, because the panel's regex does", () => {
    // '999-2000' looks reasonable but PORT_RANGE_REGEX never matches it, so the
    // panel would reject the whole call with an opaque error.
    expect(() => expandPorts(["999-2000"])).toThrow(/4-5 digits/);
  });

  it("refuses a backwards range and ports outside 1024-65535", () => {
    expect(() => expandPorts(["2458-2456"])).toThrow(/end port is below/);
    expect(() => expandPorts(["80"])).toThrow(/outside Pelican's allowed range/);
    expect(() => expandPorts(["1024-70000"])).toThrow(/outside Pelican's allowed range/);
  });

  it("caps a single call so a fat-fingered range can't insert tens of thousands of rows", () => {
    expect(() => expandPorts(["2000-65535"])).toThrow(new RegExp(`caps a single call at ${MAX_PORTS_PER_CALL}`));
  });

  it("trips the cap DURING expansion, so a pathological input can't exhaust the heap first", () => {
    // Thousands of wide ranges: if the cap were applied after expanding, this
    // would allocate ~129M entries before ever being checked.
    const huge = Array.from({ length: 2000 }, () => "1024-65535");
    const started = Date.now();
    expect(() => expandPorts(huge)).toThrow(new RegExp(`caps a single call at ${MAX_PORTS_PER_CALL}`));
    expect(Date.now() - started).toBeLessThan(1000); // bails immediately, not after 129M pushes
  });

  it("de-duplication does not falsely trip the cap", () => {
    expect(expandPorts(Array.from({ length: 300 }, () => "2456"))).toEqual([2456]);
  });

  it("refuses CIDR, which the panel would expand across every port", () => {
    expect(() => assertAllocationIp("192.168.0.0/24")).toThrow(/refuses CIDR/);
    expect(() => assertAllocationIp("192.168.0.999")).toThrow(/one literal IPv4/);
    expect(assertAllocationIp(" 192.168.0.48 ")).toBe("192.168.0.48");
  });
});

describe("create_allocations", () => {
  const existing = [{ id: 11, ip: "192.168.0.48", port: 2500, assigned: true }];

  it("sends ports as strings and reports the ids it had to re-read (204 returns nothing)", async () => {
    // The POST answers 204 with an empty body, so the allocation list must differ
    // before and after — a static mock would not prove the re-read happens.
    let posted = false;
    const calls: { url: string; init: any }[] = [];
    vi.stubGlobal(
      "fetch",
      vi.fn(async (url: string, init: any) => {
        calls.push({ url, init });
        const isPost = init?.method === "POST";
        if (isPost) {
          posted = true;
          return { ok: true, status: 204, statusText: "", headers: { get: () => null }, text: async () => "" } as any;
        }
        const rows = posted
          ? [...existing, { id: 21, ip: "192.168.0.48", port: 2456 }, { id: 22, ip: "192.168.0.48", port: 2457 }]
          : existing;
        return { ok: true, status: 200, statusText: "", headers: { get: () => null }, text: async () => JSON.stringify(list(rows)) } as any;
      }),
    );

    const res = await tool("create_allocations").run({ node: 1, ip: "192.168.0.48", ports: ["2456-2457"], alias: "valheim" }, ctx());
    expect(res.isError).toBeFalsy();
    const post = writes(calls)[0]!;
    expect(authOn(post)).toBe(`Bearer ${APP}`);
    expect(JSON.parse(post.init.body)).toEqual({ ip: "192.168.0.48", ports: ["2456", "2457"], alias: "valheim" });
    expect(res.text).toContain("192.168.0.48:2456 [21]");
    expect(res.text).toContain("192.168.0.48:2457 [22]");
    expect(res.text).toMatch(/port-forward/i);
  });

  it("refuses a port the node already has, WITHOUT posting (the unique index makes it a 500)", async () => {
    const calls = mockFetch([{ match: (u) => u.includes("/allocations"), reply: { json: list(existing) } }]);
    const res = await tool("create_allocations").run({ node: 1, ip: "192.168.0.48", ports: ["2500"] }, ctx());
    expect(res.isError).toBe(true);
    expect(res.text).toContain("192.168.0.48:2500 [11]");
    expect(res.text).toMatch(/unique index/);
    expect(writes(calls)).toHaveLength(0);
  });

  it("confirm text names the node, address, ports and expanded count", () => {
    expect(tool("create_allocations").confirm!({ node: 1, ip: "192.168.0.48", ports: ["2456-2458"] }, target({ ownerUserId: 7 }))).toBe(
      "Create allocations on Pelican node 1 on pelican-panel: 192.168.0.48 ports 2456-2458 (3 port(s))",
    );
  });
});

describe("import_egg", () => {
  const UUID = "11111111-1111-1111-1111-111111111111";
  const eggJson = (uuid = UUID) =>
    JSON.stringify({ meta: { version: "PLCN_v3" }, uuid, name: "Valheim", author: "dev@example.com", variables: [{ env_variable: "SERVER_NAME" }] });

  it("rejects content that isn't a recognised egg export, before any request", async () => {
    expect(() => parseEggContent("<!doctype html><html>404</html>")).toThrow(/parse the egg|not an egg object/);
    expect(() => parseEggContent(JSON.stringify({ meta: { version: "NOPE" }, variables: [] }))).toThrow(/meta.version/);
    expect(() => parseEggContent(JSON.stringify({ meta: { version: "PLCN_v3" } }))).toThrow(/no 'variables' array/);
  });

  it("accepts YAML as well as JSON, since the panel parses the body as YAML", () => {
    const parsed = parseEggContent("meta:\n  version: PLCN_v3\nuuid: abc\nname: Valheim\nvariables:\n  - env_variable: A\n");
    expect(parsed).toMatchObject({ uuid: "abc", name: "Valheim", version: "PLCN_v3", variableCount: 1 });
  });

  it("only fetches eggs from public https (this fetch originates inside the LAN)", () => {
    expect(() => assertEggSourceUrl("http://raw.githubusercontent.com/x.json")).toThrow(/use https/);
    expect(assertEggSourceUrl("https://raw.githubusercontent.com/x.json").host).toBe("raw.githubusercontent.com");
  });

  // RFC1918 alone is NOT the right rule for an outbound fetch: loopback,
  // link-local (cloud metadata), CGNAT and IPv6 private space are all local
  // reach, and `::ffff:127.0.0.1` must not smuggle loopback past the v4 check.
  it.each([
    ["https://192.168.0.48/x", "RFC1918"],
    ["https://10.0.0.1/x", "RFC1918"],
    ["https://172.16.5.5/x", "RFC1918"],
    ["https://127.0.0.1/x", "loopback"],
    ["https://127.0.0.1:8443/admin", "loopback with port"],
    ["https://0.0.0.0/x", "unspecified"],
    ["https://169.254.169.254/latest/meta-data/", "cloud metadata"],
    ["https://100.64.0.1/x", "CGNAT"],
    ["https://224.0.0.1/x", "multicast"],
    ["https://255.255.255.255/x", "broadcast"],
    ["https://[::1]/x", "IPv6 loopback"],
    ["https://[fd00::1]/x", "IPv6 unique-local"],
    ["https://[fe80::1]/x", "IPv6 link-local"],
    ["https://[::ffff:127.0.0.1]/x", "IPv4-mapped loopback"],
    ["https://localhost/x", "localhost"],
    ["https://panel.local/x", ".local"],
    ["https://svc.internal/x", ".internal"],
  ])("refuses %s (%s)", (url) => {
    expect(() => assertEggSourceUrl(url)).toThrow(/inside the network/);
  });

  it("re-validates EVERY redirect hop — a public URL must not be able to bounce into the LAN", async () => {
    const seen: string[] = [];
    vi.stubGlobal(
      "fetch",
      vi.fn(async (url: string) => {
        seen.push(url);
        return {
          ok: false,
          status: 302,
          statusText: "",
          headers: { get: (h: string) => (h.toLowerCase() === "location" ? "http://192.168.0.1/admin" : null) },
          text: async () => "",
        } as any;
      }),
    );
    await expect(fetchEggFromUrl("https://raw.githubusercontent.com/valheim.json")).rejects.toThrow(/inside the network|use https/);
    // The redirect target was never requested.
    expect(seen).toEqual(["https://raw.githubusercontent.com/valheim.json"]);
  });

  it("follows a redirect that stays public, and stops after the hop limit", async () => {
    let hops = 0;
    vi.stubGlobal(
      "fetch",
      vi.fn(async () => {
        hops += 1;
        return {
          ok: false,
          status: 302,
          statusText: "",
          headers: { get: (h: string) => (h.toLowerCase() === "location" ? `https://cdn.example.com/${hops}.json` : null) },
          text: async () => "",
        } as any;
      }),
    );
    await expect(fetchEggFromUrl("https://raw.githubusercontent.com/valheim.json")).rejects.toThrow(/more than 5 redirects/);
    expect(hops).toBe(6); // initial + 5 allowed hops, then refused
  });

  it("rejects an oversized body from Content-Length without reading it", async () => {
    let read = false;
    vi.stubGlobal(
      "fetch",
      vi.fn(async () => ({
        ok: true,
        status: 200,
        statusText: "",
        headers: { get: (h: string) => (h.toLowerCase() === "content-length" ? String(MAX_EGG_BYTES + 1) : null) },
        text: async () => {
          read = true;
          return "x";
        },
      })) as any,
    );
    await expect(fetchEggFromUrl("https://raw.githubusercontent.com/huge.json")).rejects.toThrow(/larger than the/);
    expect(read).toBe(false);
  });

  it("stops reading a streamed body once it passes the cap, instead of buffering it all", async () => {
    let emitted = 0;
    const chunk = Buffer.alloc(256 * 1024, 0x61);
    const body = {
      async *[Symbol.asyncIterator]() {
        for (;;) {
          emitted += 1;
          yield chunk; // an endless body, with no Content-Length to catch it
        }
      },
      cancel: async () => {},
    };
    vi.stubGlobal(
      "fetch",
      vi.fn(async () => ({ ok: true, status: 200, statusText: "", headers: { get: () => null }, body, text: async () => "" })) as any,
    );
    await expect(fetchEggFromUrl("https://raw.githubusercontent.com/endless.json")).rejects.toThrow(/larger than the/);
    // 2 MiB cap / 256 KiB chunks = 8 chunks, and the 9th trips it. Bounded, not endless.
    expect(emitted).toBeLessThanOrEqual(9);
  });

  it("sends the egg document as the RAW body (not a JSON envelope) and reports the new egg", async () => {
    const body = eggJson("22222222-2222-2222-2222-222222222222");
    const calls = mockFetch([
      { match: (u, i) => u.includes("/eggs/import") && i?.method === "POST", reply: { status: 201, json: item({ id: 22, name: "Valheim", uuid: "22222222-2222-2222-2222-222222222222" }) } },
      { match: (u) => u.includes("/eggs"), reply: { json: list([{ id: 5, name: "Paper", uuid: UUID }]) } },
    ]);
    const res = await tool("import_egg").run({ content: body }, ctx());
    expect(res.isError).toBeFalsy();
    const post = writes(calls)[0]!;
    expect(post.init.body).toBe(body); // verbatim — $request->getContent() is the egg
    expect(authOn(post)).toBe(`Bearer ${APP}`);
    expect(res.text).toContain("Imported new");
    expect(res.text).toContain("[id 22]");
  });

  it("REFUSES a uuid already on the panel, names the servers that would be affected, and posts nothing", async () => {
    const calls = mockFetch([
      { match: (u) => u.includes("/eggs/import"), reply: { status: 201, json: item({ id: 5 }) } },
      { match: (u) => u.includes("/eggs"), reply: { json: list([{ id: 5, name: "Valheim (old)", uuid: UUID }]) } },
      { match: (u) => u.includes("/servers"), reply: { json: list([{ id: 9, name: "valheim-live", egg: 5 }]) } },
    ]);
    const res = await tool("import_egg").run({ content: eggJson() }, ctx());
    expect(res.isError).toBe(true);
    expect(res.text).toContain("'Valheim (old)' [id 5]");
    expect(res.text).toContain("'valheim-live' [9]");
    expect(res.text).toMatch(/OVERWRITE/);
    expect(res.text).toMatch(/overwrite: true/);
    expect(writes(calls)).toHaveLength(0);
  });

  it("proceeds on the same uuid with overwrite:true, and says it overwrote", async () => {
    const calls = mockFetch([
      { match: (u, i) => u.includes("/eggs/import") && i?.method === "POST", reply: { status: 201, json: item({ id: 5, name: "Valheim", uuid: UUID }) } },
      { match: (u) => u.includes("/eggs"), reply: { json: list([{ id: 5, name: "Valheim (old)", uuid: UUID }]) } },
      { match: (u) => u.includes("/servers"), reply: { json: list([]) } },
    ]);
    const res = await tool("import_egg").run({ content: eggJson(), overwrite: true }, ctx());
    expect(res.isError).toBeFalsy();
    expect(res.text).toContain("OVERWROTE existing");
    expect(res.text).toMatch(/Variables not present in the imported file were removed/);
    expect(writes(calls)).toHaveLength(1);
  });

  it("requires exactly one of url/content", async () => {
    mockFetch([{ match: () => true, reply: { json: list([]) } }]);
    const both = await tool("import_egg").run({ url: "https://x/y.json", content: "{}" }, ctx());
    expect(both.isError).toBe(true);
    const neither = await tool("import_egg").run({}, ctx());
    expect(neither.isError).toBe(true);
    expect(neither.text).toContain("exactly one");
  });

  it("confirm text distinguishes a create from a destructive overwrite", () => {
    const t = target({ ownerUserId: 7 });
    expect(tool("import_egg").confirm!({ url: "https://x/valheim.json" }, t)).toBe("Import a new egg from https://x/valheim.json into pelican-panel");
    expect(tool("import_egg").confirm!({ content: "{}", overwrite: true }, t)).toMatch(/OVERWRITING any existing egg with the same uuid/);
  });
});

describe("panel host resolution (the one place a connector reaches another target)", () => {
  const sshTarget: Target = { name: "pelican48", type: "ssh", host: "192.168.0.48", credentialRef: "pelican48-ssh" };
  const panelTarget = (o: Record<string, unknown> = {}) => target({ ownerUserId: 7, sshTarget: "pelican48", ...o });

  function hostCtx(over: Partial<ToolContext> = {}, t: Target = panelTarget()): ToolContext {
    return {
      target: t,
      getCredential: async () => cred(),
      resolveTarget: (name: string) => (name === "pelican48" ? sshTarget : undefined),
      resolveCredential: async () => ({ ref: "pelican48-ssh", username: "jake", password: "pw", fields: {}, uris: [] }),
      ...over,
    };
  }
  const panelTool = (name: string, t: Target = panelTarget()) => pelicanConnector.buildTools(t).find((x) => x.name === name)!;

  it("tells you exactly what to set when sshTarget is missing", async () => {
    const t = target({ ownerUserId: 7 }); // no sshTarget
    const res = await panelTool("panel_version", t).run({}, hostCtx({}, t));
    expect(res.isError).toBe(true);
    expect(res.text).toContain("sshTarget");
    expect(res.text).toMatch(/update_target/);
  });

  it("refuses when the named target is not an ssh target", async () => {
    // Without this check a typo'd name pointing at the gateway would have this
    // connector opening a shell on the UniFi box.
    const unifi: Target = { name: "unifi", type: "unifi", host: "192.168.0.1", credentialRef: "u" };
    const t = panelTarget({ sshTarget: "unifi" });
    const res = await panelTool("panel_version", t).run({}, hostCtx({ resolveTarget: () => unifi }, t));
    expect(res.isError).toBe(true);
    expect(res.text).toMatch(/is a 'unifi' target, not 'ssh'/);
  });

  it("refuses when the named target isn't registered at all", async () => {
    const res = await panelTool("panel_version").run({}, hostCtx({ resolveTarget: () => undefined }));
    expect(res.isError).toBe(true);
    expect(res.text).toMatch(/no target by that name is registered/);
  });

  it("refuses a call site that cannot resolve other targets, rather than skipping the step", async () => {
    const res = await panelTool("panel_version").run({}, hostCtx({ resolveTarget: undefined }));
    expect(res.isError).toBe(true);
    expect(res.text).toMatch(/cannot resolve other targets/);
  });

  it("refuses a panelPath that could break out of the fixed command", () => {
    // panelPath is interpolated into shell commands, so it has to be inert.
    for (const bad of ["/var/www/pelican; rm -rf /", "/var/www/$(whoami)", "relative/path", "/var/../etc", "/var/www/pelican'"]) {
      expect(() => assertSafePath(bad, "panelPath")).toThrow(/absolute path/);
    }
    expect(assertSafePath("/var/www/pelican/", "panelPath")).toBe("/var/www/pelican");
    expect(() => assertSafeUser("www-data; id", "panelUser")).toThrow(/plain unix username/);
    expect(assertSafeUser("www-data", "panelUser")).toBe("www-data");
  });
});

describe("panel version comparison", () => {
  it("orders releases and prereleases the way Pelican tags them", () => {
    expect(compareVersions("1.0.0-beta35", "v1.0.0-beta38")).toBe(-1);
    expect(compareVersions("1.0.0-beta38", "v1.0.0-beta38")).toBe(0);
    expect(compareVersions("1.0.1", "v1.0.0-beta38")).toBe(1);
    expect(compareVersions("1.0.0-beta38", "v1.0.0")).toBe(-1); // a release outranks its prereleases
  });

  it("returns undefined rather than guessing when the shapes don't match", () => {
    // Claiming "up to date" wrongly is the dangerous failure, so refuse instead.
    expect(compareVersions("1.0.0-alpha2", "1.0.0-beta38")).toBeUndefined();
    expect(compareVersions("weird", "1.0.0")).toBeUndefined();
  });

  it("parses the version out of config/app.php", () => {
    expect(parsePanelVersion("    'version' => '1.0.0-beta35',")).toBe("1.0.0-beta35");
    expect(parsePanelVersion("no version here")).toBeUndefined();
  });
});

describe("panel_upgrade steps", () => {
  it("runs artisan and composer as the panel user, never as root", () => {
    for (const step of PANEL_UPGRADE_STEPS) {
      if (/artisan|composer/.test(step.command)) {
        expect(step.command).toContain("sudo -n -u {user}");
      }
    }
  });

  it("interpolates only the validated path and user — no other placeholders exist", () => {
    for (const step of PANEL_UPGRADE_STEPS) {
      const placeholders = [...step.command.matchAll(/\{(\w+)\}/g)].map((m) => m[1]);
      expect(placeholders.every((p) => p === "path" || p === "user")).toBe(true);
    }
  });

  it("every step survives the destructive-command deny list", () => {
    // The target's ALLOWLIST is deliberately not applied here, but DEFAULT_DENY
    // still is — so a step must never contain rm -rf, mkfs, dd of=/dev/, reboot.
    for (const step of PANEL_UPGRADE_STEPS) {
      const rendered = step.command.replaceAll("{path}", "/var/www/pelican").replaceAll("{user}", "www-data");
      expect(checkCommand(rendered).allowed).toBe(true);
    }
  });

  it("takes the panel down first and brings it back up last", () => {
    expect(PANEL_UPGRADE_STEPS[0]!.name).toBe("maintenance-mode");
    expect(PANEL_UPGRADE_STEPS[PANEL_UPGRADE_STEPS.length - 1]!.name).toBe("exit-maintenance");
    expect(PANEL_UPGRADE_STEPS.map((s) => s.name)).toContain("migrate");
  });

  it("confirm names the host, the version and whether the backup is being skipped", () => {
    const t = target({ ownerUserId: 7, sshTarget: "pelican48" });
    const confirm = pelicanConnector.buildTools(t).find((x) => x.name === "panel_upgrade")!.confirm!;
    expect(confirm({ expectVersion: "1.0.0-beta35" }, t)).toContain("UPGRADE the Pelican panel itself on host 'pelican48'");
    expect(confirm({ expectVersion: "1.0.0-beta35" }, t)).toContain("from 1.0.0-beta35");
    expect(confirm({ expectVersion: "1.0.0-beta35", skipBackup: true }, t)).toMatch(/SKIPS the database backup/);
  });
});

describe("vault-backed variables (no secret ever crosses the MCP channel)", () => {
  const SECRET = "correct-horse-battery";
  const eggVars = item({
    id: 5,
    relationships: {
      variables: {
        data: [
          { attributes: { env_variable: "SERVER_NAME", default_value: "My Server", user_editable: true } },
          { attributes: { env_variable: "PASSWORD", default_value: "secret", user_editable: true } },
        ],
      },
    },
  });

  /** A context whose vault holds the secret, plus a stub fingerprinter. */
  function vaultCtx(over: Partial<ToolContext> = {}): ToolContext {
    return {
      target: target({ ownerUserId: 7 }),
      getCredential: async () => cred(),
      resolveCredential: async (ref: string) => {
        if (ref !== "valheim-password") throw new Error(`no such item '${ref}'`);
        return { ref, password: SECRET, fields: {}, uris: [] };
      },
      fingerprint: async (v: string) => `len=${v.length} fp=deadbeef`,
      ...over,
    };
  }

  it("create_server sends the vault value in the request body but NEVER in the result", async () => {
    const calls = mockFetch([
      { match: (u, i) => u.includes("/servers") && i?.method === "POST", reply: { json: item({ id: 9, identifier: "abc123" }) } },
      { match: (u) => /\/eggs\/\d+/.test(u), reply: { json: eggVars } },
      { match: (u) => u.includes("/eggs"), reply: { json: list([{ id: 5, name: "Valheim" }]) } },
      { match: (u) => u.includes("/allocations"), reply: { json: list([{ id: 11, ip: "192.168.0.48", port: 2456, assigned: false }]) } },
      { match: (u) => u.includes("/nodes"), reply: { json: list([{ id: 1 }]) } },
    ]);
    const res = await tool("create_server").run(
      {
        name: "valheim",
        egg: "Valheim",
        allocation: "192.168.0.48:2456",
        environment: { SERVER_NAME: "Jake's server" },
        secretEnvironment: [{ name: "PASSWORD", credentialRef: "valheim-password" }],
      },
      vaultCtx(),
    );
    expect(res.isError).toBeFalsy();
    // It reaches the panel…
    expect(JSON.parse(writes(calls)[0]!.init.body).environment.PASSWORD).toBe(SECRET);
    // …and nowhere else.
    expect(res.text).not.toContain(SECRET);
    expect(res.text).toContain("PASSWORD");
    expect(res.text).toContain("len=21 fp=deadbeef"); // fingerprint, not the value
  });

  it("a vault-backed variable beats a same-named plain one", async () => {
    const calls = mockFetch([
      { match: (u, i) => u.includes("/servers") && i?.method === "POST", reply: { json: item({ id: 9 }) } },
      { match: (u) => /\/eggs\/\d+/.test(u), reply: { json: eggVars } },
      { match: (u) => u.includes("/eggs"), reply: { json: list([{ id: 5, name: "Valheim" }]) } },
      { match: (u) => u.includes("/allocations"), reply: { json: list([{ id: 11, ip: "192.168.0.48", port: 2456, assigned: false }]) } },
      { match: (u) => u.includes("/nodes"), reply: { json: list([{ id: 1 }]) } },
    ]);
    await tool("create_server").run(
      {
        name: "v",
        egg: "Valheim",
        allocation: "192.168.0.48:2456",
        environment: { PASSWORD: "typed-in-chat" },
        secretEnvironment: [{ name: "PASSWORD", credentialRef: "valheim-password" }],
      },
      vaultCtx(),
    );
    expect(JSON.parse(writes(calls)[0]!.init.body).environment.PASSWORD).toBe(SECRET);
  });

  it("update_startup_variables pulls from the vault and keeps the value out of the result", async () => {
    const calls = mockFetch([{ match: (u) => u.includes("/startup/variable"), reply: { json: {} } }]);
    const res = await tool("update_startup_variables").run(
      { server: "abc123", secretVariables: [{ name: "PASSWORD", credentialRef: "valheim-password" }] },
      vaultCtx(),
    );
    expect(res.isError).toBeFalsy();
    expect(JSON.parse(writes(calls)[0]!.init.body)).toEqual({ key: "PASSWORD", value: SECRET });
    expect(res.text).not.toContain(SECRET);
    expect(res.text).toContain("came from the vault");
  });

  it("names the item and field in the approval prompt, never the value", () => {
    const t = target({ ownerUserId: 7 });
    const confirm = pelicanConnector.buildTools(t).find((x) => x.name === "update_startup_variables")!.confirm!;
    const text = confirm({ server: "abc123", secretVariables: [{ name: "PASSWORD", credentialRef: "valheim-password", field: "password" }] }, t);
    expect(text).toContain("PASSWORD←vault:valheim-password.password");
    expect(text).not.toContain(SECRET);
  });

  it("errors name the variable, item and field — and still no value — when the item is missing", async () => {
    const calls = mockFetch([{ match: () => true, reply: { json: {} } }]);
    const res = await tool("update_startup_variables").run(
      { server: "abc123", secretVariables: [{ name: "PASSWORD", credentialRef: "typo-name" }] },
      vaultCtx(),
    );
    expect(res.isError).toBe(true);
    expect(res.text).toContain("secretVariables 'PASSWORD'");
    expect(res.text).toContain("typo-name");
    expect(writes(calls)).toHaveLength(0);
  });

  it("refuses when the vault item exists but the field is empty, rather than setting a blank password", async () => {
    mockFetch([{ match: () => true, reply: { json: {} } }]);
    const res = await tool("update_startup_variables").run(
      { server: "abc123", secretVariables: [{ name: "PASSWORD", credentialRef: "valheim-password", field: "notes" }] },
      vaultCtx(),
    );
    expect(res.isError).toBe(true);
    expect(res.text).toMatch(/no value for field 'notes'/);
    expect(res.text).toMatch(/never paste the secret into chat/);
  });

  it("fails loudly at a call site with no vault access instead of silently skipping the variable", async () => {
    mockFetch([{ match: () => true, reply: { json: {} } }]);
    const res = await tool("update_startup_variables").run(
      { server: "abc123", secretVariables: [{ name: "PASSWORD", credentialRef: "valheim-password" }] },
      vaultCtx({ resolveCredential: undefined }),
    );
    expect(res.isError).toBe(true);
    expect(res.text).toMatch(/cannot resolve vault items/);
  });
});

describe("connector wiring", () => {
  it("registers every planned tool at the right tier", () => {
    const tools = pelicanConnector.buildTools(target({ ownerUserId: 7 }));
    const reads = tools.filter((t) => t.tier === "read").map((t) => t.name).sort();
    const execs = tools.filter((t) => t.tier === "execute").map((t) => t.name).sort();
    expect(reads).toEqual([
      "list_allocations",
      "list_eggs",
      "list_files",
      "list_nodes",
      "list_schedules",
      "list_servers",
      "list_users",
      "panel_version",
      "read_file",
      "server_details",
      "server_resources",
    ]);
    expect(execs).toEqual([
      "assign_allocation",
      "create_allocations",
      "create_folder",
      "create_schedule",
      "create_server",
      "decompress_file",
      "delete_files",
      "delete_schedule",
      "import_egg",
      "panel_upgrade",
      "power_action",
      "pull_file",
      "rename_files",
      "update_schedule",
      "update_server_startup",
      "update_startup_variables",
      "write_file",
    ]);
    // Every execute tool must carry confirm text — the approval gate keys off it.
    expect(tools.filter((t) => t.tier === "execute").every((t) => typeof t.confirm === "function")).toBe(true);
    expect(pelicanConnector.requiresCredential).toBe(true);
  });

  it("snapshot captures inventory with secrets redacted", async () => {
    mockFetch([
      { match: (u) => u.includes("/servers") && !u.includes("/schedules"), reply: { json: list([{ id: 1, identifier: "abc123", name: "v", container: { environment: { RCON_PASSWORD: RCON } } }]) } },
      { match: (u) => u.includes("/nodes"), reply: { json: list([{ id: 1, name: "n", daemon_token: "TOK" }]) } },
      { match: (u) => u.includes("/eggs"), reply: { json: list([{ id: 5, name: "Valheim" }]) } },
      { match: (u) => u.includes("/schedules"), reply: { json: list([]) } },
    ]);
    const arts = await pelicanConnector.snapshot!(ctx());
    const names = arts.map((a) => a.name);
    expect(names).toContain("servers.json");
    expect(names).toContain("nodes.json");
    const all = arts.map((a) => a.data.toString()).join("");
    expect(all).not.toContain(RCON);
    expect(all).not.toContain("TOK");
  });
});

// --- files (client API) --------------------------------------------------------

const fileObj = (name: string, size: number, isFile = true) => ({
  name,
  mode: isFile ? "-rw-r--r--" : "drwxr-xr-x",
  size,
  is_file: isFile,
  is_symlink: false,
  mimetype: isFile ? "application/octet-stream" : "inode/directory",
  modified_at: "2026-10-08T17:00:00+00:00",
});
const REF = "f5eb47ac";
const POLL_DEFAULTS = { ...FILE_PULL_POLL };
afterEach(() => Object.assign(FILE_PULL_POLL, POLL_DEFAULTS));

describe("files — guards", () => {
  it("assertVolumePath refuses escapes, dot/empty segments and control chars, allows backslashes and root-when-asked", () => {
    expect(() => assertVolumePath("../etc", "file")).toThrow("'..' is refused");
    expect(() => assertVolumePath("BepInEx/../../x", "file")).toThrow("'..'");
    expect(() => assertVolumePath("a/./b", "file")).toThrow("'.'");
    expect(() => assertVolumePath("a//b", "file")).toThrow("empty");
    expect(() => assertVolumePath("a\u0000b", "file")).toThrow("control");
    expect(() => assertVolumePath("/", "file")).toThrow("volume root");
    expect(() => assertVolumePath("  ", "file")).toThrow("volume root");
    expect(assertVolumePath("/", "root", { allowRoot: true })).toBe("/");
    expect(assertVolumePath("", "root", { allowRoot: true })).toBe("/");
    // A Windows-built Thunderstore zip extracts to a file literally named this.
    expect(assertVolumePath("plugins\\Jotunn.dll", "from")).toBe("plugins\\Jotunn.dll");
    expect(assertVolumePath(" /BepInEx/plugins ", "directory")).toBe("/BepInEx/plugins");
    expect(() => assertExactName("*.zip", "files[0]")).toThrow("exact name");
    expect(assertExactName("x.zip", "f")).toBe("x.zip");
  });

  it("assertPullUrl allows only public https — the daemon fetches from inside the LAN", () => {
    expect(assertPullUrl("https://thunderstore.io/package/download/denikson/BepInExPack_Valheim/5.4.2351/").hostname).toBe("thunderstore.io");
    expect(() => assertPullUrl("http://thunderstore.io/x.zip")).toThrow("https");
    expect(() => assertPullUrl("https://192.168.0.229:8787/x.zip")).toThrow("inside the network");
    expect(() => assertPullUrl("https://127.0.0.1/x.zip")).toThrow("inside the network");
    expect(() => assertPullUrl("https://localhost/x.zip")).toThrow("inside the network");
    expect(() => assertPullUrl("not a url")).toThrow("Invalid");
  });

  it("redactFileLines masks secret-named keys and password flags and leaves everything else alone", () => {
    const input = [
      "ServerPassword = hunter2",
      'rcon_password: "abc"',
      'DISCORD_TOKEN=xoxb-123',
      'exec ./valheim_server.x86_64 -name "My server" -password "secret" -port 2456',
      "[Info   :   BepInEx] Loading [Jotunn 2.30.2]",
      "LogLevels = Fatal, Error, Warning",
      '"author": "denikson"',
      "SteamAppId=892970",
      "# password = commented-out-but-real",
      "export STEAM_PASS=exported1",
      "set RCON_PASSWORD=batch1",
      '+sv_password "cvar1" +maxplayers 16',
      "-rconpassword rcon1 -port 27015",
    ].join("\n");
    const out = redactFileLines(input);
    for (const leaked of ["commented-out-but-real", "exported1", "batch1", "cvar1", "rcon1"]) expect(out).not.toContain(leaked);
    expect(out).toContain("# password = [redacted]");
    expect(out).toContain("export STEAM_PASS=[redacted]");
    expect(out).toContain("+sv_password [redacted] +maxplayers 16");
    expect(out).toContain("-rconpassword [redacted] -port 27015");
    expect(out).not.toContain("hunter2");
    expect(out).not.toContain('"abc"');
    expect(out).not.toContain("xoxb-123");
    expect(out).not.toContain('"secret"');
    expect(out).toContain("ServerPassword = [redacted]");
    expect(out).toContain("DISCORD_TOKEN=[redacted]");
    expect(out).toContain('-name "My server" -password [redacted] -port 2456');
    expect(out).toContain("Loading [Jotunn 2.30.2]");
    expect(out).toContain("LogLevels = Fatal, Error, Warning");
    expect(out).toContain('"author": "denikson"');
    expect(out).toContain("SteamAppId=892970");
  });

  it("summarizeFiles puts folders first and prints sizes", () => {
    const text = summarizeFiles("/BepInEx", [fileObj("LogOutput.log", 4321), fileObj("plugins", 4096, false), fileObj("core", 4096, false)]);
    expect(text.indexOf("core/")).toBeLessThan(text.indexOf("plugins/"));
    expect(text.indexOf("plugins/")).toBeLessThan(text.indexOf("LogOutput.log"));
    expect(text).toContain("4321");
    expect(summarizeFiles("/x", [])).toContain("(empty)");
  });
});

describe("files — client API tools", () => {
  it("list_files GETs the listing with the CLIENT key and renders folders first", async () => {
    const calls = mockFetch([
      { match: (u) => u.includes(`/api/client/servers/${REF}/files/list`), reply: { json: list([fileObj("Jotunn.dll", 1234), fileObj("core", 4096, false)]) } },
    ]);
    const res = await tool("list_files").run({ server: REF, directory: "/BepInEx/plugins" }, ctx());
    expect(res.isError).toBeFalsy();
    expect(calls[0]!.url).toContain("directory=%2FBepInEx%2Fplugins");
    expect(authOn(calls[0]!)).toBe(`Bearer ${CLI}`);
    expect(res.text.indexOf("core/")).toBeGreaterThan(-1);
    expect(res.text.indexOf("core/")).toBeLessThan(res.text.indexOf("Jotunn.dll"));
    expect(res.text).toContain("1234");
  });

  it("list_files refuses a path escape before any call", async () => {
    const calls = mockFetch([{ match: () => true, reply: { json: list([]) } }]);
    const res = await tool("list_files").run({ server: REF, directory: "/../../etc" }, ctx());
    expect(res.isError).toBe(true);
    expect(calls.length).toBe(0);
  });

  it("read_file returns the text, tails it, and redacts secret lines", async () => {
    const body = Array.from({ length: 50 }, (_, i) => `line ${i}`).concat(["password = hunter2"]).join("\n");
    const calls = mockFetch([{ match: (u) => u.includes("/files/contents"), reply: { text: body } }]);
    const res = await tool("read_file").run({ server: REF, file: "/BepInEx/LogOutput.log", tail: 3 }, ctx());
    expect(res.isError).toBeFalsy();
    expect(calls[0]!.url).toContain("file=%2FBepInEx%2FLogOutput.log");
    expect(authOn(calls[0]!)).toBe(`Bearer ${CLI}`);
    expect(res.text).toContain("last 3 of 51 lines");
    expect(res.text).toContain("line 49");
    expect(res.text).not.toContain("line 47");
    expect(res.text).not.toContain("hunter2");
    expect(res.text).toContain("password = [redacted]");
  });

  it("read_file redacts BEFORE cutting, so a tail that lands mid-line cannot expose the rest of a value", async () => {
    const secret = "S3cr3tValueThatIsLongEnoughToBeCut";
    const body = `prefix\npassword = ${secret}`;
    mockFetch([{ match: () => true, reply: { text: body } }]);
    // maxBytes clamps to 1024 minimum, so pad the file to force a byte cut from the end inside the password line.
    const padded = `${"x".repeat(2000)}\n${body}\n${"y".repeat(1100)}`;
    mockFetch([{ match: () => true, reply: { text: padded } }]);
    const res = await tool("read_file").run({ server: REF, file: "/x.cfg", tail: 2, maxBytes: 1024 }, ctx());
    expect(res.isError).toBeFalsy();
    expect(res.text).not.toContain(secret);
    expect(res.text).not.toContain(secret.slice(-10));
  });

  it("read_file caps the bytes it returns and says so", async () => {
    mockFetch([{ match: () => true, reply: { text: "x".repeat(FILE_READ_MAX_BYTES + 5000) } }]);
    const res = await tool("read_file").run({ server: REF, file: "/big.log", maxBytes: 10_000_000 }, ctx());
    expect(res.isError).toBeFalsy();
    expect(res.text).toContain(`truncated to ${FILE_READ_MAX_BYTES}`);
    expect(res.text.length).toBeLessThan(FILE_READ_MAX_BYTES + 500);
  });

  it("read_file refuses binary content instead of dumping it", async () => {
    mockFetch([{ match: () => true, reply: { text: "MZ\u0000\u0000garbage" } }]);
    const res = await tool("read_file").run({ server: REF, file: "/x.dll" }, ctx());
    expect(res.text).toContain("binary");
    expect(res.text).not.toContain("garbage");
  });

  it("read_file: a 404 reads as a missing path, not only an ownership problem", async () => {
    mockFetch([{ match: () => true, reply: { status: 404, json: { errors: [{ code: "NotFoundHttpException", detail: "The requested resource could not be found." }] } } }]);
    const res = await tool("read_file").run({ server: REF, file: "/nope.txt" }, ctx());
    expect(res.isError).toBe(true);
    expect(res.text).toContain("no such file");
  });

  it("write_file sends the content as a raw text/plain body and never echoes it", async () => {
    const calls = mockFetch([{ match: (u, init) => u.includes("/files/write") && init.method === "POST", reply: { status: 204 } }]);
    const t = tool("write_file");
    const input = { server: REF, file: "/BepInEx/config/x.cfg", content: "Enabled = true\n" };
    const res = await t.run(input, ctx());
    expect(res.isError).toBeFalsy();
    expect(calls[0]!.url).toContain("file=%2FBepInEx%2Fconfig%2Fx.cfg");
    expect(calls[0]!.init.body).toBe("Enabled = true\n");
    expect(calls[0]!.init.headers["Content-Type"]).toBe("text/plain");
    expect(res.text).toContain("15 bytes");
    expect(res.text).not.toContain("Enabled = true");
    expect(t.confirm!(input, target())).toContain("15 bytes");
    expect(t.confirm!(input, target())).not.toContain("Enabled");
  });

  it("write_file refuses oversized content before any call", async () => {
    const calls = mockFetch([{ match: () => true, reply: { status: 204 } }]);
    const res = await tool("write_file").run({ server: REF, file: "/x", content: "y".repeat(FILE_WRITE_MAX_BYTES + 1) }, ctx());
    expect(res.isError).toBe(true);
    expect(calls.length).toBe(0);
  });

  it("create_folder POSTs root + name", async () => {
    const calls = mockFetch([{ match: (u) => u.includes("/files/create-folder"), reply: { status: 204 } }]);
    const res = await tool("create_folder").run({ server: REF, root: "/BepInEx/plugins", name: "Jotunn" }, ctx());
    expect(res.isError).toBeFalsy();
    expect(JSON.parse(calls[0]!.init.body)).toEqual({ root: "/BepInEx/plugins", name: "Jotunn" });
  });

  it("pull_file refuses an http or in-network URL before any call", async () => {
    const calls = mockFetch([{ match: () => true, reply: { status: 204 } }]);
    const bad = ["http://thunderstore.io/x.zip", "https://192.168.0.1/x.zip", "https://localhost/x.zip"];
    for (const url of bad) {
      const res = await tool("pull_file").run({ server: REF, url, directory: "/", filename: "x.zip" }, ctx());
      expect(res.isError).toBe(true);
    }
    expect(calls.length).toBe(0);
  });

  it("pull_file asks Wings for a foreground download and verifies the landed size", async () => {
    FILE_PULL_POLL.intervalMs = 1;
    const url = "https://thunderstore.io/package/download/denikson/BepInExPack_Valheim/5.4.2351/";
    const calls = mockFetch([
      { match: (u, init) => u.includes("/files/pull") && init.method === "POST", reply: { status: 204 } },
      { match: (u) => u.includes("/files/list"), reply: { json: list([fileObj("bepinex.zip", 702924)]) } },
    ]);
    const t = tool("pull_file");
    const input = { server: REF, url, directory: "/_staging", filename: "bepinex.zip", expectedBytes: 702924 };
    const res = await t.run(input, ctx());
    expect(res.isError).toBeFalsy();
    expect(JSON.parse(writes(calls)[0]!.init.body)).toEqual({ url, directory: "/_staging", filename: "bepinex.zip", use_header: false, foreground: true });
    expect(authOn(calls[0]!)).toBe(`Bearer ${CLI}`);
    expect(res.text).toContain("702924 bytes — matches");
    expect(calls.filter((c) => c.url.includes("/files/list")).length).toBe(1);
    expect(t.confirm!(input, target())).toBe(
      `Download ${url} to '/_staging/bepinex.zip' on Pelican server '${REF}' on pelican-panel (the Wings daemon fetches it; expecting 702924 bytes)`,
    );
  });

  it("a completed foreground pull without expectedBytes is accepted on first sight", async () => {
    FILE_PULL_POLL.intervalMs = 1;
    const calls = mockFetch([
      { match: (u) => u.includes("/files/pull"), reply: { status: 204 } },
      { match: (u) => u.includes("/files/list"), reply: { json: list([fileObj("x.zip", 10)]) } },
    ]);
    const res = await tool("pull_file").run({ server: REF, url: "https://thunderstore.io/x", filename: "x.zip" }, ctx());
    expect(res.isError).toBeFalsy();
    expect(calls.filter((c) => c.url.includes("/files/list")).length).toBe(1);
    expect(res.text).toContain("10 bytes");
  });

  it("looksLikeDaemonTimeout keys on the envelope's exception class, as the live panel renders it", () => {
    const env = (code: string) => ({ ok: false, status: 500, json: { errors: [{ code, status: "500", detail: "An unexpected error was encountered while processing this request, please try again." }] }, text: "" });
    expect(looksLikeDaemonTimeout(env("ConnectionException"))).toBe(true); // panel→Wings timed out; Wings keeps downloading
    expect(looksLikeDaemonTimeout(env("RequestException"))).toBe(false); // Wings answered with an error — a real failure
    expect(looksLikeDaemonTimeout({ ok: false, status: 504, text: "Gateway Time-out" })).toBe(true);
    expect(looksLikeDaemonTimeout({ ok: false, status: 422, text: "The url field must be a valid URL." })).toBe(false);
    expect(looksLikeDaemonTimeout({ ok: true, status: 204, text: "" })).toBe(false);
  });

  it("pull_file fails at once on a Wings-side refusal (RequestException), without polling", async () => {
    const calls = mockFetch([
      { match: (u) => u.includes("/files/pull"), reply: { status: 500, json: { errors: [{ code: "RequestException", status: "500", detail: "An unexpected error was encountered while processing this request, please try again." }] } } },
      { match: (u) => u.includes("/files/list"), reply: { json: list([]) } },
    ]);
    const res = await tool("pull_file").run({ server: REF, url: "https://thunderstore.io/x", filename: "x.zip" }, ctx());
    expect(res.isError).toBe(true);
    expect(res.text).toContain("RequestException");
    expect(calls.filter((c) => c.url.includes("/files/list")).length).toBe(0);
  });

  it("pull_file gives up quickly, quoting the panel's error, when the file never appears", async () => {
    FILE_PULL_POLL.intervalMs = 1;
    FILE_PULL_POLL.appearWithinMs = 15;
    FILE_PULL_POLL.maxWaitMs = 10_000;
    mockFetch([
      { match: (u) => u.includes("/files/pull"), reply: { status: 500, json: { errors: [{ code: "ConnectionException", status: "500", detail: "An unexpected error was encountered while processing this request, please try again." }] } } },
      { match: (u) => u.includes("/files/list"), reply: { json: list([]) } },
    ]);
    const res = await tool("pull_file").run({ server: REF, url: "https://thunderstore.io/x", filename: "x.zip" }, ctx());
    expect(res.isError).toBe(true);
    expect(res.text).toContain("never appeared");
    expect(res.text).toContain("ConnectionException");
  });

  it("pull_file survives the panel's 15s daemon timeout by watching the file land", async () => {
    FILE_PULL_POLL.intervalMs = 1;
    const sizes = [0, 300_000, 702_924];
    let polls = 0;
    mockFetch([
      {
        match: (u) => u.includes("/files/pull"),
        reply: { status: 500, json: { errors: [{ code: "ConnectionException", status: "500", detail: "An unexpected error was encountered while processing this request, please try again." }] } },
      },
      {
        match: (u) => u.includes("/files/list"),
        reply: () => {
          const size = sizes[Math.min(polls++, sizes.length - 1)]!;
          return { json: list(size ? [fileObj("x.zip", size)] : []) };
        },
      },
    ]);
    const res = await tool("pull_file").run({ server: REF, url: "https://thunderstore.io/x", directory: "/", filename: "x.zip", expectedBytes: 702_924 }, ctx());
    expect(res.isError).toBeFalsy();
    expect(res.text).toContain("matches the expected size");
    expect(res.text).toContain("outlived the panel's 15s daemon timeout");
    expect(polls).toBe(3);
  });

  it("pull_file fails on a size mismatch, and on a download that never finishes", async () => {
    FILE_PULL_POLL.intervalMs = 1;
    FILE_PULL_POLL.maxWaitMs = 20;
    mockFetch([
      { match: (u) => u.includes("/files/pull"), reply: { status: 204 } },
      { match: (u) => u.includes("/files/list"), reply: { json: list([fileObj("x.zip", 999_999)]) } },
    ]);
    const big = await tool("pull_file").run({ server: REF, url: "https://thunderstore.io/x", filename: "x.zip", expectedBytes: 100 }, ctx());
    expect(big.isError).toBe(true);
    expect(big.text).toContain("999999 bytes but 100 were expected");
    const settledShort = await tool("pull_file").run({ server: REF, url: "https://thunderstore.io/x", filename: "x.zip", expectedBytes: 100 }, ctx());
    expect(settledShort.isError).toBe(true); // a FINISHED download that is the wrong size is wrong now, not "still landing"
    mockFetch([
      { match: (u) => u.includes("/files/pull"), reply: { status: 504, text: "Gateway Time-out" } },
      { match: (u) => u.includes("/files/list"), reply: { json: list([fileObj("x.zip", 50)]) } },
    ]);
    const stuck = await tool("pull_file").run({ server: REF, url: "https://thunderstore.io/x", filename: "x.zip", expectedBytes: 100 }, ctx());
    expect(stuck.isError).toBe(true);
    expect(stuck.text).toContain("did not finish landing");
    expect(stuck.text).toContain("50 bytes of 100");
  });

  it("pull_file surfaces a real panel error rather than polling for a file that will never come", async () => {
    const calls = mockFetch([
      { match: (u) => u.includes("/files/pull"), reply: { status: 422, json: { errors: [{ code: "ValidationException", detail: "The url field must be a valid URL." }] } } },
      { match: (u) => u.includes("/files/list"), reply: { json: list([]) } },
    ]);
    const res = await tool("pull_file").run({ server: REF, url: "https://thunderstore.io/x", filename: "x.zip" }, ctx());
    expect(res.isError).toBe(true);
    expect(res.text).toContain("422");
    expect(calls.filter((c) => c.url.includes("/files/list")).length).toBe(0);
  });

  it("pull_file explains the panel's per-user pull throttle on a 429, without polling", async () => {
    const calls = mockFetch([
      { match: (u) => u.includes("/files/pull"), reply: { status: 429, json: { message: "Too Many Attempts." } } },
      { match: (u) => u.includes("/files/list"), reply: { json: list([]) } },
    ]);
    const res = await tool("pull_file").run({ server: REF, url: "https://thunderstore.io/x", filename: "x.zip" }, ctx());
    expect(res.isError).toBe(true);
    expect(res.text).toContain("429");
    expect(res.text).toContain("5 per 10 minutes per user");
    expect(res.text).toContain("does not extend the window");
    expect(res.text).toContain("groups of at most 5");
    // No header from the panel: say so rather than inventing a retry time.
    expect(res.text).toContain("did not say when the window resets");
    expect(res.text).not.toContain("Retry-After");
    expect(res.text).not.toContain("X-RateLimit");
    // Nothing was downloaded, so nothing is watched for.
    expect(calls.filter((c) => c.url.includes("/files/list")).length).toBe(0);
  });

  it("pull_file passes along Retry-After and X-RateLimit-Reset when the panel sends them", async () => {
    const calls = mockFetch([
      {
        match: (u) => u.includes("/files/pull"),
        reply: {
          status: 429,
          json: { message: "Too Many Attempts." },
          headers: { "Retry-After": "412", "X-RateLimit-Reset": "1791417600", "X-RateLimit-Limit": "5" },
        },
      },
      { match: (u) => u.includes("/files/list"), reply: { json: list([]) } },
    ]);
    const res = await tool("pull_file").run({ server: REF, url: "https://thunderstore.io/x", filename: "x.zip" }, ctx());
    expect(res.isError).toBe(true);
    expect(res.text).toContain("Retry-After: 412s");
    expect(res.text).toContain("X-RateLimit-Reset: 1791417600 (2026-10-08T00:00:00.000Z)");
    expect(res.text).toContain("this panel reports a limit of 5");
    expect(res.text).not.toContain("did not say when");
    expect(calls.filter((c) => c.url.includes("/files/list")).length).toBe(0);
  });

  it("pull_file's description tells the model to batch pulls in fives", () => {
    expect(tool("pull_file").description).toMatch(/5 pulls per 10 minutes per user/);
    expect(tool("pull_file").description).toMatch(/groups of at most 5/);
  });

  it("decompress_file POSTs root+file and lists the result", async () => {
    const calls = mockFetch([
      { match: (u) => u.includes("/files/decompress"), reply: { status: 204 } },
      { match: (u) => u.includes("/files/list"), reply: { json: list([fileObj("x.zip", 10), fileObj("BepInExPack_Valheim", 4096, false)]) } },
    ]);
    const res = await tool("decompress_file").run({ server: REF, root: "/_staging", file: "x.zip" }, ctx());
    expect(res.isError).toBeFalsy();
    expect(JSON.parse(writes(calls)[0]!.init.body)).toEqual({ root: "/_staging", file: "x.zip" });
    expect(res.text).toContain("BepInExPack_Valheim/");
    expect(res.text).toContain("archive itself is kept");
  });

  it("rename_files PUTs the moves and names them in the confirm; refuses patterns and escapes", async () => {
    const calls = mockFetch([{ match: (u, init) => u.includes("/files/rename") && init.method === "PUT", reply: { status: 204 } }]);
    const t = tool("rename_files");
    const files = [{ from: "_staging/plugins\\Jotunn.dll", to: "BepInEx/plugins/Jotunn/Jotunn.dll" }];
    const res = await t.run({ server: REF, files }, ctx());
    expect(res.isError).toBeFalsy();
    expect(JSON.parse(calls[0]!.init.body)).toEqual({ root: "/", files });
    expect(t.confirm!({ server: REF, files }, target())).toContain("_staging/plugins\\Jotunn.dll -> BepInEx/plugins/Jotunn/Jotunn.dll");
    const bad = await t.run({ server: REF, files: [{ from: "*.dll", to: "x" }] }, ctx());
    expect(bad.isError).toBe(true);
    const esc = await t.run({ server: REF, files: [{ from: "a", to: "../b" }] }, ctx());
    expect(esc.isError).toBe(true);
    expect(calls.length).toBe(1);
  });

  it("delete_files refuses patterns and the root, POSTs exact names, and says it is permanent", async () => {
    const calls = mockFetch([{ match: (u) => u.includes("/files/delete"), reply: { status: 204 } }]);
    const t = tool("delete_files");
    for (const files of [["*"], ["/"], ["."], ["../x"]]) {
      const res = await t.run({ server: REF, files }, ctx());
      expect(res.isError).toBe(true);
    }
    expect(calls.length).toBe(0);
    const res = await t.run({ server: REF, root: "/_staging", files: ["x.zip", "leftover"] }, ctx());
    expect(res.isError).toBeFalsy();
    expect(JSON.parse(calls[0]!.init.body)).toEqual({ root: "/_staging", files: ["x.zip", "leftover"] });
    expect(res.text).toContain("permanent");
    expect(t.confirm!({ server: REF, root: "/_staging", files: ["x.zip"] }, target())).toContain("PERMANENTLY delete [x.zip] under '/_staging'");
  });

  it("every file tool declares its tier: reads free, writes gated", () => {
    const tiers = Object.fromEntries(pelicanConnector.buildTools(target()).map((x) => [x.name, x.tier]));
    expect(tiers.list_files).toBe("read");
    expect(tiers.read_file).toBe("read");
    for (const name of ["write_file", "create_folder", "pull_file", "decompress_file", "rename_files", "delete_files"]) {
      expect(tiers[name]).toBe("execute");
      expect(tool(name).confirm).toBeTypeOf("function");
    }
  });
});
