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
  summarizeEggs,
  summarizeNodes,
  summarizeAllocations,
  summarizeServers,
  summarizeSchedules,
  cronOf,
} from "./pelican.js";
import type { Credential, Target, ToolContext } from "./types.js";

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

function mockFetch(routes: { match: (url: string, init: any) => boolean; reply: { status?: number; json?: unknown } }[]) {
  const calls: { url: string; init: any }[] = [];
  const fn = vi.fn(async (url: string, init: any) => {
    calls.push({ url, init });
    const route = routes.find((r) => r.match(url, init));
    if (!route) throw new Error(`no mock route for ${init?.method ?? "GET"} ${url}`);
    const status = route.reply.status ?? 200;
    return {
      ok: status >= 200 && status < 300,
      status,
      statusText: "",
      headers: { get: () => null, getSetCookie: () => [] },
      text: async () => (route.reply.json !== undefined ? JSON.stringify(route.reply.json) : ""),
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
  function mock(storeReply: { status?: number; json?: unknown } = { json: item({ id: 9, name: "valheim", identifier: "abc123", uuid: "u-9" }) }) {
    return mockFetch([
      { match: (u, i) => u.includes("/servers") && i?.method === "POST", reply: storeReply },
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
    expect(body.environment).toEqual({}); // 'present|array' — must be sent even when empty
    expect(body.limits).toMatchObject({ memory: 4096, disk: 10240, cpu: 0 });
    expect(body.feature_limits).toMatchObject({ databases: 0, allocations: 1, backups: 1 });
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

describe("connector wiring", () => {
  it("registers every planned tool at the right tier", () => {
    const tools = pelicanConnector.buildTools(target({ ownerUserId: 7 }));
    const reads = tools.filter((t) => t.tier === "read").map((t) => t.name).sort();
    const execs = tools.filter((t) => t.tier === "execute").map((t) => t.name).sort();
    expect(reads).toEqual(["list_allocations", "list_eggs", "list_nodes", "list_schedules", "list_servers", "list_users", "server_details", "server_resources"]);
    expect(execs).toEqual(["assign_allocation", "create_schedule", "create_server", "delete_schedule", "power_action", "update_schedule", "update_startup_variables"]);
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
