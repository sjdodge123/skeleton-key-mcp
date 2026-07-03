import { describe, it, expect, vi, afterEach } from "vitest";
import { portainerConnector, baseUrl, apiKeyFrom, summarizeContainers, demuxDockerLogs } from "./portainer.js";
import type { Credential, Target, ToolContext } from "./types.js";

function target(options: Record<string, unknown> = {}, port = 9000): Target {
  return { name: "nas", type: "portainer", host: "10.0.0.5", port, credentialRef: "portainer-key", options };
}
function cred(partial: Partial<Credential>): Credential {
  return { ref: "portainer-key", fields: {}, uris: [], ...partial };
}
function tool(name: string) {
  return portainerConnector.buildTools(target({ endpointId: 1 })).find((t) => t.name === name)!;
}

/** A minimal fetch mock that records calls and replies from a queue by matcher. */
function mockFetch(routes: { match: (url: string, init: any) => boolean; reply: { status?: number; json?: unknown; buf?: Buffer } }[]) {
  const calls: { url: string; init: any }[] = [];
  const fn = vi.fn(async (url: string, init: any) => {
    calls.push({ url, init });
    const route = routes.find((r) => r.match(url, init));
    if (!route) throw new Error(`no mock route for ${init?.method ?? "GET"} ${url}`);
    const status = route.reply.status ?? 200;
    return {
      ok: status >= 200 && status < 300,
      status,
      text: async () => (route.reply.json !== undefined ? JSON.stringify(route.reply.json) : ""),
      arrayBuffer: async () => (route.reply.buf ?? Buffer.alloc(0)).buffer,
    } as any;
  });
  vi.stubGlobal("fetch", fn);
  return calls;
}

function ctx(c: Credential, t: Target = target({ endpointId: 1 })): ToolContext {
  return { target: t, getCredential: async () => c };
}

afterEach(() => vi.unstubAllEnvs?.() ?? vi.restoreAllMocks());

describe("pure helpers", () => {
  it("baseUrl picks scheme by port and honors an override", () => {
    expect(baseUrl(target({}, 9000))).toBe("http://10.0.0.5:9000");
    expect(baseUrl(target({}, 9443))).toBe("https://10.0.0.5:9443");
    expect(baseUrl(target({ baseUrl: "https://portainer.lan/" }, 9000))).toBe("https://portainer.lan");
  });

  it("apiKeyFrom reads an explicit field, never the notes-derived secret", () => {
    expect(apiKeyFrom(cred({ fields: { token: "ptr_abc" } }))).toBe("ptr_abc");
    expect(apiKeyFrom(cred({ fields: { api_key: "ptr_xyz" } }))).toBe("ptr_xyz");
    // A password login whose notes leaked into `secret` must NOT be used as a key.
    expect(apiKeyFrom(cred({ secret: "some notes", password: "pw" }))).toBeUndefined();
  });

  it("summarizeContainers strips the leading slash and formats", () => {
    const out = summarizeContainers([{ Names: ["/pihole"], State: "running", Image: "pihole/pihole", Status: "Up 2 days" }]);
    expect(out).toBe("- pihole  [running]  pihole/pihole  Up 2 days");
    expect(summarizeContainers([])).toBe("No containers.");
  });

  it("demuxDockerLogs strips 8-byte frame headers and passes TTY streams through", () => {
    const payload = "hello\n";
    const frame = Buffer.concat([Buffer.from([1, 0, 0, 0, 0, 0, 0, payload.length]), Buffer.from(payload)]);
    expect(demuxDockerLogs(frame)).toBe("hello\n");
    expect(demuxDockerLogs(Buffer.from("raw tty line\n"))).toBe("raw tty line\n");
  });
});

describe("auth", () => {
  it("uses X-API-Key when the credential has a token", async () => {
    const calls = mockFetch([{ match: (u) => u.includes("/containers/json"), reply: { json: [{ Names: ["/x"], State: "running" }] } }]);
    const res = await tool("list_containers").run({ all: true }, ctx(cred({ fields: { token: "ptr_key" } })));
    expect(res.isError).toBeFalsy();
    expect(calls[0]!.init.headers["X-API-Key"]).toBe("ptr_key");
    expect(calls[0]!.init.headers.Authorization).toBeUndefined();
  });

  it("exchanges username/password for a JWT and sends it as Bearer", async () => {
    const calls = mockFetch([
      { match: (u, i) => u.endsWith("/api/auth") && i.method === "POST", reply: { json: { jwt: "JWT123" } } },
      { match: (u) => u.endsWith("/api/stacks"), reply: { json: [{ Id: 1, Name: "s", EndpointId: 1, Status: 1 }] } },
    ]);
    const res = await tool("list_stacks").run({}, ctx(cred({ username: "admin", password: "pw" })));
    expect(res.isError).toBeFalsy();
    expect(calls[0]!.url).toContain("/api/auth");
    expect(JSON.parse(calls[0]!.init.body)).toEqual({ username: "admin", password: "pw" });
    expect(calls[1]!.init.headers.Authorization).toBe("Bearer JWT123");
  });

  it("errors clearly when no usable credential is present", async () => {
    mockFetch([]);
    const res = await tool("list_stacks").run({}, ctx(cred({ secret: "just notes" })));
    expect(res.isError).toBe(true);
    expect(res.text).toMatch(/API key|username/);
  });
});

describe("update_stack", () => {
  it("fetches the current stack then PUTs the new file preserving Env and endpoint", async () => {
    const calls = mockFetch([
      { match: (u, i) => /\/api\/stacks\/7$/.test(u) && (!i.method || i.method === "GET"), reply: { json: { Id: 7, Name: "app", EndpointId: 2, Env: [{ name: "TZ", value: "UTC" }] } } },
      { match: (u, i) => u.includes("/api/stacks/7?endpointId=2") && i.method === "PUT", reply: { json: {} } },
    ]);
    const res = await tool("update_stack").run({ stackId: 7, stackFileContent: "services:\n  app:\n    image: x", pullImage: false }, ctx(cred({ fields: { token: "k" } })));
    expect(res.isError).toBeFalsy();
    expect(res.text).toContain("app");
    const put = calls.find((c) => c.init.method === "PUT")!;
    const body = JSON.parse(put.init.body);
    expect(body.stackFileContent).toContain("image: x");
    expect(body.env).toEqual([{ name: "TZ", value: "UTC" }]); // preserved
    expect(body.prune).toBe(false);
  });
});

describe("connector registration", () => {
  it("is a credentialed portainer connector", () => {
    expect(portainerConnector.type).toBe("portainer");
    expect(portainerConnector.requiresCredential).toBe(true);
    const names = portainerConnector.buildTools(target()).map((t) => t.name);
    expect(names).toContain("update_stack");
    expect(names).toContain("list_containers");
  });

  it("marks state-changing tools execute and inspection tools read", () => {
    const tools = portainerConnector.buildTools(target());
    const byName = new Map(tools.map((t) => [t.name, t.tier]));
    expect(byName.get("update_stack")).toBe("execute");
    expect(byName.get("restart_container")).toBe("execute");
    expect(byName.get("list_containers")).toBe("read");
    expect(byName.get("get_stack_file")).toBe("read");
  });
});
