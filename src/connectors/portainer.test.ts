import { describe, it, expect, vi, afterEach } from "vitest";
import {
  portainerConnector,
  baseUrl,
  apiKeyFrom,
  summarizeContainers,
  demuxDockerLogs,
  toArgv,
  MANAGED_MARKER,
  hasManagedMarker,
  ensureManagedMarker,
  composeImages,
  mergeEnv,
  redactEnv,
  redactSecrets,
  pickCredentialField,
  summarizeStacks,
  curateInspect,
} from "./portainer.js";
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
      arrayBuffer: async () => {
        const b = route.reply.buf ?? Buffer.alloc(0);
        return b.buffer.slice(b.byteOffset, b.byteOffset + b.byteLength); // exact bytes, not the shared pool
      },
    } as any;
  });
  vi.stubGlobal("fetch", fn);
  return calls;
}

function ctx(c: Credential, t: Target = target({ endpointId: 1 })): ToolContext {
  return { target: t, getCredential: async () => c };
}

/** A context whose vault holds other items too (for the secretEnv bridge). */
function vaultCtx(c: Credential, vault: Record<string, Credential>, t: Target = target({ endpointId: 1 })): ToolContext {
  return {
    target: t,
    getCredential: async () => c,
    resolveCredential: async (ref) => {
      const item = vault[ref];
      if (!item) throw new Error(`No vault item named "${ref}"`);
      return item;
    },
  };
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
    const frame = (payload: string, stream = 1) => Buffer.concat([Buffer.from([stream, 0, 0, 0, 0, 0, 0, payload.length]), Buffer.from(payload)]);
    expect(demuxDockerLogs(Buffer.concat([frame("out\n", 1), frame("err\n", 2)]))).toBe("out\nerr\n");
    expect(demuxDockerLogs(Buffer.from("raw tty line\n"))).toBe("raw tty line\n");
  });

  it("demuxDockerLogs falls back to raw on truncation/malformation (never silently drops)", () => {
    // Header declares 10 bytes but only 6 follow → truncated → raw.
    const truncated = Buffer.concat([Buffer.from([1, 0, 0, 0, 0, 0, 0, 10]), Buffer.from("abcdef")]);
    expect(demuxDockerLogs(truncated)).toBe(truncated.toString("utf8"));
    // Valid frame then a partial (4-byte) trailing header → raw.
    const good = Buffer.concat([Buffer.from([1, 0, 0, 0, 0, 0, 0, 2]), Buffer.from("hi")]);
    const trailingPartial = Buffer.concat([good, Buffer.from([1, 0, 0, 0])]);
    expect(demuxDockerLogs(trailingPartial)).toBe(trailingPartial.toString("utf8"));
    // Second frame with nonzero reserved bytes → raw (not half-parsed).
    const badReserved = Buffer.concat([good, Buffer.from([1, 2, 3, 4, 0, 0, 0, 1]), Buffer.from("A")]);
    expect(demuxDockerLogs(badReserved)).toBe(badReserved.toString("utf8"));
  });

  it("deriveBaseUrl (via baseUrl) brackets IPv6 literal hosts", () => {
    expect(baseUrl({ name: "n", type: "portainer", host: "fd00::10", port: 9443 })).toBe("https://[fd00::10]:9443");
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

describe("endpoint auto-detection", () => {
  it("picks a running Docker endpoint over a down/first one when endpointId is unset", async () => {
    const calls = mockFetch([
      { match: (u) => u.endsWith("/api/endpoints"), reply: { json: [
        { Id: 1, Type: 1, Status: 2 }, // down
        { Id: 5, Type: 1, Status: 1 }, // up docker ← should win
      ] } },
      { match: (u) => u.includes("/api/endpoints/5/docker/containers/json"), reply: { json: [{ Names: ["/c"], State: "running" }] } },
    ]);
    // No endpointId option → must auto-detect.
    const t: Target = { name: "nas", type: "portainer", host: "10.0.0.5", port: 9000, credentialRef: "k" };
    const listContainers = portainerConnector.buildTools(t).find((x) => x.name === "list_containers")!;
    const res = await listContainers.run({ all: true }, { target: t, getCredential: async () => cred({ fields: { token: "k" } }) });
    expect(res.isError).toBeFalsy();
    expect(calls.some((c) => c.url.includes("/api/endpoints/5/docker/containers/json"))).toBe(true);
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

describe("exec_container", () => {
  it("creates an exec instance, starts it, and demuxes the output", async () => {
    const out = "refreshed\n";
    const frame = Buffer.concat([Buffer.from([1, 0, 0, 0, 0, 0, 0, out.length]), Buffer.from(out)]);
    const calls = mockFetch([
      { match: (u, i) => /\/watchtower\/exec$/.test(u) && i.method === "POST", reply: { json: { Id: "exec123" } } },
      { match: (u, i) => u.includes("/docker/exec/exec123/start") && i.method === "POST", reply: { buf: frame } },
    ]);
    const t: Target = { name: "nas", type: "portainer", host: "10.0.0.5", port: 9000, credentialRef: "k", options: { endpointId: 1 } };
    const execTool = portainerConnector.buildTools(t).find((x) => x.name === "exec_container")!;
    const res = await execTool.run({ container: "watchtower", command: "/watchtower --run-once skeleton-key" }, ctx(cred({ fields: { token: "k" } }), t));
    expect(res.isError).toBeFalsy();
    expect(res.text).toBe("refreshed\n");
    // Exec Cmd is exact argv tokens (no shell wrapper).
    const create = calls.find((c) => c.url.endsWith("/watchtower/exec"))!;
    expect(JSON.parse(create.init.body).Cmd).toEqual(["/watchtower", "--run-once", "skeleton-key"]);
  });

  it("is execute-tier", () => {
    const tool = portainerConnector.buildTools(target()).find((x) => x.name === "exec_container")!;
    expect(tool.tier).toBe("execute");
  });
});

describe("toArgv", () => {
  it("splits on whitespace into exact tokens", () => {
    expect(toArgv("/watchtower --run-once skeleton-key")).toEqual(["/watchtower", "--run-once", "skeleton-key"]);
    expect(toArgv("  ls  -la  ")).toEqual(["ls", "-la"]);
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

describe("managed marker + compose helpers", () => {
  it("injects the marker once and detects an existing one in any comment form", () => {
    const compose = "services:\n  app:\n    image: ghcr.io/me/app:1";
    const marked = ensureManagedMarker(compose);
    expect(marked.startsWith(MANAGED_MARKER)).toBe(true);
    expect(marked).toContain("services:");
    expect(ensureManagedMarker(marked)).toBe(marked); // idempotent
    expect(hasManagedMarker(compose)).toBe(false);
    expect(hasManagedMarker("services: {}\n#   x-skeleton-key-managed:  true  \n")).toBe(true);
  });

  it("composeImages lists referenced images and ignores commented ones", () => {
    const compose = [
      "services:",
      "  web:",
      '    image: "ghcr.io/me/web:1.2.3"',
      "  db:",
      "    image: postgres:16",
      "  old:",
      "    # image: ghcr.io/me/legacy:1",
    ].join("\n");
    expect(composeImages(compose)).toEqual(["ghcr.io/me/web:1.2.3", "postgres:16"]);
  });

  it("mergeEnv lets later lists win by name, keeping first-seen order", () => {
    const merged = mergeEnv([{ name: "A", value: "1" }, { name: "B", value: "2" }], undefined, [{ name: "B", value: "3" }, { name: "C", value: "4" }]);
    expect(merged).toEqual([{ name: "A", value: "1" }, { name: "B", value: "3" }, { name: "C", value: "4" }]);
  });

  it("redactEnv keeps names and drops values; redactSecrets scrubs echoed values", () => {
    expect(redactEnv([{ name: "DB_PASSWORD", value: "hunter2!" }])).toEqual([{ name: "DB_PASSWORD", value: "<redacted>" }]);
    expect(redactSecrets("bad value: hunter2! here", ["hunter2!"])).toBe("bad value: <redacted> here");
  });

  it("pickCredentialField reads named parts, custom fields, and the default chain", () => {
    const c = cred({ username: "u", password: "pw", secret: "sk", notes: "n", fields: { token: "tok", DB_URL: "postgres://x" } });
    expect(pickCredentialField(c)).toBe("pw"); // password first
    expect(pickCredentialField(cred({ secret: "sk", fields: { token: "tok" } }))).toBe("sk");
    expect(pickCredentialField(cred({ fields: { token: "tok" } }))).toBe("tok");
    expect(pickCredentialField(c, "username")).toBe("u");
    expect(pickCredentialField(c, "notes")).toBe("n");
    expect(pickCredentialField(c, "DB_URL")).toBe("postgres://x");
    expect(pickCredentialField(c, "nope")).toBeUndefined();
  });
});

describe("create_stack", () => {
  const compose = "services:\n  app:\n    image: ghcr.io/me/app:1";

  it("POSTs to the standalone endpoint with the marker injected", async () => {
    const calls = mockFetch([
      { match: (u, i) => u.includes("/api/stacks/create/standalone/string?endpointId=1") && i.method === "POST", reply: { json: { Id: 12, Name: "app", EndpointId: 1 } } },
    ]);
    const res = await tool("create_stack").run({ name: "app", composeContent: compose, env: [{ name: "TZ", value: "UTC" }] }, ctx(cred({ fields: { token: "k" } })));
    expect(res.isError).toBeFalsy();
    const body = JSON.parse(calls[0]!.init.body);
    expect(body.name).toBe("app");
    expect(body.fromAppTemplate).toBe(false);
    expect(body.stackFileContent.startsWith(MANAGED_MARKER)).toBe(true);
    expect(body.stackFileContent).toContain("image: ghcr.io/me/app:1");
    expect(body.env).toEqual([{ name: "TZ", value: "UTC" }]);
    expect(res.text).toContain("#12");
    expect(res.text).toContain("endpoint 1");
  });

  it("rejects an unsafe stack name before any request", async () => {
    mockFetch([]);
    const res = await tool("create_stack").run({ name: "../../etc", composeContent: compose }, ctx(cred({ fields: { token: "k" } })));
    expect(res.isError).toBe(true);
    expect(res.text).toMatch(/Invalid stack name/);
  });

  it("names the stack, target and images in its confirm text", () => {
    const t = target({ endpointId: 1 });
    const text = tool("create_stack").confirm!({ name: "app", composeContent: "services:\n  a:\n    image: ghcr.io/me/app:1" }, t);
    expect(text).toContain("'app'");
    expect(text).toContain("nas");
    expect(text).toContain("ghcr.io/me/app:1");
  });

  it("is execute-tier", () => {
    expect(tool("create_stack").tier).toBe("execute");
    expect(tool("remove_stack").tier).toBe("execute");
    expect(tool("container_inspect").tier).toBe("read");
  });
});

describe("secretEnv vault bridge", () => {
  const SECRET = "s3cr3t-db-pw";
  const compose = "services:\n  app:\n    image: ghcr.io/me/app:1";
  const vault = { "app-db": cred({ ref: "app-db", password: SECRET, fields: { API_TOKEN: "tok-abcdef" } }) };

  it("resolves vault values into the stack env and never leaks them", async () => {
    const calls = mockFetch([
      { match: (u, i) => u.includes("/api/stacks/create/standalone/string") && i.method === "POST", reply: { json: { Id: 3, Name: "app", EndpointId: 1 } } },
    ]);
    const input = {
      name: "app",
      composeContent: compose,
      env: [{ name: "DB_PASSWORD", value: "placeholder" }, { name: "TZ", value: "UTC" }],
      secretEnv: [{ name: "DB_PASSWORD", credentialRef: "app-db" }, { name: "API_TOKEN", credentialRef: "app-db", field: "API_TOKEN" }],
    };
    const res = await tool("create_stack").run(input, vaultCtx(cred({ fields: { token: "k" } }), vault));
    expect(res.isError).toBeFalsy();

    const body = JSON.parse(calls[0]!.init.body);
    // secretEnv wins over the plain env entry of the same name.
    expect(body.env).toEqual([
      { name: "DB_PASSWORD", value: SECRET },
      { name: "TZ", value: "UTC" },
      { name: "API_TOKEN", value: "tok-abcdef" },
    ]);

    // INVARIANT: the value reaches Portainer and nothing else.
    const confirmText = tool("create_stack").confirm!(input, target({ endpointId: 1 }));
    expect(confirmText).not.toContain(SECRET);
    expect(confirmText).toContain("DB_PASSWORD");
    expect(confirmText).toContain("app-db");
    expect(JSON.stringify(res)).not.toContain(SECRET);
    expect(JSON.stringify(res)).not.toContain("tok-abcdef");
    expect(res.text).toContain("DB_PASSWORD"); // names are fine
  });

  it("errors naming the ref and field, never the value, when nothing resolves", async () => {
    mockFetch([]);
    const res = await tool("create_stack").run(
      { name: "app", composeContent: compose, secretEnv: [{ name: "DB_PASSWORD", credentialRef: "app-db", field: "username" }] },
      vaultCtx(cred({ fields: { token: "k" } }), vault),
    );
    expect(res.isError).toBe(true);
    expect(res.text).toContain("app-db");
    expect(res.text).toContain("username");
    expect(res.text).not.toContain(SECRET);
  });

  it("errors clearly when the vault item does not exist", async () => {
    mockFetch([]);
    const res = await tool("create_stack").run(
      { name: "app", composeContent: compose, secretEnv: [{ name: "X", credentialRef: "missing" }] },
      vaultCtx(cred({ fields: { token: "k" } }), vault),
    );
    expect(res.isError).toBe(true);
    expect(res.text).toMatch(/missing/);
  });

  it("refuses secretEnv in a context that cannot resolve vault items", async () => {
    mockFetch([]);
    const res = await tool("create_stack").run(
      { name: "app", composeContent: compose, secretEnv: [{ name: "X", credentialRef: "app-db" }] },
      ctx(cred({ fields: { token: "k" } })), // no resolveCredential
    );
    expect(res.isError).toBe(true);
    expect(res.text).toMatch(/cannot resolve vault items/);
  });

  it("update_stack merges current Env < env < secretEnv and never echoes the value", async () => {
    const calls = mockFetch([
      {
        match: (u, i) => /\/api\/stacks\/7$/.test(u) && (!i.method || i.method === "GET"),
        reply: { json: { Id: 7, Name: "app", EndpointId: 2, Env: [{ name: "TZ", value: "UTC" }, { name: "DB_PASSWORD", value: "stale" }] } },
      },
      { match: (u, i) => u.includes("/api/stacks/7?endpointId=2") && i.method === "PUT", reply: { json: {} } },
    ]);
    const res = await tool("update_stack").run(
      {
        stackId: 7,
        stackFileContent: compose,
        pullImage: false,
        env: [{ name: "TZ", value: "Europe/Berlin" }, { name: "DB_PASSWORD", value: "placeholder" }],
        secretEnv: [{ name: "DB_PASSWORD", credentialRef: "app-db" }],
      },
      vaultCtx(cred({ fields: { token: "k" } }), vault),
    );
    expect(res.isError).toBeFalsy();
    const body = JSON.parse(calls.find((c) => c.init.method === "PUT")!.init.body);
    expect(body.env).toEqual([
      { name: "TZ", value: "Europe/Berlin" }, // plain env overrides the carried-forward value
      { name: "DB_PASSWORD", value: SECRET }, // secretEnv beats both
    ]);
    expect(JSON.stringify(res)).not.toContain(SECRET);
  });

  it("scrubs a secret Portainer echoes back in an error body", async () => {
    mockFetch([
      { match: (u, i) => u.includes("/api/stacks/create/standalone/string") && i.method === "POST", reply: { status: 500, json: { message: `bad env DB_PASSWORD=${SECRET}` } } },
    ]);
    const res = await tool("create_stack").run(
      { name: "app", composeContent: compose, secretEnv: [{ name: "DB_PASSWORD", credentialRef: "app-db" }] },
      vaultCtx(cred({ fields: { token: "k" } }), vault),
    );
    expect(res.isError).toBe(true);
    expect(res.text).not.toContain(SECRET);
    expect(res.text).toContain("<redacted>");
  });
});

describe("env redaction on read paths", () => {
  it("list_stacks reports env names with redacted values", async () => {
    mockFetch([
      { match: (u) => u.endsWith("/api/stacks"), reply: { json: [{ Id: 5, Name: "media", EndpointId: 1, Status: 1, Env: [{ name: "DB_PASSWORD", value: "hunter2!" }] }] } },
    ]);
    const res = await tool("list_stacks").run({}, ctx(cred({ fields: { token: "k" } })));
    expect(res.isError).toBeFalsy();
    expect(res.text).toContain("#5 media");
    expect(res.text).toContain("DB_PASSWORD=<redacted>");
    expect(res.text).not.toContain("hunter2!");
    expect(summarizeStacks([])).toBe("No stacks.");
  });

  it("container_inspect curates the inspect and redacts every env value", async () => {
    mockFetch([
      {
        match: (u) => u.includes("/docker/containers/app/json"),
        reply: {
          json: {
            Id: "abc",
            Name: "/app",
            Image: "sha256:deadbeef",
            RestartCount: 3,
            State: { Status: "running", Running: true, ExitCode: 0, StartedAt: "2026-08-20T00:00:00Z", Health: { Status: "unhealthy", Log: [{ ExitCode: 1, Output: "probe failed\n" }] } },
            Config: { Image: "ghcr.io/me/app:1", Env: ["DB_PASSWORD=hunter2!", "TZ=UTC"], Labels: { "com.docker.compose.project": "app" } },
            HostConfig: { NetworkMode: "bridge", RestartPolicy: { Name: "unless-stopped", MaximumRetryCount: 0 } },
            Mounts: [{ Type: "bind", Source: "/volume1/app", Destination: "/data", RW: true }],
            NetworkSettings: { Ports: { "8080/tcp": [{ HostIp: "0.0.0.0", HostPort: "8080" }] } },
          },
        },
      },
    ]);
    const res = await tool("container_inspect").run({ container: "app" }, ctx(cred({ fields: { token: "k" } })));
    expect(res.isError).toBeFalsy();
    expect(res.text).not.toContain("hunter2!");
    expect(res.text).toContain("DB_PASSWORD=<redacted>");
    expect(res.text).toContain("TZ=<redacted>");
    const out = JSON.parse(res.text);
    expect(out.name).toBe("app");
    expect(out.image).toBe("ghcr.io/me/app:1");
    expect(out.imageDigest).toBe("sha256:deadbeef");
    expect(out.state).toMatchObject({ status: "running", running: true, restartCount: 3, health: "unhealthy" });
    expect(out.state.healthLog[0].output).toBe("probe failed");
    expect(out.restartPolicy).toEqual({ name: "unless-stopped", maximumRetryCount: 0 });
    expect(out.mounts).toEqual([{ type: "bind", source: "/volume1/app", destination: "/data", rw: true }]);
    expect(out.ports).toEqual([{ container: "8080/tcp", published: ["0.0.0.0:8080"] }]);
    expect(out.networkMode).toBe("bridge");
  });

  it("curateInspect tolerates a sparse inspect", () => {
    const out = curateInspect({});
    expect(out.env).toEqual([]);
    expect(out.mounts).toEqual([]);
  });
});

describe("remove_stack", () => {
  it("refuses a stack whose compose file has no skeleton-key marker", async () => {
    const calls = mockFetch([
      { match: (u, i) => /\/api\/stacks\/9$/.test(u) && (!i.method || i.method === "GET"), reply: { json: { Id: 9, Name: "legacy", EndpointId: 1 } } },
      { match: (u) => u.includes("/api/stacks/9/file"), reply: { json: { StackFileContent: "services:\n  legacy: {}" } } },
    ]);
    const res = await tool("remove_stack").run({ stackId: 9, stackName: "legacy" }, ctx(cred({ fields: { token: "k" } })));
    expect(res.isError).toBe(true);
    expect(res.text).toMatch(/no '# x-skeleton-key-managed: true' marker/);
    expect(calls.some((c) => c.init.method === "DELETE")).toBe(false);
  });

  it("refuses when the given name does not match the id", async () => {
    const calls = mockFetch([
      { match: (u, i) => /\/api\/stacks\/9$/.test(u) && (!i.method || i.method === "GET"), reply: { json: { Id: 9, Name: "other", EndpointId: 1 } } },
    ]);
    const res = await tool("remove_stack").run({ stackId: 9, stackName: "legacy" }, ctx(cred({ fields: { token: "k" } })));
    expect(res.isError).toBe(true);
    expect(res.text).toMatch(/named 'other'/);
    expect(calls.some((c) => c.init.method === "DELETE")).toBe(false);
  });

  it("deletes a managed stack on its own endpoint", async () => {
    const calls = mockFetch([
      { match: (u, i) => /\/api\/stacks\/4$/.test(u) && (!i.method || i.method === "GET"), reply: { json: { Id: 4, Name: "app", EndpointId: 2 } } },
      { match: (u) => u.includes("/api/stacks/4/file"), reply: { json: { StackFileContent: `${MANAGED_MARKER}\nservices:\n  app: {}` } } },
      { match: (u, i) => u.includes("/api/stacks/4?endpointId=2") && i.method === "DELETE", reply: { json: {} } },
    ]);
    const res = await tool("remove_stack").run({ stackId: 4, stackName: "app" }, ctx(cred({ fields: { token: "k" } })));
    expect(res.isError).toBeFalsy();
    expect(calls.some((c) => c.init.method === "DELETE")).toBe(true);
    expect(res.text).toMatch(/NOT deleted/);
  });

  it("warns in the confirm text that volumes survive", () => {
    const text = tool("remove_stack").confirm!({ stackId: 4, stackName: "app" }, target({ endpointId: 1 }));
    expect(text).toContain("'app'");
    expect(text).toContain("#4");
    expect(text).toContain("endpoint 1");
    expect(text).toMatch(/Volumes and bind mounts are NOT deleted/);
  });
});

describe("exec_container command policy", () => {
  it("refuses a destructive command before any request", async () => {
    const calls = mockFetch([]);
    const res = await tool("exec_container").run({ container: "app", command: "rm -rf /data" }, ctx(cred({ fields: { token: "k" } })));
    expect(res.isError).toBe(true);
    expect(res.text).toMatch(/^Refused: /);
    expect(calls.length).toBe(0);
  });

  it("honors a per-target denyPatterns option", async () => {
    const t = target({ endpointId: 1, denyPatterns: ["drop\\s+database"] });
    const execTool = portainerConnector.buildTools(t).find((x) => x.name === "exec_container")!;
    mockFetch([]);
    const res = await execTool.run({ container: "db", command: "psql -c DROP DATABASE app" }, ctx(cred({ fields: { token: "k" } }), t));
    expect(res.isError).toBe(true);
    expect(res.text).toMatch(/denied pattern/);
  });

  it("honors a per-target allowPatterns allowlist", async () => {
    const t = target({ endpointId: 1, allowPatterns: ["^/watchtower\\b"] });
    const execTool = portainerConnector.buildTools(t).find((x) => x.name === "exec_container")!;
    mockFetch([]);
    const res = await execTool.run({ container: "app", command: "ls -la" }, ctx(cred({ fields: { token: "k" } }), t));
    expect(res.isError).toBe(true);
    expect(res.text).toMatch(/allowlist/);
  });
});

describe("snapshot", () => {
  it("captures endpoints, stacks + compose files, and container inspects", async () => {
    mockFetch([
      { match: (u) => u.endsWith("/api/endpoints"), reply: { json: [{ Id: 1, Name: "local", Type: 1, Status: 1 }] } },
      { match: (u) => u.endsWith("/api/stacks"), reply: { json: [{ Id: 5, Name: "media", EndpointId: 1, Status: 1 }] } },
      { match: (u) => u.includes("/api/stacks/5/file"), reply: { json: { StackFileContent: "services:\n  plex: {}" } } },
      { match: (u) => u.includes("/docker/containers/json"), reply: { json: [{ Id: "abc123", Names: ["/plex"] }] } },
      { match: (u) => u.includes("/docker/containers/abc123/json"), reply: { json: { Id: "abc123", Config: { Env: ["X=1"] } } } },
    ]);
    const arts = await portainerConnector.snapshot!(ctx(cred({ fields: { token: "ptr_key" } })));
    expect(arts.map((a) => a.name)).toEqual(
      expect.arrayContaining(["endpoints.json", "stacks.json", "stack-1-media.compose.yml", "containers.json", "container-plex.inspect.json"]),
    );
    expect(arts.find((a) => a.name === "stack-1-media.compose.yml")!.data.toString()).toContain("services:");
  });
});
