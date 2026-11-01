/**
 * Conformance suite: rules every connector must meet, checked for all of them at
 * once, so a new connector inherits the checks without writing them. Each rule
 * is one CONTRIBUTING.md promise; a failure here means a connector broke it.
 *
 * Grandfathered exceptions are listed explicitly below. The lists may shrink but
 * must not grow without a maintainer's review: this file is maintainer-owned
 * (CODEOWNERS), like tools.manifest.json.
 */
import { afterAll, beforeAll, describe, expect, it, vi } from "vitest";

// --- network isolation: every way a connector can leave the process ----------
// Read tools run against these fakes; each call is recorded.
interface Call {
  method: string;
  url: string;
}
const calls: Call[] = [];
/** Just enough of each login reply for a client to get past auth and make its
 *  real request; everything else gets an empty JSON list. */
function fakeResponse(href: string): Response {
  let body: unknown = [];
  if (/\/api\/auth$/.test(href)) body = { jwt: "conformance" };
  else if (/\/access\/ticket$/.test(href)) body = { data: { ticket: "conformance", CSRFPreventionToken: "conformance" } };
  return new Response(JSON.stringify(body), { status: 200, headers: { "content-type": "application/json" } });
}
function record(url: unknown, init?: { method?: string }): Promise<Response> {
  const href = typeof url === "string" ? url : url instanceof URL ? url.href : String((url as Request).url);
  calls.push({ method: (init?.method ?? (url as Request)?.method ?? "GET").toUpperCase(), url: href });
  return Promise.resolve(fakeResponse(href));
}

vi.mock("undici", () => ({
  fetch: (url: unknown, init?: { method?: string }) => record(url, init),
  Agent: class {},
}));
vi.mock("./ssh-exec.js", async () => {
  const actual = await vi.importActual<typeof import("./ssh-exec.js")>("./ssh-exec.js");
  return {
    ...actual,
    runSsh: vi.fn(async (_t: unknown, _c: unknown, command: string) => {
      calls.push({ method: "SSH", url: command });
      return { stdout: "", stderr: "", code: 0 };
    }),
  };
});
vi.mock("socket.io-client", () => ({
  io: () => {
    throw new Error("conformance: no network");
  },
}));

import type { Connector, ConnectorTool, Credential, Target, ToolContext } from "./types.js";
import { connectorAliases, declaredOptionKeys, listConnectors, validateTargetOptions } from "./index.js";
import { buildGlobalTools } from "../mcp/builtin-tools.js";
import type { AppState } from "../app.js";
import { sampleInput } from "../../test/helpers/sample-input.js";

const connectors = listConnectors();
const globalTools = buildGlobalTools({} as AppState);

const target = (c: Connector, over: Partial<Target> = {}): Target => ({
  name: "conformance-target",
  type: c.type,
  host: "10.0.0.10",
  ...over,
});

// --- naming --------------------------------------------------------------------
const TYPE_RE = /^[a-z][a-z0-9-]*$/;
const TOOL_RE = /^[a-z][a-z0-9]*(_[a-z0-9]+)*$/;

/** Verbs that say a tool only looks. A tool named with one must be `read`. */
const READ_VERBS = ["list", "get", "read", "tail", "grep", "search", "show", "describe", "inspect", "check"];
/** Verbs that say a tool changes something. A tool named with one must be `execute`. */
const EXECUTE_VERBS = [
  "set", "create", "update", "delete", "remove", "restart", "start", "stop", "write", "rename", "import",
  "assign", "pull", "decompress", "power", "install", "upgrade", "enable", "disable", "pause", "resume",
  "reboot", "exec", "force", "store", "generate", "register", "request", "end",
];

/**
 * Connector tools whose names predate the verb-first rule. New tools must start
 * with a verb from the lists above. Renaming one of these changes a qualified
 * tool name users may rely on, so they stay until a deliberate breaking release.
 */
const LEGACY_TOOL_NAMES: Record<string, string[]> = {
  "home-assistant": ["ha_states", "ha_get", "ha_logbook", "ha_call_service", "ha_backup"],
  pelican: ["server_details", "server_resources", "panel_version", "panel_upgrade", "panel_prepare_runtime", "wings_update"],
  portainer: ["container_logs", "container_inspect"],
  proxmox: ["node_status", "guest_status", "task_log", "guest_power"],
  ssh: ["journalctl", "service_status", "disk_usage", "run_readonly", "run_command"],
  "uptime-kuma": ["monitor_status", "maintenance"],
};

const verbOf = (name: string) => name.split(/[_.]/)[0]!;

describe.each(connectors.map((c) => [c.type, c] as const))("connector %s", (_type, c) => {
  const tools = c.buildTools(target(c));

  it("has a kebab-case type", () => {
    expect(c.type).toMatch(TYPE_RE);
  });

  it("names every tool in snake_case, uniquely", () => {
    for (const t of tools) expect(t.name, t.name).toMatch(TOOL_RE);
    expect(new Set(tools.map((t) => t.name)).size).toBe(tools.length);
  });

  it("starts every new tool name with a known verb", () => {
    const legacy = new Set(LEGACY_TOOL_NAMES[c.type] ?? []);
    const offenders = tools
      .filter((t) => !legacy.has(t.name))
      .filter((t) => !READ_VERBS.includes(verbOf(t.name)) && !EXECUTE_VERBS.includes(verbOf(t.name)))
      .map((t) => t.name);
    expect(offenders, "start the name with a verb from READ_VERBS/EXECUTE_VERBS").toEqual([]);
  });

  it("keeps the legacy name list honest (no stale entries)", () => {
    const names = new Set(tools.map((t) => t.name));
    for (const n of LEGACY_TOOL_NAMES[c.type] ?? []) expect(names.has(n), `${n} no longer exists; remove it`).toBe(true);
  });

  it("gives each tool the tier its verb implies", () => {
    for (const t of tools) {
      const verb = verbOf(t.name);
      if (EXECUTE_VERBS.includes(verb)) expect(t.tier, `${t.name} reads as state-changing`).toBe("execute");
      if (READ_VERBS.includes(verb)) expect(t.tier, `${t.name} reads as read-only`).toBe("read");
    }
  });

  it("builds the same tool set whatever the target", () => {
    const other = c.buildTools(target(c, { name: "another-one", host: "10.9.8.7", port: 8443 }));
    const shape = (ts: ConnectorTool[]) => ts.map((t) => `${t.name}:${t.tier}`);
    expect(shape(other)).toEqual(shape(tools));
  });

  it("declares an introspectable, all-optional configSchema", () => {
    expect(declaredOptionKeys(c), "configSchema must be a plain z.object").not.toBeNull();
    expect(c.configSchema.safeParse({}).success).toBe(true);
  });

  it("refuses unknown option keys at registration", () => {
    expect(() => validateTargetOptions(c, { notARealOption: true })).toThrow(/Unknown option/);
  });

  it("gives every execute tool a confirm() that names the target", () => {
    const t = target(c);
    for (const tool of tools.filter((x) => x.tier === "execute")) {
      expect(typeof tool.confirm, `${tool.name} has no confirm()`).toBe("function");
      const text = tool.confirm!(sampleInput(tool.inputSchema), t);
      expect(typeof text).toBe("string");
      expect(text.includes(t.name) || text.includes(t.host), `${tool.name}: "${text}"`).toBe(true);
    }
  });
});

describe("connector aliases", () => {
  it("are kebab-or-plain lowercase and resolve to a real connector", () => {
    const types = new Set(connectors.map((c) => c.type));
    for (const [alias, type] of Object.entries(connectorAliases())) {
      expect(alias).toMatch(TYPE_RE);
      expect(types.has(type)).toBe(true);
    }
  });
});

describe("global tools", () => {
  it("are snake_case, unique, and tiered consistently with their verbs", () => {
    expect(new Set(globalTools.map((t) => t.name)).size).toBe(globalTools.length);
    for (const t of globalTools) {
      expect(t.name).toMatch(TOOL_RE);
      const verb = verbOf(t.name);
      if (EXECUTE_VERBS.includes(verb)) expect(t.tier, t.name).toBe("execute");
      if (READ_VERBS.includes(verb)) expect(t.tier, t.name).toBe("read");
    }
  });

  it("give every execute tool a confirm()", () => {
    for (const t of globalTools.filter((x) => x.tier === "execute")) expect(typeof t.confirm, t.name).toBe("function");
  });
});

// --- read tools never mutate ---------------------------------------------------
/**
 * Non-GET requests a read tool may make: logging in to get a session, never
 * changing state. Keyed by connector type; each entry is METHOD plus a path
 * regex. Keep this list short and every entry justified.
 */
const READ_TOOL_AUTH_REQUESTS: Record<string, { method: string; path: RegExp; why: string }[]> = {
  portainer: [{ method: "POST", path: /^\/api\/auth$/, why: "username/password login for a JWT when no API key is stored" }],
  proxmox: [{ method: "POST", path: /^\/api2\/json\/access\/ticket$/, why: "username/password exchange for a PVE ticket when no API token is stored" }],
  unifi: [{ method: "POST", path: /^\/api\/(auth\/)?login$/, why: "UniFi OS / legacy controller login when no API key is stored" }],
};

const credential: Credential = {
  ref: "conformance",
  username: "user",
  password: "password",
  secret: "token",
  fields: { application_key: "papp_conformance", client_key: "pacc_conformance" },
  uris: [],
};

function fakeContext(c: Connector): ToolContext {
  return {
    target: target(c),
    getCredential: async () => credential,
    resolveCredential: async (ref) => ({ ...credential, ref }),
    resolveTarget: () => undefined,
    targetsOfType: () => [],
    fingerprint: async () => "len=1 fp=00000000",
    protectedHosts: () => [],
  };
}

const withTimeout = (p: Promise<unknown>, ms: number) =>
  Promise.race([p, new Promise((resolve) => setTimeout(resolve, ms))]);

describe("read tools", () => {
  const observed: Record<string, Call[]> = {};

  beforeAll(async () => {
    vi.stubGlobal("fetch", (url: unknown, init?: { method?: string }) => record(url, init));
    for (const c of connectors) {
      for (const tool of c.buildTools(target(c)).filter((t) => t.tier === "read")) {
        calls.length = 0;
        await withTimeout(
          tool.run(sampleInput(tool.inputSchema), fakeContext(c)).catch(() => undefined),
          2000,
        );
        observed[`${c.type}.${tool.name}`] = [...calls];
      }
    }
  }, 120_000);

  afterAll(() => {
    vi.unstubAllGlobals();
  });

  it("make no state-changing HTTP request", () => {
    const offenders: string[] = [];
    for (const [key, cs] of Object.entries(observed)) {
      const type = key.slice(0, key.lastIndexOf("."));
      for (const call of cs) {
        if (call.method === "SSH" || call.method === "GET" || call.method === "HEAD") continue;
        const path = (() => {
          try {
            return new URL(call.url).pathname;
          } catch {
            return call.url;
          }
        })();
        const allowed = (READ_TOOL_AUTH_REQUESTS[type] ?? []).some((a) => a.method === call.method && a.path.test(path));
        if (!allowed) offenders.push(`${key}: ${call.method} ${path}`);
      }
    }
    expect(offenders).toEqual([]);
  });

  it("actually exercise each HTTP/SSH connector (the harness hasn't gone blind)", () => {
    // Uptime Kuma speaks Socket.IO, which this harness doesn't fake; every other
    // connector must have at least one read tool that reached a request, or the
    // check above is passing vacuously.
    const socketOnly = new Set(["uptime-kuma"]);
    for (const c of connectors.filter((x) => !socketOnly.has(x.type))) {
      const reached = Object.entries(observed).filter(([k, cs]) => k.startsWith(`${c.type}.`) && cs.length > 0);
      expect(reached.length, `no ${c.type} read tool made a request`).toBeGreaterThan(0);
    }
  });
});
