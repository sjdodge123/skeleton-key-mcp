import { describe, it, expect, vi, afterEach } from "vitest";
import { proxmoxConnector, baseUrl, pveTokenFrom, upidNode, summarizeNodes, summarizeGuests, summarizeTasks } from "./proxmox.js";
import type { Credential, Target, ToolContext } from "./types.js";

function target(options: Record<string, unknown> = {}, port = 8006): Target {
  // insecureTLS:false so tlsFetch uses the (stubbable) global fetch.
  return { name: "pve", type: "proxmox", host: "10.0.0.9", port, credentialRef: "pve-token", options: { insecureTLS: false, ...options } };
}
function cred(partial: Partial<Credential>): Credential {
  return { ref: "pve-token", fields: {}, uris: [], ...partial };
}
function ctx(c: Credential, t: Target = target()): ToolContext {
  return { target: t, getCredential: async () => c };
}
function tool(name: string, t: Target = target()) {
  return proxmoxConnector.buildTools(t).find((x) => x.name === name)!;
}
function token() {
  return cred({ fields: { token_id: "root@pam!mcp", token_secret: "SECRET-UUID" } });
}

function mockFetch(routes: { match: (url: string, init: any) => boolean; reply: { status?: number; statusText?: string; json?: unknown; text?: string } }[]) {
  const calls: { url: string; init: any }[] = [];
  vi.stubGlobal(
    "fetch",
    vi.fn(async (url: string, init: any) => {
      calls.push({ url, init });
      const route = routes.find((r) => r.match(url, init));
      if (!route) throw new Error(`no mock route for ${init?.method ?? "GET"} ${url}`);
      const status = route.reply.status ?? 200;
      const body = route.reply.text ?? (route.reply.json !== undefined ? JSON.stringify(route.reply.json) : "");
      return { ok: status >= 200 && status < 300, status, statusText: route.reply.statusText ?? "OK", text: async () => body } as any;
    }),
  );
  return calls;
}

afterEach(() => vi.restoreAllMocks());

describe("pure helpers", () => {
  it("baseUrl picks https on 8006/443", () => {
    expect(baseUrl(target({}, 8006))).toBe("https://10.0.0.9:8006");
    expect(baseUrl(target({}, 443))).toBe("https://10.0.0.9:443");
    expect(baseUrl(target({ baseUrl: "https://pve.lan/" }, 8006))).toBe("https://pve.lan");
  });

  it("pveTokenFrom builds the PVEAPIToken value from fields, username, or a full token", () => {
    expect(pveTokenFrom(cred({ fields: { token_id: "root@pam!mcp", token_secret: "s" } }))).toBe("root@pam!mcp=s");
    expect(pveTokenFrom(cred({ fields: { token_id: "root@pam!mcp" }, secret: "s2" }))).toBe("root@pam!mcp=s2");
    expect(pveTokenFrom(cred({ username: "root@pam!mcp", password: "s3" }))).toBe("root@pam!mcp=s3");
    expect(pveTokenFrom(cred({ fields: { api_token: "root@pam!mcp=s4" } }))).toBe("root@pam!mcp=s4");
    // A plain user/password (no '!') is NOT a token → undefined (ticket auth path).
    expect(pveTokenFrom(cred({ username: "root@pam", password: "pw" }))).toBeUndefined();
  });

  it("upidNode extracts + validates the node, rejecting malformed UPIDs", () => {
    expect(upidNode("UPID:pve1:0000ABCD:0000:0000:vzshutdown:100:root@pam:")).toBe("pve1");
    expect(() => upidNode("not-a-upid")).toThrow(/UPID/);
    expect(() => upidNode("UPID::x")).toThrow(/node/);
    expect(() => upidNode("UPID:bad node:x")).toThrow(/node/);
  });

  it("summarizers render nodes, guests (VM+CT), and tasks", () => {
    expect(summarizeNodes([{ node: "pve1", status: "online", cpu: 0.05, mem: 2 * 1024 ** 3, maxmem: 8 * 1024 ** 3, uptime: 90000 }])).toContain(
      "pve1 [online] cpu 5% mem 2G/8G up 1d1h",
    );
    const guests = summarizeGuests([
      { vmid: 101, name: "web", node: "pve1", type: "qemu", status: "running" },
      { vmid: 100, name: "db", node: "pve1", type: "lxc", status: "stopped" },
    ]);
    expect(guests.indexOf("100 db")).toBeLessThan(guests.indexOf("101 web")); // sorted by vmid
    expect(guests).toContain("CT on pve1"); // lxc rendered as CT
    expect(guests).toContain("VM on pve1");
    expect(summarizeTasks([{ upid: "UPID:pve1:x:", type: "qmstart", user: "root@pam", endtime: 1, status: "OK" }])).toContain("qmstart [OK] by root@pam");
  });
});

describe("API-token auth", () => {
  it("list_nodes sends the PVEAPIToken header and summarizes", async () => {
    const calls = mockFetch([{ match: (u) => u.endsWith("/api2/json/nodes"), reply: { json: { data: [{ node: "pve1", status: "online", cpu: 0.1, mem: 1024, maxmem: 4096, uptime: 100 }] } } }]);
    const res = await tool("list_nodes").run({}, ctx(token()));
    expect(res.isError).toBeFalsy();
    expect(res.text).toContain("pve1 [online]");
    expect(calls[0]!.init.headers["Authorization"]).toBe("PVEAPIToken=root@pam!mcp=SECRET-UUID");
    expect("Cookie" in calls[0]!.init.headers).toBe(false);
  });

  it("list_guests filters cluster resources and marks VM vs CT", async () => {
    mockFetch([
      {
        match: (u) => u.includes("/cluster/resources"),
        reply: { json: { data: [{ vmid: 100, name: "db", node: "pve1", type: "lxc", status: "running" }, { vmid: 101, name: "web", node: "pve1", type: "qemu", status: "running" }] } },
      },
    ]);
    const res = await tool("list_guests").run({}, ctx(token()));
    expect(res.text).toContain("100 db");
    expect(res.text).toContain("101 web");
  });

  it("surfaces a non-2xx as an error", async () => {
    mockFetch([{ match: (u) => u.endsWith("/api2/json/nodes"), reply: { status: 500, statusText: "Internal Server Error", text: "boom" } }]);
    const res = await tool("list_nodes").run({}, ctx(token()));
    expect(res.isError).toBe(true);
    expect(res.text).toContain("HTTP 500");
  });
});

describe("ticket (username/password) auth", () => {
  it("logs in via /access/ticket and sends the cookie + CSRF on a mutating call", async () => {
    const calls = mockFetch([
      { match: (u, i) => u.endsWith("/access/ticket") && i.method === "POST", reply: { json: { data: { ticket: "PVE:tkt", CSRFPreventionToken: "csrf1" } } } },
      { match: (u, i) => u.includes("/cluster/resources") && (i?.method ?? "GET") === "GET", reply: { json: { data: [{ vmid: 100, name: "web", node: "pve1", type: "qemu", status: "running" }] } } },
      { match: (u, i) => u.includes("/nodes/pve1/qemu/100/status/reboot") && i.method === "POST", reply: { json: { data: "UPID:pve1:x:" } } },
    ]);
    const res = await tool("guest_power").run({ vmid: 100, action: "reboot" }, ctx(cred({ username: "root@pam", password: "pw" })));
    expect(res.isError).toBeFalsy();

    const ticket = calls.find((c) => c.url.endsWith("/access/ticket"))!;
    expect(ticket.init.headers["Content-Type"]).toBe("application/x-www-form-urlencoded");
    expect(ticket.init.body).toContain("username=root%40pam");
    expect(ticket.init.body).toContain("password=pw");

    const reboot = calls.find((c) => c.url.includes("status/reboot"))!;
    expect(reboot.init.headers["Cookie"]).toBe("PVEAuthCookie=PVE:tkt");
    expect(reboot.init.headers["CSRFPreventionToken"]).toBe("csrf1"); // CSRF only on the write
  });
});

describe("guest_power (execute)", () => {
  function mockGuest(vmid: number, type = "qemu") {
    return mockFetch([
      { match: (u, i) => u.includes("/cluster/resources") && (i?.method ?? "GET") === "GET", reply: { json: { data: [{ vmid, name: "web", node: "pve1", type, status: "running" }] } } },
      { match: (u, i) => u.includes(`/nodes/pve1/${type}/${vmid}/status/`) && i.method === "POST", reply: { json: { data: `UPID:pve1:0000:${vmid}:` } } },
    ]);
  }

  it("looks the guest up by vmid, POSTs the action to the right node/type, and reports the UPID", async () => {
    const calls = mockGuest(100, "qemu");
    const res = await tool("guest_power").run({ vmid: 100, action: "shutdown" }, ctx(token()));
    expect(res.isError).toBeFalsy();
    expect(res.text).toContain("shutdown started on VM 100 (web) on node pve1");
    expect(res.text).toContain("UPID:pve1");
    const post = calls.find((c) => c.init.method === "POST")!;
    expect(post.url).toContain("/api2/json/nodes/pve1/qemu/100/status/shutdown");
  });

  it("errors clearly when the vmid isn't in the cluster (no POST issued)", async () => {
    const calls = mockFetch([{ match: (u) => u.includes("/cluster/resources"), reply: { json: { data: [{ vmid: 100, name: "web", node: "pve1", type: "qemu" }] } } }]);
    const res = await tool("guest_power").run({ vmid: 999, action: "start" }, ctx(token()));
    expect(res.isError).toBe(true);
    expect(res.text).toContain("No VM/CT with vmid 999");
    expect(calls.some((c) => c.init.method === "POST")).toBe(false);
  });

  it("reports an action failure (non-2xx) rather than a phantom success", async () => {
    mockFetch([
      { match: (u) => u.includes("/cluster/resources"), reply: { json: { data: [{ vmid: 100, name: "web", node: "pve1", type: "qemu" }] } } },
      { match: (u, i) => u.includes("/status/stop") && i.method === "POST", reply: { status: 500, statusText: "Internal Server Error", text: "cannot stop" } },
    ]);
    const res = await tool("guest_power").run({ vmid: 100, action: "stop" }, ctx(token()));
    expect(res.isError).toBe(true);
    expect(res.text).toContain("HTTP 500");
  });

  it("confirm names the exact vmid + action and warns on a hard stop", () => {
    const c = tool("guest_power").confirm!;
    expect(c({ vmid: 100, action: "start" }, target())).toBe("Proxmox: start guest 100 on pve");
    expect(c({ vmid: 100, action: "stop" }, target())).toContain("HARD stop");
  });

  it("has the right tiers", () => {
    const tiers = Object.fromEntries(proxmoxConnector.buildTools(target()).map((t) => [t.name, t.tier]));
    expect(tiers).toEqual({
      list_nodes: "read",
      list_guests: "read",
      node_status: "read",
      guest_status: "read",
      list_tasks: "read",
      task_log: "read",
      guest_power: "execute",
    });
  });
});

describe("status + tasks reads", () => {
  it("guest_status renders one guest's current state", async () => {
    mockFetch([
      { match: (u) => u.includes("/cluster/resources"), reply: { json: { data: [{ vmid: 100, name: "web", node: "pve1", type: "qemu" }] } } },
      { match: (u) => u.includes("/nodes/pve1/qemu/100/status/current"), reply: { json: { data: { status: "running", cpu: 0.02, mem: 512 * 1024 ** 2, maxmem: 1024 ** 3, uptime: 3600 } } } },
    ]);
    const res = await tool("guest_status").run({ vmid: 100 }, ctx(token()));
    expect(res.text).toContain("VM 100 (web) on pve1: running");
    expect(res.text).toContain("up 1h0m");
  });

  it("node_status summarizes cpu/mem/load and defaults to the first online node", async () => {
    mockFetch([
      { match: (u) => u.endsWith("/api2/json/nodes"), reply: { json: { data: [{ node: "pve1", status: "online" }] } } },
      { match: (u) => u.includes("/nodes/pve1/status"), reply: { json: { data: { cpu: 0.25, memory: { used: 2 * 1024 ** 3, total: 8 * 1024 ** 3 }, loadavg: ["0.1", "0.2", "0.3"], uptime: 100 } } } },
    ]);
    const res = await tool("node_status").run({}, ctx(token()));
    expect(res.text).toContain("Node pve1: cpu 25%");
    expect(res.text).toContain("mem 2G/8G");
  });

  it("task_log parses the node from the UPID and concatenates lines", async () => {
    const calls = mockFetch([{ match: (u) => u.includes("/nodes/pve1/tasks/") && u.includes("/log"), reply: { json: { data: [{ n: 1, t: "line one" }, { n: 2, t: "line two" }] } } }]);
    const res = await tool("task_log").run({ upid: "UPID:pve1:0000:0000:0000:vzshutdown:100:root@pam:", limit: 200 }, ctx(token()));
    expect(res.text).toContain("line one\nline two");
    expect(calls[0]!.url).toContain("/nodes/pve1/tasks/");
  });

  it("task_log rejects a malformed UPID without a request", async () => {
    const calls = mockFetch([{ match: () => true, reply: { json: { data: [] } } }]);
    const res = await tool("task_log").run({ upid: "bogus", limit: 200 }, ctx(token()));
    expect(res.isError).toBe(true);
    expect(res.text).toContain("UPID");
    expect(calls.length).toBe(0);
  });
});

describe("request bounds", () => {
  it("a hung GET times out (no indefinite hang)", async () => {
    vi.useFakeTimers();
    try {
      vi.stubGlobal("fetch", vi.fn((_u: string, init: any) => new Promise((_r, reject) => init.signal.addEventListener("abort", () => reject(Object.assign(new Error("aborted"), { name: "AbortError" }))))));
      const p = tool("list_nodes").run({}, ctx(token()));
      await vi.advanceTimersByTimeAsync(21_000);
      const res = await p;
      expect(res.isError).toBe(true);
      expect(res.text).toContain("timed out");
      expect(res.text).not.toContain("OUTCOME UNKNOWN"); // a GET is a clean no-op
    } finally {
      vi.useRealTimers();
    }
  });

  it("a hung guest_power POST is flagged OUTCOME UNKNOWN (may have started)", async () => {
    vi.useFakeTimers();
    try {
      vi.stubGlobal(
        "fetch",
        vi.fn((url: string, init: any) => {
          if (url.includes("/cluster/resources")) {
            return Promise.resolve({ ok: true, status: 200, statusText: "OK", text: async () => JSON.stringify({ data: [{ vmid: 100, name: "web", node: "pve1", type: "qemu" }] }) } as any);
          }
          return new Promise((_r, reject) => init.signal.addEventListener("abort", () => reject(Object.assign(new Error("aborted"), { name: "AbortError" }))));
        }),
      );
      const p = tool("guest_power").run({ vmid: 100, action: "stop" }, ctx(token()));
      await vi.advanceTimersByTimeAsync(21_000);
      const res = await p;
      expect(res.isError).toBe(true);
      expect(res.text).toContain("OUTCOME UNKNOWN");
    } finally {
      vi.useRealTimers();
    }
  });
});
