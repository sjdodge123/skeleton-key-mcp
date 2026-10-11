import { describe, it, expect, beforeEach, afterEach } from "vitest";
import { mkdtemp, rm, readFile } from "node:fs/promises";
import { tmpdir } from "node:os";
import path from "node:path";
import { startFakeKuma, type FakeKuma, type FakeMonitor } from "../../test/helpers/fake-uptime-kuma.js";
import { buildUptimeKumaTools, MaintenanceStore, resolveMonitor, monitorsWithTag, uptimeKumaConnector, kumaConnectOptions } from "./uptime-kuma.js";
import { assertKumaTransportOk, monitorsForServer, normalizeMonitor, redactMonitorUrl, KumaSession, tagLabel } from "./uptime-kuma-client.js";
import type { Credential, Target, ToolContext } from "./types.js";

/** The owner's shape: game-server monitors tagged managed:pelican and named after the server. */
const MONITORS: FakeMonitor[] = [
  { id: 12, name: "Valheim", type: "port", hostname: "192.168.0.48", port: 2456, active: 1, tags: [{ name: "managed", value: "pelican" }, { name: "wing", value: "node" }] },
  { id: 13, name: "Palworld", type: "port", hostname: "192.168.0.48", port: 8211, active: 1, tags: [{ name: "managed", value: "pelican" }] },
  { id: 14, name: "node", type: "ping", hostname: "192.168.0.48", active: 1, tags: [{ name: "wing", value: "node" }] },
  { id: 15, name: "Valheim query", type: "port", hostname: "192.168.0.48", port: 2457, active: 0, tags: [{ name: "server", value: "f5eb47ac" }] },
  { id: 16, name: "Website", type: "http", url: "https://user:pw@example.com/health?token=abc", active: 1, tags: [] },
];

const BEATS = {
  12: [
    { status: 0, time: "2026-10-11T01:00:00.000Z", msg: "timeout", important: true },
    { status: 1, time: "2026-10-11T01:01:00.000Z", ping: 11, msg: "200 - OK", important: true },
    { status: 1, time: "2026-10-11T01:02:00.000Z", ping: 12, msg: "200 - OK", important: false },
  ],
};

let fake: FakeKuma;
let dir: string;
let store: MaintenanceStore;

beforeEach(async () => {
  fake = await startFakeKuma({ monitors: MONITORS, beats: BEATS });
  dir = await mkdtemp(path.join(tmpdir(), "kuma-test-"));
  store = new MaintenanceStore(path.join(dir, "handles.json"));
});
afterEach(async () => {
  await fake.close();
  await rm(dir, { recursive: true, force: true });
});

function target(options: Record<string, unknown> = {}): Target {
  return { name: "status-kuma", type: "uptime-kuma", host: "127.0.0.1", port: fake.port, credentialRef: "kuma-login", options: { baseUrl: fake.url, timeoutMs: 5000, ...options } };
}
const cred = (over: Partial<Credential> = {}): Credential => ({ ref: "kuma-login", username: "admin", password: "kuma-pass", fields: {}, uris: [], ...over });
function ctx(t: Target = target(), c: Credential = cred()): ToolContext {
  return { target: t, getCredential: async () => c };
}
function tool(name: string, t: Target = target(), s: MaintenanceStore = store) {
  return buildUptimeKumaTools(s)(t).find((x) => x.name === name)!;
}
const idx = (ev: string): number => fake.log.indexOf(ev);

describe("connector shape", () => {
  it("registers as uptime-kuma, needs a credential, and splits tiers correctly", () => {
    expect(uptimeKumaConnector.type).toBe("uptime-kuma");
    expect(uptimeKumaConnector.requiresCredential).toBe(true);
    const tiers = Object.fromEntries(uptimeKumaConnector.buildTools(target()).map((t) => [t.name, t.tier]));
    expect(tiers).toEqual({
      list_monitors: "read",
      monitor_status: "read",
      pause_monitor: "execute",
      resume_monitor: "execute",
      maintenance: "execute",
      end_maintenance: "execute",
    });
    for (const t of uptimeKumaConnector.buildTools(target())) if (t.tier === "execute") expect(t.confirm).toBeTypeOf("function");
  });

  it("builds the login from the vault item and refuses an item without one — before connecting", async () => {
    expect(kumaConnectOptions(target(), cred())).toMatchObject({ baseUrl: fake.url, username: "admin", password: "kuma-pass", insecureTLS: false, timeoutMs: 5000 });
    expect(kumaConnectOptions(target(), cred({ username: undefined, password: undefined, fields: { username: "u", password: "p" } }))).toMatchObject({ username: "u", password: "p" });
    const res = await tool("list_monitors").run({}, ctx(target(), cred({ password: undefined })));
    expect(res.isError).toBe(true);
    expect(res.text).toMatch(/needs a username AND a password/);
    expect(res.text).toMatch(/request_credential/);
    expect(fake.connections).toBe(0);
  });
});

describe("transport guard", () => {
  it("allows https anywhere, http only to LAN/loopback, and never a URL with embedded credentials", () => {
    expect(() => assertKumaTransportOk("https://status.example.com")).not.toThrow();
    expect(() => assertKumaTransportOk("http://192.168.0.50:3001")).not.toThrow();
    expect(() => assertKumaTransportOk("http://127.0.0.1:3001")).not.toThrow();
    expect(() => assertKumaTransportOk("http://status.example.com")).toThrow(/not a private LAN address/);
    expect(() => assertKumaTransportOk("https://admin:pw@status.example.com")).toThrow(/must not embed credentials/);
    expect(() => assertKumaTransportOk("ftp://192.168.0.50")).toThrow(/Unsupported/);
  });

  it("refuses to send the password over plain http to a routable host without opening a socket", async () => {
    const res = await tool("list_monitors", target({ baseUrl: "http://status.example.com" })).run({}, ctx(target({ baseUrl: "http://status.example.com" })));
    expect(res.isError).toBe(true);
    expect(res.text).toMatch(/plain http/);
    expect(fake.connections).toBe(0);
  });
});

describe("session", () => {
  it("logs in, receives the post-login monitorList push, and closes", async () => {
    const s = await KumaSession.connect({ baseUrl: fake.url, username: "admin", password: "kuma-pass", timeoutMs: 5000 });
    try {
      const list = await s.monitors();
      expect(list.map((m) => m.id)).toEqual([12, 13, 14, 15, 16]);
      expect(list[0]).toMatchObject({ id: 12, name: "Valheim", active: true, tags: [{ name: "managed", value: "pelican" }, { name: "wing", value: "node" }] });
      expect(list[3]!.active).toBe(false);
    } finally {
      s.close();
    }
    expect(fake.log).toEqual(["login"]); // the list came as a push — no getMonitorList needed
  });

  it("asks for the list explicitly when no push arrives", async () => {
    // A server that never pushes after login: emulate by connecting, then
    // clearing the pushed list via a fresh session whose grace window expires.
    const s = await KumaSession.connect({ baseUrl: fake.url, username: "admin", password: "kuma-pass", timeoutMs: 5000 });
    try {
      (s as unknown as { monitorList: unknown }).monitorList = null;
      const list = await s.monitors();
      expect(list).toHaveLength(5);
      expect(fake.log).toContain("getMonitorList");
    } finally {
      s.close();
    }
  }, 10_000);

  it("turns a wrong password into a clear error that never echoes it", async () => {
    await expect(KumaSession.connect({ baseUrl: fake.url, username: "admin", password: "wrong-pass", timeoutMs: 5000 })).rejects.toThrow(/Incorrect username or password/);
    const res = await tool("list_monitors").run({}, ctx(target(), cred({ password: "wrong-pass" })));
    expect(res.isError).toBe(true);
    expect(res.text).not.toContain("wrong-pass");
    expect(res.text).toMatch(/request_credential/);
  });

  it("errors clearly when the account has 2FA enabled, without pretending to continue", async () => {
    const twofa = await startFakeKuma({ twofa: true, monitors: MONITORS });
    try {
      const t = target({ baseUrl: twofa.url });
      const res = await tool("list_monitors", t).run({}, ctx(t));
      expect(res.isError).toBe(true);
      expect(res.text).toMatch(/two-factor authentication enabled/);
      expect(res.text).toMatch(/2FA-less accounts only/);
      expect(twofa.log).toEqual(["login"]);
    } finally {
      await twofa.close();
    }
  });

  it("reports an unreachable server as a connection error", async () => {
    const gone = await startFakeKuma();
    const url = gone.url;
    await gone.close();
    await expect(KumaSession.connect({ baseUrl: url, username: "admin", password: "kuma-pass", timeoutMs: 2000 })).rejects.toThrow(/Could not connect to Uptime Kuma|Timed out/);
  }, 10_000);
});

describe("list_monitors", () => {
  it("renders id, name, type, where, state and tags — with URL credentials and query values redacted", async () => {
    const res = await tool("list_monitors").run({}, ctx());
    expect(res.isError).toBeFalsy();
    expect(res.text).toContain("Uptime Kuma monitors on status-kuma: 5 (1 paused)");
    expect(res.text).toContain("[12] Valheim — port 192.168.0.48:2456 — ACTIVE — tags: managed:pelican, wing:node");
    expect(res.text).toContain("[15] Valheim query — port 192.168.0.48:2457 — PAUSED — tags: server:f5eb47ac");
    expect(res.text).toContain("[16] Website — http https://example.com/health?token=… — ACTIVE — tags: —");
    expect(res.text).not.toContain("user:pw");
    expect(res.text).not.toContain("token=abc");
  });

  it("filters by name or tag", async () => {
    const res = await tool("list_monitors").run({ query: "managed:pelican" }, ctx());
    expect(res.text).toContain("matching 'managed:pelican': 2 of 5");
    expect(res.text).toContain("[12] Valheim");
    expect(res.text).toContain("[13] Palworld");
    expect(res.text).not.toContain("[14] node");
  });
});

describe("monitor_status", () => {
  it("reads heartbeats via getMonitorBeats and summarises latest / last change / tally", async () => {
    const res = await tool("monitor_status").run({ monitor: "Valheim", hours: 24 }, ctx());
    expect(res.isError).toBeFalsy();
    expect(res.text).toContain("Monitor [12] 'Valheim' (port 192.168.0.48:2456) on status-kuma: ACTIVE");
    expect(res.text).toContain('Latest beat: UP at 2026-10-11T01:02:00.000Z 12ms "200 - OK"');
    expect(res.text).toContain("Last status change: UP at 2026-10-11T01:01:00.000Z");
    expect(res.text).toContain("Last 24h: 3 beats — 1 DOWN, 2 UP");
    expect(fake.log).toContain("getMonitorBeats:12:24");
  });

  it("says so when a paused monitor has no beats", async () => {
    const res = await tool("monitor_status").run({ monitor: 15, hours: 24 }, ctx());
    expect(res.text).toContain("PAUSED");
    expect(res.text).toMatch(/No heartbeats in the last 24h \(paused/);
  });
});

describe("pause_monitor / resume_monitor", () => {
  it("pauses by case-insensitive name, names the monitor in the confirm, and is a no-op when already paused", async () => {
    expect(tool("pause_monitor").confirm!({ monitor: "valheim" }, target())).toBe("PAUSE Uptime Kuma monitor 'valheim' on status-kuma — no checks or notifications until resumed");
    const res = await tool("pause_monitor").run({ monitor: "valheim" }, ctx());
    expect(res.isError).toBeFalsy();
    expect(res.text).toContain("Paused Uptime Kuma monitor [12] 'Valheim'");
    expect(fake.monitors.get(12)!.active).toBe(0);
    expect(fake.log.filter((e) => e === "pauseMonitor:12")).toHaveLength(1);

    const again = await tool("pause_monitor").run({ monitor: 12 }, ctx());
    expect(again.text).toMatch(/already paused — no change/);
    expect(fake.log.filter((e) => e === "pauseMonitor:12")).toHaveLength(1);
  });

  it("resumes by id and reports an already-active monitor as no change", async () => {
    expect(tool("resume_monitor").confirm!({ monitor: 15 }, target())).toBe("RESUME Uptime Kuma monitor #15 on status-kuma");
    const res = await tool("resume_monitor").run({ monitor: 15 }, ctx());
    expect(res.text).toContain("Resumed Uptime Kuma monitor [15] 'Valheim query'");
    expect(fake.monitors.get(15)!.active).toBe(1);
    const again = await tool("resume_monitor").run({ monitor: 15 }, ctx());
    expect(again.text).toMatch(/already active — no change/);
  });

  it("refuses an unknown or ambiguous name with guidance, touching nothing", async () => {
    const res = await tool("pause_monitor").run({ monitor: "Valhiem" }, ctx());
    expect(res.isError).toBe(true);
    expect(res.text).toMatch(/No Uptime Kuma monitor is named 'Valhiem'/);
    expect(fake.log.some((e) => e.startsWith("pauseMonitor"))).toBe(false);

    const dup = MONITORS.map((m) => normalizeMonitor({ ...m, tags: [] })!).concat([normalizeMonitor({ id: 99, name: "valheim", active: 1 })!]);
    expect(() => resolveMonitor(dup, "Valheim")).toThrow(/Several monitors are named 'Valheim' \(ids 12, 99\)/);
    expect(resolveMonitor(dup, "99").id).toBe(99); // digits fall back to an id
    expect(() => resolveMonitor(dup, "pal")).toThrow(/Closest: 'Palworld' \[13\]/);
  });
});

describe("maintenance / end_maintenance", () => {
  it("pauses the selection (names, ids and a tag), returns a handle, and end_maintenance resumes exactly what it paused", async () => {
    const confirm = tool("maintenance").confirm!({ monitors: ["Valheim", 15], tag: "wing:node", note: "mod install" }, target());
    expect(confirm).toBe("PAUSE Uptime Kuma monitors ['Valheim', #15] and every monitor tagged 'wing:node' on status-kuma as a maintenance window (mod install) — end_maintenance resumes exactly these");

    const res = await tool("maintenance").run({ monitors: ["Valheim", 15], tag: "wing:node", note: "mod install" }, ctx());
    expect(res.isError).toBeFalsy();
    const handle = /mw_[0-9a-f]{8}/.exec(res.text)?.[0];
    expect(handle).toBeDefined();
    expect(res.text).toContain("paused 2 monitors — Valheim [12], node [14]");
    expect(res.text).toContain("Left alone (already paused, not covered by this handle): Valheim query [15]");
    expect(fake.monitors.get(12)!.active).toBe(0);
    expect(fake.monitors.get(14)!.active).toBe(0);
    expect(fake.monitors.get(13)!.active).toBe(1); // not selected

    // Persisted, and visible in list_monitors.
    const onDisk = JSON.parse(await readFile(path.join(dir, "handles.json"), "utf8"));
    expect(onDisk.handles).toHaveLength(1);
    expect(onDisk.handles[0]).toMatchObject({ handle, target: "status-kuma", monitors: [{ id: 12, name: "Valheim" }, { id: 14, name: "node" }], note: "mod install" });
    const listed = await tool("list_monitors").run({}, ctx());
    expect(listed.text).toContain(`${handle} since`);
    expect(listed.text).toContain("mod install: Valheim [12], node [14]");

    // Someone resumed 'node' by hand meanwhile — reported, not re-poked.
    fake.monitors.get(14)!.active = 1;
    fake.log.length = 0;
    expect(tool("end_maintenance").confirm!({ handle }, target())).toBe(`RESUME the Uptime Kuma monitors paused by maintenance handle '${handle}' on status-kuma`);
    const end = await tool("end_maintenance").run({ handle }, ctx());
    expect(end.isError).toBeFalsy();
    expect(end.text).toContain(`Maintenance ${handle} on status-kuma ended: resumed 1 of 2 — Valheim [12]`);
    expect(end.text).toContain("Already active (resumed by someone else meanwhile): node [14]");
    expect(fake.log).toContain("resumeMonitor:12");
    expect(fake.log).not.toContain("resumeMonitor:14");
    expect(fake.log).not.toContain("resumeMonitor:15"); // was paused before us — never ours to resume
    expect(fake.monitors.get(12)!.active).toBe(1);
    expect(fake.monitors.get(15)!.active).toBe(0);

    // Idempotent.
    fake.log.length = 0;
    const twice = await tool("end_maintenance").run({ handle }, ctx());
    expect(twice.isError).toBeFalsy();
    expect(twice.text).toMatch(/already ended at .* — nothing to do/);
    expect(fake.log).toEqual([]); // no login, no resumes
  });

  it("survives a Skeleton Key restart: a fresh store instance still knows the handle", async () => {
    const res = await tool("maintenance").run({ tag: "managed:pelican" }, ctx());
    const handle = /mw_[0-9a-f]{8}/.exec(res.text)![0];
    expect(fake.monitors.get(12)!.active).toBe(0);
    expect(fake.monitors.get(13)!.active).toBe(0);
    const reborn = new MaintenanceStore(path.join(dir, "handles.json"));
    const end = await tool("end_maintenance", target(), reborn).run({ handle }, ctx());
    expect(end.isError).toBeFalsy();
    expect(end.text).toContain("resumed 2 of 2 — Valheim [12], Palworld [13]");
    expect(fake.monitors.get(12)!.active).toBe(1);
    expect(fake.monitors.get(13)!.active).toBe(1);
  });

  it("keeps the handle open when a resume fails, so the same call can be retried", async () => {
    const res = await tool("maintenance").run({ monitors: ["Valheim", "Palworld"] }, ctx());
    const handle = /mw_[0-9a-f]{8}/.exec(res.text)![0];
    fake.failResume.add(12);
    const first = await tool("end_maintenance").run({ handle }, ctx());
    expect(first.isError).toBe(true);
    expect(first.text).toContain("PARTIALLY ended: resumed 1 of 2 — Palworld [13]");
    expect(first.text).toMatch(/FAILED to resume: \[12\] Valheim: .*injected resume failure/);
    expect(first.text).toContain(`retry end_maintenance '${handle}'`);
    expect((await store.get(handle))!.endedAt).toBeUndefined();

    fake.failResume.clear();
    const second = await tool("end_maintenance").run({ handle }, ctx());
    expect(second.isError).toBeFalsy();
    expect(second.text).toContain("ended: resumed 1 of 2 — Valheim [12]");
    expect(second.text).toContain("Already active (resumed by someone else meanwhile): Palworld [13]");
    expect((await store.get(handle))!.endedAt).toBeDefined();
  });

  it("still mints a handle for what it did pause when one pause fails, and flags the failure", async () => {
    fake.failPause.add(13);
    const res = await tool("maintenance").run({ tag: "managed:pelican" }, ctx());
    expect(res.isError).toBe(true);
    const handle = /mw_[0-9a-f]{8}/.exec(res.text)![0];
    expect(res.text).toContain("paused 1 monitor — Valheim [12]");
    expect(res.text).toMatch(/FAILED to pause: \[13\] Palworld: .*injected pause failure/);
    expect((await store.get(handle))!.monitors).toEqual([{ id: 12, name: "Valheim" }]);
  });

  it("mints no handle when everything selected is already paused", async () => {
    const res = await tool("maintenance").run({ monitors: [15] }, ctx());
    expect(res.isError).toBeFalsy();
    expect(res.text).toMatch(/Nothing to pause .* Valheim query \[15\] is already paused\. No handle minted/);
    expect(await store.list()).toEqual([]);
  });

  it("explains an unknown handle, listing the open ones, and refuses another target's handle", async () => {
    const none = await tool("end_maintenance").run({ handle: "mw_deadbeef" }, ctx());
    expect(none.isError).toBe(true);
    expect(none.text).toMatch(/Unknown maintenance handle 'mw_deadbeef'\. No maintenance window is open on status-kuma/);
    expect(none.text).toMatch(/resume_monitor/);

    const res = await tool("maintenance").run({ monitors: ["Valheim"] }, ctx());
    const handle = /mw_[0-9a-f]{8}/.exec(res.text)![0];
    const other = await tool("end_maintenance").run({ handle: "mw_deadbeef" }, ctx());
    expect(other.text).toContain(`Open handles on status-kuma: ${handle} (Valheim, since`);

    const elsewhere: Target = { ...target(), name: "other-kuma" };
    const wrong = await tool("end_maintenance", elsewhere).run({ handle }, ctx(elsewhere));
    expect(wrong.isError).toBe(true);
    expect(wrong.text).toMatch(/belongs to target 'status-kuma', not 'other-kuma'/);
    expect(fake.monitors.get(12)!.active).toBe(0);
  });

  it("requires a selection and reports an unknown tag", async () => {
    const none = await tool("maintenance").run({}, ctx());
    expect(none.isError).toBe(true);
    expect(none.text).toMatch(/Name at least one monitor/);
    const tag = await tool("maintenance").run({ tag: "nope" }, ctx());
    expect(tag.isError).toBe(true);
    expect(tag.text).toMatch(/No monitor on status-kuma carries the tag 'nope'/);
  });
});

describe("matching monitors to a Pelican server (pure)", () => {
  const all = MONITORS.map((m) => normalizeMonitor({ ...m, tags: (m.tags ?? []).map((t) => ({ ...t })) })!);

  it("matches managed:pelican + same name (case-insensitive) and any tag naming the server", () => {
    const { matched, unmatchedSameName } = monitorsForServer(all, { name: "valheim", identifier: "f5eb47ac", uuid: "f5eb47ac-1111-2222-3333-444444444444" });
    expect(matched.map((m) => m.id)).toEqual([12, 15]);
    expect(unmatchedSameName).toEqual([]);
  });

  it("does not match a same-named monitor without the managed tag, but reports it", () => {
    const untagged = all.map((m) => (m.id === 12 ? { ...m, tags: [] } : m));
    const { matched, unmatchedSameName } = monitorsForServer(untagged, { name: "Valheim", identifier: "f5eb47ac" });
    expect(matched.map((m) => m.id)).toEqual([15]);
    expect(unmatchedSameName.map((m) => m.id)).toEqual([12]);
  });

  it("matches nothing for a server with no monitor, and never by a tag VALUE that merely equals the server name", () => {
    const { matched } = monitorsForServer(all, { name: "Satisfactory - Ararat", identifier: "abc12345" });
    expect(matched).toEqual([]);
    // 'wing:node' says which node a monitor is on — it must not select the
    // monitors of a server that happens to be called "node".
    const { matched: node } = monitorsForServer(all, { name: "node", identifier: "zzz" });
    expect(node).toEqual([]);
  });

  it("accepts an explicit server:<name> tag and a UUID-valued tag", () => {
    const tagged = all.map((m) => (m.id === 16 ? { ...m, tags: [{ name: "server", value: "Satisfactory - Ararat" }] } : m.id === 14 ? { ...m, tags: [{ name: "pelican", value: "F5EB47AC-1111-2222-3333-444444444444" }] } : m));
    expect(monitorsForServer(tagged, { name: "satisfactory - ararat", identifier: "abc12345" }).matched.map((m) => m.id)).toEqual([16]);
    expect(monitorsForServer(tagged, { name: "Valheim", identifier: "f5eb47ac", uuid: "f5eb47ac-1111-2222-3333-444444444444" }).matched.map((m) => m.id)).toEqual([12, 14, 15]);
  });

  it("tag selection accepts name or name:value", () => {
    expect(monitorsWithTag(all, "managed:pelican").map((m) => m.id)).toEqual([12, 13]);
    expect(monitorsWithTag(all, "wing").map((m) => m.id)).toEqual([12, 14]);
    expect(monitorsWithTag(all, "WING:NODE").map((m) => m.id)).toEqual([12, 14]);
    expect(monitorsWithTag(all, "managed").map((m) => m.id)).toEqual([12, 13]);
  });
});

describe("normalisation", () => {
  it("accepts Kuma's 0/1, boolean and string actives, and tolerates null tag values", () => {
    expect(normalizeMonitor({ id: 1, name: "a", active: 1 })!.active).toBe(true);
    expect(normalizeMonitor({ id: 1, name: "a", active: 0 })!.active).toBe(false);
    expect(normalizeMonitor({ id: 1, name: "a", active: true })!.active).toBe(true);
    expect(normalizeMonitor({ id: "7", name: "a", active: "1", tags: [{ name: "x", value: null }, { name: "", value: "" }] })).toMatchObject({ id: 7, active: true, tags: [{ name: "x", value: "" }] });
    expect(normalizeMonitor({ name: "no id" })).toBeNull();
    expect(tagLabel({ name: "managed", value: "pelican" })).toBe("managed:pelican");
    expect(tagLabel({ name: "prod", value: "" })).toBe("prod");
  });

  it("redacts monitor URL userinfo and query values", () => {
    expect(redactMonitorUrl("https://u:p@h.example/x?key=secret&b=2")).toBe("https://h.example/x?key=…&b=…");
    expect(redactMonitorUrl("https://h.example/")).toBe("https://h.example/");
    expect(redactMonitorUrl("not a url")).toBe("(unparseable url)");
    expect(redactMonitorUrl(undefined)).toBeUndefined();
  });
});
