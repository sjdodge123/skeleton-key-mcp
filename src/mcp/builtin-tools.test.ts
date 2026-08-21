import { describe, it, expect, vi } from "vitest";
import type { AppState } from "../app.js";
import type { Target } from "../connectors/types.js";
import { buildGlobalTools } from "./builtin-tools.js";
import { scanLan } from "../discovery/scan.js";
import { CredentialRequestStore } from "../web/credential-requests.js";

vi.mock("../discovery/scan.js", () => ({ scanLan: vi.fn() }));
vi.mock("../snapshots/snapshot-service.js", () => ({ formSkeleton: vi.fn() }));
import { formSkeleton } from "../snapshots/snapshot-service.js";

// buildGlobalTools only touches `app` inside each tool's run() closure, so we can
// enumerate the declared tools (names/tiers/flags) without a real AppState.
const tools = buildGlobalTools({} as AppState);
const byName = new Map(tools.map((t) => [t.name, t]));

describe("global tool registry", () => {
  it("registers the credential-lifecycle tools", () => {
    for (const name of ["update_target", "vault_delete_credential", "request_credential", "credential_request_status"]) {
      expect(byName.has(name)).toBe(true);
    }
  });

  it("marks state-changing tools as execute and read-only ones as read", () => {
    expect(byName.get("request_credential")!.tier).toBe("execute");
    expect(byName.get("update_target")!.tier).toBe("execute");
    expect(byName.get("vault_delete_credential")!.tier).toBe("execute");
    expect(byName.get("credential_request_status")!.tier).toBe("read");
  });

  it("only exposes get_started while the vault is locked", () => {
    const lockedTools = tools.filter((t) => t.availableWhenLocked).map((t) => t.name);
    expect(lockedTools).toEqual(["get_started"]);
  });

  it("registers form_skeleton as an execute tool with a confirm, not available while locked", () => {
    const t = byName.get("form_skeleton")!;
    expect(t).toBeDefined();
    expect(t.tier).toBe("execute");
    expect(typeof t.confirm).toBe("function");
    expect(t.availableWhenLocked).toBeFalsy();
  });
});

describe("request_credential input schema", () => {
  const schema = byName.get("request_credential")!.inputSchema;
  const base = { name: "sxm-bot", host: "fly-app", reason: "migrate off fly.io" };
  const field = { name: "DISCORD_BOT_TOKEN" };

  const parse = (input: unknown): { success: boolean; data?: any } => schema.safeParse(input) as { success: boolean; data?: any };

  it("accepts the single-secret mode unchanged (backward compatible)", () => {
    const parsed = parse({ ...base, kind: "password", username: "root" });
    expect(parsed.success).toBe(true);
    expect(parsed.data.fields).toBeUndefined();
  });

  it("accepts a multi-field set, keeping an explicit secret:false", () => {
    const parsed = parse({
      ...base,
      fields: [field, { name: "SXM_USERNAME", secret: false, label: "SiriusXM login" }],
    });
    expect(parsed.success).toBe(true);
    expect(parsed.data.fields.map((f: { name: string }) => f.name)).toEqual(["DISCORD_BOT_TOKEN", "SXM_USERNAME"]);
    expect(parsed.data.fields[1].secret).toBe(false);
  });

  it("rejects field names that aren't env-var style", () => {
    for (const bad of ["1LEADING_DIGIT", "has-dash", "has.dot", "has space", "", "_leading"]) {
      expect(schema.safeParse({ ...base, fields: [{ name: bad }] }).success).toBe(false);
    }
  });

  it("rejects duplicate field names, an empty set, and more than 10 fields", () => {
    expect(schema.safeParse({ ...base, fields: [field, field] }).success).toBe(false);
    expect(schema.safeParse({ ...base, fields: [] }).success).toBe(false);
    const many = Array.from({ length: 11 }, (_, i) => ({ name: `F${i}` }));
    expect(schema.safeParse({ ...base, fields: many }).success).toBe(false);
  });

  it("requires exactly one mode — never both, never neither", () => {
    expect(schema.safeParse({ ...base, kind: "token", fields: [field] }).success).toBe(false);
    expect(schema.safeParse(base).success).toBe(false);
  });

  it("names the requested fields in the approval confirmation", () => {
    const confirm = byName.get("request_credential")!.confirm!;
    expect(confirm({ ...base, fields: [field] })).toContain("DISCORD_BOT_TOKEN");
    expect(confirm({ ...base, kind: "token" })).toContain("sxm-bot");
  });

  it("records the field set on the request and reports the names (only) once fulfilled", async () => {
    const requests = new CredentialRequestStore();
    const fakeApp = {
      vault: { listItemNames: async () => [] },
      credentialRequests: requests,
      publicUrl: () => "http://192.168.0.9:8787",
    } as unknown as AppState;

    const out = await byName.get("request_credential")!.run(
      { ...base, fields: [field, { name: "SXM_USERNAME", secret: false }] },
      fakeApp,
    );
    // The link always comes from the configured public URL (anti-phishing).
    expect(out.text).toContain("http://192.168.0.9:8787/credential/");
    const id = out.text.match(/\/credential\/([0-9a-f-]{36})/)![1]!;
    expect(requests.get(id)!.fields).toEqual([
      { name: "DISCORD_BOT_TOKEN", label: undefined, secret: true }, // secret defaults to true
      { name: "SXM_USERNAME", label: undefined, secret: false },
    ]);

    const status = byName.get("credential_request_status")!;
    expect((await status.run({ id }, fakeApp)).text).toContain("pending");
    requests.claim(id);
    const fulfilled = (await status.run({ id }, fakeApp)).text;
    expect(fulfilled).toContain("fulfilled");
    expect(fulfilled).toContain("DISCORD_BOT_TOKEN");
    expect(fulfilled).toContain("SXM_USERNAME");
    expect(fulfilled).toContain("credentialRef 'sxm-bot'");
  });
});

describe("network_scan gateway-first recommendation", () => {
  const scan = byName.get("network_scan")!;

  it("recommends registering a confirmed gateway first (it names the other devices)", async () => {
    vi.mocked(scanLan).mockResolvedValue([
      { host: "192.168.0.1", port: 443, connectorType: "unifi", label: "UniFi", confidence: "confirmed" },
      { host: "192.168.0.50", port: 22, connectorType: "ssh", label: "SSH host", confidence: "confirmed" },
    ] as Awaited<ReturnType<typeof scanLan>>);
    const out = (await scan.run({}, {} as AppState)).text;
    expect(out).toContain("Recommended first target");
    expect(out).toContain("192.168.0.1");
  });

  it("stays quiet when no gateway is confidently detected", async () => {
    vi.mocked(scanLan).mockResolvedValue([
      { host: "192.168.0.50", port: 22, connectorType: "ssh", label: "SSH host", confidence: "confirmed" },
      { host: "192.168.0.7", port: 8443, connectorType: "unifi", label: "UniFi", confidence: "likely" },
    ] as Awaited<ReturnType<typeof scanLan>>);
    const out = (await scan.run({}, {} as AppState)).text;
    expect(out).not.toContain("Recommended first target");
  });
});

describe("form_skeleton (background job) + skeleton_status", () => {
  const form = byName.get("form_skeleton")!;
  const status = byName.get("skeleton_status")!;

  function fakeApp(): AppState {
    return {
      registry: { list: () => [{ name: "a", type: "ssh", host: "h" }, { name: "b", type: "ssh", host: "h" }] },
      audit: { record: () => {} },
    } as unknown as AppState;
  }

  /** formSkeleton stand-in whose completion the test controls; records progress callbacks. */
  function controlled() {
    let resolve!: (v: { id: string; summary: string }) => void;
    let onProgress: ((p: any) => void) | undefined;
    vi.mocked(formSkeleton).mockImplementation((_app, _dir, _max, cb) => {
      onProgress = cb;
      return new Promise((res) => {
        resolve = res;
      });
    });
    return { finish: (v: { id: string; summary: string }) => resolve(v), progress: (p: any) => onProgress?.(p) };
  }

  it("registers skeleton_status as a read tool, not available while locked", () => {
    expect(status.tier).toBe("read");
    expect(status.availableWhenLocked).toBeFalsy();
    expect(form.inputSchema.parse({}).waitSeconds).toBe(0);
    expect(() => form.inputSchema.parse({ waitSeconds: 91 })).toThrow();
  });

  it("returns immediately with a job id; skeleton_status reports progress, then the summary once done", async () => {
    vi.mocked(formSkeleton).mockClear();
    const app = fakeApp();
    const c = controlled();
    const started = await form.run({ waitSeconds: 0 }, app);
    expect(started.isError).toBeFalsy();
    const id = started.text.match(/job-[0-9a-f]{12}/)![0];
    expect(started.text).toContain("Poll skeleton_status");

    c.progress({ targetsDone: 1, targetsTotal: 2, currentTarget: "b" });
    const mid = await status.run({ id }, app);
    expect(mid.text).toContain("running");
    expect(mid.text).toContain("1/2");
    expect(mid.text).toContain("currently: b");

    c.finish({ id: "skel-123", summary: "2 artifact(s) from 2 target(s)" });
    await new Promise((r) => setImmediate(r));
    const done = await status.run({}, app); // omitted id → most recent job
    expect(done.isError).toBeFalsy();
    expect(done.text).toContain("done");
    expect(done.text).toContain("Formed skeleton skel-123");
    expect(done.text).toContain("2 artifact(s) from 2 target(s)");
    expect(vi.mocked(formSkeleton)).toHaveBeenCalledTimes(1);
  });

  it("dedupes: a second form_skeleton while one runs returns the same job and starts NO second snapshot", async () => {
    vi.mocked(formSkeleton).mockClear();
    const app = fakeApp();
    const c = controlled();
    const first = await form.run({ waitSeconds: 0 }, app);
    const id = first.text.match(/job-[0-9a-f]{12}/)![0];
    const second = await form.run({ waitSeconds: 0 }, app);
    expect(second.text).toContain("ALREADY running");
    expect(second.text).toContain(id);
    expect(vi.mocked(formSkeleton)).toHaveBeenCalledTimes(1);
    c.finish({ id: "s", summary: "" });
    await new Promise((r) => setImmediate(r));
  });

  it("waitSeconds returns the finished summary inline when the job completes in time", async () => {
    const app = fakeApp();
    const c = controlled();
    setTimeout(() => c.finish({ id: "skel-fast", summary: "1 artifact(s)" }), 10);
    const out = await form.run({ waitSeconds: 5 }, app);
    expect(out.isError).toBeFalsy();
    expect(out.text).toContain("Formed skeleton skel-fast");
    expect(out.text).toContain("1 artifact(s)");
  });

  it("surfaces a failed job as an error from skeleton_status", async () => {
    const app = fakeApp();
    vi.mocked(formSkeleton).mockRejectedValue(new Error("snapshot key unavailable"));
    await form.run({ waitSeconds: 0 }, app);
    await new Promise((r) => setImmediate(r));
    const out = await status.run({}, app);
    expect(out.isError).toBe(true);
    expect(out.text).toContain("snapshot key unavailable");
  });

  it("skeleton_status with no job yet says so", async () => {
    const out = await status.run({}, fakeApp());
    expect(out.isError).toBe(true);
    expect(out.text).toContain("No skeleton job");
  });
});

describe("credentialId pinning across register / update / delete / list", () => {
  const ID = "11111111-2222-3333-4444-555555555555";
  const KEY_ID = "22222222-2222-3333-4444-555555555555";

  /** Fake app over a mutable target list with a name→id vault. */
  function fakeApp(targets: Target[], idsByName: Record<string, string>) {
    const deleted: string[] = [];
    const app = {
      registry: {
        list: () => targets,
        get: (n: string) => targets.find((t) => t.name === n),
        upsert: async (t: Target) => {
          const i = targets.findIndex((x) => x.name === t.name);
          if (i >= 0) targets[i] = t;
          else targets.push(t);
        },
      },
      vault: {
        resolveRef: async (ref: string) => {
          const hit = Object.entries(idsByName).find(([n, id]) => n === ref || id === ref);
          if (!hit) throw new Error(`No vault item named "${ref}"`);
          return { id: hit[1], name: hit[0] };
        },
        deleteItem: async (ref: string) => {
          deleted.push(ref);
          return { name: ref };
        },
      },
      emitToolsChanged: () => {},
    } as unknown as AppState;
    return { app, deleted };
  }

  it("register_target pins the resolved item id next to the name", async () => {
    const targets: Target[] = [];
    const { app } = fakeApp(targets, { "pihole-pw": ID });
    const out = await byName.get("register_target")!.run({ name: "pihole", type: "ssh", host: "10.0.0.2", credentialRef: "pihole-pw" }, app);
    expect(out.isError).toBeFalsy();
    expect(targets[0]).toMatchObject({ name: "pihole", credentialRef: "pihole-pw", credentialId: ID });
  });

  it("register_target refuses a credentialRef that doesn't resolve (nothing persisted)", async () => {
    const targets: Target[] = [];
    const { app } = fakeApp(targets, {});
    const out = await byName.get("register_target")!.run({ name: "pihole", type: "ssh", host: "10.0.0.2", credentialRef: "typo" }, app);
    expect(out.isError).toBe(true);
    expect(out.text).toContain("typo");
    expect(targets).toHaveLength(0);
  });

  it("update_target re-pins to the new ref's id, and keeps the pin when only host/options change", async () => {
    const targets: Target[] = [{ name: "pihole", type: "ssh", host: "10.0.0.2", credentialRef: "pihole-pw", credentialId: ID }];
    const { app } = fakeApp(targets, { "pihole-pw": ID, "pihole-ssh": KEY_ID });
    const update = byName.get("update_target")!;
    expect((await update.run({ name: "pihole", host: "10.0.0.3" }, app)).isError).toBeFalsy();
    expect(targets[0]).toMatchObject({ host: "10.0.0.3", credentialRef: "pihole-pw", credentialId: ID });
    expect((await update.run({ name: "pihole", credentialRef: "pihole-ssh" }, app)).isError).toBeFalsy();
    expect(targets[0]).toMatchObject({ credentialRef: "pihole-ssh", credentialId: KEY_ID });
  });

  it("vault_delete_credential treats a target pinned to the item's id as a dependent", async () => {
    // The target's NAME ref no longer resolves to this item (it was renamed),
    // but its pinned id still does — deleting would break it.
    const targets: Target[] = [{ name: "pihole", type: "ssh", host: "10.0.0.2", credentialRef: "old-name", credentialId: ID }];
    const { app, deleted } = fakeApp(targets, { "renamed-item": ID });
    const out = await byName.get("vault_delete_credential")!.run({ credentialRef: "renamed-item" }, app);
    expect(out.isError).toBe(true);
    expect(out.text).toContain("pihole");
    expect(deleted).toHaveLength(0);
  });

  it("list_targets shows the name with a short id suffix", async () => {
    const targets: Target[] = [{ name: "pihole", type: "ssh", host: "10.0.0.2", credentialRef: "pihole-pw", credentialId: ID }];
    const { app } = fakeApp(targets, {});
    const out = (await byName.get("list_targets")!.run({}, app)).text;
    expect(out).toContain("[cred: pihole-pw · id 11111111…]");
    expect(out).not.toContain(ID);
  });
});

describe("request_credential — validation / verify / overwrite / ttl schema", () => {
  const tool = byName.get("request_credential")!;
  const schema = tool.inputSchema;
  const base = { name: "coworker-bot", host: "discord", reason: "migrate" };
  const ok = (input: unknown) => expect(schema.safeParse(input).success).toBe(true);
  const bad = (input: unknown, msg?: RegExp) => {
    const r = schema.safeParse(input);
    expect(r.success).toBe(false);
    if (msg && !r.success) expect(JSON.stringify(r.error.issues)).toMatch(msg);
  };

  it("accepts per-field pattern/minLength/maxLength/hint and top-level ones in single-secret mode", () => {
    ok({ ...base, fields: [{ name: "DISCORD_BOT_TOKEN", pattern: "[\\w-]+\\.[\\w-]+\\.[\\w-]+", minLength: 50, maxLength: 100, hint: "Bot → Reset Token" }] });
    ok({ ...base, kind: "token", pattern: "\\d+", minLength: 3, hint: "digits" });
  });

  it("rejects a pattern that doesn't compile, lengths out of range, and min > max", () => {
    bad({ ...base, kind: "token", pattern: "(" }, /valid regular expression/);
    bad({ ...base, kind: "token", pattern: "x".repeat(201) });
    bad({ ...base, kind: "token", maxLength: 5000 });
    bad({ ...base, kind: "token", minLength: 10, maxLength: 5 }, /minLength must not exceed/);
    bad({ ...base, fields: [{ name: "A", minLength: 10, maxLength: 5 }] }, /minLength must not exceed/);
  });

  it("rejects top-level constraints when fields are used", () => {
    bad({ ...base, fields: [{ name: "A" }], pattern: "x" }, /put them on each entry/);
  });

  it("accepts a verify spec with https / LAN http and known placeholders; rejects the rest", () => {
    ok({ ...base, kind: "token", verify: { url: "https://discord.com/api/v10/users/@me", headers: { Authorization: "Bot {{value}}" } } });
    ok({ ...base, kind: "token", verify: { method: "POST", url: "http://192.168.1.10:8123/api/", expectStatus: [200, 401], timeoutMs: 3000 } });
    ok({ ...base, fields: [{ name: "TOKEN" }], verify: { url: "https://x.example/me", headers: { Authorization: "Bearer {{TOKEN}}" } } });
    bad({ ...base, kind: "token", verify: { url: "http://discord.com/api" } }, /https/);
    bad({ ...base, kind: "token", verify: { url: "https://x.example/", headers: { A: "{{TOKEN}}" } } }, /Unknown placeholder/);
    bad({ ...base, fields: [{ name: "TOKEN" }], verify: { url: "https://x.example/", headers: { A: "{{value}}" } } }, /Unknown placeholder/);
    bad({ ...base, kind: "token", verify: { url: "https://x.example/", timeoutMs: 60_000 } });
  });

  it("accepts overwrite and a ttlMinutes within [5, 240]", () => {
    ok({ ...base, kind: "token", overwrite: true, ttlMinutes: 5 });
    ok({ ...base, kind: "token", ttlMinutes: 240 });
    bad({ ...base, kind: "token", ttlMinutes: 4 });
    bad({ ...base, kind: "token", ttlMinutes: 241 });
  });

  it("confirm text names the verify host and says overwrite REPLACES the existing item", () => {
    const text = tool.confirm!({
      ...base,
      kind: "token",
      overwrite: true,
      verify: { method: "GET", url: "https://discord.com/api/v10/users/@me" },
    });
    expect(text).toContain("REPLACES the values of existing vault item 'coworker-bot'");
    expect(text).toContain("SENT to discord.com");
  });
});

describe("request_credential — run()", () => {
  function stubApp(existing: string[], publicUrl: string | null = "https://sk.lan:8787") {
    const store = new CredentialRequestStore();
    return {
      app: { vault: { listItemNames: async () => existing }, credentialRequests: store, publicUrl: () => publicUrl } as unknown as AppState,
      store,
    };
  }
  const tool = byName.get("request_credential")!;
  const parse = (input: unknown) => tool.inputSchema.parse(input);

  it("refuses a duplicate name without overwrite, and requires an existing item with overwrite", async () => {
    const dup = await tool.run(parse({ name: "bot", host: "d", reason: "r", kind: "token" }), stubApp(["bot"]).app);
    expect(dup.isError).toBe(true);
    expect(dup.text).toContain("overwrite: true");
    const missing = await tool.run(parse({ name: "bot", host: "d", reason: "r", kind: "token", overwrite: true }), stubApp([]).app);
    expect(missing.isError).toBe(true);
    expect(missing.text).toContain("no vault item named 'bot'");
  });

  it("creates an overwrite request for an existing item and says so", async () => {
    const { app, store } = stubApp(["bot"]);
    const out = await tool.run(parse({ name: "bot", host: "d", reason: "r", kind: "token", overwrite: true }), app);
    expect(out.isError).toBeFalsy();
    expect(out.text).toContain("REPLACES the listed values on the existing vault item 'bot'");
    expect(store.list()[0]!.overwrite).toBe(true);
  });

  it("honors ttlMinutes, states the actual expiry, and points at /admin/credentials as a fallback", async () => {
    const { app, store } = stubApp([]);
    const out = await tool.run(parse({ name: "bot", host: "d", reason: "r", kind: "token", ttlMinutes: 90 }), app);
    const req = store.list()[0]!;
    expect(req.expiresAt - req.createdAt).toBe(90 * 60 * 1000);
    expect(out.text).toContain("expires in 90 minutes");
    expect(out.text).toContain(new Date(req.expiresAt).toISOString());
    expect(out.text).toContain("https://sk.lan:8787/admin/credentials");
    expect(out.text).toContain(`https://sk.lan:8787/credential/${req.id}`);
  });

  it("relays hints/constraints and the verify host in the result, and stores them on the request", async () => {
    const { app, store } = stubApp([]);
    const out = await tool.run(
      parse({
        name: "bot",
        host: "discord",
        reason: "r",
        fields: [{ name: "DISCORD_BOT_TOKEN", pattern: "[\\w-]+\\.[\\w-]+\\.[\\w-]+", minLength: 50, hint: "Bot → Reset Token, NOT the Client Secret" }],
        verify: { url: "https://discord.com/api/v10/users/@me", headers: { Authorization: "Bot {{DISCORD_BOT_TOKEN}}" } },
      }),
      app,
    );
    expect(out.text).toContain("DISCORD_BOT_TOKEN: Bot → Reset Token, NOT the Client Secret");
    expect(out.text).toContain("test the value(s) against discord.com");
    const req = app.credentialRequests.get(store.list()[0]!.id)!;
    expect(req.fields![0]).toMatchObject({ pattern: "[\\w-]+\\.[\\w-]+\\.[\\w-]+", minLength: 50, hint: "Bot → Reset Token, NOT the Client Secret", secret: true });
    expect(req.verify).toMatchObject({ method: "GET", url: "https://discord.com/api/v10/users/@me" });
  });

  it("credential_request_status reports the verification outcome and fingerprints once fulfilled", async () => {
    const { app, store } = stubApp([]);
    const status = byName.get("credential_request_status")!;
    await tool.run(parse({ name: "bot", host: "d", reason: "r", kind: "token", verify: { url: "https://discord.com/api/v10/users/@me" } }), app);
    const id = store.list()[0]!.id;
    expect((await status.run({ id }, app)).text).toContain("/admin/credentials");
    store.claim(id);
    store.complete(id, { verification: "failed", fingerprints: { token: "len=72 fp=ab12cd34" } });
    const out = (await status.run({ id }, app)).text;
    expect(out).toContain("FAILED against discord.com");
    expect(out).toContain("token: len=72 fp=ab12cd34");
  });
});
