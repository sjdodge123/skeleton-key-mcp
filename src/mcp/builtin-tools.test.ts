import { describe, it, expect, vi } from "vitest";
import type { AppState } from "../app.js";
import { buildGlobalTools } from "./builtin-tools.js";
import { scanLan } from "../discovery/scan.js";
import { CredentialRequestStore } from "../web/credential-requests.js";

vi.mock("../discovery/scan.js", () => ({ scanLan: vi.fn() }));

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
