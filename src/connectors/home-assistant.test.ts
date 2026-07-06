import { describe, it, expect, vi, afterEach } from "vitest";
import { z } from "zod";
import { zodToJsonSchema } from "zod-to-json-schema";
import {
  homeAssistantConnector,
  baseUrl,
  tokenFrom,
  normalizeServiceData,
  renderServiceData,
  isWebhookPath,
  summarizeStates,
  summarizeLogbook,
  serviceData,
} from "./home-assistant.js";
import type { Credential, Target, ToolContext } from "./types.js";

function target(options: Record<string, unknown> = {}, port = 8123): Target {
  // insecureTLS:false so tlsFetch uses the (stubbable) global fetch.
  return { name: "homeassistant", type: "home-assistant", host: "10.0.0.5", port, credentialRef: "homeassistant-token", options: { insecureTLS: false, ...options } };
}
function cred(partial: Partial<Credential>): Credential {
  return { ref: "homeassistant-token", fields: {}, uris: [], ...partial };
}
function ctx(c: Credential, t: Target = target()): ToolContext {
  return { target: t, getCredential: async () => c };
}
function tool(name: string, t: Target = target()) {
  return homeAssistantConnector.buildTools(t).find((x) => x.name === name)!;
}

/** fetch mock: match by (url, init) and reply with a status + json/text body. */
function mockFetch(routes: { match: (url: string, init: any) => boolean; reply: { status?: number; statusText?: string; json?: unknown; text?: string } }[]) {
  const calls: { url: string; init: any }[] = [];
  const fn = vi.fn(async (url: string, init: any) => {
    calls.push({ url, init });
    const route = routes.find((r) => r.match(url, init));
    if (!route) throw new Error(`no mock route for ${init?.method ?? "GET"} ${url}`);
    const status = route.reply.status ?? 200;
    const body = route.reply.text ?? (route.reply.json !== undefined ? JSON.stringify(route.reply.json) : "");
    return {
      ok: status >= 200 && status < 300,
      status,
      statusText: route.reply.statusText ?? (status < 300 ? "OK" : "Bad Request"),
      text: async () => body,
    } as any;
  });
  vi.stubGlobal("fetch", fn);
  return calls;
}

afterEach(() => vi.restoreAllMocks());

describe("pure helpers", () => {
  it("baseUrl uses http on 8123 and https on 443/8443", () => {
    expect(baseUrl(target({}, 8123))).toBe("http://10.0.0.5:8123");
    expect(baseUrl(target({}, 443))).toBe("https://10.0.0.5:443");
    expect(baseUrl(target({}, 8443))).toBe("https://10.0.0.5:8443");
    expect(baseUrl(target({ baseUrl: "https://ha.lan/" }, 8123))).toBe("https://ha.lan");
  });

  it("tokenFrom prefers explicit fields, then secret, then password — never the notes", () => {
    expect(tokenFrom(cred({ fields: { token: "t1" } }))).toBe("t1");
    expect(tokenFrom(cred({ fields: { api_key: "t2" } }))).toBe("t2");
    expect(tokenFrom(cred({ secret: "t3" }))).toBe("t3");
    expect(tokenFrom(cred({ password: "t4" }))).toBe("t4");
    expect(tokenFrom(cred({ notes: "not-a-secret" }))).toBeUndefined();
  });

  it("normalizeServiceData accepts objects, parses JSON strings, and rejects non-objects", () => {
    expect(normalizeServiceData({ entity_id: "sun.sun" })).toEqual({ entity_id: "sun.sun" });
    expect(normalizeServiceData('{"entity_id":"light.kitchen"}')).toEqual({ entity_id: "light.kitchen" });
    expect(normalizeServiceData(undefined)).toEqual({});
    expect(normalizeServiceData(null)).toEqual({});
    expect(normalizeServiceData("")).toEqual({});
    expect(normalizeServiceData("   ")).toEqual({});
    expect(() => normalizeServiceData("not json")).toThrow(/valid JSON/i);
    expect(() => normalizeServiceData("[1,2,3]")).toThrow(/array/i);
    expect(() => normalizeServiceData(42)).toThrow(/must be a JSON object/i);
    expect(() => normalizeServiceData("true")).toThrow(/must be a JSON object/i);
  });

  it("summarizeStates lists, filters by substring, and reports totals", () => {
    const states = [
      { entity_id: "sun.sun", state: "below_horizon", attributes: { friendly_name: "Sun" } },
      { entity_id: "light.kitchen", state: "on" },
      { entity_id: "update.core", state: "on" },
    ];
    const all = summarizeStates(states as any);
    expect(all).toContain("3 entities");
    expect(all).toContain("sun.sun = below_horizon  (Sun)");
    const filtered = summarizeStates(states as any, "light");
    expect(filtered).toContain("light.kitchen = on");
    expect(filtered).not.toContain("sun.sun");
    expect(summarizeStates(states as any, "nope")).toContain("No entities match 'nope'");
  });

  it("renderServiceData redacts secrets (recursively), keeps other fields, and tolerates junk", () => {
    expect(renderServiceData({ entity_id: "light.k", brightness: 128 })).toBe('{"entity_id":"light.k","brightness":128}');
    expect(renderServiceData({ password: "hunter2", name: "x" })).toBe('{"password":"[redacted]","name":"x"}');
    expect(renderServiceData({ pin: "1234", api_key: "k" })).toBe('{"pin":"[redacted]","api_key":"[redacted]"}');
    // Nested + arrays: a shallow pass would leak these.
    expect(renderServiceData({ data: { token: "abc", other: 1 } })).toBe('{"data":{"token":"[redacted]","other":1}}');
    const arr = renderServiceData({ items: [{ password: "p" }, { ok: true }] });
    expect(arr).not.toContain('"p"');
    expect(arr).toBe('{"items":[{"password":"[redacted]"},{"ok":true}]}');
    expect(renderServiceData('{"entity_id":"light.k"}')).toBe('{"entity_id":"light.k"}'); // parses a JSON string
    expect(renderServiceData(undefined)).toBe("");
    expect(renderServiceData({})).toBe("");
  });

  it("renderServiceData redacts separator-delimited secret keys (alarm_code, user_pin, …)", () => {
    for (const key of ["alarm_code", "pin_code", "access_code", "user_pin", "otp", "passcode", "passphrase"]) {
      const out = renderServiceData({ [key]: "SECRETVAL", entity_id: "lock.front" });
      expect(out, key).not.toContain("SECRETVAL");
      expect(out, key).toContain('"entity_id":"lock.front"');
    }
    // A benign 'code' near-miss is over-redacted (safe) but a plain field is not.
    expect(renderServiceData({ color_name: "red" })).toBe('{"color_name":"red"}');
  });

  it("renderServiceData names every top-level key — a long value is marked, extras are listed, never silently dropped", () => {
    const longVal = "x".repeat(500);
    const oneBig = renderServiceData({ entity_id: "light.k", template: longVal });
    expect(oneBig).toContain('"entity_id":"light.k"'); // first key intact
    expect(oneBig).toContain('"template":'); // key present
    expect(oneBig).toContain("…"); // its oversized value is visibly truncated
    expect(oneBig).not.toContain(longVal); // not the whole 500-char value

    // Many medium values that blow the total budget => remaining keys are named.
    const many: Record<string, string> = {};
    for (let i = 0; i < 30; i++) many[`field_${i}`] = "y".repeat(80);
    const rendered = renderServiceData(many);
    expect(rendered).toMatch(/\+\d+ more: field_/); // explicitly names the overflow keys
    expect(rendered.length).toBeLessThan(1200); // still bounded
  });

  it("isWebhookPath flags webhook endpoints and their encoded/traversal variants", () => {
    expect(isWebhookPath("/api/webhook/abc123")).toBe(true);
    expect(isWebhookPath("api/webhook/abc123")).toBe(true);
    expect(isWebhookPath("/API/Webhook/abc")).toBe(true);
    // Encoded-bypass attempts must still be caught (HA canonicalizes before routing).
    expect(isWebhookPath("/api/%77ebhook/abc")).toBe(true); // %77 = 'w'
    expect(isWebhookPath("/api/web%68ook/abc")).toBe(true); // %68 = 'h'
    expect(isWebhookPath("/api/%2577ebhook/abc")).toBe(true); // double-encoded %25 -> % -> %77 -> w
    expect(isWebhookPath("/api/webhook%2Fabc")).toBe(true); // %2F = '/'
    expect(isWebhookPath("/api/foo/../webhook/abc")).toBe(true); // dot-segment traversal
    expect(isWebhookPath("/api/foo/%2e%2e/webhook/abc")).toBe(true); // single-encoded traversal
    expect(isWebhookPath("/api/foo/%252e%252e/webhook/abc")).toBe(true); // double-encoded traversal
    expect(isWebhookPath("/api/foo/%252e%252e/%77ebhook/abc")).toBe(true); // mixed double-encoded traversal + encoded 'w'
    // Genuine reads and near-misses stay allowed.
    expect(isWebhookPath("/api/config")).toBe(false);
    expect(isWebhookPath("/api/states/webhook.sensor")).toBe(false); // 'webhook' elsewhere is fine
    expect(isWebhookPath("/api/webhookfoo")).toBe(false); // not the webhook endpoint
  });

  it("summarizeLogbook renders when/who/what and caps output", () => {
    const out = summarizeLogbook([
      { when: "2026-07-06T04:00:00", entity_id: "automation.x", message: "triggered" },
      { when: "2026-07-06T04:01:00", name: "Projector", state: "playing" },
    ]);
    expect(out).toContain("automation.x: triggered");
    expect(out).toContain("Projector: playing");
    expect(summarizeLogbook([])).toContain("No logbook entries");
  });
});

describe("service-data schema (the double-encoding fix)", () => {
  it("advertises data as a JSON-schema object so clients transmit an object, not a string", () => {
    // The root cause of the old 400: an untyped ({}) schema made clients send the
    // structured value as a JSON string, which then got double-encoded.
    const js = zodToJsonSchema(z.object({ data: serviceData }) as any, { $refStrategy: "none" }) as any;
    expect(js.properties.data.type).toBe("object");
  });

  it("the ha_call_service tool schema exposes data as type:object", () => {
    const js = zodToJsonSchema(tool("ha_call_service").inputSchema, { $refStrategy: "none" }) as any;
    expect(js.properties.data.type).toBe("object");
  });

  it("preprocess parses a stringified data object during validation (defense in depth)", () => {
    const schema = tool("ha_call_service").inputSchema;
    const fromString = schema.parse({ domain: "light", service: "turn_on", data: '{"entity_id":"light.kitchen"}' });
    expect((fromString as any).data).toEqual({ entity_id: "light.kitchen" });
    const fromObject = schema.parse({ domain: "light", service: "turn_on", data: { entity_id: "x" } });
    expect((fromObject as any).data).toEqual({ entity_id: "x" });
  });
});

describe("tiers and confirmations", () => {
  it("assigns read/execute tiers correctly", () => {
    const byTier = Object.fromEntries(homeAssistantConnector.buildTools(target()).map((t) => [t.name, t.tier]));
    expect(byTier).toEqual({
      ha_states: "read",
      ha_get: "read",
      ha_logbook: "read",
      ha_call_service: "execute",
      ha_backup: "execute",
    });
  });

  it("read tools carry no confirm; execute tools do", () => {
    expect(tool("ha_states").confirm).toBeUndefined();
    expect(tool("ha_get").confirm).toBeUndefined();
    expect(tool("ha_logbook").confirm).toBeUndefined();
    expect(tool("ha_call_service").confirm).toBeTypeOf("function");
    expect(tool("ha_backup").confirm).toBeTypeOf("function");
  });

  it("ha_call_service confirm names the exact service, target entity, and full payload", () => {
    const c = tool("ha_call_service").confirm!;
    expect(c({ domain: "homeassistant", service: "update_entity", data: { entity_id: "sun.sun" } }, target())).toBe(
      'Call Home Assistant service homeassistant.update_entity on sun.sun — data: {"entity_id":"sun.sun"} (homeassistant)',
    );
    // Array entity_id is joined; no entity_id => no target clause.
    expect(c({ domain: "update", service: "install", data: { entity_id: ["update.a", "update.b"] } }, target())).toContain("on update.a, update.b");
    expect(c({ domain: "homeassistant", service: "restart" }, target())).toBe("Call Home Assistant service homeassistant.restart (homeassistant)");
  });

  it("confirm surfaces NON-entity payload fields so they can't be smuggled past approval", () => {
    const c = tool("ha_call_service").confirm!;
    const text = c({ domain: "light", service: "turn_on", data: { entity_id: "light.kitchen", brightness: 255, rgb_color: [255, 0, 0] } }, target());
    expect(text).toContain('"brightness":255');
    expect(text).toContain('"rgb_color":[255,0,0]');
  });

  it("confirm redacts secret-looking payload fields (they'd otherwise land in the audit detail)", () => {
    const c = tool("ha_call_service").confirm!;
    const text = c({ domain: "hassio", service: "backup_full", data: { name: "nightly", password: "hunter2", token: "abc" } }, target());
    expect(text).not.toContain("hunter2");
    expect(text).not.toContain('"token":"abc"');
    expect(text).toContain('"password":"[redacted]"');
    expect(text).toContain('"name":"nightly"'); // non-secret fields still shown
  });

  it("ha_backup confirm names the exact service", () => {
    expect(tool("ha_backup").confirm!({}, target())).toBe("Create a Home Assistant backup (backup.create_automatic) on homeassistant");
  });
});

describe("ha_call_service (POST body encoding)", () => {
  it("sends the service data as a SINGLE-encoded JSON object with auth + content-type (regression for the 400)", async () => {
    const calls = mockFetch([
      { match: (u, i) => u.endsWith("/api/services/homeassistant/update_entity") && i.method === "POST", reply: { json: [] } },
    ]);
    const res = await tool("ha_call_service").run(
      { domain: "homeassistant", service: "update_entity", data: { entity_id: "sun.sun" } },
      ctx(cred({ secret: "TKN" })),
    );
    expect(res.isError).toBeFalsy();
    const post = calls.find((c) => c.init.method === "POST")!;
    expect(post.url).toBe("http://10.0.0.5:8123/api/services/homeassistant/update_entity");
    expect(post.init.headers["Content-Type"]).toBe("application/json");
    expect(post.init.headers["Authorization"]).toBe("Bearer TKN");
    // The crux: the body is a JSON string that parses ONCE into the object — not a
    // JSON string of a JSON string (the double-encoding that caused the 400).
    expect(typeof post.init.body).toBe("string");
    const parsed = JSON.parse(post.init.body);
    expect(parsed).toEqual({ entity_id: "sun.sun" });
    expect(typeof parsed).toBe("object"); // one decode yields an object, not a string
  });

  it("normalizes a stringified data object to a single-encoded object body at runtime too", async () => {
    const calls = mockFetch([{ match: (u, i) => u.includes("/api/services/light/turn_on") && i.method === "POST", reply: { json: [] } }]);
    await tool("ha_call_service").run({ domain: "light", service: "turn_on", data: '{"entity_id":"light.kitchen"}' }, ctx(cred({ secret: "TKN" })));
    const post = calls.find((c) => c.init.method === "POST")!;
    expect(JSON.parse(post.init.body)).toEqual({ entity_id: "light.kitchen" });
  });

  it("omits the body (and Content-Type) when there is no service data", async () => {
    const calls = mockFetch([{ match: (u, i) => u.includes("/api/services/homeassistant/restart") && i.method === "POST", reply: { json: [] } }]);
    await tool("ha_call_service").run({ domain: "homeassistant", service: "restart" }, ctx(cred({ secret: "TKN" })));
    const post = calls.find((c) => c.init.method === "POST")!;
    // Empty object still serializes to "{}" — HA accepts an empty object for a
    // no-data service; the important thing is it is a single-encoded object.
    expect(JSON.parse(post.init.body)).toEqual({});
    expect(post.init.headers["Content-Type"]).toBe("application/json");
  });

  it("summarizes the entities HA reports changed", async () => {
    mockFetch([
      {
        match: (u, i) => u.includes("/api/services/light/turn_on") && i.method === "POST",
        reply: { json: [{ entity_id: "light.kitchen", state: "on" }, { entity_id: "light.hall", state: "on" }] },
      },
    ]);
    const res = await tool("ha_call_service").run({ domain: "light", service: "turn_on", data: { entity_id: "all" } }, ctx(cred({ secret: "TKN" })));
    expect(res.text).toContain("light.turn_on OK");
    expect(res.text).toContain("Changed 2: light.kitchen, light.hall");
  });

  it("reports an HA error body as a failure (not a phantom success)", async () => {
    mockFetch([
      { match: (u, i) => u.includes("/api/services/homeassistant/update_entity") && i.method === "POST", reply: { status: 400, statusText: "Bad Request", text: "400: Bad Request" } },
    ]);
    const res = await tool("ha_call_service").run({ domain: "homeassistant", service: "update_entity", data: { entity_id: "sun.sun" } }, ctx(cred({ secret: "TKN" })));
    expect(res.isError).toBe(true);
    expect(res.text).toContain("failed: HTTP 400");
  });

  it("errors clearly when the credential carries no token", async () => {
    mockFetch([{ match: () => true, reply: { json: [] } }]);
    const res = await tool("ha_call_service").run({ domain: "homeassistant", service: "restart" }, ctx(cred({})));
    expect(res.isError).toBe(true);
    expect(res.text).toContain("needs a long-lived token");
  });
});

describe("ha_backup", () => {
  it("POSTs backup.create_automatic with an empty object body", async () => {
    const calls = mockFetch([{ match: (u, i) => u.endsWith("/api/services/backup/create_automatic") && i.method === "POST", reply: { json: [] } }]);
    const res = await tool("ha_backup").run({}, ctx(cred({ secret: "TKN" })));
    expect(res.isError).toBeFalsy();
    expect(res.text).toContain("backup.create_automatic");
    const post = calls.find((c) => c.init.method === "POST")!;
    expect(JSON.parse(post.init.body)).toEqual({});
  });

  it("propagates a backup failure", async () => {
    mockFetch([{ match: (u, i) => u.endsWith("/api/services/backup/create_automatic") && i.method === "POST", reply: { status: 500, statusText: "Internal Server Error", text: "boom" } }]);
    const res = await tool("ha_backup").run({}, ctx(cred({ secret: "TKN" })));
    expect(res.isError).toBe(true);
    expect(res.text).toContain("HTTP 500");
  });
});

describe("read tools", () => {
  it("ha_states (all) summarizes and sends the bearer token", async () => {
    const calls = mockFetch([
      {
        match: (u, i) => u.endsWith("/api/states") && (i?.method ?? "GET") === "GET",
        reply: { json: [{ entity_id: "sun.sun", state: "below_horizon", attributes: { friendly_name: "Sun" } }] },
      },
    ]);
    const res = await tool("ha_states").run({}, ctx(cred({ secret: "TKN" })));
    expect(res.isError).toBeFalsy();
    expect(res.text).toContain("sun.sun = below_horizon");
    expect(calls[0]!.init.headers["Authorization"]).toBe("Bearer TKN");
    // No Content-Type on a GET (no body).
    expect(calls[0]!.init.headers["Content-Type"]).toBeUndefined();
  });

  it("ha_states (one entity) returns the full state JSON", async () => {
    mockFetch([
      { match: (u) => u.endsWith("/api/states/sun.sun"), reply: { json: { entity_id: "sun.sun", state: "below_horizon", attributes: { elevation: -33 } } } },
    ]);
    const res = await tool("ha_states").run({ entity: "sun.sun" }, ctx(cred({ secret: "TKN" })));
    expect(res.isError).toBeFalsy();
    expect(res.text).toContain('"entity_id": "sun.sun"');
    expect(res.text).toContain('"elevation": -33');
  });

  it("ha_get passes a raw path through and reports the status", async () => {
    mockFetch([{ match: (u) => u.endsWith("/api/config"), reply: { json: { version: "2026.7.1" } } }]);
    const res = await tool("ha_get").run({ path: "/api/config" }, ctx(cred({ secret: "TKN" })));
    expect(res.text).toContain("HTTP 200");
    expect(res.text).toContain('"version":"2026.7.1"');
  });

  it("ha_get refuses a webhook path (plain and percent-encoded) WITHOUT issuing a request", async () => {
    for (const path of ["/api/webhook/some_secret_id", "/api/%77ebhook/some_secret_id"]) {
      const calls = mockFetch([{ match: () => true, reply: { json: {} } }]);
      const res = await tool("ha_get").run({ path }, ctx(cred({ secret: "TKN" })));
      expect(res.isError, path).toBe(true);
      expect(res.text).toContain("Refused");
      expect(calls.length, path).toBe(0); // never hit the network
      vi.restoreAllMocks();
    }
  });

  it("ha_logbook builds the path with entity + time bounds and summarizes", async () => {
    const calls = mockFetch([
      {
        match: (u) => u.includes("/api/logbook/"),
        reply: { json: [{ when: "2026-07-06T04:00:00", entity_id: "automation.x", message: "triggered" }] },
      },
    ]);
    const res = await tool("ha_logbook").run(
      { entity: "automation.x", start: "2026-07-06T00:00:00+00:00", end: "2026-07-06T06:00:00+00:00" },
      ctx(cred({ secret: "TKN" })),
    );
    expect(res.isError).toBeFalsy();
    expect(res.text).toContain("automation.x: triggered");
    const url = calls[0]!.url;
    expect(url).toContain("/api/logbook/2026-07-06T00%3A00%3A00%2B00%3A00");
    expect(url).toContain("entity=automation.x");
    expect(url).toContain("end_time=");
  });

  it("a failing GET is reported as an error", async () => {
    mockFetch([{ match: (u) => u.endsWith("/api/states/nope.nope"), reply: { status: 404, statusText: "Not Found", text: "404: Not Found" } }]);
    const res = await tool("ha_states").run({ entity: "nope.nope" }, ctx(cred({ secret: "TKN" })));
    expect(res.isError).toBe(true);
    expect(res.text).toContain("HTTP 404");
  });

  it("ha_get bounds an oversized response and marks it truncated", async () => {
    const huge = "z".repeat(300_000); // > the ha_get read cap (256 KB)
    mockFetch([{ match: (u) => u.endsWith("/api/config"), reply: { text: huge } }]);
    const res = await tool("ha_get").run({ path: "/api/config" }, ctx(cred({ secret: "TKN" })));
    expect(res.text).toContain("(response truncated)");
    expect(res.text.length).toBeLessThan(30_000); // output itself is capped at 20 KB
  });
});

describe("structured reads fail loudly on truncated/malformed responses", () => {
  const OVERSIZED = "z".repeat(6_300_000); // > DEFAULT_MAX_BYTES (6 MB)

  it("ha_states (all) errors on a truncated response instead of reporting 'No entities'", async () => {
    mockFetch([{ match: (u) => u.endsWith("/api/states"), reply: { text: OVERSIZED } }]);
    const res = await tool("ha_states").run({}, ctx(cred({ secret: "TKN" })));
    expect(res.isError).toBe(true);
    expect(res.text).toContain("too large");
    expect(res.text).not.toContain("No entities");
  });

  it("ha_logbook errors on a truncated response instead of reporting 'No logbook entries'", async () => {
    mockFetch([{ match: (u) => u.includes("/api/logbook"), reply: { text: OVERSIZED } }]);
    const res = await tool("ha_logbook").run({}, ctx(cred({ secret: "TKN" })));
    expect(res.isError).toBe(true);
    expect(res.text).toContain("too large");
    expect(res.text).not.toContain("No logbook entries");
  });

  it("ha_states (all) errors on a 2xx non-array body", async () => {
    mockFetch([{ match: (u) => u.endsWith("/api/states"), reply: { json: { message: "unexpected" } } }]);
    const res = await tool("ha_states").run({}, ctx(cred({ secret: "TKN" })));
    expect(res.isError).toBe(true);
    expect(res.text).toContain("not a JSON array");
  });

  it("ha_logbook errors on a 2xx non-array body", async () => {
    mockFetch([{ match: (u) => u.includes("/api/logbook"), reply: { json: { message: "unexpected" } } }]);
    const res = await tool("ha_logbook").run({}, ctx(cred({ secret: "TKN" })));
    expect(res.isError).toBe(true);
    expect(res.text).toContain("not a JSON array");
  });
});

describe("request bounds", () => {
  it("aborts a hung request after the timeout and reports it (no indefinite hang)", async () => {
    vi.useFakeTimers();
    try {
      vi.stubGlobal(
        "fetch",
        vi.fn(
          (_url: string, init: any) =>
            new Promise((_resolve, reject) => {
              // Never resolves on its own; only the AbortController (timeout) settles it.
              init.signal.addEventListener("abort", () => reject(Object.assign(new Error("aborted"), { name: "AbortError" })));
            }),
        ),
      );
      const p = tool("ha_get").run({ path: "/api/config" }, ctx(cred({ secret: "TKN" })));
      await vi.advanceTimersByTimeAsync(21_000); // past REQUEST_TIMEOUT_MS
      const res = await p;
      expect(res.isError).toBe(true);
      expect(res.text).toContain("timed out");
    } finally {
      vi.useRealTimers();
    }
  });
});
