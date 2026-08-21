import { describe, it, expect, afterEach, vi } from "vitest";
import { CredentialRequestStore, REQUEST_TTL_MS, defaultTtlMinutes } from "./credential-requests.js";

/** A store with a controllable clock so TTL/eviction are deterministic. */
function storeAt(start = 1_000_000): { store: CredentialRequestStore; tick: (ms: number) => void } {
  let now = start;
  const store = new CredentialRequestStore(() => now);
  return { store, tick: (ms: number) => (now += ms) };
}

const sample = { name: "nas1", host: "192.168.0.50", kind: "password" as const, reason: "onboard nas1" };

describe("CredentialRequestStore", () => {
  it("creates a pending request with a unique id and a form (CSRF) token", () => {
    const { store } = storeAt();
    const a = store.create(sample);
    const b = store.create(sample);
    expect(a.status).toBe("pending");
    expect(a.id).not.toBe(b.id);
    expect(a.formToken).toBeTruthy();
    expect(a.formToken).not.toBe(b.formToken);
  });

  it("claims a pending request exactly once (single-use)", () => {
    const { store } = storeAt();
    const req = store.create(sample);
    expect(store.claim(req.id)).toBe(true);
    expect(store.get(req.id)!.status).toBe("fulfilled");
    expect(store.get(req.id)!.fulfilledName).toBe("nas1");
    // Second concurrent claim is rejected — the link can't be double-written.
    expect(store.claim(req.id)).toBe(false);
  });

  it("release() reverts a claim so the user can retry after a failed write", () => {
    const { store } = storeAt();
    const req = store.create(sample);
    expect(store.claim(req.id)).toBe(true);
    expect(store.release(req.id)).toBe(true);
    expect(store.get(req.id)!.status).toBe("pending");
    expect(store.get(req.id)!.fulfilledName).toBeUndefined();
    // Now claimable again.
    expect(store.claim(req.id)).toBe(true);
    // release only reverts a fulfilled request, not a pending one.
    expect(store.release("nope")).toBe(false);
  });

  it("cannot claim a declined request", () => {
    const { store } = storeAt();
    const req = store.create(sample);
    expect(store.decline(req.id)).toBe(true);
    expect(store.claim(req.id)).toBe(false);
    expect(store.get(req.id)!.status).toBe("declined");
  });

  it("expires a pending request past its TTL and refuses to claim it", () => {
    const { store, tick } = storeAt();
    const req = store.create(sample);
    tick(REQUEST_TTL_MS + 1);
    expect(store.get(req.id)!.status).toBe("expired");
    expect(store.claim(req.id)).toBe(false);
  });

  it("does not expire a request that was claimed before the TTL", () => {
    const { store, tick } = storeAt();
    const req = store.create(sample);
    store.claim(req.id);
    tick(REQUEST_TTL_MS + 1);
    expect(store.get(req.id)!.status).toBe("fulfilled");
  });

  it("returns undefined for an unknown id", () => {
    const { store } = storeAt();
    expect(store.get("nope")).toBeUndefined();
  });

  it("round-trips multi-field metadata (names/labels/secret flags) and drops `kind`", () => {
    const { store } = storeAt();
    const fields = [
      { name: "DISCORD_BOT_TOKEN", label: "From the developer portal", secret: true },
      { name: "SXM_USERNAME", secret: false },
    ];
    const req = store.create({ name: "sxm-bot", host: "fly-app", fields, reason: "migrate off fly.io" });
    expect(store.get(req.id)!.fields).toEqual(fields);
    // Multi-field replaces the single-value mode rather than coexisting with it.
    expect(store.get(req.id)!.kind).toBeUndefined();
    // The stored metadata is a copy — mutating the caller's array can't change
    // what the form renders or writes.
    fields[0]!.name = "TAMPERED";
    expect(store.get(req.id)!.fields![0]!.name).toBe("DISCORD_BOT_TOKEN");
  });

  it("keeps single-secret mode intact when no fields are given", () => {
    const { store } = storeAt();
    const req = store.create(sample);
    expect(store.get(req.id)!.kind).toBe("password");
    expect(store.get(req.id)!.fields).toBeUndefined();
  });
});

describe("CredentialRequestStore — per-request TTL", () => {
  afterEach(() => vi.unstubAllEnvs());

  it("defaults to 30 minutes and records expiresAt", () => {
    const { store } = storeAt(1_000);
    const req = store.create(sample);
    expect(req.ttlMs).toBe(30 * 60 * 1000);
    expect(req.expiresAt).toBe(1_000 + 30 * 60 * 1000);
  });

  it("honors ttlMinutes per request and clamps it to [5, 240]", () => {
    const { store, tick } = storeAt();
    const short = store.create({ ...sample, ttlMinutes: 5 });
    const long = store.create({ ...sample, ttlMinutes: 120 });
    expect(store.create({ ...sample, ttlMinutes: 1 }).ttlMs).toBe(5 * 60 * 1000);
    expect(store.create({ ...sample, ttlMinutes: 10_000 }).ttlMs).toBe(240 * 60 * 1000);
    tick(6 * 60 * 1000);
    expect(store.get(short.id)!.status).toBe("expired");
    expect(store.get(long.id)!.status).toBe("pending");
    tick(115 * 60 * 1000);
    expect(store.get(long.id)!.status).toBe("expired");
  });

  it("reads the default from SKELETON_KEY_CREDENTIAL_TTL_MINUTES (clamped)", () => {
    vi.stubEnv("SKELETON_KEY_CREDENTIAL_TTL_MINUTES", "60");
    expect(defaultTtlMinutes()).toBe(60);
    expect(storeAt().store.create(sample).ttlMs).toBe(60 * 60 * 1000);
    vi.stubEnv("SKELETON_KEY_CREDENTIAL_TTL_MINUTES", "2");
    expect(defaultTtlMinutes()).toBe(5);
    vi.stubEnv("SKELETON_KEY_CREDENTIAL_TTL_MINUTES", "garbage");
    expect(defaultTtlMinutes()).toBe(30);
  });
});

describe("CredentialRequestStore — list() and complete()", () => {
  it("lists only pending, unexpired requests as metadata (no formToken, no values)", () => {
    const { store, tick } = storeAt();
    const a = store.create({ ...sample, ttlMinutes: 5 });
    const b = store.create({
      name: "bot",
      host: "discord",
      fields: [{ name: "DISCORD_BOT_TOKEN", secret: true }],
      reason: "migrate",
      overwrite: true,
      verify: { method: "GET", url: "https://discord.com/api/v10/users/@me" },
    });
    const c = store.create(sample);
    store.decline(c.id);
    tick(6 * 60 * 1000); // a expires
    const list = store.list();
    expect(list.map((r) => r.id)).toEqual([b.id]);
    expect(list[0]).toMatchObject({ name: "bot", host: "discord", fields: ["DISCORD_BOT_TOKEN"], overwrite: true, verifyHost: "discord.com" });
    expect(JSON.stringify(list)).not.toContain(b.formToken);
    expect(store.list().find((r) => r.id === a.id)).toBeUndefined();
  });

  it("complete() attaches verification + fingerprints to a claimed request, and release() clears them", () => {
    const { store } = storeAt();
    const req = store.create(sample);
    expect(store.complete(req.id, { verification: "passed", fingerprints: {} })).toBe(false); // not yet claimed
    store.claim(req.id);
    expect(store.complete(req.id, { verification: "passed", fingerprints: { password: "len=7 fp=deadbeef" } })).toBe(true);
    expect(store.get(req.id)!.verification).toBe("passed");
    expect(store.get(req.id)!.fingerprints).toEqual({ password: "len=7 fp=deadbeef" });
    store.release(req.id);
    expect(store.get(req.id)!.verification).toBeUndefined();
    expect(store.get(req.id)!.fingerprints).toBeUndefined();
  });

  it("copies verify/constraints metadata so later caller mutation has no effect", () => {
    const { store } = storeAt();
    const verify = { method: "GET" as const, url: "https://api.example.com/me", headers: { Authorization: "Bearer {{value}}" } };
    const constraints = { pattern: "x+", hint: "only x" };
    const req = store.create({ ...sample, kind: "token", verify, constraints });
    verify.headers.Authorization = "TAMPERED";
    constraints.hint = "TAMPERED";
    expect(store.get(req.id)!.verify!.headers!.Authorization).toBe("Bearer {{value}}");
    expect(store.get(req.id)!.constraints!.hint).toBe("only x");
  });
});
