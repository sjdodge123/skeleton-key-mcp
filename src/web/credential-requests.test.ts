import { describe, it, expect } from "vitest";
import { CredentialRequestStore, REQUEST_TTL_MS } from "./credential-requests.js";

/** A store with a controllable clock so TTL/eviction are deterministic. */
function storeAt(start = 1_000_000): { store: CredentialRequestStore; tick: (ms: number) => void } {
  let now = start;
  const store = new CredentialRequestStore(() => now);
  return { store, tick: (ms: number) => (now += ms) };
}

const sample = { name: "nas1", host: "192.168.0.50", kind: "password" as const, reason: "onboard nas1" };

describe("CredentialRequestStore", () => {
  it("creates a pending request with a unique id", () => {
    const { store } = storeAt();
    const a = store.create(sample);
    const b = store.create(sample);
    expect(a.status).toBe("pending");
    expect(a.id).not.toBe(b.id);
  });

  it("fulfills a pending request exactly once (single-use)", () => {
    const { store } = storeAt();
    const req = store.create(sample);
    expect(store.fulfill(req.id)).toBe(true);
    expect(store.get(req.id)!.status).toBe("fulfilled");
    expect(store.get(req.id)!.fulfilledName).toBe("nas1");
    // Second attempt is rejected — the link can't be reused.
    expect(store.fulfill(req.id)).toBe(false);
  });

  it("cannot fulfill a declined request", () => {
    const { store } = storeAt();
    const req = store.create(sample);
    expect(store.decline(req.id)).toBe(true);
    expect(store.fulfill(req.id)).toBe(false);
    expect(store.get(req.id)!.status).toBe("declined");
  });

  it("expires a pending request past its TTL and refuses to fulfill it", () => {
    const { store, tick } = storeAt();
    const req = store.create(sample);
    tick(REQUEST_TTL_MS + 1);
    expect(store.get(req.id)!.status).toBe("expired");
    expect(store.fulfill(req.id)).toBe(false);
  });

  it("does not expire a request that was fulfilled before the TTL", () => {
    const { store, tick } = storeAt();
    const req = store.create(sample);
    store.fulfill(req.id);
    tick(REQUEST_TTL_MS + 1);
    expect(store.get(req.id)!.status).toBe("fulfilled");
  });

  it("returns undefined for an unknown id", () => {
    const { store } = storeAt();
    expect(store.get("nope")).toBeUndefined();
  });
});
