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
});
