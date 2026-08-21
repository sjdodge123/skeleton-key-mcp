import { describe, it, expect } from "vitest";
import { fingerprintWith } from "./fingerprint.js";

describe("fingerprintWith", () => {
  const key = Buffer.alloc(32, 7);
  it("reports the byte length and an 8-hex keyed prefix", () => {
    expect(fingerprintWith(key, "abc")).toMatch(/^len=3 fp=[0-9a-f]{8}$/);
  });
  it("is deterministic under one key and differs across keys (not an offline-verifiable hash)", () => {
    const a = fingerprintWith(key, "MTUwNzE5.abc.def");
    expect(fingerprintWith(key, "MTUwNzE5.abc.def")).toBe(a);
    expect(fingerprintWith(Buffer.alloc(32, 8), "MTUwNzE5.abc.def")).not.toBe(a);
  });
  it("distinguishes a 32-char client secret from a ~70-char bot token by length alone", () => {
    expect(fingerprintWith(key, "x".repeat(32))).toMatch(/^len=32 /);
    expect(fingerprintWith(key, "y".repeat(70))).toMatch(/^len=70 /);
  });
  it("counts UTF-8 bytes, not code points", () => {
    expect(fingerprintWith(key, "é")).toMatch(/^len=2 /);
  });
});
