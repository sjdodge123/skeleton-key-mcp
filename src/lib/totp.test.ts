import { describe, it, expect, beforeEach, afterEach, vi } from "vitest";
import { createHmac } from "node:crypto";
import { generateTotpCode, generateTotpSecret, totpKeyUri, verifyTotpCode } from "./totp.js";

// Characterisation tests for the admin second factor. They pin what an
// already-enrolled authenticator app depends on, checked against an
// independent RFC 4648 / RFC 6238 reference below — never against otplib
// itself — so a library upgrade that shifts any default fails here.
// Written against otplib 12.0.1 and kept unchanged across the v13 migration.

const BASE32 = "ABCDEFGHIJKLMNOPQRSTUVWXYZ234567";

function base32Decode(s: string): Buffer {
  let bits = 0;
  let value = 0;
  const out: number[] = [];
  for (const ch of s.toUpperCase()) {
    const idx = BASE32.indexOf(ch);
    if (idx < 0) throw new Error(`not base32: ${ch}`);
    value = (value << 5) | idx;
    bits += 5;
    if (bits >= 8) {
      out.push((value >>> (bits - 8)) & 0xff);
      bits -= 8;
    }
  }
  return Buffer.from(out);
}

/** RFC 6238 with RFC 4226 dynamic truncation: SHA-1, 6 digits, 30 s step, T0 = 0. */
function referenceCode(secretB32: string, unixSeconds: number): string {
  const counter = Buffer.alloc(8);
  counter.writeBigUInt64BE(BigInt(Math.floor(unixSeconds / 30)));
  const mac = createHmac("sha1", base32Decode(secretB32)).update(counter).digest();
  const offset = mac[mac.length - 1] & 0x0f;
  const bin = mac.readUInt32BE(offset) & 0x7fffffff;
  return String(bin % 1_000_000).padStart(6, "0");
}

function at(unixSeconds: number): void {
  vi.setSystemTime(unixSeconds * 1000);
}

// RFC 6238 Appendix B seed for SHA-1 ("12345678901234567890"), base32-encoded.
const RFC_SECRET = "GEZDGNBVGY3TQOJQGEZDGNBVGY3TQOJQ";
// A 10-byte secret in the shape every existing enrollment has.
const ENROLLED = "JBSWY3DPEHPK3PXP";
// Produced by otplib 12's authenticator.generateSecret() — must keep verifying.
const ENROLLED_V12 = "HQFCULQAE4ADMHTY";
// 1_800_000_000 is a step boundary (÷30); test mid-step.
const STEP_START = 1_800_000_000;
const NOW = STEP_START + 15;

beforeEach(() => {
  vi.useFakeTimers({ toFake: ["Date"] });
});
afterEach(() => {
  vi.useRealTimers();
});

describe("TOTP secret format", () => {
  it("is 16 chars of unpadded RFC 4648 base32 (10 bytes), fresh each time", () => {
    const seen = new Set<string>();
    for (let i = 0; i < 50; i++) {
      const s = generateTotpSecret();
      expect(s).toMatch(/^[A-Z2-7]{16}$/);
      expect(base32Decode(s)).toHaveLength(10);
      seen.add(s);
    }
    expect(seen.size).toBe(50);
  });
});

describe("TOTP code generation: SHA-1, 6 digits, 30-second step", () => {
  it.each([
    [59, "287082"],
    [1111111109, "081804"],
    [1111111111, "050471"],
    [1234567890, "005924"],
    [2000000000, "279037"],
  ])("matches the RFC 6238 SHA-1 vector at T=%i (last 6 digits, zero-padded)", (t, code) => {
    at(t);
    expect(generateTotpCode(RFC_SECRET)).toBe(code);
    expect(verifyTotpCode(code, RFC_SECRET)).toBe(true);
  });

  it("agrees with the reference for 10-byte secrets, including one minted by v12", () => {
    for (const secret of [ENROLLED, ENROLLED_V12, generateTotpSecret()]) {
      for (const t of [NOW, NOW + 3600, 1_700_000_007]) {
        at(t);
        expect(generateTotpCode(secret)).toBe(referenceCode(secret, t));
      }
    }
  });

  it("holds one code for the whole 30-second step and rolls at the boundary", () => {
    at(STEP_START);
    const code = generateTotpCode(ENROLLED);
    at(STEP_START + 29);
    expect(generateTotpCode(ENROLLED)).toBe(code);
    at(STEP_START + 30);
    expect(generateTotpCode(ENROLLED)).toBe(referenceCode(ENROLLED, STEP_START + 30));
    expect(generateTotpCode(ENROLLED)).not.toBe(code);
  });
});

describe("TOTP verification window: current step only (window 0)", () => {
  it("accepts the current step's code for secrets enrolled under v12", () => {
    at(NOW);
    expect(verifyTotpCode(referenceCode(ENROLLED, NOW), ENROLLED)).toBe(true);
    expect(verifyTotpCode(referenceCode(ENROLLED_V12, NOW), ENROLLED_V12)).toBe(true);
  });

  it("rejects the code from one step before and one step after", () => {
    at(NOW);
    expect(verifyTotpCode(referenceCode(ENROLLED, NOW - 30), ENROLLED)).toBe(false);
    expect(verifyTotpCode(referenceCode(ENROLLED, NOW + 30), ENROLLED)).toBe(false);
  });

  it("rejects codes two or more steps away", () => {
    at(NOW);
    for (const steps of [-10, -3, -2, 2, 3, 10]) {
      expect(verifyTotpCode(referenceCode(ENROLLED, NOW + steps * 30), ENROLLED)).toBe(false);
    }
  });

  it("stops accepting a code the second its step ends", () => {
    const code = referenceCode(ENROLLED, STEP_START);
    at(STEP_START + 29);
    expect(verifyTotpCode(code, ENROLLED)).toBe(true);
    at(STEP_START + 30);
    expect(verifyTotpCode(code, ENROLLED)).toBe(false);
  });

  it("accepts a lowercase rendering of the secret", () => {
    at(NOW);
    expect(verifyTotpCode(referenceCode(ENROLLED, NOW), ENROLLED.toLowerCase())).toBe(true);
  });
});

describe("TOTP verification fails closed on malformed input", () => {
  it("returns false (never throws) for malformed tokens", () => {
    at(NOW);
    const code = referenceCode(ENROLLED, NOW);
    for (const token of ["", "12345", "1234567", `${code}0`, ` ${code}`, `${code}\n`, "abcdef", "12345a"]) {
      expect(verifyTotpCode(token, ENROLLED)).toBe(false);
    }
  });

  it("returns false (never throws) for a missing or non-base32 secret", () => {
    at(NOW);
    for (const secret of ["", "not base32!", "JBSW Y3DP EHPK 3PXP"]) {
      expect(verifyTotpCode("123456", secret)).toBe(false);
    }
  });
});

describe("TOTP enrollment URI", () => {
  it("is byte-for-byte the otpauth:// URI authenticator apps have been scanning", () => {
    expect(totpKeyUri("skeleton-key", "Skeleton Key", ENROLLED)).toBe(
      "otpauth://totp/Skeleton%20Key:skeleton-key?secret=JBSWY3DPEHPK3PXP&period=30&digits=6&algorithm=SHA1&issuer=Skeleton%20Key",
    );
  });

  it("percent-encodes the label and issuer", () => {
    expect(totpKeyUri("admin@home lab", "Skeleton Key", ENROLLED)).toBe(
      "otpauth://totp/Skeleton%20Key:admin%40home%20lab?secret=JBSWY3DPEHPK3PXP&period=30&digits=6&algorithm=SHA1&issuer=Skeleton%20Key",
    );
  });
});
