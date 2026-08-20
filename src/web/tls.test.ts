import { describe, it, expect, beforeEach, afterEach } from "vitest";
import { mkdtemp, rm, stat, writeFile } from "node:fs/promises";
import { tmpdir } from "node:os";
import path from "node:path";
import { X509Certificate } from "node:crypto";
import {
  certFingerprint,
  generateSelfSignedCert,
  needsRegeneration,
  pairMatches,
  resolveTls,
  tlsMode,
} from "./tls.js";

/**
 * These tests shell out to the real `openssl` (present in the Docker image, on
 * CI runners, and on dev machines as OpenSSL or LibreSSL) — generation is the
 * behavior under test, so no mocking.
 */

let dir: string;
const noop = (): void => {};

beforeEach(async () => {
  dir = await mkdtemp(path.join(tmpdir(), "sk-tls-"));
});
afterEach(async () => {
  await rm(dir, { recursive: true, force: true });
});

describe("tlsMode", () => {
  it("defaults to auto; exactly the documented 'off' (case-insensitive) disables", () => {
    const prev = process.env.SKELETON_KEY_TLS;
    try {
      delete process.env.SKELETON_KEY_TLS;
      expect(tlsMode()).toBe("auto");
      for (const v of ["off", "OFF", " off "]) {
        process.env.SKELETON_KEY_TLS = v;
        expect(tlsMode()).toBe("off");
      }
      for (const v of ["auto", "0", "false", "no", "on"]) {
        process.env.SKELETON_KEY_TLS = v;
        expect(tlsMode()).toBe("auto");
      }
    } finally {
      if (prev === undefined) delete process.env.SKELETON_KEY_TLS;
      else process.env.SKELETON_KEY_TLS = prev;
    }
  });
});

describe("generateSelfSignedCert", () => {
  it("produces a parseable server cert with the requested SANs and a 0600 key", async () => {
    const { cert, key } = await generateSelfSignedCert({
      dir,
      hosts: ["localhost", "127.0.0.1", "192.168.1.10", "skeleton.lan"],
    });
    const x509 = new X509Certificate(cert);
    expect(key).toContain("PRIVATE KEY");
    expect(x509.checkIP("127.0.0.1")).toBeTruthy();
    expect(x509.checkIP("192.168.1.10")).toBeTruthy();
    expect(x509.checkHost("localhost", { subject: "never" })).toBeTruthy();
    expect(x509.checkHost("skeleton.lan", { subject: "never" })).toBeTruthy();
    expect(x509.checkIP("10.9.9.9")).toBeUndefined();
    // Validity stays inside Apple's 825-day cap for locally-trusted certs.
    const days = (Date.parse(x509.validTo) - Date.parse(x509.validFrom)) / 86_400_000;
    expect(days).toBeLessThanOrEqual(826);
    const mode = (await stat(path.join(dir, "key.pem"))).mode & 0o777;
    expect(mode).toBe(0o600);
  });

  it("drops SAN-unsafe host strings instead of writing them into the openssl config", async () => {
    const { cert } = await generateSelfSignedCert({
      dir,
      hosts: ["evil\nIP.9 = 1.2.3.4", "ok.lan"],
    });
    const x509 = new X509Certificate(cert);
    expect(x509.checkHost("ok.lan", { subject: "never" })).toBeTruthy();
    expect(x509.checkIP("1.2.3.4")).toBeUndefined();
  });
});

describe("needsRegeneration", () => {
  it("is false for a fresh cert covering its hosts, true near expiry or for an unknown host", async () => {
    const { cert } = await generateSelfSignedCert({ dir, hosts: ["localhost", "192.168.1.10"] });
    expect(needsRegeneration(cert, ["192.168.1.10"])).toBe(false);
    expect(needsRegeneration(cert, ["192.168.1.99"])).toBe(true);
    expect(needsRegeneration(cert, ["new-host.lan"])).toBe(true);
    // 824 days out is within the 30-day renewal margin of the 825-day validity.
    const nearExpiry = new Date(Date.now() + 824 * 86_400_000);
    expect(needsRegeneration(cert, [], nearExpiry)).toBe(true);
    expect(needsRegeneration("not a certificate", [])).toBe(true);
  });

  it("matches bracketed IPv6 URL hostnames against IP SANs, and never churns on a SAN-impossible host", async () => {
    const { cert } = await generateSelfSignedCert({ dir, hosts: ["localhost", "[fd00::1]"] });
    // The bracketed form (what URL.hostname yields) both generates and matches.
    expect(new X509Certificate(cert).checkIP("fd00::1")).toBeTruthy();
    expect(needsRegeneration(cert, ["[fd00::1]"])).toBe(false);
    // A host that can never be a SAN must not force a re-issue on every boot.
    expect(needsRegeneration(cert, ["under_score.lan"])).toBe(false);
  });
});

describe("pairMatches", () => {
  it("accepts a matching pair and rejects a mismatched or garbage one", async () => {
    const a = await generateSelfSignedCert({ dir, hosts: ["localhost"] });
    const b = await generateSelfSignedCert({ dir: path.join(dir, "b"), hosts: ["localhost"] });
    expect(pairMatches(a.cert, a.key)).toBe(true);
    expect(pairMatches(a.cert, b.key)).toBe(false);
    expect(pairMatches(a.cert, "not a key")).toBe(false);
  });
});

describe("resolveTls", () => {
  it("returns null when TLS is off", async () => {
    expect(await resolveTls({ mode: "off", log: noop })).toBeNull();
  });

  it("generates on first boot and reuses the identical material afterwards", async () => {
    const opts = { mode: "auto" as const, dir, lanIps: ["192.168.1.10"], log: noop };
    const first = await resolveTls(opts);
    expect(first?.source).toBe("generated");
    const second = await resolveTls(opts);
    expect(second && certFingerprint(second.cert)).toBe(first && certFingerprint(first.cert));
  });

  it("re-issues when the pinned public-URL host is missing from the SANs", async () => {
    const base = { mode: "auto" as const, dir, lanIps: ["192.168.1.10"], log: noop };
    const first = await resolveTls(base);
    const reissued = await resolveTls({ ...base, publicUrlHost: "10.0.0.7" });
    expect(reissued && certFingerprint(reissued.cert)).not.toBe(first && certFingerprint(first.cert));
    expect(new X509Certificate(reissued!.cert).checkIP("10.0.0.7")).toBeTruthy();
    // And now it's stable again.
    const third = await resolveTls({ ...base, publicUrlHost: "10.0.0.7" });
    expect(third && certFingerprint(third.cert)).toBe(reissued && certFingerprint(reissued.cert));
  });

  it("serves a mounted pair, and fails loudly when the pair is broken", async () => {
    const { cert, key } = await generateSelfSignedCert({ dir, hosts: ["localhost"] });
    const certFile = path.join(dir, "mounted-cert.pem");
    const keyFile = path.join(dir, "mounted-key.pem");
    await writeFile(certFile, cert);
    await writeFile(keyFile, key);
    const ok = await resolveTls({ mode: "auto", dir, certFile, keyFile, log: noop });
    expect(ok?.source).toBe("mounted");
    expect(ok?.cert).toBe(cert);

    await expect(resolveTls({ mode: "auto", dir, certFile, log: noop })).rejects.toThrow(/set together/);
    await expect(
      resolveTls({ mode: "auto", dir, certFile: path.join(dir, "missing.pem"), keyFile, log: noop }),
    ).rejects.toThrow(/Could not read/);
    // A key that doesn't belong to the cert must fail loudly by name, not
    // crash later inside https.createServer.
    const other = await generateSelfSignedCert({ dir: path.join(dir, "other"), hosts: ["localhost"] });
    await writeFile(keyFile, other.key);
    await expect(resolveTls({ mode: "auto", dir, certFile, keyFile, log: noop })).rejects.toThrow(/not the private key/);
    await writeFile(certFile, "garbage");
    await writeFile(keyFile, key);
    await expect(resolveTls({ mode: "auto", dir, certFile, keyFile, log: noop })).rejects.toThrow(/parseable/);
  });

  it("re-issues a torn/mismatched on-disk pair instead of serving it", async () => {
    const base = { mode: "auto" as const, dir, lanIps: ["192.168.1.10"], log: noop };
    const first = await resolveTls(base);
    // Simulate a crash between the key and cert writes of a re-issue:
    // a fresh key lands next to the previous cert.
    const other = await generateSelfSignedCert({ dir: path.join(dir, "other"), hosts: ["localhost"] });
    await writeFile(path.join(dir, "key.pem"), other.key);
    const healed = await resolveTls(base);
    expect(healed).not.toBeNull();
    expect(pairMatches(healed!.cert, healed!.key)).toBe(true);
    expect(healed && certFingerprint(healed.cert)).not.toBe(first && certFingerprint(first.cert));
  });

  it("falls back to plain HTTP — never the mismatched pair — when a torn pair can't be re-issued", async () => {
    const base = { mode: "auto" as const, dir, lanIps: ["192.168.1.10"], log: noop };
    await resolveTls(base);
    const other = await generateSelfSignedCert({ dir: path.join(dir, "other"), hosts: ["localhost"] });
    await writeFile(path.join(dir, "key.pem"), other.key);
    const logs: string[] = [];
    const out = await resolveTls({
      ...base,
      opensslBin: path.join(dir, "no-such-openssl"),
      log: (m) => logs.push(m),
    });
    expect(out).toBeNull();
    expect(logs.join("\n")).toContain("torn or mismatched");
    expect(logs.join("\n")).toContain("PLAIN HTTP");
  });

  it("falls back to plain HTTP when generation fails with no prior material", async () => {
    const logs: string[] = [];
    const out = await resolveTls({
      mode: "auto",
      dir,
      lanIps: [],
      opensslBin: path.join(dir, "no-such-openssl"),
      log: (m) => logs.push(m),
    });
    expect(out).toBeNull();
    expect(logs.join("\n")).toContain("PLAIN HTTP");
  });

  it("keeps serving the existing cert when a re-issue fails", async () => {
    const base = { mode: "auto" as const, dir, lanIps: ["192.168.1.10"], log: noop };
    const first = await resolveTls(base);
    const logs: string[] = [];
    const out = await resolveTls({
      ...base,
      publicUrlHost: "10.0.0.7", // forces a re-issue attempt…
      opensslBin: path.join(dir, "no-such-openssl"), // …which fails
      log: (m) => logs.push(m),
    });
    expect(out && certFingerprint(out.cert)).toBe(first && certFingerprint(first.cert));
    expect(logs.join("\n")).toContain("existing certificate");
  });
});
