import { describe, it, expect, vi, afterEach, beforeAll, afterAll } from "vitest";
import { execFileSync } from "node:child_process";
import { mkdtempSync, rmSync, readFileSync } from "node:fs";
import { tmpdir } from "node:os";
import path from "node:path";
import { createServer, type Server } from "node:https";
import { deriveBaseUrl, tlsFetch } from "./net.js";
import type { Target } from "./types.js";

const target = (host: string, port?: number): Target => ({ name: "t", type: "http", host, port });

afterEach(() => vi.unstubAllGlobals());

describe("deriveBaseUrl", () => {
  it("infers scheme from the port and honors an explicit baseUrl", () => {
    expect(deriveBaseUrl(target("10.0.0.5", 8080))).toBe("http://10.0.0.5:8080");
    expect(deriveBaseUrl(target("10.0.0.5", 443))).toBe("https://10.0.0.5:443");
    expect(deriveBaseUrl(target("10.0.0.5", 9443), { httpsPorts: [443, 9443] })).toBe("https://10.0.0.5:9443");
    expect(deriveBaseUrl(target("x"), { baseUrl: "https://p.lan/" })).toBe("https://p.lan");
  });
  it("brackets IPv6 literal hosts", () => {
    expect(deriveBaseUrl(target("fd00::10", 8006))).toBe("http://[fd00::10]:8006");
  });
});

describe("tlsFetch", () => {
  it("uses global fetch for the secure path", async () => {
    const fn = vi.fn(async () => ({ ok: true, status: 200, text: async () => "" }) as any);
    vi.stubGlobal("fetch", fn);
    await tlsFetch("https://x", { method: "GET" }, false);
    expect(fn).toHaveBeenCalledOnce();
  });

  it("never mutates the process-global TLS setting on the insecure path", async () => {
    const before = process.env.NODE_TLS_REJECT_UNAUTHORIZED;
    await tlsFetch("https://127.0.0.1:0/", { method: "GET" }, true).catch(() => {});
    expect(process.env.NODE_TLS_REJECT_UNAUTHORIZED).toBe(before);
  });
});

// Real self-signed HTTPS server: proves the per-request TLS-skip actually works
// (and guards against undici-version-compat regressions — Node's bundled fetch
// rejects this package's Agent, so the insecure path must use undici's own
// fetch). Skips gracefully where openssl isn't available.
describe("tlsFetch against a self-signed server", () => {
  let dir: string | null = null;
  let server: Server | null = null;
  let url = "";

  beforeAll(async () => {
    try {
      const d = mkdtempSync(path.join(tmpdir(), "sk-tls-"));
      execFileSync("openssl", ["req", "-x509", "-newkey", "rsa:2048", "-keyout", `${d}/k.pem`, "-out", `${d}/c.pem`, "-days", "1", "-nodes", "-subj", "/CN=localhost"], { stdio: "ignore" });
      dir = d;
      server = createServer({ key: readFileSync(`${d}/k.pem`), cert: readFileSync(`${d}/c.pem`) }, (_req, res) => { res.writeHead(200); res.end("ok"); });
      await new Promise<void>((r) => server!.listen(0, r));
      url = `https://localhost:${(server!.address() as any).port}/`;
    } catch {
      dir = null; // openssl unavailable — the manual smoke covers this
    }
  });
  afterAll(() => {
    server?.close();
    if (dir) rmSync(dir, { recursive: true, force: true });
  });

  it("rejects a self-signed cert when secure, accepts it when insecureTLS is set", async () => {
    if (!dir) return; // environment without openssl
    await expect(tlsFetch(url, { method: "GET" }, false)).rejects.toThrow();
    const res = await tlsFetch(url, { method: "GET" }, true);
    expect(res.status).toBe(200);
    expect(await res.text()).toBe("ok");
  });
});
