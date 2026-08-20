import { describe, it, expect, beforeAll, afterAll, vi } from "vitest";
import https from "node:https";
import { mkdtemp, rm } from "node:fs/promises";
import { tmpdir } from "node:os";
import path from "node:path";
import { Agent, fetch as undiciFetch } from "undici";
import { AppState } from "../app.js";
import { buildHttpApp } from "./server.js";
import { generateSelfSignedCert } from "./tls.js";

/**
 * End-to-end over real TLS: the express app behind a native https server must
 * (1) serve the wizard/API/discovery routes, (2) see req.protocol === "https"
 * so the OAuth issuer follows the scheme, (3) hand out the certificate at
 * /tls/cert.pem, and (4) present a cert that passes full verification when the
 * client trusts it as a CA — the exact NODE_EXTRA_CA_CERTS contract Claude Code
 * relies on.
 */

let dir: string;
let app: AppState;
let server: https.Server;
let base: string;
let certPem: string;

// Verifies against our self-signed cert exactly like NODE_EXTRA_CA_CERTS would:
// full chain + hostname verification, with only the CA set swapped.
let trusting: Agent;

beforeAll(async () => {
  vi.stubEnv("SKELETON_KEY_PUBLIC_URL", "");
  dir = await mkdtemp(path.join(tmpdir(), "sk-tls-srv-"));
  process.env.SKELETON_KEY_DATA_DIR = dir;
  const material = await generateSelfSignedCert({ dir: path.join(dir, "tls"), hosts: ["localhost", "127.0.0.1"] });
  certPem = material.cert;
  app = await AppState.create();
  const ex = buildHttpApp(app, { tlsCertPem: certPem });
  server = https.createServer({ cert: material.cert, key: material.key }, ex);
  await new Promise<void>((resolve) => server.listen(0, "127.0.0.1", resolve));
  const port = (server.address() as { port: number }).port;
  base = `https://127.0.0.1:${port}`;
  trusting = new Agent({ connect: { ca: certPem } });
});

afterAll(async () => {
  vi.unstubAllEnvs();
  await trusting.close();
  server.close();
  app.audit.close();
  app.oauth.close();
  await rm(dir, { recursive: true, force: true });
});

describe("https server", () => {
  it("answers /healthz over TLS with the self-signed cert fully verified", async () => {
    const res = await undiciFetch(`${base}/healthz`, { dispatcher: trusting });
    expect(res.ok).toBe(true);
    expect(await res.json()).toEqual({ ok: true });
  });

  it("advertises an https:// OAuth issuer (req.protocol follows the TLS socket)", async () => {
    const res = await undiciFetch(`${base}/.well-known/oauth-authorization-server`, { dispatcher: trusting });
    const meta = (await res.json()) as { issuer: string; token_endpoint: string };
    expect(meta.issuer).toBe(base);
    expect(meta.token_endpoint).toBe(`${base}/oauth/token`);
  });

  it("serves the active certificate at /tls/cert.pem for the one-time trust step", async () => {
    const res = await undiciFetch(`${base}/tls/cert.pem`, { dispatcher: trusting });
    expect(res.ok).toBe(true);
    expect(res.headers.get("content-type")).toContain("application/x-pem-file");
    expect(await res.text()).toBe(certPem);
  });

  it("does not expose /tls/cert.pem when built without TLS material", async () => {
    const plain = buildHttpApp(app);
    const httpSrv = plain.listen(0, "127.0.0.1");
    await new Promise<void>((resolve) => httpSrv.once("listening", resolve));
    const port = (httpSrv.address() as { port: number }).port;
    try {
      const res = await fetch(`http://127.0.0.1:${port}/tls/cert.pem`);
      expect(res.status).toBe(404);
    } finally {
      httpSrv.close();
    }
  });

  it("rejects the connection for a client that does not trust the cert", async () => {
    const strict = new Agent({ connect: { rejectUnauthorized: true } });
    try {
      await expect(undiciFetch(`${base}/healthz`, { dispatcher: strict })).rejects.toThrow();
    } finally {
      await strict.close();
    }
  });
});
