import { describe, it, expect, beforeAll, afterAll } from "vitest";
import { createServer, type Server } from "node:http";
import {
  checkConstraints,
  compileFullMatch,
  isLanHost,
  runVerifyProbe,
  templateHeaders,
  templatePlaceholders,
  validateVerifyUrl,
} from "./credential-verify.js";

/**
 * The pre-store verification probe. Invariants: the secret is only ever sent
 * to the approved URL (https, or http on the LAN), redirects are not followed,
 * and no result ever carries the templated headers or the response body.
 */

describe("validateVerifyUrl / isLanHost", () => {
  it("accepts https anywhere", () => {
    expect(validateVerifyUrl("https://discord.com/api/v10/users/@me")).toBeNull();
  });

  it("accepts plain http only for RFC1918 / loopback hosts", () => {
    for (const ok of ["http://10.0.0.5/x", "http://192.168.1.1:8123/api", "http://172.16.3.4/", "http://172.31.255.1/", "http://127.0.0.1:9/", "http://localhost:8787/"]) {
      expect(validateVerifyUrl(ok)).toBeNull();
    }
    for (const bad of ["http://discord.com/api", "http://8.8.8.8/", "http://172.32.0.1/", "http://172.15.0.1/", "http://example.lan/"]) {
      expect(validateVerifyUrl(bad)).toMatch(/https/);
    }
  });

  it("rejects other schemes, embedded credentials, and garbage", () => {
    expect(validateVerifyUrl("ftp://10.0.0.1/")).toMatch(/https/);
    expect(validateVerifyUrl("https://user:pw@api.example.com/")).toMatch(/credentials/);
    expect(validateVerifyUrl("not a url")).toMatch(/valid absolute URL/);
  });

  it("isLanHost handles bracketed IPv6 loopback", () => {
    expect(isLanHost("[::1]")).toBe(true);
    expect(isLanHost("2001:db8::1")).toBe(false);
  });
});

describe("header templating", () => {
  it("lists placeholders and substitutes known ones, leaving unknown ones intact", () => {
    const headers = { Authorization: "Bot {{value}}", "X-A": "{{ FIELD_A }}/{{nope}}" };
    expect(templatePlaceholders(headers).sort()).toEqual(["FIELD_A", "nope", "value"]);
    expect(templateHeaders(headers, { value: "tok", FIELD_A: "a" })).toEqual({ Authorization: "Bot tok", "X-A": "a/{{nope}}" });
    expect(templateHeaders(undefined, {})).toEqual({});
  });
});

describe("constraints", () => {
  it("compiles patterns as a full match and reports value-free problems", () => {
    expect(compileFullMatch("[a-z]+")!.test("abc")).toBe(true);
    expect(compileFullMatch("[a-z]+")!.test("abc1")).toBe(false); // full match, not substring
    expect(compileFullMatch("(")).toBeNull();
    expect(checkConstraints("abc", { minLength: 4 })).toBe("too short");
    expect(checkConstraints("abcde", { maxLength: 4 })).toBe("too long");
    expect(checkConstraints("abc1", { pattern: "[a-z]+" })).toBe("does not match the expected pattern");
    expect(checkConstraints("abc", { pattern: "[a-z]+", minLength: 1, maxLength: 5 })).toBeNull();
    expect(checkConstraints("anything", undefined)).toBeNull();
  });
});

describe("runVerifyProbe", () => {
  let server: Server;
  let base: string;
  const hits: { path: string; method: string; auth?: string }[] = [];

  beforeAll(async () => {
    server = createServer((req, res) => {
      hits.push({ path: req.url!, method: req.method!, auth: req.headers.authorization });
      if (req.url === "/ok") return res.writeHead(200).end("secret-body");
      if (req.url === "/teapot") return res.writeHead(418).end("body");
      if (req.url === "/redirect") return res.writeHead(302, { location: "https://evil.example/" }).end();
      if (req.url === "/slow") return void setTimeout(() => res.writeHead(200).end(), 2000);
      res.writeHead(401).end('{"message":"Unauthorized"}');
    });
    await new Promise<void>((r) => server.listen(0, "127.0.0.1", () => r()));
    base = `http://127.0.0.1:${(server.address() as { port: number }).port}`;
  });
  afterAll(() => server.close());

  it("passes on 2xx with the templated header sent, exposing only host + status", async () => {
    const r = await runVerifyProbe({ method: "GET", url: `${base}/ok`, headers: { Authorization: "Bot {{value}}" } }, { value: "s3cret" });
    expect(r).toEqual({ ok: true, host: new URL(base).host, status: 200 });
    expect(hits.at(-1)).toMatchObject({ path: "/ok", method: "GET", auth: "Bot s3cret" });
    expect(JSON.stringify(r)).not.toContain("s3cret");
    expect(JSON.stringify(r)).not.toContain("secret-body");
  });

  it("fails on a non-2xx with a host+code reason and no body", async () => {
    const r = await runVerifyProbe({ method: "POST", url: `${base}/nope` }, { value: "x" });
    expect(r.ok).toBe(false);
    expect(r.status).toBe(401);
    expect(r.reason).toBe(`HTTP 401 from ${new URL(base).host}`);
    expect(JSON.stringify(r)).not.toContain("Unauthorized");
  });

  it("honors expectStatus", async () => {
    expect((await runVerifyProbe({ method: "GET", url: `${base}/teapot`, expectStatus: [418] }, {})).ok).toBe(true);
    expect((await runVerifyProbe({ method: "GET", url: `${base}/ok`, expectStatus: [204] }, {})).ok).toBe(false);
  });

  it("does not follow redirects (a 3xx is a failure, the secret never goes to the redirect target)", async () => {
    const r = await runVerifyProbe({ method: "GET", url: `${base}/redirect`, headers: { Authorization: "{{value}}" } }, { value: "tok" });
    expect(r.ok).toBe(false);
    expect(r.status).toBe(302);
  });

  it("times out without throwing", async () => {
    const r = await runVerifyProbe({ method: "GET", url: `${base}/slow`, timeoutMs: 500 }, {});
    expect(r.ok).toBe(false);
    expect(r.reason).toMatch(/timed out/);
  });

  it("refuses a disallowed URL before sending anything", async () => {
    const before = hits.length;
    const r = await runVerifyProbe({ method: "GET", url: "http://example.com/x", headers: { A: "{{value}}" } }, { value: "tok" });
    expect(r.ok).toBe(false);
    expect(r.reason).toMatch(/https/);
    expect(hits.length).toBe(before);
  });

  it("reports an unreachable host without leaking error internals", async () => {
    const r = await runVerifyProbe({ method: "GET", url: "http://127.0.0.1:1/", headers: { A: "{{value}}" } }, { value: "tok" });
    expect(r.ok).toBe(false);
    expect(r.reason).toMatch(/could not reach 127\.0\.0\.1:1/);
    expect(JSON.stringify(r)).not.toContain("tok");
  });
});
