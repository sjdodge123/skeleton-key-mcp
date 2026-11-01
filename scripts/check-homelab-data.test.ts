import { describe, it, expect } from "vitest";
import { spawnSync } from "node:child_process";
import path from "node:path";

const script = path.resolve(import.meta.dirname, "check-homelab-data.mjs");

// Built at runtime so this file never contains the strings the check refuses.
const lan = (host: number) => ["192", "168", "0", String(host)].join(".");

function scan(text: string, opts: { denylist?: string; ci?: boolean; require?: boolean } = {}) {
  const args = [script, "--text-env", "SAMPLE"];
  if (opts.require) args.push("--require-denylist");
  const env: NodeJS.ProcessEnv = { PATH: process.env.PATH, SAMPLE: text };
  if (opts.denylist !== undefined) env.SKELETON_KEY_DENYLIST = opts.denylist;
  if (opts.ci) env.CI = "true";
  // Run outside any checkout so a maintainer's local denylist file can't leak in.
  const res = spawnSync(process.execPath, args, { env, cwd: path.parse(process.cwd()).root, encoding: "utf8" });
  return { code: res.status, out: res.stdout + res.stderr };
}

describe("check-homelab-data", () => {
  it("refuses a full address in the maintainer's LAN range", () => {
    const r = scan(`collector at ${lan(32)}:514`);
    expect(r.code).toBe(1);
    expect(r.out).toContain("LAN address");
  });

  it("allows placeholders, the network address and bare subnet examples", () => {
    expect(scan("use 192.168.1.40, 10.0.0.5 or 203.0.113.7").code).toBe(0);
    expect(scan(`network ${lan(0)}/24, subnet '192.168.0'`).code).toBe(0);
    expect(scan(`not an address: 1${lan(9)}`).code).toBe(0);
  });

  it("refuses denylist entries as whole tokens, case-insensitively", () => {
    const denylist = "# comment\nbox77\nexample.org\n";
    expect(scan("ssh into BOX77 now", { denylist }).code).toBe(1);
    expect(scan("see https://status.example.org/", { denylist }).code).toBe(1);
    expect(scan("box770 and mybox77x are different names", { denylist }).code).toBe(0);
  });

  it("does not match an address entry inside a longer address", () => {
    const denylist = "10.9.9.9";
    expect(scan("host 10.9.9.9", { denylist }).code).toBe(1);
    expect(scan("host 10.9.9.99", { denylist }).code).toBe(0);
  });

  it("never prints the matched denylist entry in CI", () => {
    const r = scan("ssh into box77", { denylist: "box77", ci: true });
    expect(r.code).toBe(1);
    expect(r.out).toContain("private denylist entry #1");
    expect(r.out).not.toContain("box77");
  });

  it("fails closed when a denylist is required but none is loaded", () => {
    expect(scan("anything", { require: true }).code).toBe(2);
    expect(scan("anything", { denylist: "box77", require: true }).code).toBe(0);
  });
});
