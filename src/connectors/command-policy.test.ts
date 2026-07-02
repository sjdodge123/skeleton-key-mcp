import { describe, it, expect } from "vitest";
import { checkCommand, READONLY_ALLOW } from "./command-policy.js";

describe("command policy deny-list", () => {
  it("blocks recursive force rm in any flag order", () => {
    expect(checkCommand("rm -rf /").allowed).toBe(false);
    expect(checkCommand("rm -fr /var/log").allowed).toBe(false);
    expect(checkCommand("sudo rm  -Rf  /data").allowed).toBe(false);
  });

  it("blocks filesystem and disk destroyers", () => {
    expect(checkCommand("mkfs.ext4 /dev/sda1").allowed).toBe(false);
    expect(checkCommand("dd if=/dev/zero of=/dev/sda").allowed).toBe(false);
    expect(checkCommand("wipefs -a /dev/sdb").allowed).toBe(false);
  });

  it("blocks power-state changes and fork bombs", () => {
    expect(checkCommand("shutdown -h now").allowed).toBe(false);
    expect(checkCommand("reboot").allowed).toBe(false);
    expect(checkCommand(":(){ :|:& };:").allowed).toBe(false);
  });

  it("allows ordinary read commands", () => {
    expect(checkCommand("tail -n 100 /var/log/syslog").allowed).toBe(true);
    expect(checkCommand("systemctl restart nginx").allowed).toBe(true);
    expect(checkCommand("docker ps").allowed).toBe(true);
  });

  it("honors an extra per-target deny pattern", () => {
    const res = checkCommand("systemctl stop firewalld", { deny: ["systemctl stop"] });
    expect(res.allowed).toBe(false);
  });

  it("enforces allowlist mode for readonly commands", () => {
    expect(checkCommand("cat /etc/hosts", { allow: READONLY_ALLOW }).allowed).toBe(true);
    expect(checkCommand("ip addr", { allow: READONLY_ALLOW }).allowed).toBe(true);
    // Not on the readonly allowlist:
    expect(checkCommand("systemctl restart nginx", { allow: READONLY_ALLOW }).allowed).toBe(false);
    expect(checkCommand("echo hi > /tmp/x", { allow: READONLY_ALLOW }).allowed).toBe(false);
  });

  it("rejects empty commands", () => {
    expect(checkCommand("   ").allowed).toBe(false);
  });
});
