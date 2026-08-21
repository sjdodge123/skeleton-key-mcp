import { describe, it, expect, vi } from "vitest";

vi.mock("ssh2", async () => {
  // A Client that connects and never emits "ready" — simulates an unreachable
  // host so runSsh's own timeout timer is what rejects the promise. Imported
  // dynamically inside the factory since vi.mock factories are hoisted above
  // top-level imports.
  const { EventEmitter } = await import("node:events");
  class FakeClient extends EventEmitter {
    connect() {
      /* never fires "ready" */
    }
    end() {
      /* no-op */
    }
    exec() {
      /* not reached before timeout */
    }
  }
  return { Client: FakeClient };
});

import {
  resolveSshAuth,
  buildConnectConfig,
  shellQuote,
  runSsh,
  MAX_SSH_TIMEOUT_MS,
  wrapCommand,
  firstWord,
  looksLikeSudoPasswordFailure,
  sudoHint,
  SSH_PATH_APPEND,
} from "./ssh-exec.js";
import type { Credential } from "../secrets/types.js";
import type { Target } from "./types.js";

function cred(partial: Partial<Credential>): Credential {
  return { ref: "x", fields: {}, uris: [], ...partial };
}

const KEY = "-----BEGIN OPENSSH PRIVATE KEY-----\nabc\n-----END OPENSSH PRIVATE KEY-----";

describe("resolveSshAuth", () => {
  it("uses password auth when the only 'secret' is freeform notes (the hand-off bug)", () => {
    // getCredential exposes item.notes as cred.secret; it must NOT be read as a key.
    const auth = resolveSshAuth(cred({ password: "pw", secret: "Stored via Skeleton Key credential hand-off. onboard nas" }));
    expect(auth).toEqual({ password: "pw" });
  });

  it("uses the explicit private_key field (with passphrase) as a key", () => {
    const auth = resolveSshAuth(cred({ fields: { private_key: KEY, key_passphrase: "pp" }, password: "ignored" }));
    expect(auth).toEqual({ privateKey: KEY, passphrase: "pp" });
  });

  it("uses a key-shaped secret as a key", () => {
    const auth = resolveSshAuth(cred({ secret: KEY }));
    expect(auth).toEqual({ privateKey: KEY, passphrase: undefined });
  });

  it("prefers a real key over a password when both are present", () => {
    const auth = resolveSshAuth(cred({ secret: KEY, password: "pw" }));
    expect(auth.privateKey).toBe(KEY);
    expect(auth.password).toBeUndefined();
  });

  it("uses a key-shaped notes value as the key (older items stored the key in notes)", () => {
    const auth = resolveSshAuth(cred({ notes: KEY }));
    expect(auth).toEqual({ privateKey: KEY, passphrase: undefined });
  });

  it("does NOT treat freeform notes as a key (falls back to password)", () => {
    const auth = resolveSshAuth(cred({ notes: "Stored via hand-off. reason", password: "pw" }));
    expect(auth).toEqual({ password: "pw" });
  });

  it("returns no auth when neither a key nor a password is available", () => {
    expect(resolveSshAuth(cred({ secret: "just a note" }))).toEqual({});
  });
});

describe("buildConnectConfig", () => {
  const target = (partial: Partial<Target> = {}): Target => ({ name: "t", type: "ssh", host: "10.0.0.9", ...partial });

  it("enables keyboard-interactive alongside password auth (for PAM/hardened servers)", () => {
    const cfg = buildConnectConfig(target({ port: 2222 }), cred({ username: "sam", password: "pw" }), 5000);
    expect(cfg.password).toBe("pw");
    expect(cfg.tryKeyboard).toBe(true);
    expect(cfg.username).toBe("sam");
    expect(cfg.port).toBe(2222);
  });

  it("does NOT enable keyboard-interactive for key auth", () => {
    const cfg = buildConnectConfig(target(), cred({ fields: { private_key: KEY } }), 5000);
    expect(cfg.privateKey).toBe(KEY);
    expect(cfg.tryKeyboard).toBeUndefined();
    expect(cfg.password).toBeUndefined();
  });

  it("defaults port 22 and username 'root' when unset", () => {
    const cfg = buildConnectConfig(target(), cred({ password: "pw" }), 5000);
    expect(cfg.port).toBe(22);
    expect(cfg.username).toBe("root");
  });
});

describe("shellQuote", () => {
  it("single-quotes and escapes embedded quotes", () => {
    expect(shellQuote("a'b")).toBe(`'a'\\''b'`);
  });
});

describe("runSsh timeout", () => {
  const target = (partial: Partial<Target> = {}): Target => ({ name: "nas1", type: "ssh", host: "10.0.0.5", ...partial });

  it("rejects with a message stating the limit hit and how to raise it (per-call timeoutMs)", async () => {
    vi.useFakeTimers();
    try {
      const promise = runSsh(target(), cred({ password: "pw" }), "echo hi", { timeoutMs: 5_000 });
      const assertion = expect(promise).rejects.toThrow(
        /timed out after 5000ms \(5s\)[\s\S]*commandTimeoutMs[\s\S]*timeoutSeconds/,
      );
      await vi.advanceTimersByTimeAsync(5_000);
      await assertion;
    } finally {
      vi.useRealTimers();
    }
  });

  it("falls back to DEFAULT_SSH_TIMEOUT_MS (20s) when no timeoutMs is given", async () => {
    vi.useFakeTimers();
    try {
      const promise = runSsh(target(), cred({ password: "pw" }), "echo hi");
      const assertion = expect(promise).rejects.toThrow(/timed out after 20000ms \(20s\)/);
      await vi.advanceTimersByTimeAsync(20_000);
      await assertion;
    } finally {
      vi.useRealTimers();
    }
  });

  it("MAX_SSH_TIMEOUT_MS is 10 minutes", () => {
    expect(MAX_SSH_TIMEOUT_MS).toBe(600_000);
  });
});

describe("wrapCommand (PATH + sudoPrefixes)", () => {
  it("appends (not prepends) the system dirs to PATH so the host's own precedence wins", () => {
    const out = wrapCommand("docker ps");
    expect(out).toBe(`export PATH="$PATH:${SSH_PATH_APPEND}"; docker ps`);
    expect(out.indexOf("$PATH:")).toBeLessThan(out.indexOf("/usr/local/bin"));
  });

  it("leaves the command untouched apart from the PATH export when no sudoPrefixes match", () => {
    expect(wrapCommand("ls -la /tmp", { sudoPrefixes: ["docker"], noPathExport: true })).toBe("ls -la /tmp");
  });

  it("prefixes `sudo -n` to the first command when its program matches", () => {
    expect(wrapCommand("docker ps -a", { sudoPrefixes: ["docker"], noPathExport: true })).toBe("sudo -n docker ps -a");
    expect(wrapCommand("synopkg list", { sudoPrefixes: ["docker", "synopkg"], noPathExport: true })).toBe("sudo -n synopkg list");
  });

  it("matches on basename too, so an absolute path to the binary is also elevated", () => {
    expect(wrapCommand("/usr/local/bin/docker ps", { sudoPrefixes: ["docker"], noPathExport: true })).toBe("sudo -n /usr/local/bin/docker ps");
  });

  it("skips leading VAR=value assignments when finding the program (and keeps them)", () => {
    expect(wrapCommand("DOCKER_HOST=unix:///var/run/docker.sock docker ps", { sudoPrefixes: ["docker"], noPathExport: true })).toBe(
      "sudo -n DOCKER_HOST=unix:///var/run/docker.sock docker ps",
    );
    expect(wrapCommand(`A=1 B="two words" docker info`, { sudoPrefixes: ["docker"], noPathExport: true })).toBe(`sudo -n A=1 B="two words" docker info`);
  });

  it("only sudos the FIRST command of a pipeline / && chain", () => {
    expect(wrapCommand("docker ps | grep nginx", { sudoPrefixes: ["docker", "grep"], noPathExport: true })).toBe("sudo -n docker ps | grep nginx");
    expect(wrapCommand("cd /tmp && docker ps", { sudoPrefixes: ["docker"], noPathExport: true })).toBe("cd /tmp && docker ps"); // first command is cd
  });

  it("never double-sudos a command the user already prefixed with sudo", () => {
    expect(wrapCommand("sudo docker ps", { sudoPrefixes: ["docker", "sudo"], noPathExport: true })).toBe("sudo docker ps");
  });

  it("firstWord returns the program after env assignments", () => {
    expect(firstWord("FOO=bar docker ps")).toBe("docker");
    expect(firstWord("   ls")).toBe("ls");
    expect(firstWord("")).toBe("");
  });

  it("detects a non-interactive sudo password failure and the hint names the binary + user", () => {
    expect(looksLikeSudoPasswordFailure("sudo: a password is required\n")).toBe(true);
    expect(looksLikeSudoPasswordFailure("sudo: 3 incorrect password attempts")).toBe(true);
    expect(looksLikeSudoPasswordFailure("permission denied while trying to connect to the Docker daemon socket")).toBe(false);
    const hint = sudoHint("docker", "skeletonkey");
    expect(hint).toContain("NOPASSWD");
    expect(hint).toContain("skeletonkey ALL=(root)");
    expect(hint).toContain("command -v docker");
    expect(hint).toContain("/etc/sudoers.d/skeleton-key-docker");
  });
});
