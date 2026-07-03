import { describe, it, expect } from "vitest";
import { resolveSshAuth, buildConnectConfig, shellQuote } from "./ssh-exec.js";
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
