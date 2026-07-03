import { Client, type ConnectConfig } from "ssh2";
import type { Credential } from "../secrets/types.js";
import type { Target } from "./types.js";

export interface SshExecResult {
  stdout: string;
  stderr: string;
  code: number | null;
}

/** True only for text that is actually an SSH private key. Used so freeform
 *  notes (which `getCredential` exposes via `cred.secret`) aren't mistaken for a
 *  key and handed to ssh2, which would fail with "Unsupported key format" even
 *  though the credential is a perfectly good username/password login. */
function looksLikePrivateKey(v: string | undefined): v is string {
  return !!v && (v.includes("-----BEGIN") || v.startsWith("PuTTY-User-Key-File"));
}

/**
 * Decide SSH auth from a resolved Credential (pure, exported for testing).
 * A private key is preferred, but ONLY an explicit `private_key` field or a
 * key-shaped `secret` counts — otherwise we fall back to password auth. This is
 * what makes password logins from the credential hand-off (whose notes land in
 * `cred.secret`) work instead of being misread as a broken key.
 */
export function resolveSshAuth(cred: Credential): { privateKey?: string; passphrase?: string; password?: string } {
  const keyField = cred.fields["private_key"];
  const privateKey = keyField ?? (looksLikePrivateKey(cred.secret) ? cred.secret : undefined);
  if (privateKey) return { privateKey, passphrase: cred.fields["key_passphrase"] || undefined };
  if (cred.password) return { password: cred.password };
  return {};
}

/**
 * Build the ssh2 ConnectConfig for a target (pure, exported for testing). When
 * authenticating with a password we ALSO enable keyboard-interactive: many
 * hardened / PAM-configured servers accept only the "keyboard-interactive"
 * method (not the plain "password" method), so a correct password would
 * otherwise fail with "All configured authentication methods failed" — even
 * though a normal `ssh` client (which falls back to keyboard-interactive) works.
 */
export function buildConnectConfig(target: Target, cred: Credential, timeoutMs: number): ConnectConfig {
  const auth = resolveSshAuth(cred);
  return {
    host: target.host,
    port: target.port ?? 22,
    username: cred.username ?? cred.fields["username"] ?? "root",
    readyTimeout: timeoutMs,
    ...auth,
    ...(auth.password ? { tryKeyboard: true } : {}),
  };
}

/**
 * Open a one-shot SSH connection, run a command, and return its output.
 * Auth comes from the target's resolved Credential (see `resolveSshAuth`).
 */
export function runSsh(
  target: Target,
  cred: Credential,
  command: string,
  opts: { timeoutMs?: number } = {},
): Promise<SshExecResult> {
  const timeoutMs = opts.timeoutMs ?? 20_000;
  const config = buildConnectConfig(target, cred, timeoutMs);

  return new Promise<SshExecResult>((resolve, reject) => {
    const conn = new Client();
    const timer = setTimeout(() => {
      conn.end();
      reject(new Error(`SSH to ${target.name} (${target.host}) timed out after ${timeoutMs}ms.`));
    }, timeoutMs);

    // Answer keyboard-interactive prompts with the password (the server-prompted
    // equivalent of password auth). Only wired up when we're doing password auth.
    if (config.tryKeyboard && config.password) {
      conn.on("keyboard-interactive", (_name, _instructions, _lang, prompts, finish) => {
        finish(prompts.map(() => config.password ?? ""));
      });
    }

    conn
      .on("ready", () => {
        conn.exec(command, (err, stream) => {
          if (err) {
            clearTimeout(timer);
            conn.end();
            return reject(err);
          }
          let stdout = "";
          let stderr = "";
          let code: number | null = null;
          stream
            .on("close", (exitCode: number | null) => {
              clearTimeout(timer);
              code = exitCode;
              conn.end();
              resolve({ stdout, stderr, code });
            })
            .on("data", (d: Buffer) => (stdout += d.toString()))
            .stderr.on("data", (d: Buffer) => (stderr += d.toString()));
        });
      })
      .on("error", (err) => {
        clearTimeout(timer);
        reject(err);
      })
      .connect(config);
  });
}

/** Escape a value for safe single-quoted inclusion in a remote shell command. */
export function shellQuote(value: string): string {
  return `'${value.replace(/'/g, `'\\''`)}'`;
}
