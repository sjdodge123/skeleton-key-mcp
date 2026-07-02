import { Client, type ConnectConfig } from "ssh2";
import type { Credential } from "../secrets/types.js";
import type { Target } from "./types.js";

export interface SshExecResult {
  stdout: string;
  stderr: string;
  code: number | null;
}

/**
 * Open a one-shot SSH connection, run a command, and return its output.
 * Auth comes from the target's resolved Credential: a private key (in `secret`
 * or the `private_key` field) is preferred, falling back to password auth.
 */
export function runSsh(
  target: Target,
  cred: Credential,
  command: string,
  opts: { timeoutMs?: number } = {},
): Promise<SshExecResult> {
  const timeoutMs = opts.timeoutMs ?? 20_000;
  const privateKey = cred.fields["private_key"] ?? cred.secret;
  const usePassword = !privateKey && cred.password;

  const config: ConnectConfig = {
    host: target.host,
    port: target.port ?? 22,
    username: cred.username ?? cred.fields["username"] ?? "root",
    readyTimeout: timeoutMs,
    ...(privateKey
      ? { privateKey, passphrase: cred.fields["key_passphrase"] || undefined }
      : {}),
    ...(usePassword ? { password: cred.password } : {}),
  };

  return new Promise<SshExecResult>((resolve, reject) => {
    const conn = new Client();
    const timer = setTimeout(() => {
      conn.end();
      reject(new Error(`SSH to ${target.name} (${target.host}) timed out after ${timeoutMs}ms.`));
    }, timeoutMs);

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
