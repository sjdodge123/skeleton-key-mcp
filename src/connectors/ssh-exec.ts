import { Client, type ConnectConfig } from "ssh2";
import type { Credential } from "../secrets/types.js";
import type { Target } from "./types.js";

export interface SshExecResult {
  stdout: string;
  stderr: string;
  code: number | null;
}

/** Preserves today's behavior when no `commandTimeoutMs` / `timeoutSeconds` is set. */
export const DEFAULT_SSH_TIMEOUT_MS = 20_000;
/** Hard ceiling for both the per-target option and the per-call override (10 minutes). */
export const MAX_SSH_TIMEOUT_MS = 600_000;

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
  // A private key may live in the explicit field, in `secret`, or (for older
  // vault items) in `notes` — but ONLY if it's actually key-shaped, so freeform
  // notes on a password login are never mistaken for a key (#26). getCredential
  // no longer folds notes into `secret`, so we check `notes` directly here to
  // keep key-in-notes items working.
  const privateKey =
    cred.fields["private_key"] ??
    (looksLikePrivateKey(cred.secret) ? cred.secret : undefined) ??
    (looksLikePrivateKey(cred.notes) ? cred.notes : undefined);
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
 * Directories APPENDED to the remote PATH for every command. A non-interactive
 * SSH session on Synology DSM / embedded hosts gets a minimal PATH that omits
 * `/usr/local/bin` (docker, synopkg, pihole, …). Appending — not prepending —
 * keeps the host's own precedence for anything already on its PATH.
 */
export const SSH_PATH_APPEND = "/usr/local/bin:/usr/local/sbin:/usr/sbin:/sbin";
const PATH_PREFIX = `export PATH="$PATH:${SSH_PATH_APPEND}"; `;

export interface WrapCommandOptions {
  /** Command names (first word, after any leading `VAR=value` assignments) that
   *  get `sudo -n ` prefixed. Only the FIRST command of a pipeline / `&&` chain
   *  is sudo'd. */
  sudoPrefixes?: string[];
  /** Skip the PATH export (tests / callers that supply their own environment). */
  noPathExport?: boolean;
}

/**
 * Split a raw command into leading `VAR=value` assignments, the first word
 * (the program), and the rest. Pure helper for `wrapCommand`.
 */
function splitFirstWord(command: string): { assignments: string; program: string; rest: string } {
  const m = /^(\s*(?:[A-Za-z_][A-Za-z0-9_]*=(?:'[^']*'|"[^"]*"|[^\s'"]*)\s+)*)(\S+)([\s\S]*)$/.exec(command);
  if (!m) return { assignments: "", program: "", rest: command };
  return { assignments: m[1] ?? "", program: m[2] ?? "", rest: m[3] ?? "" };
}

/** The command's program name (first word after leading env assignments), or "". */
export function firstWord(command: string): string {
  return splitFirstWord(command).program;
}

/**
 * Wrap a RAW (already policy-checked) command for a sane non-interactive
 * environment: append the usual system dirs to PATH and, if the program
 * matches a configured `sudoPrefixes` entry, prefix `sudo -n` to that first
 * command (so e.g. `docker ps` on a Synology becomes `sudo -n docker ps`).
 * Pure, exported for testing. Callers MUST run the command policy on the raw
 * command BEFORE wrapping — this function never weakens or re-checks it.
 */
export function wrapCommand(command: string, opts: WrapCommandOptions = {}): string {
  let cmd = command;
  const prefixes = opts.sudoPrefixes ?? [];
  if (prefixes.length) {
    const { assignments, program, rest } = splitFirstWord(command);
    // Match on the basename too, so `/usr/local/bin/docker` hits a `docker` prefix.
    const base = program.slice(program.lastIndexOf("/") + 1);
    if (program && program !== "sudo" && (prefixes.includes(program) || prefixes.includes(base))) {
      // `sudo VAR=value cmd` keeps the assignment visible to the command (sudo's
      // own env handling applies), which is the least surprising translation.
      cmd = `sudo -n ${assignments}${program}${rest}`;
    }
  }
  return opts.noPathExport ? cmd : PATH_PREFIX + cmd;
}

/** True when stderr shows `sudo -n` was refused for lack of a NOPASSWD rule. */
export function looksLikeSudoPasswordFailure(stderr: string): boolean {
  return /a password is required|sudo: /.test(stderr);
}

/** One-line operator hint appended to a result when non-interactive sudo failed. */
export function sudoHint(program: string, username: string): string {
  const bin = program || "<binary>";
  return (
    `Hint: sudo needs a password for '${bin}' on this host. Grant the SSH user passwordless sudo for that binary only: ` +
    `echo '${username} ALL=(root) NOPASSWD: $(command -v ${bin})' | sudo tee /etc/sudoers.d/skeleton-key-${bin} && sudo chmod 0440 /etc/sudoers.d/skeleton-key-${bin}`
  );
}

/**
 * Open a one-shot SSH connection, run a command, and return its output.
 * Auth comes from the target's resolved Credential (see `resolveSshAuth`).
 * The command is wrapped by `wrapCommand` (PATH export + optional sudo) —
 * pass the RAW command, already policy-checked.
 */
export function runSsh(
  target: Target,
  cred: Credential,
  rawCommand: string,
  opts: { timeoutMs?: number } & WrapCommandOptions = {},
): Promise<SshExecResult> {
  const timeoutMs = opts.timeoutMs ?? DEFAULT_SSH_TIMEOUT_MS;
  const config = buildConnectConfig(target, cred, timeoutMs);
  const command = wrapCommand(rawCommand, opts);

  return new Promise<SshExecResult>((resolve, reject) => {
    const conn = new Client();
    const timer = setTimeout(() => {
      conn.end();
      reject(
        new Error(
          `SSH command on ${target.name} (${target.host}) timed out after ${timeoutMs}ms (${Math.round(timeoutMs / 1000)}s). ` +
            `Raise it via the target's "commandTimeoutMs" option (max ${MAX_SSH_TIMEOUT_MS}ms), or pass "timeoutSeconds" on this call (max ${MAX_SSH_TIMEOUT_MS / 1000}s).`,
        ),
      );
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
