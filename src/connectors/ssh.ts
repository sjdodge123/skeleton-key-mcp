import { z } from "zod";
import type { Connector, ConnectorTool, SnapshotArtifact, Target, ToolContext, ToolResult } from "./types.js";
import { runSsh, shellQuote } from "./ssh-exec.js";
import { checkCommand, READONLY_ALLOW, type CommandPolicyOptions } from "./command-policy.js";

const optionsSchema = z
  .object({
    /** Extra denied command patterns for this host. */
    denyPatterns: z.array(z.string()).optional(),
    /** Restrict `run_command` to an allowlist (in addition to run_readonly). */
    allowPatterns: z.array(z.string()).optional(),
    /** Config-dump commands run by `form_skeleton` for this host. Each becomes one
     *  artifact. If unset, a default read-only system profile is captured. */
    snapshotCommands: z.array(z.string()).optional(),
  })
  .default({});

function policyFor(target: Target): CommandPolicyOptions {
  const opts = optionsSchema.parse(target.options ?? {});
  return { deny: opts.denyPatterns, allow: opts.allowPatterns };
}

async function exec(ctx: ToolContext, command: string): Promise<ToolResult> {
  const cred = await ctx.getCredential();
  const { stdout, stderr, code } = await runSsh(ctx.target, cred, command);
  const body = stdout || stderr || "(no output)";
  return {
    text: code === 0 ? body : `exit ${code}\n${body}`,
    isError: code !== 0,
  };
}

function buildTools(target: Target): ConnectorTool[] {
  const readTools: ConnectorTool[] = [
    {
      name: "tail_log",
      description: `Tail the last N lines of a log file on ${target.name}.`,
      tier: "read",
      inputSchema: z.object({
        path: z.string().describe("Absolute path to the log file."),
        lines: z.number().int().positive().max(2000).default(200),
      }),
      run: (input, ctx) => {
        const { path, lines } = input as { path: string; lines: number };
        return exec(ctx, `tail -n ${lines} ${shellQuote(path)}`);
      },
    },
    {
      name: "journalctl",
      description: `Read systemd journal entries on ${target.name}.`,
      tier: "read",
      inputSchema: z.object({
        unit: z.string().optional().describe("Restrict to a systemd unit."),
        lines: z.number().int().positive().max(2000).default(200),
        since: z.string().optional().describe('e.g. "1 hour ago", "2024-01-01".'),
      }),
      run: (input, ctx) => {
        const { unit, lines, since } = input as { unit?: string; lines: number; since?: string };
        let cmd = `journalctl -n ${lines} --no-pager`;
        if (unit) cmd += ` -u ${shellQuote(unit)}`;
        if (since) cmd += ` --since ${shellQuote(since)}`;
        return exec(ctx, cmd);
      },
    },
    {
      name: "service_status",
      description: `Show status of a systemd service on ${target.name}.`,
      tier: "read",
      inputSchema: z.object({ unit: z.string() }),
      run: (input, ctx) => {
        const { unit } = input as { unit: string };
        return exec(ctx, `systemctl status ${shellQuote(unit)} --no-pager`);
      },
    },
    {
      name: "disk_usage",
      description: `Show filesystem usage (df -h) on ${target.name}.`,
      tier: "read",
      inputSchema: z.object({}),
      run: (_input, ctx) => exec(ctx, "df -h"),
    },
    {
      name: "grep_logs",
      description: `grep a pattern across files or a directory on ${target.name}.`,
      tier: "read",
      inputSchema: z.object({
        pattern: z.string(),
        path: z.string().describe("File or directory to search."),
        recursive: z.boolean().default(false),
      }),
      run: (input, ctx) => {
        const { pattern, path, recursive } = input as {
          pattern: string;
          path: string;
          recursive: boolean;
        };
        const flags = recursive ? "-rn" : "-n";
        return exec(ctx, `grep ${flags} -- ${shellQuote(pattern)} ${shellQuote(path)}`);
      },
    },
    {
      name: "run_readonly",
      description: `Run a read-only inspection command on ${target.name} (allowlisted: cat, ls, ps, systemctl status, ip, ss, docker ps/logs, ...).`,
      tier: "read",
      inputSchema: z.object({ command: z.string() }),
      run: (input, ctx) => {
        const { command } = input as { command: string };
        const verdict = checkCommand(command, { allow: READONLY_ALLOW });
        if (!verdict.allowed) {
          return Promise.resolve({ text: `Refused: ${verdict.reason}`, isError: true });
        }
        return exec(ctx, command);
      },
    },
  ];

  const executeTools: ConnectorTool[] = [
    {
      name: "run_command",
      description: `Run an arbitrary shell command on ${target.name}. Destructive commands are refused by policy.`,
      tier: "execute",
      inputSchema: z.object({ command: z.string() }),
      confirm: (input, t) =>
        `Run on ${t.name} (${t.host}): ${(input as { command: string }).command}`,
      run: (input, ctx) => {
        const { command } = input as { command: string };
        const verdict = checkCommand(command, policyFor(ctx.target));
        if (!verdict.allowed) {
          return Promise.resolve({ text: `Refused: ${verdict.reason}`, isError: true });
        }
        return exec(ctx, command);
      },
    },
    {
      name: "restart_service",
      description: `Restart a systemd service on ${target.name}.`,
      tier: "execute",
      inputSchema: z.object({ unit: z.string() }),
      confirm: (input, t) => `Restart service '${(input as { unit: string }).unit}' on ${t.name} (${t.host})`,
      run: (input, ctx) => {
        const { unit } = input as { unit: string };
        return exec(ctx, `systemctl restart ${shellQuote(unit)}`);
      },
    },
  ];

  return [...readTools, ...executeTools];
}

/** Read-only host profile captured when a target defines no `snapshotCommands`.
 *  Each yields one artifact; failures are skipped (a partial profile is fine). */
const DEFAULT_PROFILE: { name: string; cmd: string }[] = [
  { name: "uname.txt", cmd: "uname -a" },
  { name: "os-release.txt", cmd: "cat /etc/os-release 2>/dev/null" },
  { name: "ip-addr.txt", cmd: "ip a 2>/dev/null || ifconfig -a 2>/dev/null" },
  { name: "packages.txt", cmd: "dpkg -l 2>/dev/null || rpm -qa 2>/dev/null || apk info -v 2>/dev/null" },
  { name: "crontab.txt", cmd: "crontab -l 2>/dev/null" },
  { name: "docker-ps.txt", cmd: "docker ps -a 2>/dev/null" },
];

/**
 * Capture a config skeleton of an SSH host: the operator's `snapshotCommands`
 * if set, else a read-only system profile — plus a Pi-hole teleporter backup
 * when `pihole` is present. Uses `runSsh` directly (fixed backup commands, not
 * subject to the interactive command policy). Every step is best-effort so one
 * failing command never aborts the whole target's snapshot.
 */
async function snapshot(ctx: ToolContext): Promise<SnapshotArtifact[]> {
  const cred = await ctx.getCredential();
  const target = ctx.target;
  const opts = optionsSchema.parse(target.options ?? {});
  const arts: SnapshotArtifact[] = [];

  const custom = !!opts.snapshotCommands?.length;
  const commands = custom ? opts.snapshotCommands!.map((cmd, i) => ({ name: `cmd-${i + 1}.txt`, cmd })) : DEFAULT_PROFILE;
  const policy = policyFor(target);

  for (const { name, cmd } of commands) {
    // Operator-supplied snapshotCommands are a model-influenceable command path,
    // so they MUST honor the same deny-list as run_command (rm -rf / mkfs / dd …);
    // the fixed read-only DEFAULT_PROFILE is trusted and skips the check.
    if (custom) {
      const verdict = checkCommand(cmd, policy);
      if (!verdict.allowed) {
        arts.push({ name, data: Buffer.from(`Refused by command policy: ${verdict.reason}`, "utf8") });
        continue;
      }
    }
    try {
      const { stdout, stderr, code } = await runSsh(target, cred, cmd);
      const body = stdout || (code !== 0 ? `exit ${code}\n${stderr}` : "");
      // `note` is written UNENCRYPTED into the manifest, so never store an
      // operator's custom command there (it can embed inline credentials, e.g.
      // `mysqldump -pPASS`); the fixed profile commands are safe to label.
      if (body.trim()) arts.push({ name, data: Buffer.from(body, "utf8"), ...(custom ? {} : { note: cmd }) });
    } catch {
      /* skip a failing command — a partial profile is acceptable */
    }
  }

  // Pi-hole: the teleporter tarball is the real one-click restore artifact.
  try {
    const { stdout: hasPihole } = await runSsh(target, cred, "command -v pihole 2>/dev/null");
    if (hasPihole.trim()) {
      // Create the teleporter in a temp dir, base64 it back over the (text-only)
      // ssh channel with a portable encoder (BSD base64 has no GNU -w0), clean up.
      const teleporterCmd =
        'd=$(mktemp -d) && cd "$d" && pihole -a -t >/dev/null 2>&1 && ' +
        'f=$(ls -1 *.tar.gz 2>/dev/null | head -1) && [ -n "$f" ] && ' +
        "base64 \"$f\" | tr -d '\\n'; cd / && rm -rf \"$d\"";
      const { stdout: b64 } = await runSsh(target, cred, teleporterCmd);
      const trimmed = b64.trim();
      if (trimmed) {
        arts.push({ name: "teleporter.tar.gz", data: Buffer.from(trimmed, "base64"), note: "Pi-hole teleporter backup (contains secrets)" });
      } else {
        // Pi-hole present but no teleporter produced (Pi-hole v6 replaced
        // `pihole -a -t`) — surface the gap instead of silently omitting a backup.
        arts.push({
          name: "pihole-BACKUP-MISSING.txt",
          data: Buffer.from("Pi-hole detected but `pihole -a -t` produced no teleporter archive (Pi-hole v6 changed this command). Capture a backup manually.", "utf8"),
          note: "teleporter capture failed",
        });
      }
      const { stdout: setupVars } = await runSsh(target, cred, "cat /etc/pihole/setupVars.conf 2>/dev/null");
      if (setupVars.trim()) {
        arts.push({ name: "pihole-setupVars.conf", data: Buffer.from(setupVars, "utf8"), note: "Pi-hole config reference" });
      }
    }
  } catch {
    /* pihole capture is best-effort */
  }

  return arts;
}

export const sshConnector: Connector = {
  type: "ssh",
  label: "SSH host",
  configSchema: optionsSchema,
  requiresCredential: true,
  buildTools,
  snapshot,
};
