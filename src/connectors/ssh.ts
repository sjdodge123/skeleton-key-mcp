import { z } from "zod";
import type { Connector, ConnectorTool, Target, ToolContext, ToolResult } from "./types.js";
import { runSsh, shellQuote } from "./ssh-exec.js";
import { checkCommand, READONLY_ALLOW, type CommandPolicyOptions } from "./command-policy.js";

const optionsSchema = z
  .object({
    /** Extra denied command patterns for this host. */
    denyPatterns: z.array(z.string()).optional(),
    /** Restrict `run_command` to an allowlist (in addition to run_readonly). */
    allowPatterns: z.array(z.string()).optional(),
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

export const sshConnector: Connector = {
  type: "ssh",
  label: "SSH host",
  configSchema: optionsSchema,
  requiresCredential: true,
  buildTools,
};
