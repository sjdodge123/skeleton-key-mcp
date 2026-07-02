/**
 * Guardrails for shell commands run over SSH. This is defense-in-depth on top of
 * the approval gate — even an approved `execute` call is refused if it matches a
 * destructive pattern, unless the target explicitly allows it.
 */

/** Patterns denied by default on every SSH target. */
export const DEFAULT_DENY: RegExp[] = [
  /\brm\s+(-[a-z]*r[a-z]*f|-[a-z]*f[a-z]*r)\b/i, // rm -rf / -fr in any flag order
  /\bmkfs(\.\w+)?\b/i,
  /\bdd\b[^|]*\bof=\/dev\//i,
  /\b(shutdown|reboot|halt|poweroff)\b/i, // use restart_service for scoped restarts
  /\bfdisk\b|\bparted\b|\bwipefs\b/i,
  /:\s*\(\s*\)\s*\{.*\|.*&.*\}\s*;/, // fork bomb ":(){ :|:& };:"
  />\s*\/dev\/(sd|nvme|mmcblk|vd)/i, // writing straight to a block device
  /\bchmod\s+-R\s+000\b/i,
];

export interface PolicyResult {
  allowed: boolean;
  reason?: string;
}

export interface CommandPolicyOptions {
  /** Extra deny patterns (strings compiled case-insensitively) for this target. */
  deny?: string[];
  /** If set, ONLY commands matching one of these are allowed (allowlist mode). */
  allow?: string[];
}

export function checkCommand(command: string, opts: CommandPolicyOptions = {}): PolicyResult {
  const trimmed = command.trim();
  if (!trimmed) return { allowed: false, reason: "Empty command." };

  const extraDeny = (opts.deny ?? []).map((p) => new RegExp(p, "i"));
  for (const pattern of [...DEFAULT_DENY, ...extraDeny]) {
    if (pattern.test(trimmed)) {
      return { allowed: false, reason: `Command matches a denied pattern: ${pattern}` };
    }
  }

  if (opts.allow && opts.allow.length > 0) {
    const allow = opts.allow.map((p) => new RegExp(p, "i"));
    if (!allow.some((p) => p.test(trimmed))) {
      return { allowed: false, reason: "Command is not on this target's allowlist." };
    }
  }

  return { allowed: true };
}

/** Read-only allowlist for the `run_readonly` tool: safe inspection commands. */
export const READONLY_ALLOW: string[] = [
  "^\\s*(cat|less|head|tail|grep|egrep|zgrep|find|ls|stat|du|df|free|uptime|uname|hostname)\\b",
  "^\\s*(ps|top|htop|systemctl\\s+status|journalctl|dmesg|who|w|id|env|date)\\b",
  "^\\s*(ip\\s+(a|addr|r|route|link)|ss|netstat|ping|traceroute|dig|nslookup|host|arp)\\b",
  "^\\s*(docker\\s+(ps|logs|inspect|stats)|zpool\\s+status|smartctl\\s+-)\\b",
];
