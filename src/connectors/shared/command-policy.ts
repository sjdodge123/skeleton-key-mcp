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
  /** Allowlist mode only: patterns refused when they match any single command of
   *  a compound line — for allowlisted commands whose flags can also write
   *  (`ip link set`, `date -s`, `find -delete`, …). Matched case-sensitively. */
  segmentDeny?: string[];
}

type SplitResult = { segments: string[] } | { reason: string };

/** End index (exclusive) of an output redirection that starts at `cmd[i] === ">"`,
 *  or null when it writes somewhere other than /dev/null or another fd. */
function redirectEnd(cmd: string, i: number): number | null {
  let j = i + 1;
  if (cmd[j] === ">" || cmd[j] === "|") j++; // >> and >|
  if (cmd[j] === "&") {
    // fd duplication: 2>&1, >&2, 2>&-
    j++;
    const m = /^(\d+|-)/.exec(cmd.slice(j));
    return m ? j + m[0].length : null;
  }
  while (cmd[j] === " " || cmd[j] === "\t") j++;
  const target = "/dev/null";
  if (!cmd.startsWith(target, j)) return null;
  const after = cmd[j + target.length];
  return after === undefined || /[\s;|&]/.test(after) ? j + target.length : null;
}

/**
 * Split a shell line into the simple commands it would run, so allowlist mode can
 * vet EVERY one of them — checking only the start let `cat x; systemctl stop y`
 * or `ls | tee /etc/…` through. Quote-aware (`grep -E 'a|b'` is one command).
 * Refuses anything it can't vet per command: substitution (`$(…)`, backticks,
 * `<(…)`), subshells/grouping parens, backgrounding, input redirection/here-docs,
 * and output redirection except to /dev/null or another fd.
 */
export function splitCompound(cmd: string): SplitResult {
  const segments: string[] = [];
  let cur = "";
  let quote: "'" | '"' | null = null;
  const push = () => {
    if (cur.trim()) segments.push(cur.trim());
    cur = "";
  };
  for (let i = 0; i < cmd.length; i++) {
    const c = cmd[i];
    const next = cmd[i + 1];
    if (quote === "'") {
      cur += c;
      if (c === "'") quote = null;
      continue;
    }
    if (c === "\\") {
      cur += c + (next ?? "");
      i++;
      continue;
    }
    if (c === "`" || (c === "$" && next === "(")) return { reason: "Command substitution is not allowed here." };
    if (quote === '"') {
      cur += c;
      if (c === '"') quote = null;
      continue;
    }
    if (c === "'" || c === '"') {
      quote = c;
      cur += c;
      continue;
    }
    if (c === ";" || c === "\n") {
      push();
      continue;
    }
    if (c === "|") {
      if (next === "|" || next === "&") i++; // ||, |&
      push();
      continue;
    }
    if (c === "&") {
      if (next === "&") {
        i++;
        push();
        continue;
      }
      if (next === ">") {
        // &> / &>> : both streams — only to /dev/null
        const end = redirectEnd(cmd, i + 1);
        if (end === null) return { reason: "Output redirection to a file is not allowed here." };
        cur += cmd.slice(i, end);
        i = end - 1;
        continue;
      }
      return { reason: "Backgrounding (&) is not allowed here." };
    }
    if (c === ">") {
      const end = redirectEnd(cmd, i);
      if (end === null) return { reason: "Output redirection to a file is not allowed here." };
      cur += cmd.slice(i, end);
      i = end - 1;
      continue;
    }
    if (c === "<") return { reason: "Input redirection, here-docs and process substitution are not allowed here." };
    if (c === "(" || c === ")") return { reason: "Subshells and grouping are not allowed here." };
    cur += c;
  }
  if (quote) return { reason: "Unterminated quote." };
  push();
  return { segments };
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
    const split = splitCompound(trimmed);
    if ("reason" in split) return { allowed: false, reason: split.reason };
    const allow = opts.allow.map((p) => new RegExp(p, "i"));
    // Case-SENSITIVE: flag case carries meaning (`smartctl -x` reads, `-X` aborts a test).
    const segmentDeny = (opts.segmentDeny ?? []).map((p) => new RegExp(p));
    for (const segment of split.segments) {
      if (!allow.some((p) => p.test(segment))) {
        const shown = split.segments.length > 1 ? ` (\`${segment}\`)` : "";
        return { allowed: false, reason: `Command is not on this target's allowlist${shown}.` };
      }
      const denied = segmentDeny.find((p) => p.test(segment));
      if (denied) {
        return { allowed: false, reason: `\`${segment}\` uses a state-changing form refused in read-only mode: ${denied}` };
      }
    }
  }

  return { allowed: true };
}

/** Trailing redirections an end-anchored allow pattern admits — exactly the
 *  forms `splitCompound` lets through (fd duplication, /dev/null). */
const TRAILING_REDIRECTS = "(\\s+(\\d*|&)>{1,2}(&\\d+|&-|\\s*/dev/null))*";

/** Read-only allowlist for the `run_readonly` tool: safe inspection commands.
 *  Every command of a compound line must match (see `splitCompound`). */
export const READONLY_ALLOW: string[] = [
  "^\\s*(cat|less|head|tail|grep|egrep|zgrep|find|ls|stat|du|df|free|uptime|uname|hostname)\\b",
  "^\\s*(wc|cut|tr|column|sort)\\b",
  "^\\s*(ps|top|htop|journalctl|dmesg|who|w|id|env|date)\\b",
  "^\\s*systemctl\\s+(status|list-units|list-unit-files|list-timers|is-active|is-enabled|is-failed|show|cat)\\b",
  // `systemctl --failed` is `list-units --failed`; anchored so no verb can follow.
  `^\\s*systemctl\\s+--failed(\\s+--(no-pager|no-legend|plain|full|all))*${TRAILING_REDIRECTS}\\s*$`,
  // `ip` takes abbreviated subcommands (`ip l s` = link set), so only an object
  // followed by nothing or an explicit show/list/get is admitted.
  "^\\s*ip(\\s+-\\S+)*\\s+(a|addr|address|r|route|l|link|n|neigh|neighbor|rule|maddr)(\\s+(show|list|lst|ls|get)\\b.*)?\\s*$",
  "^\\s*(ss|netstat|ping|traceroute|dig|nslookup|host|arp)\\b",
  "^\\s*(docker\\s+(ps|logs|inspect|stats)|zpool\\s+(status|list|iostat)|zfs\\s+(list|get)|smartctl\\s+-)\\b",
  // Hardware / block devices
  "^\\s*(lspci|lsusb|lsblk|lscpu|lsmod|findmnt|blkid|pvs|vgs|lvs)\\b",
  "^\\s*nvme\\s+(list|smart-log|id-ctrl|id-ns|error-log)\\b",
  // Kernel modules: modinfo only reads module metadata; `dkms status` lists
  // out-of-tree module builds per kernel (install/build/remove stay out).
  "^\\s*modinfo\\b",
  "^\\s*dkms\\s+status\\b",
  // Proxmox VE (read-only subcommands only)
  "^\\s*pveversion\\b",
  // Major-upgrade checklists: read-only checks; `--full` is their only option.
  `^\\s*pve(7to8|8to9)(\\s+--full)?${TRAILING_REDIRECTS}\\s*$`,
  "^\\s*pvesm\\s+(status|list|path)\\b",
  "^\\s*qm\\s+(config|status|list|listsnapshot|pending|showcmd)\\b",
  "^\\s*pct\\s+(config|status|list|listsnapshot|pending)\\b",
  "^\\s*pvecm\\s+(status|nodes)\\b",
  "^\\s*pvesh\\s+get\\b",
  // UPS status (NUT client / apcupsd). `upsc` only queries upsd; `\b` keeps the
  // state-changing `upscmd` (beeper, battery test, shutdown) and `upsrw` off.
  "^\\s*upsc\\b",
  "^\\s*apcaccess\\b",
];

/** State-changing forms of commands that READONLY_ALLOW admits by name. Checked
 *  per command of a compound line, so a grep pattern mentioning them is fine. */
export const READONLY_DENY: string[] = [
  "^\\s*find\\b.*\\s-(exec|execdir|ok|okdir|delete|fprint|fprint0|fprintf|fls)\\b",
  "^\\s*ip\\b.*\\s(add|del|delete|set|flush|change|replace|append|prepend|restore)\\b",
  "^\\s*ip\\b.*\\s-(b|batch|force)\\b",
  "^\\s*date\\b.*(\\s(-s|--set)\\b|\\s\\d{4,})",
  "^\\s*hostname\\b.*(\\s[^-\\s]|\\s-[A-Za-z0-9]*[Fb]|--file|--boot)",
  "^\\s*dmesg\\b.*(\\s-[A-Za-z0-9]*[cCDEn]|--clear|--read-clear|--console-)",
  "^\\s*journalctl\\b.*--(vacuum|rotate|flush|relinquish-var|smart-relinquish-var|sync|setup-keys|update-catalog)",
  "^\\s*ss\\b.*(\\s-[A-Za-z0-9]*K|--kill)",
  "^\\s*arp\\b.*(\\s-[A-Za-z0-9]*[dsf]|--delete|--set|--file)",
  "^\\s*env\\s+\\S", // `env CMD` runs CMD
  "^\\s*smartctl\\b.*(\\s-[A-Za-z0-9]*[tXsoS]|--(test|abort|set|smart|offlineauto|saveauto))",
  "^\\s*sort\\b.*(\\s-[A-Za-z0-9]*o|--output)",
  "^\\s*ping\\b.*\\s-[A-Za-z0-9]*f",
];

/** Policy check for `run_readonly`. */
export function checkReadonly(command: string): PolicyResult {
  return checkCommand(command, { allow: READONLY_ALLOW, segmentDeny: READONLY_DENY });
}
