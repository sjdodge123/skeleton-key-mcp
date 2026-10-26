import { shellQuote, looksLikeSudoPasswordFailure, type SshExecResult } from "./ssh-exec.js";
import type { Credential } from "./types.js";

/**
 * Pelican panel-host plumbing — the PURE half of `panel_version`,
 * `panel_prepare_runtime`, `panel_upgrade` and `wings_update` (the SSH glue lives
 * in `pelican.ts`). Everything here is deterministic and unit-tested without a
 * host: command construction, argument validation, output parsing, composer PHP
 * constraints, and the operator hints printed when the helper is missing or
 * sudo refuses.
 *
 * **The root boundary.** A panel upgrade has host-level prerequisites that need
 * root — a new PHP release + php-fpm + the nginx socket, the panel upgrade itself,
 * and the Wings binary — but the SSH user must not get general sudo for that. The owner installs ONE
 * root-owned, non-writable helper (`scripts/host/skeleton-key-pelican-host.sh`,
 * shipped in this repo) and grants ONE NOPASSWD sudoers rule for that path
 * alone. Skeleton Key only ever runs `sudo -n <helper> <fixed subcommand>
 * <validated arg>`; the helper itself re-validates the argument, accepts nothing
 * else, and refuses to run if it is not root-owned/non-writable. A failed sudo
 * returns the exact rule to add — nothing broader is ever suggested.
 */

/** Where the owner installs the helper; the sudoers rule names this path. */
export const HELPER_PATH = "/usr/local/sbin/skeleton-key-pelican-host.sh";
/** Where the helper lives in this repo. */
export const HELPER_REPO_PATH = "scripts/host/skeleton-key-pelican-host.sh";
/** The one sudoers drop-in the rule goes into. */
export const HELPER_SUDOERS_FILE = "/etc/sudoers.d/skeleton-key-pelican-host";

export const HELPER_SUBCOMMANDS = ["status", "php-prepare", "panel-upgrade", "wings-update"] as const;
export type HelperSubcommand = (typeof HELPER_SUBCOMMANDS)[number];

// --- Argument validation (mirrors the helper's own checks) ------------------------

/** `8.N` only — the one shape `php-prepare` accepts. */
export function assertPhpVersionArg(v: string): string {
  const t = v.trim();
  if (!/^8\.\d{1,2}$/.test(t)) {
    throw new Error(`phpVersion must be a PHP 8 major.minor like '8.4' (got '${v}'). The host helper accepts nothing else either.`);
  }
  return t;
}

const RELEASE_TAG = /^v\d+\.\d+\.\d+(?:-[A-Za-z0-9]+(?:\.[A-Za-z0-9]+)*)?$/;

/** A Pelican/Wings release tag like `v1.0.0-rc.1`; a missing `v` is added. */
function assertTag(tag: string, what: string): string {
  const t = tag.trim();
  const norm = t.startsWith("v") ? t : `v${t}`;
  if (norm.length > 40 || !RELEASE_TAG.test(norm)) {
    throw new Error(`${what} must be a release tag like 'v1.0.0-rc.1' (got '${tag}').`);
  }
  return norm;
}
export function assertWingsTag(tag: string): string {
  return assertTag(tag, "tag");
}
export function assertReleaseTag(tag: string): string {
  return assertTag(tag, "release");
}

/** The installed panel version as config/app.php spells it (no leading `v`). */
export function assertPanelVersion(v: string): string {
  const t = v.trim();
  if (t.length > 40 || !/^\d+\.\d+\.\d+(?:-[A-Za-z0-9]+(?:\.[A-Za-z0-9]+)*)?$/.test(t)) {
    throw new Error(`expectVersion must be a panel version like '1.0.0-beta35' (got '${v}').`);
  }
  return t;
}

// --- Commands sent to the host ------------------------------------------------------

/**
 * The helper invocation. `sudo -n` only: a password prompt fails instead of
 * hanging, and the failure is turned into the sudoers hint. The argument is
 * validated AND single-quoted — belt and braces, since the helper re-validates.
 */
export function helperCommand(sub: "status"): string;
export function helperCommand(sub: "php-prepare", phpVersion: string): string;
export function helperCommand(sub: "wings-update", tag: string): string;
export function helperCommand(sub: "panel-upgrade", expectVersion: string, tag: string, skipBackup?: boolean): string;
export function helperCommand(sub: HelperSubcommand, a?: string, b?: string, skipBackup?: boolean): string {
  const args: string[] = [];
  switch (sub) {
    case "status":
      break;
    case "php-prepare":
      if (a === undefined) throw new Error("php-prepare needs a PHP version");
      args.push(assertPhpVersionArg(a));
      break;
    case "wings-update":
      if (a === undefined) throw new Error("wings-update needs a tag");
      args.push(assertWingsTag(a));
      break;
    case "panel-upgrade":
      if (a === undefined || b === undefined) throw new Error("panel-upgrade needs the installed version and a tag");
      args.push(assertPanelVersion(a), assertReleaseTag(b));
      // The helper accepts exactly this literal as its only option.
      if (skipBackup) args.push("--skip-backup");
      break;
  }
  return [`sudo -n ${HELPER_PATH} ${sub}`, ...args.map(shellQuote)].join(" ");
}

/** Unprivileged PHP CLI version probe, in the helper's key=value format. */
const PHP_CLI_PROBE = `php -r 'echo "php_cli=" . PHP_VERSION . "\\n";' 2>/dev/null`;

/**
 * The read used by `panel_version` and the pre-flight of every host tool. Runs
 * the helper's `status` when it is installed (that needs root — `wings version`
 * is not executable by the SSH user on a typical install), and degrades to an
 * unprivileged PHP probe when the helper is missing (`helper=0`) or sudo refuses
 * (`helper=1` + `helper_rc=<n>`, with sudo's complaint on stderr), so the version
 * read keeps working and the result names the exact fix.
 */
export const HOST_STATUS_COMMAND =
  `H=${HELPER_PATH}; if [ -x "$H" ]; then sudo -n "$H" status; rc=$?; ` +
  `if [ "$rc" -ne 0 ]; then echo helper=1; echo "helper_rc=$rc"; ${PHP_CLI_PROBE}; fi; ` +
  `else echo helper=0; ${PHP_CLI_PROBE}; fi`;

/**
 * Unprivileged apt read of the php<8.N>-fpm package: installed version vs the
 * candidate apt would install. It reads the host's cached package lists (only
 * root can refresh them), so "current" means "as of the last apt update" — the
 * helper's `php-prepare` refreshes the lists itself before installing.
 */
export function phpPackagePolicyCommand(phpVersion: string): string {
  return `LC_ALL=C apt-cache policy php${assertPhpVersionArg(phpVersion)}-fpm 2>/dev/null`;
}

export interface AptPolicy {
  /** Undefined when the package is not installed (`Installed: (none)`). */
  installed?: string;
  candidate?: string;
}

/** `apt-cache policy` output → installed / candidate versions. */
export function parseAptPolicy(stdout: string): AptPolicy {
  const field = (name: string): string | undefined => {
    const v = new RegExp(`^\\s*${name}:\\s*(\\S+)`, "m").exec(stdout)?.[1];
    return v && v !== "(none)" ? v : undefined;
  };
  return { installed: field("Installed"), candidate: field("Candidate") };
}

/** "8.4.27" out of a Debian package version like "8.4.27-1+ubuntu24.04.1+deb.sury.org+1". */
export function upstreamPhpVersion(debVersion: string): string {
  return /^(?:\d+:)?(\d+\.\d+\.\d+)/.exec(debVersion)?.[1] ?? debVersion;
}

/**
 * The PHP major.minor actually serving the panel: the nginx fastcgi socket's
 * version first (that is what php-fpm requests hit), then the CLI default, then
 * the CLI version itself.
 */
export function servingPhpMinor(s: HostStatus): string | undefined {
  const fromSocket = /\/php(8\.\d{1,2})-fpm\.sock$/.exec(s.nginxSocket ?? "")?.[1];
  if (fromSocket) return fromSocket;
  if (s.phpDefault && /^8\.\d{1,2}$/.test(s.phpDefault)) return s.phpDefault;
  const cli = /^(8\.\d{1,2})\./.exec(s.phpCli ?? "")?.[1];
  return cli;
}

/** The installed panel's own `require.php` line — one line, never the whole file. */
export function currentPhpRequirementCommand(panelPath: string): string {
  return `grep -m1 -E '^[[:space:]]*"php"[[:space:]]*:' ${panelPath}/composer.json`;
}

// --- Parsing the helper's output ------------------------------------------------------

export interface HostStatus {
  /** The helper answered (or, when false, the fallback probe did). */
  helper: boolean;
  /** Set when the helper exists but `sudo -n … status` exited non-zero. */
  helperRc?: number;
  helperVersion?: number;
  /** The panel version the helper read from config/app.php (helper v2+). */
  panelVersion?: string;
  /** `php -r 'echo PHP_VERSION;'`, e.g. "8.3.6". */
  phpCli?: string;
  /** The `php` alternative, e.g. "8.3". */
  phpDefault?: string;
  phpInstalled: string[];
  phpFpmActive: string[];
  nginxSite?: string;
  nginxSocket?: string;
  nginxActive?: string;
  /** Wings version without the leading `v`, e.g. "1.0.0-beta22". */
  wings?: string;
  wingsActive?: string;
}

/** "1.0.0-beta22" from `wings v1.0.0-beta22` (or a bare version), else undefined. */
export function parseWingsVersion(text: string): string | undefined {
  const m = /^(?:wings\s+)?v?(\d+\.\d+\.\d+[A-Za-z0-9.-]*)/.exec(text.trim());
  return m?.[1];
}

/** key=value lines → HostStatus; unknown keys and non-matching lines are ignored. */
/** `key=value` lines → map; anything else (progress text, `php -v`) is ignored. */
export function parseKeyValues(stdout: string): Map<string, string> {
  const kv = new Map<string, string>();
  for (const line of stdout.split(/\r?\n/)) {
    const m = /^([a-z_]+)=(.*)$/.exec(line.trim());
    if (m) kv.set(m[1]!, m[2]!.trim());
  }
  return kv;
}

export function parseHostStatus(stdout: string): HostStatus {
  const kv = parseKeyValues(stdout);
  const str = (k: string): string | undefined => kv.get(k) || undefined;
  const list = (k: string): string[] => (kv.get(k) ?? "").split(/\s+/).filter(Boolean);
  const num = (k: string): number | undefined => {
    const v = kv.get(k);
    return v && /^\d+$/.test(v) ? Number(v) : undefined;
  };
  const wings = str("wings");
  return {
    helper: kv.get("helper") === "1",
    helperRc: num("helper_rc"),
    helperVersion: num("helper_version"),
    panelVersion: str("panel_version"),
    phpCli: str("php_cli"),
    phpDefault: str("php_default"),
    phpInstalled: list("php_installed"),
    phpFpmActive: list("php_fpm_active"),
    nginxSite: str("nginx_site"),
    nginxSocket: str("nginx_socket"),
    nginxActive: str("nginx_active"),
    wings: wings ? parseWingsVersion(wings) : undefined,
    wingsActive: str("wings_active"),
  };
}

/** The helper's `panel-upgrade` steps in order — the names it reports in
 *  `steps_done` / `failed_step`. Download, pre-flight and backup come BEFORE
 *  maintenance mode by design. */
export const PANEL_UPGRADE_STEP_NAMES = [
  "download-release",
  "download-checksum",
  "preflight-platform",
  "db-backup",
  "maintenance-mode",
  "extract",
  "fix-permissions",
  "composer-install",
  "migrate",
  "clear-caches",
  "restart-queue",
  "exit-maintenance",
] as const;

export interface UpgradeResult {
  before?: string;
  after?: string;
  alreadyCurrent: boolean;
  /** Root-only run log on the host with every step's output. */
  log?: string;
  /** Backup path, or the literal "skipped". */
  dbBackup?: string;
  stepsDone: string[];
  failedStep?: string;
  /** True when the helper stopped with the panel still in maintenance mode. */
  maintenance?: boolean;
}

/** The `panel-upgrade` subcommand's stdout → result (success or failure shape). */
export function parseUpgradeResult(stdout: string): UpgradeResult {
  const kv = parseKeyValues(stdout);
  const str = (k: string): string | undefined => kv.get(k) || undefined;
  return {
    before: str("panel_before"),
    after: str("panel_after"),
    alreadyCurrent: kv.get("already_current") === "1",
    log: str("upgrade_log"),
    dbBackup: str("db_backup"),
    stepsDone: (kv.get("steps_done") ?? "").split(/\s+/).filter(Boolean),
    failedStep: str("failed_step"),
    maintenance: kv.has("maintenance") ? kv.get("maintenance") === "1" : undefined,
  };
}

// --- Operator hints -------------------------------------------------------------------

/** The SSH user the sudoers rule is for; falls back to a placeholder rather than
 *  emitting a malformed rule. */
export function sshUserOf(cred: Credential): string {
  const u = cred.username ?? cred.fields["username"];
  return u && /^[A-Za-z0-9._-]+$/.test(u) ? u : "<ssh-user>";
}

/** THE sudoers rule — the whole root grant. */
export function sudoersLine(user: string): string {
  return `${user} ALL=(root) NOPASSWD: ${HELPER_PATH}`;
}

export function sudoersInstallSnippet(user: string): string {
  return (
    `echo '${sudoersLine(user)}' | sudo tee ${HELPER_SUDOERS_FILE} >/dev/null && ` +
    `sudo chmod 0440 ${HELPER_SUDOERS_FILE} && sudo visudo -cf ${HELPER_SUDOERS_FILE}`
  );
}

export function helperInstallSnippet(user: string): string {
  return [
    `Install it once, by hand, as an admin on the panel host (copy ${HELPER_REPO_PATH} from the Skeleton Key repo there first):`,
    `  sudo install -o root -g root -m 0755 skeleton-key-pelican-host.sh ${HELPER_PATH}`,
    `  ${sudoersInstallSnippet(user)}`,
    `That rule is the only root access Skeleton Key gets on this host; the script accepts only 'status', 'php-prepare <8.N>' and 'wings-update <vTAG>'.`,
  ].join("\n");
}

export type HelperFailure = "missing" | "sudo" | "refused" | "failed";

/**
 * Why a helper run did not succeed. Order matters: `sudo: /usr/local/sbin/…:
 * command not found` also matches the sudo-password heuristic, so "missing" is
 * decided first.
 */
export function classifyHelperFailure(res: SshExecResult, status?: HostStatus): HelperFailure {
  if (status && !status.helper) return "missing";
  if (res.code === 127 || /command not found|No such file or directory/i.test(res.stderr)) return "missing";
  if (looksLikeSudoPasswordFailure(res.stderr)) return "sudo";
  if (res.code === 2 || status?.helperRc === 2) return "refused";
  return "failed";
}

export function helperFailureText(kind: HelperFailure, user: string, res: SshExecResult, sub: HelperSubcommand): string {
  const tail = res.stderr.trim().split("\n").slice(-4).join(" | ").slice(0, 400);
  switch (kind) {
    case "missing":
      return `the host helper is not installed (${HELPER_PATH} is missing or not executable). ${helperInstallSnippet(user)}`;
    case "sudo":
      return (
        `sudo refused to run the host helper without a password for SSH user '${user}'. ` +
        `Add exactly this rule on the panel host (nothing broader): ${sudoersLine(user)} — ${sudoersInstallSnippet(user)}`
      );
    case "refused":
      return `the host helper REFUSED '${sub}' (exit 2): ${tail || "(no detail)"}`;
    default:
      return `the host helper failed during '${sub}' (exit ${res.code ?? "?"}): ${tail || "(no detail)"}`;
  }
}

/** The problem with a HOST_STATUS_COMMAND result, or undefined when the helper answered. */
export function hostStatusProblem(res: SshExecResult, status: HostStatus, user: string): string | undefined {
  if (!status.helper) return helperFailureText("missing", user, res, "status");
  if (status.helperRc !== undefined || res.code !== 0) return helperFailureText(classifyHelperFailure(res, status), user, res, "status");
  return undefined;
}

// --- Versions -------------------------------------------------------------------------

type Triple = [number, number, number];

function parseVersionParts(s: string): { v: Triple; parts: number } | undefined {
  const m = /^v?(\d+)(?:\.(\d+))?(?:\.(\d+))?(?:[^\d.]|$)/.exec(s.trim());
  if (!m) return undefined;
  const parts = m[3] !== undefined ? 3 : m[2] !== undefined ? 2 : 1;
  return { v: [Number(m[1]), Number(m[2] ?? 0), Number(m[3] ?? 0)], parts };
}

/** "8.3.6" / "8.4.0RC1" / "8.4" → [8,3,6] / [8,4,0] / [8,4,0]. */
export function parsePhpVersion(s: string): Triple | undefined {
  return parseVersionParts(s)?.v;
}

function cmpTriple(a: Triple, b: Triple): number {
  for (let i = 0; i < 3; i += 1) if (a[i] !== b[i]) return a[i]! < b[i]! ? -1 : 1;
  return 0;
}

/** Prerelease tags Pelican uses, lowest first. Unknown tags are not ordered. */
const PRERELEASE_ORDER = ["alpha", "beta", "rc"];

/**
 * Compare two Pelican/Wings versions well enough to say "behind / same / ahead".
 * Tags look like `v1.0.0-beta38` or `v1.0.0-rc.1`; numeric components compare
 * left to right, then the prerelease stage (alpha < beta < rc < release), then
 * its number. Returns -1/0/1, or undefined when a shape is unrecognised or the
 * stages are not both known — the caller must then say "could not compare"
 * rather than guess, because claiming "up to date" wrongly is the bad failure.
 */
export function compareVersions(a: string, b: string): number | undefined {
  const parse = (v: string) => {
    const m = /^v?(\d+)\.(\d+)\.(\d+)(?:-([A-Za-z]+)\.?(\d+))?$/.exec(v.trim());
    if (!m) return undefined;
    return {
      nums: [Number(m[1]), Number(m[2]), Number(m[3])] as Triple,
      // No prerelease outranks any prerelease: 1.0.0 > 1.0.0-rc.1 > 1.0.0-beta38.
      pre: m[4] ? { stage: PRERELEASE_ORDER.indexOf(m[4].toLowerCase()), num: Number(m[5]) } : undefined,
    };
  };
  const pa = parse(a);
  const pb = parse(b);
  if (!pa || !pb) return undefined;
  const n = cmpTriple(pa.nums, pb.nums);
  if (n !== 0) return n;
  if (!pa.pre && !pb.pre) return 0;
  if (!pa.pre) return 1;
  if (!pb.pre) return -1;
  if (pa.pre.stage < 0 || pb.pre.stage < 0) return undefined; // an unknown stage — don't guess
  if (pa.pre.stage !== pb.pre.stage) return pa.pre.stage < pb.pre.stage ? -1 : 1;
  if (pa.pre.num === pb.pre.num) return 0;
  return pa.pre.num < pb.pre.num ? -1 : 1;
}

// --- Composer PHP constraints ----------------------------------------------------------

interface Bound {
  v: Triple;
  inclusive: boolean;
}
interface Range {
  lo?: Bound;
  hi?: Bound;
}

const bump = (v: Triple, at: 0 | 1): Triple => (at === 0 ? [v[0] + 1, 0, 0] : [v[0], v[1] + 1, 0]);

/** One composer constraint token → a range, or undefined when not understood. */
function parseConstraintToken(tok: string): Range | undefined {
  if (tok === "*" || tok === "x" || tok === "X") return {};
  let m: RegExpExecArray | null;
  if ((m = /^\^(.+)$/.exec(tok))) {
    const p = parseVersionParts(m[1]!);
    if (!p) return undefined;
    // ^8.4 → >=8.4.0 <9.0.0 (^0.x stays within the minor, as composer does).
    return { lo: { v: p.v, inclusive: true }, hi: { v: p.v[0] > 0 ? bump(p.v, 0) : bump(p.v, 1), inclusive: false } };
  }
  if ((m = /^~(.+)$/.exec(tok))) {
    const p = parseVersionParts(m[1]!);
    if (!p) return undefined;
    // ~8.4 → >=8.4 <9.0; ~8.4.1 → >=8.4.1 <8.5.0.
    return { lo: { v: p.v, inclusive: true }, hi: { v: p.parts >= 3 ? bump(p.v, 1) : bump(p.v, 0), inclusive: false } };
  }
  if ((m = /^(>=|<=|>|<|==|=|!=)\s*(.+)$/.exec(tok))) {
    const op = m[1]!;
    const p = parseVersionParts(m[2]!);
    if (!p || op === "!=") return undefined;
    switch (op) {
      case ">=":
        return { lo: { v: p.v, inclusive: true } };
      case ">":
        return { lo: { v: p.v, inclusive: false } };
      case "<":
        return { hi: { v: p.v, inclusive: false } };
      case "<=":
        return { hi: { v: p.v, inclusive: true } };
      default:
        return { lo: { v: p.v, inclusive: true }, hi: { v: p.v, inclusive: true } };
    }
  }
  if ((m = /^(\d+)(?:\.(\d+))?\.[x*]$/.exec(tok))) {
    // 8.4.* → >=8.4.0 <8.5.0; 8.* → >=8.0.0 <9.0.0
    const v: Triple = [Number(m[1]), Number(m[2] ?? 0), 0];
    return { lo: { v, inclusive: true }, hi: { v: m[2] !== undefined ? bump(v, 1) : bump(v, 0), inclusive: false } };
  }
  if (/^v?\d+(?:\.\d+){0,2}$/.test(tok)) {
    const p = parseVersionParts(tok)!;
    if (p.parts === 3) return { lo: { v: p.v, inclusive: true }, hi: { v: p.v, inclusive: true } };
    return { lo: { v: p.v, inclusive: true }, hi: { v: p.parts === 2 ? bump(p.v, 1) : bump(p.v, 0), inclusive: false } };
  }
  return undefined;
}

function inRange(v: Triple, r: Range): boolean {
  if (r.lo) {
    const c = cmpTriple(v, r.lo.v);
    if (c < 0 || (c === 0 && !r.lo.inclusive)) return false;
  }
  if (r.hi) {
    const c = cmpTriple(v, r.hi.v);
    if (c > 0 || (c === 0 && !r.hi.inclusive)) return false;
  }
  return true;
}

/** One `||` alternative (an AND of tokens, or a hyphen range) → ranges, or undefined. */
function parseAlternative(alt: string): Range[] | undefined {
  const hyphen = /^\s*(\S+)\s+-\s+(\S+)\s*$/.exec(alt);
  if (hyphen) {
    const lo = parseVersionParts(hyphen[1]!);
    const hi = parseVersionParts(hyphen[2]!);
    if (!lo || !hi) return undefined;
    // "8.2 - 8.4" is >=8.2.0 <8.5.0; "8.2.0 - 8.4.1" is >=8.2.0 <=8.4.1 (composer's rule).
    return [{ lo: { v: lo.v, inclusive: true }, hi: hi.parts >= 3 ? { v: hi.v, inclusive: true } : { v: hi.parts === 2 ? bump(hi.v, 1) : bump(hi.v, 0), inclusive: false } }];
  }
  const tokens = alt.trim().split(/[\s,]+/).filter(Boolean);
  if (!tokens.length) return undefined;
  const ranges: Range[] = [];
  for (const tok of tokens) {
    const r = parseConstraintToken(tok);
    if (!r) return undefined;
    ranges.push(r);
  }
  return ranges;
}

/**
 * Does `version` satisfy a composer `require.php` constraint such as
 * `"^8.4 || ^8.5"`, `">=8.2"`, `"~8.3.0"`, `"8.2 - 8.4"`? Returns undefined when
 * the constraint (or the version) cannot be interpreted — callers must treat that
 * as "check by hand", never as satisfied.
 */
export function phpSatisfies(constraint: string, version: string): boolean | undefined {
  const v = parsePhpVersion(version);
  if (!v || !constraint.trim()) return undefined;
  const alternatives = constraint.split(/\|\|?/).map((s) => s.trim());
  const parsed: Range[][] = [];
  for (const alt of alternatives) {
    const ranges = parseAlternative(alt);
    if (!ranges) return undefined;
    parsed.push(ranges);
  }
  return parsed.some((ranges) => ranges.every((r) => inRange(v, r)));
}

/**
 * The lowest PHP 8 major.minor that satisfies a constraint — what `php-prepare`
 * should install. `"^8.4 || ^8.5"` → "8.4". Undefined when nothing in 8.0–8.9
 * does, or the constraint cannot be interpreted; this tool only knows PHP 8.
 */
export function phpVersionFor(constraint: string): string | undefined {
  for (let minor = 0; minor <= 9; minor += 1) {
    const ok = phpSatisfies(constraint, `8.${minor}.0`);
    if (ok === undefined) return undefined;
    if (ok) return `8.${minor}`;
  }
  return undefined;
}

/** `require.php` out of a composer.json body OR just its `"php": "…"` line. */
export function composerPhpRequirement(text: string): string | undefined {
  try {
    const j = JSON.parse(text) as { require?: { php?: unknown } };
    const php = j?.require?.php;
    return typeof php === "string" ? php : undefined;
  } catch {
    /* a single grep'd line — fall through */
  }
  const m = /"php"\s*:\s*"([^"]+)"/.exec(text);
  return m?.[1];
}

// --- GitHub reads ---------------------------------------------------------------------

export const PANEL_RAW_BASE = "https://raw.githubusercontent.com/pelican-dev/panel";
export const WINGS_LATEST_URL = "https://api.github.com/repos/pelican-dev/wings/releases/latest";

/** The PHP constraint a panel release declares, from its own composer.json. */
export async function fetchReleasePhpRequirement(tag: string): Promise<{ php?: string; error?: string }> {
  let t: string;
  try {
    t = assertReleaseTag(tag);
  } catch (e) {
    return { error: e instanceof Error ? e.message : String(e) };
  }
  try {
    const res = await fetch(`${PANEL_RAW_BASE}/${t}/composer.json`, { signal: AbortSignal.timeout(10_000) });
    if (!res.ok) return { error: `GitHub answered HTTP ${res.status} for ${t}/composer.json` };
    const php = composerPhpRequirement(await res.text());
    return php ? { php } : { error: `${t}/composer.json has no require.php` };
  } catch (e) {
    return { error: e instanceof Error ? e.message : String(e) };
  }
}

/** Latest Wings release tag. Best-effort, like `latestPanelRelease`. */
export async function latestWingsRelease(): Promise<{ tag?: string; error?: string }> {
  try {
    const res = await fetch(WINGS_LATEST_URL, { headers: { Accept: "application/vnd.github+json" }, signal: AbortSignal.timeout(10_000) });
    if (!res.ok) return { error: `GitHub answered HTTP ${res.status}` };
    const body = JSON.parse(await res.text()) as { tag_name?: string };
    return body?.tag_name ? { tag: body.tag_name } : { error: "GitHub returned no tag_name" };
  } catch (e) {
    return { error: e instanceof Error ? e.message : String(e) };
  }
}

// --- The runtime report appended to panel_version -----------------------------------------

export interface RuntimeReportInput {
  status: HostStatus;
  /** From `hostStatusProblem` — the helper is missing or sudo refused. */
  helperProblem?: string;
  installedPanel?: string;
  /** The installed panel's own `require.php`. */
  currentPhpRequirement?: string;
  /** The latest panel release and its `require.php`. */
  releaseTag?: string;
  releasePhpRequirement?: string;
  releaseRequirementError?: string;
  latestWingsTag?: string;
  latestWingsError?: string;
  /** The PHP minor serving the panel and its php<ver>-fpm apt picture. */
  phpPackage?: { phpVersion: string; policy: AptPolicy };
}

/** Human text: PHP picture, the requirement verdict, Wings, and the helper state. */
export function runtimeReport(i: RuntimeReportInput): string {
  const s = i.status;
  const lines: string[] = [];

  if (s.phpCli) {
    const extras = [
      s.phpDefault ? `CLI default php${s.phpDefault}` : "",
      s.phpInstalled.length ? `installed: ${s.phpInstalled.join(", ")}` : "",
      s.phpFpmActive.length ? `php-fpm active: ${s.phpFpmActive.join(", ")}` : "",
    ].filter(Boolean);
    const nginx = s.nginxSocket ? `; nginx fastcgi socket ${s.nginxSocket}${s.nginxSite ? ` (${s.nginxSite})` : ""}` : "";
    lines.push(`PHP ${s.phpCli}${extras.length ? ` (${extras.join("; ")})` : ""}${nginx}.`);
  } else {
    lines.push("PHP version: unknown — the host did not answer the php probe.");
  }

  if (i.phpPackage) {
    const { phpVersion: v, policy: p } = i.phpPackage;
    const pkg = `php${v}-fpm`;
    if (!p.installed) {
      lines.push(`Package ${pkg}: not installed according to apt (or apt-cache could not be read).`);
    } else if (!p.candidate) {
      lines.push(`Package ${pkg} ${p.installed}: apt reports no candidate, so pending patch releases are unknown.`);
    } else if (p.installed !== p.candidate) {
      // apt never offers a downgrade as the candidate, so a differing candidate is an upgrade.
      lines.push(
        `Package ${pkg} is BEHIND: installed ${p.installed}, apt candidate ${p.candidate} — PHP ${upstreamPhpVersion(p.installed)} → ${upstreamPhpVersion(p.candidate)} ` +
          `is a same-minor patch release (this is how PHP security fixes ship). Run panel_prepare_runtime with phpVersion '${v}' and patchUpdate: true.`,
      );
    } else {
      lines.push(`Package ${pkg} ${p.installed} matches the apt candidate (as of the host's last package-list refresh).`);
    }
  }

  if (i.releaseTag) {
    const req = i.releasePhpRequirement;
    if (req) {
      const sat = s.phpCli ? phpSatisfies(req, s.phpCli) : undefined;
      const want = phpVersionFor(req);
      if (sat === true) lines.push(`Release ${i.releaseTag} requires PHP ${req} — met.`);
      else if (sat === false)
        lines.push(
          `Release ${i.releaseTag} requires PHP ${req} — NOT met by ${s.phpCli}. Run panel_prepare_runtime${want ? ` (phpVersion '${want}')` : ""} BEFORE panel_upgrade; panel_upgrade refuses until this is met.`,
        );
      else lines.push(`Release ${i.releaseTag} requires PHP ${req} — could not compare with the installed version; check by hand.`);
    } else {
      lines.push(`Could not read the PHP requirement of ${i.releaseTag} (${i.releaseRequirementError ?? "unknown error"}).`);
    }
  }
  if (i.currentPhpRequirement) {
    lines.push(`The installed panel${i.installedPanel ? ` (${i.installedPanel})` : ""} declares PHP ${i.currentPhpRequirement}.`);
  }

  if (s.wings) {
    let w = `Wings ${s.wings}${s.wingsActive ? ` (service ${s.wingsActive})` : ""}`;
    if (i.latestWingsTag) {
      const c = compareVersions(s.wings, i.latestWingsTag);
      w +=
        c === undefined
          ? `; latest Wings release ${i.latestWingsTag} — could not compare, check by hand.`
          : c < 0
            ? `; latest Wings release ${i.latestWingsTag} — behind. Run wings_update (expectVersion '${s.wings}', tag '${i.latestWingsTag}') AFTER the panel upgrade; Pelican ships panel and Wings in lockstep.`
            : c === 0
              ? `; that is the latest Wings release.`
              : `; ahead of the latest Wings release ${i.latestWingsTag}.`;
    } else {
      w += `; could not reach GitHub for the latest Wings release (${i.latestWingsError ?? "unknown error"}).`;
    }
    lines.push(w);
  } else {
    lines.push(`Wings version: unknown${i.helperProblem ? " — it is read by the host helper, which is not usable yet (see below)" : ""}.`);
  }

  lines.push(i.helperProblem ? `Host helper: ${i.helperProblem}` : `Host helper: installed${s.helperVersion ? ` (v${s.helperVersion})` : ""}, sudo rule works.`);
  return lines.join("\n");
}
