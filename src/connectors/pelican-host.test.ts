import { describe, it, expect, vi, afterEach } from "vitest";
import { spawnSync } from "node:child_process";
import { readFileSync, statSync } from "node:fs";
import { fileURLToPath } from "node:url";

vi.mock("./ssh-exec.js", async () => {
  const actual = await vi.importActual<typeof import("./ssh-exec.js")>("./ssh-exec.js");
  return { ...actual, runSsh: vi.fn() };
});

import { runSsh } from "./ssh-exec.js";
import { pelicanConnector } from "./pelican.js";
import {
  HELPER_PATH,
  HOST_STATUS_COMMAND,
  helperCommand,
  currentPhpRequirementCommand,
  parseHostStatus,
  parseWingsVersion,
  phpSatisfies,
  phpVersionFor,
  composerPhpRequirement,
  assertPhpVersionArg,
  assertWingsTag,
  assertPanelVersion,
  PANEL_UPGRADE_STEP_NAMES,
  parseUpgradeResult,
  sudoersLine,
  sudoersInstallSnippet,
  helperInstallSnippet,
  classifyHelperFailure,
  hostStatusProblem,
  runtimeReport,
  sshUserOf,
  compareVersions,
} from "./pelican-host.js";
import { checkCommand, DEFAULT_DENY } from "./command-policy.js";
import type { Credential, Target, ToolContext } from "./types.js";

// --- fixtures -------------------------------------------------------------------------

const PANEL = "/var/www/pelican";
const sshTarget: Target = { name: "panel-host", type: "ssh", host: "192.168.1.48", credentialRef: "panel-host-ssh" };
const panelTarget: Target = {
  name: "pelican-panel",
  type: "pelican",
  host: "192.168.1.48",
  credentialRef: "pelican-panel",
  options: { ownerUserId: 7, sshTarget: "panel-host" },
};
const sshCred: Credential = { ref: "panel-host-ssh", username: "skeleton", password: "pw", fields: {}, uris: [] };

function ctx(): ToolContext {
  return {
    target: panelTarget,
    getCredential: async () => ({ ref: "pelican-panel", fields: { application_key: "papp_x", client_key: "pacc_y" }, uris: [] }),
    resolveTarget: (n: string) => (n === "panel-host" ? sshTarget : undefined),
    resolveCredential: async () => sshCred,
  };
}
const tool = (name: string) => pelicanConnector.buildTools(panelTarget).find((t) => t.name === name)!;

/** The ONLY command strings these tools may send. Anything else fails the test. */
const VERSION_CMD = `grep -m1 "'version'" ${PANEL}/config/app.php`;
const COMPOSER_CMD = currentPhpRequirementCommand(PANEL);
const PREPARE_CMD = helperCommand("php-prepare", "8.4");
const WINGS_CMD = helperCommand("wings-update", "v1.0.0-rc.1");
const UPGRADE_CMD = helperCommand("panel-upgrade", "1.0.0-beta35", "v1.0.0-rc.1");
const UPGRADE_CMD_PINNED_SKIP = helperCommand("panel-upgrade", "1.0.0-beta35", "v1.0.0-rc.2", true);
const EXPECTED_COMMANDS = new Set([VERSION_CMD, HOST_STATUS_COMMAND, COMPOSER_CMD, PREPARE_CMD, WINGS_CMD, UPGRADE_CMD, UPGRADE_CMD_PINNED_SKIP]);

type Reply = { stdout?: string; stderr?: string; code?: number };
let sent: string[] = [];
/** A fake panel host: exact command → reply (or a thrower, for transport errors).
 *  An unknown command throws, so a tool that strays from its fixed command set
 *  fails loudly. */
function host(replies: Record<string, Reply | (() => never)>) {
  vi.mocked(runSsh).mockImplementation(async (_t, _c, cmd: string) => {
    sent.push(cmd);
    const r = replies[cmd];
    if (!r) throw new Error(`unexpected SSH command: ${cmd}`);
    if (typeof r === "function") return r();
    return { stdout: r.stdout ?? "", stderr: r.stderr ?? "", code: r.code ?? 0 };
  });
}

const VERSION_LINE = { stdout: "    'version' => '1.0.0-beta35',\n" };
const COMPOSER_LINE = { stdout: '    "php": "^8.3 || ^8.4 || ^8.5",\n' };
const status = (over: Record<string, string> = {}) =>
  Object.entries({
    helper: "1",
    helper_version: "1",
    panel_root: PANEL,
    php_cli: "8.3.6",
    php_default: "8.3",
    php_installed: "8.3",
    php_fpm_active: "8.3",
    nginx_site: "/etc/nginx/sites-available/pelican.conf",
    nginx_socket: "/run/php/php8.3-fpm.sock",
    nginx_active: "active",
    wings: "1.0.0-beta22",
    wings_active: "active",
    ...over,
  })
    .map(([k, v]) => `${k}=${v}`)
    .join("\n") + "\n";
const STATUS_83 = { stdout: status() };
const STATUS_84 = { stdout: status({ php_cli: "8.4.1", php_default: "8.4", php_installed: "8.3 8.4", php_fpm_active: "8.3 8.4", nginx_socket: "/run/php/php8.4-fpm.sock" }) };
const STATUS_NO_HELPER = { stdout: "helper=0\nphp_cli=8.3.6\n" };
const STATUS_SUDO_DENIED = { stdout: "helper=1\nhelper_rc=1\nphp_cli=8.3.6\n", stderr: "sudo: a password is required\n", code: 0 };

function mockGithub(opts: { latestPanel?: string; latestWings?: string; composer?: Record<string, string>; composerStatus?: number } = {}) {
  const reply = (code: number, body: string) => ({ ok: code < 300, status: code, text: async () => body, json: async () => JSON.parse(body) });
  vi.stubGlobal(
    "fetch",
    vi.fn(async (url: string) => {
      if (url.startsWith("https://api.github.com/repos/pelican-dev/panel/releases/latest")) return reply(200, JSON.stringify({ tag_name: opts.latestPanel ?? "v1.0.0-rc.1" }));
      if (url.startsWith("https://api.github.com/repos/pelican-dev/wings/releases/latest")) return reply(200, JSON.stringify({ tag_name: opts.latestWings ?? "v1.0.0-rc.1" }));
      const m = /^https:\/\/raw\.githubusercontent\.com\/pelican-dev\/panel\/([^/]+)\/composer\.json$/.exec(url);
      if (m) {
        if (opts.composerStatus) return reply(opts.composerStatus, "");
        const php = (opts.composer ?? { "v1.0.0-rc.1": "^8.4 || ^8.5" })[m[1]!];
        return php ? reply(200, JSON.stringify({ name: "pelican-dev/panel", require: { php, "ext-intl": "*" } })) : reply(404, "not found");
      }
      throw new Error(`unexpected fetch ${url}`);
    }),
  );
}

afterEach(() => {
  // Every command that reached the (mocked) host must be one of the fixed strings.
  for (const cmd of sent) expect(EXPECTED_COMMANDS.has(cmd), `unexpected command sent: ${cmd}`).toBe(true);
  sent = [];
  vi.restoreAllMocks();
  vi.unstubAllGlobals();
});

// --- pure: arguments & commands --------------------------------------------------------

describe("helper arguments and the fixed commands", () => {
  it("accepts only a PHP 8 major.minor", () => {
    expect(assertPhpVersionArg(" 8.4 ")).toBe("8.4");
    expect(assertPhpVersionArg("8.10")).toBe("8.10");
    for (const bad of ["8.4; id", "7.4", "8", "8.4.1", "9.0", "$(id)", "8.4\nid"]) expect(() => assertPhpVersionArg(bad)).toThrow(/major\.minor/);
  });

  it("accepts only a release tag shape (and adds the leading v)", () => {
    expect(assertWingsTag("v1.0.0-rc.1")).toBe("v1.0.0-rc.1");
    expect(assertWingsTag("1.0.0-beta22")).toBe("v1.0.0-beta22");
    for (const bad of ["v1.0.0-rc.1;x", "latest", "../x", "v1.0", "v1.0.0-rc.1 x", `v1.0.0-${"a".repeat(40)}`]) {
      expect(() => assertWingsTag(bad)).toThrow(/release tag/);
    }
  });

  it("builds exactly `sudo -n <helper> <subcommand> '<arg>'` and nothing else", () => {
    expect(helperCommand("status")).toBe(`sudo -n ${HELPER_PATH} status`);
    expect(PREPARE_CMD).toBe(`sudo -n /usr/local/sbin/skeleton-key-pelican-host.sh php-prepare '8.4'`);
    expect(WINGS_CMD).toBe(`sudo -n /usr/local/sbin/skeleton-key-pelican-host.sh wings-update 'v1.0.0-rc.1'`);
    expect(UPGRADE_CMD).toBe(`sudo -n /usr/local/sbin/skeleton-key-pelican-host.sh panel-upgrade '1.0.0-beta35' 'v1.0.0-rc.1'`);
    expect(UPGRADE_CMD_PINNED_SKIP).toBe(`sudo -n /usr/local/sbin/skeleton-key-pelican-host.sh panel-upgrade '1.0.0-beta35' 'v1.0.0-rc.2' '--skip-backup'`);
    expect(() => helperCommand("php-prepare", "8.4 && id")).toThrow();
    expect(() => helperCommand("wings-update", "'; id; '")).toThrow();
    expect(() => helperCommand("panel-upgrade", "1.0.0-beta35; id", "v1.0.0-rc.1")).toThrow(/panel version/);
    expect(() => helperCommand("panel-upgrade", "1.0.0-beta35", "latest")).toThrow(/release tag/);
    expect(assertPanelVersion(" 1.0.0-beta35 ")).toBe("1.0.0-beta35");
    expect(() => assertPanelVersion("v1.0.0-beta35")).toThrow(/panel version/);
  });

  it("every fixed command survives the destructive-command deny list", () => {
    for (const cmd of [HOST_STATUS_COMMAND, PREPARE_CMD, WINGS_CMD, UPGRADE_CMD, UPGRADE_CMD_PINNED_SKIP, COMPOSER_CMD, helperCommand("status")]) {
      expect(checkCommand(cmd).allowed, cmd).toBe(true);
    }
  });

  it("the status read degrades to an unprivileged php probe when the helper is missing or sudo refuses", () => {
    expect(HOST_STATUS_COMMAND).toContain(`if [ -x "$H" ]; then sudo -n "$H" status;`);
    expect(HOST_STATUS_COMMAND).toContain("echo helper=0;");
    expect(HOST_STATUS_COMMAND).toContain('echo "helper_rc=$rc"');
    expect(HOST_STATUS_COMMAND).toMatch(/php -r 'echo "php_cli=" \. PHP_VERSION/);
  });
});

// --- pure: parsing ----------------------------------------------------------------------

describe("helper output parsing", () => {
  it("parses the status block and ignores anything that is not key=value", () => {
    const s = parseHostStatus(`PHP 8.4.1 (cli) (built: Jan 1 2026)\nskeleton-key-pelican-host: done\n${STATUS_84.stdout}`);
    expect(s.helper).toBe(true);
    expect(s.helperVersion).toBe(1);
    expect(s.phpCli).toBe("8.4.1");
    expect(s.phpDefault).toBe("8.4");
    expect(s.phpInstalled).toEqual(["8.3", "8.4"]);
    expect(s.phpFpmActive).toEqual(["8.3", "8.4"]);
    expect(s.nginxSocket).toBe("/run/php/php8.4-fpm.sock");
    expect(s.wings).toBe("1.0.0-beta22");
    expect(s.wingsActive).toBe("active");
    expect(s.helperRc).toBeUndefined();
  });

  it("parses the fallback shapes", () => {
    expect(parseHostStatus(STATUS_NO_HELPER.stdout)).toMatchObject({ helper: false, phpCli: "8.3.6", phpInstalled: [], wings: undefined });
    expect(parseHostStatus(STATUS_SUDO_DENIED.stdout)).toMatchObject({ helper: true, helperRc: 1, phpCli: "8.3.6" });
    expect(parseHostStatus("wings=\nphp_cli=\n").wings).toBeUndefined();
  });

  it("parses the panel-upgrade result in both its shapes", () => {
    const ok = parseUpgradeResult(
      `panel_before=1.0.0-beta35\nupgrade_log=/var/log/skeleton-key/panel-upgrade-1.log\ndb_backup=/var/www/pelican/storage/pelican-db-backup-1.sqlite\nsteps_done=${PANEL_UPGRADE_STEP_NAMES.join(" ")}\nmaintenance=0\npanel_after=1.0.0-rc.1\n`,
    );
    expect(ok).toMatchObject({ before: "1.0.0-beta35", after: "1.0.0-rc.1", alreadyCurrent: false, maintenance: false, dbBackup: "/var/www/pelican/storage/pelican-db-backup-1.sqlite" });
    expect(ok.stepsDone).toEqual([...PANEL_UPGRADE_STEP_NAMES]);
    const bad = parseUpgradeResult("panel_before=1.0.0-beta35\nupgrade_log=/var/log/skeleton-key/x.log\ndb_backup=skipped\nfailed_step=composer-install\nsteps_done=download-release download-checksum\nmaintenance=1\n");
    expect(bad).toMatchObject({ failedStep: "composer-install", maintenance: true, dbBackup: "skipped", stepsDone: ["download-release", "download-checksum"] });
    expect(parseUpgradeResult("panel_before=1.0.0-rc.1\npanel_after=1.0.0-rc.1\nalready_current=1\n").alreadyCurrent).toBe(true);
    expect(parseUpgradeResult("").maintenance).toBeUndefined();
  });

  it("reads the version out of `wings version` output", () => {
    expect(parseWingsVersion("wings v1.0.0-beta22\nCopyright © 2018 - 2026 Dane Everitt & Contributors")).toBe("1.0.0-beta22");
    expect(parseWingsVersion("1.0.0-rc.1")).toBe("1.0.0-rc.1");
    expect(parseWingsVersion("wings vdevelop")).toBeUndefined();
    expect(parseHostStatus("wings=wings v1.0.0-beta22\n").wings).toBe("1.0.0-beta22");
  });
});

// --- pure: composer constraints ---------------------------------------------------------

describe("composer PHP constraints", () => {
  it("evaluates Pelican's real constraints (rc.1 raised the floor to 8.4)", () => {
    expect(phpSatisfies("^8.4 || ^8.5", "8.3.6")).toBe(false);
    expect(phpSatisfies("^8.4 || ^8.5", "8.4.0")).toBe(true);
    expect(phpSatisfies("^8.4 || ^8.5", "8.5.2")).toBe(true);
    expect(phpSatisfies("^8.4 || ^8.5", "9.0.0")).toBe(false);
    expect(phpSatisfies("^8.3 || ^8.4 || ^8.5", "8.4.0")).toBe(true); // beta35 can run on 8.4
    expect(phpSatisfies("^8.3 || ^8.4 || ^8.5", "8.2.9")).toBe(false);
  });

  it("understands the other operators composer allows", () => {
    expect(phpSatisfies(">=8.2", "8.1.30")).toBe(false);
    expect(phpSatisfies(">=8.2", "8.2.0")).toBe(true);
    expect(phpSatisfies(">8.4.0", "8.4.0")).toBe(false);
    expect(phpSatisfies("<8.5", "8.4.9")).toBe(true);
    expect(phpSatisfies("~8.3.0", "8.3.9")).toBe(true);
    expect(phpSatisfies("~8.3.0", "8.4.0")).toBe(false);
    expect(phpSatisfies("~8.3", "8.4.0")).toBe(true);
    expect(phpSatisfies("~8.3", "9.0.0")).toBe(false);
    expect(phpSatisfies("8.2 - 8.4", "8.4.9")).toBe(true);
    expect(phpSatisfies("8.2 - 8.4", "8.5.0")).toBe(false);
    expect(phpSatisfies("8.4.*", "8.4.3")).toBe(true);
    expect(phpSatisfies("8.4.*", "8.5.0")).toBe(false);
    expect(phpSatisfies(">=8.2 <8.5", "8.4.0")).toBe(true);
    expect(phpSatisfies(">=8.2, <8.5", "8.5.0")).toBe(false);
    expect(phpSatisfies("*", "8.0.0")).toBe(true);
    expect(phpSatisfies("8.4", "8.4.7")).toBe(true);
  });

  it("answers undefined — never 'satisfied' — for anything it cannot interpret", () => {
    expect(phpSatisfies("!=8.3", "8.4.0")).toBeUndefined();
    expect(phpSatisfies("garbage", "8.4.0")).toBeUndefined();
    expect(phpSatisfies("", "8.4.0")).toBeUndefined();
    expect(phpSatisfies("^8.4", "unknown")).toBeUndefined();
    expect(phpSatisfies("8.4.0RC1", "8.4.0")).toBeUndefined(); // a prerelease-pinned constraint — not guessed at
  });

  it("picks the lowest PHP 8 release that satisfies a constraint", () => {
    expect(phpVersionFor("^8.4 || ^8.5")).toBe("8.4");
    expect(phpVersionFor(">=8.2")).toBe("8.2");
    expect(phpVersionFor(">8.4.0")).toBe("8.5");
    expect(phpVersionFor("^9.0")).toBeUndefined();
    expect(phpVersionFor("garbage")).toBeUndefined();
  });

  it("reads require.php from a whole composer.json or the grep'd line", () => {
    expect(composerPhpRequirement(JSON.stringify({ require: { php: "^8.4 || ^8.5" } }))).toBe("^8.4 || ^8.5");
    expect(composerPhpRequirement('    "php": "^8.3 || ^8.4 || ^8.5",\n')).toBe("^8.3 || ^8.4 || ^8.5");
    expect(composerPhpRequirement(JSON.stringify({ require: {} }))).toBeUndefined();
    expect(composerPhpRequirement("")).toBeUndefined();
  });

  it("compareVersions ranks the prerelease stages so beta → rc reads as 'behind'", () => {
    expect(compareVersions("1.0.0-beta22", "v1.0.0-rc.1")).toBe(-1);
    expect(compareVersions("1.0.0-rc.1", "v1.0.0-rc.1")).toBe(0);
    expect(compareVersions("1.0.0-foo1", "v1.0.0-rc.1")).toBeUndefined();
  });
});

// --- pure: hints ------------------------------------------------------------------------

describe("the sudoers hint names one rule and nothing broader", () => {
  it("derives the rule from the SSH user", () => {
    expect(sudoersLine("skeleton")).toBe("skeleton ALL=(root) NOPASSWD: /usr/local/sbin/skeleton-key-pelican-host.sh");
    expect(sudoersInstallSnippet("skeleton")).toContain("sudo tee /etc/sudoers.d/skeleton-key-pelican-host");
    expect(sudoersInstallSnippet("skeleton")).toContain("sudo chmod 0440 /etc/sudoers.d/skeleton-key-pelican-host");
    expect(sudoersInstallSnippet("skeleton")).toContain("sudo visudo -cf");
    const snippet = helperInstallSnippet("skeleton");
    expect(snippet).toContain(`sudo install -o root -g root -m 0755 skeleton-key-pelican-host.sh ${HELPER_PATH}`);
    expect(snippet).toContain(sudoersLine("skeleton"));
    expect(snippet).not.toMatch(/ALL=\(ALL\)|NOPASSWD: ALL/);
  });

  it("takes the user from the credential and refuses to emit a malformed rule", () => {
    expect(sshUserOf(sshCred)).toBe("skeleton");
    expect(sshUserOf({ ref: "x", fields: { username: "deploy-bot" }, uris: [] })).toBe("deploy-bot");
    expect(sshUserOf({ ref: "x", username: "bad user; ALL", fields: {}, uris: [] })).toBe("<ssh-user>");
    expect(sshUserOf({ ref: "x", fields: {}, uris: [] })).toBe("<ssh-user>");
  });

  it("tells a missing helper apart from a denied sudo (the sudo heuristic also matches 'sudo: … not found')", () => {
    expect(classifyHelperFailure({ stdout: "", stderr: `sudo: ${HELPER_PATH}: command not found\n`, code: 1 })).toBe("missing");
    expect(classifyHelperFailure({ stdout: "", stderr: "", code: 127 })).toBe("missing");
    expect(classifyHelperFailure({ stdout: "", stderr: "sudo: a password is required\n", code: 1 })).toBe("sudo");
    expect(classifyHelperFailure({ stdout: "", stderr: "skeleton-key-pelican-host: REFUSED: bad version\n", code: 2 })).toBe("refused");
    expect(classifyHelperFailure({ stdout: "", stderr: "E: Unable to locate package php8.9\n", code: 100 })).toBe("failed");
  });

  it("hostStatusProblem is undefined when the helper answered, else the exact fix", () => {
    expect(hostStatusProblem({ stdout: STATUS_83.stdout, stderr: "", code: 0 }, parseHostStatus(STATUS_83.stdout), "skeleton")).toBeUndefined();
    const missing = hostStatusProblem({ ...STATUS_NO_HELPER, stderr: "", code: 0 }, parseHostStatus(STATUS_NO_HELPER.stdout), "skeleton")!;
    expect(missing).toMatch(/not installed/);
    expect(missing).toContain(sudoersLine("skeleton"));
    const denied = hostStatusProblem({ stdout: STATUS_SUDO_DENIED.stdout, stderr: STATUS_SUDO_DENIED.stderr, code: 0 }, parseHostStatus(STATUS_SUDO_DENIED.stdout), "skeleton")!;
    expect(denied).toMatch(/sudo refused/);
    expect(denied).toContain(sudoersLine("skeleton"));
  });
});

describe("runtimeReport", () => {
  it("names the gap and the exact next calls when the release needs a newer PHP", () => {
    const text = runtimeReport({
      status: parseHostStatus(STATUS_83.stdout),
      installedPanel: "1.0.0-beta35",
      currentPhpRequirement: "^8.3 || ^8.4 || ^8.5",
      releaseTag: "v1.0.0-rc.1",
      releasePhpRequirement: "^8.4 || ^8.5",
      latestWingsTag: "v1.0.0-rc.1",
    });
    expect(text).toContain("PHP 8.3.6 (CLI default php8.3; installed: 8.3; php-fpm active: 8.3); nginx fastcgi socket /run/php/php8.3-fpm.sock");
    expect(text).toContain("Release v1.0.0-rc.1 requires PHP ^8.4 || ^8.5 — NOT met by 8.3.6. Run panel_prepare_runtime (phpVersion '8.4') BEFORE panel_upgrade");
    expect(text).toContain("The installed panel (1.0.0-beta35) declares PHP ^8.3 || ^8.4 || ^8.5.");
    expect(text).toContain("Wings 1.0.0-beta22 (service active); latest Wings release v1.0.0-rc.1 — behind. Run wings_update (expectVersion '1.0.0-beta22', tag 'v1.0.0-rc.1') AFTER the panel upgrade");
    expect(text).toContain("Host helper: installed (v1), sudo rule works.");
  });

  it("says met / current when there is nothing to do", () => {
    const text = runtimeReport({
      status: parseHostStatus(status({ php_cli: "8.4.1", wings: "1.0.0-rc.1" })),
      releaseTag: "v1.0.0-rc.1",
      releasePhpRequirement: "^8.4 || ^8.5",
      latestWingsTag: "v1.0.0-rc.1",
    });
    expect(text).toContain("requires PHP ^8.4 || ^8.5 — met.");
    expect(text).toContain("that is the latest Wings release.");
  });

  it("reports an unusable helper instead of guessing the Wings version", () => {
    const text = runtimeReport({ status: parseHostStatus(STATUS_NO_HELPER.stdout), helperProblem: "the host helper is not installed (…)" });
    expect(text).toContain("Wings version: unknown — it is read by the host helper");
    expect(text).toContain("Host helper: the host helper is not installed");
  });
});

// --- the shipped helper script ------------------------------------------------------------

describe("scripts/host/skeleton-key-pelican-host.sh", () => {
  const script = fileURLToPath(new URL("../../scripts/host/skeleton-key-pelican-host.sh", import.meta.url));
  const run = (...args: string[]) => spawnSync("bash", [script, ...args], { encoding: "utf8" });

  it("is executable and parses", () => {
    expect(statSync(script).mode & 0o111).not.toBe(0);
    expect(spawnSync("bash", ["-n", script], { encoding: "utf8" }).status).toBe(0);
  });

  it("exits 2 for anything but the three fixed subcommands, and validates before touching privilege", () => {
    expect(run().status).toBe(2);
    expect(run("bogus").status).toBe(2);
    expect(run("status", "extra").status).toBe(2);
    expect(run("php-prepare").status).toBe(2);
    expect(run("php-prepare", "8.4; id").status).toBe(2);
    expect(run("php-prepare", "7.4").status).toBe(2);
    expect(run("wings-update", "v1.0.0-rc.1;x").status).toBe(2);
    expect(run("wings-update", "latest").status).toBe(2);
    expect(run("wings-update", "v1.0.0-rc.1", "more").status).toBe(2);
    expect(run("php-prepare", "8.4; id").stderr).toMatch(/REFUSED: php-prepare: version must look like 8.4/);
  });

  it("refuses to do privileged work as a non-root user (so a stray direct call does nothing)", () => {
    if (process.getuid?.() === 0) return; // CI as root would get further; the check is for the SSH user
    const r = run("php-prepare", "8.4");
    expect(r.status).toBe(2);
    expect(r.stderr).toMatch(/must run as root/);
    expect(run("wings-update", "v1.0.0-rc.1").status).toBe(2);
  });

  it("panel-upgrade: exact arity, strict shapes, one literal option — all checked before privilege", () => {
    expect(run("panel-upgrade").status).toBe(2);
    expect(run("panel-upgrade", "1.0.0-beta35").status).toBe(2);
    expect(run("panel-upgrade", "1.0.0; id", "v1.0.0-rc.1").status).toBe(2);
    expect(run("panel-upgrade", "1.0.0; id", "v1.0.0-rc.1").stderr).toMatch(/REFUSED: panel-upgrade: version must look like 1.0.0-beta35/);
    expect(run("panel-upgrade", "1.0.0-beta35", "latest").status).toBe(2);
    expect(run("panel-upgrade", "1.0.0-beta35", "v1.0.0-rc.1", "--nope").status).toBe(2);
    expect(run("panel-upgrade", "1.0.0-beta35", "v1.0.0-rc.1", "--skip-backup", "x").status).toBe(2);
    if (process.getuid?.() !== 0) {
      const r = run("panel-upgrade", "1.0.0-beta35", "v1.0.0-rc.1", "--skip-backup");
      expect(r.status).toBe(2);
      expect(r.stderr).toMatch(/must run as root/);
    }
  });

  it("panel-upgrade runs the documented steps in order, as the panel user, with download + pre-flight + backup before maintenance mode", () => {
    const text = readFileSync(script, "utf8");
    const positions = PANEL_UPGRADE_STEP_NAMES.map((n) => text.indexOf(`step ${n} `));
    for (const [i, p] of positions.entries()) expect(p, PANEL_UPGRADE_STEP_NAMES[i]).toBeGreaterThan(0);
    expect([...positions].sort((a, b) => a - b)).toEqual(positions);
    expect(positions[PANEL_UPGRADE_STEP_NAMES.indexOf("maintenance-mode")]).toBeGreaterThan(positions[PANEL_UPGRADE_STEP_NAMES.indexOf("db-backup")]!);
    // artisan and tar never run as root (composer's step line continues onto the next line, so check it by name)
    for (const line of text.split("\n").filter((l) => /^\s*step \S+ .*(artisan|tar -xzf)/.test(l))) expect(line).toContain("as_panel_user");
    expect(text).toMatch(/step composer-install as_panel_user/);
    expect(text).toMatch(/step preflight-platform as_panel_user/);
    expect(text).toContain("check-platform-reqs --lock --no-dev");
    expect(text).toContain('MYSQL_PWD="$DB_PASSWORD"');
    expect(text).not.toMatch(/-p"\$DB_PASSWORD"/); // the password never goes on a command line
    expect(text).toContain("trap '' HUP");
  });

  it("contains none of the deny-listed words, so the policy never trips on it", () => {
    const text = readFileSync(script, "utf8");
    for (const pattern of DEFAULT_DENY) expect(text, String(pattern)).not.toMatch(pattern);
    // and the owner-facing contract in its header
    expect(text).toContain("ALL=(root) NOPASSWD: /usr/local/sbin/skeleton-key-pelican-host.sh");
    expect(text).toMatch(/^PANEL_ROOT=\/var\/www\/pelican$/m);
  });
});

// --- tools ----------------------------------------------------------------------------------

describe("panel_version reports the whole upgrade story in one read", () => {
  it("installed/latest + PHP vs requirement + Wings vs latest + helper state", async () => {
    mockGithub();
    host({ [VERSION_CMD]: VERSION_LINE, [HOST_STATUS_COMMAND]: STATUS_83, [COMPOSER_CMD]: COMPOSER_LINE });
    const res = await tool("panel_version").run({}, ctx());
    expect(res.isError).toBeFalsy();
    expect(res.text).toContain("installed **1.0.0-beta35**, latest released **v1.0.0-rc.1**. An upgrade is available");
    expect(res.text).toContain("PHP 8.3.6");
    expect(res.text).toContain("/run/php/php8.3-fpm.sock");
    expect(res.text).toContain("requires PHP ^8.4 || ^8.5 — NOT met by 8.3.6. Run panel_prepare_runtime (phpVersion '8.4')");
    expect(res.text).toContain("Wings 1.0.0-beta22 (service active); latest Wings release v1.0.0-rc.1 — behind");
    expect(res.text).toContain("Host helper: installed (v1), sudo rule works.");
    expect(sent).toEqual([VERSION_CMD, HOST_STATUS_COMMAND, COMPOSER_CMD]);
  });

  it("still answers when the helper is not installed, with the install steps", async () => {
    mockGithub();
    host({ [VERSION_CMD]: VERSION_LINE, [HOST_STATUS_COMMAND]: STATUS_NO_HELPER, [COMPOSER_CMD]: COMPOSER_LINE });
    const res = await tool("panel_version").run({}, ctx());
    expect(res.isError).toBeFalsy();
    expect(res.text).toContain("installed **1.0.0-beta35**");
    expect(res.text).toContain("NOT met by 8.3.6"); // the unprivileged probe still gives the PHP version
    expect(res.text).toContain("Wings version: unknown");
    expect(res.text).toContain(`sudo install -o root -g root -m 0755 skeleton-key-pelican-host.sh ${HELPER_PATH}`);
    expect(res.text).toContain(sudoersLine("skeleton"));
  });

  it("names the one sudoers line when the helper is installed but sudo refuses", async () => {
    mockGithub();
    host({ [VERSION_CMD]: VERSION_LINE, [HOST_STATUS_COMMAND]: STATUS_SUDO_DENIED, [COMPOSER_CMD]: COMPOSER_LINE });
    const res = await tool("panel_version").run({}, ctx());
    expect(res.isError).toBeFalsy();
    expect(res.text).toMatch(/Host helper: sudo refused to run the host helper without a password for SSH user 'skeleton'/);
    expect(res.text).toContain("skeleton ALL=(root) NOPASSWD: /usr/local/sbin/skeleton-key-pelican-host.sh");
  });
});

describe("panel_prepare_runtime", () => {
  const prepare = (input: Record<string, unknown>) => tool("panel_prepare_runtime").run(input, ctx());

  it("confirm names the host, the PHP version, the release and the helper", () => {
    const text = tool("panel_prepare_runtime").confirm!({ phpVersion: "8.4", release: "v1.0.0-rc.1" }, panelTarget);
    expect(text).toContain("PREPARE the PHP runtime on Pelican host 'panel-host'");
    expect(text).toContain("install PHP 8.4");
    expect(text).toContain("php8.4-fpm");
    expect(text).toContain("for panel release v1.0.0-rc.1");
    expect(text).toContain(`${HELPER_PATH} via sudo -n and nothing else`);
    expect(tool("panel_prepare_runtime").confirm!({ phpVersion: "8.4" }, panelTarget)).toContain("for panel release latest");
  });

  it("refuses a hostile phpVersion before anything is sent", async () => {
    host({});
    const res = await prepare({ phpVersion: "8.4; id" });
    expect(res.isError).toBe(true);
    expect(res.text).toMatch(/major\.minor/);
    expect(sent).toEqual([]);
  });

  it("refuses a PHP version the release's composer.json does not allow", async () => {
    mockGithub();
    host({ [HOST_STATUS_COMMAND]: STATUS_83 });
    const res = await prepare({ phpVersion: "8.3" });
    expect(res.isError).toBe(true);
    expect(res.text).toMatch(/PHP 8.3 does not satisfy v1.0.0-rc.1's requirement '\^8.4 \|\| \^8.5'; the lowest 8.x that does is 8.4/);
    expect(sent.some((c) => c.includes("php-prepare"))).toBe(false);
  });

  it("fails closed when the release's composer.json cannot be read", async () => {
    mockGithub({ composerStatus: 500 });
    host({ [HOST_STATUS_COMMAND]: STATUS_83 });
    const res = await prepare({ phpVersion: "8.4" });
    expect(res.isError).toBe(true);
    expect(res.text).toMatch(/Could not read the PHP requirement of v1.0.0-rc.1 .*refusing to change the runtime/);
    expect(sent).toEqual([]);
  });

  it("is a no-op when the host already runs a satisfying PHP on the right socket", async () => {
    mockGithub();
    host({ [HOST_STATUS_COMMAND]: STATUS_84 });
    const res = await prepare({ phpVersion: "8.4" });
    expect(res.isError).toBeFalsy();
    expect(res.text).toMatch(/Nothing to do: host 'panel-host' already runs PHP 8.4.1/);
    expect(sent).toEqual([HOST_STATUS_COMMAND]);
  });

  it("refuses when the INSTALLED panel could not run on the new PHP", async () => {
    mockGithub();
    host({ [HOST_STATUS_COMMAND]: STATUS_83, [COMPOSER_CMD]: { stdout: '    "php": "~8.3.0",\n' } });
    const res = await prepare({ phpVersion: "8.4" });
    expect(res.isError).toBe(true);
    expect(res.text).toMatch(/installed panel declares PHP ~8.3.0 and would stop working on PHP 8.4 BEFORE the upgrade/);
    expect(sent).toEqual([HOST_STATUS_COMMAND, COMPOSER_CMD]);
  });

  it("refuses when the installed panel's requirement cannot be read, rather than assuming", async () => {
    mockGithub();
    host({ [HOST_STATUS_COMMAND]: STATUS_83, [COMPOSER_CMD]: { stdout: "", stderr: "grep: No such file", code: 2 } });
    const res = await prepare({ phpVersion: "8.4" });
    expect(res.isError).toBe(true);
    expect(res.text).toMatch(/could not read the installed panel's own PHP requirement/);
  });

  it("stops with the install steps when the helper is missing, and with the sudoers line when sudo refuses", async () => {
    mockGithub();
    host({ [HOST_STATUS_COMMAND]: STATUS_NO_HELPER, [COMPOSER_CMD]: COMPOSER_LINE });
    let res = await prepare({ phpVersion: "8.4" });
    expect(res.isError).toBe(true);
    expect(res.text).toMatch(/Cannot prepare the runtime: the host helper is not installed/);
    expect(res.text).toContain(`sudo install -o root -g root -m 0755 skeleton-key-pelican-host.sh ${HELPER_PATH}`);
    expect(sent.some((c) => c.includes("php-prepare"))).toBe(false);

    sent = [];
    host({ [HOST_STATUS_COMMAND]: STATUS_SUDO_DENIED, [COMPOSER_CMD]: COMPOSER_LINE });
    res = await prepare({ phpVersion: "8.4" });
    expect(res.isError).toBe(true);
    expect(res.text).toContain("skeleton ALL=(root) NOPASSWD: /usr/local/sbin/skeleton-key-pelican-host.sh");
    expect(sent.some((c) => c.includes("php-prepare"))).toBe(false);
  });

  it("runs exactly `sudo -n <helper> php-prepare '8.4'` once everything checks out, and reports the new picture", async () => {
    mockGithub();
    host({
      [HOST_STATUS_COMMAND]: STATUS_83,
      [COMPOSER_CMD]: COMPOSER_LINE,
      [PREPARE_CMD]: { stdout: `PHP 8.4.1 (cli) (built: Jan 1 2026)\n${STATUS_84.stdout}`, stderr: "skeleton-key-pelican-host: done\n" },
    });
    const res = await prepare({ phpVersion: "8.4" });
    expect(res.isError).toBeFalsy();
    expect(res.text).toContain("Prepared the PHP runtime on host 'panel-host' for v1.0.0-rc.1 (requires PHP ^8.4 || ^8.5): PHP CLI now **8.4.1** (default php8.4), nginx fastcgi socket /run/php/php8.4-fpm.sock");
    expect(res.text).toContain("Next: panel_upgrade");
    expect(sent).toEqual([HOST_STATUS_COMMAND, COMPOSER_CMD, PREPARE_CMD]);
    expect(vi.mocked(runSsh).mock.calls.find((c) => c[2] === PREPARE_CMD)![3]).toEqual({ timeoutMs: 600_000 });
  });

  it("honours an explicit release tag and reports a helper refusal verbatim", async () => {
    mockGithub({ composer: { "v1.0.0-rc.2": "^8.4" } });
    host({
      [HOST_STATUS_COMMAND]: STATUS_83,
      [COMPOSER_CMD]: COMPOSER_LINE,
      [PREPARE_CMD]: { stdout: "", stderr: "skeleton-key-pelican-host: REFUSED: php-prepare: panel root /var/www/pelican does not exist\n", code: 2 },
    });
    const res = await prepare({ phpVersion: "8.4", release: "v1.0.0-rc.2" });
    expect(res.isError).toBe(true);
    expect(res.text).toMatch(/php-prepare 8.4 FAILED on 'panel-host' — the host helper REFUSED 'php-prepare' \(exit 2\): .*panel root/);
    expect(vi.mocked(fetch as unknown as (...a: unknown[]) => unknown).mock.calls.map((c) => String(c[0]))).toContain(
      "https://raw.githubusercontent.com/pelican-dev/panel/v1.0.0-rc.2/composer.json",
    );
  });
});

describe("wings_update", () => {
  const update = (input: Record<string, unknown>) => tool("wings_update").run(input, ctx());
  const WINGS_AFTER = { stdout: `wings v1.0.0-rc.1\n${status({ wings: "1.0.0-rc.1" })}` };

  it("confirm names the host, both versions and the helper", () => {
    const text = tool("wings_update").confirm!({ expectVersion: "1.0.0-beta22", tag: "v1.0.0-rc.1" }, panelTarget);
    expect(text).toContain("UPDATE the Wings daemon on Pelican host 'panel-host' from 1.0.0-beta22 to v1.0.0-rc.1");
    expect(text).toContain(`${HELPER_PATH} via sudo -n and nothing else`);
  });

  it("refuses a malformed tag before anything is sent", async () => {
    host({});
    const res = await update({ expectVersion: "1.0.0-beta22", tag: "v1.0.0-rc.1; id" });
    expect(res.isError).toBe(true);
    expect(res.text).toMatch(/release tag/);
    expect(sent).toEqual([]);
  });

  it("refuses a stale expectVersion (the picture must be current)", async () => {
    host({ [HOST_STATUS_COMMAND]: STATUS_83 });
    const res = await update({ expectVersion: "1.0.0-beta21", tag: "v1.0.0-rc.1" });
    expect(res.isError).toBe(true);
    expect(res.text).toMatch(/you said it is on '1.0.0-beta21', but host 'panel-host' runs '1.0.0-beta22'/);
    expect(sent).toEqual([HOST_STATUS_COMMAND]);
  });

  it("is a no-op when Wings is already on the tag", async () => {
    host({ [HOST_STATUS_COMMAND]: { stdout: status({ wings: "1.0.0-rc.1" }) } });
    const res = await update({ expectVersion: "v1.0.0-rc.1", tag: "v1.0.0-rc.1" });
    expect(res.isError).toBeFalsy();
    expect(res.text).toMatch(/Nothing to do: Wings on 'panel-host' is already 1.0.0-rc.1/);
    expect(sent).toEqual([HOST_STATUS_COMMAND]);
  });

  it("needs the helper: missing → install steps, sudo denied → the sudoers line, no version → says so", async () => {
    host({ [HOST_STATUS_COMMAND]: STATUS_NO_HELPER });
    let res = await update({ expectVersion: "1.0.0-beta22", tag: "v1.0.0-rc.1" });
    expect(res.isError).toBe(true);
    expect(res.text).toMatch(/Cannot update Wings: the host helper is not installed/);

    host({ [HOST_STATUS_COMMAND]: STATUS_SUDO_DENIED });
    res = await update({ expectVersion: "1.0.0-beta22", tag: "v1.0.0-rc.1" });
    expect(res.isError).toBe(true);
    expect(res.text).toContain(sudoersLine("skeleton"));

    host({ [HOST_STATUS_COMMAND]: { stdout: status({ wings: "" }) } });
    res = await update({ expectVersion: "1.0.0-beta22", tag: "v1.0.0-rc.1" });
    expect(res.isError).toBe(true);
    expect(res.text).toMatch(/reported no Wings version/);
    expect(sent.some((c) => c.includes("wings-update"))).toBe(false);
  });

  it("runs exactly `sudo -n <helper> wings-update 'v1.0.0-rc.1'` and notes the panel lagging behind", async () => {
    host({ [HOST_STATUS_COMMAND]: STATUS_83, [WINGS_CMD]: WINGS_AFTER, [VERSION_CMD]: VERSION_LINE });
    const res = await update({ expectVersion: "1.0.0-beta22", tag: "v1.0.0-rc.1" });
    expect(res.isError).toBeFalsy();
    expect(res.text).toContain("Updated Wings on host 'panel-host': **1.0.0-beta22 → 1.0.0-rc.1** (service active)");
    expect(res.text).toContain("/usr/local/bin/wings.prev");
    expect(res.text).toContain("the panel is on 1.0.0-beta35, behind Wings v1.0.0-rc.1");
    expect(sent).toEqual([HOST_STATUS_COMMAND, WINGS_CMD, VERSION_CMD]);
    expect(vi.mocked(runSsh).mock.calls.find((c) => c[2] === WINGS_CMD)![3]).toEqual({ timeoutMs: 300_000 });
  });

  it("reports a failed update and whether the helper rolled back", async () => {
    host({
      [HOST_STATUS_COMMAND]: STATUS_83,
      [WINGS_CMD]: { stdout: "", stderr: "skeleton-key-pelican-host: rolled back to the previous wings binary\nskeleton-key-pelican-host: ERROR: wings unit is not active after updating to v1.0.0-rc.1; rolled back\n", code: 1 },
    });
    const res = await update({ expectVersion: "1.0.0-beta22", tag: "v1.0.0-rc.1" });
    expect(res.isError).toBe(true);
    expect(res.text).toMatch(/wings-update v1.0.0-rc.1 FAILED on 'panel-host' — the host helper failed during 'wings-update' \(exit 1\)/);
    expect(res.text).toContain("The previous binary was restored.");
  });
});

describe("panel_upgrade runs through the helper, under the one sudoers rule", () => {
  const upgrade = (input: Record<string, unknown>) => tool("panel_upgrade").run(input, ctx());
  const UPGRADE_OK = {
    stdout:
      [
        "panel_before=1.0.0-beta35",
        "upgrade_log=/var/log/skeleton-key/panel-upgrade-20261011-030000.log",
        "db_backup=/var/www/pelican/storage/pelican-db-backup-20261011-030000.sqlite",
        `steps_done=${PANEL_UPGRADE_STEP_NAMES.join(" ")}`,
        "maintenance=0",
        "panel_after=1.0.0-rc.1",
      ].join("\n") + "\n",
    stderr: "skeleton-key-pelican-host: step: exit-maintenance\nskeleton-key-pelican-host: done\n",
  };

  it("refuses before maintenance mode when the PHP floor is not met, naming panel_prepare_runtime", async () => {
    mockGithub();
    host({ [VERSION_CMD]: VERSION_LINE, [HOST_STATUS_COMMAND]: STATUS_83 });
    const res = await upgrade({ expectVersion: "1.0.0-beta35" });
    expect(res.isError).toBe(true);
    expect(res.text).toMatch(/Refusing to upgrade: v1.0.0-rc.1 requires PHP \^8.4 \|\| \^8.5, but host 'panel-host' runs PHP 8.3.6/);
    expect(res.text).toContain("Run panel_prepare_runtime with phpVersion '8.4' first");
    expect(sent).toEqual([VERSION_CMD, HOST_STATUS_COMMAND]);
  });

  it("fails closed when the release's PHP requirement cannot be established", async () => {
    mockGithub({ composerStatus: 503 });
    host({ [VERSION_CMD]: VERSION_LINE });
    const res = await upgrade({ expectVersion: "1.0.0-beta35" });
    expect(res.isError).toBe(true);
    expect(res.text).toMatch(/Refusing to upgrade: could not read the PHP requirement of v1.0.0-rc.1/);
    expect(sent).toEqual([VERSION_CMD]);
  });

  it("fails closed when the host's PHP version cannot be read (helper present, sudo denied)", async () => {
    mockGithub();
    host({ [VERSION_CMD]: VERSION_LINE, [HOST_STATUS_COMMAND]: { stdout: "helper=1\nhelper_rc=1\n", stderr: "sudo: a password is required\n", code: 0 } });
    const res = await upgrade({ expectVersion: "1.0.0-beta35" });
    expect(res.isError).toBe(true);
    expect(res.text).toMatch(/could not read the host's PHP version/);
    expect(res.text).toContain(sudoersLine("skeleton"));
  });

  it("refuses a stale expectVersion before touching GitHub or the helper", async () => {
    host({ [VERSION_CMD]: VERSION_LINE });
    const res = await upgrade({ expectVersion: "1.0.0-beta34" });
    expect(res.isError).toBe(true);
    expect(res.text).toMatch(/you said the panel is on '1.0.0-beta34', but it is actually on '1.0.0-beta35'/);
    expect(sent).toEqual([VERSION_CMD]);
  });

  it("is a no-op when the panel is already on the target release", async () => {
    mockGithub({ latestPanel: "v1.0.0-beta35" });
    host({ [VERSION_CMD]: VERSION_LINE });
    const res = await upgrade({ expectVersion: "1.0.0-beta35" });
    expect(res.isError).toBeFalsy();
    expect(res.text).toMatch(/Nothing to do: the panel on host 'panel-host' is already on v1.0.0-beta35/);
    expect(sent).toEqual([VERSION_CMD]);
  });

  it("sends exactly `sudo -n <helper> panel-upgrade '<installed>' '<tag>'` once the gate passes, and reports the result", async () => {
    mockGithub();
    host({ [VERSION_CMD]: VERSION_LINE, [HOST_STATUS_COMMAND]: STATUS_84, [UPGRADE_CMD]: UPGRADE_OK });
    const res = await upgrade({ expectVersion: "1.0.0-beta35" });
    expect(res.isError).toBeFalsy();
    expect(res.text).toContain("Upgraded the Pelican panel on host 'panel-host': **1.0.0-beta35 → 1.0.0-rc.1**");
    expect(res.text).toContain(`Steps completed (${PANEL_UPGRADE_STEP_NAMES.length})`);
    expect(res.text).toContain("Pre-upgrade database backup: /var/www/pelican/storage/pelican-db-backup-20261011-030000.sqlite");
    expect(res.text).toContain("Run log: /var/log/skeleton-key/panel-upgrade-20261011-030000.log");
    expect(res.text).toContain("wings_update");
    expect(sent).toEqual([VERSION_CMD, HOST_STATUS_COMMAND, UPGRADE_CMD]);
    expect(vi.mocked(runSsh).mock.calls.find((c) => c[2] === UPGRADE_CMD)![3]).toEqual({ timeoutMs: 600_000 });
  });

  it("pins an explicit release (its composer.json decides the gate) and passes --skip-backup as the one literal flag", async () => {
    mockGithub({ composer: { "v1.0.0-rc.2": "^8.4" } });
    host({
      [VERSION_CMD]: VERSION_LINE,
      [HOST_STATUS_COMMAND]: STATUS_84,
      [UPGRADE_CMD_PINNED_SKIP]: { stdout: `panel_before=1.0.0-beta35\nupgrade_log=/var/log/skeleton-key/x.log\ndb_backup=skipped\nsteps_done=${PANEL_UPGRADE_STEP_NAMES.filter((s) => s !== "db-backup").join(" ")}\nmaintenance=0\npanel_after=1.0.0-rc.2\n` },
    });
    const res = await upgrade({ expectVersion: "1.0.0-beta35", release: "v1.0.0-rc.2", skipBackup: true });
    expect(res.isError).toBeFalsy();
    expect(res.text).toContain("**1.0.0-beta35 → 1.0.0-rc.2**");
    expect(res.text).toContain("No database backup was taken.");
    expect(vi.mocked(fetch as unknown as (...a: unknown[]) => unknown).mock.calls.map((c) => String(c[0]))).toContain(
      "https://raw.githubusercontent.com/pelican-dev/panel/v1.0.0-rc.2/composer.json",
    );
    expect(sent).toEqual([VERSION_CMD, HOST_STATUS_COMMAND, UPGRADE_CMD_PINNED_SKIP]);
  });

  it("reports the failed step, the maintenance state, the backup and the log when the helper stops mid-run", async () => {
    mockGithub();
    host({
      [VERSION_CMD]: VERSION_LINE,
      [HOST_STATUS_COMMAND]: STATUS_84,
      [UPGRADE_CMD]: {
        stdout:
          "panel_before=1.0.0-beta35\nupgrade_log=/var/log/skeleton-key/panel-upgrade-20261011-030000.log\n" +
          "db_backup=/var/www/pelican/storage/pelican-db-backup-20261011-030000.sqlite\nfailed_step=composer-install\n" +
          "steps_done=download-release download-checksum preflight-platform db-backup maintenance-mode extract fix-permissions\nmaintenance=1\n",
        stderr: "skeleton-key-pelican-host: composer-install: Your lock file does not contain a compatible set of packages.\nskeleton-key-pelican-host: ERROR: step 'composer-install' failed (exit 2); full output in /var/log/skeleton-key/panel-upgrade-20261011-030000.log\n",
        code: 1,
      },
    });
    const res = await upgrade({ expectVersion: "1.0.0-beta35" });
    expect(res.isError).toBe(true);
    expect(res.text).toMatch(/Panel upgrade to v1.0.0-rc.1 FAILED at step 'composer-install' on 'panel-host'/);
    expect(res.text).toContain("Steps completed: download-release, download-checksum, preflight-platform, db-backup, maintenance-mode, extract, fix-permissions.");
    expect(res.text).toContain("still in MAINTENANCE MODE");
    expect(res.text).toContain("/var/www/pelican/storage/pelican-db-backup-20261011-030000.sqlite");
    expect(res.text).toContain("/var/log/skeleton-key/panel-upgrade-20261011-030000.log");
  });

  it("says the upgrade did not start when sudo refuses the helper or the helper refuses the arguments", async () => {
    mockGithub();
    host({ [VERSION_CMD]: VERSION_LINE, [HOST_STATUS_COMMAND]: STATUS_84, [UPGRADE_CMD]: { stderr: "sudo: a password is required\n", code: 1 } });
    let res = await upgrade({ expectVersion: "1.0.0-beta35" });
    expect(res.isError).toBe(true);
    expect(res.text).toMatch(/Panel upgrade did not start — sudo refused/);
    expect(res.text).toContain(sudoersLine("skeleton"));

    sent = [];
    host({
      [VERSION_CMD]: VERSION_LINE,
      [HOST_STATUS_COMMAND]: STATUS_84,
      [UPGRADE_CMD]: { stdout: "", stderr: "skeleton-key-pelican-host: REFUSED: panel-upgrade: the panel is on '1.0.0-beta36', not '1.0.0-beta35' — stale picture\n", code: 2 },
    });
    res = await upgrade({ expectVersion: "1.0.0-beta35" });
    expect(res.isError).toBe(true);
    expect(res.text).toMatch(/did not start — the host helper REFUSED 'panel-upgrade' \(exit 2\): .*stale picture/);
  });

  it("turns an SSH timeout into 'wait, then panel_version' — never into a re-run", async () => {
    mockGithub();
    host({
      [VERSION_CMD]: VERSION_LINE,
      [HOST_STATUS_COMMAND]: STATUS_84,
      [UPGRADE_CMD]: () => {
        throw new Error("SSH command on panel-host (192.168.1.48) timed out after 600000ms (600s). Raise it via …");
      },
    });
    const res = await upgrade({ expectVersion: "1.0.0-beta35" });
    expect(res.isError).toBe(true);
    expect(res.text).toMatch(/timed out after 10 minutes while the helper was still upgrading/);
    expect(res.text).toContain("do NOT re-run panel_upgrade yet");
    expect(res.text).toContain("/var/log/skeleton-key/");
  });
});
