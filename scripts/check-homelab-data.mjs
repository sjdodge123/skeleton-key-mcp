#!/usr/bin/env node
// Refuses real homelab data (hostnames, LAN addresses, personal identifiers) in
// anything that would land in this public repository: tracked files, staged
// changes, commit messages, and PR text.
//
// Two rules:
//  1. Public, always on: no full 192.168.0.N address. Placeholders use
//     192.168.1.x, 10.0.0.x or the RFC 5737 ranges (see CONTRIBUTING.md). A bare
//     subnet example such as '192.168.0' is fine; it names no machine.
//  2. Private denylist: the maintainer's own hostnames, domains and addresses.
//     The list can't live in the repo (that would publish it), so it comes from
//     the SKELETON_KEY_DENYLIST env var (CI secret) and/or the local file
//     `$(git rev-parse --git-common-dir)/info/homelab-denylist`, which every
//     worktree of a checkout shares and git never commits. One entry per line,
//     `#` comments, matched case-insensitively as a whole token.
//
// In CI the denylist entry that matched is never printed: Actions logs are
// public, so printing it would leak the very thing this check protects.
//
// Usage:
//   node scripts/check-homelab-data.mjs                 scan every tracked file
//   node scripts/check-homelab-data.mjs --staged        scan staged files (pre-commit)
//   node scripts/check-homelab-data.mjs --message FILE  scan a commit message (commit-msg)
//   node scripts/check-homelab-data.mjs --text-env VAR  scan the text in env VAR (PR title/body)
//   --require-denylist                                  fail if no denylist entries loaded

import { execFileSync } from "node:child_process";
import { existsSync, readFileSync } from "node:fs";
import path from "node:path";

const args = process.argv.slice(2);
const flag = (name) => args.includes(name);
const valueOf = (name) => {
  const i = args.indexOf(name);
  return i >= 0 ? args[i + 1] : undefined;
};
const inCI = Boolean(process.env.CI);

const git = (...a) => execFileSync("git", a, { encoding: "buffer", maxBuffer: 256 * 1024 * 1024 });

// --- rule 1: the maintainer's LAN range, as full addresses -------------------
const LAN_ADDRESS = /(?<![0-9.])192\.168\.0\.([0-9]{1,3})(?![0-9])/g;

// --- rule 2: the private denylist -------------------------------------------
function denylistFile() {
  try {
    const common = git("rev-parse", "--git-common-dir").toString().trim();
    return path.resolve(common, "info", "homelab-denylist");
  } catch {
    return undefined;
  }
}

function loadDenylist() {
  const raw = [];
  if (process.env.SKELETON_KEY_DENYLIST) raw.push(process.env.SKELETON_KEY_DENYLIST);
  const file = denylistFile();
  if (file && existsSync(file)) raw.push(readFileSync(file, "utf8"));
  const entries = new Set();
  for (const block of raw) {
    for (const line of block.split(/\r?\n/)) {
      const entry = line.replace(/#.*/, "").trim().toLowerCase();
      if (entry) entries.add(entry);
    }
  }
  return [...entries];
}

const escapeRe = (s) => s.replace(/[.*+?^${}()|[\]\\]/g, "\\$&");
// Whole token: not glued to a word character or hyphen on either side, and an
// address entry doesn't match a longer address (…0.9 must not hit …0.90).
const tokenRe = (entry) => new RegExp(`(?<![A-Za-z0-9_-])${escapeRe(entry)}(?![A-Za-z0-9_-]|\\.[0-9])`, "gi");

const denylist = loadDenylist();
const denyRes = denylist.map((entry, i) => ({ entry, index: i + 1, re: tokenRe(entry) }));

if (flag("--require-denylist") && denylist.length === 0) {
  console.error(
    "check-homelab-data: no denylist entries loaded, and this run requires them.\n" +
      "Set the SKELETON_KEY_DENYLIST repository secret (one entry per line), or for a local run\n" +
      "create $(git rev-parse --git-common-dir)/info/homelab-denylist.",
  );
  process.exit(2);
}

// --- scanning ----------------------------------------------------------------
const findings = [];

function scanText(label, text) {
  const lines = text.split(/\r?\n/);
  lines.forEach((line, i) => {
    for (const m of line.matchAll(LAN_ADDRESS)) {
      if (m[1] === "0") continue; // 192.168.0.0 is a network address, not a machine
      findings.push(`${label}:${i + 1}:${m.index + 1}: LAN address ${m[0]} — use a placeholder (192.168.1.x, 10.0.0.x)`);
    }
    for (const { entry, index, re } of denyRes) {
      for (const m of line.matchAll(re)) {
        const what = inCI ? `private denylist entry #${index}` : `private denylist entry '${entry}'`;
        findings.push(`${label}:${i + 1}:${m.index + 1}: matches ${what} — use a placeholder`);
      }
    }
  });
}

const isBinary = (buf) => buf.subarray(0, 8000).includes(0);

function scanBlob(label, buf) {
  if (isBinary(buf)) return;
  scanText(label, buf.toString("utf8"));
}

const nulList = (buf) => buf.toString("utf8").split("\0").filter(Boolean);

if (valueOf("--message")) {
  const file = valueOf("--message");
  // Drop git's comment lines; they aren't part of the commit.
  const text = readFileSync(file, "utf8").split(/\r?\n/).filter((l) => !l.startsWith("#")).join("\n");
  scanText("commit message", text);
} else if (valueOf("--text-env")) {
  const name = valueOf("--text-env");
  scanText(name, process.env[name] ?? "");
} else if (flag("--staged")) {
  for (const file of nulList(git("diff", "--cached", "--name-only", "--diff-filter=ACMR", "-z"))) {
    scanBlob(file, git("show", `:${file}`));
  }
} else {
  for (const file of nulList(git("ls-files", "-z"))) {
    if (!existsSync(file)) continue; // deleted in the working tree
    scanBlob(file, readFileSync(file));
  }
}

if (findings.length) {
  console.error(findings.join("\n"));
  console.error(
    `\ncheck-homelab-data: ${findings.length} finding(s). This repository is public; real hostnames, ` +
      "LAN addresses and personal identifiers never go in it. There is no bypass marker: replace the value.",
  );
  process.exit(1);
}
const scope = denylist.length ? `LAN-address rule + ${denylist.length} denylist entries` : "LAN-address rule only (no denylist loaded)";
console.log(`check-homelab-data: clean (${scope}).`);
