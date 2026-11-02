/**
 * Import boundaries for connectors. A connector holds credentials while it
 * runs, so what it can reach is part of the security model:
 *
 *  - A connector folder (`src/connectors/<type>/`) may import only its own
 *    files, `../types.ts`, `../shared/*`, and a short list of packages. It may
 *    not reach the secrets store, the audit log, config, the web layer, another
 *    connector, or process/filesystem/raw-socket builtins.
 *  - `shared/` helpers follow the same rules and never import a connector.
 *  - The registry (`index.ts`) imports each connector only through its
 *    `index.ts`, and the rest of the app reaches connectors only through
 *    `index.ts`, `types.ts` and `shared/`.
 *
 * ESLint's `no-restricted-imports` would normally do this, but typescript-eslint
 * doesn't support TypeScript 7 yet, so the rules live here, in the required test
 * run. Exceptions are listed with their reason; this file is maintainer-owned.
 */
import { describe, expect, it } from "vitest";
import { readFileSync } from "node:fs";
import { execFileSync } from "node:child_process";
import path from "node:path";

const repo = path.resolve(import.meta.dirname, "..", "..");
const CONNECTORS = "src/connectors";

/** Packages any connector may import. Anything else needs an exception. */
const PACKAGE_ALLOW = new Set(["zod", "js-yaml"]);
/** Builtins that touch processes, the filesystem, or raw sockets. */
const FORBIDDEN_BUILTINS = new Set([
  "child_process", "fs", "fs/promises", "module", "net", "dgram", "tls", "http", "https", "http2",
  "worker_threads", "vm", "cluster", "inspector", "repl",
]);

/** file → specifiers it may import despite the rules, and why. */
const EXCEPTIONS: Record<string, { allow: string[]; why: string }> = {
  "src/connectors/uptime-kuma/index.ts": {
    allow: ["node:fs/promises", "../../config/paths.js", "../../lib/atomic-file.js"],
    why: "persists maintenance handles so a restart can't strand monitors paused with no record",
  },
  "src/connectors/uptime-kuma/client.ts": {
    allow: ["node:module", "socket.io-client"],
    why: "Kuma has no REST API for monitor control; Socket.IO is its only control channel",
  },
  "src/connectors/pelican/index.ts": {
    allow: ["../uptime-kuma/index.js", "../uptime-kuma/client.js"],
    why: "power_action pauses and resumes the server's Uptime Kuma monitors (suppressMonitors)",
  },
  "src/connectors/shared/net.ts": {
    allow: ["undici"],
    why: "per-request TLS dispatcher for self-signed LAN services (tlsFetch)",
  },
  "src/connectors/shared/ssh-exec.ts": {
    allow: ["ssh2", "../../secrets/types.js"],
    why: "the SSH transport; imports only the Credential type from secrets",
  },
};

const IMPORT_RES = [
  /^\s*(?:import|export)\s[^;]*?\sfrom\s*["']([^"']+)["']/gms,
  /^\s*import\s*["']([^"']+)["']/gm,
  /\bimport\(\s*["']([^"']+)["']\s*\)/g,
  /\brequire\(\s*["']([^"']+)["']\s*\)/g,
];

function importsOf(file: string): string[] {
  const text = readFileSync(path.join(repo, file), "utf8");
  const found = new Set<string>();
  for (const re of IMPORT_RES) for (const m of text.matchAll(re)) found.add(m[1]!);
  return [...found];
}

const tracked = execFileSync("git", ["ls-files", "src"], { cwd: repo, encoding: "utf8" })
  .split("\n")
  .filter((f) => f.endsWith(".ts") && !f.endsWith(".test.ts"));

/** Resolve a relative specifier to a repo path (.js → .ts). */
function resolveRel(from: string, spec: string): string {
  return path.posix.normalize(path.posix.join(path.posix.dirname(from), spec)).replace(/\.js$/, ".ts");
}

const builtinName = (spec: string) => spec.replace(/^node:/, "");
const isBuiltinSpec = (spec: string) => spec.startsWith("node:") || FORBIDDEN_BUILTINS.has(spec);

function checkConnectorFile(file: string): string[] {
  const parts = file.split("/"); // src/connectors/<dir>/...
  const dir = parts[2]!;
  const own = `${CONNECTORS}/${dir}/`;
  const allow = new Set(EXCEPTIONS[file]?.allow ?? []);
  const problems: string[] = [];
  for (const spec of importsOf(file)) {
    if (allow.has(spec)) continue;
    if (spec.startsWith(".")) {
      const target = resolveRel(file, spec);
      const ok = target.startsWith(own) || target === `${CONNECTORS}/types.ts` || target.startsWith(`${CONNECTORS}/shared/`);
      if (!ok) problems.push(`${file}: imports ${spec} (outside its folder, types.ts and shared/)`);
    } else if (isBuiltinSpec(spec)) {
      if (FORBIDDEN_BUILTINS.has(builtinName(spec))) problems.push(`${file}: imports builtin ${spec}`);
    } else if (!PACKAGE_ALLOW.has(spec)) {
      problems.push(`${file}: imports package ${spec} (not in PACKAGE_ALLOW)`);
    }
  }
  return problems;
}

describe("connector import boundaries", () => {
  const connectorFiles = tracked.filter((f) => f.startsWith(`${CONNECTORS}/`) && f.split("/").length > 3);

  it("finds the connector files (the check isn't vacuous)", () => {
    expect(connectorFiles.length).toBeGreaterThan(10);
  });

  it("keeps connector and shared files inside their boundary", () => {
    expect(connectorFiles.flatMap(checkConnectorFile)).toEqual([]);
  });

  it("never lets shared/ import a connector", () => {
    const bad = connectorFiles
      .filter((f) => f.startsWith(`${CONNECTORS}/shared/`))
      .flatMap((f) => importsOf(f).filter((s) => s.startsWith(".")).map((s) => [f, resolveRel(f, s)] as const))
      .filter(([, t]) => t.startsWith(`${CONNECTORS}/`) && !t.startsWith(`${CONNECTORS}/shared/`) && t !== `${CONNECTORS}/types.ts`)
      .map(([f, t]) => `${f} -> ${t}`);
    expect(bad).toEqual([]);
  });

  it("registers each connector only through its index.ts", () => {
    const bad = importsOf(`${CONNECTORS}/index.ts`)
      .filter((s) => s.startsWith("./"))
      .map((s) => resolveRel(`${CONNECTORS}/index.ts`, s))
      .filter((t) => t !== `${CONNECTORS}/types.ts` && !/^src\/connectors\/[^/]+\/index\.ts$/.test(t));
    expect(bad).toEqual([]);
  });

  it("lets the rest of the app reach connectors only through index.ts, types.ts and shared/", () => {
    const bad: string[] = [];
    for (const f of tracked.filter((x) => !x.startsWith(`${CONNECTORS}/`))) {
      for (const s of importsOf(f).filter((x) => x.startsWith("."))) {
        const t = resolveRel(f, s);
        if (!t.startsWith(`${CONNECTORS}/`)) continue;
        if (t === `${CONNECTORS}/index.ts` || t === `${CONNECTORS}/types.ts` || t.startsWith(`${CONNECTORS}/shared/`)) continue;
        bad.push(`${f} -> ${t}`);
      }
    }
    expect(bad).toEqual([]);
  });

  it("has no stale exceptions", () => {
    for (const [file, { allow }] of Object.entries(EXCEPTIONS)) {
      const used = new Set(importsOf(file));
      for (const spec of allow) expect(used.has(spec), `${file} no longer imports ${spec}; drop the exception`).toBe(true);
    }
  });
});
