import { mkdir, readFile, readdir } from "node:fs/promises";
import { randomBytes } from "node:crypto";
import { createGzip } from "node:zlib";
import path from "node:path";
import type { Writable } from "node:stream";
import { paths } from "../config/paths.js";
import { getConnector } from "../connectors/index.js";
import { writeFileAtomic } from "../lib/atomic-file.js";
import type { AppState } from "../app.js";
import type { SnapshotArtifact, ToolContext } from "../connectors/types.js";
import { getOrCreateSnapshotKey, encryptArtifact, decryptArtifact, sha256 } from "./crypto.js";
import { TarWriter } from "./tar.js";

/** Per-artifact plaintext cap — a guardrail against an unexpectedly huge export
 *  buffering into memory. Homelab config/backups are far smaller. */
const MAX_ARTIFACT_BYTES = 64 * 1024 * 1024;

type TargetStatus = "ok" | "partial" | "error" | "skipped";

interface ManifestArtifact {
  name: string;
  /** Path to the encrypted blob, relative to the skeleton dir. */
  file: string;
  /** SHA-256 of the PLAINTEXT (integrity check after decrypt). */
  sha256: string;
  bytes: number;
  note?: string;
}
interface ManifestTarget {
  name: string;
  type: string;
  status: TargetStatus;
  error: string | null;
  artifacts: ManifestArtifact[];
}
interface Manifest {
  version: 1;
  id: string;
  createdAt: string;
  encryption: { algo: string; nonceBytes: number; layout: string };
  targetCount: number;
  artifactCount: number;
  totalPlaintextBytes: number;
  targets: ManifestTarget[];
}

/** Metadata-only summary of a stored skeleton (no secrets, no artifact bytes). */
export interface SkeletonSummary {
  id: string;
  createdAt: string;
  targetCount: number;
  artifactCount: number;
  totalPlaintextBytes: number;
  targets: { name: string; type: string; status: TargetStatus }[];
}

/** Keep artifact leaf names filesystem-safe and flat (no path separators). */
function sanitize(name: string): string {
  const s = name.replace(/[^a-zA-Z0-9._-]/g, "_");
  return s === "" || s === "." || s === ".." ? "artifact" : s;
}

/**
 * Snapshot every registered target's config to an ENCRYPTED skeleton on disk and
 * return a summary only. A backup necessarily contains secrets, so artifact bytes
 * are encrypted at rest and never returned here, put in the manifest, or audited.
 * Per-target failures are isolated (partial skeleton), never a hard fail.
 */
export async function formSkeleton(app: AppState, snapshotsDir: string = paths.snapshotsDir): Promise<{ id: string; summary: string }> {
  const key = await getOrCreateSnapshotKey(app);
  const createdAt = new Date().toISOString();
  const id = `${createdAt.replace(/[:.]/g, "-")}-${randomBytes(2).toString("hex")}`;
  const dir = path.join(snapshotsDir, id);
  await mkdir(dir, { recursive: true });

  const targets: ManifestTarget[] = [];
  let artifactCount = 0;
  let totalPlaintextBytes = 0;

  for (const target of app.registry.list()) {
    const connector = getConnector(target.type);
    if (!connector?.snapshot) {
      targets.push({ name: target.name, type: target.type, status: "skipped", error: null, artifacts: [] });
      continue;
    }
    const ctx: ToolContext = {
      target,
      getCredential: () => {
        if (!target.credentialRef) throw new Error(`Target '${target.name}' has no credentialRef.`);
        return app.credentialFor(target.credentialRef);
      },
    };

    let artifacts: SnapshotArtifact[];
    try {
      artifacts = await connector.snapshot(ctx);
    } catch (e) {
      const msg = e instanceof Error ? e.message : String(e);
      targets.push({ name: target.name, type: target.type, status: "error", error: msg, artifacts: [] });
      auditTarget(app, target.name, "error", `snapshot failed: ${msg}`);
      continue;
    }

    const mArts: ManifestArtifact[] = [];
    const errors: string[] = [];
    await mkdir(path.join(dir, target.name), { recursive: true });
    for (const art of artifacts) {
      const safeName = sanitize(art.name);
      if (art.data.length > MAX_ARTIFACT_BYTES) {
        errors.push(`${safeName}: ${art.data.length} bytes over the ${MAX_ARTIFACT_BYTES}-byte cap`);
        continue;
      }
      const rel = path.join(target.name, `${safeName}.enc`);
      const blob = encryptArtifact(key, art.data, `${id}/${target.name}/${safeName}`);
      await writeFileAtomic(path.join(dir, rel), blob, 0o600);
      mArts.push({ name: safeName, file: rel, sha256: sha256(art.data), bytes: art.data.length, ...(art.note ? { note: art.note } : {}) });
      artifactCount++;
      totalPlaintextBytes += art.data.length;
    }
    const status: TargetStatus = errors.length ? (mArts.length ? "partial" : "error") : "ok";
    targets.push({ name: target.name, type: target.type, status, error: errors.length ? errors.join("; ") : null, artifacts: mArts });
    auditTarget(app, target.name, status === "error" ? "error" : "ok", `${mArts.length} artifact(s)${errors.length ? `, ${errors.length} skipped` : ""}`);
  }

  const manifest: Manifest = {
    version: 1,
    id,
    createdAt,
    encryption: { algo: "xchacha20poly1305_ietf", nonceBytes: 24, layout: "nonce||ciphertext" },
    targetCount: targets.length,
    artifactCount,
    totalPlaintextBytes,
    targets,
  };
  await writeFileAtomic(path.join(dir, "manifest.json"), JSON.stringify(manifest, null, 2), 0o600);
  await writeFileAtomic(path.join(dir, "RESTORE.md"), restoreDoc(manifest), 0o600);

  return { id, summary: summarize(manifest) };
}

/** List stored skeletons (metadata only), newest first. */
export async function listSkeletons(snapshotsDir: string = paths.snapshotsDir): Promise<SkeletonSummary[]> {
  let entries: import("node:fs").Dirent[];
  try {
    entries = await readdir(snapshotsDir, { withFileTypes: true });
  } catch {
    return [];
  }
  const out: SkeletonSummary[] = [];
  for (const e of entries) {
    if (!e.isDirectory()) continue;
    try {
      const m = JSON.parse(await readFile(path.join(snapshotsDir, e.name, "manifest.json"), "utf8")) as Manifest;
      out.push({
        id: m.id,
        createdAt: m.createdAt,
        targetCount: m.targetCount,
        artifactCount: m.artifactCount,
        totalPlaintextBytes: m.totalPlaintextBytes,
        targets: m.targets.map((t) => ({ name: t.name, type: t.type, status: t.status })),
      });
    } catch {
      /* skip a dir without a valid manifest */
    }
  }
  out.sort((a, b) => (a.createdAt < b.createdAt ? 1 : -1));
  return out;
}

/**
 * Decrypt a skeleton and stream it to `out` as a gzipped tar. The ONLY plaintext
 * egress for skeleton artifacts — the caller MUST TOTP-gate it. Validates the id
 * (and asserts the resolved path stays inside snapshotsDir) before writing any
 * bytes, so a missing/invalid id can still be answered with a clean error.
 */
export async function streamSkeletonTar(app: AppState, id: string, out: Writable, snapshotsDir: string = paths.snapshotsDir): Promise<void> {
  if (!/^[0-9A-Za-z._-]+$/.test(id) || id.includes("..")) throw new Error("invalid skeleton id");
  const dir = path.join(snapshotsDir, id);
  const rootResolved = path.resolve(snapshotsDir);
  const resolved = path.resolve(dir);
  if (resolved !== rootResolved && !resolved.startsWith(rootResolved + path.sep)) throw new Error("skeleton id escapes snapshots dir");

  // Pre-flight (before any output) so a missing skeleton yields a clean 404.
  const manifestRaw = await readFile(path.join(dir, "manifest.json"), "utf8");
  const manifest = JSON.parse(manifestRaw) as Manifest;
  const key = await getOrCreateSnapshotKey(app);

  const gzip = createGzip();
  const done = new Promise<void>((resolve, reject) => {
    out.on("finish", resolve);
    out.on("error", reject);
    gzip.on("error", reject);
  });
  gzip.pipe(out);
  const tar = new TarWriter(gzip);
  try {
    tar.addFile("manifest.json", Buffer.from(manifestRaw, "utf8"));
    try {
      tar.addFile("RESTORE.md", await readFile(path.join(dir, "RESTORE.md")));
    } catch {
      /* RESTORE.md is optional */
    }
    for (const t of manifest.targets) {
      for (const a of t.artifacts) {
        const blob = await readFile(path.join(dir, a.file));
        const plaintext = decryptArtifact(key, blob, `${id}/${t.name}/${a.name}`);
        if (sha256(plaintext) !== a.sha256) throw new Error(`integrity check failed for ${a.file}`);
        tar.addFile(`${t.name}/${a.name}`, plaintext);
      }
    }
    tar.finish();
    gzip.end();
    await done;
  } catch (e) {
    gzip.destroy();
    throw e;
  }
}

function auditTarget(app: AppState, target: string, status: "ok" | "error", detail: string): void {
  app.audit.record({ ts: new Date().toISOString(), tool: "form_skeleton", target, tier: "execute", args: {}, status, detail: detail.slice(0, 500) });
}

function summarize(m: Manifest): string {
  const lines = m.targets.map(
    (t) => `  - ${t.name} (${t.type}): ${t.status}${t.artifacts.length ? ` — ${t.artifacts.length} artifact(s)` : ""}${t.error ? ` [${t.error}]` : ""}`,
  );
  return `${m.artifactCount} artifact(s) from ${m.targetCount} target(s), ${Math.round(m.totalPlaintextBytes / 1024)} KiB (encrypted at rest).\n${lines.join("\n")}`;
}

function restoreDoc(m: Manifest): string {
  const rows = m.targets
    .flatMap((t) => t.artifacts.map((a) => `| ${t.name} | ${t.type} | ${a.name} | ${a.bytes} | ${a.note ?? ""} |`))
    .join("\n");
  return `# Skeleton ${m.id}

Created ${m.createdAt}. ${m.artifactCount} artifact(s) across ${m.targetCount} target(s).

**These files contain SECRETS** (VPN keys, tokens, backups). They are stored ENCRYPTED
(${m.encryption.algo}) inside the Skeleton Key data volume and are only decryptable by this
instance. This \`.tar.gz\` you are reading is the DECRYPTED copy — keep it somewhere safe and
delete it when done. For true off-box DR, download a fresh skeleton periodically and store it
off the Skeleton Key host (a NAS factory-reset would take the on-box copies with it).

## Restore per service

- **UniFi** — restore \`backup.unf\` via the controller UI (Settings → System → Backups → Restore).
  \`settings.txt\`/\`networks.txt\`/\`devices.txt\` are scrubbed human references only.
- **Pi-hole** — import \`teleporter.tar.gz\` via Settings → Teleporter (or \`pihole -a -t\` import).
  \`pihole-setupVars.conf\` is a reference.
- **Home Assistant** — the full backup .tar stays ON the HA device (Settings → System → Backups);
  \`config.json\`/\`backup-status.txt\` here are references. Pull the .tar off the device separately for true DR.
- **Proxmox** — recreate guests from \`guest-*.config.json\`; \`storage.json\`/\`network-*.json\` document the host.
- **Portainer/Docker** — redeploy each stack from its \`stack-*.compose.yml\`; \`container-*.inspect.json\` documents runtime config.
- **SSH hosts** — \`*.txt\` are a read-only system profile for reference.

## Contents

| target | type | artifact | bytes | note |
|---|---|---|---|---|
${rows}

## Cleanup

Skeletons are not auto-pruned. Remove old ones from \`skeletons/\` in the data volume when no longer needed.
`;
}
