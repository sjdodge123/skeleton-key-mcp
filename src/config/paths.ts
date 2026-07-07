import fs from "node:fs";
import path from "node:path";

/**
 * All mutable runtime state lives under DATA_DIR, which is mounted as a Docker
 * volume so it survives container restarts. Nothing here is baked into the image.
 */
export const DATA_DIR = process.env.SKELETON_KEY_DATA_DIR
  ? path.resolve(process.env.SKELETON_KEY_DATA_DIR)
  : path.resolve(process.cwd(), "data");

export const paths = {
  dataDir: DATA_DIR,
  /** libsodium-encrypted store of Skeleton Key's own secrets (bw api key, bearer token, TOTP seed). */
  bootstrapStore: path.join(DATA_DIR, "bootstrap.store"),
  /** User-registered targets (no secrets — only vault item references). */
  registry: path.join(DATA_DIR, "targets.yaml"),
  /** Append-only audit database. */
  auditDb: path.join(DATA_DIR, "audit.sqlite"),
  /** Home for the `bw` CLI's encrypted offline vault cache. */
  bwCacheDir: path.join(DATA_DIR, "bw-cache"),
  /** Marker written when the first-run wizard completes. */
  setupComplete: path.join(DATA_DIR, "setup-complete.json"),
  /** Auto-detected public base URL, persisted on first boot. Non-secret and
   *  readable while the vault is locked (unlock guidance needs it). */
  publicUrl: path.join(DATA_DIR, "public-url"),
  /** SHA-256 hash of the MCP bearer token, so it can be verified while the vault
   *  is locked. Non-secret (hash of a 256-bit random token). */
  bearerHash: path.join(DATA_DIR, "mcp-bearer.hash"),
  /** Encrypted disaster-recovery skeletons:
   *  skeletons/<id>/<target>/<artifact>.enc + manifest.json + RESTORE.md. */
  snapshotsDir: path.join(DATA_DIR, "skeletons"),
} as const;

/**
 * DEPRECATED boot-unlock path: resolve the master passphrase from
 * `SKELETON_KEY_PASSPHRASE_FILE` (preferred of the two) or
 * `SKELETON_KEY_PASSPHRASE`. Superseded by web-UI-managed auto-unlock (a random
 * key file that never contains the passphrase — see BootstrapStore keyslots);
 * still honored so existing deployments keep booting, with a warning at boot.
 *
 * File handling: exactly one trailing newline is stripped (editors/`echo`
 * append one) plus a leading UTF-8 BOM — no full trim, a passphrase may contain
 * meaningful spaces. If the file is set but unreadable/empty, this fails closed
 * to `undefined` (manual web-UI unlock) rather than silently using a possibly
 * stale inline `SKELETON_KEY_PASSPHRASE`; the passphrase value is never logged.
 */
export function resolveUnlockPassphrase(): string | undefined {
  const file = process.env.SKELETON_KEY_PASSPHRASE_FILE;
  if (file) {
    try {
      // Strip a UTF-8 BOM (Windows editors add one) and exactly one trailing
      // newline of any convention (\n, \r\n, or a lone \r) — never a full trim.
      const passphrase = fs
        .readFileSync(file, "utf8")
        .replace(/^\uFEFF/, "")
        .replace(/\r?\n$|\r$/, "");
      if (!passphrase) {
        console.error(
          `[skeleton-key] SKELETON_KEY_PASSPHRASE_FILE (${file}) is empty. ` +
            "Skipping boot auto-unlock; unlock via the web UI.",
        );
        return undefined;
      }
      return passphrase;
    } catch (err) {
      console.error(
        `[skeleton-key] Could not read SKELETON_KEY_PASSPHRASE_FILE (${file}): ` +
          `${err instanceof Error ? err.message : String(err)}. ` +
          "Skipping boot auto-unlock; unlock via the web UI.",
      );
      return undefined;
    }
  }
  // Normalize empty → undefined; a zero-length passphrase can't unlock anything.
  return process.env.SKELETON_KEY_PASSPHRASE || undefined;
}

export const env = {
  /** Interface the HTTP server binds to. Defaults to all interfaces inside the
   *  container; the compose file maps it to the LAN only. */
  bindHost: process.env.SKELETON_KEY_BIND_HOST ?? "0.0.0.0",
  port: Number(process.env.SKELETON_KEY_PORT ?? 8787),
  /** Where the boot auto-unlock key lives (a non-secret *path*; the key itself
   *  is written there by the web UI when auto-unlock is enabled). Must point
   *  into a host mount OUTSIDE the data volume — never store the key next to
   *  the encrypted store it unlocks. */
  get unlockKeyFile(): string {
    return process.env.SKELETON_KEY_UNLOCK_KEY_FILE ?? "/run/secrets/skeleton-key/unlock-key";
  },
  /** DEPRECATED passphrase-in-environment boot unlock (see resolveUnlockPassphrase).
   *  Resolved lazily so the file (if any) is read at boot, not at import. */
  get unlockPassphrase(): string | undefined {
    return resolveUnlockPassphrase();
  },
} as const;
