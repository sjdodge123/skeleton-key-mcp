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
} as const;

export const env = {
  /** Interface the HTTP server binds to. Defaults to all interfaces inside the
   *  container; the compose file maps it to the LAN only. */
  bindHost: process.env.SKELETON_KEY_BIND_HOST ?? "0.0.0.0",
  port: Number(process.env.SKELETON_KEY_PORT ?? 8787),
  /** Passphrase used to unlock the bootstrap store. In v1 it may be supplied at
   *  container start; later the web UI prompts for it. */
  unlockPassphrase: process.env.SKELETON_KEY_PASSPHRASE,
} as const;
