import { execFile } from "node:child_process";
import { promisify } from "node:util";
import { X509Certificate, createPrivateKey } from "node:crypto";
import { mkdir, readFile, unlink, writeFile } from "node:fs/promises";
import net from "node:net";
import path from "node:path";
import { paths } from "../config/paths.js";
import { detectLanIps } from "../config/public-url.js";
import { writeFileAtomic } from "../lib/atomic-file.js";

const execFileP = promisify(execFile);

/**
 * LAN TLS for the web UI + MCP endpoint. Everything the UI carries — the master
 * passphrase at unlock, credentials typed into request_credential forms — must
 * not transit the LAN in the clear, and MCP clients refuse to send OAuth tokens
 * to a non-HTTPS endpoint. Resolution order:
 *
 *   1. `SKELETON_KEY_TLS=off` — explicit opt-out, serve plain HTTP (old behavior).
 *   2. `SKELETON_KEY_TLS_CERT_FILE` + `SKELETON_KEY_TLS_KEY_FILE` — a user-mounted
 *      pair (e.g. from a private CA). Both must be set and readable; a broken
 *      explicit config fails the boot loudly rather than silently serving a
 *      different cert.
 *   3. Self-managed: a self-signed certificate generated into `data/tls/` on
 *      first boot (openssl CLI — present in the image; ubiquitous elsewhere) and
 *      reused until it nears expiry or stops covering the public-URL host. If
 *      generation fails we fall back to the previous material, or to plain HTTP
 *      with a loud warning — a Watchtower-upgraded container must come up
 *      serving *something* rather than crash-loop.
 *
 * The certificate is public material (sent in every handshake); the private key
 * lives mode-0600 in the data volume — same trust domain as the encrypted
 * bootstrap store it sits next to.
 */

export interface TlsMaterial {
  /** PEM certificate presented to clients. */
  cert: string;
  /** PEM private key. */
  key: string;
  source: "mounted" | "generated";
}

/** Apple caps locally-trusted TLS certs at 825 days — stay inside it so the
 *  one-time trust step works on macOS/iOS clients too. */
const CERT_DAYS = 825;
/** Regenerate this long before expiry so a long-running box never crosses into
 *  serving an expired certificate between boots. */
const RENEW_MARGIN_MS = 30 * 24 * 3600 * 1000;

const CERT_NAME = "cert.pem";
const KEY_NAME = "key.pem";

/** TLS on/off switch: exactly the documented `SKELETON_KEY_TLS=off` disables
 *  (case-insensitive); anything else means auto. */
export function tlsMode(): "auto" | "off" {
  return (process.env.SKELETON_KEY_TLS ?? "").trim().toLowerCase() === "off" ? "off" : "auto";
}

/** SHA-256 fingerprint of a PEM certificate — logged at boot so the one-time
 *  trust step can be verified out-of-band against what the browser shows. */
export function certFingerprint(certPem: string): string {
  return new X509Certificate(certPem).fingerprint256;
}

/** URL.hostname wraps IPv6 literals in brackets ("[fd00::1]") — strip them so
 *  the address can be matched against / written into a SAN. */
export function normalizeSanHost(host: string): string {
  return host.replace(/^\[(.+)\]$/, "$1");
}

/**
 * True when the certificate and private key are a matching pair. A mismatch
 * (torn write, half-rotated mounted pair) would otherwise surface only as an
 * ERR_OSSL_X509_KEY_VALUES_MISMATCH throw from https.createServer — after every
 * fallback path has already committed to the material.
 */
export function pairMatches(certPem: string, keyPem: string): boolean {
  try {
    return new X509Certificate(certPem).checkPrivateKey(createPrivateKey(keyPem));
  } catch {
    return false;
  }
}

/**
 * True when the self-managed certificate should be re-issued: unparseable,
 * within RENEW_MARGIN of expiry, or no longer covering one of `requiredHosts`
 * (e.g. the admin pinned SKELETON_KEY_PUBLIC_URL to a host the cert has never
 * seen). Only SANs count — regeneration means every client re-trusts, so the
 * required set is deliberately just the stable public-URL host, never the
 * container's own (churning) interface addresses.
 */
export function needsRegeneration(certPem: string, requiredHosts: string[], now: Date = new Date()): boolean {
  let cert: X509Certificate;
  try {
    cert = new X509Certificate(certPem);
  } catch {
    return true;
  }
  if (Date.parse(cert.validTo) - now.getTime() < RENEW_MARGIN_MS) return true;
  for (const raw of requiredHosts) {
    const host = normalizeSanHost(raw);
    // A host that can never appear in a SAN must not trigger regeneration —
    // it would re-issue (new fingerprint, forced re-trust) on every boot,
    // forever, without ever satisfying the check.
    if (!isSanHost(host)) continue;
    const covered = net.isIP(host) ? cert.checkIP(host) : cert.checkHost(host, { subject: "never" });
    if (!covered) return true;
  }
  return false;
}

/** A host we're willing to put in the SAN list (and therefore into an openssl
 *  config file): an IP literal or a plain DNS name. Anything else is dropped —
 *  this doubles as injection hardening for the generated config. */
function isSanHost(host: string): boolean {
  return net.isIP(host) !== 0 || /^[A-Za-z0-9]([A-Za-z0-9.-]{0,251}[A-Za-z0-9])?$/.test(host);
}

/**
 * Generate a fresh self-signed cert + key pair into `dir` via the openssl CLI
 * (config-file driven, so it works on both OpenSSL and LibreSSL). The pair is
 * committed with writeFileAtomic so a crash mid-generation never leaves a torn
 * pair on disk (and resolveTls additionally verifies the pair matches).
 */
export async function generateSelfSignedCert(opts: {
  dir: string;
  hosts: string[];
  opensslBin?: string;
  days?: number;
}): Promise<{ cert: string; key: string }> {
  await mkdir(opts.dir, { recursive: true, mode: 0o700 });
  const dns: string[] = [];
  const ips: string[] = [];
  for (const host of new Set(opts.hosts.map(normalizeSanHost))) {
    if (!isSanHost(host)) continue;
    (net.isIP(host) ? ips : dns).push(host);
  }
  if (dns.length === 0 && ips.length === 0) {
    dns.push("localhost");
    ips.push("127.0.0.1");
  }
  const alt = [
    ...dns.map((d, i) => `DNS.${i + 1} = ${d}`),
    ...ips.map((ip, i) => `IP.${i + 1} = ${ip}`),
  ].join("\n");
  // CA:TRUE lets the self-signed cert act as its own trust anchor everywhere
  // (NODE_EXTRA_CA_CERTS, browsers, keychains) without a separate CA + leaf.
  const cnf = `[req]
distinguished_name = dn
x509_extensions = ext
prompt = no

[dn]
CN = skeleton-key

[ext]
basicConstraints = critical, CA:TRUE, pathlen:0
keyUsage = critical, digitalSignature, keyEncipherment, keyCertSign
extendedKeyUsage = serverAuth
subjectAltName = @alt

[alt]
${alt}
`;
  const cnfFile = path.join(opts.dir, ".openssl.cnf.tmp");
  const keyTmp = path.join(opts.dir, `.${KEY_NAME}.tmp`);
  const certTmp = path.join(opts.dir, `.${CERT_NAME}.tmp`);
  let cert: string;
  let key: string;
  try {
    await writeFile(cnfFile, cnf, { mode: 0o600 });
    await execFileP(
      opts.opensslBin ?? "openssl",
      [
        "req", "-x509", "-newkey", "rsa:2048", "-sha256", "-nodes",
        "-days", String(opts.days ?? CERT_DAYS),
        "-keyout", keyTmp, "-out", certTmp, "-config", cnfFile,
      ],
      { timeout: 60_000 },
    );
    key = await readFile(keyTmp, "utf8");
    cert = await readFile(certTmp, "utf8");
    // Key lands first: a stray cert without its key is harmless, the reverse isn't.
    await writeFileAtomic(path.join(opts.dir, KEY_NAME), key, 0o600);
    await writeFileAtomic(path.join(opts.dir, CERT_NAME), cert, 0o644);
  } finally {
    await unlink(cnfFile).catch(() => {});
    await unlink(keyTmp).catch(() => {});
    await unlink(certTmp).catch(() => {});
  }
  return { cert, key };
}

export interface ResolveTlsOptions {
  /** Host of the effective public URL, if known — must end up in the SANs. */
  publicUrlHost?: string | null;
  /** Overrides for tests. */
  mode?: "auto" | "off";
  dir?: string;
  certFile?: string;
  keyFile?: string;
  opensslBin?: string;
  lanIps?: string[];
  now?: Date;
  log?: (msg: string) => void;
}

/**
 * Decide what (if anything) the server should serve TLS with. Returns null for
 * plain HTTP — either the explicit opt-out or the generation-failure fallback.
 * Throws only for an explicitly configured but broken mounted pair.
 */
export async function resolveTls(opts: ResolveTlsOptions = {}): Promise<TlsMaterial | null> {
  const log = opts.log ?? ((m: string) => console.log(m));
  if ((opts.mode ?? tlsMode()) === "off") {
    log(
      "[skeleton-key] TLS disabled (SKELETON_KEY_TLS=off) — serving PLAIN HTTP. " +
        "Passphrases and hand-off credentials will transit the LAN unencrypted, and MCP " +
        "clients may refuse the OAuth token endpoint.",
    );
    return null;
  }

  const certFile = opts.certFile ?? process.env.SKELETON_KEY_TLS_CERT_FILE;
  const keyFile = opts.keyFile ?? process.env.SKELETON_KEY_TLS_KEY_FILE;
  if (certFile || keyFile) {
    // An explicit mounted pair is deliberate config — fail the boot loudly on
    // any problem instead of silently serving some other certificate.
    if (!certFile || !keyFile) {
      throw new Error(
        "SKELETON_KEY_TLS_CERT_FILE and SKELETON_KEY_TLS_KEY_FILE must be set together (or neither).",
      );
    }
    let cert: string;
    let key: string;
    try {
      cert = await readFile(certFile, "utf8");
      key = await readFile(keyFile, "utf8");
    } catch (err) {
      throw new Error(
        `Could not read the mounted TLS pair (${certFile} / ${keyFile}): ` +
          `${err instanceof Error ? err.message : String(err)}`,
      );
    }
    try {
      new X509Certificate(cert);
    } catch {
      throw new Error(`SKELETON_KEY_TLS_CERT_FILE (${certFile}) is not a parseable PEM certificate.`);
    }
    if (!pairMatches(cert, key)) {
      // Without this check the mismatch surfaces as a cryptic OpenSSL throw
      // from https.createServer (e.g. after rotating only one half of the pair).
      throw new Error(
        `SKELETON_KEY_TLS_KEY_FILE (${keyFile}) is not the private key for SKELETON_KEY_TLS_CERT_FILE (${certFile}).`,
      );
    }
    return { cert, key, source: "mounted" };
  }

  // Self-managed certificate in the data volume.
  const dir = opts.dir ?? paths.tlsDir;
  let existing: { cert: string; key: string } | null = null;
  try {
    existing = {
      cert: await readFile(path.join(dir, CERT_NAME), "utf8"),
      key: await readFile(path.join(dir, KEY_NAME), "utf8"),
    };
  } catch {
    /* first boot (or half-missing pair) — generate below */
  }
  if (existing && !pairMatches(existing.cert, existing.key)) {
    // A torn re-issue (crash between the two writes) or corrupted volume must
    // never reach https.createServer — it would throw KEY_VALUES_MISMATCH and
    // crash-loop the boot. Treat it as absent: regenerate, or fall back to HTTP.
    log(`[skeleton-key] WARNING: the on-disk TLS pair in ${dir} is torn or mismatched — re-issuing.`);
    existing = null;
  }
  const required = opts.publicUrlHost ? [opts.publicUrlHost] : [];
  if (opts.publicUrlHost && !isSanHost(normalizeSanHost(opts.publicUrlHost))) {
    log(
      `[skeleton-key] WARNING: public URL host "${opts.publicUrlHost}" cannot appear in a certificate SAN — ` +
        "clients dialing it will fail TLS hostname verification.",
    );
  }
  if (existing && !needsRegeneration(existing.cert, required, opts.now)) {
    return { ...existing, source: "generated" };
  }

  const hosts = ["localhost", "127.0.0.1", ...(opts.lanIps ?? detectLanIps()), ...required];
  try {
    const fresh = await generateSelfSignedCert({ dir, hosts, opensslBin: opts.opensslBin });
    log(
      existing
        ? "[skeleton-key] TLS certificate re-issued (near expiry or missing the public-URL host) — browsers and NODE_EXTRA_CA_CERTS clients must re-trust it."
        : `[skeleton-key] Generated a self-signed TLS certificate in ${dir} (one-time browser trust step required — see README).`,
    );
    return { ...fresh, source: "generated" };
  } catch (err) {
    const msg = err instanceof Error ? err.message : String(err);
    if (existing) {
      log(
        `[skeleton-key] WARNING: TLS certificate re-issue failed (${msg}); continuing with the existing certificate.`,
      );
      return { ...existing, source: "generated" };
    }
    log(
      `[skeleton-key] WARNING: TLS certificate generation failed (${msg}) — falling back to PLAIN HTTP. ` +
        "Fix the cause (is `openssl` installed?) or mount a pair via SKELETON_KEY_TLS_CERT_FILE/KEY_FILE.",
    );
    return null;
  }
}
