// Docker HEALTHCHECK: a localhost liveness probe of /healthz.
//
// Probes the scheme implied by SKELETON_KEY_TLS; in auto mode it falls back to
// HTTP so the cert-generation-failure fallback still reports live (that
// degradation is deliberate — the boot log carries the warning).
//
// The HTTPS probe verifies the server's own certificate rather than skipping
// verification: it trusts the cert the server serves (the self-managed one in
// <data dir>/tls/, or the user-mounted SKELETON_KEY_TLS_CERT_FILE) plus the
// system roots. The self-managed cert names 127.0.0.1, so the hostname check
// applies; a user-mounted cert is issued for the LAN name, not 127.0.0.1, so
// for it only the hostname check is skipped — the chain is still verified.
import { readFileSync } from "node:fs";
import http from "node:http";
import https from "node:https";
import path from "node:path";
import tls from "node:tls";

const port = process.env.SKELETON_KEY_PORT || 8787;
const tlsOff = (process.env.SKELETON_KEY_TLS || "").trim().toLowerCase() === "off";
const mountedCert = process.env.SKELETON_KEY_TLS_CERT_FILE;
const dataDir = path.resolve(process.env.SKELETON_KEY_DATA_DIR || "data");
const certFile = mountedCert || path.join(dataDir, "tls", "cert.pem");

function tlsOptions() {
  const own = readFileSync(certFile, "utf8"); // unreadable → the probe fails → HTTP fallback
  return {
    ca: [own, ...tls.rootCertificates],
    ...(mountedCert ? { checkServerIdentity: () => undefined } : {}),
  };
}

function probe(scheme) {
  return new Promise((resolve, reject) => {
    const mod = scheme === "https" ? https : http;
    const req = mod.get(
      { host: "127.0.0.1", port, path: "/healthz", timeout: 4000, ...(scheme === "https" ? tlsOptions() : {}) },
      (res) => {
        res.resume();
        if (res.statusCode === 200) resolve();
        else reject(new Error(`${scheme} ${res.statusCode}`));
      },
    );
    req.on("timeout", () => req.destroy(new Error(`${scheme} timeout`)));
    req.on("error", reject);
  });
}

(tlsOff ? probe("http") : probe("https").catch(() => probe("http"))).then(
  () => process.exit(0),
  () => process.exit(1),
);
