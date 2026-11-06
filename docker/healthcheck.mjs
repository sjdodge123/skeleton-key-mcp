// Docker HEALTHCHECK: a localhost liveness probe of /healthz.
//
// Probes the scheme implied by SKELETON_KEY_TLS; in auto mode it falls back to
// HTTP so the cert-generation-failure fallback still reports live (that
// degradation is deliberate — the boot log carries the warning).
//
// Certificate verification is skipped for THIS one request only (not through
// NODE_TLS_REJECT_UNAUTHORIZED, which turns it off process-wide and prints a
// warning into every health log): the probe talks to 127.0.0.1, which a
// self-signed or user-mounted certificate need not name, and it sends nothing.
import http from "node:http";
import https from "node:https";

const port = process.env.SKELETON_KEY_PORT || 8787;
const tlsOff = (process.env.SKELETON_KEY_TLS || "").trim().toLowerCase() === "off";

function probe(scheme) {
  return new Promise((resolve, reject) => {
    const mod = scheme === "https" ? https : http;
    const req = mod.get(
      { host: "127.0.0.1", port, path: "/healthz", timeout: 4000, ...(scheme === "https" ? { rejectUnauthorized: false } : {}) },
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
