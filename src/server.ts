import http from "node:http";
import https from "node:https";
import sodium from "./lib/sodium.js";
import { AppState } from "./app.js";
import { buildHttpApp } from "./web/server.js";
import { env, paths } from "./config/paths.js";
import { detectLanBaseUrl, savePublicUrl, switchScheme } from "./config/public-url.js";
import { certFingerprint, resolveTls, tlsMode } from "./web/tls.js";
import { loadUnlockKey } from "./secrets/unlock-key-file.js";

/** Hostname of an absolute URL, or null (used to pin the TLS cert's SANs). */
function urlHost(url: string | null | undefined): string | null {
  try {
    return url ? new URL(url).hostname : null;
  } catch {
    return null;
  }
}

async function main(): Promise<void> {
  await sodium.ready;
  const app = await AppState.create();

  // TLS on by default (self-signed into data/tls, or a user-mounted pair);
  // SKELETON_KEY_TLS=off opts out. A throw here (broken explicit pair) is a
  // deliberate boot failure; generation problems fall back to HTTP inside
  // resolveTls so an auto-upgraded container always comes up.
  // app.publicUrl() already encodes the env-over-persisted precedence (and
  // treats an empty env var as unset) — don't re-derive it here.
  const tls = await resolveTls({ publicUrlHost: urlHost(app.publicUrl()) });
  const scheme: "http" | "https" = tls ? "https" : "http";

  // Determine a public base URL on first boot so user-facing links (unlock
  // guidance, credential hand-off) are clickable out of the box. An explicit
  // SKELETON_KEY_PUBLIC_URL always wins; otherwise, if we haven't persisted one
  // yet, auto-detect the LAN address and remember it. The user can override any
  // time via the env var (which takes priority over the persisted value).
  // When TLS flips on (or off) across an upgrade, the persisted URL's scheme is
  // migrated in place so every link keeps pointing at a reachable origin.
  const pinned = process.env.SKELETON_KEY_PUBLIC_URL;
  const persisted = app.publicUrl();
  if (pinned) {
    if (!pinned.startsWith(`${scheme}://`)) {
      console.warn(
        `[skeleton-key] SKELETON_KEY_PUBLIC_URL (${pinned}) does not match the ${scheme}:// scheme ` +
          "this server is actually serving — user-facing links and the OAuth issuer will be unreachable. " +
          "Update the env var to the new scheme (see README “LAN TLS”).",
      );
    }
  } else if (!persisted) {
    const detected = detectLanBaseUrl(env.port, scheme);
    if (detected) {
      await savePublicUrl(detected).catch(() => {});
      app.setLearnedPublicUrl(detected);
      console.log(`[skeleton-key] Auto-detected public URL: ${detected} (override with SKELETON_KEY_PUBLIC_URL).`);
    }
  } else if (!persisted.startsWith(`${scheme}://`)) {
    if (scheme === "http" && tlsMode() !== "off") {
      // TLS failed this boot but wasn't disabled: keep the https:// links —
      // an accidental fallback must not persist a downgrade of the URLs that
      // carry the master passphrase and hand-off credentials.
      console.warn(
        `[skeleton-key] TLS is unavailable this boot (not disabled) — keeping the persisted public URL (${persisted}) ` +
          "on https://. User-facing links may fail until TLS recovers.",
      );
    } else {
      const migrated = switchScheme(persisted, scheme);
      if (migrated) {
        await savePublicUrl(migrated).catch(() => {});
        app.setLearnedPublicUrl(migrated);
        console.log(`[skeleton-key] Public URL scheme updated for ${scheme.toUpperCase()}: ${persisted} → ${migrated}.`);
      } else {
        console.warn(
          `[skeleton-key] Persisted public URL (${persisted}) could not be migrated to ${scheme}:// ` +
            "(no explicit port, or it carries a path) — user-facing links keep the old scheme. " +
            "Fix data/public-url or set SKELETON_KEY_PUBLIC_URL.",
        );
      }
    }
  }

  // Boot auto-unlock, in order of preference: the web-UI-managed unlock key
  // file (a random key — the passphrase never touches disk), then the
  // DEPRECATED passphrase-in-environment path. If neither applies, the web UI
  // prompts for the passphrase (the wizard handles first-run).
  if (await app.store.exists()) {
    let how: string | null = null;
    const unlockKey = loadUnlockKey(env.unlockKeyFile);
    if (unlockKey) {
      try {
        await app.store.unlockWithKey(unlockKey);
        how = "auto-unlock key file";
      } catch (err) {
        console.error(
          "[skeleton-key] Auto-unlock key file rejected:",
          err instanceof Error ? err.message : err,
        );
      } finally {
        sodium.memzero(unlockKey);
      }
    }
    if (!how) {
      const passphrase = env.unlockPassphrase;
      if (passphrase) {
        console.warn(
          "[skeleton-key] SKELETON_KEY_PASSPHRASE / SKELETON_KEY_PASSPHRASE_FILE are DEPRECATED: " +
            "enable boot auto-unlock in the web UI instead — it stores a random unlock key in a " +
            "host-mounted file, so the master passphrase can be removed from the environment entirely.",
        );
        try {
          await app.store.unlock(passphrase);
          how = "passphrase env (deprecated)";
        } catch (err) {
          console.error("[skeleton-key] Boot unlock failed:", err instanceof Error ? err.message : err);
        }
      }
    }
    if (how) {
      try {
        await app.postUnlock();
        console.log(`[skeleton-key] Store unlocked at boot (${how}).`);
      } catch (err) {
        console.error("[skeleton-key] Post-unlock init failed:", err instanceof Error ? err.message : err);
      }
    }
  }

  // Housekeeping: drop expired OAuth codes/tokens at boot and hourly.
  app.oauth.purgeExpired();
  const purgeTimer = setInterval(() => app.oauth.purgeExpired(), 3600_000);
  purgeTimer.unref();

  const httpApp = buildHttpApp(app, { tlsCertPem: tls?.cert ?? null });
  const server = tls
    ? https.createServer({ cert: tls.cert, key: tls.key }, httpApp)
    : http.createServer(httpApp);
  if (tls) {
    // A client still pointed at http:// (or one that doesn't trust the cert)
    // fails the handshake before any route runs — surface a throttled hint so
    // that failure mode is diagnosable from the container log.
    let lastHandshakeLog = 0;
    (server as https.Server).on("tlsClientError", (err) => {
      const now = Date.now();
      if (now - lastHandshakeLog < 60_000) return;
      lastHandshakeLog = now;
      console.warn(
        `[skeleton-key] TLS handshake failed (${err.message}). If this is a client still configured ` +
          "with http://, update it to https:// — and point NODE_EXTRA_CA_CERTS at the certificate " +
          "for Node-based MCP clients (see README).",
      );
    });
  }
  server.listen(env.port, env.bindHost, async () => {
    const setup = await app.isSetupComplete();
    console.log(`[skeleton-key] Listening on ${scheme}://${env.bindHost}:${env.port}`);
    console.log(`[skeleton-key] Data dir: ${paths.dataDir}`);
    if (tls) {
      const where = tls.source === "mounted" ? "mounted via SKELETON_KEY_TLS_CERT_FILE" : "self-signed, data/tls";
      console.log(`[skeleton-key] TLS certificate (${where}) SHA-256 fingerprint: ${certFingerprint(tls.cert)}`);
      console.log(
        `[skeleton-key] One-time trust: download ${app.publicUrl() ?? `https://<host>:${env.port}`}/tls/cert.pem ` +
          "and trust it in your browser/OS; for Claude Code set NODE_EXTRA_CA_CERTS to that file.",
      );
    }
    console.log(
      setup
        ? "[skeleton-key] Setup complete. MCP endpoint at /mcp (bearer required)."
        : "[skeleton-key] First run — open the web UI to complete setup.",
    );
  });

  const shutdown = () => {
    server.close();
    app.audit.close();
    app.oauth.close();
    process.exit(0);
  };
  process.on("SIGTERM", shutdown);
  process.on("SIGINT", shutdown);
}

main().catch((err) => {
  console.error("[skeleton-key] Fatal:", err);
  process.exit(1);
});
