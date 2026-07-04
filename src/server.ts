import sodium from "./lib/sodium.js";
import { AppState } from "./app.js";
import { buildHttpApp } from "./web/server.js";
import { env, paths } from "./config/paths.js";
import { detectLanBaseUrl, savePublicUrl } from "./config/public-url.js";
import { loadUnlockKey } from "./secrets/unlock-key-file.js";

async function main(): Promise<void> {
  await sodium.ready;
  const app = await AppState.create();

  // Determine a public base URL on first boot so user-facing links (unlock
  // guidance, credential hand-off) are clickable out of the box. An explicit
  // SKELETON_KEY_PUBLIC_URL always wins; otherwise, if we haven't persisted one
  // yet, auto-detect the LAN address and remember it. The user can override any
  // time via the env var (which takes priority over the persisted value).
  if (!process.env.SKELETON_KEY_PUBLIC_URL && !app.publicUrl()) {
    const detected = detectLanBaseUrl(env.port);
    if (detected) {
      await savePublicUrl(detected).catch(() => {});
      app.setLearnedPublicUrl(detected);
      console.log(`[skeleton-key] Auto-detected public URL: ${detected} (override with SKELETON_KEY_PUBLIC_URL).`);
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

  const httpApp = buildHttpApp(app);
  const server = httpApp.listen(env.port, env.bindHost, async () => {
    const setup = await app.isSetupComplete();
    console.log(`[skeleton-key] Listening on http://${env.bindHost}:${env.port}`);
    console.log(`[skeleton-key] Data dir: ${paths.dataDir}`);
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
