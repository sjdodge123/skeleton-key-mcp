import sodium from "./lib/sodium.js";
import { AppState } from "./app.js";
import { buildHttpApp } from "./web/server.js";
import { env, paths } from "./config/paths.js";
import { detectLanBaseUrl, savePublicUrl } from "./config/public-url.js";

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

  // If a store already exists and a passphrase was provided via env, unlock at
  // boot; otherwise the web UI prompts for it (the wizard handles first-run).
  if ((await app.store.exists()) && env.unlockPassphrase) {
    try {
      await app.store.unlock(env.unlockPassphrase);
      const s = app.store.get();
      if (s.bwServerUrl && s.bwClientId && s.bwClientSecret && s.bwMasterPassword) {
        await app.vault.reestablish({
          serverUrl: s.bwServerUrl,
          clientId: s.bwClientId,
          clientSecret: s.bwClientSecret,
          masterPassword: s.bwMasterPassword,
        });
        // Best-effort refresh; safe to fail if Vaultwarden is unreachable (offline cache).
        await app.vault.sync().catch(() => {});
      }
      await app.ensureBearerHash();
      console.log("[skeleton-key] Store unlocked at boot.");
    } catch (err) {
      console.error("[skeleton-key] Boot unlock failed:", err instanceof Error ? err.message : err);
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
