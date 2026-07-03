import sodium from "./lib/sodium.js";
import { AppState } from "./app.js";
import { buildHttpApp } from "./web/server.js";
import { env, paths } from "./config/paths.js";

async function main(): Promise<void> {
  await sodium.ready;
  const app = await AppState.create();

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
