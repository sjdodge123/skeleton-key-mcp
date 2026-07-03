import { Router, type Request, type Response } from "express";
import { z } from "zod";
import type { AppState } from "../app.js";
import { SetupService } from "../setup/setup-service.js";
import { scanLan } from "../discovery/scan.js";
import { listConnectors, getConnector } from "../connectors/index.js";
import { resolveTools } from "../mcp/tool-registry.js";

/** Wrap an async handler so thrown errors become 400s with a message. */
function h(fn: (req: Request, res: Response) => Promise<void>) {
  return (req: Request, res: Response) => {
    fn(req, res).catch((err: unknown) => {
      const message = err instanceof Error ? err.message : String(err);
      if (!res.headersSent) res.status(400).json({ error: message });
    });
  };
}

/**
 * REST API behind the web UI. During first-run these power the setup wizard;
 * the same target/status endpoints later back the admin console. Setup-mutating
 * endpoints refuse to run once setup is complete (fail closed).
 */
export function buildApiRouter(app: AppState): Router {
  const router = Router();
  const setup = new SetupService(app);

  // --- Status (always available) ---
  router.get(
    "/status",
    h(async (_req, res) => {
      res.json({
        setupComplete: await app.isSetupComplete(),
        storeExists: await app.store.exists(),
        storeLocked: app.store.locked,
        vaultUnlocked: app.vault.unlocked,
        targetCount: app.registry.list().length,
        toolCount: app.store.locked ? 0 : resolveTools(app).length,
        connectors: listConnectors().map((c) => ({
          type: c.type,
          label: c.label,
          requiresCredential: c.requiresCredential,
        })),
      });
    }),
  );

  // --- Store lifecycle ---
  router.post(
    "/store/init",
    h(async (req, res) => {
      if (await app.store.exists()) {
        res.status(409).json({ error: "Store already exists; unlock instead." });
        return;
      }
      const { passphrase } = z.object({ passphrase: z.string().min(8) }).parse(req.body);
      await app.store.initialize(passphrase);
      res.json({ ok: true });
    }),
  );

  router.post(
    "/store/unlock",
    h(async (req, res) => {
      const { passphrase } = z.object({ passphrase: z.string().min(1) }).parse(req.body);
      await app.store.unlock(passphrase);
      // If a Vaultwarden connection was previously saved, re-establish it.
      const s = app.store.get();
      if (s.bwServerUrl && s.bwClientId && s.bwClientSecret && s.bwMasterPassword) {
        await app.vault.reestablish({
          serverUrl: s.bwServerUrl,
          clientId: s.bwClientId,
          clientSecret: s.bwClientSecret,
          masterPassword: s.bwMasterPassword,
        });
      }
      res.json({ ok: true, vaultUnlocked: app.vault.unlocked });
    }),
  );

  // --- Setup-only endpoints ---
  const guardSetup = async (res: Response): Promise<boolean> => {
    if (await app.isSetupComplete()) {
      res.status(403).json({ error: "Setup already complete; use the admin console." });
      return false;
    }
    if (app.store.locked) {
      res.status(409).json({ error: "Initialize or unlock the store first." });
      return false;
    }
    return true;
  };

  router.post(
    "/setup/vault",
    h(async (req, res) => {
      if (!(await guardSetup(res))) return;
      const input = z
        .object({
          serverUrl: z.string().url(),
          clientId: z.string().min(1),
          clientSecret: z.string().min(1),
          masterPassword: z.string().min(1),
          collectionName: z.string().optional(),
        })
        .parse(req.body);
      const checks = await setup.connectVault(input);
      res.json({ checks });
    }),
  );

  router.post(
    "/setup/checks",
    h(async (_req, res) => {
      if (!(await guardSetup(res))) return;
      res.json({ checks: await setup.runChecks() });
    }),
  );

  router.post(
    "/setup/discover",
    h(async (req, res) => {
      if (!(await guardSetup(res))) return;
      const opts = z
        .object({
          subnets: z.array(z.string()).optional(),
          start: z.number().int().optional(),
          end: z.number().int().optional(),
          timeoutMs: z.number().int().optional(),
        })
        .parse(req.body ?? {});
      res.json({ services: await scanLan(opts) });
    }),
  );

  router.post(
    "/setup/totp/begin",
    h(async (_req, res) => {
      if (!(await guardSetup(res))) return;
      res.json(await setup.beginTotpEnrollment());
    }),
  );

  router.post(
    "/setup/totp/verify",
    h(async (req, res) => {
      if (!(await guardSetup(res))) return;
      const { token } = z.object({ token: z.string().min(6) }).parse(req.body);
      res.json({ valid: setup.verifyTotp(token) });
    }),
  );

  router.post(
    "/setup/token",
    h(async (_req, res) => {
      if (!(await guardSetup(res))) return;
      res.json({ token: await setup.generateBearerToken() });
    }),
  );

  router.post(
    "/setup/complete",
    h(async (_req, res) => {
      if (!(await guardSetup(res))) return;
      await setup.complete();
      res.json({ ok: true });
    }),
  );

  // --- Targets (used by both wizard and admin) ---
  router.get(
    "/targets",
    h(async (_req, res) => {
      res.json({ targets: app.registry.list() });
    }),
  );

  router.post(
    "/targets",
    h(async (req, res) => {
      if (!(await guardSetup(res))) return; // v1: registration only during setup
      const body = z
        .object({
          name: z.string().min(1),
          type: z.string().min(1),
          host: z.string().min(1),
          port: z.number().int().positive().optional(),
          credentialRef: z.string().optional(),
          options: z.record(z.unknown()).optional(),
        })
        .parse(req.body);
      const connector = getConnector(body.type);
      if (!connector) {
        res.status(400).json({ error: `Unknown connector type: ${body.type}` });
        return;
      }
      // Validate connector-specific options.
      connector.configSchema.parse(body.options ?? {});
      if (connector.requiresCredential && !body.credentialRef) {
        res.status(400).json({ error: `Connector '${body.type}' requires a credentialRef.` });
        return;
      }
      await app.registry.upsert(body);
      res.json({ ok: true });
    }),
  );

  router.delete(
    "/targets/:name",
    h(async (req, res) => {
      if (!(await guardSetup(res))) return;
      const removed = await app.registry.remove(req.params.name!);
      res.json({ ok: removed });
    }),
  );

  // --- OAuth client management (authorized agents) ---
  router.get(
    "/oauth/clients",
    h(async (_req, res) => {
      res.json({ clients: app.oauth.listClientsWithTokens() });
    }),
  );

  // Revoking an agent's access is sensitive, so require a fresh TOTP code.
  router.post(
    "/oauth/clients/:id/revoke",
    h(async (req, res) => {
      const { totp } = z.object({ totp: z.string().min(6) }).parse(req.body);
      if (!app.verifyTotp(totp)) {
        res.status(403).json({ error: "Invalid authenticator code." });
        return;
      }
      const ok = app.oauth.revokeClient(req.params.id!);
      app.audit.record({
        ts: new Date().toISOString(), tool: "oauth.revoke", target: req.params.id!,
        tier: "execute", args: {}, status: ok ? "ok" : "error", detail: "agent access revoked",
      });
      res.json({ ok });
    }),
  );

  return router;
}
