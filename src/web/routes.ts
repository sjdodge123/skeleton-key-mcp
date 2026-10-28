import { existsSync } from "node:fs";
import { Router, type Request, type Response } from "express";
import { z } from "zod";
import sodium from "../lib/sodium.js";
import type { AppState } from "../app.js";
import { env } from "../config/paths.js";
import { saveUnlockKey, removeUnlockKey } from "../secrets/unlock-key-file.js";
import { SetupService } from "../setup/setup-service.js";
import { scanLan } from "../discovery/scan.js";
import { listConnectors, getConnector, registerableType } from "../connectors/index.js";
import { resolveTools } from "../mcp/tool-registry.js";
import { listSkeletons, streamSkeletonTar } from "../snapshots/snapshot-service.js";
import { paramStr } from "./http-util.js";
import { lockoutMessage, passphraseRateLimit, refuseLockedOut, clientAttempt, totpRateLimit } from "./rate-limit.js";

/** Strip URLs from a vault error before it leaves on the unauthenticated status
 *  endpoint — the vault's address is not something a LAN client should learn. */
function redactUrls(msg: string | null | undefined): string | null {
  return msg ? msg.replace(/https?:\/\/[^\s"')]+/gi, "<vault url>") : null;
}

function hostOf(url: string | null | undefined): string | null {
  if (!url) return null;
  try {
    return new URL(url).host;
  } catch {
    return null;
  }
}

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
  // Every route below that takes a TOTP code mounts this first: a locked-out
  // client gets 429 before its body is parsed (see ./rate-limit.ts).
  const totpLimit = totpRateLimit(app);

  /** Verify the body's code through the attempt limiter. On refusal sends 403
   *  (wrong code) or 429 + Retry-After (locked out) and returns false. */
  const totpOk = (req: Request, res: Response, totp: string): boolean => {
    const check = app.checkTotp(totp, clientAttempt(req));
    if (check.ok) return true;
    if (check.retryAfterSeconds) {
      refuseLockedOut(res, check.retryAfterSeconds).json({ error: lockoutMessage(check.retryAfterSeconds) });
    } else {
      res.status(403).json({ error: "Invalid authenticator code." });
    }
    return false;
  };

  // --- Status (always available) ---
  router.get(
    "/status",
    h(async (_req, res) => {
      res.json({
        setupComplete: await app.isSetupComplete(),
        storeExists: await app.store.exists(),
        storeLocked: app.store.locked,
        vaultUnlocked: app.vault.unlocked,
        vaultError: redactUrls(app.vaultError),
        publicUrl: app.publicUrl(),
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
      const { passphrase } = z.object({ passphrase: z.string().min(8) }).parse(req.body ?? {});
      await app.store.initialize(passphrase);
      res.json({ ok: true });
    }),
  );

  router.post(
    "/store/unlock",
    passphraseRateLimit(app),
    h(async (req, res) => {
      const { passphrase } = z.object({ passphrase: z.string().min(1) }).parse(req.body ?? {});
      // Attempt-limited like TOTP (its own budget); also one argon2 at a time.
      const refused = await app.unlockWithPassphrase(passphrase, clientAttempt(req));
      if (refused) {
        const { retryAfterSeconds: wait, busy } = refused;
        refuseLockedOut(res, wait).json({ error: busy ? "An unlock is already in progress — try again in a moment." : lockoutMessage(wait, "passphrases") });
        return;
      }
      // Re-establish the saved vault session, keep the bearer hash current, and
      // nudge locked sessions to re-list tools — shared with the boot paths.
      // A vault failure here must not read as a failed unlock: the store IS
      // open, so say so and let the admin page offer the repair (re-pointing
      // the vault URL) instead of bouncing the user back to the passphrase box.
      try {
        await app.postUnlock();
      } catch (err) {
        res.json({
          ok: true,
          vaultUnlocked: false,
          vaultError: redactUrls(err instanceof Error ? err.message : String(err)),
        });
        return;
      }
      res.json({ ok: true, vaultUnlocked: app.vault.unlocked });
    }),
  );

  // --- Boot auto-unlock (keyslot + host-mounted key file) ---
  // Sensitive: post-setup, enabling/disabling requires a fresh TOTP code (like
  // OAuth revocation). During the wizard the store was just created by the
  // person at the keyboard and TOTP may not be enrolled yet, so it's open —
  // consistent with the other pre-setup mutations.
  const guardAutoUnlock = async (req: Request, res: Response): Promise<boolean> => {
    if (app.store.locked) {
      res.status(409).json({ error: "Unlock the store first." });
      return false;
    }
    if (await app.isSetupComplete()) {
      const { totp } = z.object({ totp: z.string().min(6) }).parse(req.body ?? {});
      if (!totpOk(req, res, totp)) return false;
    }
    return true;
  };

  // Status is gated too (POST so the TOTP travels in the body): whether the
  // restart kill-switch is disabled — and where the key file lives — is not
  // something an unauthenticated LAN client should be able to enumerate.
  router.post(
    "/store/autounlock/status",
    totpLimit,
    h(async (req, res) => {
      if (!(await guardAutoUnlock(req, res))) return;
      res.json({
        enabled: await app.store.autoUnlockEnabled(),
        keyFile: env.unlockKeyFile,
        keyFilePresent: existsSync(env.unlockKeyFile),
      });
    }),
  );

  router.post(
    "/store/autounlock/enable",
    totpLimit,
    h(async (req, res) => {
      if (!(await guardAutoUnlock(req, res))) return;
      const key = await app.store.enableAutoUnlock();
      try {
        await saveUnlockKey(env.unlockKeyFile, key);
      } catch (err) {
        // No key file → the slot is useless; roll it back so state stays honest.
        await app.store.disableAutoUnlock().catch(() => {});
        res.status(400).json({
          error:
            `Could not write the unlock key file (${env.unlockKeyFile}): ` +
            `${err instanceof Error ? err.message : String(err)}. ` +
            "Mount a writable host directory there (see docker-compose.yml) or set SKELETON_KEY_UNLOCK_KEY_FILE.",
        });
        return;
      } finally {
        sodium.memzero(key);
      }
      app.audit.record({
        ts: new Date().toISOString(), tool: "store.autounlock_enable", target: "bootstrap-store",
        tier: "execute", args: { keyFile: env.unlockKeyFile }, status: "ok",
        detail: "boot auto-unlock enabled (keyslot + key file)",
      });
      res.json({ ok: true, keyFile: env.unlockKeyFile });
    }),
  );

  router.post(
    "/store/autounlock/disable",
    totpLimit,
    h(async (req, res) => {
      if (!(await guardAutoUnlock(req, res))) return;
      await app.store.disableAutoUnlock();
      const keyFileRemoved = await removeUnlockKey(env.unlockKeyFile);
      app.audit.record({
        ts: new Date().toISOString(), tool: "store.autounlock_disable", target: "bootstrap-store",
        tier: "execute", args: { keyFile: env.unlockKeyFile, keyFileRemoved }, status: "ok",
        detail: "boot auto-unlock disabled (keyslot removed)",
      });
      res.json({ ok: true, keyFileRemoved });
    }),
  );

  // --- Vault connection (post-setup repair) ---
  // Re-point the Vaultwarden client at a new https:// URL — the fix when the
  // stored LAN http:// address stops being accepted by the Bitwarden CLI. Same
  // gate as the auto-unlock controls: store unlocked, and once setup is
  // complete a fresh TOTP (it re-logs the service account in and rewrites a
  // bootstrap secret). Fails closed: the stored URL is only replaced after the
  // vault unlocks and syncs on the new one.
  router.post(
    "/vault/server",
    totpLimit,
    h(async (req, res) => {
      if (!(await guardAutoUnlock(req, res))) return;
      const { serverUrl } = z
        .object({
          serverUrl: z
            .string()
            .url()
            .refine((u) => u.startsWith("https://"), { message: "The Bitwarden CLI only accepts https:// vault URLs." }),
        })
        .parse(req.body ?? {});
      const prior = app.store.get().bwServerUrl;
      try {
        await app.changeVaultServer(serverUrl);
      } catch (err) {
        const message = err instanceof Error ? err.message : String(err);
        app.audit.record({
          ts: new Date().toISOString(), tool: "vault.change_server", target: "vaultwarden",
          tier: "execute", args: { host: hostOf(serverUrl), priorHost: hostOf(prior) }, status: "error",
          detail: redactUrls(message) ?? "vault reconnect failed",
        });
        res.status(400).json({ error: message });
        return;
      }
      app.audit.record({
        ts: new Date().toISOString(), tool: "vault.change_server", target: "vaultwarden",
        tier: "execute", args: { host: hostOf(serverUrl), priorHost: hostOf(prior) }, status: "ok",
        detail: "vault server URL changed; service account re-logged in, offline cache re-synced",
      });
      res.json({ ok: true, vaultUnlocked: app.vault.unlocked, checks: await setup.runChecks().catch(() => []) });
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
          serverUrl: z
            .string()
            .url()
            .refine((u) => u.startsWith("https://"), { message: "The Bitwarden CLI only accepts https:// vault URLs." }),
          clientId: z.string().min(1),
          clientSecret: z.string().min(1),
          masterPassword: z.string().min(1),
          collectionName: z.string().optional(),
        })
        .parse(req.body ?? {});
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
      const services = (await scanLan(opts)).map((s) => ({ ...s, registerType: registerableType(s.connectorType, s.port, s.confidence) }));
      res.json({ services });
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
    totpLimit,
    h(async (req, res) => {
      if (!(await guardSetup(res))) return;
      const { token } = z.object({ token: z.string().min(6) }).parse(req.body ?? {});
      const check = setup.verifyTotp(token, clientAttempt(req));
      if (!check.ok && check.retryAfterSeconds) {
        refuseLockedOut(res, check.retryAfterSeconds).json({ error: lockoutMessage(check.retryAfterSeconds) });
        return;
      }
      res.json({ valid: check.ok });
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
          options: z.record(z.string(), z.unknown()).optional(),
        })
        .parse(req.body ?? {});
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
      const name = paramStr(req, "name");
      if (!name) {
        res.status(400).json({ error: "Invalid target name." });
        return;
      }
      const removed = await app.registry.remove(name);
      res.json({ ok: removed });
    }),
  );

  // --- Activity log (audit view) ---
  // TOTP-gated read of the append-only audit log (arguments are only ever stored
  // as a SHA-256 digest, never in the clear). POST so the code travels in the
  // body, like the other admin reads; needs an unlocked store to verify TOTP.
  router.post(
    "/audit/recent",
    totpLimit,
    h(async (req, res) => {
      if (app.store.locked) {
        res.status(409).json({ error: "Unlock the store first." });
        return;
      }
      const { totp, limit } = z
        .object({ totp: z.string().min(6), limit: z.number().int().positive().max(1000).optional() })
        .parse(req.body ?? {});
      if (!totpOk(req, res, totp)) return;
      // `detail` on an EXECUTE entry is the tool's confirmation text, which is
      // derived from the call arguments and can embed a raw command line (SSH
      // run_command, Portainer exec) — i.e. potentially a secret. `args` is already
      // stored only as a hash; redact execute-tier `detail` here too so this reader
      // can never surface argument-derived text. Non-execute detail is
      // system-generated (session/store/oauth events) and safe to show.
      const entries = app.audit.recent(limit ?? 200).map((e) => (e.tier === "execute" ? { ...e, detail: null } : e));
      res.json({ entries });
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
    totpLimit,
    h(async (req, res) => {
      const { totp } = z.object({ totp: z.string().min(6) }).parse(req.body ?? {});
      if (!totpOk(req, res, totp)) return;
      const id = paramStr(req, "id");
      if (!id) {
        res.status(400).json({ error: "Invalid client id." });
        return;
      }
      const ok = app.oauth.revokeClient(id);
      app.audit.record({
        ts: new Date().toISOString(), tool: "oauth.revoke", target: id,
        tier: "execute", args: {}, status: ok ? "ok" : "error", detail: "agent access revoked",
      });
      res.json({ ok });
    }),
  );

  // --- Disaster-recovery skeletons (encrypted config backups) ---
  // TOTP-gated. The list is metadata only. The download decrypts and streams a
  // .tar.gz — the ONLY plaintext egress for skeleton artifacts (which contain
  // secrets), so both need an unlocked store + a fresh TOTP code.
  router.post(
    "/snapshots",
    totpLimit,
    h(async (req, res) => {
      if (app.store.locked) {
        res.status(409).json({ error: "Unlock the store first." });
        return;
      }
      const { totp } = z.object({ totp: z.string().min(6) }).parse(req.body ?? {});
      if (!totpOk(req, res, totp)) return;
      res.json({ skeletons: await listSkeletons() });
    }),
  );

  // --- Pending credential hand-off links ---
  // TOTP-gated, metadata only (names/hosts/expiry — never a value). Lets the
  // admin recover a one-time link that their chat UI failed to render before
  // the TTL runs out. Links are built from the configured public URL ONLY,
  // never the request Host header (anti-phishing, see CLAUDE.md).
  router.post(
    "/credential-requests",
    totpLimit,
    h(async (req, res) => {
      if (app.store.locked) {
        res.status(409).json({ error: "Unlock the store first." });
        return;
      }
      const { totp } = z.object({ totp: z.string().min(6) }).parse(req.body ?? {});
      if (!totpOk(req, res, totp)) return;
      const base = app.publicUrl();
      const requests = app.credentialRequests.list().map((r) => ({
        ...r,
        expiresAt: new Date(r.expiresAt).toISOString(),
        createdAt: new Date(r.createdAt).toISOString(),
        link: `${base ?? ""}/credential/${r.id}`,
      }));
      res.json({ publicUrl: base, requests });
    }),
  );

  router.post(
    "/snapshots/:id/download",
    totpLimit,
    h(async (req, res) => {
      if (app.store.locked) {
        res.status(409).json({ error: "Unlock the store first." });
        return;
      }
      const { totp } = z.object({ totp: z.string().min(6) }).parse(req.body ?? {});
      if (!totpOk(req, res, totp)) return;
      const id = paramStr(req, "id");
      if (!id || !/^[0-9A-Za-z._-]+$/.test(id)) {
        res.status(400).json({ error: "Invalid skeleton id." });
        return;
      }
      res.setHeader("Content-Type", "application/gzip");
      res.setHeader("Content-Disposition", `attachment; filename="skeleton-${id}.tar.gz"`);
      try {
        // Streams gzip→res; validates the id stays inside the snapshots dir and
        // verifies each artifact's plaintext hash before writing it.
        await streamSkeletonTar(app, id, res);
        app.audit.record({ ts: new Date().toISOString(), tool: "snapshots.download", target: id, tier: "execute", args: { id }, status: "ok", detail: "skeleton downloaded" });
      } catch (e) {
        const msg = e instanceof Error ? e.message : String(e);
        app.audit.record({ ts: new Date().toISOString(), tool: "snapshots.download", target: id, tier: "execute", args: { id }, status: "error", detail: msg.slice(0, 300) });
        if (!res.headersSent) {
          res.removeHeader("Content-Type");
          res.removeHeader("Content-Disposition");
          res.status(404).json({ error: "Skeleton not found or unreadable." });
        } else {
          res.destroy();
        }
      }
    }),
  );

  return router;
}
