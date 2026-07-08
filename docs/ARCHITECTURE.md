# Architecture

Skeleton Key is a self-hosted **MCP server** that gives an AI agent audited access to a homelab: read logs, run approved commands, and manage services across the user's machines. It runs as a Docker container on the LAN, authenticates agents via OAuth 2.1, and pulls infrastructure credentials from a **scoped Vaultwarden collection** it can read but that can never expose the user's personal passwords.

This document is the orientation map. For build/commands and hard rules see `CLAUDE.md`; for the product scope and roadmap see `docs/SCOPE.md`; for current state and open threads see `docs/STATUS.md`.

## Big picture

```
Claude (MCP client)
  │  Streamable HTTP + OAuth 2.1 access token
  ▼
┌──────────────────────── Docker container on the LAN ────────────────────────┐
│  Express app (src/web/server.ts) — one LAN-bound port                        │
│    /            wizard SPA (src/web/ui.ts)                                    │
│    /api         wizard + admin REST (src/web/routes.ts)                       │
│    /oauth/*,    OAuth 2.1 authz server + discovery (src/web/oauth-routes.ts)  │
│      /.well-known/*                                                           │
│    /mcp         stateful MCP endpoint (mountMcp), gated by mcpAuth            │
│                                                                              │
│  MCP core (src/mcp/*)                                                         │
│    buildMcpServer → ListTools/CallTool + server `instructions`               │
│    resolveTools   → global tools ⊕ per-target connector tools                │
│    approval       → read/execute tiers + audit                               │
│                                                                              │
│  AppState (src/app.ts): store · vault · registry · audit · oauth · TOTP       │
│    - onToolsChanged/emitToolsChanged → live tools/list_changed push          │
│                                                                              │
│  Secrets: bootstrap store (libsodium) + Vaultwarden client (bw CLI + cache)  │
│  Persistence (SQLite): audit.sqlite, oauth.sqlite                             │
│  Registry: targets.yaml (no secrets — only credentialRefs)                    │
└──────────────────────────────────────────────────────────────────────────────┘
   │ SSH (ssh2)          │ HTTP/REST          │ bw CLI
   ▼                     ▼                    ▼
 target hosts       target web APIs      Vaultwarden (scoped org/collection)
```

All mutable state lives under `SKELETON_KEY_DATA_DIR` (`/data` in the image, a Docker volume): the encrypted bootstrap store, the `bw` offline cache, `audit.sqlite`, `oauth.sqlite`, `targets.yaml`, `setup-complete.json`, and the encrypted disaster-recovery skeletons (`skeletons/`, `paths.snapshotsDir`).

## Module responsibilities

**Entry / state**
- `src/server.ts` — process entry. Boots, optionally auto-unlocks — preferring the web-UI-managed unlock key file (`SKELETON_KEY_UNLOCK_KEY_FILE`, a random keyslot key; the passphrase never touches disk) over the deprecated `SKELETON_KEY_PASSPHRASE_FILE` / `SKELETON_KEY_PASSPHRASE` env path — starts an hourly OAuth-token purge, listens, and shuts down cleanly.
- `src/app.ts` — `AppState`: the shared handles (bootstrap store, Vaultwarden client, target registry, audit log, OAuth service). Also `verifyTotp` (single source of truth for admin 2FA), `credentialFor`, `isSetupComplete`, and the `onToolsChanged`/`emitToolsChanged` event used for live tool-list updates.
- `src/config/paths.ts` — resolves the data dir and all file paths (incl. `snapshotsDir` = `data/skeletons`); reads `SKELETON_KEY_*` env.
- `src/config/public-url.ts` — the public base URL for user-facing links (unlock guidance, credential hand-off). Auto-detects the LAN address on first boot and persists it (`data/public-url`); `AppState.publicUrl()` resolves `SKELETON_KEY_PUBLIC_URL` → persisted value → null. Never derived from a request `Host` header (those links ask for secrets — anti-phishing).

**Secrets**
- `src/secrets/bootstrap-store.ts` — a libsodium `crypto_secretbox` file holding *only* Skeleton Key's own secrets (bw API key, master password, MCP bearer token, TOTP seed, and the `snapshotKey` that encrypts disaster-recovery skeletons — generated lazily on first `form_skeleton`, so `/data` alone can't decrypt a skeleton). A random data key encrypts the payload and is wrapped per keyslot (v2 `SKMCP2`): always by an argon2id passphrase KEK, optionally by a random boot auto-unlock key kept in a host-mounted file (`src/secrets/unlock-key-file.ts`). Legacy v1 stores migrate on first passphrase unlock. Locked at rest; keys only in memory.
- `src/secrets/vaultwarden.ts` — wraps the `bw` CLI against the scoped service account. Reads come from the CLI's **local encrypted offline cache** (survives Vaultwarden outages); only `sync` touches the server. `reestablish()` brings the client to unlocked from any `bw` state (only sets the server + logs in when unauthenticated — never re-runs `bw config server` while logged in). `createLoginItem()` writes to the scoped collection via `bw create item`, feeding the payload on **stdin** (never argv). Errors are **sanitized** so a `bw` failure can't leak the payload/session into logs; the session travels via `BW_SESSION` env, not argv.
- `src/lib/sodium.ts` — loads the **sumo** libsodium build via `createRequire` (standard build lacks argon2; the package's ESM entry is broken). Import sodium from here only.

**Connectors (per service *type*)**
- `src/connectors/types.ts` — `Connector` (type + config schema + tool factories) and `ConnectorTool` (name, `tier: read|execute`, zod input, optional `confirm`, `run`). Also the optional `Connector.snapshot?(ctx)` hook, which returns `SnapshotArtifact[]` (a filename-safe `name`, plaintext `data` bytes, optional non-secret `note`) for the disaster-recovery skeleton flow. Artifact bytes are PLAINTEXT and may contain secrets, so the snapshot service encrypts them at rest — they must never reach a `ToolResult`, the manifest, the audit log, or the model context.
- `src/connectors/index.ts` — registry (`getConnector`, `listConnectors`) and `registerableType()` (maps a discovered product type to the `ssh`/`http` connector that can actually register it).
- `src/connectors/ssh.ts` + `ssh-exec.ts` — the reference connector: read tools (tail/journalctl/status/df/grep/run_readonly) and gated execute (run_command with a deny-list, restart_service). `shellQuote` for safe remote command building.
- `src/connectors/command-policy.ts` — deny-list (rm -rf, mkfs, dd, fork bombs, …) + a read-only allowlist.
- `src/connectors/ssh-keygen.ts` — shells out to `ssh-keygen` for OpenSSH-format ed25519 keys (reliably parsed by ssh2); keys generated in a throwaway temp dir.
- `src/connectors/http.ts` — generic HTTP/REST connector (fallback for any web service).
- `src/connectors/home-assistant.ts` — bespoke **Home Assistant** connector (REST + long-lived bearer token). Read: `ha_states` (all/one/filter), `ha_get` (allowlisted read-only GET escape hatch — side-effecting paths like `/api/webhook` refused), `ha_logbook`. Execute: `ha_call_service` (POST `/api/services/<domain>/<service>`), `ha_backup` (`backup.create_automatic`). Exists because the generic `http` connector double-encodes a POST body (untyped `z.unknown()` → the client sends a JSON *string* → `JSON.stringify` again → HA rejects it with a bare `400`); here service data is a typed object, normalized and JSON-encoded exactly once.
- `src/connectors/portainer.ts` — bespoke **Portainer** connector (Docker mgmt). Auth via a Portainer API key (`X-API-Key`, read from an explicit `token`/`api_key` field) or username/password → JWT. Read tools: `list_endpoints`, `list_containers`, `container_logs` (Docker log-frame demux), `list_stacks`, `get_stack_file`. Execute tools: `start/stop/restart_container` and `update_stack` (redeploy a stack from an edited compose file — how Skeleton Key can change its own stack's env and recreate it).
- `src/connectors/unifi.ts` — bespoke **UniFi** connector (UniFi OS API, cookie/CSRF). Read: `list_devices`, `list_clients`, `list_networks`, `get_settings` (secrets scrubbed by a `SECRET_KEY` denylist covering the token / `*_key` / `passwd` / `psk` / `secret` / `cert` families — widened after it once exposed the gateway API token, SSH password hash, mgmt key, IPS token, and a PSK). Execute: `set_gateway_feature`, `set_network_ipv6`, plus `set_remote_logging` (surgical read-modify-write of the gateway's rsyslogd group to stream userspace syslog and/or kernel netconsole to a LAN collector — RFC1918 egress guard via `isPrivateIPv4`; built to capture a gateway crash's own logs) and `force_provision` (POST `/cmd/devmgr` `force-provision` so a `/rest/setting` write actually applies on the device rather than only the controller DB; defaults to the gateway, identified positively by role/model, not IP).
- `src/connectors/proxmox.ts` — bespoke **Proxmox VE** connector (PVE REST `/api2/json`). Auth via an API token (`Authorization: PVEAPIToken=<id>=<secret>`, preferred) or a username/password ticket (`PVEAuthCookie` + a `CSRFPreventionToken` on writes). Read: `list_nodes`, `list_guests` (VMs + CTs via `/cluster/resources`), `node_status`, `guest_status`, `list_tasks`, `task_log`. Execute: `guest_power` (start/shutdown/reboot/stop a guest, looked up by vmid so the approval names it exactly; a hard `stop` is called out). Requests are time-bounded; a POST timeout is reported as `OUTCOME UNKNOWN` (the action may have started). Destructive lifecycle ops (delete/snapshot-rollback/migrate) are out of v1.

**Discovery**
- `src/discovery/scan.ts` — opt-in LAN scan (RFC1918-gated). Fingerprints each open port: SSH banner for 22; HTTP GET + content-signature match for web ports. Emits a `confidence` (confirmed/likely/open). `matchHttp` is the pure matcher; `httpProbe` always settles (bounded body read).

**Snapshots (disaster-recovery skeletons)**
- `src/snapshots/crypto.ts` — the `snapshotKey` lifecycle (`getOrCreateSnapshotKey`, lazily minted into the bootstrap store) plus `crypto_aead_xchacha20poly1305_ietf` `encryptArtifact`/`decryptArtifact` (per-artifact random nonce, the target/artifact path bound as AAD) and a plaintext `sha256`.
- `src/snapshots/tar.ts` — `TarWriter`, a hand-rolled streaming ustar writer (no dependency); combined with `node:zlib` gzip it produces the download `.tar.gz`.
- `src/snapshots/snapshot-service.ts` — orchestration. `formSkeleton(app)` iterates every registered target, calls each connector's `snapshot(ctx)`, encrypts each artifact under the `snapshotKey`, and writes `data/skeletons/<id>/<target>/<artifact>.enc` + `manifest.json` + `RESTORE.md`; per-target failures are isolated (partial skeleton, never a hard fail) and it returns a summary only. `listSkeletons` reads manifest metadata; `streamSkeletonTar` decrypts (verifying each artifact's plaintext hash and that the id stays inside the snapshots dir) and streams the gzip tar — the only plaintext egress.

**MCP**
- `src/mcp/server.ts` — `buildMcpServer`: low-level SDK `Server` with `ListTools`/`CallTool` handlers and onboarding `instructions` sent on connect.
- `src/mcp/tool-registry.ts` — `resolveTools`: composes **global tools** (built once per app, memoized) + **per-target connector tools** into one `ResolvedTool` with a bound `invoke(input)` and `targetName` (null for global). No static tool list.
- `src/mcp/builtin-tools.ts` — the global tools: `get_started`, `network_scan`, `vault_generate_ssh_key`, `vault_store_login`, `vault_list_credentials`, `vault_validate_ssh`, `register_target`, `update_target`, `vault_delete_credential`, `request_credential`, `credential_request_status`, `list_targets`, `form_skeleton` (execute — snapshot every registered target to an encrypted on-box skeleton; returns a summary only, artifact bytes never leave the box here).
- `src/mcp/approval.ts` — `read`/`execute` annotations + confirmation text for the permission prompt.

**Web / transport**
- `src/web/server.ts` — the Express app; `mountMcp()` implements the **stateful** Streamable HTTP endpoint (sessions keyed by `Mcp-Session-Id`, idle sweeper + session cap, `tools/list_changed` push). Exported so tests can drive the real session lifecycle.
- `src/web/auth.ts` — `mcpAuth`: setup-complete gate, then accepts a valid OAuth access token **or** the legacy static bearer; 401s carry the RFC 9728 `WWW-Authenticate` discovery hint. Auth routing is independent of lock state, so an expired token gets a 401→refresh (works while locked) rather than a dead 503. A locked vault is a kill-switch enforced at the tool layer (CallTool locked gate in `src/mcp/server.ts`): only a banner-only `get_started` runs, so clients get actionable "unlock at `<url>`" guidance without a leaked token being able to enumerate targets or scan the LAN before unlock.
- `src/web/oauth-routes.ts` — OAuth 2.1 authorization server: discovery metadata, dynamic client registration, `/authorize` (TOTP-gated consent screen), `/token`, `/revoke`.
- `src/web/credential-routes.ts` + `credential-requests.ts` — secure credential hand-off (#18): the `request_credential` tool mints a one-time link served here; the user types the secret into a TOTP-gated form that writes it straight to the scoped vault, so secrets never transit the chat/MCP channel. `CredentialRequestStore` holds only request *metadata* (never the secret), with a 15-min TTL and single-use fulfillment.
- `src/oauth/oauth-service.ts` — token/code/client store (SQLite). PKCE S256, single-use codes, refresh-token rotation, opaque tokens stored as SHA-256 hashes.
- `src/web/routes.ts` — wizard + admin REST (store init/unlock, vault connect, checks, discover, TOTP, token, target CRUD, OAuth client list/revoke). Also the TOTP-gated skeleton routes: `POST /api/snapshots` (list, metadata only) and `POST /api/snapshots/:id/download` (decrypt + stream a `.tar.gz` — the only plaintext egress). Both fail closed: `store.locked` → 409, bad `verifyTotp` → 403.
- `src/web/http-util.ts` — `baseUrl` (prefers `SKELETON_KEY_PUBLIC_URL`, never trusts `X-Forwarded-*`) and `firstStr` (coerces array query/body params).
- `src/web/ui.ts` — the first-run wizard SPA (embedded string; vanilla JS).
- `src/setup/*` — wizard orchestration and the scoping/durability verification.

**Persistence / audit**
- `src/audit/audit-log.ts` — append-only SQLite; args stored as a SHA-256 digest (never in the clear).
- `src/config/registry.ts` — `targets.yaml`; stores `{name,type,host,port,credentialRef,options}` — **no secrets**.

## Key flows

**Setup (first run, wizard):** set master passphrase (inits the bootstrap store) → connect the scoped Vaultwarden service account (`reestablish` + `sync`) → automated scoping/durability checks → enroll TOTP → generate the MCP bearer token → mark `setup-complete.json`. See `docs/SCOPE.md` for the scoped-account model and *why* it's cryptographically safe.

**Agent connect (OAuth):** client hits `/mcp` unauthenticated → 401 + `WWW-Authenticate` → client fetches discovery, dynamically registers, opens the browser **consent** page → user approves with a TOTP code → authorization code (PKCE) → `/token` → short-lived access token (+ refresh). Thereafter `mcpAuth` validates the token per request.

**Tool call:** `mountMcp` routes to the session's `Server` → `CallTool` resolves the tool (`findTool`), validates input (zod), applies the approval/execute gate, runs `invoke` (which lazily fetches a credential from the vault for connector tools), and writes an audit row.

**Conversational onboarding:** `network_scan` → `vault_generate_ssh_key` (stores the private key in the vault, returns the public key to install) → `register_target` (persists the target and fires `emitToolsChanged` → `tools/list_changed`, so the new per-target tools appear live) → `vault_validate_ssh`.

**Disaster-recovery skeleton:** `form_skeleton` (or the wider flight-recorder plan) → `formSkeleton` iterates every registered target → each connector's `snapshot(ctx)` returns config exports + cheap native backups (Pi-hole teleporter, UniFi `.unf`, a triggered Home Assistant backup, Proxmox/Portainer/ssh configs) → each artifact is encrypted under the `snapshotKey` to `data/skeletons/<id>/…` alongside a `manifest.json` + `RESTORE.md`. The tool returns a summary only; the admin pulls the plaintext `.tar.gz` off-box later via the TOTP-gated `POST /api/snapshots/:id/download`, which decrypts and streams it.

## Security model (load-bearing)

- **Scoped Vaultwarden + offline cache.** The service account belongs to one org/collection; org keys are separate from the personal user key, so it is *cryptographically* unable to read personal passwords. Reads work offline from the `bw` cache.
- **Secrets never in argv/logs.** `BW_SESSION` env (not `--session`), `bw create item` payload via stdin, sanitized `bw` errors, audit args hashed, generated private keys stored but never returned to the caller.
- **OAuth 2.1 + TOTP consent.** Browser-redirect authorization, PKCE, single-use codes, rotating refresh tokens, per-client revocation — all consent/revocation gated by the admin TOTP.
- **Tool tiers + approval + audit.** Every tool is `read` or `execute`; execute tools carry confirmation text (surfaced to the agent's permission prompt) and are audited. SSH command deny-list is defense-in-depth.
- **LAN only.** Bind to a LAN IP; no internet exposure. `SKELETON_KEY_PUBLIC_URL` pins the OAuth issuer so a forged `Host` header can't redirect discovery.

## Extending

- **New connector:** implement `Connector` in `src/connectors/types.ts`, register in `src/connectors/index.ts`. Per-target tools then compose automatically via `resolveTools`, namespaced `${type}.${name}.${tool}`. Optionally implement `snapshot(ctx)` so the target contributes artifacts to `form_skeleton` (return `SnapshotArtifact[]`; the service encrypts them — never surface the bytes yourself).
- **New global tool:** add to `buildGlobalTools` in `src/mcp/builtin-tools.ts` (operates on the vault/registry, not a single target).
- Always: declare the `read`/`execute` tier, pull credentials from the Vaultwarden client (never env/files), and keep secrets off argv and out of tool results.

## Testing & deploy

- `npm test` (vitest). Notable: `command-policy`, `bootstrap-store`, `oauth-service` (PKCE/rotation/revocation), `scan` (fingerprint matcher + httpProbe no-hang), `mcp-endpoint` (real stateful session lifecycle incl. teardown). Two standalone HTTP flow harnesses live in the session scratchpad (OAuth e2e, stateful MCP) for manual runs.
- Multi-stage `Dockerfile` (bundles the `bw` CLI + `openssh-client`); `docker-compose.yml` is Portainer-importable and LAN-bound. CI (`.github/workflows/ci.yml`) gates every PR; `docker.yml` publishes `ghcr.io/<owner>/skeleton-key-mcp:latest` on merge to `main`.
