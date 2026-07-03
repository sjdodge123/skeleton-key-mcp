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

All mutable state lives under `SKELETON_KEY_DATA_DIR` (`/data` in the image, a Docker volume): the encrypted bootstrap store, the `bw` offline cache, `audit.sqlite`, `oauth.sqlite`, `targets.yaml`, and `setup-complete.json`.

## Module responsibilities

**Entry / state**
- `src/server.ts` — process entry. Boots, optionally auto-unlocks (`SKELETON_KEY_PASSPHRASE`), starts an hourly OAuth-token purge, listens, and shuts down cleanly.
- `src/app.ts` — `AppState`: the shared handles (bootstrap store, Vaultwarden client, target registry, audit log, OAuth service). Also `verifyTotp` (single source of truth for admin 2FA), `credentialFor`, `isSetupComplete`, and the `onToolsChanged`/`emitToolsChanged` event used for live tool-list updates.
- `src/config/paths.ts` — resolves the data dir and all file paths; reads `SKELETON_KEY_*` env.

**Secrets**
- `src/secrets/bootstrap-store.ts` — a libsodium `crypto_secretbox` file holding *only* Skeleton Key's own secrets (bw API key, master password, MCP bearer token, TOTP seed). Key derived from a passphrase via argon2id. Locked at rest; unlocked in memory.
- `src/secrets/vaultwarden.ts` — wraps the `bw` CLI against the scoped service account. Reads come from the CLI's **local encrypted offline cache** (survives Vaultwarden outages); only `sync` touches the server. `reestablish()` brings the client to unlocked from any `bw` state (only sets the server + logs in when unauthenticated — never re-runs `bw config server` while logged in). `createLoginItem()` writes to the scoped collection via `bw create item`, feeding the payload on **stdin** (never argv). Errors are **sanitized** so a `bw` failure can't leak the payload/session into logs; the session travels via `BW_SESSION` env, not argv.
- `src/lib/sodium.ts` — loads the **sumo** libsodium build via `createRequire` (standard build lacks argon2; the package's ESM entry is broken). Import sodium from here only.

**Connectors (per service *type*)**
- `src/connectors/types.ts` — `Connector` (type + config schema + tool factories) and `ConnectorTool` (name, `tier: read|execute`, zod input, optional `confirm`, `run`).
- `src/connectors/index.ts` — registry (`getConnector`, `listConnectors`) and `registerableType()` (maps a discovered product type to the `ssh`/`http` connector that can actually register it).
- `src/connectors/ssh.ts` + `ssh-exec.ts` — the reference connector: read tools (tail/journalctl/status/df/grep/run_readonly) and gated execute (run_command with a deny-list, restart_service). `shellQuote` for safe remote command building.
- `src/connectors/command-policy.ts` — deny-list (rm -rf, mkfs, dd, fork bombs, …) + a read-only allowlist.
- `src/connectors/ssh-keygen.ts` — shells out to `ssh-keygen` for OpenSSH-format ed25519 keys (reliably parsed by ssh2); keys generated in a throwaway temp dir.
- `src/connectors/http.ts` — generic HTTP/REST connector (fallback for any web service).

**Discovery**
- `src/discovery/scan.ts` — opt-in LAN scan (RFC1918-gated). Fingerprints each open port: SSH banner for 22; HTTP GET + content-signature match for web ports. Emits a `confidence` (confirmed/likely/open). `matchHttp` is the pure matcher; `httpProbe` always settles (bounded body read).

**MCP**
- `src/mcp/server.ts` — `buildMcpServer`: low-level SDK `Server` with `ListTools`/`CallTool` handlers and onboarding `instructions` sent on connect.
- `src/mcp/tool-registry.ts` — `resolveTools`: composes **global tools** (built once per app, memoized) + **per-target connector tools** into one `ResolvedTool` with a bound `invoke(input)` and `targetName` (null for global). No static tool list.
- `src/mcp/builtin-tools.ts` — the global tools: `get_started`, `network_scan`, `vault_generate_ssh_key`, `vault_store_login`, `vault_list_credentials`, `vault_validate_ssh`, `register_target`, `list_targets`.
- `src/mcp/approval.ts` — `read`/`execute` annotations + confirmation text for the permission prompt.

**Web / transport**
- `src/web/server.ts` — the Express app; `mountMcp()` implements the **stateful** Streamable HTTP endpoint (sessions keyed by `Mcp-Session-Id`, idle sweeper + session cap, `tools/list_changed` push). Exported so tests can drive the real session lifecycle.
- `src/web/auth.ts` — `mcpAuth`: setup-complete + vault-unlocked gate, then accepts a valid OAuth access token **or** the legacy static bearer; 401s carry the RFC 9728 `WWW-Authenticate` discovery hint.
- `src/web/oauth-routes.ts` — OAuth 2.1 authorization server: discovery metadata, dynamic client registration, `/authorize` (TOTP-gated consent screen), `/token`, `/revoke`.
- `src/oauth/oauth-service.ts` — token/code/client store (SQLite). PKCE S256, single-use codes, refresh-token rotation, opaque tokens stored as SHA-256 hashes.
- `src/web/routes.ts` — wizard + admin REST (store init/unlock, vault connect, checks, discover, TOTP, token, target CRUD, OAuth client list/revoke).
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

## Security model (load-bearing)

- **Scoped Vaultwarden + offline cache.** The service account belongs to one org/collection; org keys are separate from the personal user key, so it is *cryptographically* unable to read personal passwords. Reads work offline from the `bw` cache.
- **Secrets never in argv/logs.** `BW_SESSION` env (not `--session`), `bw create item` payload via stdin, sanitized `bw` errors, audit args hashed, generated private keys stored but never returned to the caller.
- **OAuth 2.1 + TOTP consent.** Browser-redirect authorization, PKCE, single-use codes, rotating refresh tokens, per-client revocation — all consent/revocation gated by the admin TOTP.
- **Tool tiers + approval + audit.** Every tool is `read` or `execute`; execute tools carry confirmation text (surfaced to the agent's permission prompt) and are audited. SSH command deny-list is defense-in-depth.
- **LAN only.** Bind to a LAN IP; no internet exposure. `SKELETON_KEY_PUBLIC_URL` pins the OAuth issuer so a forged `Host` header can't redirect discovery.

## Extending

- **New connector:** implement `Connector` in `src/connectors/types.ts`, register in `src/connectors/index.ts`. Per-target tools then compose automatically via `resolveTools`, namespaced `${type}.${name}.${tool}`.
- **New global tool:** add to `buildGlobalTools` in `src/mcp/builtin-tools.ts` (operates on the vault/registry, not a single target).
- Always: declare the `read`/`execute` tier, pull credentials from the Vaultwarden client (never env/files), and keep secrets off argv and out of tool results.

## Testing & deploy

- `npm test` (vitest). Notable: `command-policy`, `bootstrap-store`, `oauth-service` (PKCE/rotation/revocation), `scan` (fingerprint matcher + httpProbe no-hang), `mcp-endpoint` (real stateful session lifecycle incl. teardown). Two standalone HTTP flow harnesses live in the session scratchpad (OAuth e2e, stateful MCP) for manual runs.
- Multi-stage `Dockerfile` (bundles the `bw` CLI + `openssh-client`); `docker-compose.yml` is Portainer-importable and LAN-bound. CI (`.github/workflows/ci.yml`) gates every PR; `docker.yml` publishes `ghcr.io/<owner>/skeleton-key-mcp:latest` on merge to `main`.
