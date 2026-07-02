# CLAUDE.md

This file provides guidance to Claude Code (claude.ai/code) when working with code in this repository.

## What this is

**Skeleton Key MCP** — an MCP server (TypeScript/Node) that gives Claude full, audited access to a homelab: read logs on any server, execute changes with approval, and manage common services (SSH hosts, Synology, UniFi, Home Assistant, Proxmox, Pi-hole, Docker via Portainer). Credentials come from a **scoped Vaultwarden collection**; a LAN-only admin web UI manages targets. It's a framework — users register their own targets; nothing is hard-coded. See `docs/SCOPE.md` for the full architecture and roadmap.

**This project holds the "keys to the city."** Treat every design choice through a security lens: the whole point is broad infrastructure access, so the guardrails (encryption, 2FA, approval gate, audit log, LAN-only) are load-bearing, not optional polish.

## Fixed decisions (do not relitigate without asking)

- **Stack:** TypeScript / Node, using the official MCP SDK (`@modelcontextprotocol/sdk`).
- **Transport:** Streamable HTTP with a static bearer token (server runs as a Docker container on the NAS, so stdio won't reach it). Not stdio.
- **Secrets:** **Scoped Vaultwarden + offline cache.** Infra credentials live in a dedicated Vaultwarden Organization/Collection accessed by a service account that is a member of *only* that org. Because org keys are separate from the personal user key, this account is **cryptographically unable** to decrypt the user's personal passwords — do not weaken this (e.g. never log in as the user's personal Vaultwarden account, never widen the service account's collections). Reads come from the `bw` CLI's **local encrypted offline cache**, so an outage of the Vaultwarden server does not lock Skeleton Key out (degrades to last-known-good creds); the server is only contacted to sync. A small **local libsodium-encrypted bootstrap store** holds only Skeleton Key's own secrets (the Vaultwarden service-account API key, the MCP bearer token, the TOTP seed). No plaintext `.env` for credentials — a `.env` may hold only non-secret config.
- **2FA:** TOTP (otplib) gates the admin web UI. The scoped service account has its own credentials distinct from the user's personal login.
- **Exposure:** LAN only, always. No internet-facing reverse proxy, no tunnels. Remote access = VPN into the LAN.

## Architecture in one breath

Connector-per-integration behind a single MCP tool registry. Each connector (`ssh`, `portainer`, `proxmox`, `home-assistant`, `unifi`, `synology`, `pihole`, `network`) exposes tools split into two tiers:

- **`read` tools** — logs, status, config inspection, diagnostics. Safe to run freely.
- **`execute` tools** — anything state-changing. Must route through the approval gate and write an audit-log entry. Their confirmation text must name the exact action and target so the permission prompt is meaningful.

Connectors fetch credentials from the Vaultwarden secrets client at call time (held in memory only); they never read a secrets store directly. The **v1 execute set is Portainer, SSH, Home Assistant, and Proxmox** — other connectors are read-only until asked otherwise. Everything a tool does lands in an append-only audit table. The Synology connector is **multi-host** (two DiskStations + a VirtualDSM).

## When adding a new tool

1. Declare its tier (`read` vs `execute`) — this is not optional metadata; the approval gate keys off it.
2. Pull credentials from the Vaultwarden secrets client, not from env or config files.
3. For `execute` tools: write the audit entry (tool, target, args digest, timestamp, result) and honor any per-target command allow/deny list (SSH especially — deny destructive commands like `rm -rf`, `mkfs`, `dd`).
4. Keep destructive NAS/network endpoints out of v1 unless specifically requested.

## Build order

Follow the phases in `docs/SCOPE.md`: core skeleton (server + secrets client + audit) → SSH connector (read then execute) → execute connectors (Portainer → Home Assistant → Proxmox) → read connectors (Pi-hole, UniFi, Synology, network) → admin web UI → Docker packaging. The SSH read tools alone satisfy the core "read logs everywhere" goal, so land those early.

## Commands

- `npm run dev` — run the server with reload (`tsx watch src/server.ts`).
- `npm run build` / `npm run typecheck` — compile to `dist/` / type-only check.
- `npm test` — vitest; `npx vitest run <path>` for a single file, `npm run test:watch` to watch.
- Docker: `docker compose build && docker compose up`; the stack is importable into Portainer on the NAS.

Config comes from env (see `src/config/paths.ts`): `SKELETON_KEY_DATA_DIR` (runtime state), `SKELETON_KEY_PORT`, `SKELETON_KEY_BIND_HOST`, `SKELETON_KEY_PASSPHRASE` (optional boot unlock), `SKELETON_KEY_DISABLE_EXECUTE=1` (kill-switch for all execute tools).

## Implementation notes

- **libsodium:** import from `src/lib/sodium.ts`, never the package directly. We use the **sumo** build (`libsodium-wrappers-sumo`) because the standard build omits `crypto_pwhash` (argon2), and load it via `createRequire` because its published ESM entry is broken.
- **Adding a connector:** implement the `Connector` interface in `src/connectors/types.ts`, register it in `src/connectors/index.ts`. Tools are composed dynamically per registered target in `src/mcp/tool-registry.ts` (`resolveTools`) and namespaced `${type}.${name}.${tool}`. There is no static tool list.
- **Secrets never hit the registry:** `targets.yaml` stores only a `credentialRef` (a Vaultwarden item name); the actual credential is fetched in-memory at call time via `AppState.credentialFor`.
- **Setup gating:** the MCP endpoint returns 503 until `data/setup-complete.json` exists AND the store+vault are unlocked (`src/web/auth.ts`). Setup-mutating API routes fail closed once setup is complete.

## Connector notes (service types, not a specific deployment)

These are portability considerations for the planned connectors — Skeleton Key ships with no hard-coded hosts; users register their own targets.

- **Synology DSM:** the connector must be multi-host (a user may run several DiskStations, incl. VirtualDSM). DSM Web API.
- **UniFi:** UniFi OS devices (UDM/Cloud Gateway family) use the UniFi OS API (cookie/CSRF), not a self-hosted controller login — detect which the user has.
- **Proxmox VE:** prefer API-token auth over user/password.
- **Home Assistant:** HAOS vs container install decides whether config edits go over SSH or the Supervisor API; the REST API + long-lived token covers states/services/logs either way.
- **Pi-hole / DNS:** relevant to network troubleshooting; Pi-hole API for stats/blocklists.
- **Consumer ISP routers:** often little/no API — treat as read-only/documented targets at best.
- **Discovery/networking:** on a bridged container the LAN scan only sees Docker's subnet; users provide their real subnet to the scan or run with host networking (see `src/discovery/scan.ts`).
