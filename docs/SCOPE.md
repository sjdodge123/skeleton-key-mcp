# Skeleton Key MCP — Project Scope

**One-liner:** An MCP server that gives Claude full, audited access to the homelab — read logs anywhere, execute changes with approval, manage network/router/Home Assistant/NAS/hypervisors, and spin up containers — with credentials pulled from a scoped Vaultwarden collection and a LAN-only admin web UI.

"Keys to the city" for local infrastructure troubleshooting, so no more manual SSH-hopping.

## Decisions made (2026-07-02)

| Decision | Choice |
|---|---|
| Stack | TypeScript / Node (official MCP SDK for server, one language for UI too) |
| Secrets | **Scoped Vaultwarden** — dedicated org/collection + service account (see below). Local encrypted file only for Skeleton Key's own bootstrap secrets. |
| Deployment | Docker container on the NAS, MCP over Streamable HTTP with bearer auth |
| Exposure | LAN only. Never exposed to the open internet. |
| 2FA | TOTP on the admin web UI; scoped service account has its own credentials + API key |
| v1 execute targets | Portainer (Docker), SSH, Home Assistant, Proxmox VMs/LXC |

## Supported service types (examples — users register their own)

Skeleton Key ships with no hard-coded hosts. The table below is the roadmap of
service *types* the connectors target; a deployment registers whatever exists on
its own network, and anything else is reachable via the generic `ssh` / `http`
connectors.

| Service type | Kind | Connector | Notes |
|---|---|---|---|
| Synology DiskStation | NAS (may be multiple, incl. VirtualDSM) | synology + ssh | Multi-target — connector must handle several DSM hosts |
| Pi-hole | DNS sinkhole | pihole + ssh | Relevant to network troubleshooting |
| UniFi (UDM / Cloud Gateway family) | Network gateway | unifi | UniFi OS device — cookie/CSRF auth, not a self-hosted controller login |
| Consumer ISP router | ISP gateway | (documented target) | Often little/no API — read-only at best |
| Home Assistant | Home automation | home-assistant | Long-lived token; HAOS vs container affects config edits |
| Vaultwarden | Password manager | **secrets source** | Not a target — it's where credentials come from (see secrets model) |
| Portainer | Docker management | portainer | Spin up / manage containers — headline feature |
| Proxmox VE | Hypervisor | proxmox | VMs + LXC; strong REST API |
| Nginx Proxy Manager | Reverse proxy | http (later) | Config via API |
| Media / monitoring stack (Plex, *arr, Uptime Kuma, …) | Apps | http (later) | All have REST APIs; low priority |

## Architecture

```
Claude (Code / Desktop / mobile via LAN)
        │  Streamable HTTP + bearer token
        ▼
┌─────────────────────────── Docker on NAS ───────────────────────────┐
│  MCP Server (Node/TS)                                               │
│  ├── Tool registry (per-target tools, read vs execute tiers)        │
│  ├── Approval gate (execute tools require explicit confirmation)    │
│  ├── Audit log (every tool call, append-only)                       │
│  └── Secrets client → Vaultwarden (scoped) + local bootstrap store  │
│                                                                     │
│  Admin Web UI (LAN-only)                                            │
│  ├── Login: passphrase + TOTP (2FA)                                 │
│  └── Manage: targets, URLs, notes, audit log, token rotation        │
└──────────────────────────────────────────────────────────────────────┘
        │ SSH (ssh2)      │ REST APIs
        ▼                 ▼
  Synology · Proxmox · Pi-hole · UniFi OS · Home Assistant · Portainer
```

## Secrets model — scoped Vaultwarden (the crux)

**Goal:** use the existing Vaultwarden, but make it *cryptographically impossible* for Claude/Skeleton Key to read personal passwords — only homelab credentials.

**Why it works:** in the Bitwarden/Vaultwarden model, the personal vault is encrypted with the user's *user key*; each **Organization** has its own separate symmetric key, handed only to that org's members. A service account that belongs *only* to a homelab org never receives the personal user key, so it cannot decrypt personal items — this is a cryptographic boundary, not just an ACL.

**Setup (service account creates its own org — avoids invites/SMTP):**
1. Create a dedicated Vaultwarden **user account** for Skeleton Key (empty personal vault). With sign-ups disabled, invite it from the `/admin` page (needs `ADMIN_TOKEN`); without SMTP the invited email self-registers at `/#/signup`.
2. **Log in as that account** and create an **Organization** "Skeleton Key" (Vaults page → FILTERS → *New organization*, Free plan) — the account becomes the org owner, so no cross-user invite/confirmation is needed.
3. Add one **Collection** ("Homelab") holding *only* local infra credentials (Synology, Proxmox, UniFi, HA token, Portainer, Pi-hole, SSH keys, etc.).
4. Generate the account's **API key** (Settings → Security → Keys → View API Key). Skeleton Key authenticates non-interactively via the `bw` CLI as this account. Because it owns only this org and holds no personal data, it cannot decrypt the real user's personal vault.

**Result:** worst case (full host compromise) exposes only homelab creds — which an attacker on the box already reaches — never personal passwords.

**Local bootstrap store:** a small local file, encrypted with libsodium `crypto_secretbox` (key via argon2id from a passphrase entered at unlock), holds *only* Skeleton Key's own secrets: the Vaultwarden service-account API key, the MCP bearer token, and the TOTP seed. Everything else lives in Vaultwarden. Vault starts **locked**; unlocked via the web UI after boot.

**Durability — offline cache (resolves the "what if Vaultwarden is down?" problem):** the `bw` CLI keeps a *local encrypted vault cache* (`data.json`) and serves reads from it **offline** — the server is only contacted to *sync*, not to read. Skeleton Key reads credentials from this cache, so it keeps working during a Vaultwarden outage (degrades to last-known-good creds, never locked out). Sync happens on unlock and on a schedule when Vaultwarden is reachable. This is strictly more durable than a bespoke single-file local vault: you get the offline copy *and* a synced backup on the Vaultwarden server, while keeping the cryptographic scoping (only the homelab collection is ever synced/cached).

- **Deployment nuance:** if Vaultwarden and Skeleton Key run on the same NAS, a full-NAS outage takes both down (troubleshoot from elsewhere then). The common cases — Vaultwarden container crash, or a network blip — are fully covered by the cache. For max resilience, host Skeleton Key slightly independent of the component most likely to fail.

## Connector modules (one per integration)

| Connector | Transport | Read tools | Execute tools |
|---|---|---|---|
| **ssh** | ssh2, key/password from Vaultwarden | tail/grep logs, systemctl status, df/top, journalctl | run command (allow/deny-listed), restart service, edit file |
| **portainer** | Portainer REST API | list stacks/containers, container logs, stats | deploy stack/container, start/stop/restart, pull image |
| **proxmox** | Proxmox VE REST API (token auth) | node/VM/LXC status, task logs, resource usage | start/stop/reboot VM & LXC, snapshot |
| **home-assistant** | HA REST + WebSocket (long-lived token) | states, error log, logbook, config check, automation traces | call services, reload configs, restart HA |
| **unifi** | UniFi OS API (cookie/CSRF) | clients, health, WAN status, firewall/port-forward rules, events | (v1: read-only) block client, firewall edits later |
| **synology** | DSM Web API (multi-host) | system health, storage/SMART, package status, shares | packages/shares (careful tier, later) |
| **pihole** | Pi-hole API | query stats, blocklist status, top domains, DNS logs | enable/disable blocking, flush cache |
| **network** | local exec inside container | ping, traceroute, DNS lookup, port check, mtr | — (diagnostics only) |

## Security model (beyond secrets)

- **Tool tiers:** every tool declares `read` or `execute`. Execute tools route through the approval gate and name the exact action + target in confirmation text so the permission prompt is meaningful. Per-connector dry-run where feasible.
- **MCP auth:** static bearer token required on the HTTP transport; stored in the Claude client config, not the repo.
- **Audit:** append-only SQLite table — tool, target, args digest, caller, timestamp, result status. Viewable in the web UI.
- **Blast-radius limits:** SSH allow/deny command lists (deny `rm -rf`, `mkfs`, `dd`, etc.); destructive UniFi/DSM endpoints excluded from v1.
- **Web UI:** LAN-bound only, HTTPS (local/self-signed cert), single admin account (+ optional second user later).

## Build phases

1. **Core skeleton** — MCP server over Streamable HTTP + bearer auth; local bootstrap store; Vaultwarden secrets client (unlock, fetch by item name); target registry; audit log.
2. **SSH connector** — read tools first (logs, status), then gated execute. Satisfies "read logs on every server."
3. **Execute connectors** — Portainer → Home Assistant → Proxmox (the confirmed v1 execute set).
4. **Read connectors** — Pi-hole, UniFi (read-only), Synology, network diagnostics.
5. **Admin web UI** — passphrase + TOTP login, target/notes CRUD, audit viewer, token rotation.
6. **Packaging** — Dockerfile + compose stack deployed via Portainer on the NAS; docs for connecting Claude Code/Desktop.

## Explicit non-goals

- No exposure to the open internet (no reverse proxy, no tunnels — LAN only; VPN into the LAN for remote access).
- No access to the user's personal Vaultwarden vault — only the scoped homelab collection.
- No multi-tenant/user management beyond the single admin.
- No autonomous execution — every state-changing tool goes through the approval gate.

## Open questions

- Home Assistant install type (HAOS vs container) — decides whether config edits go over SSH or the Supervisor API.
- Proxmox: confirm host IP and whether an API token (preferred) vs user/password is used.
- Confirm hostnames/IPs for each target (dashboard entries may be stale) before wiring connectors.
- Does Vaultwarden here support org API-key login for the service account, or fall back to `bw` CLI session unlock? (Verify against the running Vaultwarden version.)
