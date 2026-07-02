# 🗝️ Skeleton Key MCP

Connect it up and it unlocks your homelab's potential.

Skeleton Key is a self-hosted [MCP](https://modelcontextprotocol.io) server that lets Claude **read logs across your whole homelab** and, **with your approval, act on it** — restart a service, run a command, hit an API — from one place. Credentials come from a **scoped Vaultwarden collection** it can read but that can never expose your personal passwords. A first-run web wizard walks you through the whole setup.

It's a framework, not a fixed inventory: connectors are adapters for a *type* of service, and you register your own instances. Generic **SSH** and **HTTP** connectors mean anything reachable is usable on day one.

> **Security:** LAN only. Never expose this to the internet. Remote access = VPN into your LAN.

## Quick start

CI publishes an image to `ghcr.io/sjdodge123/skeleton-key-mcp:latest` on every push to `main`.

```bash
docker pull ghcr.io/sjdodge123/skeleton-key-mcp:latest
# If the GHCR package is private, log in first:
#   echo <GITHUB_PAT_with_read:packages> | docker login ghcr.io -u sjdodge123 --password-stdin
```

1. **Deploy the container** on your NAS/home server (e.g. import `docker-compose.yml` as a stack in Portainer). Edit the `ports:` line to bind your host's LAN IP.
2. **Open the web UI** at `http://<host>:8787/` and follow the wizard:
   - set a master passphrase (encrypts Skeleton Key's own secrets; also your admin login),
   - create a scoped **Vaultwarden** org + collection + service-account user (the wizard tells you exactly how) and connect it,
   - review the automatic **scoping & durability** checks,
   - optionally **scan your LAN** to discover services and register them,
   - enroll **TOTP** 2FA,
   - copy the **Claude connect command**.
3. **Connect Claude** (Code or Desktop): `claude mcp add --transport http skeleton-key http://<host>:8787/mcp`. On first use, Claude opens a browser **consent page**; approve it with your authenticator code. Claude now sees tools for each registered service.

## Connecting Claude (OAuth)

Skeleton Key is an **OAuth 2.1** resource+authorization server, so there's no token to copy or store in plaintext:

- Add the server (`claude mcp add --transport http skeleton-key http://<host>:8787/mcp`).
- The first request 401s with a discovery hint; Claude auto-registers, then opens the **"Authorize an AI agent"** page served by Skeleton Key.
- You approve with your **TOTP code** (PKCE + short-lived access tokens that auto-refresh).
- Revoke an agent anytime — it's TOTP-gated (`POST /api/oauth/clients/:id/revoke`); a future admin console surfaces this in the UI.

A **static bearer token** is still accepted as a fallback for clients without OAuth support (shown under "Advanced" in the wizard).

## Configuration

### Environment variables

All configuration is optional — the defaults work for a standard container deploy. Set these in the `environment:` block of your compose/Portainer stack.

| Variable | Default | Purpose |
|---|---|---|
| `SKELETON_KEY_DATA_DIR` | `/data` (image) · `./data` (dev) | Directory for all mutable state: the encrypted bootstrap store, the `bw` offline cache, the audit DB, and `targets.yaml`. Back this up; it's the only stateful part. |
| `SKELETON_KEY_PORT` | `8787` | Port the HTTP server (web UI + `/mcp`) listens on **inside** the container. |
| `SKELETON_KEY_BIND_HOST` | `0.0.0.0` | Interface the server binds to inside the container. Leave at `0.0.0.0`; scope exposure with the host-side port mapping (below), not this. |
| `SKELETON_KEY_PASSPHRASE` | _(unset)_ | Optional. If set, the encrypted store is **unlocked automatically at boot** so the MCP endpoint comes back up without manual intervention after a restart. If unset, you unlock via the web UI after each restart. Prefer a Docker/Portainer **secret** over an inline value — it's your master passphrase. |
| `SKELETON_KEY_DISABLE_EXECUTE` | _(unset)_ | Set to `1` as a kill-switch: all `execute`-tier tools are refused and audited as denied, leaving only read-only tools. Useful while testing or if you want Claude to look but not touch. |
| `SKELETON_KEY_PUBLIC_URL` | _(unset)_ | The externally-reachable base URL (e.g. `http://192.168.1.10:8787`). Used as the OAuth issuer / discovery origin so it can't be steered by a forged `Host` header. Set this if a reverse proxy sits in front; otherwise the request's own host is used and `X-Forwarded-*` is ignored. |

### Docker / compose setup

| Setting | Example | Why it matters |
|---|---|---|
| **Port mapping** | `"192.168.1.10:8787:8787"` | **This is your security boundary.** Bind to the NAS's specific **LAN IP**, not `0.0.0.0` or `8787:8787`, so the service is never reachable from the WAN. Format is `HOST_IP:HOST_PORT:CONTAINER_PORT`. Never put this behind an internet-facing reverse proxy. |
| **Networking** | bridge (default) or `network_mode: host` | On the default bridge network the container only sees Docker's internal subnet, so built-in **LAN discovery** can't enumerate your real network — type your subnet (e.g. `192.168.0`) into the scan, or use `network_mode: host` for full discovery. Reaching already-registered targets works either way. |
| **Volume** | `skeleton-key-data:/data` | Persists everything in `SKELETON_KEY_DATA_DIR` across restarts and image updates. Without it you'd re-run the wizard every restart. Use a named volume or a host bind mount you back up. |
| **`image` vs `build`** | `image: ghcr.io/sjdodge123/skeleton-key-mcp:latest` | On the NAS, pull the CI-built image. Use `build: .` only when developing from a source checkout. |
| **`restart`** | `unless-stopped` | Brings Skeleton Key back after a NAS reboot. Pair with `SKELETON_KEY_PASSPHRASE` for hands-off recovery, or unlock via the UI. |
| **Watchtower label** | `com.centurylinklabs.watchtower.enable: "true"` | If you run [Watchtower](https://containrrr.dev/watchtower/), this opts the container into auto-updates: when CI publishes a new `:latest`, Watchtower pulls and recreates it on its next poll. The `/data` volume persists, so no re-setup. Force an immediate update with `docker exec watchtower /watchtower --run-once skeleton-key`. |

Minimal Portainer stack:

```yaml
services:
  skeleton-key:
    image: ghcr.io/sjdodge123/skeleton-key-mcp:latest
    container_name: skeleton-key
    restart: unless-stopped
    ports:
      - "192.168.1.10:8787:8787"   # your NAS's LAN IP
    environment:
      SKELETON_KEY_PORT: "8787"
      SKELETON_KEY_BIND_HOST: "0.0.0.0"
      # SKELETON_KEY_PASSPHRASE: "..."       # optional auto-unlock (prefer a secret)
      # SKELETON_KEY_DISABLE_EXECUTE: "1"    # optional read-only mode
    volumes:
      - skeleton-key-data:/data
volumes:
  skeleton-key-data:
```

## How credentials stay safe

The service account belongs to exactly one Vaultwarden organization/collection. In Bitwarden's model, organization keys are separate from your personal user key, so this account is **cryptographically unable** to decrypt your personal vault — only the homelab collection. Reads are served from the `bw` CLI's **local encrypted offline cache**, so a Vaultwarden outage degrades you to last-known-good credentials instead of locking you out.

## Connectors

| Type | Status | Tools |
|---|---|---|
| `ssh` | ✅ read + gated execute | tail_log, journalctl, service_status, disk_usage, grep_logs, run_readonly, run_command, restart_service |
| `http` | ✅ generic | get (read), request (execute) |
| synology, proxmox, unifi, home-assistant, portainer, pihole | 🔜 later phases | — |

Every tool is tagged `read` or `execute`. Execute tools produce a precise confirmation string, are surfaced to Claude's permission prompt, and are written to an append-only audit log. Destructive shell commands (`rm -rf`, `mkfs`, `dd`, …) are refused by policy even when approved.

## Development

```bash
npm install        # install deps (bundles the sumo libsodium build)
npm run dev        # run the server with reload (tsx watch)
npm run build      # compile to dist/
npm test           # run unit tests (vitest)
npm run typecheck  # type-only check
```

Runtime state lives under `SKELETON_KEY_DATA_DIR` (default `./data`): the encrypted bootstrap store, the `bw` offline cache, the audit DB, and `targets.yaml`. None of it is committed.

Requires the Bitwarden CLI (`bw`) on `PATH` for the Vaultwarden connection step; the Docker image installs it for you.

See `docs/SCOPE.md` for the full architecture and roadmap.
