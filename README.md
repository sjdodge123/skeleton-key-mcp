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
   - copy the generated **Claude MCP snippet**.
3. **Add the snippet to Claude** (Code or Desktop). Claude now sees tools for each registered service.

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
