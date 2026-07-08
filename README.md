# 🗝️ Skeleton Key MCP

Connect it up and it unlocks your homelab's potential.

Skeleton Key is a self-hosted [MCP](https://modelcontextprotocol.io) server that lets Claude **read logs across your whole homelab** and, **with your approval, act on it** — restart a service, run a command, hit an API — from one place. Credentials come from a **scoped Vaultwarden collection** it can read but that can never expose your personal passwords. A first-run web wizard walks you through the whole setup.

It's a framework, not a fixed inventory: connectors are adapters for a *type* of service, and you register your own instances. Generic **SSH** and **HTTP** connectors mean anything reachable is usable on day one.

**Near-turnkey onboarding:** once your scoped Vaultwarden collection exists and the first MCP connection is made, the rest happens *in conversation with Claude* — it can scan your LAN, generate and store SSH keys, register targets, and validate access, all through built-in tools. See [Conversational onboarding](#conversational-onboarding).

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
   - optionally enable **boot auto-unlock** (see [Boot auto-unlock](#boot-auto-unlock)),
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
| `SKELETON_KEY_UNLOCK_KEY_FILE` | `/run/secrets/skeleton-key/unlock-key` | Where the **boot auto-unlock key** lives inside the container. This is a non-secret *path* — the key itself is a random value the web UI writes there when you enable auto-unlock (see [Boot auto-unlock](#boot-auto-unlock)). Only set this to override the default location. |
| `SKELETON_KEY_PASSPHRASE` / `SKELETON_KEY_PASSPHRASE_FILE` | _(unset)_ | **Deprecated.** The old auto-unlock: your master passphrase in the environment (or in a file the `_FILE` variant points at). Still honored, with a warning at boot, so existing deployments keep working — but prefer [Boot auto-unlock](#boot-auto-unlock), which never puts the passphrase on disk at all. |
| `SKELETON_KEY_DISABLE_EXECUTE` | _(unset)_ | Set to `1` as a kill-switch: all `execute`-tier tools are refused and audited as denied, leaving only read-only tools. Useful while testing or if you want Claude to look but not touch. |
| `SKELETON_KEY_PUBLIC_URL` | _(unset)_ | The externally-reachable base URL (e.g. `http://192.168.1.10:8787`). Used as the OAuth issuer / discovery origin so it can't be steered by a forged `Host` header. Set this if a reverse proxy sits in front; otherwise the request's own host is used and `X-Forwarded-*` is ignored. |

### Docker / compose setup

| Setting | Example | Why it matters |
|---|---|---|
| **Port mapping** | `"192.168.1.10:8787:8787"` | **This is your security boundary.** Bind to the NAS's specific **LAN IP**, not `0.0.0.0` or `8787:8787`, so the service is never reachable from the WAN. Format is `HOST_IP:HOST_PORT:CONTAINER_PORT`. Never put this behind an internet-facing reverse proxy. |
| **Networking** | bridge (default) or `network_mode: host` | On the default bridge network the container only sees Docker's internal subnet, so built-in **LAN discovery** can't enumerate your real network — type your subnet (e.g. `192.168.0`) into the scan, or use `network_mode: host` for full discovery. Reaching already-registered targets works either way. |
| **Volume** | `skeleton-key-data:/data` | Persists everything in `SKELETON_KEY_DATA_DIR` across restarts and image updates. Without it you'd re-run the wizard every restart. Use a named volume or a host bind mount you back up. |
| **`image` vs `build`** | `image: ghcr.io/sjdodge123/skeleton-key-mcp:latest` | On the NAS, pull the CI-built image. Use `build: .` only when developing from a source checkout. |
| **`restart`** | `unless-stopped` | Brings Skeleton Key back after a NAS reboot. Pair with [Boot auto-unlock](#boot-auto-unlock) for hands-off recovery, or unlock via the UI. |
| **Secrets mount** | `/volume1/docker/secrets/skeleton-key:/run/secrets/skeleton-key` | Only needed for [Boot auto-unlock](#boot-auto-unlock): a small host directory where Skeleton Key stores its generated unlock key. Deliberately separate from `/data` so a backup of the data volume never contains both the encrypted store and its key. |
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
      # SKELETON_KEY_DISABLE_EXECUTE: "1"    # optional read-only mode
    volumes:
      - skeleton-key-data:/data
      # Optional, for boot auto-unlock (see README section) — a host dir owned
      # by uid 1000, chmod 700:
      # - /volume1/docker/secrets/skeleton-key:/run/secrets/skeleton-key
volumes:
  skeleton-key-data:
```

## Boot auto-unlock

By default, every container restart **re-locks** Skeleton Key: no tools work (and none are even listed) until you open the web UI and enter your master passphrase. That's a deliberate kill-switch — but it also means a NAS reboot at 3am leaves your MCP endpoint locked until you notice.

Auto-unlock trades that kill-switch for hands-off recovery, without ever writing your passphrase anywhere:

1. **Mount a small host directory** for the key (separate from `/data` on purpose — a backup of the data volume must never contain both the encrypted store and its key):
   ```bash
   mkdir -p /volume1/docker/secrets/skeleton-key
   chown 1000:1000 /volume1/docker/secrets/skeleton-key   # the container runs as uid 1000, not root
   chmod 700 /volume1/docker/secrets/skeleton-key
   ```
   and add the volume line from the stack example above.
2. **Enable it in the web UI** — either the wizard's *Auto-unlock* step on first setup, or any time later from the unlock page (`http://<host>:8787/`): unlock, enter your **authenticator code**, and click *Enable auto-unlock*.

Skeleton Key then generates a **random unlock key**, enrolls it as a second keyslot on the encrypted store, and writes it to the mounted directory. At boot, that key unlocks the store; your passphrase stays exactly where it was — in your head. Disabling (same TOTP-gated page) removes the keyslot and deletes the file; a leaked copy of the old key is useless afterwards.

**Trade-off, stated plainly:** with auto-unlock on, anyone who can restart the container gets an unlocked instance — the restart kill-switch is gone. You're narrowing "who can read the secret" (a `chmod 700` host dir instead of a passphrase in the stack definition and `portainer.db`), not adding a lock. If you want the kill-switch back, disable auto-unlock.

Existing deployments: stores created before auto-unlock migrate to the keyslot format automatically on their next passphrase unlock — nothing manual. If you were using `SKELETON_KEY_PASSPHRASE`, it still works but warns at boot; switch to auto-unlock and delete the env var from your stack.

## Conversational onboarding

After the wizard (scoped vault + first MCP connection), you don't hand-build the rest — you ask Claude. These **global MCP tools** are always available:

| Tool | Tier | What it does |
|---|---|---|
| `network_scan` | read | Scans your LAN for known services (Synology, Proxmox, UniFi, Home Assistant, Portainer, Pi-hole, SSH). Pass your subnet (e.g. `192.168.0`) if running in a bridged container. |
| `vault_generate_ssh_key` | execute | Generates a dedicated ed25519 keypair, stores the **private** key in your Homelab collection, and returns the **public** key + the `authorized_keys` line to install. The private key is never shown. |
| `vault_store_login` | execute | Stores an arbitrary username/password/token + URL in the collection (for APIs, web UIs, …). |
| `vault_list_credentials` | read | Lists the item names in the scoped collection (no secret values). |
| `vault_validate_ssh` | read | SSH-connects to a host with a stored key and runs a harmless `id` to confirm access works. |
| `register_target` | execute | Registers a service as a target so its tools become available. |
| `list_targets` | read | Lists registered targets. |
| `form_skeleton` | execute | Captures an encrypted disaster-recovery snapshot of every registered target (see [Disaster-recovery skeletons](#disaster-recovery-skeletons)). |

A typical first session, entirely in chat:

> **You:** Map my network — my LAN is 192.168.0.
> **Claude:** *(network_scan)* Found a Synology at 192.168.0.20, Proxmox at 192.168.0.30, …
> **You:** Generate an SSH key for the Synology, user `skeletonkey`, and register it.
> **Claude:** *(vault_generate_ssh_key)* Here's the public key to install: `ssh-ed25519 …`. *(register_target)* Registered `synology1`.
> **You:** I installed it — validate.
> **Claude:** *(vault_validate_ssh)* ✅ Works. `uid=1027(skeletonkey) …`

Execute-tier tools go through Claude's approval prompt and are audited; installing the returned public key on each host is the one manual step (that's the security boundary — Skeleton Key never pushes its own key onto your machines).

## How credentials stay safe

The service account belongs to exactly one Vaultwarden organization/collection. In Bitwarden's model, organization keys are separate from your personal user key, so this account is **cryptographically unable** to decrypt your personal vault — only the homelab collection. Reads are served from the `bw` CLI's **local encrypted offline cache**, so a Vaultwarden outage degrades you to last-known-good credentials instead of locking you out.

## Connectors

| Type | Status | Tools |
|---|---|---|
| `ssh` | ✅ read + gated execute | tail_log, journalctl, service_status, disk_usage, grep_logs, run_readonly, run_command, restart_service |
| `http` | ✅ generic | get (read), request (execute) |
| `portainer` | ✅ read + gated execute | list_endpoints, list_containers, container_logs, list_stacks, get_stack_file, start/stop/restart_container, exec_container, update_stack |
| `home-assistant` | ✅ read + gated execute | ha_states, ha_get, ha_logbook, ha_call_service, ha_backup |
| `proxmox` | ✅ read + gated execute | list_nodes, list_guests, node_status, guest_status, list_tasks, task_log, guest_power |
| `unifi` | ✅ read + gated execute | list_devices, list_clients, list_networks, get_settings, set_network_ipv6, set_gateway_feature, set_remote_logging, force_provision |
| synology, pihole | 🔜 later phases | — |

Every tool is tagged `read` or `execute`. Execute tools produce a precise confirmation string, are surfaced to Claude's permission prompt, and are written to an append-only audit log. Destructive shell commands (`rm -rf`, `mkfs`, `dd`, …) are refused by policy even when approved.

The UniFi connector can also stream a gateway's logs off-box (`set_remote_logging` — syslog / kernel netconsole to a LAN collector, RFC1918-only) and push a pending controller change onto the device (`force_provision`) so a `/rest/setting` write actually applies rather than sitting in the controller DB.

## Disaster-recovery skeletons

Ask Claude to `form_skeleton` and it walks every registered target and captures a **config snapshot** — scrubbed settings plus native backups where the service offers one: UniFi's `.unf` export, a Home Assistant backup, Pi-hole's teleporter, Proxmox guest/storage/network configs, Portainer stack compose + container inspects, and read-only system profiles over SSH. It's your pre-change safety net (e.g. before a risky network experiment).

Because a backup contains secrets, this is handled with the same care as the vault:

- Each artifact is **encrypted at rest** (XChaCha20-Poly1305) under a key held inside the already-encrypted bootstrap store, written to `data/skeletons/<id>/…` alongside a manifest and a `RESTORE.md`. A copy of the `/data` volume alone can't decrypt a skeleton — the store's key is wrapped by the off-volume auto-unlock key.
- The snapshot bytes **never reach the chat, a tool result, the manifest, or the audit log** — `form_skeleton` returns only a summary. The one plaintext egress is a **TOTP-gated download** (`POST /api/snapshots/:id/download`) from the web UI, which decrypts and streams a `.tar.gz`. Per-target failures are isolated, so one unreachable host yields a partial skeleton rather than no skeleton.

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
