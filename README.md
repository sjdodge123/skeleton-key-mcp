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
2. **Open the web UI** at `https://<host>:8787/` and follow the wizard (your browser warns about the self-signed certificate on first visit — see [LAN TLS](#lan-tls) for the one-time trust step):
   - set a master passphrase (encrypts Skeleton Key's own secrets; also your admin login),
   - create a scoped **Vaultwarden** org + collection + service-account user (the wizard tells you exactly how) and connect it,
   - review the automatic **scoping & durability** checks,
   - optionally **scan your LAN** to discover services and register them,
   - enroll **TOTP** 2FA,
   - optionally enable **boot auto-unlock** (see [Boot auto-unlock](#boot-auto-unlock)),
   - copy the **Claude connect command**.
3. **Connect Claude** (Code or Desktop): trust the certificate ([LAN TLS](#lan-tls)), then `claude mcp add --transport http skeleton-key https://<host>:8787/mcp`. On first use, Claude opens a browser **consent page**; approve it with your authenticator code. Claude now sees tools for each registered service.

## Connecting Claude (OAuth)

Skeleton Key is an **OAuth 2.1** resource+authorization server, so there's no token to copy or store in plaintext:

- Add the server (`claude mcp add --transport http skeleton-key https://<host>:8787/mcp`).
- The first request 401s with a discovery hint; Claude auto-registers, then opens the **"Authorize an AI agent"** page served by Skeleton Key.
- You approve with your **TOTP code** (PKCE + short-lived access tokens that auto-refresh).
- Revoke an agent anytime — it's TOTP-gated (`POST /api/oauth/clients/:id/revoke`); a future admin console surfaces this in the UI.

A **static bearer token** is still accepted as a fallback for clients without OAuth support (shown under "Advanced" in the wizard).

## LAN TLS

Everything the web UI carries — the master passphrase at unlock, credentials typed into hand-off forms — must not cross the LAN in the clear, and MCP clients refuse to send OAuth tokens to a non-HTTPS endpoint. So Skeleton Key serves **HTTPS by default**: on first boot it generates a self-signed certificate into `data/tls/` (SANs cover `localhost`, the interface addresses the container can see, and the public-URL host) and re-issues it automatically near expiry or when the public URL points at a host the certificate doesn't cover. Existing deployments migrate on upgrade: the persisted public URL's scheme flips to `https://`, and if certificate generation ever fails the server falls back to plain HTTP with a loud log warning instead of refusing to boot (the persisted URL keeps its `https://` scheme in that case — only the explicit `SKELETON_KEY_TLS=off` migrates it back).

Two deployment notes:

- **Bridged Docker networking (the compose default):** inside a bridged container the only detectable addresses are Docker-internal, so the first-boot certificate does **not** cover the LAN IP your clients actually dial through the port mapping. Set `SKELETON_KEY_PUBLIC_URL` (e.g. `https://192.168.1.10:8787`) — on the next boot the certificate re-issues itself to cover that host. Host networking doesn't have this problem.
- **Upgrading a pre-TLS deployment that pinned `SKELETON_KEY_PUBLIC_URL`:** the server never rewrites an explicit pin, so update the env var from `http://…` to `https://…` (or remove it) — otherwise OAuth discovery and the unlock/credential links keep advertising a scheme the port no longer serves (the boot log warns about the mismatch).

Because the certificate is self-signed, each client trusts it **once**:

1. **Get the certificate.** It's served at `https://<host>:8787/tls/cert.pem` (public material — it's presented in every TLS handshake anyway):

   ```bash
   curl -k https://<host>:8787/tls/cert.pem -o skeleton-key.pem
   ```

   Verify its SHA-256 fingerprint against the one printed in the container's boot log (`docker logs skeleton-key | grep fingerprint`) — that closes the trust-on-first-use gap of the `-k` fetch.
2. **Browsers** — either click through the warning once, or import `skeleton-key.pem` into your OS trust store (macOS: Keychain Access → System → import, set *Always Trust*; Windows: `certmgr.msc` → Trusted Root Certification Authorities) for a clean padlock.
3. **Claude Code / Node-based MCP clients** — point Node at the certificate before launching:

   ```bash
   export NODE_EXTRA_CA_CERTS=/path/to/skeleton-key.pem
   claude mcp add --transport http skeleton-key https://<host>:8787/mcp
   ```

   Put the `export` in your shell profile so every `claude` session gets it. (This *adds* a trusted CA; it does not disable verification for anything else.)

Prefer your own CA? Mount a pair and set `SKELETON_KEY_TLS_CERT_FILE` / `SKELETON_KEY_TLS_KEY_FILE` — then clients already trusting your CA need no extra step. To opt out entirely (old behavior), set `SKELETON_KEY_TLS=off`; expect MCP clients to require an `mcp-remote <url> --allow-http` stdio bridge in that mode. TLS here is **in addition to** the LAN-only rule, not a substitute — keep the port bound to the LAN either way.

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
| `SKELETON_KEY_PUBLIC_URL` | _(unset)_ | The externally-reachable base URL (e.g. `https://192.168.1.10:8787`). Used as the OAuth issuer / discovery origin so it can't be steered by a forged `Host` header. Set this if a reverse proxy sits in front; otherwise the request's own host is used and `X-Forwarded-*` is ignored. |
| `SKELETON_KEY_TLS` | `auto` | [LAN TLS](#lan-tls). `auto` (default) serves HTTPS with a mounted or self-managed certificate; `off` serves plain HTTP (old behavior — passphrases and hand-off credentials then cross the LAN unencrypted). |
| `SKELETON_KEY_CREDENTIAL_TTL_MINUTES` | `30` | Default lifetime of a `request_credential` hand-off link (clamped to 5–240). A single request can override it with `ttlMinutes`. |
| `SKELETON_KEY_TLS_CERT_FILE` / `SKELETON_KEY_TLS_KEY_FILE` | _(unset)_ | Mount your own PEM certificate + private key (e.g. from a private CA) instead of the auto-generated self-signed pair. Set both or neither; a broken pair fails the boot loudly rather than silently serving a different certificate. |

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
2. **Enable it in the web UI** — either the wizard's *Auto-unlock* step on first setup, or any time later from the unlock page (`https://<host>:8787/`): unlock, enter your **authenticator code**, and click *Enable auto-unlock*.

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
| `request_credential` / `credential_request_status` | execute / read | Mints a one-time, TOTP-gated web link where you type a password, token, or a whole set of app secrets straight into the vault — nothing passes through the chat (see [Credential hand-off](#credential-hand-off)). |
| `register_target` / `update_target` | execute | Registers a service as a target so its tools become available; re-points it at a different credential. The vault item's immutable id is pinned at that moment, so a later rename can't serve a stale value. |
| `vault_delete_credential` | execute | Retires a vault item (refuses while a target still depends on it). |
| `list_targets` | read | Lists registered targets. |
| `form_skeleton` / `skeleton_status` | execute / read | Starts an encrypted disaster-recovery snapshot of every registered target as a background job; poll `skeleton_status` for progress and the summary (see [Disaster-recovery skeletons](#disaster-recovery-skeletons)). |

A typical first session, entirely in chat:

> **You:** Map my network — my LAN is 192.168.0.
> **Claude:** *(network_scan)* Found a Synology at 192.168.0.20, Proxmox at 192.168.0.30, …
> **You:** Generate an SSH key for the Synology, user `skeletonkey`, and register it.
> **Claude:** *(vault_generate_ssh_key)* Here's the public key to install: `ssh-ed25519 …`. *(register_target)* Registered `synology1`.
> **You:** I installed it — validate.
> **Claude:** *(vault_validate_ssh)* ✅ Works. `uid=1027(skeletonkey) …`

Execute-tier tools go through Claude's approval prompt and are audited; installing the returned public key on each host is the one manual step (that's the security boundary — Skeleton Key never pushes its own key onto your machines).

## How credentials stay safe

The service account belongs to exactly one Vaultwarden organization/collection. In Bitwarden's model, organization keys are separate from your personal user key, so this account is **cryptographically unable** to decrypt your personal vault — only the homelab collection. Reads are served from the `bw` CLI's **local encrypted offline cache**, so a Vaultwarden outage degrades you to last-known-good credentials instead of locking you out. Targets remember the vault item's **immutable id**, not just its name, and a deploy-time read (`secretEnv`) re-syncs the cache first — so renaming an item mid-migration can't hand a stack a stale value, and a trashed item never satisfies a reference.

### Credential hand-off

Claude never asks you to paste a secret. `request_credential` mints a one-time link; you open it, the page asks for your authenticator code, and what you type goes browser → Skeleton Key → vault. Learned the hard way during a Discord bot migration (the OAuth2 *Client Secret* was stored where the *Bot Token* belonged, twice), the form now pushes back:

- **Shape checks** — the agent can attach a `pattern`, `minLength`/`maxLength`, and a human `hint` ("Developer Portal → Bot → Reset Token; ~70 chars with two dots") to each field. The browser refuses a non-matching value and shows the hint; the server re-checks before anything is written, and never echoes what you typed.
- **Live verification** — an optional `verify` probe (e.g. `GET https://discord.com/api/v10/users/@me` with `Authorization: Bot {{DISCORD_BOT_TOKEN}}`) runs *before* the vault write. Because this sends the secret to that URL, the host is named in the approval prompt and on the form. A failed probe lets you retype or knowingly store anyway; the outcome is reported in `credential_request_status`.
- **Refill in place** — `overwrite: true` replaces the values of an existing item (same id, same name) instead of forcing a parade of `-v2` names.
- **Recoverable links** — if your chat client fails to render the link, `/admin/credentials` lists every open request (TOTP-gated). Links default to 30 minutes (`ttlMinutes` / `SKELETON_KEY_CREDENTIAL_TTL_MINUTES`).
- **Fingerprints** — once stored, `credential_request_status` reports a keyed fingerprint (`len=72 fp=ab12cd34`) per field. `create_stack`/`update_stack` report the same for each injected secret and `container_inspect` for each env var, so "did the right value get deployed?" is a comparison, not a guess — and the fingerprint is an HMAC under a per-install key, so it's useless for offline guessing if it ends up in a transcript.

## Connectors

| Type | Status | Tools |
|---|---|---|
| `ssh` | ✅ read + gated execute | tail_log, journalctl, service_status, disk_usage, grep_logs, run_readonly, run_command, restart_service — commands get a sane `PATH`; the `sudoPrefixes` option (e.g. `["docker"]`) wraps named binaries in `sudo -n` for hosts like Synology where the docker socket is root-only |
| `http` | ✅ generic | get (read), request (execute) |
| `portainer` | ✅ read + gated execute | list_endpoints, list_containers, container_logs, list_stacks, get_stack_file, container_inspect, start/stop/restart_container, exec_container, create_stack, update_stack, remove_stack |
| `home-assistant` | ✅ read + gated execute | ha_states, ha_get, ha_logbook, ha_call_service, ha_backup |
| `proxmox` | ✅ read + gated execute | list_nodes, list_guests, node_status, guest_status, list_tasks, task_log, guest_power |
| `unifi` | ✅ read + gated execute | list_devices, list_clients, list_networks, get_settings, set_network_ipv6, set_gateway_feature, set_remote_logging, force_provision |
| synology, pihole | 🔜 later phases | — |

Every tool is tagged `read` or `execute`. Execute tools produce a precise confirmation string, are surfaced to Claude's permission prompt, and are written to an append-only audit log. Destructive shell commands (`rm -rf`, `mkfs`, `dd`, …) are refused by policy even when approved.

The UniFi connector can also stream a gateway's logs off-box (`set_remote_logging` — syslog / kernel netconsole to a LAN collector, RFC1918-only) and push a pending controller change onto the device (`force_provision`) so a `/rest/setting` write actually applies rather than sitting in the controller DB.

## Disaster-recovery skeletons

Ask Claude to `form_skeleton` and it walks every registered target (as a background job — it returns a job id at once and `skeleton_status` reports progress, so a slow host can't trip your MCP client's tool timeout; a second call while one is running just returns the same job instead of triggering every native backup again) and captures a **config snapshot** — scrubbed settings plus native backups where the service offers one: UniFi's `.unf` export, a Home Assistant backup, Pi-hole's teleporter, Proxmox guest/storage/network configs, Portainer stack compose + container inspects, and read-only system profiles over SSH. It's your pre-change safety net (e.g. before a risky network experiment).

Because a backup contains secrets, this is handled with the same care as the vault:

- Each artifact is **encrypted at rest** (XChaCha20-Poly1305) under a key held inside the already-encrypted bootstrap store, written to `data/skeletons/<id>/…` alongside a manifest and a `RESTORE.md`. A copy of the `/data` volume alone can't decrypt a skeleton — the store's key is wrapped by the off-volume auto-unlock key.
- The snapshot bytes **never reach the chat, a tool result, the manifest, or the audit log** — `form_skeleton` returns only a summary. The one plaintext egress is a **TOTP-gated download** (`POST /api/snapshots/:id/download`) that decrypts and streams a `.tar.gz` — API-only today; a web-UI page to list and download skeletons is tracked in [#50](https://github.com/sjdodge123/skeleton-key-mcp/issues/50). Per-target failures are isolated, so one unreachable host yields a partial skeleton rather than no skeleton.

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
