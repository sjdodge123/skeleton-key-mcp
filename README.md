# 🗝️ Skeleton Key MCP

Connect it up and it unlocks your homelab's potential.

Skeleton Key is a self-hosted [MCP](https://modelcontextprotocol.io) server that lets Claude **read logs across your whole homelab** and, **with your approval, act on it** — restart a service, run a command, hit an API — from one place. Credentials come from a **scoped Vaultwarden collection** it can read but that can never expose your personal passwords. A first-run web wizard walks you through the setup, and after that Claude does the rest in conversation: it maps your LAN, sets up access to each host, and keeps Skeleton Key itself up to date.

It's a framework, not a fixed inventory: connectors are adapters for a *type* of service, and you register your own instances. Generic **SSH** and **HTTP** connectors mean anything reachable is usable on day one.

> **Security:** LAN only. Never expose this to the internet. Remote access = VPN into your LAN.

**Contents:** [What you need](#what-you-need) · [Install](#install) · [Update](#update) · [Connecting Claude](#connecting-claude-oauth) · [LAN TLS](#lan-tls) · [Configuration](#configuration) · [Boot auto-unlock](#boot-auto-unlock) · [Lockouts](#lockouts) · [Conversational onboarding](#conversational-onboarding) · [How credentials stay safe](#how-credentials-stay-safe) · [Connectors](#connectors) · [Disaster-recovery skeletons](#disaster-recovery-skeletons) · [Development](#development)

## What you need

- **A Docker host on your LAN** — a NAS, mini PC or VM. [Portainer](https://www.portainer.io/) is optional but recommended: it's the easiest way to deploy the stack, and once it's registered as a target, Claude can update Skeleton Key for you.
- **A Vaultwarden (or Bitwarden-compatible) server you control**, reachable from the Docker host over **HTTPS**. The wizard walks you through creating a dedicated organization, collection and service account; your personal vault is never touched.
- **An authenticator app** (any TOTP app) for the admin login and approvals.
- **An MCP client** — Claude Code or Claude Desktop.

## Install

About 15 minutes. Replace `192.168.1.10` below with your Docker host's LAN address.

1. **Deploy the stack.** Use [`docker-compose.yml`](docker-compose.yml) from this repo, or the minimal version below. Set the host's LAN address in two places: the `ports:` line (this is the security boundary — never `0.0.0.0`) and `SKELETON_KEY_PUBLIC_URL`.

   ```yaml
   services:
     skeleton-key:
       image: ghcr.io/sjdodge123/skeleton-key-mcp:latest
       container_name: skeleton-key
       restart: unless-stopped
       ports:
         - "192.168.1.10:8787:8787"
       environment:
         SKELETON_KEY_PUBLIC_URL: "https://192.168.1.10:8787"
       volumes:
         - skeleton-key-data:/data
         # Recommended, for boot auto-unlock (step 2):
         # - /srv/skeleton-key/secrets:/run/secrets/skeleton-key
   volumes:
     skeleton-key-data:
   ```

   - **Portainer:** Stacks → *Add stack* → paste the file → *Deploy the stack*.
   - **Docker Compose:** save it as `docker-compose.yml`, then `docker compose up -d`.

2. **(Recommended) Prepare boot auto-unlock**, so a reboot doesn't leave Skeleton Key locked until you notice. Create a small host directory for the unlock key, uncomment the second volume line above, and redeploy:

   ```bash
   mkdir -p /srv/skeleton-key/secrets
   chown 1000:1000 /srv/skeleton-key/secrets   # the container runs as uid 1000
   chmod 700 /srv/skeleton-key/secrets
   ```

   You switch it on later in the wizard. See [Boot auto-unlock](#boot-auto-unlock) for the trade-off.

3. **Run the setup wizard** at `https://192.168.1.10:8787/`. Your browser warns about the self-signed certificate on this first visit; click through it, or trust the certificate first ([LAN TLS](#lan-tls)). The wizard walks you through:
   - a **master passphrase** (encrypts Skeleton Key's own secrets; also your admin login),
   - the **Vaultwarden** connection: it tells you exactly how to create the scoped org, collection and service account, then checks that the scoping really holds,
   - an optional **LAN scan**,
   - **TOTP** enrollment,
   - **boot auto-unlock** (if you did step 2),
   - the **connect command** for Claude.

4. **Trust the certificate on the machine running Claude** (one time):

   ```bash
   curl -k https://192.168.1.10:8787/tls/cert.pem -o ~/skeleton-key.pem
   export NODE_EXTRA_CA_CERTS=~/skeleton-key.pem   # add this line to your shell profile too
   ```

   Compare the certificate's fingerprint with the one in the container's boot log to close the trust-on-first-use gap ([LAN TLS](#lan-tls) has the details, including Claude Desktop).

5. **Connect Claude:**

   ```bash
   claude mcp add --transport http skeleton-key https://192.168.1.10:8787/mcp
   ```

   On first use, Claude opens a consent page; approve it with your authenticator code.

6. **Let Claude take it from here.** Ask *"What can Skeleton Key do? Help me set up my homelab."* Claude calls `get_started` and walks you through mapping your network and registering hosts ([Conversational onboarding](#conversational-onboarding)). Register the Portainer that runs Skeleton Key early on: that's what lets Claude update it later.

**Verifying the image (optional).** Images are signed with [cosign](https://github.com/sigstore/cosign) (keyless) and carry an SBOM and build provenance:

```bash
cosign verify ghcr.io/sjdodge123/skeleton-key-mcp:latest \
  --certificate-identity-regexp '^https://github.com/sjdodge123/skeleton-key-mcp/\.github/workflows/docker\.yml@' \
  --certificate-oidc-issuer https://token.actions.githubusercontent.com
```

## Update

Releases are tagged `vX.Y.Z` and listed on the [releases page](https://github.com/sjdodge123/skeleton-key-mcp/releases) with notes. `:latest` moves only when a release is tagged; merges to `main` publish `:main` and `:sha-<short>` for testing and never reach `:latest`. Your configuration, targets and encrypted store live in the `/data` volume, so an update never repeats the setup.

### Ask Claude (recommended)

Once Skeleton Key is installed and the Portainer that runs it is registered as a target, updating is a conversation:

> **You:** Is there a Skeleton Key update? If so, install it.
>
> **Claude:** *(get_started)* You're on v0.4.0; the latest release is v0.4.1 — it patches dependencies in the bundled Bitwarden CLI and makes the health check verify its own certificate. *(update_stack_images)* Updating the `skeleton-key` stack… *(the connection drops while the container restarts)* *(get_started)* Back up on v0.4.1, unlocked, with all your targets.

What happens under the hood:

1. `get_started` reports the running version. Claude checks the releases page itself; the server never contacts the internet to look for updates.
2. Claude finds the stack running `ghcr.io/sjdodge123/skeleton-key-mcp` on your Portainer target and calls **`update_stack_images`**. It re-pulls the image and redeploys the stack **without touching its compose file or environment**. Your approval prompt names the exact stack and host. If a setting was ever edited on the running container but not in the stack file, the redeploy would undo it, so the tool refuses first and lists the variables that differ; Claude then fixes the stack file with your OK and tries again.
3. The MCP connection drops while the container is recreated, which is expected. After about 30 seconds Claude calls `get_started` again to confirm the new version. With [boot auto-unlock](#boot-auto-unlock) it's back unlocked; without it, unlock it in the web UI.

Not registered Portainer yet? Ask Claude: *"Register the Portainer that runs Skeleton Key."* It needs a Portainer access token, which it collects through a one-time secure link, never in chat.

### Automatically with Watchtower

If you run [Watchtower](https://containrrr.dev/watchtower/), the `com.centurylinklabs.watchtower.enable: "true"` label in [`docker-compose.yml`](docker-compose.yml) opts Skeleton Key in: Watchtower pulls each new release on its next poll. Claude can also trigger it right away (`exec_container` on the watchtower container with `/watchtower --run-once skeleton-key`).

### By hand

- **Portainer:** Stacks → `skeleton-key` → *Editor* → *Update the stack* with **Re-pull image and redeploy** switched on.
- **Docker Compose:** `docker compose pull && docker compose up -d` in the stack's directory.

### Pin a version or roll back

Every release is also published as `:X.Y.Z` and `:X.Y`. To stay on a release, or go back to one, set the image tag in your stack (e.g. `ghcr.io/sjdodge123/skeleton-key-mcp:0.4.0`) and redeploy. Read the release notes before rolling back across several releases: a release that changes the `/data` format says so.

## Connecting Claude (OAuth)

Skeleton Key is an **OAuth 2.1** resource and authorization server, so there's no token to copy or store in plaintext:

- Add the server (`claude mcp add --transport http skeleton-key https://<host>:8787/mcp`).
- The first request gets a 401 with a discovery hint; Claude registers itself, then opens the **"Authorize an AI agent"** page served by Skeleton Key.
- You approve with your **TOTP code** (PKCE, short-lived access tokens that refresh automatically).
- Revoke an agent anytime; revocation is TOTP-gated (`POST /api/oauth/clients/:id/revoke`).

A **static bearer token** is still accepted as a fallback for clients without OAuth support (shown under "Advanced" in the wizard).

## LAN TLS

Everything the web UI carries — the master passphrase at unlock, credentials typed into hand-off forms — must not cross the LAN in the clear, and MCP clients refuse to send OAuth tokens to a non-HTTPS endpoint. So Skeleton Key serves **HTTPS by default**: on first boot it generates a self-signed certificate into `data/tls/` (covering `localhost`, the addresses the container can see, and the public-URL host) and re-issues it automatically near expiry or when the public URL points at a host the certificate doesn't cover. If certificate generation ever fails, the server falls back to plain HTTP with a loud log warning instead of refusing to boot.

Two deployment notes:

- **Bridged Docker networking (the compose default):** inside a bridged container the only detectable addresses are Docker-internal, so set `SKELETON_KEY_PUBLIC_URL` to the address your clients actually use. The certificate then covers it. Host networking doesn't have this problem.
- **Upgrading a pre-TLS deployment that pinned `SKELETON_KEY_PUBLIC_URL`:** the server never rewrites an explicit pin, so change it from `http://…` to `https://…` (or remove it). Otherwise OAuth discovery and the unlock/credential links keep advertising a scheme the port no longer serves; the boot log warns about the mismatch.

Because the certificate is self-signed, each client trusts it **once**:

1. **Get the certificate.** It's served at `https://<host>:8787/tls/cert.pem` (public material — it's presented in every TLS handshake anyway):

   ```bash
   curl -k https://<host>:8787/tls/cert.pem -o skeleton-key.pem
   ```

   Verify its SHA-256 fingerprint against the one printed in the container's boot log (`docker logs skeleton-key | grep fingerprint`) — that closes the trust-on-first-use gap of the `-k` fetch.
2. **Browsers** — either click through the warning once, or import `skeleton-key.pem` into your OS trust store (macOS: Keychain Access → System → import, set *Always Trust*; Windows: `certmgr.msc` → Trusted Root Certification Authorities) for a clean padlock.
3. **Claude Code and other Node-based MCP clients** — point Node at the certificate before launching:

   ```bash
   export NODE_EXTRA_CA_CERTS=/path/to/skeleton-key.pem
   ```

   Put the `export` in your shell profile so every `claude` session gets it. The Claude desktop app doesn't read your shell profile: set the same variable in the `env` block of `~/.claude/settings.json`. This *adds* a trusted certificate; it does not turn off verification for anything else.

Prefer your own CA? Mount a pair and set `SKELETON_KEY_TLS_CERT_FILE` / `SKELETON_KEY_TLS_KEY_FILE`; clients that already trust your CA need no extra step. To opt out entirely, set `SKELETON_KEY_TLS=off`; expect MCP clients to need an `mcp-remote <url> --allow-http` stdio bridge in that mode. TLS here is **in addition to** the LAN-only rule, not a substitute — keep the port bound to the LAN either way.

## Configuration

### Environment variables

All configuration is optional — the defaults work for a standard container deploy. Set these in the `environment:` block of your compose/Portainer stack.

| Variable | Default | Purpose |
|---|---|---|
| `SKELETON_KEY_PUBLIC_URL` | auto-detected | The address clients reach Skeleton Key at (e.g. `https://192.168.1.10:8787`). Used for the OAuth issuer and for every link that asks for a secret, and never taken from a request's `Host` header. Auto-detection inside a bridged container only sees Docker-internal addresses, so set it there. |
| `SKELETON_KEY_DATA_DIR` | `/data` (image) · `./data` (dev) | Directory for all mutable state: the encrypted bootstrap store, the `bw` offline cache, the audit DB, and `targets.yaml`. Back this up; it's the only stateful part. |
| `SKELETON_KEY_PORT` | `8787` | Port the server (web UI + `/mcp`) listens on **inside** the container. |
| `SKELETON_KEY_BIND_HOST` | `0.0.0.0` | Interface the server binds to inside the container. Leave at `0.0.0.0`; scope exposure with the host-side port mapping, not this. |
| `SKELETON_KEY_UNLOCK_KEY_FILE` | `/run/secrets/skeleton-key/unlock-key` | Where the **boot auto-unlock key** lives inside the container. A non-secret *path* — the key itself is a random value the web UI writes there when you enable auto-unlock. Only set this to override the default location. |
| `SKELETON_KEY_TLS` | `auto` | [LAN TLS](#lan-tls). `auto` serves HTTPS with a mounted or self-managed certificate; `off` serves plain HTTP (passphrases and hand-off credentials then cross the LAN unencrypted). |
| `SKELETON_KEY_TLS_CERT_FILE` / `SKELETON_KEY_TLS_KEY_FILE` | _(unset)_ | Mount your own PEM certificate + private key instead of the self-signed pair. Set both or neither; a broken pair fails the boot loudly rather than silently serving a different certificate. |
| `SKELETON_KEY_CREDENTIAL_TTL_MINUTES` | `30` | Default lifetime of a `request_credential` hand-off link (clamped to 5–240). A single request can override it with `ttlMinutes`. |
| `SKELETON_KEY_DISABLE_EXECUTE` | _(unset)_ | Set to `1` as a kill-switch: all `execute`-tier tools are refused and audited as denied, leaving only read-only tools. |
| `SKELETON_KEY_PASSPHRASE` / `SKELETON_KEY_PASSPHRASE_FILE` | _(unset)_ | **Deprecated.** The old auto-unlock: your master passphrase in the environment (or a file). Still honored, with a warning at boot — prefer [Boot auto-unlock](#boot-auto-unlock), which never puts the passphrase on disk. |

### Docker / compose setup

| Setting | Example | Why it matters |
|---|---|---|
| **Port mapping** | `"192.168.1.10:8787:8787"` | **This is your security boundary.** Bind to the host's specific **LAN IP**, not `0.0.0.0` or `8787:8787`, so the service is never reachable from the WAN. Never put this behind an internet-facing reverse proxy. |
| **Networking** | bridge (default) or `network_mode: host` | On the default bridge network the container only sees Docker's internal subnet, so the built-in **LAN scan** can't enumerate your real network — give the scan your subnet (e.g. `192.168.1`), or use `network_mode: host`. Reaching registered targets works either way. |
| **Volume** | `skeleton-key-data:/data` | Persists everything across restarts and updates. Use a named volume or a host bind mount you back up. |
| **`image` vs `build`** | `image: ghcr.io/sjdodge123/skeleton-key-mcp:latest` | Pull the published image. Use `build: .` only when developing from a source checkout. |
| **`restart`** | `unless-stopped` | Brings Skeleton Key back after a reboot. Pair with [Boot auto-unlock](#boot-auto-unlock) for hands-off recovery. |
| **Secrets mount** | `/srv/skeleton-key/secrets:/run/secrets/skeleton-key` | Only for [Boot auto-unlock](#boot-auto-unlock). Deliberately separate from `/data`, so a backup of the data volume never contains both the encrypted store and its key. |
| **Watchtower label** | `com.centurylinklabs.watchtower.enable: "true"` | Opts the container into [Watchtower](https://containrrr.dev/watchtower/) updates (see [Update](#update)). |

## Boot auto-unlock

By default, every container restart **re-locks** Skeleton Key: no tools work (and none are even listed) until you open the web UI and enter your master passphrase. That's a deliberate kill-switch — but it also means a reboot at 3am leaves your MCP endpoint locked until you notice.

Auto-unlock trades that kill-switch for hands-off recovery, without ever writing your passphrase anywhere:

1. **Mount a small host directory** for the key (step 2 of [Install](#install)), separate from `/data` on purpose.
2. **Enable it in the web UI** — the wizard's *Auto-unlock* step on first setup, or any time later from the unlock page: unlock, enter your **authenticator code**, and click *Enable auto-unlock*.

Skeleton Key then generates a **random unlock key**, enrolls it as a second keyslot on the encrypted store, and writes it to the mounted directory. At boot, that key unlocks the store; your passphrase stays in your head. Disabling (same TOTP-gated page) removes the keyslot and deletes the file, so a leaked copy of the old key is useless afterwards.

**Trade-off, stated plainly:** with auto-unlock on, anyone who can restart the container gets an unlocked instance — the restart kill-switch is gone. You're narrowing "who can read the secret" (a `chmod 700` host directory instead of a passphrase in the stack definition), not adding a lock. If you want the kill-switch back, disable auto-unlock.

Existing deployments: stores created before auto-unlock migrate to the keyslot format automatically on their next passphrase unlock. If you were using `SKELETON_KEY_PASSPHRASE`, it still works but warns at boot; switch to auto-unlock and delete the variable from your stack.

## Lockouts

Every authenticator-code prompt (the admin pages, agent consent, credential links) and the master-passphrase unlock is **attempt-limited**. Five wrong entries from one address lock that address out for a minute. Ten wrong entries from anywhere in 24 h lock out **everyone** for a minute. Repeated lockouts double, up to 4 hours. While locked out you get *"Too many wrong …"* (HTTP 429), and the code is not even checked. A correct code during a lockout is refused too, so wait for the time shown.

Because the global limit has to hold against an attacker on your LAN using many addresses, **someone on the LAN can keep you locked out** by repeatedly entering wrong codes. While that lasts you can't read the activity log in the web UI. To find and stop them:

1. **Find the address.** Every lockout is logged to the container's stdout, e.g. `[skeleton-key] TOTP lockout: global until 2026-10-28T04:00:00.000Z, last client 192.168.1.77`. When you're back in, the activity log (`/admin`) has `auth.totp_failed` rows per wrong code, and the `auth.*_refused` rows name the addresses that kept trying.
2. **Block it at the network** (a firewall rule on your router, or pull the device off the LAN). That ends the attack. Restarting doesn't.
3. **Restart only as a last resort.** The counters are in memory, so a restart clears them. Without auto-unlock, the restart also re-locks the vault until you enter your passphrase. **With [auto-unlock](#boot-auto-unlock) enabled, the restart comes back unlocked with a fresh budget for the attacker too.** So block first, then restart.

## Conversational onboarding

After the wizard (scoped vault + first MCP connection), you don't hand-build the rest — you ask Claude. These **global tools** are always available:

| Tool | Tier | What it does |
|---|---|---|
| `get_started` | read | The running version, what's registered, and the recommended next step. The only tool available while the vault is locked, and then it shows only how to unlock. |
| `network_scan` | read | Scans your LAN for known services (Synology, Proxmox, UniFi, Home Assistant, Portainer, Pi-hole, SSH). Pass your subnet (e.g. `192.168.1`) if running in a bridged container. |
| `vault_generate_ssh_key` | execute | Generates a dedicated ed25519 keypair, stores the **private** key in your homelab collection, and returns the **public** key + the `authorized_keys` line to install. The private key is never shown. |
| `vault_store_login` | execute | Stores a username/password/token + URL in the collection (for APIs, web UIs, …). |
| `vault_list_credentials` | read | Lists the item names in the scoped collection (no secret values). |
| `vault_validate_ssh` | read | SSH-connects to a host with a stored key and runs a harmless `id` to confirm access works. |
| `request_credential` / `credential_request_status` | execute / read | Mints a one-time, TOTP-gated web link where you type a password, token, or a whole set of app secrets straight into the vault — nothing passes through the chat (see [Credential hand-off](#credential-hand-off)). |
| `register_target` / `update_target` | execute | Registers a service as a target so its tools appear; re-points it at a different credential or changes its options. Unknown options are refused. The vault item's immutable id is pinned, so a later rename can't serve a stale value. |
| `vault_delete_credential` | execute | Retires a vault item (refuses while a target still depends on it). |
| `list_targets` | read | Lists registered targets. |
| `form_skeleton` / `skeleton_status` | execute / read | Starts an encrypted disaster-recovery snapshot of every registered target as a background job; poll `skeleton_status` for progress (see [Disaster-recovery skeletons](#disaster-recovery-skeletons)). |

A typical first session, entirely in chat:

> **You:** Map my network — my LAN is 192.168.1.
> **Claude:** *(network_scan)* Found a Synology at 192.168.1.20, Proxmox at 192.168.1.30, …
> **You:** Generate an SSH key for the Synology, user `skeletonkey`, and register it.
> **Claude:** *(vault_generate_ssh_key)* Here's the public key to install: `ssh-ed25519 …`. *(register_target)* Registered `synology1`.
> **You:** I installed it — validate.
> **Claude:** *(vault_validate_ssh)* ✅ Works. `uid=1027(skeletonkey) …`

Execute-tier tools go through Claude's approval prompt and are audited. Installing the returned public key on each host is the one manual step; that's the security boundary — Skeleton Key never pushes its own key onto your machines.

## How credentials stay safe

The service account belongs to exactly one Vaultwarden organization/collection. In Bitwarden's model, organization keys are separate from your personal user key, so this account is **cryptographically unable** to decrypt your personal vault — only the homelab collection. Reads are served from the `bw` CLI's **local encrypted offline cache**, so a Vaultwarden outage degrades you to last-known-good credentials instead of locking you out. Targets remember the vault item's **immutable id**, not just its name, and a deploy-time read (`secretEnv`) re-syncs the cache first — so renaming an item can't hand a stack a stale value, and a trashed item never satisfies a reference.

### Credential hand-off

Claude never asks you to paste a secret. `request_credential` mints a one-time link; you open it, the page asks for your authenticator code, and what you type goes browser → Skeleton Key → vault. Look-alike values are a classic mistake (a Discord OAuth2 *Client Secret* where the *Bot Token* belongs, say), so the form pushes back:

- **Shape checks** — the agent can attach a `pattern`, `minLength`/`maxLength`, and a human `hint` ("Developer Portal → Bot → Reset Token; ~70 chars with two dots") to each field. The browser refuses a non-matching value and shows the hint; the server re-checks before anything is written, and never echoes what you typed.
- **Live verification** — an optional `verify` probe (e.g. `GET https://discord.com/api/v10/users/@me` with `Authorization: Bot {{DISCORD_BOT_TOKEN}}`) runs *before* the vault write. Because this sends the secret to that URL, the host is named in the approval prompt and on the form. A failed probe lets you retype or knowingly store anyway.
- **Refill in place** — `overwrite: true` replaces the values of an existing item (same id, same name) instead of forcing a parade of `-v2` names.
- **Recoverable links** — if your chat client fails to render the link, `/admin/credentials` lists every open request (TOTP-gated). Links default to 30 minutes (`ttlMinutes` / `SKELETON_KEY_CREDENTIAL_TTL_MINUTES`).
- **Fingerprints** — once stored, `credential_request_status` reports a keyed fingerprint (`len=72 fp=ab12cd34`) per field. `create_stack`/`update_stack` report the same for each injected secret and `container_inspect` for each env var, so "did the right value get deployed?" is a comparison, not a guess. The fingerprint is an HMAC under a per-install key, so it's useless for offline guessing if it ends up in a transcript.

## Connectors

| Type | What it covers |
|---|---|
| `ssh` | Logs, journal, service status, disk usage, read-only commands; approval-gated `run_command` and `restart_service`. Destructive commands (`rm -rf`, `mkfs`, `dd`, …) are refused even when approved. |
| `http` | Any REST API: `get` (read) and `request` (approval-gated). |
| `portainer` | Containers, logs and stacks; create, update and redeploy stacks with vault-backed secrets; `update_stack_images` for image updates (this is how Claude updates Skeleton Key). |
| `home-assistant` | States, logbook, service calls, backups. |
| `proxmox` | Nodes, guests, tasks; guest power actions. |
| `unifi` | UniFi OS gateways: devices, clients, networks, scrubbed settings, port forwards; surgical, revertable gateway changes. |
| `pelican` | [Pelican](https://pelican.dev/) game-server panels: servers, power, startup variables, schedules, server files, panel and Wings upgrades. |
| `uptime-kuma` | Monitors, plus audited pause/resume and maintenance windows, so a deliberate restart doesn't page anyone. |

Planned: `synology` (multi-host, DSM Web API) and `pihole`. Each connector's README in [`src/connectors/<type>/`](src/connectors) documents its credential, options and tools; the complete list of tools, tiers and inputs is [`tools.manifest.json`](tools.manifest.json).

Every tool is tagged `read` or `execute`. Execute tools produce a precise confirmation string, are surfaced to Claude's permission prompt, and are written to an append-only audit log. Want a connector for something else? See [CONTRIBUTING.md](CONTRIBUTING.md#adding-a-connector).

## Disaster-recovery skeletons

Ask Claude to `form_skeleton` and it walks every registered target and captures a **config snapshot** — scrubbed settings plus native backups where the service offers one: UniFi's `.unf` export, a Home Assistant backup, Pi-hole's teleporter, Proxmox guest/storage/network configs, Portainer stack compose + container inspects, and read-only system profiles over SSH. It runs as a background job (`skeleton_status` reports progress), so a slow host can't trip your client's tool timeout. It's your safety net before a risky change.

Because a backup contains secrets, it gets the same care as the vault:

- Each artifact is **encrypted at rest** (XChaCha20-Poly1305) under a key held inside the already-encrypted bootstrap store, written to `data/skeletons/<id>/…` with a manifest and a `RESTORE.md`. A copy of the `/data` volume alone can't decrypt a skeleton.
- The snapshot bytes **never reach the chat, a tool result, the manifest, or the audit log** — `form_skeleton` returns only a summary. The one plaintext egress is a **TOTP-gated download** (`POST /api/snapshots/:id/download`) that decrypts and streams a `.tar.gz`; a web page to list and download skeletons is tracked in [#50](https://github.com/sjdodge123/skeleton-key-mcp/issues/50). One unreachable host yields a partial skeleton, never no skeleton.

## Development

```bash
npm install        # install deps; also enables the repo's git hooks
npm run dev        # run the server with reload (tsx watch)
npm run build      # compile to dist/
npm test           # run unit tests (vitest)
npm run typecheck  # type-only check
```

Runtime state lives under `SKELETON_KEY_DATA_DIR` (default `./data`): the encrypted bootstrap store, the `bw` offline cache, the audit DB, and `targets.yaml`. None of it is committed. The Vaultwarden connection needs the Bitwarden CLI (`bw`) on `PATH`; the Docker image ships it.

Start with [`docs/ARCHITECTURE.md`](docs/ARCHITECTURE.md) (module map and data flows), [`docs/SCOPE.md`](docs/SCOPE.md) (scope and security model) and [`docs/STATUS.md`](docs/STATUS.md) (what's done and what's next). New connectors: [`docs/CONNECTOR_GUIDE.md`](docs/CONNECTOR_GUIDE.md).

## Contributing

Contributions are welcome, especially new connectors. Read [CONTRIBUTING.md](CONTRIBUTING.md) first. It covers the security non-negotiables, the naming conventions, and how to propose a connector. Please follow the [Code of Conduct](CODE_OF_CONDUCT.md).

**Found a vulnerability?** Report it privately. See [SECURITY.md](SECURITY.md).

## License

[Apache-2.0](LICENSE)
