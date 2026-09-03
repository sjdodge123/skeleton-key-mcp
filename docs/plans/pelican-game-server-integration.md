# Plan: Pelican game-server provisioning + exposure + monitoring integration

Status: **draft, reviewed once (2026-08-21), not started**. Written 2026-08-21
from a planning conversation; revised the same day after a design review
(review findings are folded in below — see "Review history"). Not yet broken
into PRs.

## Goal

Let Claude drive the full lifecycle of standing up a game server conversationally —
e.g. "make a new valheim server" → Claude asks a couple of follow-up questions
(desired server hours, which Discord channel, any special config) → provisions
it, schedules its on/off hours, exposes it to the internet, creates the branded
Discord webhook, and wires it into the existing Discord/Uptime-Kuma status
pipeline — **the owner does nothing but answer questions**. No hand-editing of
five admin panels the way the Palworld server was set up.

## Decisions already made (do not relitigate without asking)

- **Exposure model:** both, depending on server type. Web-facing / HTTP-ish
  traffic goes through Cloudflare Tunnel; raw game protocols (Minecraft-style
  TCP/UDP) go through a UniFi port-forward + a DNS-only (unproxied) Cloudflare
  record. (Tunnel public hostnames only carry HTTP(S); raw game traffic cannot
  ride the tunnel, so most game servers take the port-forward path.)
- **Reverse proxy:** none installed today — cloudflared only. No Nginx Proxy
  Manager / Caddy / Traefik connector needed for this work.
- **"Server hours" scheduling:** enforced by **Pelican's own** per-server
  schedule/task system (cron-like power actions), not a new scheduler inside
  Skeleton Key. Skeleton Key only reads/writes that schedule via the Pelican API.
- **Discord webhooks are created by Skeleton Key** (revised 2026-08-21 — the
  original "owner creates the webhook by hand" decision was reversed to meet
  the zero-touch goal). A **dedicated, minimal Discord bot** owned by Skeleton
  Key does it: a separate Discord application whose bot has **only View
  Channels + Manage Webhooks**, granted on the games category (not
  server-wide), no privileged intents. Raid-Ledger's existing bot is **not**
  reused — it has no webhook capability, lacks the Manage Webhooks flag, and
  carries Manage Roles / Kick Members / MessageContent, which is far more
  authority than this job needs (checked 2026-08-21).
- **Channel resolution:** Claude lists the guild's channels and proposes one
  by name; it asks the owner to confirm when the match is ambiguous. Never
  auto-creates channels (the bot can't — no Manage Channels).
- **Game icon source:** Raid-Ledger's IGDB-backed `GET /games/search?q=`
  endpoint supplies cover art, applied as the webhook's avatar **at creation
  time**. No per-server icon is stored anywhere else — PKGM already renders
  each message with the webhook's own avatar (`DISCORD_USE_BRAND_IDENTITY=0`
  default, `app/notify.py`), so the PKGM `icon_url` field from the first draft
  is **dropped**, and so is the "re-sync from the existing avatar" path.
- **Webhook URLs are secrets** (`{id}/{token}` alone lets anyone post as the
  webhook and re-avatar it). They are written by the server straight into the
  vault and **never** appear in a tool result, confirmation text, audit detail,
  or the chat. PKGM receives them from the vault, in-memory, at call time.

## Prior state / research findings

- `Pelican-Kuma-GameMonitor` (PKGM) already auto-creates Kuma push monitors
  per Pelican server, maintains a dynamic Kuma status page grouped by
  wing/node, and syncs Pelican power schedules into Kuma maintenance windows
  so scheduled-off time isn't reported as degraded. This is **done and not
  part of this plan** — Skeleton Key should not duplicate it.
- PKGM's per-server Discord webhook config is managed through a **Flask admin
  UI only** (`app/admin.py`), not a JSON API: `POST /save` takes HTML form
  fields `url__<identifier>` / `name__<identifier>`, **merges** onto the stored
  config (so posting a single server is safe), protected by HTTP Basic auth
  (`ADMIN_USER` defaults to `admin`, `ADMIN_PASS`). `POST /test` with
  `identifier` sends a test embed through the resolved webhook — use it as the
  post-assignment check. The `/` page renders every stored webhook URL, so the
  Basic-auth creds are effectively a master key to every webhook token.
- PKGM already uses **two** Pelican keys (`PEL_APP_KEY` for
  `/api/application/*`, `PEL_CLIENT_KEY` for `/api/client/*`) — confirming the
  split below.
- **Pelican API shape (verified against `pelican-dev/panel` source):**
  - There are **no nests** in Pelican. `StoreServerRequest` takes `egg`
    directly; required fields are `name`, `user` (owner id), `egg`,
    `docker_image`/`startup`/`environment`, `limits.*`, `feature_limits.*`, and
    either `allocation.default` (+ `allocation.additional[]`) or a `deploy`
    block that lets the panel pick a node/allocation.
  - The **Application API** (`papp_` keys) exposes Servers, Nodes, Eggs, Users,
    Allocations, DatabaseHosts, Databases, Mounts, Roles, Plugins with
    per-resource none/read/write permissions and an `allowed_ips` list. It has
    **no power and no schedule endpoints**.
  - **Power and schedules live only under the Client API** (`pacc_` keys):
    `PowerController`, `ScheduleController`, `ScheduleTaskController`,
    `StartupController`, `NetworkAllocationController`. A client key acts as its
    user, so that user must **own** (or be a subuser on) every server Claude
    manages.
- Raid-Ledger `GET /games/search?q=` (`api/src/igdb/igdb.controller.ts`) is
  **public** — no `AuthGuard`, only `@RateLimit('search')` (30/min). Resolved;
  no service token needed.
- **Discord (verified against the webhook + reference docs):**
  - `POST /channels/{channel_id}/webhooks` (bot auth, Manage Webhooks) takes
    `name` and `avatar` (image data URI: `data:image/png;base64,…`; PNG/JPEG/
    GIF; ≤10 MiB — we cap far lower). The response contains the webhook
    `token`; the URL is `https://discord.com/api/webhooks/{id}/{token}`.
  - `GET`/`PATCH /webhooks/{id}/{token}` work with the token alone (no bot
    auth) — PATCH accepts `name`/`avatar` only, not `channel_id`. The
    token-only `GET` is the natural `verify` probe for a webhook URL.
- **Cloudflare (verified against the "create a tunnel via API" docs):**
  - `PUT /accounts/{account}/cfd_tunnel/{tunnel}/configurations` **replaces
    the entire configuration** and the ingress list must end with a catch-all
    rule. Any "add one hostname" tool is therefore a read-modify-write.
  - A public hostname additionally needs a **proxied CNAME** to
    `<tunnel-id>.cfargotunnel.com` in the zone — a separate DNS write.
  - Token permissions: `Account › Cloudflare Tunnel › Edit` ("Cloudflare Tunnel
    Write") for config; `Zone › DNS › Edit` for records. Both are independently
    scopeable.
  - Only a **remotely-managed** tunnel honors the configurations API; a
    locally-managed (`config.yml`) tunnel ignores it. Which one this account
    runs is not yet confirmed — **blocking for the cloudflare step**.
- No UniFi port-forward CRUD exists yet in `src/connectors/unifi.ts` (only
  gateway feature toggles, IPv6, remote logging, force-provision). Read tools
  for existing forwarding rules also don't exist. The classic REST endpoint is
  `/proxy/network/api/s/{site}/rest/portforward` on UniFi OS — confirm the
  current firmware still serves it (the newer Integration API doesn't expose
  port-forwards). A new rule is written to the controller DB and needs the
  existing `force_provision` to take effect on the gateway.
- No `cloudflare` or `discord` connector exists yet.

## Credential model (decide-once; all items live in the scoped Vaultwarden collection)

| Vault item | Type / fields | Scope | Onboarded via |
|---|---|---|---|
| `pelican-panel` | login; fields `application_key`, `client_key` | App key: servers **r/w**, allocations **r/w**, eggs **read**, nodes **read**, users **read**; `none` for database hosts, databases, mounts, roles, plugins. Client key: belongs to a **dedicated Pelican user** (e.g. `skeleton-key`) that owns every server Claude creates — never the admin's personal account. Both keys: **Allowed IPs** = the NAS. | `request_credential` with `fields`, per-field `pattern` (`^papp_`, `^pacc_`) and `verify` probes (`GET /api/application/nodes`, `GET /api/client`). |
| `discord-skeleton-key-bot` | secret = bot token; fields `guild_id`, `application_id` | Dedicated application; bot permissions **View Channels + Manage Webhooks only**, granted on the games category; no privileged intents. | `request_credential` with the existing Discord bot-token `pattern` + `verify` (`GET /users/@me`, `Authorization: Bot …`). |
| `discord-webhook-<server-identifier>` | login; secret = webhook URL; fields `webhook_id`, `channel_id` | One item per webhook, **written by the server** from `create_webhook`'s response via `createLoginItem`. | Never via chat. If the owner must supply an existing webhook, `request_credential` with `pattern` `^https://discord(app)?\.com/api/webhooks/\d+/[\w-]+$` and a token-only `GET` verify. |
| `pkgm-admin` | login; username/password | PKGM Basic auth. Target `baseUrl` must be https or an RFC1918 `http` host (Basic auth goes on the wire). | `request_credential`, verify `GET /` with the Basic header. |
| `cloudflare-api` | secret = API token; fields `account_id`, `zone_id`, `tunnel_id` | **One token**, `Zone › DNS › Edit` on the single zone + `Account › Cloudflare Tunnel › Edit`; client-IP filter = home WAN IP; never a Global API key or account-wide token. | `request_credential`, verify `GET /user/tokens/verify`. |

## Scope of work

### 1. `pelican` connector (new) — biggest piece, build first

Talks to the Pelican Panel **Application API** for provisioning/inventory and
the **Client API** for power, startup and schedules (the connector picks the
key per tool from the single `pelican-panel` item). Needs its own target
registration (Panel URL + `credentialRef`) — separate from the existing
`pelican48` SSH target, which is the box's shell, not the panel HTTP API.
Target option `ownerUserId` (the dedicated Pelican user's id) is required and
is what `create_server` sets as `user`.

- **read:** `list_eggs`, `list_nodes`, `list_allocations` (node LAN IP + free
  ports — the port-forward step needs this), `list_servers`, `server_details`,
  `server_resources`, `list_schedules`
- **execute:** `create_server` (egg + allocation/deploy + limits + env →
  new server owned by `ownerUserId`), `update_startup_variables`,
  `power_action` (start/stop/restart/kill — confirm text spells out
  "KILL (ungraceful)"), `create_schedule` / `update_schedule` /
  `delete_schedule` (this is what enforces "server hours"), `assign_allocation`
- Confirm text names the server (identifier + name) and the exact change,
  e.g. `Create Pelican server 'valheim' (egg 'Valheim', allocation
  192.168.0.48:2456, owner user 7) on pelican-panel`.
- Implement `snapshot()` (server + schedule JSON) so `form_skeleton` covers it.

### 2. `discord` connector (new) — webhook management with a dedicated bot

One target = one guild (`guild_id` from the credential, or target option).

- **read:** `list_channels` (text channels the bot can see, with category),
  `list_webhooks` (id, name, channel — **never** tokens)
- **execute:** `create_webhook(channelId, name, iconSource)` — resolves cover
  art (see §3), creates the webhook **with the avatar in the same call**,
  writes `discord-webhook-<identifier>` to the vault, and returns only the
  webhook id, name, channel and the vault item name. `delete_webhook(id)`
  for cleanup (confirm names channel + webhook name).
- Bot token is read in-memory per call; webhook token from the create
  response touches nothing but the vault write.
- Outbound image fetch policy (same posture as the credential verify probe):
  https only, no redirects, host allowlist (`images.igdb.com`), content-type
  check, size cap ~2 MB, nothing from response bodies in results.

### 3. `pkgm` connector (new) — thin wrapper around PKGM's admin form

- **execute:** `assign_webhook(identifier, webhookCredentialRef, displayName?)`
  — reads the webhook URL from the vault via `ctx.resolveCredential`, POSTs
  `url__<identifier>` / `name__<identifier>` to `/save` with the Basic-auth
  creds, then calls `/test` so the result reports whether a test embed was
  delivered. Confirm text: `Assign webhook 'valheim-status' (vault item
  discord-webhook-valheim) to PKGM server 'valheim' on pkgm` — never the URL.
- **read:** `list_assignments` (identifier → webhook *name/id*, derived from
  the vault items; never fetch/parse `/` for URLs).
- No PKGM code change required.

Icon resolution (shared helper used by §2): Raid-Ledger `GET /games/search?q=`
→ first match's cover URL (Claude disambiguates with the owner if several);
fallback to an explicit `iconUrl` argument (allowlisted host) when Raid-Ledger
is unavailable, so RL is never a hard dependency of provisioning.

### 4. UniFi port-forward CRUD (extends existing `unifi` connector)

- **read:** `list_port_forwards`
- **execute:** `create_port_forward`, `update_port_forward`,
  `delete_port_forward` — surgical read-modify-write, same pattern as the
  existing gateway-feature toggles (report prior state / rule id so it's
  revertable), and the result reminds the caller to `force_provision`.
- **Guardrails (hard, not just confirm text):** destination must be an RFC1918
  IPv4 (reuse the `set_remote_logging` check); **deny** forwards to the
  Skeleton Key host/port, the UniFi gateway, Vaultwarden, Portainer, and low
  infra ports (22, 443, 8787, …); prefer constraining the destination to an
  IP:port returned by `pelican.list_allocations`.
- Confirm text reads like `Open WAN UDP 2456-2458 → 192.168.0.48:2456
  ('valheim') on unifi`.
- Update `docs/SCOPE.md` (UniFi execute row + security-model bullet) — it
  currently says UniFi execute is toggles-only.

### 5. `cloudflare` connector (new)

- **read:** `list_dns_records`, `get_tunnel_config`
- **execute:** `create_dns_record` / `update_dns_record` / `delete_dns_record`
  (`proxied:false` A record for raw game-protocol hosts; `proxied:true` CNAME
  to `<tunnel-id>.cfargotunnel.com` for tunnel hostnames),
  `set_tunnel_hostname(hostname, service)` / `remove_tunnel_hostname` — a
  **server-side read-modify-write** of the remotely-managed tunnel config that
  preserves every other ingress rule and the catch-all, and whose confirm text
  enumerates hostnames **added and removed**; it refuses a write that would
  drop an existing hostname unless that hostname was explicitly named.
- **Dynamic WAN IP:** a DNS-only A record points at the home WAN IP. Decide
  between UniFi's built-in DDNS → Cloudflare (preferred: no Skeleton Key
  involvement) or a scheduled `update_dns_record`; otherwise the record rots on
  the first ISP lease change.

## End-to-end conversational flow this enables

"make a new valheim server" →

1. `pelican.list_eggs` resolves "Valheim" → egg id (disambiguates if multiple)
2. Claude asks: desired server hours, any startup/env overrides, which
   Discord channel (after `discord.list_channels`)
3. `pelican.create_server` (execute, approval-gated) provisions it
4. `pelican.create_schedule` (execute) sets the power on/off cron from the
   stated hours
5. Exposure, by server type:
   - raw game protocol: `unifi.create_port_forward` → `unifi.force_provision`
     → `cloudflare.create_dns_record` (A, unproxied)
   - web-facing: `cloudflare.set_tunnel_hostname` →
     `cloudflare.create_dns_record` (CNAME, proxied)
6. `discord.create_webhook` — IGDB art as avatar, URL straight into the vault
7. `pkgm.assign_webhook` — PKGM picks it up on its next run; Kuma monitor +
   maintenance windows follow automatically (existing PKGM behavior)

Every execute step stays a small, individually approval-gated and
audit-logged call — this does not collapse into one mega-tool. The owner's
only inputs are answers in chat plus the one-time `request_credential` links
during onboarding.

## Suggested build order

1. `pelican` connector, read tools (+ credential item with both keys, dedicated
   owner user created in the panel)
2. `pelican` execute: `create_server`, `power_action`, schedule CRUD, snapshot
3. `discord` connector (dedicated bot app created in the Developer Portal,
   token onboarded via `request_credential`)
4. `pkgm` connector (`assign_webhook`)
5. UniFi port-forward CRUD (+ SCOPE.md update)
6. `cloudflare` connector (DNS first — it's useful alone; tunnel hostname
   tools only once the tunnel is confirmed remotely-managed)

Steps 3–4 and 5–6 are independent of each other and can be parallel PRs.

## Open items

**Blocking (settle before the step that needs them):**
- Before step 1: create the dedicated Pelican user + the two scoped keys
  (Allowed IPs = NAS). Confirm `create_server` with the Application key's
  `servers:write` + `allocations:write` + `eggs:read` + `nodes:read` +
  `users:read` is sufficient.
- ~~Before step 6's tunnel tools: confirm the existing tunnel is
  **remotely-managed**~~ **Resolved 2026-09-03:** checked via
  `GET /accounts/{account}/cfd_tunnel` with the `cloudflare-api-token` cred —
  the relevant tunnel, `status.gamernight.net` (running as the `awesome_knuth`
  container on nas229), reports `"remote_config": true, "config_src":
  "cloudflare"` — remotely-managed, no migration needed. (A second,
  unrelated tunnel `chaochao-dev` is locally-managed — `config_src: "local"`
  — but nothing in this plan touches it.) The current `cloudflare-api-token`
  only has DNS + zone:read scope, not Tunnel Edit — still needs the broader
  token before step 6's write tools per the credential table.

**Confirm while building:**
- Webhook-avatar CDN path (`cdn.discordapp.com/avatars/{webhook_id}/{hash}.png`)
  is conventional but not spelled out in the docs — only matters for
  `list_webhooks` display; verify live against the Palworld webhook.
- UniFi OS firmware still serves `rest/portforward`.
- DDNS choice (§5).

**Resolved:** Raid-Ledger `/games/search` auth (public, rate-limited);
credential naming/scoping (table above); PKGM `icon_url` (not needed — dropped).

## Review history

- 2026-08-21 design review. Blocking findings fixed in this revision: webhook
  URL was routed through chat (now vault-only, created by our own bot); Pelican
  modelled with Pterodactyl's nests and a single Application key (now egg-
  direct, two keys, dedicated owner user); `update_tunnel_ingress` would have
  replaced the whole tunnel config and omitted the DNS CNAME (now diffed RMW +
  explicit DNS step, gated on remote management). Also added: port-forward
  guardrails, per-credential scoping table, outbound-fetch policy, DDNS
  question; dropped the PKGM `icon_url` prerequisite and the avatar re-sync
  path; decided against reusing Raid-Ledger's bot.
