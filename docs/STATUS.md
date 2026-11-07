# Status & Roadmap

Where the project stands and what's next. Update it as work lands. For the module map see
`docs/ARCHITECTURE.md`; for product scope and the security model see `docs/SCOPE.md`; for
rules and commands see `CLAUDE.md`. Per-release detail lives in the GitHub releases and PRs.

_Last updated: 2026-11-07._

## TL;DR

- **Phase 1 (the server) is complete.** A real MCP client connects over OAuth, onboards a
  homelab conversationally (scan → credential → register → validate), and drives read and
  approval-gated execute tools across eight connectors.
- **Phase 2 (contributor readiness) shipped in v0.4.0.** One folder per connector, a committed
  tool manifest, a conformance suite, import boundaries, a scaffold, and a connector guide.
- **Phase 3 (pluggability) is next.** See "Next" below.

Releases are tag-driven: a merge to `main` publishes `:main` and `:sha-<short>`; only a pushed
`vX.Y.Z` tag moves `:latest` (see CONTRIBUTING "Releases").

## Done (merged to `main`)

**Core**
- Express app, stateful Streamable-HTTP MCP endpoint, and a dynamic tool registry (global
  tools ⊕ per-target connector tools) that pushes `tools/list_changed` when targets change.
- Append-only audit log for every tool call.
- Server `instructions` on connect plus a live `get_started` tool make a fresh session
  self-guiding.

**Secrets and auth**
- libsodium bootstrap store with keyslots: a passphrase slot (argon2) and an optional random
  machine-unlock key on a host mount, so boot auto-unlock never writes the passphrase to disk.
  `SKELETON_KEY_PASSPHRASE` / `_FILE` are deprecated but honored.
- Scoped Vaultwarden client over the `bw` CLI with an offline cache; targets pin the vault
  item's immutable id, trashed items never satisfy a ref, deploy-time reads re-sync first.
- OAuth 2.1 (dynamic client registration, PKCE, TOTP-gated consent, rotating refresh tokens,
  per-client revocation), with the static bearer as a fallback.
- Locked vault is a kill-switch: every tool except a banner-only `get_started` is withheld
  from `tools/list` and `tools/call`.
- TOTP and passphrase attempt limiting on every gated route.
- `request_credential`: a one-time, TOTP-gated web form so secrets never transit chat. Per-field
  shape checks, a pre-store `verify` probe, overwrite-in-place, link TTLs, an open-links admin
  page, and keyed fingerprints for comparing vault and deployed values.
- LAN TLS on by default (self-signed, auto-renewed) or a user-mounted cert.

**Connectors** (`src/connectors/<type>/`; tools listed in `tools.manifest.json`)
- `ssh` — logs, journal, service status; gated `run_command` behind a deny-list; a
  quote-aware read-only allowlist for `run_readonly`.
- `http` — generic REST reads and gated requests.
- `portainer` — containers, stacks, inspect, logs; `create_stack` / `update_stack` with
  `secretEnv` resolved server-side; `remove_stack` only for stacks Skeleton Key created; `update_stack_images` re-pulls and redeploys any
  stack unchanged, which is how an agent updates Skeleton Key itself (`get_started` reports the version).
- `unifi` — UniFi OS gateways: devices, clients, networks, scrubbed settings; surgical
  revertable writes (gateway features, per-network IPv6, remote logging, port forwards,
  force-provision).
- `home-assistant` — states, logbook, service calls, backups.
- `proxmox` — nodes, guests, tasks; guest power with live re-verification.
- `pelican` — game-server panel: inventory, provisioning, power, startup variables, build
  limits, schedules, server files, and panel/Wings upgrades through a root-owned host helper
  with one sudoers rule (`scripts/host/`).
- `uptime-kuma` — monitor inventory and audited pause/resume/maintenance windows; Pelican's
  `power_action` can wrap a manual bounce in them (`suppressMonitors`).

**Global tools**
- LAN discovery with content fingerprinting (`network_scan`).
- Vault and registry management (`vault_*`, `register_target`, `update_target`, `list_targets`).
- `form_skeleton`: encrypted disaster-recovery snapshots of every target, run as a background
  job, downloadable only through a TOTP-gated route.

**Repo and CI**
- Apache-2.0, security policy, issue/PR templates, CODEOWNERS, rulesets on `main`.
- CI: typecheck, tests, build, CodeQL, dependency review, image build + scan, workflow lint,
  signed images.
- Code-scanning baseline is clean: the bundled Bitwarden CLI installs from a lock file with
  patched dependencies, the runtime image carries no npm/yarn, and the base image is pinned
  by digest. Typecheck/test/build, workflow lint, dependency review, the image build + scan
  (fails on a fixable critical CVE) and CodeQL are all required checks.
- `check-homelab-data` keeps real hostnames and addresses out of tracked files, commits and
  PR text (git hooks plus the required CI check).
- Phase 2 contributor tooling (v0.4.0): connector folders, `tools.manifest.json` with a
  drift test, the conformance suite, import-boundary test, registration-time option
  validation, `npm run new:connector`, and `docs/CONNECTOR_GUIDE.md`.

## Next

Roughly in priority order.

1. **Phase 3 — pluggable secret providers.** A `SecretsProvider` interface so vaults other
   than Vaultwarden can back a deployment, with the scoping guarantee stated per provider.
2. **Phase 3 — connector families.** Shared tool contracts (names and input shapes) for
   hypervisors, routers and NAS, checked by the conformance suite.
3. **Phase 3 — recipes and command packs.** Declarative app recipes for `create_stack`, and
   reusable allowlist packs for the SSH connector.
4. **New connectors.** `synology` (DSM Web API, multi-host incl. VirtualDSM) and `pihole`
   (stats, blocklists); discovery already detects both and falls back to `http` today.
5. **Admin console.** Grow the web UI past the first-run wizard: audit-log viewer, target CRUD,
   OAuth client list/revoke, token rotation, vault re-unlock, and a snapshots page to list and
   download DR skeletons ([#50](https://github.com/sjdodge123/skeleton-key-mcp/issues/50)).
6. **Dry-run for execute tools**, starting with a compose preview for `create_stack` /
   `update_stack`.
7. **Monitor-suppression audit detail.** `power_action … suppressMonitors` pauses and resumes
   monitors on the uptime-kuma target under the Pelican tool's single approval; the audit row
   records the call but not which monitor ids were touched. A per-pause/resume audit row
   would close the gap.
8. **Smaller follow-ups.**
   - The web-UI target form doesn't pin `credentialId` (it pins lazily on first read).
   - `verify` URLs over plain http are allowed for literal LAN IPs only, not LAN hostnames.
   - `overwrite` replaces named fields but never removes stale ones.
   - `container_inspect` fingerprints every env var, not just secrets.
   - Scan accuracy: secondary probes for SPA shells that don't self-identify, and a progress
     indicator.

## Working agreements

- **Every non-trivial change:** branch → PR → CI green. Merges are a maintainer's call.
- **Security-sensitive PRs** (auth, secrets, the MCP gate, the connection path) get an
  adversarial review and are never auto-merged.
- **`main` is protected** (PR + passing CI required, linear history). Don't push to it directly.
- **Verify behavior, don't just typecheck.** Review passes have repeatedly caught runtime bugs
  that compiled fine; add tests that exercise the real path.
- **No real homelab data in the repo**, and no rules about one particular deployment. See
  CLAUDE.md "Public-repo hygiene".
