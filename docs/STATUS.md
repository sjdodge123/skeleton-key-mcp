# Status & Handoff

Living status doc. Update it as work lands. For architecture see `docs/ARCHITECTURE.md`; for rules/commands see `CLAUDE.md`.

_Last updated: 2026-07-03._

## TL;DR

Phase 1 is **complete and deployed**. A real MCP client (Claude Code) is connected over OAuth against a live instance on the owner's NAS and has driven the conversational onboarding tools end-to-end (network scan, key generation, target registration, validation). Everything below "Done" is merged to `main`; the image auto-publishes to GHCR and is picked up by Watchtower.

## Done (merged to `main`)

- **Core skeleton** — Express app, stateful Streamable-HTTP MCP endpoint, dynamic tool registry (global ⊕ per-target), append-only audit log.
- **Secrets** — libsodium bootstrap store; scoped-Vaultwarden client over the `bw` CLI with offline cache; secrets kept off argv/logs; `reestablish()` unlock logic.
- **Generic SSH connector** — read tools + gated execute with a command deny-list; generic HTTP connector.
- **First-run wizard** — passphrase, vault connect + scoping/durability checks, LAN discovery, TOTP, connect-Claude step; clickable steps, submit spinners.
- **OAuth 2.1 auth** — discovery, dynamic client registration, PKCE, TOTP-gated consent, rotating refresh tokens, per-client revocation; static bearer retained as fallback.
- **Conversational onboarding tools** — `get_started`, `network_scan`, `vault_generate_ssh_key`, `vault_store_login`, `vault_list_credentials`, `vault_validate_ssh`, `register_target`, `list_targets`.
- **Self-guiding onboarding** — server `instructions` on connect + live `tools/list_changed` push on target registration.
- **LAN discovery fingerprinting** — SSH banner + HTTP content match with confidence levels (replaces port-only guessing).
- **Packaging & CI** — multi-stage Dockerfile, Portainer compose, CI on every PR, GHCR publish on merge, branch protection.
- **Exact-name credential lookup (#14)** — `getCredential` resolves refs by exact item name → id → case-insensitive → unique-substring (`bw get item` substring-matched, so `PiHole` broke when `pihole-ssh` was created; found live during onboarding). Bounded via `bw list items --search` (id-shaped refs use a direct `bw get item`).
- **Locked-vault UX (#13/#14)** — a locked vault no longer 503s authenticated clients; sessions connect and a banner-only `get_started` tells the user how to unlock, while every other tool is withheld from **both** `tools/call` and `tools/list` so a leaked token can't enumerate/scan before unlock. Unlock emits `tools/list_changed` so live sessions recover. Auth routing is lock-independent (expired token → 401→refresh, not a dead 503); unlock URLs come from the pinned/auto-detected public URL only, never the client Host header. Reworked twice after adversarial `/code-review` (first cut removed the restart kill-switch; second missed the `tools/list` gate).
- **Credential lifecycle (#15–#18)** — `update_target` re-points a target's credentialRef (options shallow-merged so the SSH deny-list survives); `vault_delete_credential` retires an item (guarded against deleting one a target still uses); **`request_credential`/`credential_request_status`** hand off secrets via a one-time, TOTP-gated web form (`src/web/credential-routes.ts`) so passwords/tokens never transit the chat/MCP channel; `get_started`/instructions now teach both onboarding flows and the never-ask-secrets-in-chat rule.
- **Public URL auto-detect (#21)** — the base URL for user-facing (secret-asking) links is auto-detected from the LAN on first boot and persisted, with `SKELETON_KEY_PUBLIC_URL` as override; never derived from the client Host header.
- **Wizard-managed boot auto-unlock (keyslots)** — the bootstrap store moved to a keyslot format (`SKMCP2`: random data key wrapped by the argon2 passphrase KEK and, optionally, by a random machine unlock key; v1 stores migrate on first passphrase unlock). Enabling auto-unlock (wizard step or the TOTP-gated post-setup unlock page) writes the random key — never the passphrase — to a host-mounted file (`SKELETON_KEY_UNLOCK_KEY_FILE`), which boot prefers. `SKELETON_KEY_PASSPHRASE` / `_FILE` are **deprecated** (still honored with a boot warning).

Each feature PR went through an adversarial `/code-review`; findings were fixed before merge (notably: OAuth secret-leak/refresh-rotation, provisioning secret-in-argv leak + shell-injection, stateful-transport teardown recursion + session leak, scan httpProbe hang, locked-state kill-switch gaps, credential-delete guard bypass).

## Open PRs

None. `main` is the source of truth.

## Known gaps / good next tasks

Roughly in priority order — pick up any of these:

0. **Verify bearer while locked (#20)** — a valid legacy static bearer gets a 401 (not a clear "locked") while the store is locked, because it can only be verified against the locked store. Fix: hash it lock-independently (like OAuth tokens) so it can be verified — and safely admitted to the banner-only `get_started` — while locked.

1. **LAN TLS for the web UI + MCP endpoint** (owner-flagged 2026-07-03). Everything the UI carries — the master passphrase at unlock, credentials typed into `request_credential` forms — currently transits the LAN as **plain HTTP**. The existing guardrails don't cover this: LAN-only shrinks the attacker pool but a compromised IoT device doing ARP spoofing can capture the passphrase; the pinned public URL stops *us* linking to a forged origin but not an attacker *answering as* ours; TOTP protects actions, not transit. This is exactly TLS's job (confidentiality + server authentication). Sketch: native HTTPS — self-signed cert generated on first boot (or a user-mounted cert/key pair), one-time browser trust step documented; mind the OAuth issuer URL (scheme changes) and MCP client trust of self-signed certs (`NODE_EXTRA_CA_CERTS` for Claude Code). The "no reverse proxy" rule is about *internet* exposure — a LAN-only TLS terminator or native TLS is compatible with the security model. Note: boot auto-unlock reduces how often the passphrase transits; the credential hand-off forms still carry a secret every time.
2. **Bespoke connectors** (the biggest value). `ssh`/`http` plus **`portainer`** (done — Docker mgmt incl. `update_stack` to redeploy a stack from an edited compose). Discovery maps `portainer` detections to the real connector now; `synology`, `proxmox`, `unifi`, `home-assistant`, `pihole` still fall back to `http`. Next suggested: **Home Assistant** (REST + long-lived token), **Proxmox** (API token). Each is a `Connector` in `src/connectors/`.
3. **Admin console** — the web UI is first-run-wizard only. Grow it into an authenticated admin page: audit-log viewer, target CRUD, OAuth client list/revoke (endpoints already exist under `/api/oauth/clients`), token rotation, vault re-unlock. Reuse the wizard's TOTP/verify components.
4. **Scan accuracy round 2** — fingerprints are content-based now but still imperfect (e.g., SPA shells that don't self-identify show as "likely"/"open"). Consider secondary probes (Portainer `/api/status`, Pi-hole `/admin`) and de-noising the results list.
5. **Operational polish** — consider a scan progress indicator (the fingerprinting scan is slower than the old port scan).
6. **Per-target command policies & dry-run** — the deny-list is global; add per-target allow/deny and optional dry-run for execute tools.

## Environment notes (not in the repo on purpose)

- The repo is **public** and deliberately carries **no real hostnames/IPs** — use generic placeholders (`<NAS_LAN_IP>:8787`, `192.168.x`) in code and docs.
- The live deployment specifics (actual LAN IP, Vaultwarden internal URL, which hosts exist) live only with the owner. Don't hard-code them.
- Watchtower on the NAS auto-pulls new `:latest`; a container restart re-locks the vault (unlock via the web UI unless `SKELETON_KEY_PASSPHRASE` is set).

## Working agreements (how this project has been run)

- **Every non-trivial change:** branch → PR → CI green. Merges are the owner's call.
- **Security-sensitive PRs** (anything touching auth, secrets, the connection path) get an adversarial `/code-review` and are **not** auto-merged — leave them for the owner to review/merge. Docs/mechanical changes may auto-merge after CI.
- **`main` is protected** (PR + passing CI required, linear history). Don't push to it directly.
- Verify behavior, don't just typecheck — the review passes have repeatedly caught runtime bugs that compiled fine (transport teardown recursion, scan hang). Add tests that exercise the real path.
