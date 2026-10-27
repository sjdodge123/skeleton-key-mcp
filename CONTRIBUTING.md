# Contributing to Skeleton Key

Thanks for helping. Skeleton Key gives an AI agent broad, audited access to someone's
infrastructure, so every contribution is reviewed through a security lens first and a
feature lens second. This guide explains the rules that make that review fast.

New to the codebase? Read [`docs/ARCHITECTURE.md`](docs/ARCHITECTURE.md) (module map and
data flows) and [`docs/SCOPE.md`](docs/SCOPE.md) (product scope and security model) first.

## The non-negotiables

A PR that breaks one of these will not be merged, however useful the feature is.

1. **Secrets never transit the chat or MCP channel.** No tool may return, log, audit, or
   embed a credential value in an error message. Compare values with keyed fingerprints
   (`src/lib/fingerprint.ts`), never by echoing them. Ask users for secrets with
   `request_credential`, never in chat.
2. **Every tool declares its tier honestly.** A tool that changes state in any way is
   `execute`, even if the change looks harmless. `read` tools skip the approval gate, so a
   mis-tiered tool is a security bug.
3. **Execute tools say exactly what they will do.** `confirm()` must name the action and
   the target (`RESTART container 'web' on portainer 'nas1'`), so the approval prompt
   means something.
4. **Credentials come from the tool context.** Use `ctx.getCredential()` /
   `ctx.resolveCredential()`. Never read env vars, config files, or the bootstrap store
   for a secret.
5. **LAN only.** No feature that exposes Skeleton Key to the internet, opens tunnels, or
   phones home.
6. **The vault scope never widens.** The service identity can read only the
   infrastructure collection it was given. Don't add code that logs in as a personal
   account or asks for broader access.
7. **No real hostnames, IPs, or personal data** in code, tests, fixtures, or docs. Use
   placeholders (`nas1`, `192.168.1.x`, `example.com`).

## Development setup

```bash
npm install
npm run dev        # server with reload
npm run typecheck
npm test           # vitest; `npx vitest run <path>` for one file
npm run build
```

Node 22 is what CI uses. Tests must not reach the network. Use the fakes in
`test/helpers/` or an in-process server.

## Naming conventions

Consistent names let dozens of adapters coexist without collisions.

| Thing | Convention | Example |
|---|---|---|
| Connector `type` | lowercase kebab-case, `^[a-z][a-z0-9-]*$`, named for the product | `opnsense`, `truenas`, `home-assistant` |
| Tool name | `snake_case`, verb first | `list_vms`, `get_settings`, `restart_service` |
| Tool verbs | `list_` `get_` read; `set_` `create_` `update_` `delete_` `restart_` `start_` `stop_` execute | |
| Qualified tool name | `${type}.${target}.${tool}`, assembled by the registry, never by hand | `proxmox.pve1.list_guests` |
| Connector files | `src/connectors/<type>.ts` + `<type>.test.ts` (moving to `src/connectors/<type>/` soon) | `src/connectors/unifi.ts` |
| Branch | `<kind>/<scope>-<short-description>` | `feat/opnsense-connector`, `fix/ssh-quote-parsing` |
| Commit / PR title | [Conventional Commits](https://www.conventionalcommits.org): `<kind>(<scope>): <summary>` | `feat(opnsense): list firewall rules` |

Commit kinds: `feat`, `fix`, `docs`, `test`, `refactor`, `chore`, `ci`, `security`. The
scope is the connector type, or the core area (`mcp`, `secrets`, `web`, `oauth`, `audit`,
`discovery`, `snapshots`, `ci`, `docs`).

When several products do the same job (routers, hypervisors, NAS), reuse the tool names and
input shapes of the existing connector for that job. For example, `list_guests` on a new
hypervisor should look like it does on `proxmox`. This lets the agent learn a family once.

## Adding a connector

1. **Open an issue first** with the *Connector request* template. Say which API you will
   use, how it authenticates, and which tools are `read` vs `execute`. Confirm the API
   exists by watching the product's own UI make the calls; an unauthenticated probe can't
   prove a route exists.
2. Implement the `Connector` interface (`src/connectors/types.ts`) and register it in
   `src/connectors/index.ts`.
3. Start **read-only**. Add `execute` tools in a follow-up PR once the read side is merged.
4. Validate `options` with a strict zod `configSchema`. Don't accept unknown keys silently.
5. Keep destructive endpoints (factory reset, disk wipe, firmware flash, delete pool) out
   unless a maintainer explicitly agrees to them in the issue.
6. Tests: cover every tool, including the `confirm()` text of each execute tool, and the
   error path when the credential is missing or wrong.
7. Add a row to the connector table in `README.md`.

**Dependencies.** Prefer `undici`/`fetch` and the shared helpers in `src/connectors/net.ts`
over new packages. A new runtime dependency needs a maintainer's agreement in the issue:
every package runs inside a process that can read the vault.

**Coming soon:** pluggable secret providers (vaults other than Vaultwarden), connector
families with shared tool contracts, declarative app recipes, and command packs for the
SSH allowlist. Please hold PRs in those areas until the interfaces land, or discuss
the design in an issue first.

## Pull requests

- One logical change per PR. Fill in the PR template, including the security checklist.
- CI (typecheck, tests, build, CodeQL, dependency review) must be green.
- Changes under core paths (auth, secrets, the MCP gate, audit, CI, dependencies) require
  review by a code owner. See [`.github/CODEOWNERS`](.github/CODEOWNERS).
- PRs are squash-merged; the PR title becomes the commit message, so make it a valid
  Conventional Commit.

## Releases

Maintainers cut releases by tagging `vX.Y.Z` on `main`. Tags publish the `:latest`,
`:X.Y.Z`, and `:X.Y` images. Every merge to `main` publishes `:main` and `:sha-<short>`
for testing, but never `:latest`. That way a merged PR doesn't reach anyone's homelab
until a release is cut deliberately.

## Reporting a vulnerability

Don't open a public issue. See [`SECURITY.md`](SECURITY.md).

## License

Skeleton Key is licensed under [Apache-2.0](LICENSE). By submitting a contribution you
agree that it is licensed under the same terms (Section 5 of the license).
