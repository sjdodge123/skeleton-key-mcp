# Pelican Panel (game servers) (`pelican`)

A Pelican game-server panel: inventory, provisioning, power, schedules, files, and (through a registered `ssh` target) panel/PHP/Wings upgrades.

## Credential

Required. One item with two fields: `application_key` (`papp_…`, Application API) and `client_key` (`pacc_…`, Client API, belonging to a dedicated panel user that owns the managed servers). Each tool uses the key its API needs, never a fallback.

## Options

| Option | Meaning |
|---|---|
| `baseUrl` | Panel URL. Plain http is allowed only to a private LAN address. |
| `ownerUserId` | Panel user id that owns servers `create_server` makes. |
| `sshTarget` | Name of the registered `ssh` target for the panel host (needed for version/upgrade tools). |
| `panelPath` | Panel install path (default `/var/www/pelican`). |
| `monitorsTarget` | Which `uptime-kuma` target to use for monitor suppression when several exist. |
| `panelUser` | Panel's system user (default `www-data`). |
| `insecureTLS` | Skip TLS verification for this target only. |

Unknown options are refused at registration.

## Tools

The authoritative list (tiers and inputs) is [`tools.manifest.json`](../../../tools.manifest.json).

- **read:** `list_eggs`, `list_nodes`, `list_allocations`, `list_users`, `list_servers`, `server_details`, `server_resources`, `list_schedules`, `panel_version`, `list_files`, `read_file`
- **execute** (approval-gated, audited): `panel_upgrade`, `panel_prepare_runtime`, `wings_update`, `create_allocations`, `import_egg`, `create_server`, `update_server_startup`, `update_server_build`, `power_action`, `update_startup_variables`, `create_schedule`, `update_schedule`, `delete_schedule`, `assign_allocation`, `write_file`, `create_folder`, `pull_file`, `decompress_file`, `rename_files`, `delete_files`
- **snapshot:** contributes artifacts to `form_skeleton` disaster-recovery snapshots.

## Safety notes

- Root work on the panel host runs only through `scripts/host/skeleton-key-pelican-host.sh` under ONE NOPASSWD rule, with fixed subcommands and validated arguments (`host.ts`).
- `power_action` with `suppressMonitors: true` pauses the server's Uptime Kuma monitors, acts, verifies, and resumes them in a `finally`.
- Game passwords and other secret startup variables are vault references, never chat values.
