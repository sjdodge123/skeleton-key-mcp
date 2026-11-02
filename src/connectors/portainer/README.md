# Portainer (Docker) (`portainer`)

Docker through a Portainer CE/BE instance: containers, logs and stacks.

## Credential

Required. A Portainer API key (My account → Access tokens) in the item's `token`/`api_key` field, sent as `X-API-Key`. A username + password also works (exchanged for a JWT via `/api/auth`).

## Options

| Option | Meaning |
|---|---|
| `baseUrl` | Base URL; default from host/port. |
| `endpointId` | Docker environment to use when the instance has several. |
| `insecureTLS` | Skip TLS verification for this target only. |
| `denyPatterns` | Extra denied patterns for `exec_container`. |
| `allowPatterns` | Restrict `exec_container` to an allowlist. |

Unknown options are refused at registration.

## Tools

The authoritative list (tiers and inputs) is [`tools.manifest.json`](../../../tools.manifest.json).

- **read:** `list_endpoints`, `list_containers`, `container_logs`, `list_stacks`, `container_inspect`, `get_stack_file`
- **execute** (approval-gated, audited): `restart_container`, `stop_container`, `start_container`, `create_stack`, `update_stack`, `remove_stack`, `exec_container`
- **snapshot:** contributes artifacts to `form_skeleton` disaster-recovery snapshots.

## Safety notes

- Stack secrets go in `secretEnv` as vault item references, resolved at deploy time; values never reach the chat, a tool result or an error. Reads report env var **names** with redacted values, plus keyed fingerprints for comparison.
- `remove_stack` only removes stacks Skeleton Key created.
