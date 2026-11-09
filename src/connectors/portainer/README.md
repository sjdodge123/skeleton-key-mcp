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
- **execute** (approval-gated, audited): `restart_container`, `stop_container`, `start_container`, `create_stack`, `update_stack`, `update_stack_images`, `remove_stack`, `exec_container`
- **snapshot:** contributes artifacts to `form_skeleton` disaster-recovery snapshots.

## Safety notes

- Stack secrets go in `secretEnv` as vault item references, resolved at deploy time; values never reach the chat, a tool result or an error. Reads report env var **names** with redacted values, plus keyed fingerprints for comparison.
- `remove_stack` only removes stacks Skeleton Key created.
- `update_stack_images` re-pulls and redeploys a stack without touching its compose file or env, so it is allowed on any stack. It is how an agent updates Skeleton Key itself when its stack runs on a registered Portainer.
- Before redeploying, `update_stack_images` compares each running container's environment with what the stack file would set (after `${VAR}` substitution; image defaults ignored). If a redeploy would change or drop a variable — typically one edited on the container but never saved to the stack file — it refuses and lists the variables with keyed fingerprints of both values, never the values. `allowEnvDrift: true` redeploys anyway, and the approval prompt says so. It fails closed when the comparison can't run.
