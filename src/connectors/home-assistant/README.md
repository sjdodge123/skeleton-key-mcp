# Home Assistant (`home-assistant`)

Home Assistant's REST API: states, logbook, service calls and backups.

Also registrable as: `homeassistant`.

## Credential

Required. A long-lived access token (Profile → Security), sent as a bearer token.

## Options

| Option | Meaning |
|---|---|
| `baseUrl` | Base URL; HA's default 8123 is plain http. |
| `insecureTLS` | Skip TLS verification for this target only. |

Unknown options are refused at registration.

## Tools

The authoritative list (tiers and inputs) is [`tools.manifest.json`](../../../tools.manifest.json).

- **read:** `ha_states`, `ha_get`, `ha_logbook`
- **execute** (approval-gated, audited): `ha_call_service`, `ha_backup`
- **snapshot:** contributes artifacts to `form_skeleton` disaster-recovery snapshots.

## Safety notes

- `ha_get` is restricted to an allowlist of low-sensitivity read endpoints; side-effecting and private surfaces are refused.
- Service data is a typed object, encoded exactly once (the generic `http` connector double-encodes bodies for HA).
