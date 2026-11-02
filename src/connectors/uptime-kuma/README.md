# Uptime Kuma (monitors / notification suppression) (`uptime-kuma`)

An Uptime Kuma instance over Socket.IO (Kuma has no REST API for monitor control).

## Credential

Required. A Kuma login (username + password). Kuma's API keys only guard `/metrics`.

## Options

| Option | Meaning |
|---|---|
| `baseUrl` | Kuma URL; 443/8443 imply https. |
| `insecureTLS` | Skip TLS verification for this target only. |
| `timeoutMs` | Connect / per-request timeout (default 15 s). |

Unknown options are refused at registration.

## Tools

The authoritative list (tiers and inputs) is [`tools.manifest.json`](../../../tools.manifest.json).

- **read:** `list_monitors`, `monitor_status`
- **execute** (approval-gated, audited): `pause_monitor`, `resume_monitor`, `maintenance`, `end_maintenance`

## Safety notes

- Execute tools only pause and resume monitors.
- `maintenance` pauses a set of monitors and returns a persisted handle; `end_maintenance` resumes exactly what that handle paused (never a monitor that was already paused) and is idempotent.
