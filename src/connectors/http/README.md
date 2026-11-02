# HTTP / REST service (`http`)

Any service that speaks HTTP but has no bespoke connector yet.

## Credential

Optional. Presented according to `auth`: bearer token, basic login, or a named header.

## Options

| Option | Meaning |
|---|---|
| `baseUrl` | Base URL; default `http://host:port`. |
| `auth` | `none` (default), `bearer`, `basic`, or `header`. |
| `headerName` | Header name when `auth` is `header` (e.g. `X-API-Key`). |
| `insecureTLS` | Skip TLS verification for this target only (self-signed LAN cert). |

Unknown options are refused at registration.

## Tools

The authoritative list (tiers and inputs) is [`tools.manifest.json`](../../../tools.manifest.json).

- **read:** `get`
- **execute** (approval-gated, audited): `request`

## Safety notes

- `request` is `execute` for every method, including GET, because the caller picks the method.
- Prefer a bespoke connector once one exists: field-level redaction and typed bodies only come with one.
