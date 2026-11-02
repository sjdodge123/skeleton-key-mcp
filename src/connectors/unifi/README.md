# UniFi (network) (`unifi`)

A UniFi OS gateway (UDM / Cloud Gateway family) or a self-hosted controller; which one is auto-detected.

## Credential

Required. A UniFi OS API key (Control Plane → Integrations), sent as `X-API-Key`. A username + password login is the fallback.

## Options

| Option | Meaning |
|---|---|
| `baseUrl` | Base URL; 443/8443 imply https. |
| `site` | Site short id (default `default`). |
| `insecureTLS` | Skip TLS verification for this target only (default on: UniFi OS ships a self-signed cert). |

Unknown options are refused at registration.

## Tools

The authoritative list (tiers and inputs) is [`tools.manifest.json`](../../../tools.manifest.json).

- **read:** `list_devices`, `list_clients`, `list_networks`, `list_port_forwards`, `get_settings`
- **execute** (approval-gated, audited): `set_network_ipv6`, `set_gateway_feature`, `set_remote_logging`, `create_port_forward`, `update_port_forward`, `delete_port_forward`, `force_provision`
- **snapshot:** contributes artifacts to `form_skeleton` disaster-recovery snapshots.

## Safety notes

- Network objects embed WireGuard/OpenVPN private keys, so every read is field-whitelisted and read-modify-write happens server-side; key material never reaches a tool result.
- Writes are surgical and revertable (feature toggles, per-network IPv6, remote logging, port forwards). Port forwards refuse to expose or redirect Skeleton Key's own control plane.
