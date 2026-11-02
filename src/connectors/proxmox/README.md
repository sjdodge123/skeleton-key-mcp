# Proxmox VE (`proxmox`)

A Proxmox VE node or cluster over `/api2/json`.

## Credential

Required. Preferred: an API token (`token_id` field or a `user@realm!tokenid` username, plus `token_secret`/secret/password). Fallback: username + password, exchanged for a ticket.

## Options

| Option | Meaning |
|---|---|
| `baseUrl` | Base URL; always https. |
| `node` | Default node for node-scoped reads. |
| `insecureTLS` | Skip certificate verification for this target only (default on: PVE ships a self-signed cert). Transit is always TLS. |

Unknown options are refused at registration.

## Tools

The authoritative list (tiers and inputs) is [`tools.manifest.json`](../../../tools.manifest.json).

- **read:** `list_nodes`, `list_guests`, `node_status`, `guest_status`, `list_tasks`, `task_log`
- **execute** (approval-gated, audited): `guest_power`
- **snapshot:** contributes artifacts to `form_skeleton` disaster-recovery snapshots.

## Safety notes

- The one execute tool, `guest_power`, looks the guest up by vmid so the approval prompt can name it.
- Destructive lifecycle operations (delete, rollback, migrate) are deliberately out of scope.
