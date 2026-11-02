# SSH host (`ssh`)

Any host reachable over SSH. The generic fallback that makes every Linux box readable on day one.

## Credential

Required. A login with a password or a private key (`vault_generate_ssh_key` creates and stores one). Optional `secret` = key passphrase.

## Options

| Option | Meaning |
|---|---|
| `denyPatterns` | Extra denied command patterns for this host (on top of the built-in `rm -rf`/`mkfs`/`dd` deny list). |
| `allowPatterns` | Restrict `run_command` to an allowlist. |
| `snapshotCommands` | Config-dump commands `form_skeleton` runs; each becomes one artifact. Unset = a default read-only system profile. |
| `commandTimeoutMs` | Per-target default timeout for one command (capped at 10 minutes). |
| `sudoPrefixes` | Command names that need root (e.g. `["docker"]` on a Synology). `sudo -n` is prefixed to the first command only; needs a NOPASSWD rule scoped to that binary. |

Unknown options are refused at registration.

## Tools

The authoritative list (tiers and inputs) is [`tools.manifest.json`](../../../tools.manifest.json).

- **read:** `tail_log`, `journalctl`, `service_status`, `disk_usage`, `grep_logs`, `run_readonly`
- **execute** (approval-gated, audited): `run_command`, `restart_service`
- **snapshot:** contributes artifacts to `form_skeleton` disaster-recovery snapshots.

## Safety notes

- `run_readonly` vets **every** command of a compound line against a read-only allowlist (`../shared/command-policy.ts`) and refuses substitution, redirects and the write modes of allowlisted commands.
- `run_command` is `execute`: approval-gated, audited, and still subject to the deny list.
