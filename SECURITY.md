# Security policy

Skeleton Key holds the credentials to an entire homelab and lets an AI agent act on it.
We treat security reports as the highest-priority work in the project.

## Reporting a vulnerability

**Please do not open a public issue, discussion, or PR for a vulnerability.**

Report it privately through GitHub:
[**Report a vulnerability**](https://github.com/sjdodge123/skeleton-key-mcp/security/advisories/new)
(the *Security* tab → *Report a vulnerability*).

Please include the affected version or commit, a description of the impact, and steps to
reproduce. Never include real credentials, hostnames, or IPs from your own network. This
is a volunteer project, but we aim to:

- acknowledge a report within **3 days**,
- give an initial assessment within **10 days**,
- ship a fix or mitigation for confirmed high-severity issues as fast as we can, and credit
  you in the advisory unless you'd rather stay anonymous.

## Supported versions

Only the latest release (the `:latest` image and the newest `vX.Y.Z` tag) gets security
fixes.

## What we especially want to hear about

- Running an `execute` action without approval: a mis-tiered tool, a bypass of the
  approval gate, or a way around `SKELETON_KEY_DISABLE_EXECUTE`.
- Bypasses of the command allow/deny policy (SSH `run_readonly` / `run_command`,
  Portainer `exec_container`), including shell metacharacter and quoting tricks.
- Any path by which a secret reaches the chat, a tool result, an error message, the audit
  log, or a snapshot manifest.
- Reading vault items outside the scoped collection, or widening the service account's access.
- Auth weaknesses: OAuth/PKCE, TOTP gating, token storage, the static bearer, the
  locked-vault kill-switch, or `Host` header tricks that steer unlock or credential links.
- Defaults that expose Skeleton Key beyond the LAN.
- Supply-chain problems in the published image or the release workflow.

## Out of scope

- Problems that only exist if you expose Skeleton Key to the internet against the docs.
- Attacks that need an already-authenticated admin session **and** a valid TOTP code.
- Vulnerabilities in the services Skeleton Key manages. Report those to their vendors.
