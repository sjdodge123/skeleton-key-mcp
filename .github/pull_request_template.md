## What and why

<!-- What this changes and why. Link the issue: "Closes #123". -->

## How it was verified

<!-- Tests added/updated, and any manual run against a real (redacted) service. -->

## Security checklist

<!-- Check each box, or explain why it doesn't apply. See CONTRIBUTING.md → "The non-negotiables". -->

- [ ] Every new or changed tool has the right tier; anything that changes state is `execute`.
- [ ] Every `execute` tool's `confirm()` names the exact action **and** target.
- [ ] Credentials come only from `ctx.getCredential()` / `ctx.resolveCredential()`, never env, files, or the bootstrap store.
- [ ] No secret can reach a tool result, error message, log line, audit entry, or snapshot manifest.
- [ ] No new runtime dependency (or a maintainer agreed to it in the linked issue).
- [ ] No real hostnames, IPs, usernames, or personal data in code, tests, or docs.
- [ ] Destructive endpoints are left out, or were explicitly agreed in the issue.
- [ ] README connector table / docs updated if behavior changed.
