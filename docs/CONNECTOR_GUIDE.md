# Writing a connector

A connector adapts one *type* of service (a router OS, a hypervisor, a NAS) to Skeleton
Key's tool registry. This guide walks through adding one. Read
[CONTRIBUTING.md](../CONTRIBUTING.md) first; its non-negotiables apply to every line.

## 1. Agree on the shape in an issue

Open a *Connector request* issue before writing code. Name the API and how it
authenticates, list each tool with its tier (`read` or `execute`), and confirm the API
by watching the product's own UI make the calls. A maintainer agrees to the tool list,
any new runtime dependency, and any destructive endpoint before you start.

If another connector already does the same job (another hypervisor, another router),
reuse its tool names and input shapes, so the agent learns the family once.

## 2. Scaffold

```bash
npm run new:connector -- opnsense "OPNsense"
```

This creates `src/connectors/opnsense/` with:

| File | What it is |
|---|---|
| `index.ts` | exports the `Connector`: type, label, `configSchema`, `buildTools` |
| `index.test.ts` | starter tests for the read tool, including the missing-credential path |
| `README.md` | what it talks to, the credential, options, tools, safety notes |

Register it in `src/connectors/index.ts` (the scaffold prints the two lines). From then
on the conformance and boundary suites check it on every test run.

Helpers only this connector uses live in its folder (`client.ts`, `host.ts`). Helpers
several connectors need go in `src/connectors/shared/` (maintainer-owned).

## 3. Implement the read side

- **Credentials** come only from `ctx.getCredential()` (or `ctx.resolveCredential()` for
  another vault item). Pick fields explicitly (`cred.fields["api_key"]`); never treat the
  item's notes as a secret.
- **HTTP** goes through `tlsFetch` and `deriveBaseUrl` from `../shared/net.ts`.
  `insecureTLS` is per target and per request, never process-wide.
- **Never return a secret.** Whitelist the fields a read returns when the API embeds key
  material (the UniFi connector is the model). Errors must not quote credentials or raw
  upstream bodies that may contain them.
- **Options** are a plain `z.object` whose fields are all optional or defaulted.
  Registration refuses keys the schema doesn't declare.

## 4. Add execute tools (in a follow-up PR)

- `tier: "execute"` for anything that changes state, however small.
- `confirm(input, target)` returns one line naming the exact action **and the target**:
  `RESTART container 'web' on portainer 'nas1'`. The approval prompt shows it.
- Prefer surgical, revertable operations. Keep destructive endpoints out unless a
  maintainer agreed to them in the issue.

## 5. Check and publish the tool list

```bash
npm test             # your tests + conformance + import boundaries
npm run manifest     # regenerate tools.manifest.json, then commit it
npm run typecheck
```

## What CI enforces

**Conformance** (`src/connectors/conformance.test.ts`) runs against every registered
connector:

- kebab-case type; snake_case, verb-first, unique tool names;
- a tool's verb matches its tier (`delete_*` is `execute`, `list_*` is `read`);
- the tool set doesn't depend on the target;
- every execute tool's `confirm()` names the target;
- an introspectable `configSchema` that refuses unknown keys at registration;
- a folder README that names every tool;
- **read tools send no state-changing request.** Each read tool runs against a recording
  fake of `fetch` and SSH; any non-GET request fails unless it is a login listed in
  `READ_TOOL_AUTH_REQUESTS`.

**Import boundaries** (`src/connectors/boundaries.test.ts`): a connector imports only
its own folder, `../types.ts`, `../shared/*`, `zod` and `js-yaml`. No `child_process`,
`fs`, raw sockets, the secrets store, the audit log, config, the web layer, or another
connector. A genuine need becomes a reviewed entry in that file's `EXCEPTIONS`, with the
reason.

**The manifest** (`tools.manifest.json`): a test fails when it is stale, so every new
tool, tier and input is a visible diff a maintainer reviews.

The exception lists in those files may shrink, but adding to them needs a maintainer.
