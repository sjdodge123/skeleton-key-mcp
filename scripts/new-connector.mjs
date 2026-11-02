#!/usr/bin/env node
// Scaffold a connector folder that already passes the conformance suite:
//   npm run new:connector -- <type> ["Human label"]
// Writes src/connectors/<type>/{index.ts,index.test.ts,README.md} with one
// read-only tool. You then register it in src/connectors/index.ts, replace the
// placeholder API call, and run `npm run manifest`.

import { existsSync, mkdirSync, writeFileSync } from "node:fs";
import path from "node:path";

const [type, labelArg] = process.argv.slice(2);
if (!type || !/^[a-z][a-z0-9-]*$/.test(type)) {
  console.error('usage: npm run new:connector -- <type> ["Human label"]   (type: lowercase kebab-case, e.g. opnsense)');
  process.exit(2);
}
const label = labelArg ?? type.split("-").map((w) => w[0].toUpperCase() + w.slice(1)).join(" ");
const camel = type.replace(/-([a-z0-9])/g, (_, c) => c.toUpperCase());
const dir = path.resolve(import.meta.dirname, "..", "src", "connectors", type);
if (existsSync(dir)) {
  console.error(`src/connectors/${type}/ already exists.`);
  process.exit(1);
}

const index = `import { z } from "zod";
import type { Connector, ConnectorTool, Target, ToolContext, ToolResult } from "../types.js";
import { deriveBaseUrl, tlsFetch } from "../shared/net.js";

/**
 * ${label} connector.
 *
 * TODO: say which API this talks to, how it authenticates, and why a bespoke
 * connector beats the generic \`http\` one (field redaction, typed bodies, …).
 * Start read-only; add execute tools in a follow-up PR (CONTRIBUTING.md).
 */

const optionsSchema = z
  .object({
    /** Base URL; if omitted, host/port form it (443 ⇒ https, else http). */
    baseUrl: z.string().url().optional(),
    /** Skip TLS verification for THIS target only (self-signed LAN cert). */
    insecureTLS: z.boolean().default(false),
  })
  .prefault({});

function options(target: Target) {
  return optionsSchema.parse(target.options ?? {});
}

async function get(ctx: ToolContext, apiPath: string): Promise<ToolResult> {
  const cred = await ctx.getCredential();
  const token = cred.secret ?? cred.password;
  if (!token) return { text: \`Target '\${ctx.target.name}' has no API token in its vault item.\`, isError: true };
  const opts = options(ctx.target);
  const url = \`\${deriveBaseUrl(ctx.target, { baseUrl: opts.baseUrl })}\${apiPath}\`;
  const res = await tlsFetch(url, { method: "GET", headers: { Accept: "application/json", Authorization: \`Bearer \${token}\` } }, opts.insecureTLS);
  // Never echo a credential, and never return raw upstream fields that may hold secrets.
  if (!res.ok) return { text: \`${label} answered HTTP \${res.status} for \${apiPath}.\`, isError: true };
  return { text: (await res.text()).slice(0, 20_000) };
}

function buildTools(target: Target): ConnectorTool[] {
  return [
    {
      name: "get_status",
      description: \`Read ${label}'s status on \${target.name}.\`,
      tier: "read",
      inputSchema: z.object({}),
      // TODO: replace with the product's real status endpoint.
      run: (_input, ctx) => get(ctx, "/api/status"),
    },
  ];
}

export const ${camel}Connector: Connector = {
  type: "${type}",
  label: "${label}",
  configSchema: optionsSchema,
  requiresCredential: true,
  buildTools,
};
`;

const test = `import { describe, it, expect, vi, afterEach } from "vitest";
import type { Credential, Target, ToolContext } from "../types.js";
import { ${camel}Connector } from "./index.js";

const target: Target = { name: "${type}1", type: "${type}", host: "10.0.0.10", port: 443, credentialRef: "${type}1-token" };
const cred: Credential = { ref: "${type}1-token", secret: "token", fields: {}, uris: [] };
const ctx = (over: Partial<ToolContext> = {}): ToolContext => ({ target, getCredential: async () => cred, ...over });
const tool = (name: string) => ${camel}Connector.buildTools(target).find((t) => t.name === name)!;

afterEach(() => vi.unstubAllGlobals());

describe("${type} get_status", () => {
  it("sends the token as a bearer header and returns the body", async () => {
    const fetchMock = vi.fn(async () => new Response('{"ok":true}', { status: 200 }));
    vi.stubGlobal("fetch", fetchMock);
    const res = await tool("get_status").run({}, ctx());
    expect(res.isError).toBeFalsy();
    expect(res.text).toContain('"ok":true');
    const [url, init] = fetchMock.mock.calls[0] as unknown as [string, RequestInit];
    expect(url).toBe("https://10.0.0.10:443/api/status");
    expect((init.headers as Record<string, string>).Authorization).toBe("Bearer token");
  });

  it("fails clearly without a token, sending nothing", async () => {
    const fetchMock = vi.fn();
    vi.stubGlobal("fetch", fetchMock);
    const res = await tool("get_status").run({}, ctx({ getCredential: async () => ({ ...cred, secret: undefined }) }));
    expect(res.isError).toBe(true);
    expect(fetchMock).not.toHaveBeenCalled();
  });
});
`;

const readme = `# ${label} (\`${type}\`)

TODO: one line on what this connector talks to.

## Credential

Required. TODO: which vault field holds what (e.g. an API token in the item's secret).

## Options

| Option | Meaning |
|---|---|
| \`baseUrl\` | Base URL; default from host/port. |
| \`insecureTLS\` | Skip TLS verification for this target only. |

Unknown options are refused at registration.

## Tools

The authoritative list (tiers and inputs) is [\`tools.manifest.json\`](../../../tools.manifest.json).

- **read:** \`get_status\`
- **execute** (approval-gated, audited): (none)

## Safety notes

- TODO: what this connector refuses, redacts, or never touches.
`;

mkdirSync(dir, { recursive: true });
writeFileSync(path.join(dir, "index.ts"), index);
writeFileSync(path.join(dir, "index.test.ts"), test);
writeFileSync(path.join(dir, "README.md"), readme);

console.log(`Created src/connectors/${type}/ (index.ts, index.test.ts, README.md).

Next:
  1. Register it in src/connectors/index.ts:
       import { ${camel}Connector } from "./${type}/index.js";
       registerConnector(${camel}Connector);
  2. Replace the placeholder endpoint and fill in the TODOs.
  3. npm test              # conformance + boundaries run against it automatically
  4. npm run manifest      # then commit tools.manifest.json
`);
