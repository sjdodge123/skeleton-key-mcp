import { z } from "zod";
import type { Connector, ConnectorTool, Credential, Target, ToolContext } from "./types.js";

/**
 * Generic HTTP/REST connector — the fallback for any service that speaks HTTP
 * but doesn't yet have a bespoke adapter. Bespoke connectors (Synology, Proxmox,
 * UniFi, Home Assistant, Portainer, Pi-hole) will build on this same shape in
 * later phases; for now it offers raw read/execute request tools.
 */

const optionsSchema = z
  .object({
    /** Base URL; if omitted, `host`/`port` form http://host:port. */
    baseUrl: z.string().url().optional(),
    /** How the credential is presented. */
    auth: z.enum(["none", "bearer", "basic", "header"]).default("none"),
    /** Header name when auth === "header" (e.g. "X-API-Key"). */
    headerName: z.string().optional(),
    /** Skip TLS verification for self-signed LAN certs. */
    insecureTLS: z.boolean().default(false),
  })
  .default({});

function baseUrl(target: Target): string {
  const opts = optionsSchema.parse(target.options ?? {});
  if (opts.baseUrl) return opts.baseUrl.replace(/\/$/, "");
  const scheme = (target.port ?? 80) === 443 ? "https" : "http";
  return `${scheme}://${target.host}${target.port ? `:${target.port}` : ""}`;
}

function authHeaders(target: Target, cred: Credential): Record<string, string> {
  const opts = optionsSchema.parse(target.options ?? {});
  const token = cred.secret ?? cred.password ?? "";
  switch (opts.auth) {
    case "bearer":
      return { Authorization: `Bearer ${token}` };
    case "basic":
      return {
        Authorization: `Basic ${Buffer.from(`${cred.username ?? ""}:${cred.password ?? ""}`).toString("base64")}`,
      };
    case "header":
      return opts.headerName ? { [opts.headerName]: token } : {};
    default:
      return {};
  }
}

async function request(
  ctx: ToolContext,
  method: string,
  path: string,
  body?: unknown,
): Promise<{ text: string; isError?: boolean }> {
  const opts = optionsSchema.parse(ctx.target.options ?? {});
  if (opts.insecureTLS) process.env.NODE_TLS_REJECT_UNAUTHORIZED = "0";
  let headers: Record<string, string> = { Accept: "application/json" };
  if (ctx.target.credentialRef) {
    headers = { ...headers, ...authHeaders(ctx.target, await ctx.getCredential()) };
  }
  if (body !== undefined) headers["Content-Type"] = "application/json";

  const url = `${baseUrl(ctx.target)}${path.startsWith("/") ? path : `/${path}`}`;
  const res = await fetch(url, {
    method,
    headers,
    body: body !== undefined ? JSON.stringify(body) : undefined,
  });
  const text = await res.text();
  return {
    text: `HTTP ${res.status} ${res.statusText}\n${text.slice(0, 20_000)}`,
    isError: !res.ok,
  };
}

function buildTools(target: Target): ConnectorTool[] {
  return [
    {
      name: "get",
      description: `GET a path on ${target.name}'s HTTP API (${baseUrl(target)}).`,
      tier: "read",
      inputSchema: z.object({ path: z.string().describe("Path, e.g. /api/status") }),
      run: (input, ctx) => request(ctx, "GET", (input as { path: string }).path),
    },
    {
      name: "request",
      description: `Make an arbitrary HTTP request to ${target.name} (non-GET may change state).`,
      tier: "execute",
      inputSchema: z.object({
        method: z.enum(["GET", "POST", "PUT", "PATCH", "DELETE"]),
        path: z.string(),
        body: z.unknown().optional(),
      }),
      confirm: (input, t) => {
        const { method, path } = input as { method: string; path: string };
        return `HTTP ${method} ${baseUrl(t)}${path}`;
      },
      run: (input, ctx) => {
        const { method, path, body } = input as { method: string; path: string; body?: unknown };
        return request(ctx, method, path, body);
      },
    },
  ];
}

export const httpConnector: Connector = {
  type: "http",
  label: "HTTP / REST service",
  configSchema: optionsSchema,
  requiresCredential: false,
  buildTools,
};
