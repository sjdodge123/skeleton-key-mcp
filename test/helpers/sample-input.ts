import type { z } from "zod";
import { toolInputJsonSchema } from "../../src/mcp/server.js";

type JsonSchema = {
  type?: string | string[];
  properties?: Record<string, JsonSchema>;
  items?: JsonSchema;
  enum?: unknown[];
  const?: unknown;
  anyOf?: JsonSchema[];
  oneOf?: JsonSchema[];
  minimum?: number;
  maximum?: number;
  exclusiveMinimum?: number;
  minLength?: number;
  minItems?: number;
  format?: string;
  default?: unknown;
};

/** A plausible string for a field, keyed off its name, so tools that branch on
 *  the shape of a path or URL get past their first check. */
function sampleString(key: string, s: JsonSchema): string {
  const k = key.toLowerCase();
  let v = "example";
  if (s.format === "uri" || k.includes("url")) v = "https://example.com/file.txt";
  else if (k.includes("path") || k === "file" || k === "root" || k === "directory") v = "/tmp/example";
  else if (k.includes("host") || k === "ip") v = "10.0.0.20";
  else if (k.includes("version") || k === "release") v = "v1.0.0";
  else if (k.includes("cron") || k.includes("minute") || k.includes("hour")) v = "0";
  return v.padEnd(s.minLength ?? 0, "x");
}

function sampleFor(key: string, s: JsonSchema | undefined): unknown {
  if (!s) return "example";
  if (s.const !== undefined) return s.const;
  if (s.enum?.length) return s.enum[0];
  const branch = (s.anyOf ?? s.oneOf)?.find((b) => b.type !== "null");
  if (branch) return sampleFor(key, branch);
  const type = Array.isArray(s.type) ? s.type.find((t) => t !== "null") : s.type;
  switch (type) {
    case "string":
      return sampleString(key, s);
    case "integer":
    case "number": {
      const min = s.minimum ?? (s.exclusiveMinimum !== undefined ? s.exclusiveMinimum + 1 : 1);
      return Math.min(Math.max(min, 1), s.maximum ?? Number.MAX_SAFE_INTEGER);
    }
    case "boolean":
      // false is the conservative choice for flags like `force` or `confirm`.
      return false;
    case "array":
      return Array.from({ length: Math.max(s.minItems ?? 1, 1) }, () => sampleFor(key, s.items));
    case "object":
      return Object.fromEntries(Object.entries(s.properties ?? {}).map(([k, v]) => [k, sampleFor(k, v)]));
    default:
      return "example";
  }
}

/**
 * Build an input for a tool from its schema, filling every field, optional ones
 * included. Used by the conformance suite to call `confirm()` and read tools
 * without hand-written fixtures per tool. When the sample satisfies the schema,
 * the parsed value (defaults applied) is returned, matching what the MCP
 * handler passes a tool in production.
 */
export function sampleInput(schema: z.ZodTypeAny): unknown {
  const raw = sampleFor("", toolInputJsonSchema(schema) as JsonSchema);
  const parsed = schema.safeParse(raw);
  return parsed.success ? parsed.data : raw;
}
