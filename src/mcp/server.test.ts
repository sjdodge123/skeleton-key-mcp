import { describe, it, expect } from "vitest";
import { z } from "zod";
import type { AppState } from "../app.js";
import { listConnectors } from "../connectors/index.js";
import { buildGlobalTools } from "./builtin-tools.js";
import { toolInputJsonSchema } from "./server.js";

/** Every advertised input schema: the global tools plus one target per connector type. */
function allToolSchemas(): [string, z.ZodType][] {
  const out: [string, z.ZodType][] = buildGlobalTools({} as AppState).map((g) => [g.name, g.inputSchema]);
  for (const c of new Set(listConnectors())) {
    const target = { name: "t", type: c.type, host: "192.168.1.10", options: {} };
    for (const t of c.buildTools(target)) out.push([`${c.type}.${t.name}`, t.inputSchema]);
  }
  return out;
}

describe("toolInputJsonSchema", () => {
  it("gives every tool a closed object schema with its real properties", () => {
    // zod-to-json-schema silently emitted `{ $schema }` alone for zod 4 schemas,
    // which would have advertised every tool as taking anything.
    const tools = allToolSchemas();
    expect(tools.length).toBeGreaterThan(50);
    for (const [name, schema] of tools) {
      const js = toolInputJsonSchema(schema) as Record<string, unknown>;
      expect(js.type, name).toBe("object");
      expect(js.properties, name).toBeTypeOf("object");
      expect(js.additionalProperties, name).toBe(false);
    }
  });

  it("keeps a field with a default optional (input view, not output)", () => {
    const js = toolInputJsonSchema(z.object({ a: z.string(), n: z.number().default(5) })) as any;
    expect(js.required).toEqual(["a"]);
  });

  it("closes nested strip objects but leaves records and passthrough objects open", () => {
    const js = toolInputJsonSchema(
      z.object({
        inner: z.object({ k: z.string() }),
        rec: z.record(z.string(), z.string()),
        loose: z.object({ k: z.string() }).passthrough(),
      }),
    ) as any;
    expect(js.properties.inner.additionalProperties).toBe(false);
    expect(js.properties.rec.additionalProperties).toEqual({ type: "string" });
    expect(js.properties.loose.additionalProperties).toEqual({});
  });
});
