import { describe, it, expect, vi, beforeEach } from "vitest";
import type { AppState } from "../app.js";
import type { Connector, Target, ToolContext } from "../connectors/types.js";
import { resolveTools, findTool } from "./tool-registry.js";

/**
 * A stand-in connector whose single tool records the ToolContext it was handed,
 * so we can assert exactly how the registry wires credential resolution.
 */
let captured: ToolContext | undefined;
const probeConnector: Connector = {
  type: "probe",
  label: "Probe",
  configSchema: { parse: (v: unknown) => v } as never,
  requiresCredential: true,
  buildTools: () => [
    {
      name: "probe",
      description: "probe",
      tier: "read",
      inputSchema: { parse: (v: unknown) => v } as never,
      run: async (_input, ctx) => {
        captured = ctx;
        return { text: "ok" };
      },
    },
  ],
};

vi.mock("../connectors/index.js", () => ({
  getConnector: (type: string) => (type === "probe" ? probeConnector : undefined),
}));

function appFor(targets: Target[]): { app: AppState; credentialFor: ReturnType<typeof vi.fn> } {
  const credentialFor = vi.fn(async (ref: string) => ({ ref, fields: {}, uris: [] }));
  const app = { registry: { list: () => targets }, credentialFor } as unknown as AppState;
  return { app, credentialFor };
}

const targetWithCred: Target = { name: "p1", type: "probe", host: "10.0.0.9", credentialRef: "p1-item" };

beforeEach(() => {
  captured = undefined;
});

describe("per-target tool context", () => {
  it("namespaces the tool and passes both credential resolvers", async () => {
    const { app, credentialFor } = appFor([targetWithCred]);
    const tool = findTool(app, "probe.p1.probe")!;
    expect(tool).toBeDefined();
    expect(tool.targetName).toBe("p1");
    await tool.invoke({});
    expect(captured!.target.name).toBe("p1");
    expect(typeof captured!.resolveCredential).toBe("function");

    // getCredential is unchanged: the target's own item.
    await captured!.getCredential();
    expect(credentialFor).toHaveBeenLastCalledWith("p1-item");

    // resolveCredential reaches ANY vault item by name, same lazy path.
    const other = await captured!.resolveCredential!("app-db");
    expect(credentialFor).toHaveBeenLastCalledWith("app-db");
    expect(other.ref).toBe("app-db");
  });

  it("resolves nothing until a tool asks (no credential read at list time)", () => {
    const { app, credentialFor } = appFor([targetWithCred]);
    resolveTools(app);
    expect(credentialFor).not.toHaveBeenCalled();
  });

  it("still errors on getCredential for a target with no credentialRef, but can resolve other items", async () => {
    const { app, credentialFor } = appFor([{ name: "p2", type: "probe", host: "10.0.0.8" }]);
    await findTool(app, "probe.p2.probe")!.invoke({});
    await expect(captured!.getCredential()).rejects.toThrow(/no credentialRef/);
    await captured!.resolveCredential!("shared-item");
    expect(credentialFor).toHaveBeenCalledWith("shared-item");
  });

  it("skips targets whose connector type is unknown", () => {
    const { app } = appFor([{ name: "x", type: "nonexistent", host: "10.0.0.7" }]);
    expect(resolveTools(app).some((t) => t.targetName === "x")).toBe(false);
  });
});
