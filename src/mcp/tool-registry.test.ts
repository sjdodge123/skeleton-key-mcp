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

/**
 * A fake AppState over a mutable target list. `credentialFor` resolves any ref
 * (optionally failing for ids listed in `goneIds`, as a deleted item would);
 * `vault.resolveRef` maps names → ids via `idsByName`; `registry.upsert`
 * records re-pins.
 */
function appFor(
  targets: Target[],
  opts: { goneIds?: string[]; idsByName?: Record<string, string>; locked?: boolean } = {},
): { app: AppState; credentialFor: ReturnType<typeof vi.fn>; upsert: ReturnType<typeof vi.fn>; resolveRef: ReturnType<typeof vi.fn> } {
  const credentialFor = vi.fn(async (ref: string, o?: { byId?: boolean; fresh?: boolean }) => {
    if (o?.byId && opts.goneIds?.includes(ref)) throw new Error(`No vault item with id "${ref}"`);
    return { ref, fields: {}, uris: [], username: o?.byId ? `by-id:${ref}` : `by-name:${ref}` };
  });
  const upsert = vi.fn(async (t: Target) => {
    const i = targets.findIndex((x) => x.name === t.name);
    if (i >= 0) targets[i] = t;
    else targets.push(t);
  });
  const resolveRef = vi.fn(async (name: string) => {
    const id = opts.idsByName?.[name];
    if (!id) throw new Error(`No vault item named "${name}"`);
    return { id, name };
  });
  const app = {
    registry: { list: () => targets, get: (n: string) => targets.find((t) => t.name === n), upsert },
    vault: { resolveRef },
    locked: opts.locked ?? false,
    credentialFor,
  } as unknown as AppState;
  return { app, credentialFor, upsert, resolveRef };
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

    // resolveCredential reaches ANY vault item by name, same lazy path, and
    // forwards the `fresh` option for deploy-time reads.
    const other = await captured!.resolveCredential!("app-db");
    expect(credentialFor).toHaveBeenLastCalledWith("app-db", undefined);
    expect(other.ref).toBe("app-db");
    await captured!.resolveCredential!("app-db", { fresh: true });
    expect(credentialFor).toHaveBeenLastCalledWith("app-db", { fresh: true });
    expect(typeof captured!.fingerprint).toBe("function");
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
    expect(credentialFor).toHaveBeenCalledWith("shared-item", undefined);
  });

  it("skips targets whose connector type is unknown", () => {
    const { app } = appFor([{ name: "x", type: "nonexistent", host: "10.0.0.7" }]);
    expect(resolveTools(app).some((t) => t.targetName === "x")).toBe(false);
  });
});

describe("credentialId pinning in getCredential", () => {
  const ID = "11111111-2222-3333-4444-555555555555";
  const NEW_ID = "22222222-2222-3333-4444-555555555555";
  const pinned: Target = { name: "p1", type: "probe", host: "10.0.0.9", credentialRef: "p1-item", credentialId: ID };

  it("reads by the pinned id, not the name — and reports the human-facing ref", async () => {
    const { app, credentialFor, upsert } = appFor([{ ...pinned }], { idsByName: { "p1-item": ID } });
    await findTool(app, "probe.p1.probe")!.invoke({});
    const cred = await captured!.getCredential();
    expect(credentialFor).toHaveBeenCalledTimes(1);
    expect(credentialFor).toHaveBeenCalledWith(ID, { byId: true });
    expect(cred.username).toBe(`by-id:${ID}`);
    expect(cred.ref).toBe("p1-item"); // never a bare UUID
    expect(upsert).not.toHaveBeenCalled(); // pin still valid → no registry write
  });

  it("falls back to the name when the pinned item is gone, and re-pins the new id", async () => {
    const targets = [{ ...pinned }];
    const { app, credentialFor, upsert } = appFor(targets, { goneIds: [ID], idsByName: { "p1-item": NEW_ID } });
    await findTool(app, "probe.p1.probe")!.invoke({});
    const cred = await captured!.getCredential();
    expect(cred.username).toBe("by-name:p1-item");
    expect(credentialFor).toHaveBeenNthCalledWith(1, ID, { byId: true });
    expect(credentialFor).toHaveBeenNthCalledWith(2, "p1-item");
    expect(upsert).toHaveBeenCalledTimes(1);
    expect(targets[0]!.credentialId).toBe(NEW_ID);
    expect(targets[0]!.credentialRef).toBe("p1-item");
  });

  it("pins lazily for a legacy target with no credentialId", async () => {
    const targets: Target[] = [{ ...targetWithCred }];
    const { app, upsert } = appFor(targets, { idsByName: { "p1-item": ID } });
    await findTool(app, "probe.p1.probe")!.invoke({});
    await captured!.getCredential();
    expect(upsert).toHaveBeenCalledTimes(1);
    expect(targets[0]!.credentialId).toBe(ID);
  });

  it("re-pin is best-effort: the credential is still returned if the vault can't resolve the name", async () => {
    const { app, upsert } = appFor([{ ...targetWithCred }], { idsByName: {} });
    await findTool(app, "probe.p1.probe")!.invoke({});
    const cred = await captured!.getCredential();
    expect(cred.username).toBe("by-name:p1-item");
    expect(upsert).not.toHaveBeenCalled();
  });

  it("surfaces a locked-vault error instead of retrying by name", async () => {
    const { app, credentialFor } = appFor([{ ...pinned }], { goneIds: [ID], locked: true });
    await findTool(app, "probe.p1.probe")!.invoke({});
    await expect(captured!.getCredential()).rejects.toThrow();
    expect(credentialFor).toHaveBeenCalledTimes(1);
  });
});
