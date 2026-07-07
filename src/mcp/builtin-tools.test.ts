import { describe, it, expect, vi } from "vitest";
import type { AppState } from "../app.js";
import { buildGlobalTools } from "./builtin-tools.js";
import { scanLan } from "../discovery/scan.js";

vi.mock("../discovery/scan.js", () => ({ scanLan: vi.fn() }));

// buildGlobalTools only touches `app` inside each tool's run() closure, so we can
// enumerate the declared tools (names/tiers/flags) without a real AppState.
const tools = buildGlobalTools({} as AppState);
const byName = new Map(tools.map((t) => [t.name, t]));

describe("global tool registry", () => {
  it("registers the credential-lifecycle tools", () => {
    for (const name of ["update_target", "vault_delete_credential", "request_credential", "credential_request_status"]) {
      expect(byName.has(name)).toBe(true);
    }
  });

  it("marks state-changing tools as execute and read-only ones as read", () => {
    expect(byName.get("request_credential")!.tier).toBe("execute");
    expect(byName.get("update_target")!.tier).toBe("execute");
    expect(byName.get("vault_delete_credential")!.tier).toBe("execute");
    expect(byName.get("credential_request_status")!.tier).toBe("read");
  });

  it("only exposes get_started while the vault is locked", () => {
    const lockedTools = tools.filter((t) => t.availableWhenLocked).map((t) => t.name);
    expect(lockedTools).toEqual(["get_started"]);
  });

  it("registers form_skeleton as an execute tool with a confirm, not available while locked", () => {
    const t = byName.get("form_skeleton")!;
    expect(t).toBeDefined();
    expect(t.tier).toBe("execute");
    expect(typeof t.confirm).toBe("function");
    expect(t.availableWhenLocked).toBeFalsy();
  });
});

describe("network_scan gateway-first recommendation", () => {
  const scan = byName.get("network_scan")!;

  it("recommends registering a confirmed gateway first (it names the other devices)", async () => {
    vi.mocked(scanLan).mockResolvedValue([
      { host: "192.168.0.1", port: 443, connectorType: "unifi", label: "UniFi", confidence: "confirmed" },
      { host: "192.168.0.50", port: 22, connectorType: "ssh", label: "SSH host", confidence: "confirmed" },
    ] as Awaited<ReturnType<typeof scanLan>>);
    const out = (await scan.run({}, {} as AppState)).text;
    expect(out).toContain("Recommended first target");
    expect(out).toContain("192.168.0.1");
  });

  it("stays quiet when no gateway is confidently detected", async () => {
    vi.mocked(scanLan).mockResolvedValue([
      { host: "192.168.0.50", port: 22, connectorType: "ssh", label: "SSH host", confidence: "confirmed" },
      { host: "192.168.0.7", port: 8443, connectorType: "unifi", label: "UniFi", confidence: "likely" },
    ] as Awaited<ReturnType<typeof scanLan>>);
    const out = (await scan.run({}, {} as AppState)).text;
    expect(out).not.toContain("Recommended first target");
  });
});
