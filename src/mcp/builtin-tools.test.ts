import { describe, it, expect } from "vitest";
import type { AppState } from "../app.js";
import { buildGlobalTools } from "./builtin-tools.js";

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
});
