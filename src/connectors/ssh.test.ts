import { describe, it, expect, vi } from "vitest";

vi.mock("./ssh-exec.js", async () => {
  const actual = await vi.importActual<typeof import("./ssh-exec.js")>("./ssh-exec.js");
  return {
    ...actual,
    runSsh: vi.fn(),
    shellQuote: (s: string) => `'${s}'`,
  };
});

import { sshConnector } from "./ssh.js";
import { runSsh, MAX_SSH_TIMEOUT_MS } from "./ssh-exec.js";
import type { Target, ToolContext } from "./types.js";

const cred = { ref: "c", fields: {}, uris: [] };
const ctxFor = (t: Target): ToolContext => ({ target: t, getCredential: async () => cred });
const base: Target = { name: "host", type: "ssh", host: "h", credentialRef: "c" };

function toolNamed(target: Target, name: string) {
  const tool = sshConnector.buildTools(target).find((t) => t.name === name);
  if (!tool) throw new Error(`tool ${name} not found`);
  return tool;
}

describe("ssh commandTimeoutMs option", () => {
  it("accepts a per-target commandTimeoutMs within the max", () => {
    expect(() => sshConnector.configSchema.parse({ commandTimeoutMs: 120_000 })).not.toThrow();
  });

  it("rejects a commandTimeoutMs above the 10-minute max", () => {
    expect(() => sshConnector.configSchema.parse({ commandTimeoutMs: MAX_SSH_TIMEOUT_MS + 1 })).toThrow();
  });

  it("rejects a non-positive commandTimeoutMs", () => {
    expect(() => sshConnector.configSchema.parse({ commandTimeoutMs: 0 })).toThrow();
    expect(() => sshConnector.configSchema.parse({ commandTimeoutMs: -1 })).toThrow();
  });

  it("leaves commandTimeoutMs unset by default (today's ~20s behavior is preserved)", () => {
    expect(sshConnector.configSchema.parse({}).commandTimeoutMs).toBeUndefined();
  });
});

describe("ssh timeout precedence: per-call > per-target > default", () => {
  it("passes no timeoutMs to runSsh when neither per-call nor per-target is set (runSsh applies its own default)", async () => {
    vi.mocked(runSsh).mockResolvedValue({ stdout: "ok", stderr: "", code: 0 });
    const tool = toolNamed(base, "run_command");
    await tool.run({ command: "echo hi" }, ctxFor(base));
    expect(runSsh).toHaveBeenCalledWith(base, cred, "echo hi", { timeoutMs: undefined });
  });

  it("uses the target's commandTimeoutMs when no per-call override is given", async () => {
    vi.mocked(runSsh).mockResolvedValue({ stdout: "ok", stderr: "", code: 0 });
    const t: Target = { ...base, options: { commandTimeoutMs: 90_000 } };
    const tool = toolNamed(t, "run_command");
    await tool.run({ command: "echo hi" }, ctxFor(t));
    expect(runSsh).toHaveBeenCalledWith(t, cred, "echo hi", { timeoutMs: 90_000 });
  });

  it("a per-call timeoutSeconds overrides the target's commandTimeoutMs", async () => {
    vi.mocked(runSsh).mockResolvedValue({ stdout: "ok", stderr: "", code: 0 });
    const t: Target = { ...base, options: { commandTimeoutMs: 90_000 } };
    const tool = toolNamed(t, "run_command");
    await tool.run({ command: "echo hi", timeoutSeconds: 300 }, ctxFor(t));
    expect(runSsh).toHaveBeenCalledWith(t, cred, "echo hi", { timeoutMs: 300_000 });
  });

  it("a per-call timeoutSeconds overrides the default even with no per-target option", async () => {
    vi.mocked(runSsh).mockResolvedValue({ stdout: "ok", stderr: "", code: 0 });
    const tool = toolNamed(base, "run_command");
    await tool.run({ command: "echo hi", timeoutSeconds: 45 }, ctxFor(base));
    expect(runSsh).toHaveBeenCalledWith(base, cred, "echo hi", { timeoutMs: 45_000 });
  });

  it("rejects a per-call timeoutSeconds above the 600s cap", () => {
    const tool = toolNamed(base, "run_command");
    expect(() => tool.inputSchema.parse({ command: "echo hi", timeoutSeconds: 601 })).toThrow();
  });

  it("read tools (e.g. tail_log) honor the target's commandTimeoutMs (no per-call override exists for them)", async () => {
    vi.mocked(runSsh).mockResolvedValue({ stdout: "log body", stderr: "", code: 0 });
    const t: Target = { ...base, options: { commandTimeoutMs: 60_000 } };
    const tool = toolNamed(t, "tail_log");
    await tool.run({ path: "/var/log/x.log", lines: 10 }, ctxFor(t));
    expect(runSsh).toHaveBeenCalledWith(t, cred, expect.any(String), { timeoutMs: 60_000 });
  });

  it("read tools fall back to runSsh's default when no per-target option is set", async () => {
    vi.mocked(runSsh).mockResolvedValue({ stdout: "log body", stderr: "", code: 0 });
    const tool = toolNamed(base, "tail_log");
    await tool.run({ path: "/var/log/x.log", lines: 10 }, ctxFor(base));
    expect(runSsh).toHaveBeenCalledWith(base, cred, expect.any(String), { timeoutMs: undefined });
  });
});
