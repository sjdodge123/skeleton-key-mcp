import { describe, it, expect, vi } from "vitest";

vi.mock("./ssh-exec.js", () => ({
  runSsh: vi.fn(),
  shellQuote: (s: string) => `'${s}'`,
}));

import { sshConnector } from "./ssh.js";
import { runSsh } from "./ssh-exec.js";
import type { Target, ToolContext } from "./types.js";

const cred = { ref: "c", fields: {}, uris: [] };
const ctxFor = (t: Target): ToolContext => ({ target: t, getCredential: async () => cred });
const base: Target = { name: "host", type: "ssh", host: "h", credentialRef: "c" };

describe("ssh snapshot", () => {
  it("captures a default read-only system profile (host is not Pi-hole)", async () => {
    vi.mocked(runSsh).mockImplementation(async (_t, _c, cmd: string) => {
      if (cmd.includes("command -v pihole")) return { stdout: "", stderr: "", code: 1 };
      return { stdout: `out: ${cmd.slice(0, 12)}`, stderr: "", code: 0 };
    });
    const arts = await sshConnector.snapshot!(ctxFor(base));
    expect(arts.map((a) => a.name)).toEqual(expect.arrayContaining(["uname.txt", "os-release.txt", "packages.txt", "crontab.txt"]));
    expect(arts.some((a) => a.name.startsWith("teleporter"))).toBe(false);
  });

  it("captures the Pi-hole teleporter (base64-decoded) + setupVars when pihole is present", async () => {
    const tarball = Buffer.from("PIHOLE-TELEPORTER-BYTES\x00\x01\x02\xff");
    vi.mocked(runSsh).mockImplementation(async (_t, _c, cmd: string) => {
      if (cmd.includes("command -v pihole")) return { stdout: "/usr/local/bin/pihole\n", stderr: "", code: 0 };
      if (cmd.includes("pihole -a -t")) return { stdout: tarball.toString("base64"), stderr: "", code: 0 };
      if (cmd.includes("setupVars")) return { stdout: "WEBPASSWORD=deadbeef\n", stderr: "", code: 0 };
      return { stdout: "profile", stderr: "", code: 0 };
    });
    const arts = await sshConnector.snapshot!(ctxFor(base));
    const tele = arts.find((a) => a.name === "teleporter.tar.gz")!;
    expect(tele).toBeDefined();
    expect(tele.data.equals(tarball)).toBe(true); // exact binary round-trip through base64
    expect(arts.some((a) => a.name === "pihole-setupVars.conf")).toBe(true);
  });

  it("honors options.snapshotCommands when configured", async () => {
    vi.mocked(runSsh).mockImplementation(async (_t, _c, cmd: string) => {
      if (cmd.includes("command -v pihole")) return { stdout: "", stderr: "", code: 1 };
      return { stdout: `ran ${cmd}`, stderr: "", code: 0 };
    });
    const t: Target = { ...base, options: { snapshotCommands: ["cat /etc/a", "cat /etc/b"] } };
    const arts = await sshConnector.snapshot!(ctxFor(t));
    expect(arts.map((a) => a.name)).toEqual(["cmd-1.txt", "cmd-2.txt"]);
    expect(arts[0]!.data.toString()).toContain("cat /etc/a");
  });

  it("skips profile commands that produce no output (partial profile)", async () => {
    vi.mocked(runSsh).mockImplementation(async (_t, _c, cmd: string) => {
      if (cmd.includes("uname")) return { stdout: "Linux host", stderr: "", code: 0 };
      return { stdout: "", stderr: "", code: cmd.includes("pihole") ? 1 : 0 };
    });
    const arts = await sshConnector.snapshot!(ctxFor(base));
    expect(arts.map((a) => a.name)).toEqual(["uname.txt"]);
  });
});
