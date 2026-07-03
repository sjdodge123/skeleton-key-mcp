import { describe, it, expect, beforeEach, afterEach, vi } from "vitest";
import { mkdtemp, rm } from "node:fs/promises";
import { tmpdir } from "node:os";
import path from "node:path";
import { detectLanBaseUrl, loadPublicUrl, savePublicUrl } from "./public-url.js";

type Ifaces = ReturnType<typeof import("node:os").networkInterfaces>;

// Minimal fake of os.networkInterfaces() output.
function ifaces(spec: Record<string, { address: string; family?: string; internal?: boolean }[]>): Ifaces {
  const out: any = {};
  for (const [name, addrs] of Object.entries(spec)) {
    out[name] = addrs.map((a) => ({ address: a.address, family: a.family ?? "IPv4", internal: a.internal ?? false, netmask: "", mac: "", cidr: null }));
  }
  return out as Ifaces;
}

describe("detectLanBaseUrl", () => {
  it("returns the private LAN IPv4 with the given port", () => {
    const url = detectLanBaseUrl(8787, ifaces({ eth0: [{ address: "192.168.0.42" }] }));
    expect(url).toBe("http://192.168.0.42:8787");
  });

  it("ignores loopback and public addresses", () => {
    const url = detectLanBaseUrl(8787, ifaces({
      lo: [{ address: "127.0.0.1", internal: true }],
      eth0: [{ address: "8.8.8.8" }],
    }));
    expect(url).toBeNull();
  });

  it("prefers a 192.168 address over 10.x and 172.16", () => {
    const url = detectLanBaseUrl(8080, ifaces({
      a: [{ address: "10.1.2.3" }],
      b: [{ address: "192.168.5.5" }],
      c: [{ address: "172.16.0.9" }],
    }));
    expect(url).toBe("http://192.168.5.5:8080");
  });

  it("returns null when only Docker-internal / no private IPv4 exists", () => {
    expect(detectLanBaseUrl(8787, ifaces({ lo: [{ address: "::1", family: "IPv6", internal: true }] }))).toBeNull();
  });
});

describe("persisted public URL", () => {
  let dir: string;
  beforeEach(async () => {
    dir = await mkdtemp(path.join(tmpdir(), "sk-url-"));
  });
  afterEach(async () => {
    await rm(dir, { recursive: true, force: true });
  });

  it("round-trips through save/load and returns null before anything is written", async () => {
    const file = path.join(dir, "public-url");
    expect(await loadPublicUrl(file)).toBeNull();
    await savePublicUrl("http://192.168.0.9:8787", file);
    expect(await loadPublicUrl(file)).toBe("http://192.168.0.9:8787");
  });
});

describe("AppState.publicUrl priority", () => {
  let dir: string;
  beforeEach(async () => {
    dir = await mkdtemp(path.join(tmpdir(), "sk-url-app-"));
    process.env.SKELETON_KEY_DATA_DIR = dir;
    vi.stubEnv("SKELETON_KEY_PUBLIC_URL", "");
  });
  afterEach(async () => {
    vi.unstubAllEnvs();
    await rm(dir, { recursive: true, force: true });
  });

  it("uses the persisted value, and lets the env var override it (trailing slash trimmed)", async () => {
    const { AppState } = await import("../app.js");
    const app = await AppState.create();
    try {
      app.setLearnedPublicUrl("http://192.168.0.9:8787");
      expect(app.publicUrl()).toBe("http://192.168.0.9:8787");
      vi.stubEnv("SKELETON_KEY_PUBLIC_URL", "https://sk.lan:8787/");
      expect(app.publicUrl()).toBe("https://sk.lan:8787");
    } finally {
      app.audit.close();
      app.oauth.close();
    }
  });
});
