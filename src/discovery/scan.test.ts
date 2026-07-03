import { describe, it, expect } from "vitest";
import http from "node:http";
import type { AddressInfo } from "node:net";
import { isPrivateSubnet, matchHttp, httpProbe } from "./scan.js";

describe("httpProbe body cap (must not hang)", () => {
  it("resolves with a bounded body when a large multi-chunk body is streamed", async () => {
    // Server that streams >8KB across many chunks and never ends promptly — the
    // pre-fix code destroyed the request past the cap without resolving, hanging.
    const server = http.createServer((_req, res) => {
      res.writeHead(200, { "content-type": "text/html" });
      const chunk = "<div>proxmox filler</div>".repeat(50); // ~1.25KB
      let sent = 0;
      const timer = setInterval(() => {
        res.write(chunk);
        if (++sent > 100) {
          clearInterval(timer);
        }
      }, 5);
    });
    await new Promise<void>((r) => server.listen(0, "127.0.0.1", r));
    const port = (server.address() as AddressInfo).port;
    try {
      const res = await httpProbe("127.0.0.1", port, false, 3000);
      expect(res).not.toBeNull();
      expect(res!.body.length).toBeLessThanOrEqual(8192);
      expect(res!.body).toContain("proxmox");
    } finally {
      server.close();
    }
  });

  it("resolves null when nothing is listening (no hang)", async () => {
    // Port 1 is virtually never open; connection refused should resolve null fast.
    const res = await httpProbe("127.0.0.1", 1, false, 800);
    expect(res).toBeNull();
  });
});

describe("isPrivateSubnet", () => {
  it("accepts RFC1918 /24 prefixes", () => {
    expect(isPrivateSubnet("192.168.0")).toBe(true);
    expect(isPrivateSubnet("192.168.1")).toBe(true);
    expect(isPrivateSubnet("10.0.1")).toBe(true);
    expect(isPrivateSubnet("172.16.5")).toBe(true);
    expect(isPrivateSubnet("172.31.200")).toBe(true);
  });

  it("rejects public and out-of-range prefixes", () => {
    expect(isPrivateSubnet("8.8.8")).toBe(false);
    expect(isPrivateSubnet("192.169.0")).toBe(false);
    expect(isPrivateSubnet("172.15.0")).toBe(false);
    expect(isPrivateSubnet("172.32.0")).toBe(false);
    expect(isPrivateSubnet("1.2.3")).toBe(false);
  });

  it("rejects malformed input", () => {
    expect(isPrivateSubnet("192.168")).toBe(false);
    expect(isPrivateSubnet("192.168.0.1")).toBe(false);
    expect(isPrivateSubnet("192.168.abc")).toBe(false);
    expect(isPrivateSubnet("")).toBe(false);
    expect(isPrivateSubnet("192.168.300")).toBe(false);
  });
});

describe("matchHttp (service fingerprinting)", () => {
  it("identifies services from body content", () => {
    expect(matchHttp({}, "<title>Proxmox Virtual Environment</title>")?.type).toBe("proxmox");
    expect(matchHttp({}, "<title>Home Assistant</title>")?.type).toBe("home-assistant");
    expect(matchHttp({}, "loading portainer...")?.type).toBe("portainer");
    expect(matchHttp({}, "Synology DiskStation login")?.type).toBe("synology");
    expect(matchHttp({}, "<title>UniFi Network</title>")?.type).toBe("unifi");
    expect(matchHttp({}, "Pi-hole Admin Console")?.type).toBe("pihole");
  });

  it("identifies services from headers", () => {
    expect(matchHttp({ "x-powered-by": "Portainer" }, "")?.type).toBe("portainer");
    expect(matchHttp({ server: "Pi-hole" }, "")?.type).toBe("pihole");
  });

  it("returns null for a generic web server (no false positive)", () => {
    expect(matchHttp({ server: "nginx" }, "<title>Welcome to nginx</title>")).toBeNull();
    expect(matchHttp({ server: "Apache" }, "<html><body>It works!</body></html>")).toBeNull();
    // A plain login page that names none of the known products stays unidentified.
    expect(matchHttp({}, "<title>Sign in</title>")).toBeNull();
  });

  it("does not match the short unanchored 'ubnt' substring", () => {
    expect(matchHttp({}, "customwords ubntx and things")).toBeNull();
  });

  it("ignores the redirect Location header (avoids false positives)", () => {
    // A redirect target path containing a product name must NOT trigger a match.
    expect(matchHttp({ location: "https://host/plex/web" }, "<title>Redirecting</title>")).toBeNull();
    expect(matchHttp({ location: "/unifi/manage" }, "generic body")).toBeNull();
  });
});
