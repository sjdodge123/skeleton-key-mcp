import { describe, it, expect } from "vitest";
import { isPrivateSubnet, matchHttp } from "./scan.js";

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
});
