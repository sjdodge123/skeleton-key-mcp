import { describe, it, expect } from "vitest";
import { registerableType, getConnector } from "./index.js";

describe("registerableType", () => {
  it("routes a fingerprint-confirmed detection to its bespoke connector", () => {
    expect(registerableType("portainer", 9000, "confirmed")).toBe("portainer");
    expect(registerableType("ssh", 22, "confirmed")).toBe("ssh");
    // Home Assistant now has a bespoke connector, so a confirmed :8123 detection
    // registers as it rather than falling back to the generic http connector.
    expect(registerableType("home-assistant", 8123, "confirmed")).toBe("home-assistant");
    expect(registerableType("proxmox", 8006, "confirmed")).toBe("proxmox");
  });

  it("downgrades a port-only guess to the generic connector (no broken portainer target)", () => {
    // Any HTTPS-on-9443 only *hints* Portainer — don't suggest registering it as one.
    expect(registerableType("portainer", 9443, "likely")).toBe("http");
    expect(registerableType("portainer", 9443, "open")).toBe("http");
  });

  it("falls back for types with no bespoke connector regardless of confidence", () => {
    expect(registerableType("synology", 5000, "confirmed")).toBe("http");
    expect(registerableType("synology", 22, "confirmed")).toBe("ssh"); // port-22 fallback branch
  });

  it("treats missing confidence as unconfirmed (falls back)", () => {
    expect(registerableType("portainer", 9000)).toBe("http");
    expect(registerableType("ssh", 22)).toBe("ssh"); // port-22 fallback still applies
  });

  it("portainer is a registered connector", () => {
    expect(getConnector("portainer")?.type).toBe("portainer");
  });

  it("home-assistant is a registered connector, reachable by its no-hyphen alias too", () => {
    expect(getConnector("home-assistant")?.type).toBe("home-assistant");
    expect(getConnector("homeassistant")?.type).toBe("home-assistant");
  });

  it("proxmox is a registered connector", () => {
    expect(getConnector("proxmox")?.type).toBe("proxmox");
  });
});
