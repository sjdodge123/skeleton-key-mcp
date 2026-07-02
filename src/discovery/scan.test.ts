import { describe, it, expect } from "vitest";
import { isPrivateSubnet } from "./scan.js";

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
    expect(isPrivateSubnet("192.169.0")).toBe(false); // not 168
    expect(isPrivateSubnet("172.15.0")).toBe(false); // below 16
    expect(isPrivateSubnet("172.32.0")).toBe(false); // above 31
    expect(isPrivateSubnet("1.2.3")).toBe(false);
  });

  it("rejects malformed input", () => {
    expect(isPrivateSubnet("192.168")).toBe(false); // only 2 octets
    expect(isPrivateSubnet("192.168.0.1")).toBe(false); // full IP, not a /24 prefix
    expect(isPrivateSubnet("192.168.abc")).toBe(false);
    expect(isPrivateSubnet("")).toBe(false);
    expect(isPrivateSubnet("192.168.300")).toBe(false); // octet > 255
  });
});
