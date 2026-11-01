import { describe, it, expect } from "vitest";
import { generateSshKey } from "./ssh-keygen.js";

// Requires ssh-keygen on PATH (present on CI runners, macOS, and the image).
describe("generateSshKey", () => {
  it("produces an OpenSSH ed25519 keypair and fingerprint", async () => {
    const key = await generateSshKey("test-comment");
    expect(key.publicKey).toMatch(/^ssh-ed25519 AAAA[\w+/=]+ test-comment$/);
    expect(key.privateKey).toContain("OPENSSH PRIVATE KEY");
    expect(key.fingerprint).toMatch(/^SHA256:/);
  });

  it("supports an encrypted private key", async () => {
    const key = await generateSshKey("enc", "s3cret-pass");
    expect(key.privateKey).toContain("OPENSSH PRIVATE KEY");
    expect(key.publicKey.startsWith("ssh-ed25519 ")).toBe(true);
  });
});
