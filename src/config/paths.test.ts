import { describe, it, expect, beforeEach, afterEach, vi } from "vitest";
import { mkdtemp, rm, writeFile } from "node:fs/promises";
import { tmpdir } from "node:os";
import path from "node:path";
import { resolveUnlockPassphrase } from "./paths.js";

describe("resolveUnlockPassphrase", () => {
  let dir: string;
  let errorSpy: ReturnType<typeof vi.spyOn>;

  beforeEach(async () => {
    dir = await mkdtemp(path.join(tmpdir(), "sk-passphrase-"));
    errorSpy = vi.spyOn(console, "error").mockImplementation(() => {});
  });
  afterEach(async () => {
    vi.unstubAllEnvs();
    errorSpy.mockRestore();
    await rm(dir, { recursive: true, force: true });
  });

  async function passphraseFile(contents: string): Promise<string> {
    const file = path.join(dir, "passphrase");
    await writeFile(file, contents, "utf8");
    return file;
  }

  it("reads the passphrase from SKELETON_KEY_PASSPHRASE_FILE", async () => {
    vi.stubEnv("SKELETON_KEY_PASSPHRASE_FILE", await passphraseFile("s3cret"));
    expect(resolveUnlockPassphrase()).toBe("s3cret");
  });

  it("strips exactly one trailing newline (LF and CRLF), nothing more", async () => {
    vi.stubEnv("SKELETON_KEY_PASSPHRASE_FILE", await passphraseFile("s3cret\n"));
    expect(resolveUnlockPassphrase()).toBe("s3cret");

    vi.stubEnv("SKELETON_KEY_PASSPHRASE_FILE", await passphraseFile("s3cret\r\n"));
    expect(resolveUnlockPassphrase()).toBe("s3cret");

    // Only the final newline goes; inner ones and a second trailing one stay.
    vi.stubEnv("SKELETON_KEY_PASSPHRASE_FILE", await passphraseFile("s3cret\n\n"));
    expect(resolveUnlockPassphrase()).toBe("s3cret\n");
  });

  it("preserves meaningful leading/trailing spaces (no full trim)", async () => {
    vi.stubEnv("SKELETON_KEY_PASSPHRASE_FILE", await passphraseFile("  pass with spaces  \n"));
    expect(resolveUnlockPassphrase()).toBe("  pass with spaces  ");
  });

  it("prefers the file over an inline SKELETON_KEY_PASSPHRASE", async () => {
    vi.stubEnv("SKELETON_KEY_PASSPHRASE_FILE", await passphraseFile("from-file"));
    vi.stubEnv("SKELETON_KEY_PASSPHRASE", "from-env");
    expect(resolveUnlockPassphrase()).toBe("from-file");
  });

  it("falls back to SKELETON_KEY_PASSPHRASE when no file var is set", () => {
    vi.stubEnv("SKELETON_KEY_PASSPHRASE", "inline-secret");
    expect(resolveUnlockPassphrase()).toBe("inline-secret");
  });

  it("returns undefined when neither variable is set", () => {
    vi.stubEnv("SKELETON_KEY_PASSPHRASE_FILE", "");
    vi.stubEnv("SKELETON_KEY_PASSPHRASE", "");
    expect(resolveUnlockPassphrase()).toBeUndefined();
  });

  it("fails closed on an unreadable file: logs to stderr (path only, no secret) and returns undefined", async () => {
    const missing = path.join(dir, "does-not-exist");
    vi.stubEnv("SKELETON_KEY_PASSPHRASE_FILE", missing);
    vi.stubEnv("SKELETON_KEY_PASSPHRASE", "inline-secret");

    // Set-but-unreadable is a config error: do NOT silently use the inline var.
    expect(resolveUnlockPassphrase()).toBeUndefined();
    expect(errorSpy).toHaveBeenCalledOnce();
    const message = String(errorSpy.mock.calls[0]?.[0]);
    expect(message).toContain("SKELETON_KEY_PASSPHRASE_FILE");
    expect(message).toContain(missing);
    expect(message).not.toContain("inline-secret");
  });
});
