import { describe, it, expect, beforeEach, afterEach } from "vitest";
import { mkdtemp, rm } from "node:fs/promises";
import { tmpdir } from "node:os";
import path from "node:path";
import { hashBearer, loadBearerHash, saveBearerHash } from "./bearer-hash.js";

// NOTE: AppState.verifyBearer's locked-path behavior is exercised in
// src/web/auth.test.ts; a full AppState integration here is impractical because
// paths.dataDir is frozen at import (shared store path across the suite).

describe("bearer hash module", () => {
  let dir: string;
  beforeEach(async () => {
    dir = await mkdtemp(path.join(tmpdir(), "sk-bh-"));
  });
  afterEach(async () => {
    await rm(dir, { recursive: true, force: true });
  });

  it("hashes deterministically and differs per token", () => {
    expect(hashBearer("abc")).toBe(hashBearer("abc"));
    expect(hashBearer("abc")).not.toBe(hashBearer("abd"));
    expect(hashBearer("abc")).toHaveLength(64); // sha256 hex
  });

  it("round-trips through save/load and is null before anything is written", async () => {
    const file = path.join(dir, "mcp-bearer.hash");
    expect(await loadBearerHash(file)).toBeNull();
    await saveBearerHash(hashBearer("tok"), file);
    expect(await loadBearerHash(file)).toBe(hashBearer("tok"));
  });
});
