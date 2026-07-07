import { describe, it, expect, beforeEach, afterEach } from "vitest";
import { mkdtemp, rm, readFile, writeFile, stat } from "node:fs/promises";
import { tmpdir } from "node:os";
import path from "node:path";
import { Writable } from "node:stream";
import { gunzipSync } from "node:zlib";
import { z } from "zod";
import { BootstrapStore } from "../secrets/bootstrap-store.js";
import { registerConnector } from "../connectors/index.js";
import type { AppState } from "../app.js";
import type { Connector, Target } from "../connectors/types.js";
import { formSkeleton, listSkeletons, streamSkeletonTar } from "./snapshot-service.js";

const SECRET = "SUPERSECRET-TOKEN-abc123";

const mk = (over: Partial<Connector> & Pick<Connector, "type">): Connector => ({
  label: "t",
  configSchema: z.object({}),
  requiresCredential: false,
  buildTools: () => [],
  ...over,
});

registerConnector(mk({
  type: "snaptest-ok",
  snapshot: async () => [
    { name: "config.json", data: Buffer.from('{"ok":true}'), note: "cfg" },
    { name: "backup.bin", data: Buffer.from(SECRET), note: "contains a secret" },
  ],
}));
registerConnector(mk({ type: "snaptest-fail", snapshot: async () => { throw new Error("unreachable host"); } }));
registerConnector(mk({ type: "snaptest-none" })); // no snapshot → skipped

let dir: string;
let snapDir: string;
let auditLog: any[];
let app: AppState;

const targets: Target[] = [
  { name: "okhost", type: "snaptest-ok", host: "h", credentialRef: "c1" },
  { name: "failhost", type: "snaptest-fail", host: "h", credentialRef: "c2" },
  { name: "nohost", type: "snaptest-none", host: "h", credentialRef: "c3" },
];

beforeEach(async () => {
  dir = await mkdtemp(path.join(tmpdir(), "skmcp-snap-svc-"));
  snapDir = path.join(dir, "skeletons");
  auditLog = [];
  const store = await BootstrapStore.open(path.join(dir, "bootstrap.store"));
  await store.initialize("correct horse battery staple");
  app = {
    store,
    registry: { list: () => targets },
    credentialFor: async (ref: string) => ({ ref, fields: {}, uris: [] }),
    audit: { record: (e: any) => auditLog.push(e) },
  } as unknown as AppState;
});
afterEach(async () => {
  await rm(dir, { recursive: true, force: true });
});

function collector(): { stream: Writable; done: Promise<Buffer> } {
  const chunks: Buffer[] = [];
  let resolve!: (b: Buffer) => void;
  let reject!: (e: unknown) => void;
  const done = new Promise<Buffer>((res, rej) => { resolve = res; reject = rej; });
  const stream = new Writable({
    write(chunk, _enc, cb) { chunks.push(Buffer.from(chunk)); cb(); },
    final(cb) { cb(); resolve(Buffer.concat(chunks)); },
  });
  stream.on("error", reject);
  return { stream, done };
}

describe("formSkeleton", () => {
  it("writes a partial skeleton: ok / error / skipped per target, with per-target audit", async () => {
    const { id } = await formSkeleton(app, snapDir);
    const manifest = JSON.parse(await readFile(path.join(snapDir, id, "manifest.json"), "utf8"));

    const byName = Object.fromEntries(manifest.targets.map((t: any) => [t.name, t]));
    expect(byName.okhost.status).toBe("ok");
    expect(byName.okhost.artifacts).toHaveLength(2);
    expect(byName.failhost.status).toBe("error");
    expect(byName.failhost.error).toMatch(/unreachable host/);
    expect(byName.nohost.status).toBe("skipped");

    // per-target audit rows
    expect(auditLog.filter((e) => e.tool === "form_skeleton").map((e) => [e.target, e.status])).toEqual(
      expect.arrayContaining([["okhost", "ok"], ["failhost", "error"]]),
    );

    // encrypted artifacts on disk, 0600, and NOT the plaintext
    const encPath = path.join(snapDir, id, "okhost", "backup.bin.enc");
    expect((await stat(encPath)).mode & 0o777).toBe(0o600);
    const enc = await readFile(encPath);
    expect(enc.includes(SECRET)).toBe(false);

    // RESTORE.md written; snapshotKey persisted
    expect((await readFile(path.join(snapDir, id, "RESTORE.md"), "utf8")).length).toBeGreaterThan(0);
    expect(typeof app.store.get().snapshotKey).toBe("string");
  });

  it("never leaks artifact bytes into the manifest or the returned summary", async () => {
    const { id, summary } = await formSkeleton(app, snapDir);
    const manifestRaw = await readFile(path.join(snapDir, id, "manifest.json"), "utf8");
    expect(manifestRaw.includes(SECRET)).toBe(false);
    expect(summary.includes(SECRET)).toBe(false);
    // manifest records only names/hashes/sizes/notes.
    const art = JSON.parse(manifestRaw).targets.find((t: any) => t.name === "okhost").artifacts[0];
    expect(art).toMatchObject({ name: "config.json", file: "okhost/config.json.enc" });
    expect(art.sha256).toMatch(/^[0-9a-f]{64}$/);
  });
});

describe("listSkeletons + streamSkeletonTar", () => {
  it("lists metadata only and streams a decryptable .tar.gz round-trip", async () => {
    const { id } = await formSkeleton(app, snapDir);

    const list = await listSkeletons(snapDir);
    expect(list).toHaveLength(1);
    expect(list[0]!.id).toBe(id);
    expect(JSON.stringify(list[0]).includes(SECRET)).toBe(false);

    const { stream, done } = collector();
    await streamSkeletonTar(app, id, stream, snapDir);
    const tar = gunzipSync(await done);
    // The decrypted secret + the metadata files are present in the archive.
    expect(tar.includes(SECRET)).toBe(true);
    expect(tar.includes("manifest.json")).toBe(true);
    expect(tar.includes("RESTORE.md")).toBe(true);
    expect(tar.includes("okhost/backup.bin")).toBe(true);
  });

  it("throws if an encrypted artifact was tampered with (integrity/auth)", async () => {
    const { id } = await formSkeleton(app, snapDir);
    const encPath = path.join(snapDir, id, "okhost", "config.json.enc");
    const enc = await readFile(encPath);
    enc[enc.length - 1] ^= 0x01;
    await writeFile(encPath, enc);
    const { stream } = collector();
    await expect(streamSkeletonTar(app, id, stream, snapDir)).rejects.toThrow();
  });

  it("rejects a path-traversal id", async () => {
    const { stream } = collector();
    await expect(streamSkeletonTar(app, "../etc", stream, snapDir)).rejects.toThrow(/invalid skeleton id/);
  });

  it("throws for an unknown id (missing manifest)", async () => {
    const { stream } = collector();
    await expect(streamSkeletonTar(app, "nope-does-not-exist", stream, snapDir)).rejects.toThrow();
  });
});
