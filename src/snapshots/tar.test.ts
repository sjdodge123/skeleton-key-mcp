import { describe, it, expect } from "vitest";
import { createGzip, gunzipSync } from "node:zlib";
import { TarWriter } from "./tar.js";

async function buildTarGz(entries: { name: string; data: Buffer }[]): Promise<Buffer> {
  const gz = createGzip();
  const chunks: Buffer[] = [];
  gz.on("data", (c: Buffer) => chunks.push(c));
  const done = new Promise<void>((resolve) => gz.on("end", resolve));
  const tar = new TarWriter(gz);
  for (const e of entries) tar.addFile(e.name, e.data);
  tar.finish();
  gz.end();
  await done;
  return gunzipSync(Buffer.concat(chunks));
}

const octal = (n: number, w: number) => n.toString(8).padStart(w, "0");

describe("TarWriter (ustar)", () => {
  it("produces a readable ustar archive with correct header + content + trailer", async () => {
    const content = Buffer.from("hello world");
    const tar = await buildTarGz([{ name: "target/file.txt", data: content }]);

    // name @0, ustar magic @257, size (octal) @124..135, content @512.
    expect(tar.subarray(0, "target/file.txt".length).toString("ascii")).toBe("target/file.txt");
    expect(tar[15]).toBe(0); // NUL-terminated within the 100-byte name field
    expect(tar.subarray(257, 262).toString("ascii")).toBe("ustar");
    expect(tar.subarray(124, 135).toString("ascii")).toBe(octal(content.length, 11));
    expect(tar.subarray(512, 512 + content.length).toString("utf8")).toBe("hello world");

    // Archive = header(512) + content padded to 512 + two zero blocks (1024).
    expect(tar.length).toBe(512 + 512 + 1024);
    expect(tar.subarray(tar.length - 1024).every((b) => b === 0)).toBe(true);
  });

  it("round-trips two files at 512-byte-aligned offsets", async () => {
    const a = Buffer.from("aaaa");
    const b = Buffer.from("bbbbbb");
    const tar = await buildTarGz([
      { name: "a.txt", data: a },
      { name: "b.txt", data: b },
    ]);
    expect(tar.subarray(512, 512 + a.length).toString()).toBe("aaaa");
    // second header starts at 1024 (first header + padded content)
    expect(tar.subarray(1024, 1024 + "b.txt".length).toString("ascii")).toBe("b.txt");
    expect(tar.subarray(1536, 1536 + b.length).toString()).toBe("bbbbbb");
  });

  it("rejects an entry name longer than the 100-byte ustar limit", () => {
    const tar = new TarWriter(createGzip());
    expect(() => tar.addFile("x".repeat(101), Buffer.alloc(1))).toThrow(/too long/);
  });
});
