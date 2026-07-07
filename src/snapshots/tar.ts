import type { Writable } from "node:stream";

/**
 * Minimal streaming ustar (POSIX tar) writer — enough to bundle a skeleton's
 * decrypted artifacts into a `.tar` we then gzip. No dependency (the codebase is
 * stdlib-first). Entry names stay well under the 100-byte ustar limit
 * (`<target>/<artifact>`); anything longer is rejected rather than silently
 * truncated.
 */
export class TarWriter {
  constructor(private readonly out: Writable) {}

  addFile(name: string, data: Buffer): void {
    if (Buffer.byteLength(name, "utf8") > 100) throw new Error(`tar entry name too long (>100 bytes): ${name}`);
    this.out.write(header(name, data.length));
    this.out.write(data);
    const pad = (512 - (data.length % 512)) % 512;
    if (pad) this.out.write(Buffer.alloc(pad));
  }

  /** Two 512-byte zero blocks mark end-of-archive. */
  finish(): void {
    this.out.write(Buffer.alloc(1024));
  }
}

function octal(n: number, width: number): string {
  return n.toString(8).padStart(width, "0");
}

function header(name: string, size: number): Buffer {
  const h = Buffer.alloc(512);
  h.write(name, 0, 100, "utf8"); // name
  h.write("0000644\0", 100, 8, "ascii"); // mode
  h.write("0000000\0", 108, 8, "ascii"); // uid
  h.write("0000000\0", 116, 8, "ascii"); // gid
  h.write(octal(size, 11) + "\0", 124, 12, "ascii"); // size (11 octal digits + NUL)
  h.write(octal(0, 11) + "\0", 136, 12, "ascii"); // mtime = 0 (deterministic)
  h.write("        ", 148, 8, "ascii"); // checksum placeholder = 8 spaces (summed as-is)
  h.write("0", 156, 1, "ascii"); // typeflag = regular file
  h.write("ustar\0", 257, 6, "ascii"); // magic
  h.write("00", 263, 2, "ascii"); // version
  // Header checksum = unsigned sum of all 512 bytes with the checksum field held
  // at 8 spaces; written back as 6 octal digits + NUL + space.
  let sum = 0;
  for (const b of h) sum += b;
  h.write(octal(sum, 6) + "\0 ", 148, 8, "ascii");
  return h;
}
