import { readFile, writeFile, mkdir } from "node:fs/promises";
import path from "node:path";
import sodium from "../lib/sodium.js";
import type { BootstrapSecrets } from "./types.js";
import { paths } from "../config/paths.js";

const MAGIC = "SKMCP1";

interface OnDiskFormat {
  magic: string;
  /** argon2id parameters, stored so the file remains readable if defaults change. */
  kdf: { salt: string; opslimit: number; memlimit: number };
  nonce: string;
  ciphertext: string;
}

/**
 * Encrypted-at-rest store for Skeleton Key's *own* secrets. The encryption key is
 * derived from a passphrase via argon2id (libsodium crypto_pwhash) and held only
 * in memory while unlocked. This is NOT where homelab credentials live — those
 * stay in the scoped Vaultwarden collection.
 */
export class BootstrapStore {
  private key: Uint8Array | null = null;
  private cache: BootstrapSecrets = {};

  private constructor(private readonly file: string) {}

  static async open(file: string = paths.bootstrapStore): Promise<BootstrapStore> {
    await sodium.ready;
    return new BootstrapStore(file);
  }

  get locked(): boolean {
    return this.key === null;
  }

  async exists(): Promise<boolean> {
    try {
      await readFile(this.file);
      return true;
    } catch {
      return false;
    }
  }

  private deriveKey(passphrase: string, salt: Uint8Array, opslimit: number, memlimit: number): Uint8Array {
    return sodium.crypto_pwhash(
      sodium.crypto_secretbox_KEYBYTES,
      passphrase,
      salt,
      opslimit,
      memlimit,
      sodium.crypto_pwhash_ALG_ARGON2ID13,
    );
  }

  /** Create a brand-new store protected by `passphrase`. Fails if one exists. */
  async initialize(passphrase: string): Promise<void> {
    if (await this.exists()) {
      throw new Error("Bootstrap store already exists; refusing to overwrite.");
    }
    const salt = sodium.randombytes_buf(sodium.crypto_pwhash_SALTBYTES);
    const opslimit = sodium.crypto_pwhash_OPSLIMIT_MODERATE;
    const memlimit = sodium.crypto_pwhash_MEMLIMIT_MODERATE;
    this.key = this.deriveKey(passphrase, salt, opslimit, memlimit);
    this.cache = {};
    await this.persist(salt, opslimit, memlimit);
  }

  /** Unlock an existing store with `passphrase`. Throws on wrong passphrase. */
  async unlock(passphrase: string): Promise<void> {
    const raw = await readFile(this.file, "utf8");
    const parsed = JSON.parse(raw) as OnDiskFormat;
    if (parsed.magic !== MAGIC) throw new Error("Unrecognized bootstrap store format.");
    const salt = sodium.from_base64(parsed.kdf.salt);
    const key = this.deriveKey(passphrase, salt, parsed.kdf.opslimit, parsed.kdf.memlimit);
    const nonce = sodium.from_base64(parsed.nonce);
    const ciphertext = sodium.from_base64(parsed.ciphertext);
    let plaintext: Uint8Array;
    try {
      plaintext = sodium.crypto_secretbox_open_easy(ciphertext, nonce, key);
    } catch {
      throw new Error("Incorrect passphrase or corrupted bootstrap store.");
    }
    this.key = key;
    this.cache = JSON.parse(new TextDecoder().decode(plaintext)) as BootstrapSecrets;
  }

  lock(): void {
    this.key = null;
    this.cache = {};
  }

  private assertUnlocked(): void {
    if (!this.key) throw new Error("Bootstrap store is locked.");
  }

  get(): Readonly<BootstrapSecrets> {
    this.assertUnlocked();
    return this.cache;
  }

  async update(patch: Partial<BootstrapSecrets>): Promise<void> {
    this.assertUnlocked();
    this.cache = { ...this.cache, ...patch };
    // Re-read the on-disk salt/params to preserve them across writes.
    const raw = await readFile(this.file, "utf8");
    const parsed = JSON.parse(raw) as OnDiskFormat;
    await this.persist(
      sodium.from_base64(parsed.kdf.salt),
      parsed.kdf.opslimit,
      parsed.kdf.memlimit,
    );
  }

  private async persist(salt: Uint8Array, opslimit: number, memlimit: number): Promise<void> {
    this.assertUnlocked();
    const nonce = sodium.randombytes_buf(sodium.crypto_secretbox_NONCEBYTES);
    const plaintext = new TextEncoder().encode(JSON.stringify(this.cache));
    const ciphertext = sodium.crypto_secretbox_easy(plaintext, nonce, this.key!);
    const out: OnDiskFormat = {
      magic: MAGIC,
      kdf: { salt: sodium.to_base64(salt), opslimit, memlimit },
      nonce: sodium.to_base64(nonce),
      ciphertext: sodium.to_base64(ciphertext),
    };
    await mkdir(path.dirname(this.file), { recursive: true });
    await writeFile(this.file, JSON.stringify(out), { mode: 0o600 });
  }
}
