import { readFile, mkdir } from "node:fs/promises";
import path from "node:path";
import { writeFileAtomic } from "../lib/atomic-file.js";
import sodium from "../lib/sodium.js";
import type { BootstrapSecrets } from "./types.js";
import { paths } from "../config/paths.js";

/** v1: payload encrypted directly under the passphrase-derived key. */
const MAGIC_V1 = "SKMCP1";
/** v2: payload encrypted under a random data key, which is wrapped per keyslot. */
const MAGIC_V2 = "SKMCP2";

interface KdfParams {
  salt: string;
  opslimit: number;
  memlimit: number;
}

interface V1Format {
  magic: string;
  /** argon2id parameters, stored so the file remains readable if defaults change. */
  kdf: KdfParams;
  nonce: string;
  ciphertext: string;
}

/** One wrapping of the data key: secretbox(dataKey) under a slot-specific KEK. */
interface KeySlot {
  nonce: string;
  wrapped: string;
}

interface PassphraseSlot extends KeySlot {
  kdf: KdfParams;
}

interface V2Format {
  magic: string;
  slots: {
    /** KEK derived from the admin's master passphrase via argon2id. */
    passphrase: PassphraseSlot;
    /** KEK is a random machine key stored in a host-mounted file (boot auto-unlock).
     *  Optional — absent unless the admin enabled auto-unlock. */
    unlockKey?: KeySlot;
  };
  nonce: string;
  ciphertext: string;
}

/**
 * Encrypted-at-rest store for Skeleton Key's *own* secrets. A random data key
 * encrypts the payload and is itself wrapped once per unlock method (keyslot):
 * always by an argon2id passphrase KEK, optionally by a random unlock key kept
 * in a host-mounted file for boot auto-unlock — so the human passphrase never
 * touches disk. Keys are held only in memory while unlocked. This is NOT where
 * homelab credentials live — those stay in the scoped Vaultwarden collection.
 */
export class BootstrapStore {
  private dataKey: Uint8Array | null = null;
  private slots: V2Format["slots"] | null = null;
  private cache: BootstrapSecrets = {};

  private constructor(private readonly file: string) {}

  static async open(file: string = paths.bootstrapStore): Promise<BootstrapStore> {
    await sodium.ready;
    return new BootstrapStore(file);
  }

  get locked(): boolean {
    return this.dataKey === null;
  }

  async exists(): Promise<boolean> {
    try {
      await readFile(this.file);
      return true;
    } catch {
      return false;
    }
  }

  private deriveKek(passphrase: string, salt: Uint8Array, opslimit: number, memlimit: number): Uint8Array {
    return sodium.crypto_pwhash(
      sodium.crypto_secretbox_KEYBYTES,
      passphrase,
      salt,
      opslimit,
      memlimit,
      sodium.crypto_pwhash_ALG_ARGON2ID13,
    );
  }

  /** Wrap the data key under `kek` as a fresh slot. */
  private wrapDataKey(kek: Uint8Array): KeySlot {
    const nonce = sodium.randombytes_buf(sodium.crypto_secretbox_NONCEBYTES);
    return {
      nonce: sodium.to_base64(nonce),
      wrapped: sodium.to_base64(sodium.crypto_secretbox_easy(this.dataKey!, nonce, kek)),
    };
  }

  private makePassphraseSlot(passphrase: string): PassphraseSlot {
    const salt = sodium.randombytes_buf(sodium.crypto_pwhash_SALTBYTES);
    const opslimit = sodium.crypto_pwhash_OPSLIMIT_MODERATE;
    const memlimit = sodium.crypto_pwhash_MEMLIMIT_MODERATE;
    const kek = this.deriveKek(passphrase, salt, opslimit, memlimit);
    const slot = this.wrapDataKey(kek);
    sodium.memzero(kek);
    return { ...slot, kdf: { salt: sodium.to_base64(salt), opslimit, memlimit } };
  }

  /** Create a brand-new store protected by `passphrase`. Fails if one exists. */
  async initialize(passphrase: string): Promise<void> {
    if (await this.exists()) {
      throw new Error("Bootstrap store already exists; refusing to overwrite.");
    }
    this.dataKey = sodium.randombytes_buf(sodium.crypto_secretbox_KEYBYTES);
    this.cache = {};
    this.slots = { passphrase: this.makePassphraseSlot(passphrase) };
    await this.persist();
  }

  private async readOnDisk(): Promise<V1Format | V2Format> {
    const raw = await readFile(this.file, "utf8");
    const parsed = JSON.parse(raw) as V1Format | V2Format;
    if (parsed.magic !== MAGIC_V1 && parsed.magic !== MAGIC_V2) {
      throw new Error("Unrecognized bootstrap store format.");
    }
    return parsed;
  }

  private openPayload(parsed: { nonce: string; ciphertext: string }, key: Uint8Array): BootstrapSecrets {
    const plaintext = sodium.crypto_secretbox_open_easy(
      sodium.from_base64(parsed.ciphertext),
      sodium.from_base64(parsed.nonce),
      key,
    );
    return JSON.parse(new TextDecoder().decode(plaintext)) as BootstrapSecrets;
  }

  /** Unwrap the data key from a slot; returns null if the KEK doesn't fit. */
  private unwrapDataKey(slot: KeySlot, kek: Uint8Array): Uint8Array | null {
    try {
      return sodium.crypto_secretbox_open_easy(
        sodium.from_base64(slot.wrapped),
        sodium.from_base64(slot.nonce),
        kek,
      );
    } catch {
      return null;
    }
  }

  /**
   * Unlock an existing store with `passphrase`. Throws on wrong passphrase.
   * A v1 store is transparently migrated to the keyslot format on success.
   */
  async unlock(passphrase: string): Promise<void> {
    const parsed = await this.readOnDisk();

    if (parsed.magic === MAGIC_V1) {
      const v1 = parsed as V1Format;
      const salt = sodium.from_base64(v1.kdf.salt);
      const key = this.deriveKek(passphrase, salt, v1.kdf.opslimit, v1.kdf.memlimit);
      let cache: BootstrapSecrets;
      try {
        cache = this.openPayload(v1, key);
      } catch {
        throw new Error("Incorrect passphrase or corrupted bootstrap store.");
      } finally {
        sodium.memzero(key);
      }
      // Migrate: adopt a random data key and rewrite as v2 (passphrase slot only).
      this.dataKey = sodium.randombytes_buf(sodium.crypto_secretbox_KEYBYTES);
      this.cache = cache;
      this.slots = { passphrase: this.makePassphraseSlot(passphrase) };
      await this.persist();
      return;
    }

    const v2 = parsed as V2Format;
    const slot = v2.slots.passphrase;
    const kek = this.deriveKek(
      passphrase,
      sodium.from_base64(slot.kdf.salt),
      slot.kdf.opslimit,
      slot.kdf.memlimit,
    );
    const dataKey = this.unwrapDataKey(slot, kek);
    sodium.memzero(kek);
    if (!dataKey) throw new Error("Incorrect passphrase or corrupted bootstrap store.");
    this.adopt(v2, dataKey);
  }

  /**
   * Unlock with the machine auto-unlock key (boot path — no argon2 involved).
   * Throws if no auto-unlock slot is enrolled or the key doesn't fit.
   */
  async unlockWithKey(unlockKey: Uint8Array): Promise<void> {
    const parsed = await this.readOnDisk();
    if (parsed.magic === MAGIC_V1) {
      throw new Error("Store predates auto-unlock; unlock once with the passphrase to migrate it.");
    }
    const v2 = parsed as V2Format;
    if (!v2.slots.unlockKey) {
      throw new Error("Auto-unlock is not enrolled for this store.");
    }
    const dataKey = this.unwrapDataKey(v2.slots.unlockKey, unlockKey);
    if (!dataKey) throw new Error("Auto-unlock key does not match this store.");
    this.adopt(v2, dataKey);
  }

  /** Common tail of both unlock paths: decrypt payload, take ownership of keys. */
  private adopt(v2: V2Format, dataKey: Uint8Array): void {
    let cache: BootstrapSecrets;
    try {
      cache = this.openPayload(v2, dataKey);
    } catch {
      sodium.memzero(dataKey);
      throw new Error("Corrupted bootstrap store payload.");
    }
    this.dataKey = dataKey;
    this.cache = cache;
    this.slots = v2.slots;
  }

  /**
   * Enroll (or rotate) the boot auto-unlock keyslot. Returns the fresh random
   * key — the caller persists it to the host-mounted key file and must
   * `sodium.memzero` it afterwards. Requires the store to be unlocked.
   */
  async enableAutoUnlock(): Promise<Uint8Array> {
    this.assertUnlocked();
    const unlockKey = sodium.randombytes_buf(sodium.crypto_secretbox_KEYBYTES);
    // Stage the slot change and roll it back if persist fails, so in-memory
    // state never disagrees with disk (a later update() would otherwise
    // persist a slot whose key was never returned to the caller).
    const previous = this.slots!.unlockKey;
    this.slots!.unlockKey = this.wrapDataKey(unlockKey);
    try {
      await this.persist();
    } catch (err) {
      if (previous) this.slots!.unlockKey = previous;
      else delete this.slots!.unlockKey;
      sodium.memzero(unlockKey);
      throw err;
    }
    return unlockKey;
  }

  /** Remove the auto-unlock keyslot (the key file alone can no longer unlock). */
  async disableAutoUnlock(): Promise<void> {
    this.assertUnlocked();
    const previous = this.slots!.unlockKey;
    if (!previous) return;
    delete this.slots!.unlockKey;
    try {
      await this.persist();
    } catch (err) {
      this.slots!.unlockKey = previous;
      throw err;
    }
  }

  /** Whether an auto-unlock slot is enrolled. Readable while locked. */
  async autoUnlockEnabled(): Promise<boolean> {
    try {
      const parsed = await this.readOnDisk();
      return parsed.magic === MAGIC_V2 && !!(parsed as V2Format).slots.unlockKey;
    } catch {
      return false;
    }
  }

  lock(): void {
    if (this.dataKey) sodium.memzero(this.dataKey);
    this.dataKey = null;
    this.slots = null;
    this.cache = {};
  }

  private assertUnlocked(): void {
    if (!this.dataKey) throw new Error("Bootstrap store is locked.");
  }

  get(): Readonly<BootstrapSecrets> {
    this.assertUnlocked();
    return this.cache;
  }

  async update(patch: Partial<BootstrapSecrets>): Promise<void> {
    this.assertUnlocked();
    this.cache = { ...this.cache, ...patch };
    await this.persist();
  }

  private async persist(): Promise<void> {
    this.assertUnlocked();
    const nonce = sodium.randombytes_buf(sodium.crypto_secretbox_NONCEBYTES);
    const plaintext = new TextEncoder().encode(JSON.stringify(this.cache));
    const out: V2Format = {
      magic: MAGIC_V2,
      slots: this.slots!,
      nonce: sodium.to_base64(nonce),
      ciphertext: sodium.to_base64(sodium.crypto_secretbox_easy(plaintext, nonce, this.dataKey!)),
    };
    await mkdir(path.dirname(this.file), { recursive: true });
    // Durable atomic write (fsync + rename) — a crash or power loss can't
    // destroy or truncate the only copy.
    await writeFileAtomic(this.file, JSON.stringify(out), 0o600);
  }
}
