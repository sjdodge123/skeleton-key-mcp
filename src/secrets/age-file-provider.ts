import { randomBytes, randomUUID } from "node:crypto";
import { open, readFile, rename, unlink } from "node:fs/promises";
import path from "node:path";
import { z } from "zod";
import * as age from "age-encryption";
import type { BootstrapSecrets, Credential } from "./types.js";
import type { NewSecretItem, ReadOptions, SecretIdentity, SecretItemPatch, SecretsProvider } from "./provider.js";
import type { BackendSetupResult, CheckResult, SecretsBackend } from "./backend.js";
import { UserFacingError } from "../lib/errors.js";

/**
 * `SecretsProvider` backed by one age-encrypted JSON file
 * (https://age-encryption.org), decrypted in memory with an age identity held
 * in the libsodium bootstrap store. The file holds only homelab secrets; the
 * operator can read and edit it with the standard `age` CLI.
 *
 * File format (the plaintext inside the age envelope):
 *
 *   { "version": 1,
 *     "items": [ { "id": "<uuid>", "name": "nas1-ssh", "username": "admin",
 *                  "password": "…", "uris": ["https://nas1.example.com"],
 *                  "notes": "…", "fields": { "private_key": "…" } } ] }
 *
 * `id` may be left out of hand-written items; the next write fills it in.
 *
 * How it meets the provider security contract (`./provider.ts`):
 *
 * 1. Scoping — the boundary is the file's contents. The identity decrypts only
 *    files encrypted to its recipient, and this provider opens exactly one
 *    path (config, `SKELETON_KEY_AGE_FILE`), so nothing outside that file is
 *    reachable; no personal vault is involved at all. What goes in the file is
 *    the operator's decision, enforced by age's encryption, not by filtering.
 * 2. Values in memory only — the file is decrypted in memory on each call and
 *    plaintext is never written to disk; writes encrypt in memory and replace
 *    the file atomically (0600 temp file, fsync, rename). The identity reaches
 *    nothing but the age library. No value is ever in argv, a log, an error.
 * 3. Value-free failures — every failure is an `AgeFileError` of a fixed
 *    class. Library, `JSON.parse` and zod messages are never surfaced (the
 *    library's bech32 errors can quote characters of the key, and JSON parse
 *    errors quote the plaintext); a format error names only the JSON path and
 *    issue code. No error carries a `cause`.
 * 4. Resolution — exact name, then id, then a unique case-insensitive name;
 *    an ambiguous match is refused. Unlike Vaultwarden there is no substring
 *    fallback (that exists only to keep old `bw get` refs working).
 *    `resolveById` matches ids only. An item WITHOUT an id is matched by name
 *    as its id — pinning degrades to the name for that item until the first
 *    write gives it a UUID (then the target's pin misses once, falls back to
 *    its name and re-pins). There is no trash: a deleted item is gone.
 * 5. No caller-chosen scope — the file path and the recipients writes encrypt
 *    to come from config only; no method takes a path or a recipient.
 * 6. Offline — the file is local, so there is no network dependency. A
 *    missing, unreadable or undecryptable file fails closed (it is never
 *    treated as empty), and `describeFailure` says which.
 *
 * Capabilities: `create` / `update` / `delete`. No `sync` — there is no cache:
 * every call reads the file as it is now, so hand edits apply without a
 * restart and `fresh` reads are inherently fresh. Concurrent writes from this
 * process are serialized; a hand edit racing a write is last-writer-wins.
 */

const ItemSchema = z
  .object({
    id: z.string().min(1).optional(),
    name: z.string().min(1),
    username: z.string().optional(),
    password: z.string().optional(),
    notes: z.string().optional(),
    uris: z.array(z.string()).optional(),
    fields: z.record(z.string(), z.string()).optional(),
  })
  .strict();
const DocSchema = z.object({ version: z.literal(1), items: z.array(ItemSchema) }).strict();

type AgeItem = z.infer<typeof ItemSchema>;
type AgeDoc = z.infer<typeof DocSchema>;

const ARMOR_HEADER = "-----BEGIN AGE ENCRYPTED FILE-----";

/** The fixed failure classes. Their text is the whole message — no input,
 *  library message or file content is ever appended (contract item 3). */
const FAILURES = {
  "not-configured": "The age file provider has no identity yet — run its setup step.",
  "not-connected": "The age file provider isn't connected — unlock Skeleton Key first.",
  identity: "That is not a valid age identity (expected AGE-SECRET-KEY-1… or AGE-SECRET-KEY-PQ-1…).",
  missing: "The age secrets file does not exist (SKELETON_KEY_AGE_FILE).",
  unreadable: "The age secrets file could not be read — check its permissions.",
  decrypt: "The age identity cannot decrypt the secrets file — it was encrypted to a different recipient, or it is damaged.",
  format: "The decrypted secrets file is not in the expected format",
  write: "The age secrets file could not be written — check the directory's permissions and free space.",
} as const;
export type AgeFileFailure = keyof typeof FAILURES;

export class AgeFileError extends Error {
  constructor(
    readonly failure: AgeFileFailure,
    /** Only for `format`: a JSON path + zod issue code, never a value. */
    where?: string,
  ) {
    super(failure === "format" ? `${FAILURES.format}${where ? ` (${where})` : ""}.` : FAILURES[failure]);
    this.name = "AgeFileError";
  }
}

export interface AgeFileOptions {
  /** The encrypted file (config, never a caller's choice). */
  file: string;
  /** Extra `age1…` recipients writes also encrypt to (validated at boot). */
  recipients: string[];
}

/** Validate an identity string and derive its recipient; fixed error otherwise. */
async function recipientOf(identity: string): Promise<string> {
  if (!/^AGE-SECRET-KEY-(?:PQ-)?1[0-9A-Z]+$/.test(identity)) throw new AgeFileError("identity");
  try {
    return await age.identityToRecipient(identity);
  } catch {
    throw new AgeFileError("identity");
  }
}

/** Check every configured extra recipient by encrypting an empty payload to it
 *  (the library parses recipients lazily). Throws naming the entry's position
 *  only — recipients are public, but the rule is: no input in errors. */
export async function validateRecipients(recipients: string[]): Promise<void> {
  for (const [i, r] of recipients.entries()) {
    try {
      const e = new age.Encrypter();
      e.addRecipient(r);
      await e.encrypt(new Uint8Array(0));
    } catch {
      throw new Error(`SKELETON_KEY_AGE_RECIPIENTS entry ${i + 1} is not an age recipient (age1…).`);
    }
  }
}

/** JSON path of a zod issue, items-level only (`items[3]`), plus its code. */
function formatWhere(err: z.ZodError): string {
  const issue = err.issues[0];
  if (!issue) return "";
  const [top, index] = issue.path;
  const at = top === "items" && typeof index === "number" ? `items[${index}]` : typeof top === "string" ? top : "root";
  return `${at}: ${issue.code}`;
}

function toCredential(ref: string, item: AgeItem): Credential {
  const fields = { ...(item.fields ?? {}) };
  return {
    ref,
    username: item.username,
    password: item.password,
    // Same rule as the Vaultwarden adapter: `secret` is an EXPLICIT secret
    // field only, never the notes (#26).
    secret: fields["private_key"] ?? fields["token"] ?? fields["api_key"] ?? undefined,
    notes: item.notes,
    fields,
    uris: item.uris ?? [],
  };
}

function ambiguous(n: number, ref: string, how: string): UserFacingError {
  return new UserFacingError(`${n} items in the age secrets file ${how} "${ref}" — rename them so the credentialRef is unique.`);
}

/** Resolve a human ref: exact name → id → unique case-insensitive name. */
function resolveItem(items: AgeItem[], ref: string): AgeItem {
  const exact = items.filter((i) => i.name === ref);
  if (exact.length === 1) return exact[0]!;
  if (exact.length > 1) throw ambiguous(exact.length, ref, "are named");
  const byId = items.filter((i) => i.id !== undefined && i.id === ref);
  if (byId.length === 1) return byId[0]!;
  if (byId.length > 1) throw ambiguous(byId.length, ref, "share the id");
  const ci = items.filter((i) => i.name.toLowerCase() === ref.toLowerCase());
  if (ci.length === 1) return ci[0]!;
  if (ci.length > 1) throw ambiguous(ci.length, ref, "match (case-insensitively)");
  throw new UserFacingError(`No item named "${ref}" in the age secrets file.`);
}

/** Resolve a pinned id: the id only — an id-less item's id is its name. */
function resolveId(items: AgeItem[], id: string): AgeItem {
  const hits = items.filter((i) => (i.id ?? i.name) === id);
  if (hits.length === 1) return hits[0]!;
  if (hits.length > 1) throw ambiguous(hits.length, id, "share the id");
  throw new UserFacingError(`No item with id "${id}" in the age secrets file (deleted or recreated).`);
}

export class AgeFileSecretsProvider implements SecretsProvider {
  readonly kind = "age-file";
  readonly label = "age file";

  private identity: string | null = null;
  private recipient: string | null = null;
  /** Serializes writes (read-modify-write of the whole file). */
  private writes: Promise<unknown> = Promise.resolve();

  constructor(readonly opts: AgeFileOptions) {}

  get ready(): boolean {
    return this.identity !== null;
  }

  /** The recipients writes encrypt to (public keys), or [] before connect. */
  get writeRecipients(): string[] {
    return this.recipient ? [this.recipient, ...this.opts.recipients] : [];
  }

  /**
   * Lifecycle (`AgeFileBackend` only): validate `identity`, prove it decrypts
   * the file, then hold it. With `createIfMissing`, a missing file is created
   * empty — never an existing one overwritten. On any failure the provider is
   * left exactly as it was. Returns the file's item count.
   */
  async open(identity: string, opts: { createIfMissing?: boolean } = {}): Promise<number> {
    const recipient = await recipientOf(identity);
    let doc: AgeDoc;
    try {
      doc = await this.readDoc(identity);
    } catch (err) {
      if (!(opts.createIfMissing && err instanceof AgeFileError && err.failure === "missing")) throw err;
      doc = { version: 1, items: [] };
      await this.writeDoc(doc, [recipient, ...this.opts.recipients]);
    }
    this.identity = identity;
    this.recipient = recipient;
    return doc.items.length;
  }

  async get(ref: string, _opts: ReadOptions = {}): Promise<Credential> {
    const { items } = await this.readDoc();
    return toCredential(ref, resolveItem(items, ref));
  }

  async resolveById(id: string, _opts: ReadOptions = {}): Promise<Credential> {
    const { items } = await this.readDoc();
    return toCredential(id, resolveId(items, id));
  }

  async resolveRef(ref: string): Promise<SecretIdentity> {
    const item = resolveItem((await this.readDoc()).items, ref);
    return { id: item.id ?? item.name, name: item.name };
  }

  async list(): Promise<string[]> {
    return (await this.readDoc()).items.map((i) => i.name);
  }

  create(item: NewSecretItem): Promise<{ name: string }> {
    return this.mutate((doc) => {
      if (doc.items.some((i) => i.name === item.name)) {
        throw new UserFacingError(`An item named "${item.name}" already exists in the age secrets file — pick a different name.`);
      }
      const fields = Object.fromEntries((item.fields ?? []).map((f) => [f.name, f.value]));
      doc.items.push(
        ItemSchema.parse({
          id: randomUUID(),
          name: item.name,
          username: item.username,
          password: item.password,
          notes: item.notes,
          uris: item.url ? [item.url] : undefined,
          fields: Object.keys(fields).length ? fields : undefined,
        }),
      );
      return { name: item.name };
    });
  }

  update(ref: string, patch: SecretItemPatch): Promise<SecretIdentity> {
    return this.mutate((doc) => {
      const item = resolveItem(doc.items, ref);
      if (patch.username !== undefined) item.username = patch.username;
      if (patch.password !== undefined) item.password = patch.password;
      if (patch.fields?.length) {
        item.fields = { ...(item.fields ?? {}) };
        for (const f of patch.fields) item.fields[f.name] = f.value;
      }
      item.id ??= randomUUID();
      return { id: item.id, name: item.name };
    });
  }

  delete(ref: string): Promise<{ name: string }> {
    return this.mutate((doc) => {
      const item = resolveItem(doc.items, ref);
      doc.items = doc.items.filter((i) => i !== item);
      return { name: item.name };
    });
  }

  describeFailure(err: unknown): string {
    if (err instanceof UserFacingError || err instanceof AgeFileError) return err.message;
    // Anything else (a bug, an fs error we didn't classify) is logged by name
    // only and summarized generically — its message may quote file content.
    console.error(`[skeleton-key] age file failure: ${err instanceof Error ? err.name : "Error"} → unclassified`);
    return "The age secrets file operation failed.";
  }

  /** Read-modify-write under the write lock. Fills in any missing ids. */
  private mutate<T>(fn: (doc: AgeDoc) => T): Promise<T> {
    const run = this.writes.then(async () => {
      const doc = await this.readDoc();
      const result = fn(doc);
      for (const i of doc.items) i.id ??= randomUUID();
      await this.writeDoc(doc, this.writeRecipients);
      return result;
    });
    this.writes = run.catch(() => {});
    return run;
  }

  private async readDoc(identity: string | null = this.identity): Promise<AgeDoc> {
    if (!identity) throw new AgeFileError("not-connected");
    let raw: Buffer;
    try {
      raw = await readFile(this.opts.file);
    } catch (err) {
      throw new AgeFileError((err as { code?: unknown }).code === "ENOENT" ? "missing" : "unreadable");
    }
    let plaintext: string;
    try {
      const text = raw.toString("utf8").trimStart();
      const ciphertext = text.startsWith(ARMOR_HEADER) ? age.armor.decode(text) : new Uint8Array(raw);
      const d = new age.Decrypter();
      d.addIdentity(identity);
      plaintext = await d.decrypt(ciphertext, "text");
    } catch {
      throw new AgeFileError("decrypt");
    }
    let json: unknown;
    try {
      json = JSON.parse(plaintext);
    } catch {
      throw new AgeFileError("format", "not valid JSON");
    }
    const parsed = DocSchema.safeParse(json);
    if (!parsed.success) throw new AgeFileError("format", formatWhere(parsed.error));
    return parsed.data;
  }

  private async writeDoc(doc: AgeDoc, recipients: string[]): Promise<void> {
    if (recipients.length === 0) throw new AgeFileError("not-connected");
    let armored: string;
    try {
      const e = new age.Encrypter();
      for (const r of recipients) e.addRecipient(r);
      armored = age.armor.encode(await e.encrypt(`${JSON.stringify(doc, null, 2)}\n`));
    } catch {
      throw new AgeFileError("write");
    }
    await atomicWrite(this.opts.file, armored);
  }
}

/** Write `data` to `file` atomically: a 0600 temp file in the same directory,
 *  fsync'd, then renamed over the target. Any failure removes the temp file
 *  and leaves the target untouched. */
async function atomicWrite(file: string, data: string): Promise<void> {
  const dir = path.dirname(file);
  const tmp = path.join(dir, `.${path.basename(file)}.${randomBytes(6).toString("hex")}.tmp`);
  let fh: Awaited<ReturnType<typeof open>> | undefined;
  try {
    fh = await open(tmp, "wx", 0o600);
    await fh.writeFile(data);
    await fh.sync();
    await fh.close();
    fh = undefined;
    await rename(tmp, file);
  } catch {
    await fh?.close().catch(() => {});
    await unlink(tmp).catch(() => {});
    throw new AgeFileError("write");
  }
  // Persist the rename itself; best-effort (not every platform syncs a dir fd).
  try {
    const d = await open(dir, "r");
    await d.sync().finally(() => d.close());
  } catch {
    /* ignore */
  }
}

const SetupInput = z
  .object({
    /** An existing identity to use; omitted → generate a new X25519 one. */
    identity: z.string().optional(),
  })
  .strict();

/**
 * The age-file connection lifecycle (`SecretsBackend`). Its one saved setting
 * is the identity (`ageIdentity` in the bootstrap store); the file path and
 * extra recipients are non-secret config.
 */
export class AgeFileBackend implements SecretsBackend {
  readonly provider: AgeFileSecretsProvider;

  constructor(opts: AgeFileOptions) {
    this.provider = new AgeFileSecretsProvider(opts);
  }

  configured(s: Readonly<BootstrapSecrets>): boolean {
    return !!s.ageIdentity;
  }

  async connect(s: Readonly<BootstrapSecrets>): Promise<void> {
    if (!s.ageIdentity) throw new AgeFileError("not-configured");
    await this.provider.open(s.ageIdentity);
  }

  /**
   * Use a pasted identity, or generate one. A missing file is created empty;
   * an existing file must decrypt with the identity (so setup can never
   * overwrite a file it can't read).
   */
  async setup(input: unknown): Promise<BackendSetupResult> {
    const i = SetupInput.parse(input ?? {});
    const identity = i.identity?.trim() || (await age.generateX25519Identity());
    try {
      await this.provider.open(identity, { createIfMissing: true });
    } catch (err) {
      if (err instanceof AgeFileError) throw new UserFacingError(err.message);
      throw err;
    }
    return { patch: { ageIdentity: identity } };
  }

  async verify(_s: Readonly<BootstrapSecrets>): Promise<CheckResult[]> {
    const results: CheckResult[] = [];
    try {
      const n = (await this.provider.list()).length;
      results.push({
        name: "Identity decrypts the secrets file",
        passed: true,
        detail: n > 0 ? `${n} credential item(s) readable.` : "The file is empty — add credentials with request_credential once setup is done, or encrypt a file yourself (below).",
      });
    } catch (err) {
      results.push({ name: "Identity decrypts the secrets file", passed: false, detail: this.provider.describeFailure(err) });
    }
    const recipients = this.provider.writeRecipients;
    results.push({
      name: "Writes are encrypted to",
      passed: recipients.length > 0,
      detail:
        recipients.length > 0
          ? `${recipients.join(", ")}. To edit the file by hand, decrypt it with a matching identity and re-encrypt it to the same recipients (age -r …).`
          : "Not connected.",
    });
    return results;
  }
}
