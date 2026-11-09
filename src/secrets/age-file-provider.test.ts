import { describe, it, expect, beforeEach, afterEach, vi } from "vitest";
import { lstat, mkdir, mkdtemp, readdir, readFile, rm, stat, symlink, writeFile } from "node:fs/promises";
import { tmpdir } from "node:os";
import path from "node:path";
import * as age from "age-encryption";
import { z } from "zod";
import { AgeFileBackend, AgeFileError, AgeFileSecretsProvider, derivedId, validateRecipients } from "./age-file-provider.js";
import { capabilitiesOf } from "./provider.js";
import { selectedProviderKind } from "./select.js";
import { UserFacingError } from "../lib/errors.js";

/** A secret-looking marker that must never appear in an error, log or result. */
const SECRET = "hunter2-S3CR3T-value";

let dir: string;
let file: string;

beforeEach(async () => {
  dir = await mkdtemp(path.join(tmpdir(), "sk-age-"));
  file = path.join(dir, "secrets.age");
});
afterEach(async () => {
  vi.restoreAllMocks();
  await rm(dir, { recursive: true, force: true });
});

async function encryptTo(recipient: string, plaintext: string, armored = true): Promise<Uint8Array | string> {
  const e = new age.Encrypter();
  e.addRecipient(recipient);
  const ct = await e.encrypt(plaintext);
  return armored ? age.armor.encode(ct) : ct;
}

async function decryptWith(identity: string): Promise<any> {
  const d = new age.Decrypter();
  d.addIdentity(identity);
  return JSON.parse(await d.decrypt(age.armor.decode(await readFile(file, "utf8")), "text"));
}

/** A provider opened on a file holding `items`, written by the "operator". */
async function providerWith(items: unknown[], opts: { armored?: boolean; recipients?: string[] } = {}) {
  const identity = await age.generateX25519Identity();
  const recipient = await age.identityToRecipient(identity);
  await writeFile(file, await encryptTo(recipient, JSON.stringify({ version: 1, items }), opts.armored ?? true));
  const p = new AgeFileSecretsProvider({ file, recipients: opts.recipients ?? [] });
  await p.open(identity);
  return { p, identity, recipient };
}

const ID_A = "0b5c3a52-5f4e-4b8e-9e1a-2f6d7c8b9a01";
const ID_B = "0b5c3a52-5f4e-4b8e-9e1a-2f6d7c8b9a02";

describe("age-file provider: reads", () => {
  it("resolves exact name, then id, then a unique case-insensitive name", async () => {
    const { p } = await providerWith([
      { id: ID_A, name: "nas1-ssh", username: "admin", fields: { private_key: "KEY" } },
      { id: ID_B, name: "Kuma1", password: "pw" },
    ]);
    expect((await p.get("nas1-ssh")).username).toBe("admin");
    expect((await p.get(ID_B)).password).toBe("pw");
    expect((await p.get("kuma1")).password).toBe("pw");
    expect(await p.resolveRef("kuma1")).toEqual({ id: ID_B, name: "Kuma1" });
    await expect(p.get("kuma")).rejects.toThrow(/No item named "kuma"/); // no substring fallback
  });

  it("refuses an ambiguous ref instead of guessing", async () => {
    const { p } = await providerWith([
      { id: ID_A, name: "dup", password: "one" },
      { id: ID_B, name: "dup", password: "two" },
      { name: "Case" },
      { name: "case" },
    ]);
    await expect(p.get("dup")).rejects.toThrow(/2 items .* are named "dup"/);
    await expect(p.get("CASE")).rejects.toThrow(/2 items .* match \(case-insensitively\) "CASE"/);
  });

  it("resolveById matches ids only — never a name; an id-less item's id is a UUID derived from its name", async () => {
    const { p } = await providerWith([
      { id: ID_A, name: ID_B, password: "named-like-an-id" },
      { id: ID_B, name: "real", password: "right" },
      { name: "legacy", password: "no-id" },
    ]);
    expect((await p.resolveById(ID_B)).password).toBe("right");
    await expect(p.resolveById("real")).rejects.toThrow(/No item with id "real"/);
    await expect(p.resolveById("legacy")).rejects.toThrow(/No item with id "legacy"/);
    const { id } = await p.resolveRef("legacy");
    expect(id).toBe(derivedId("legacy"));
    // The registry pins only UUIDs (targetSchema.credentialId), so this must be one.
    expect(z.string().uuid().safeParse(id).success).toBe(true);
    expect((await p.resolveById(id)).password).toBe("no-id");
  });

  it("maps an item to a Credential the way the Vaultwarden adapter does (notes are never the secret)", async () => {
    const { p } = await providerWith([
      { id: ID_A, name: "a", notes: "-----BEGIN looks like a key", fields: { token: "T" }, uris: ["https://nas1.example.com"] },
      { id: ID_B, name: "b", notes: "just notes" },
    ]);
    expect(await p.get("a")).toEqual({
      ref: "a", username: undefined, password: undefined, secret: "T", notes: "-----BEGIN looks like a key",
      fields: { token: "T" }, uris: ["https://nas1.example.com"],
    });
    expect((await p.get("b")).secret).toBeUndefined();
  });

  it("reads a binary (non-armored) file too, and list returns names only", async () => {
    const { p } = await providerWith([{ id: ID_A, name: "x", password: SECRET }], { armored: false });
    const names = await p.list();
    expect(names).toEqual(["x"]);
    expect(JSON.stringify(names)).not.toContain(SECRET);
  });

  it("sees a hand edit on the next call — there is no cache, so no sync capability", async () => {
    const { p, recipient } = await providerWith([{ id: ID_A, name: "old" }]);
    await writeFile(file, await encryptTo(recipient, JSON.stringify({ version: 1, items: [{ name: "new" }] })));
    expect(await p.list()).toEqual(["new"]);
    expect(capabilitiesOf(p)).toEqual(["create", "update", "delete"]);
  });
});

describe("age-file provider: writes", () => {
  it("create assigns a UUID, refuses a duplicate name, and fills in ids missing from hand-written items", async () => {
    const { p, identity } = await providerWith([{ name: "hand-written", password: "x" }]);
    await p.create({ name: "new", username: "u", password: "p", url: "https://kuma1.example.com", notes: "n", fields: [{ name: "token", value: "T", hidden: true }] });
    await expect(p.create({ name: "new" })).rejects.toThrow(/already exists/);
    const doc = await decryptWith(identity);
    expect(doc.version).toBe(1);
    const created = doc.items.find((i: any) => i.name === "new");
    expect(created).toMatchObject({ username: "u", password: "p", notes: "n", uris: ["https://kuma1.example.com"], fields: { token: "T" } });
    expect(created.id).toMatch(/^[0-9a-f-]{36}$/);
    // The stored id is the derived one, so a pin taken before this write still matches.
    expect(doc.items.find((i: any) => i.name === "hand-written").id).toBe(derivedId("hand-written"));
  });

  it("a pin taken on an id-less item survives the write that stores its id", async () => {
    const { p } = await providerWith([{ name: "legacy", password: "v1" }]);
    const pinned = (await p.resolveRef("legacy")).id;
    await p.create({ name: "other" });
    await p.update("legacy", { password: "v2" });
    expect((await p.resolveById(pinned)).password).toBe("v2");
  });

  it("refuses a hand-written id that isn't a UUID (the registry couldn't pin it)", async () => {
    const { p, recipient } = await providerWith([]);
    await writeFile(file, await encryptTo(recipient, JSON.stringify({ version: 1, items: [{ id: "abc", name: "x" }] })));
    await expect(p.list()).rejects.toThrow(/items\[0\]: invalid_format/);
  });

  it("update replaces only the listed values and keeps the rest; an id-less item gets an id", async () => {
    const { p, identity } = await providerWith([{ name: "app", username: "keep", password: "old", notes: "keep", fields: { A: "1", B: "2" } }]);
    const out = await p.update("app", { password: "new", fields: [{ name: "B", value: "20" }, { name: "C", value: "3" }] });
    expect(out.name).toBe("app");
    expect(out.id).toBe(derivedId("app"));
    const [item] = (await decryptWith(identity)).items;
    expect(item).toEqual({ id: out.id, name: "app", username: "keep", password: "new", notes: "keep", fields: { A: "1", B: "20", C: "3" } });
  });

  it("delete removes the item; a deleted item never satisfies a ref", async () => {
    const { p } = await providerWith([{ id: ID_A, name: "gone" }, { id: ID_B, name: "stays" }]);
    expect(await p.delete("gone")).toEqual({ name: "gone" });
    expect(await p.list()).toEqual(["stays"]);
    await expect(p.resolveById(ID_A)).rejects.toThrow(/No item with id/);
  });

  it("writes through a symlinked path instead of replacing the link", async () => {
    const { p } = await providerWith([]);
    const mount = path.join(dir, "mount");
    await mkdir(mount);
    const real = path.join(mount, "secrets.age");
    await writeFile(real, await readFile(file));
    await rm(file);
    await symlink(real, file);
    await p.create({ name: "x", password: "p" });
    expect((await lstat(file)).isSymbolicLink()).toBe(true);
    expect(await p.list()).toEqual(["x"]);
    expect(await readdir(mount)).toEqual(["secrets.age"]);
  });

  it("writes atomically: 0600, armored, no temp file left behind", async () => {
    const { p } = await providerWith([]);
    await p.create({ name: "x", password: "p" });
    expect((await stat(file)).mode & 0o777).toBe(0o600);
    expect((await readFile(file, "utf8")).startsWith("-----BEGIN AGE ENCRYPTED FILE-----")).toBe(true);
    expect(await readdir(dir)).toEqual(["secrets.age"]);
  });

  it("serializes concurrent writes, so none is lost", async () => {
    const { p } = await providerWith([]);
    await Promise.all(["a", "b", "c", "d", "e"].map((name) => p.create({ name, password: name })));
    expect((await p.list()).sort()).toEqual(["a", "b", "c", "d", "e"]);
  });

  it("encrypts writes to the configured extra recipients too, so the operator keeps access", async () => {
    const operator = await age.generateX25519Identity();
    const { p } = await providerWith([], { recipients: [await age.identityToRecipient(operator)] });
    await p.create({ name: "x", password: "p" });
    expect((await decryptWith(operator)).items.map((i: any) => i.name)).toEqual(["x"]);
  });

  it("a failed write leaves the file untouched and no temp file behind", async () => {
    const { p } = await providerWith([{ id: ID_A, name: "keep" }]);
    const before = await readFile(file, "utf8");
    vi.spyOn(age.Encrypter.prototype, "encrypt").mockRejectedValueOnce(new Error(`encrypt broke near ${SECRET}`));
    const err = await p.create({ name: "x", password: SECRET }).catch((e: unknown) => e);
    expect(err).toBeInstanceOf(AgeFileError);
    expect(String((err as Error).message)).not.toContain(SECRET);
    expect(await readFile(file, "utf8")).toBe(before);
    expect(await readdir(dir)).toEqual(["secrets.age"]);
  });
});

describe("age-file provider: failures are fixed and value-free (contract items 2, 3, 6)", () => {
  /** Assert nothing about `err` — message, own properties, describeFailure — carries SECRET. */
  function assertValueFree(p: AgeFileSecretsProvider, err: unknown): void {
    expect(err).toBeInstanceOf(Error);
    const e = err as Error & Record<string, unknown>;
    expect(e.message).not.toContain(SECRET);
    expect(JSON.stringify(Object.fromEntries(Object.entries(e)))).not.toContain(SECRET);
    expect(e.cause).toBeUndefined();
    expect(p.describeFailure(err)).not.toContain(SECRET);
  }

  it("plaintext that isn't JSON: the parser's message (which quotes the text) never surfaces", async () => {
    const identity = await age.generateX25519Identity();
    await writeFile(file, await encryptTo(await age.identityToRecipient(identity), `{"version":1,"items":[${SECRET}`));
    const p = new AgeFileSecretsProvider({ file, recipients: [] });
    const err = await p.open(identity).catch((e: unknown) => e);
    assertValueFree(p, err);
    expect((err as Error).message).toBe("The decrypted secrets file is not in the expected format (not valid JSON).");
    expect(p.ready).toBe(false);
  });

  it("a schema violation names the item and the issue code, never a key or value", async () => {
    const { p, recipient } = await providerWith([]);
    await writeFile(file, await encryptTo(recipient, JSON.stringify({ version: 1, items: [{ name: "ok" }, { name: "x", [SECRET]: SECRET }] })));
    const err = await p.list().catch((e: unknown) => e);
    assertValueFree(p, err);
    expect((err as Error).message).toBe("The decrypted secrets file is not in the expected format (items[1]: unrecognized_keys).");
  });

  it("a malformed identity is refused with fixed text (the library's bech32 error quotes key characters)", async () => {
    const p = new AgeFileSecretsProvider({ file, recipients: [] });
    for (const bad of [`AGE-SECRET-KEY-1${SECRET.toUpperCase()}`, SECRET, "AGE-SECRET-KEY-1QQQQ"]) {
      const err = await p.open(bad).catch((e: unknown) => e);
      assertValueFree(p, err);
      expect((err as AgeFileError).failure).toBe("identity");
      expect((err as Error).message).not.toContain("QQQQ");
    }
  });

  it("the wrong identity is a decrypt failure, and the provider stays not-ready", async () => {
    const { recipient } = await providerWith([{ name: "x", password: SECRET }]);
    void recipient;
    const p = new AgeFileSecretsProvider({ file, recipients: [] });
    const err = await p.open(await age.generateX25519Identity()).catch((e: unknown) => e);
    assertValueFree(p, err);
    expect((err as AgeFileError).failure).toBe("decrypt");
    expect(p.ready).toBe(false);
    await expect(p.list()).rejects.toThrow(/isn't connected/);
  });

  it("fails closed when the file disappears — never an empty list", async () => {
    const { p } = await providerWith([{ id: ID_A, name: "x" }]);
    await rm(file);
    const err = await p.list().catch((e: unknown) => e);
    expect((err as AgeFileError).failure).toBe("missing");
    await expect(p.get("x")).rejects.toThrow(/does not exist/);
  });

  it("an unexpected error is summarized generically and logged by class only", async () => {
    const p = new AgeFileSecretsProvider({ file, recipients: [] });
    const logged = vi.spyOn(console, "error").mockImplementation(() => {});
    expect(p.describeFailure(new TypeError(`boom ${SECRET}`))).toBe("The age secrets file operation failed.");
    expect(logged.mock.calls.flat().join(" ")).toBe("[skeleton-key] age file failure: TypeError → unclassified");
    expect(p.describeFailure(new UserFacingError('No item named "x" in the age secrets file.'))).toBe('No item named "x" in the age secrets file.');
  });
});

describe("age-file backend lifecycle", () => {
  it("setup with no identity generates one and creates an empty file; connect reopens it from the store", async () => {
    const b = new AgeFileBackend({ file, recipients: [] });
    expect(b.configured({})).toBe(false);
    const { patch, finalize } = await b.setup({}, {});
    expect(patch.ageIdentity).toMatch(/^AGE-SECRET-KEY-1/);
    // Nothing is created until the identity is persisted and finalize runs.
    expect(b.provider.ready).toBe(false);
    expect(await readdir(dir)).toEqual([]);
    await finalize!();
    expect(b.provider.ready).toBe(true);
    expect(await b.provider.list()).toEqual([]);
    const checks = await b.verify({});
    expect(checks.map((c) => c.passed)).toEqual([true, true]);
    expect(checks[1]!.detail).toContain(await age.identityToRecipient(patch.ageIdentity!));
    expect(JSON.stringify(checks)).not.toContain(patch.ageIdentity!);

    const again = new AgeFileBackend({ file, recipients: [] });
    expect(again.configured(patch)).toBe(true);
    await again.connect(patch);
    expect(again.provider.ready).toBe(true);
  });

  it("setup never overwrites an existing file it can't decrypt", async () => {
    await providerWith([{ id: ID_A, name: "precious", password: SECRET }]);
    const before = await readFile(file, "utf8");
    const b = new AgeFileBackend({ file, recipients: [] });
    const err = await b.setup({}, {}).catch((e: unknown) => e);
    expect(err).toBeInstanceOf(UserFacingError);
    expect((err as Error).message).toMatch(/cannot decrypt/);
    expect(await readFile(file, "utf8")).toBe(before);
    expect(b.provider.ready).toBe(false);
  });

  it("setup with a pasted identity opens the operator's existing file", async () => {
    const { identity } = await providerWith([{ id: ID_A, name: "nas1-ssh" }]);
    const b = new AgeFileBackend({ file, recipients: [] });
    const r = await b.setup({ identity: `  ${identity}\n` }, {});
    expect(r.patch.ageIdentity).toBe(identity);
    await r.finalize!();
    expect(await b.provider.list()).toEqual(["nas1-ssh"]);
  });

  it("setup rejects unknown input keys, so a typo can't be silently ignored", async () => {
    const b = new AgeFileBackend({ file, recipients: [] });
    await expect(b.setup({ identiy: "x" }, {})).rejects.toThrow();
  });

  it("re-running setup with a blank identity reuses the saved one instead of minting a key that can't open the file", async () => {
    const b = new AgeFileBackend({ file, recipients: [] });
    const first = await b.setup({}, {});
    await first.finalize!();
    const again = new AgeFileBackend({ file, recipients: [] });
    const second = await again.setup({}, first.patch);
    expect(second.patch.ageIdentity).toBe(first.patch.ageIdentity);
    await second.finalize!();
    expect(again.provider.ready).toBe(true);
  });

  it("a reconnect that can't read the file leaves the provider not-ready (fails closed)", async () => {
    const b = new AgeFileBackend({ file, recipients: [] });
    const r = await b.setup({}, {});
    await r.finalize!();
    expect(b.provider.ready).toBe(true);
    await writeFile(file, "garbage");
    await expect(b.connect(r.patch)).rejects.toMatchObject({ failure: "decrypt" });
    expect(b.provider.ready).toBe(false);
  });

  it("connect without a saved identity throws not-configured", async () => {
    const b = new AgeFileBackend({ file, recipients: [] });
    await expect(b.connect({})).rejects.toMatchObject({ failure: "not-configured" });
  });

  it("has no server to change", () => {
    expect(new AgeFileBackend({ file, recipients: [] }).changeServer).toBeUndefined();
  });
});

describe("provider selection config", () => {
  it("defaults to vaultwarden and accepts the known kinds", () => {
    expect(selectedProviderKind(undefined)).toBe("vaultwarden");
    expect(selectedProviderKind("vaultwarden")).toBe("vaultwarden");
    expect(selectedProviderKind("age-file")).toBe("age-file");
  });

  it("refuses an unknown kind loudly, naming the valid ones and not echoing the value", () => {
    expect(() => selectedProviderKind(`bitwarden-${SECRET}`)).toThrow(/must be one of: vaultwarden, age-file/);
    try {
      selectedProviderKind(SECRET);
    } catch (err) {
      expect((err as Error).message).not.toContain(SECRET);
    }
  });

  it("validates extra recipients by position, without echoing them", async () => {
    const good = await age.identityToRecipient(await age.generateX25519Identity());
    await expect(validateRecipients([good])).resolves.toBeUndefined();
    await expect(validateRecipients([good, `age1${SECRET}`])).rejects.toThrow(/^SKELETON_KEY_AGE_RECIPIENTS entry 2 is not an age recipient/);
    await expect(validateRecipients([good, `age1${SECRET}`])).rejects.not.toThrow(new RegExp(SECRET));
  });
});
