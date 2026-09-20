/**
 * Vault-backed secret references, shared by every connector that has to put a
 * password or token into a request.
 *
 * The rule this exists to enforce: a secret must never transit the chat/MCP
 * channel or the model context. So a tool never takes the value — it takes a
 * *reference* to a vault item, and the value is resolved in-process at call
 * time, used once in the outbound request body, and dropped. Nothing here may
 * return a value to a caller: the errors name the variable, the item and the
 * field, and the only thing reported back is a keyed fingerprint.
 *
 * Originally written for Portainer's `secretEnv` (stack deploys); extracted here
 * when Pelican needed the same thing for a game server's startup variables,
 * which is the second connector to need it and so no longer connector-specific.
 */
import type { Credential, ToolContext } from "./types.js";

/** One resolved name/value pair, for the outbound request body ONLY. */
export interface SecretValue {
  name: string;
  value: string;
}

/** "Put vault item `credentialRef`'s value into `name`." */
export interface SecretRef {
  name: string;
  credentialRef: string;
  field?: string;
}

/**
 * Pick one value out of a vault item. Named parts (`username`/`password`/
 * `secret`/`notes`) read the corresponding property and fall back to a custom
 * field of the same name; anything else is a custom field. With no field given:
 * password, else secret, else the `token` custom field.
 */
export function pickCredentialField(cred: Credential, field?: string): string | undefined {
  if (!field) return cred.password ?? cred.secret ?? cred.fields["token"];
  const named: Record<string, string | undefined> = {
    username: cred.username,
    password: cred.password,
    secret: cred.secret,
    notes: cred.notes,
  };
  return (field in named ? named[field] : undefined) ?? cred.fields[field];
}

/**
 * Resolve references into real values through the vault.
 *
 * INVARIANT: the returned values are for the outbound request body only — the
 * caller must never put them in a ToolResult, an error, or the audit log.
 *
 * `label` names the calling parameter (`secretEnv`, `secretVariables`, …) so the
 * error tells the operator which input to fix.
 */
export async function resolveSecretRefs(ctx: ToolContext, refs: SecretRef[] | undefined, label = "secretEnv"): Promise<SecretValue[]> {
  if (!refs?.length) return [];
  if (!ctx.resolveCredential) throw new Error(`This context cannot resolve vault items, so ${label} is unavailable here.`);
  const out: SecretValue[] = [];
  for (const [idx, r] of refs.entries()) {
    let cred: Credential;
    try {
      // `fresh`: a secret about to be injected must never come from a stale
      // offline cache (a renamed item once served its old value through a whole
      // deploy cycle). Bounded — an outage degrades to cache. One sync (before
      // the first lookup) refreshes the cache for all of them.
      cred = await ctx.resolveCredential(r.credentialRef, { fresh: idx === 0 });
    } catch (e) {
      throw new Error(`${label} '${r.name}': cannot read vault item '${r.credentialRef}' — ${e instanceof Error ? e.message : String(e)}`);
    }
    const value = pickCredentialField(cred, r.field);
    if (value === undefined || value === "") {
      throw new Error(
        `${label} '${r.name}': vault item '${r.credentialRef}' has no value for field '${r.field ?? "password/secret/token"}'. ` +
          `Store it on that item (or name a different field) — never paste the secret into chat.`,
      );
    }
    out.push({ name: r.name, value });
  }
  return out;
}

/** Keyed-fingerprint function, as handed to a tool via `ToolContext.fingerprint`. */
export type Fingerprinter = (value: string) => Promise<string>;

/**
 * Trailing block for a result: one `NAME: len=<n> fp=<hex>` line per injected
 * secret, so what landed can be checked against the vault in seconds without
 * either value being shown. Empty (never a value echo) with no fingerprinter.
 */
export async function secretFingerprintBlock(secrets: SecretValue[], fp?: Fingerprinter): Promise<string> {
  if (!fp || !secrets.length) return "";
  const lines: string[] = [];
  for (const e of secrets) {
    try {
      lines.push(`  ${e.name}: ${await fp(e.value)}`);
    } catch {
      lines.push(`  ${e.name}: (fingerprint unavailable)`);
    }
  }
  return `\nSecret fingerprints (compare with the vault's via credential_request_status):\n${lines.join("\n")}`;
}

/** Confirm-text fragment naming a secret ref's source, never its value. */
export function describeSecretRef(r: SecretRef): string {
  return `${r.name}←vault:${r.credentialRef}${r.field ? `.${r.field}` : ""}`;
}
