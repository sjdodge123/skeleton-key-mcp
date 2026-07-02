import type { VaultwardenClient } from "../secrets/vaultwarden.js";

export interface CheckResult {
  name: string;
  passed: boolean;
  detail: string;
}

/**
 * Automated safety checks run by the wizard after the vault connects. They prove
 * the two properties the whole security model rests on: the service account is
 * scoped to a single collection (can't read personal passwords), and reads keep
 * working while the vault is unlocked (durability).
 */
export async function verifyScoping(
  vault: VaultwardenClient,
  expectedCollection?: string,
): Promise<CheckResult[]> {
  const results: CheckResult[] = [];

  // 1. Exactly one organization membership.
  try {
    const orgs = await vault.listOrganizations();
    results.push({
      name: "Single organization membership",
      passed: orgs.length === 1,
      detail:
        orgs.length === 1
          ? `Member of exactly one org: "${orgs[0]!.name}".`
          : `Expected 1 org, found ${orgs.length}: ${orgs.map((o) => o.name).join(", ")}. ` +
            "The service account should belong ONLY to the Skeleton Key org.",
    });
  } catch (err) {
    results.push({ name: "Single organization membership", passed: false, detail: msg(err) });
  }

  // 2. Access limited to the expected collection.
  try {
    const collections = await vault.listCollections();
    const names = collections.map((c) => c.name);
    const scoped =
      collections.length === 1 &&
      (!expectedCollection || names[0] === expectedCollection);
    results.push({
      name: "Scoped to one collection",
      passed: scoped,
      detail: scoped
        ? `Access limited to a single collection: "${names[0]}".`
        : `Expected 1 collection${expectedCollection ? ` ("${expectedCollection}")` : ""}, ` +
          `found ${collections.length}: ${names.join(", ")}.`,
    });
  } catch (err) {
    results.push({ name: "Scoped to one collection", passed: false, detail: msg(err) });
  }

  // 3. At least one item is decryptable (proves the cache is usable).
  try {
    const names = await vault.listItemNames();
    results.push({
      name: "Credentials decryptable from cache",
      passed: names.length > 0,
      detail:
        names.length > 0
          ? `${names.length} credential item(s) available offline.`
          : "No items found. Add your homelab credentials to the collection.",
    });
  } catch (err) {
    results.push({ name: "Credentials decryptable from cache", passed: false, detail: msg(err) });
  }

  return results;
}

function msg(err: unknown): string {
  return err instanceof Error ? err.message : String(err);
}
