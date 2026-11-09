import { env } from "../config/paths.js";
import type { BootstrapStore } from "./bootstrap-store.js";
import type { SecretsBackend } from "./backend.js";
import { VaultwardenBackend } from "./vaultwarden-provider.js";
import { AgeFileBackend, validateRecipients } from "./age-file-provider.js";

/** The secrets backends a deployment can select with SKELETON_KEY_SECRETS_PROVIDER. */
export const SECRETS_PROVIDER_KINDS = ["vaultwarden", "age-file"] as const;
export type SecretsProviderKind = (typeof SECRETS_PROVIDER_KINDS)[number];

/**
 * The configured provider kind. Unset means `vaultwarden`, so existing
 * deployments are unchanged. Anything else unknown fails the boot loudly —
 * never a silent fallback to a different vault.
 */
export function selectedProviderKind(raw: string | undefined = env.secretsProvider): SecretsProviderKind {
  if (!raw) return "vaultwarden";
  if ((SECRETS_PROVIDER_KINDS as readonly string[]).includes(raw)) return raw as SecretsProviderKind;
  throw new Error(`SKELETON_KEY_SECRETS_PROVIDER must be one of: ${SECRETS_PROVIDER_KINDS.join(", ")}.`);
}

/**
 * Build the selected backend. Its connection settings are read from the
 * bootstrap store later (at unlock); only non-secret config is read here, and
 * a malformed value fails the boot.
 */
export async function createSecretsBackend(kind: SecretsProviderKind, store: BootstrapStore): Promise<SecretsBackend> {
  switch (kind) {
    case "vaultwarden":
      // The collection is read from the store at write time (it is locked at
      // construction). A write while the store is locked throws from `get()`
      // rather than falling back to "the only collection" — fail closed.
      return new VaultwardenBackend(undefined, () => store.get().bwCollectionName);
    case "age-file": {
      const recipients = env.ageRecipients;
      await validateRecipients(recipients);
      return new AgeFileBackend({ file: env.ageFile, recipients });
    }
  }
}
