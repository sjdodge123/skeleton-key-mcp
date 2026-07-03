/** A credential resolved from the vault for a target. Shape is intentionally loose
 *  because different connectors need different fields. */
export interface Credential {
  /** The vault item name this came from. */
  ref: string;
  username?: string;
  password?: string;
  /** An explicit secret field — API token, long-lived token, or private key.
   *  Deliberately NOT the item's freeform notes (see getCredential): treating
   *  notes as a secret let a password login's notes be misread as a token/key. */
  secret?: string;
  /** The item's freeform notes, exposed separately from `secret`. */
  notes?: string;
  /** Arbitrary custom fields stored on the vault item. */
  fields: Record<string, string>;
  /** URIs stored on the item, if any. */
  uris: string[];
}

/** Skeleton Key's own bootstrap secrets — kept in the local encrypted store,
 *  distinct from the homelab credentials that live in Vaultwarden. */
export interface BootstrapSecrets {
  /** Vaultwarden service-account API key. */
  bwClientId?: string;
  bwClientSecret?: string;
  /** Service-account master password, used for `bw unlock`. */
  bwMasterPassword?: string;
  /** Internal LAN URL of the Vaultwarden server. */
  bwServerUrl?: string;
  /** Name of the collection Skeleton Key is scoped to. */
  bwCollectionName?: string;
  /** Static bearer token clients present to reach the MCP endpoint. */
  mcpBearerToken?: string;
  /** TOTP seed for the admin web UI (base32). */
  totpSecret?: string;
  /** Argon2id-hashed admin passphrase for the web UI (separate from the store key). */
  adminPassphraseHash?: string;
}
