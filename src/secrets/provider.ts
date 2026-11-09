import type { Credential } from "./types.js";
import { UserFacingError } from "../lib/errors.js";

/**
 * The secrets backend a deployment reads homelab credentials from. Vaultwarden
 * (`src/secrets/vaultwarden-provider.ts`) is the first implementation; anything
 * else that can hold infrastructure credentials can back a deployment by
 * implementing this interface.
 *
 * SECURITY CONTRACT — every implementation must hold all of these, and its
 * module doc must say HOW (see "Secrets providers" in docs/ARCHITECTURE.md):
 *
 * 1. **Scoping.** The identity the provider authenticates as can read ONLY the
 *    homelab's infrastructure secrets, never the operator's personal ones, and
 *    that boundary is enforced by the backend (an org/collection key, a policy,
 *    a separate file), not by filtering in this process. `list` returning
 *    something outside that scope is a bug in the provider, not in a caller.
 * 2. **Values stay in memory.** A secret value is returned only inside a
 *    `Credential` from `get` / `resolveById`. It never appears in argv, a log
 *    line, an error message, a thrown error's properties, an audit entry, or
 *    anything `list` / `resolveRef` / `create` / `update` / `delete` return.
 * 3. **Failures are describable without values.** `describeFailure` turns any
 *    error this provider throws into a fixed summary safe for an HTTP client.
 * 4. **Resolution is unambiguous or refused.** A ref resolves to exactly one
 *    live item or throws; an ambiguous match is an error, never a guess, and a
 *    deleted/trashed item never satisfies a ref.
 * 5. **The scope never widens at runtime.** No method takes a scope, account,
 *    or collection argument from a caller.
 * 6. **Offline behaviour is stated.** The module doc says what happens when
 *    the backend is unreachable (serve a cache, or fail closed).
 */
export interface SecretsProvider {
  /** Stable machine id of the backend, e.g. "vaultwarden". */
  readonly kind: string;
  /** Human name for messages, e.g. "Vaultwarden". */
  readonly label: string;
  /** True when credentials can be read right now (connected / unlocked).
   *  `AppState.locked` is true whenever this is false. */
  readonly ready: boolean;

  /** Read a credential by its human-facing ref (an item name). `fresh` asks the
   *  provider to refresh any local cache first, best-effort and time-bounded;
   *  a provider with no cache treats it as a no-op. */
  get(ref: string, opts?: ReadOptions): Promise<Credential>;
  /** Read a credential by its immutable id (a target's pinned `credentialId`):
   *  match the id only, never a name, so a rename or a same-named duplicate
   *  can't be served in its place. */
  resolveById(id: string, opts?: ReadOptions): Promise<Credential>;
  /** Resolve a ref to its canonical identity WITHOUT returning the secret —
   *  used to pin `credentialId` at registration and to find a deletion's
   *  dependents. A provider without separate ids returns the name as the id. */
  resolveRef(ref: string): Promise<SecretIdentity>;
  /** Names of every item in scope. Names only — never a value. */
  list(): Promise<string[]>;

  /** Create a new item. Refuses a name that already exists. */
  create?(item: NewSecretItem): Promise<{ name: string }>;
  /** Re-fill an existing item in place: the listed username / password /
   *  fields (by name) are replaced, everything else is kept. */
  update?(ref: string, patch: SecretItemPatch): Promise<SecretIdentity>;
  /** Delete an item by ref. */
  delete?(ref: string): Promise<{ name: string }>;
  /** Refresh any local cache from the backend. */
  sync?(): Promise<void>;

  /** A fixed, value-free summary of an error this provider threw, safe to show
   *  an HTTP client (contract item 3). */
  describeFailure(err: unknown): string;
}

export interface ReadOptions {
  /** Refresh the provider's cache first (bounded, best-effort) — for values
   *  about to be injected into a deploy. */
  fresh?: boolean;
}

export interface SecretIdentity {
  id: string;
  name: string;
}

export interface SecretField {
  name: string;
  value: string;
  /** Store as a concealed field when the backend distinguishes them. */
  hidden?: boolean;
}

/** A new login-shaped item. Where it lands is the provider's own configured
 *  scope — never a caller's choice (contract item 5). */
export interface NewSecretItem {
  name: string;
  username?: string;
  password?: string;
  url?: string;
  notes?: string;
  fields?: SecretField[];
}

export interface SecretItemPatch {
  username?: string;
  password?: string;
  fields?: SecretField[];
}

/** The optional capabilities a provider may implement. */
export const SECRETS_CAPABILITIES = ["create", "update", "delete", "sync"] as const;
export type SecretsCapability = (typeof SECRETS_CAPABILITIES)[number];

/** The optional capabilities this provider implements, derived from the methods
 *  it actually has so the list can't drift from the implementation. */
export function capabilitiesOf(provider: SecretsProvider): SecretsCapability[] {
  return SECRETS_CAPABILITIES.filter((c) => typeof provider[c] === "function");
}

/** True when the provider implements `cap`. */
export function hasCapability(provider: SecretsProvider, cap: SecretsCapability): boolean {
  return typeof provider[cap] === "function";
}

const WHAT: Record<SecretsCapability, string> = {
  create: "create vault items",
  update: "update vault items in place",
  delete: "delete vault items",
  sync: "refresh its cache",
};

/**
 * The provider's `cap` method, bound, or a clear refusal when the configured
 * provider doesn't implement it — so a write tool on a read-only provider says
 * what is missing and what to do instead of failing on `undefined is not a
 * function`. Call it BEFORE any side effect (key generation, link minting).
 */
export function requireCapability<C extends SecretsCapability>(
  provider: SecretsProvider,
  cap: C,
): NonNullable<SecretsProvider[C]> {
  const fn = provider[cap];
  if (typeof fn !== "function") {
    throw new UserFacingError(
      `The configured secrets provider (${provider.label}) cannot ${WHAT[cap]}. ` +
        `Make this change in ${provider.label} directly, then refer to the item by name.`,
      409,
    );
  }
  return (fn as (...args: never[]) => unknown).bind(provider) as NonNullable<SecretsProvider[C]>;
}
