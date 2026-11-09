import type { SecretsProvider } from "./provider.js";
import type { BootstrapSecrets } from "./types.js";

/** One wizard / status check. `detail` reaches the unauthenticated wizard
 *  API, so it must never carry a secret value or a raw backend message. */
export interface CheckResult {
  name: string;
  passed: boolean;
  detail: string;
}

/** What a backend's setup step hands back: the bootstrap-store patch to
 *  persist (only produced once the backend actually connected with it). */
export interface BackendSetupResult {
  patch: Partial<BootstrapSecrets>;
  /** Run after `patch` is persisted: any side effect that must not happen
   *  before the settings it depends on are safely saved (the age provider
   *  creating its file). Throws like `setup`. */
  finalize?: () => Promise<void>;
}

/**
 * The connection LIFECYCLE of a secrets backend: everything that isn't a
 * credential read or write. `AppState`, the setup wizard and the web routes
 * drive a backend only through this interface, so none of them needs to know
 * which vault is behind `AppState.secrets`.
 *
 * The backend's own credentials (an API key, an identity) live in the
 * libsodium bootstrap store; `connect`/`setup`/`repair` receive or return them
 * as store fields and never log or echo them. Failures are thrown as-is and
 * summarized by `provider.describeFailure` — except from `setup`, which wraps
 * a backend failure in a value-free `UserFacingError` itself so the wizard
 * route can tell "the vault said no" (400) from a local fault (logged 500).
 */
export interface SecretsBackend {
  /** The credential surface every consumer uses (`AppState.secrets`). */
  readonly provider: SecretsProvider;

  /** True when the bootstrap store holds this backend's saved settings. */
  configured(store: Readonly<BootstrapSecrets>): boolean;

  /** Re-establish the connection from saved settings — after every store
   *  unlock, and on an admin "reconnect". Throws when it can't; afterwards
   *  `provider.ready` says whether credentials are readable. */
  connect(store: Readonly<BootstrapSecrets>): Promise<void>;

  /** The wizard's connect step (and the post-setup connect for a newly
   *  selected backend; `store` holds any settings saved by an earlier run of
   *  the step): validate `input` against this backend's own schema
   *  (a `ZodError` the routes turn into a 400 naming fields, never values),
   *  connect with it, and return the store patch to persist. A backend
   *  failure is thrown as a `UserFacingError` carrying `describeFailure`. */
  setup(input: unknown, store: Readonly<BootstrapSecrets>): Promise<BackendSetupResult>;

  /** Scoping / durability checks against the live connection, shown by the
   *  wizard. Never throws: a failed probe is a failed check. */
  verify(store: Readonly<BootstrapSecrets>): Promise<CheckResult[]>;

  /** Optional, for backends reached over the network: re-point the saved
   *  connection at a new server URL (already validated as https by the route)
   *  using the saved credentials. Returns the patch to persist only once the
   *  backend is connected on it — a bad URL leaves the saved one untouched.
   *  A precondition refusal is a `UserFacingError`; a connection failure is
   *  thrown raw for `describeFailure`. */
  changeServer?(serverUrl: string, store: Readonly<BootstrapSecrets>): Promise<BackendSetupResult>;
}
