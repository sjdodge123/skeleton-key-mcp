import { randomUUID } from "node:crypto";

/**
 * In-memory registry of pending credential hand-off requests (issue #18).
 *
 * The agent creates a request; the user opens a one-time link and types the
 * secret into a TOTP-gated web form served by Skeleton Key, which writes it
 * straight into the scoped vault. The secret therefore travels
 * browser → server → vault and never through the chat/MCP channel or the
 * model's context. This store holds only the *metadata* of a request — never
 * the secret value, which is written to the vault and discarded on submit.
 */

export type CredentialKind = "password" | "token";
export type RequestStatus = "pending" | "fulfilled" | "expired" | "declined";

/**
 * Shape constraints for one value. The Discord migration stored an OAuth2
 * Client Secret (32 chars, no dots) where a Bot Token (~70 chars, two dots) was
 * expected because the form had no way to say "that's not it" — these let the
 * agent describe the expected shape AND where to get it, and the form/server
 * refuse a value that doesn't match before anything reaches the vault.
 */
export interface FieldConstraints {
  /** Regex source, applied as a full match `^(?:pattern)$`. */
  pattern?: string;
  minLength?: number;
  maxLength?: number;
  /** Human text: expected shape and where to obtain the value. Never a value. */
  hint?: string;
}

/**
 * One named value in a multi-field request (e.g. migrating an app's env secrets:
 * DISCORD_BOT_TOKEN, SXM_USERNAME, SXM_PASSWORD). This is *metadata only* — the
 * name/label describe the input to render; the value the user types is written
 * straight to the vault and never stored here.
 */
export interface CredentialField extends FieldConstraints {
  /** Env-var style name; becomes the Vaultwarden custom-field name. */
  name: string;
  /** Optional human help text rendered next to the input. */
  label?: string;
  /** Masked input + hidden (secret) Vaultwarden field type. */
  secret: boolean;
}

/**
 * Optional pre-store probe: Skeleton Key sends the submitted value(s) to this
 * URL (templated into headers) and only stores them if the response status is
 * acceptable. Because this means the server WILL transmit the secret to `url`,
 * the host is shown to the human both in the approval prompt and on the form.
 */
export interface VerifySpec {
  method: "GET" | "POST";
  url: string;
  /** Header VALUES may contain `{{value}}` (single-secret) or `{{FIELD_NAME}}`. */
  headers?: Record<string, string>;
  /** Acceptable HTTP statuses; default any 2xx. */
  expectStatus?: number[];
  /** Probe timeout, capped at 15s. */
  timeoutMs?: number;
}

export type VerificationOutcome = "passed" | "failed" | "skipped";

export interface CredentialRequest {
  id: string;
  name: string; // vault item name to create (also the future credentialRef)
  host: string;
  username?: string;
  /** Single-secret mode. Undefined when `fields` is set (multi-field mode). */
  kind?: CredentialKind;
  /** Single-secret mode: shape constraints for the one value. */
  constraints?: FieldConstraints;
  /**
   * Multi-field mode: one link collects this whole named SET onto ONE vault
   * item. Metadata only — never any value the user types.
   */
  fields?: CredentialField[];
  reason: string;
  verify?: VerifySpec;
  /** Re-fill an existing vault item (same id) instead of creating a new one. */
  overwrite: boolean;
  createdAt: number;
  ttlMs: number;
  expiresAt: number;
  status: RequestStatus;
  /** CSRF token: rendered only in the same-origin form, required on POST so a
   *  blind cross-site POST (which can't read the page) can't act on the link. */
  formToken: string;
  /** Set once fulfilled — the vault item name the agent can now register with. */
  fulfilledName?: string;
  /** Outcome of the pre-store probe (set on fulfilment). */
  verification?: VerificationOutcome;
  /** Keyed `len=<n> fp=<8 hex>` per stored field (see src/lib/fingerprint.ts) —
   *  lets the agent compare against what a stack later reports WITHOUT the
   *  value ever being here. */
  fingerprints?: Record<string, string>;
}

/** Fallback link lifetime when `SKELETON_KEY_CREDENTIAL_TTL_MINUTES` is unset. */
export const DEFAULT_TTL_MINUTES = 30;
export const MIN_TTL_MINUTES = 5;
export const MAX_TTL_MINUTES = 240;
/** Default link lifetime in ms (kept for callers/tests that predate per-request TTLs). */
export const REQUEST_TTL_MS = DEFAULT_TTL_MINUTES * 60 * 1000;
/** Backstop so a flood of requests can't grow the map without bound. */
const MAX_REQUESTS = 100;

/** Default TTL in minutes: env override (clamped to the allowed range) or 30. */
export function defaultTtlMinutes(): number {
  const raw = Number(process.env.SKELETON_KEY_CREDENTIAL_TTL_MINUTES);
  if (!Number.isFinite(raw) || raw <= 0) return DEFAULT_TTL_MINUTES;
  return Math.min(MAX_TTL_MINUTES, Math.max(MIN_TTL_MINUTES, Math.floor(raw)));
}

export interface NewRequest {
  name: string;
  host: string;
  username?: string;
  /** Omit when `fields` is given — the two modes are mutually exclusive. */
  kind?: CredentialKind;
  constraints?: FieldConstraints;
  fields?: CredentialField[];
  reason: string;
  verify?: VerifySpec;
  overwrite?: boolean;
  /** Link lifetime; clamped to [MIN_TTL_MINUTES, MAX_TTL_MINUTES]. */
  ttlMinutes?: number;
}

/** Metadata-only view of a pending request for the admin "pending links" page. */
export interface PendingRequestSummary {
  id: string;
  name: string;
  host: string;
  reason: string;
  fields: string[];
  overwrite: boolean;
  verifyHost?: string;
  createdAt: number;
  expiresAt: number;
}

export class CredentialRequestStore {
  private readonly requests = new Map<string, CredentialRequest>();

  constructor(private readonly now: () => number = Date.now) {}

  create(input: NewRequest): CredentialRequest {
    this.prune();
    if (this.requests.size >= MAX_REQUESTS) {
      // Evict the oldest to bound memory.
      const oldest = [...this.requests.values()].sort((a, b) => a.createdAt - b.createdAt)[0];
      if (oldest) this.requests.delete(oldest.id);
    }
    const ttlMinutes = Math.min(MAX_TTL_MINUTES, Math.max(MIN_TTL_MINUTES, Math.floor(input.ttlMinutes ?? defaultTtlMinutes())));
    const ttlMs = ttlMinutes * 60 * 1000;
    const createdAt = this.now();
    const multi = Boolean(input.fields?.length);
    const req: CredentialRequest = {
      id: randomUUID(),
      name: input.name,
      host: input.host,
      username: input.username,
      kind: multi ? undefined : (input.kind ?? "password"),
      constraints: !multi && input.constraints ? { ...input.constraints } : undefined,
      // Copy the field metadata so a later mutation by the caller can't change
      // what the form renders / writes.
      fields: multi ? input.fields!.map((f) => ({ ...f })) : undefined,
      reason: input.reason,
      verify: input.verify
        ? { ...input.verify, headers: input.verify.headers ? { ...input.verify.headers } : undefined, expectStatus: input.verify.expectStatus?.slice() }
        : undefined,
      overwrite: Boolean(input.overwrite),
      createdAt,
      ttlMs,
      expiresAt: createdAt + ttlMs,
      status: "pending",
      formToken: randomUUID(),
    };
    this.requests.set(req.id, req);
    return req;
  }

  /** Fetch a request, lazily transitioning a stale pending one to `expired`. */
  get(id: string): CredentialRequest | undefined {
    const req = this.requests.get(id);
    if (!req) return undefined;
    if (req.status === "pending" && this.now() - req.createdAt > req.ttlMs) {
      req.status = "expired";
    }
    return req;
  }

  /** Pending (unexpired) requests, metadata only — for the admin page that lets
   *  the user find a link their chat UI failed to render. */
  list(): PendingRequestSummary[] {
    const out: PendingRequestSummary[] = [];
    for (const id of this.requests.keys()) {
      const req = this.get(id)!;
      if (req.status !== "pending") continue;
      out.push({
        id: req.id,
        name: req.name,
        host: req.host,
        reason: req.reason,
        fields: req.fields ? req.fields.map((f) => f.name) : [req.kind === "token" ? "token" : "password"],
        overwrite: req.overwrite,
        verifyHost: req.verify ? safeHost(req.verify.url) : undefined,
        createdAt: req.createdAt,
        expiresAt: req.expiresAt,
      });
    }
    return out.sort((a, b) => b.createdAt - a.createdAt);
  }

  /**
   * Atomically claim a pending request (pending → fulfilled), returning true for
   * exactly one caller — enforces single-use and closes the TOCTOU where two
   * concurrent submits both pass the pending check and both write to the vault.
   * The caller must `release()` if the subsequent vault write fails.
   */
  claim(id: string): boolean {
    const req = this.get(id);
    if (!req || req.status !== "pending") return false;
    req.status = "fulfilled";
    req.fulfilledName = req.name;
    return true;
  }

  /** Revert a claimed request to pending after a failed vault write, so the user
   *  can retry the same link. No-op unless the request is currently fulfilled. */
  release(id: string): boolean {
    const req = this.requests.get(id);
    if (!req || req.status !== "fulfilled") return false;
    req.status = "pending";
    req.fulfilledName = undefined;
    req.verification = undefined;
    req.fingerprints = undefined;
    return true;
  }

  /** Attach the fulfilment outcome (probe result + value fingerprints — never
   *  values) to a claimed request. */
  complete(id: string, meta: { verification: VerificationOutcome; fingerprints: Record<string, string> }): boolean {
    const req = this.requests.get(id);
    if (!req || req.status !== "fulfilled") return false;
    req.verification = meta.verification;
    req.fingerprints = { ...meta.fingerprints };
    return true;
  }

  decline(id: string): boolean {
    const req = this.get(id);
    if (!req || req.status !== "pending") return false;
    req.status = "declined";
    return true;
  }

  private prune(): void {
    for (const [id, req] of this.requests) {
      // Drop long-dead entries (well past TTL) regardless of terminal status.
      if (this.now() - req.createdAt > req.ttlMs * 2) this.requests.delete(id);
    }
  }
}

/** Hostname (+port) of a URL for display, or the raw string if it doesn't parse. */
export function safeHost(url: string): string {
  try {
    return new URL(url).host;
  } catch {
    return url;
  }
}
