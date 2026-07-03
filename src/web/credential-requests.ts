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

export interface CredentialRequest {
  id: string;
  name: string; // vault item name to create (also the future credentialRef)
  host: string;
  username?: string;
  kind: CredentialKind;
  reason: string;
  createdAt: number;
  status: RequestStatus;
  /** Set once fulfilled — the vault item name the agent can now register with. */
  fulfilledName?: string;
}

/** How long a request link stays valid. */
export const REQUEST_TTL_MS = 15 * 60 * 1000;
/** Backstop so a flood of requests can't grow the map without bound. */
const MAX_REQUESTS = 100;

export interface NewRequest {
  name: string;
  host: string;
  username?: string;
  kind: CredentialKind;
  reason: string;
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
    const req: CredentialRequest = {
      id: randomUUID(),
      name: input.name,
      host: input.host,
      username: input.username,
      kind: input.kind,
      reason: input.reason,
      createdAt: this.now(),
      status: "pending",
    };
    this.requests.set(req.id, req);
    return req;
  }

  /** Fetch a request, lazily transitioning a stale pending one to `expired`. */
  get(id: string): CredentialRequest | undefined {
    const req = this.requests.get(id);
    if (!req) return undefined;
    if (req.status === "pending" && this.now() - req.createdAt > REQUEST_TTL_MS) {
      req.status = "expired";
    }
    return req;
  }

  /** Mark a pending request fulfilled. Returns false if it isn't claimable
   *  (already used, declined, expired, or unknown) — enforces single-use. */
  fulfill(id: string): boolean {
    const req = this.get(id);
    if (!req || req.status !== "pending") return false;
    req.status = "fulfilled";
    req.fulfilledName = req.name;
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
      if (this.now() - req.createdAt > REQUEST_TTL_MS * 2) this.requests.delete(id);
    }
  }
}
