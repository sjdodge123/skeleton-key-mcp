import { isIPv4, isIPv6 } from "node:net";

/**
 * Brute-force limits for the admin second factor and the master passphrase,
 * and a plain request limiter for the unauthenticated OAuth endpoints.
 *
 * In-memory by design: a restart resets every counter. Without boot
 * auto-unlock a restart also re-locks the vault, so there is no code to guess
 * until the admin unlocks. WITH auto-unlock the store comes back unlocked, so
 * a restart is a fresh budget — nothing on this surface lets a client cause
 * one, but a crash it could trigger would. Persisting the counters is a
 * possible follow-up.
 */

export interface LockoutPolicy {
  /** Failures within `windowMs` that start a lockout. */
  maxFailures: number;
  windowMs: number;
  /** The first lockout; each further one doubles it, up to `maxLockoutMs`. */
  baseLockoutMs: number;
  maxLockoutMs: number;
  /** Quiet time after a lockout ends before the doubling starts over. */
  resetAfterMs: number;
}

const MINUTE = 60_000;
const HOUR = 60 * MINUTE;

/**
 * The TOTP budget. A code is 6 digits and only the current 30-second step is
 * accepted, so every guess succeeds with probability 1e-6 however guesses are
 * spread across steps; the only lever is how many guesses an attacker gets.
 *
 * The global budget is the bound, because a LAN attacker can use as many
 * addresses as they like. It allows 10 wrong codes per 24 h before a lockout
 * of 1, 2, 4 … 128 minutes, then 4 hours for every further one. The doubling
 * only starts over after 48 h with no lockout running and no failure at all —
 * longer than the 24 h window, so guesses paced into the wait can't age out
 * just as the ladder resets. Pacing under the threshold yields 9 a day;
 * climbing the ladder and waiting out the reset about 41. The best strategy
 * is simply guessing whenever allowed, which settles at 10 per 4 h: ~60 a
 * day, ~22,000 a year — a 2.2% chance of success per year, ~45 years
 * expected (~31 years median). `attempt-limiter.test.ts` simulates these
 * strategies against this exact policy. Without the limiter, the whole code
 * space falls in well under an hour.
 *
 * The per-client budget (5 per 15 min) cuts a single noisy address off first
 * and gives the admin a short, local lockout for a run of typos; the numbers
 * above do not rest on it.
 */
export const TOTP_LIMITS = {
  client: { maxFailures: 5, windowMs: 15 * MINUTE, baseLockoutMs: MINUTE, maxLockoutMs: 4 * HOUR, resetAfterMs: 24 * HOUR },
  global: { maxFailures: 10, windowMs: 24 * HOUR, baseLockoutMs: MINUTE, maxLockoutMs: 4 * HOUR, resetAfterMs: 48 * HOUR },
} as const satisfies { client: LockoutPolicy; global: LockoutPolicy };

/**
 * The master-passphrase budget on `/api/store/unlock`, counted separately from
 * TOTP. Guessing a passphrase is already hopeless at argon2 speed; this mainly
 * bounds the argon2 work (~1 s of CPU each) an unauthenticated LAN client can
 * demand, and refuses during a lockout without deriving anything.
 */
export const PASSPHRASE_LIMITS = TOTP_LIMITS;

export type LimitScope = "client" | "global";

/** Why an attempt may not be made right now. */
export interface Refusal {
  scope: LimitScope;
  retryAfterMs: number;
}

/** A lockout that a failure just started. */
export interface Lockout {
  scope: LimitScope;
  durationMs: number;
  /** Failures that triggered it (the policy's `maxFailures`). */
  failures: number;
}

interface Bucket {
  /** Timestamps of failures still inside the window, oldest first. */
  failures: number[];
  lockedUntil: number;
  /** Lockouts so far in this escalation run. */
  level: number;
  /** When the last failure was recorded (0 = never). */
  lastFailureAt: number;
}

/**
 * Counts FAILED attempts — not requests — against a per-client and a global
 * budget. The caller asks `blocked()` before evaluating anything and must not
 * evaluate the attempt when it returns a refusal; then reports the outcome
 * with `fail()` or `succeed()`. Everything is synchronous, so a burst of
 * parallel requests can't slip past the check between two awaits.
 */
export class AttemptLimiter {
  private readonly global: Bucket = { failures: [], lockedUntil: 0, level: 0, lastFailureAt: 0 };
  private readonly clients = new Map<string, Bucket>();
  private readonly now: () => number;
  private readonly maxClients: number;

  constructor(
    private readonly policy: { client: LockoutPolicy; global: LockoutPolicy },
    opts: { maxClients?: number; now?: () => number } = {},
  ) {
    this.now = opts.now ?? (() => Date.now());
    this.maxClients = opts.maxClients ?? 1024;
  }

  /** The active lockout covering `client`, or null. Consumes no budget. */
  blocked(client: string): Refusal | null {
    const now = this.now();
    const g = this.global.lockedUntil - now;
    const c = (this.clients.get(client)?.lockedUntil ?? 0) - now;
    if (g <= 0 && c <= 0) return null;
    return g >= c ? { scope: "global", retryAfterMs: g } : { scope: "client", retryAfterMs: c };
  }

  /** Record a wrong attempt. Returns the lockouts it started (none, one, or both scopes). */
  fail(client: string): Lockout[] {
    const now = this.now();
    let bucket = this.clients.get(client);
    if (!bucket) {
      this.makeRoom(now);
      bucket = { failures: [], lockedUntil: 0, level: 0, lastFailureAt: 0 };
      this.clients.set(client, bucket);
    }
    const started: Lockout[] = [];
    const c = this.record(bucket, this.policy.client, now);
    if (c) started.push({ scope: "client", ...c });
    const g = this.record(this.global, this.policy.global, now);
    if (g) started.push({ scope: "global", ...g });
    return started;
  }

  /**
   * A correct attempt: forget this client's failures and escalation. The
   * global window is left to age out — resetting it would hand an attacker a
   * fresh budget every time the admin signs in.
   */
  succeed(client: string): void {
    this.clients.delete(client);
  }

  private record(b: Bucket, p: LockoutPolicy, now: number): Omit<Lockout, "scope"> | null {
    if (b.level > 0 && now - lastActivity(b) >= p.resetAfterMs) b.level = 0;
    b.lastFailureAt = now;
    b.failures = b.failures.filter((t) => now - t < p.windowMs);
    b.failures.push(now);
    if (b.failures.length < p.maxFailures) return null;
    const durationMs = Math.min(p.baseLockoutMs * 2 ** b.level, p.maxLockoutMs);
    b.lockedUntil = now + durationMs;
    b.level++;
    b.failures = [];
    return { durationMs, failures: p.maxFailures };
  }

  /** Keep the client map bounded: drop idle entries, then the oldest. The
   *  global bucket still holds, so evicting an attacker's entry gains nothing. */
  private makeRoom(now: number): void {
    if (this.clients.size < this.maxClients) return;
    const p = this.policy.client;
    for (const [key, b] of this.clients) {
      const idle = b.lockedUntil <= now && b.failures.every((t) => now - t >= p.windowMs);
      if (idle && (b.level === 0 || now - lastActivity(b) >= p.resetAfterMs)) this.clients.delete(key);
    }
    while (this.clients.size >= this.maxClients) {
      const oldest = this.clients.keys().next().value;
      if (oldest === undefined) break;
      this.clients.delete(oldest);
    }
  }
}

/** The escalation only resets after `resetAfterMs` with no lockout running
 *  AND no failure at all — guesses made while waiting restart the wait. */
function lastActivity(b: Bucket): number {
  return Math.max(b.lockedUntil, b.lastFailureAt);
}

/**
 * Fixed-window request counter per key, for endpoints that need no secret
 * (OAuth registration and token). `hit` returns 0 when the request may
 * proceed, else the milliseconds until the window resets.
 */
export class RequestLimiter {
  private readonly windows = new Map<string, { start: number; count: number }>();
  private readonly now: () => number;
  private readonly maxKeys: number;

  constructor(
    private readonly max: number,
    private readonly windowMs: number,
    opts: { maxKeys?: number; now?: () => number } = {},
  ) {
    this.now = opts.now ?? (() => Date.now());
    this.maxKeys = opts.maxKeys ?? 1024;
  }

  hit(key: string): number {
    const now = this.now();
    let w = this.windows.get(key);
    if (!w || now - w.start >= this.windowMs) {
      if (!w && this.windows.size >= this.maxKeys) {
        for (const [k, v] of this.windows) if (now - v.start >= this.windowMs) this.windows.delete(k);
        while (this.windows.size >= this.maxKeys) {
          const oldest = this.windows.keys().next().value;
          if (oldest === undefined) break;
          this.windows.delete(oldest);
        }
      }
      w = { start: now, count: 0 };
      this.windows.set(key, w);
    }
    if (w.count >= this.max) return w.start + this.windowMs - now;
    w.count++;
    return 0;
  }
}

/**
 * The key a client is counted under: its IPv4 address, or its IPv6 /64 — a
 * single LAN host can pick any address in its /64, so counting full IPv6
 * addresses would give it 2^64 budgets. IPv4-mapped IPv6 reads as the IPv4.
 */
export function clientKey(ip: string | undefined): string {
  if (!ip) return "unknown";
  const bare = ip.replace(/%.*$/, "");
  const mapped = /^::ffff:(\d+\.\d+\.\d+\.\d+)$/i.exec(bare);
  if (mapped) return mapped[1]!;
  if (isIPv4(bare)) return bare;
  if (!isIPv6(bare)) return "unknown";
  const [head = "", tail] = bare.split("::");
  const headParts = head ? head.split(":") : [];
  const tailParts = tail === undefined ? [] : tail ? tail.split(":") : [];
  // An embedded IPv4 tail counts as two groups; it only ever sits past the /64.
  const tailGroups = tailParts.reduce((n, p) => n + (p.includes(".") ? 2 : 1), 0);
  const groups = [...headParts, ...Array<string>(Math.max(0, 8 - headParts.length - tailGroups)).fill("0"), ...tailParts];
  return `${groups
    .slice(0, 4)
    .map((g) => (parseInt(g, 16) || 0).toString(16))
    .join(":")}::/64`;
}

/**
 * Coalesces refusals into at most one audit entry per `intervalMs`, so a
 * flood against a closed gate can't bloat the append-only log. Each entry
 * names the DISTINCT clients seen since the last one (the first few), so the
 * admin's own refused retry can't mask the address that caused the lockout.
 */
export class RefusalCoalescer {
  private pending = 0;
  private readonly clients = new Set<string>();
  private more = false;
  private lastAt = Number.NEGATIVE_INFINITY;

  constructor(
    private readonly intervalMs: number,
    private readonly maxClients = 5,
    private readonly now: () => number = () => Date.now(),
  ) {}

  /** Note one refusal. Returns what to write when an entry is due, else null. */
  note(client: string): { count: number; clients: string } | null {
    this.pending++;
    if (this.clients.size < this.maxClients) this.clients.add(client);
    else if (!this.clients.has(client)) this.more = true;
    const now = this.now();
    if (now - this.lastAt < this.intervalMs) return null;
    const out = { count: this.pending, clients: [...this.clients].join(", ") + (this.more ? ", …" : "") };
    this.pending = 0;
    this.clients.clear();
    this.more = false;
    this.lastAt = now;
    return out;
  }
}
