import { describe, it, expect } from "vitest";
import { AttemptLimiter, RequestLimiter, TOTP_LIMITS, clientKey, type LockoutPolicy } from "./attempt-limiter.js";

const MIN = 60_000;
const HOUR = 60 * MIN;
const DAY = 24 * HOUR;

function clock(start = 1_000_000) {
  let t = start;
  return { now: () => t, advance: (ms: number) => (t += ms) };
}

const policy = (p: Partial<LockoutPolicy>): LockoutPolicy => ({
  maxFailures: 3,
  windowMs: 10 * MIN,
  baseLockoutMs: MIN,
  maxLockoutMs: 8 * MIN,
  resetAfterMs: HOUR,
  ...p,
});

describe("AttemptLimiter", () => {
  it("locks a client out after N failures, and the lockout expires", () => {
    const c = clock();
    const l = new AttemptLimiter({ client: policy({}), global: policy({ maxFailures: 100 }) }, { now: c.now });
    expect(l.fail("a")).toEqual([]);
    expect(l.fail("a")).toEqual([]);
    expect(l.blocked("a")).toBeNull();
    expect(l.fail("a")).toEqual([{ scope: "client", durationMs: MIN, failures: 3 }]);
    expect(l.blocked("a")).toEqual({ scope: "client", retryAfterMs: MIN });
    expect(l.blocked("b")).toBeNull(); // per-client: someone else is unaffected
    c.advance(MIN - 1);
    expect(l.blocked("a")?.retryAfterMs).toBe(1);
    c.advance(1);
    expect(l.blocked("a")).toBeNull();
  });

  it("a success resets the client's counter and escalation", () => {
    const c = clock();
    const l = new AttemptLimiter({ client: policy({}), global: policy({ maxFailures: 100 }) }, { now: c.now });
    l.fail("a");
    l.fail("a");
    l.succeed("a");
    expect(l.fail("a")).toEqual([]);
    expect(l.fail("a")).toEqual([]);
    expect(l.fail("a")).toHaveLength(1); // a full fresh budget, at the base duration
    c.advance(MIN);
    l.succeed("a");
    l.fail("a");
    l.fail("a");
    expect(l.fail("a")[0]?.durationMs).toBe(MIN); // escalation forgotten too
  });

  it("failures outside the window age out", () => {
    const c = clock();
    const l = new AttemptLimiter({ client: policy({}), global: policy({ maxFailures: 100 }) }, { now: c.now });
    l.fail("a");
    l.fail("a");
    c.advance(10 * MIN);
    expect(l.fail("a")).toEqual([]);
  });

  it("doubles each consecutive lockout up to the cap, and resets after a quiet period", () => {
    const c = clock();
    const l = new AttemptLimiter({ client: policy({ maxFailures: 1 }), global: policy({ maxFailures: 100 }) }, { now: c.now });
    const durations: number[] = [];
    for (let i = 0; i < 6; i++) {
      const [lock] = l.fail("a");
      durations.push(lock!.durationMs);
      c.advance(lock!.durationMs);
    }
    expect(durations).toEqual([MIN, 2 * MIN, 4 * MIN, 8 * MIN, 8 * MIN, 8 * MIN]);
    c.advance(HOUR - 1);
    expect(l.fail("a")[0]!.durationMs).toBe(8 * MIN); // not quiet long enough
    c.advance(8 * MIN + HOUR);
    expect(l.fail("a")[0]!.durationMs).toBe(MIN);
  });

  it("the global budget locks EVERY client out, however many addresses are used", () => {
    const c = clock();
    const l = new AttemptLimiter({ client: policy({}), global: policy({ maxFailures: 5 }) }, { now: c.now });
    for (let i = 0; i < 4; i++) expect(l.fail(`10.0.0.${i}`)).toEqual([]);
    expect(l.fail("10.0.0.99")).toEqual([{ scope: "global", durationMs: MIN, failures: 5 }]);
    expect(l.blocked("10.0.0.200")).toEqual({ scope: "global", retryAfterMs: MIN });
    // A success elsewhere does not lift a global lockout, nor refill the global window.
    l.succeed("10.0.0.200");
    expect(l.blocked("10.0.0.200")).not.toBeNull();
  });

  it("a client's success does not reset the global window", () => {
    const l = new AttemptLimiter({ client: policy({}), global: policy({ maxFailures: 3 }) }, { now: clock().now });
    l.fail("x");
    l.fail("y");
    l.succeed("x");
    expect(l.fail("z")).toEqual([{ scope: "global", durationMs: MIN, failures: 3 }]);
  });

  it("reports the longer lockout when both scopes are locked", () => {
    const c = clock();
    const l = new AttemptLimiter({ client: policy({ maxFailures: 1, baseLockoutMs: 5 * MIN }), global: policy({ maxFailures: 2 }) }, { now: c.now });
    l.fail("a");
    c.advance(5 * MIN);
    expect(l.fail("a").map((x) => x.scope)).toEqual(["client", "global"]);
    expect(l.blocked("a")).toEqual({ scope: "client", retryAfterMs: 8 * MIN }); // client doubled to 10, capped at 8
  });

  it("keeps the client map bounded", () => {
    const l = new AttemptLimiter({ client: policy({}), global: policy({ maxFailures: 1e9 }) }, { maxClients: 8, now: clock().now });
    for (let i = 0; i < 100; i++) l.fail(`c${i}`);
    expect((l as unknown as { clients: Map<string, unknown> }).clients.size).toBeLessThanOrEqual(8);
  });

  describe("TOTP_LIMITS arithmetic (the numbers in the PR and the module comment)", () => {
    /** Run an attacker strategy against the real policy for `days`, counting
     *  every code that gets evaluated (= every guess). Unlimited addresses. */
    function simulate(days: number, strategy: (l: AttemptLimiter, c: ReturnType<typeof clock>) => void): number {
      const c = clock();
      const l = new AttemptLimiter(TOTP_LIMITS, { now: c.now });
      let guesses = 0;
      let ip = 0;
      const end = c.now() + days * DAY;
      const guess = (): boolean => {
        const who = `198.51.100.${ip++ % 250}`; // a fresh address each time: per-client limits never bite
        if (l.blocked(who)) return false;
        guesses++;
        l.fail(who);
        return true;
      };
      while (c.now() < end) strategy(Object.assign(l, { guess }), c);
      return guesses;
    }
    type Sim = AttemptLimiter & { guess: () => boolean };

    it("greedy (guess whenever allowed) settles at the 4-hour cap: ≤ 60 guesses a day", () => {
      const days = 60;
      const n = simulate(days, (l, c) => {
        if (!(l as Sim).guess()) c.advance(1000);
      });
      // The ladder's first ~8 h give 80 extra; after that 10 per 4 h.
      expect(n / days).toBeLessThanOrEqual(62);
    });

    it("climb the ladder then wait out the reset: ≤ ~68 a day", () => {
      const days = 60;
      const n = simulate(days, (l, c) => {
        // 8 lockouts (1 … 128 min), then sit out the 24 h reset.
        for (let lockouts = 0; lockouts < 8; ) {
          if ((l as Sim).guess()) {
            if (l.blocked("probe")) lockouts++;
          } else c.advance(1000);
        }
        while (l.blocked("probe")) c.advance(1000);
        c.advance(DAY);
      });
      expect(n / days).toBeLessThanOrEqual(70);
    });

    it("pacing just under the threshold yields only 9 a day", () => {
      const days = 30;
      const n = simulate(days, (l, c) => {
        for (let i = 0; i < 9; i++) (l as Sim).guess();
        c.advance(DAY);
      });
      expect(n / days).toBeLessThanOrEqual(9);
    });

    it("≤ 70 guesses a day over a year is a < 3% chance against a 6-digit code", () => {
      const perYear = 70 * 365;
      const p = 1 - (1 - 1e-6) ** perYear;
      expect(p).toBeLessThan(0.03);
      expect(1e6 / perYear).toBeGreaterThan(35); // expected years to success
    });
  });
});

describe("RequestLimiter", () => {
  it("allows max per window per key, then reports the wait", () => {
    const c = clock();
    const r = new RequestLimiter(3, MIN, { now: c.now });
    expect([r.hit("a"), r.hit("a"), r.hit("a")]).toEqual([0, 0, 0]);
    expect(r.hit("a")).toBe(MIN);
    expect(r.hit("b")).toBe(0);
    c.advance(MIN);
    expect(r.hit("a")).toBe(0);
  });

  it("keeps the key map bounded", () => {
    const r = new RequestLimiter(1, MIN, { maxKeys: 4, now: clock().now });
    for (let i = 0; i < 50; i++) r.hit(`k${i}`);
    expect((r as unknown as { windows: Map<string, unknown> }).windows.size).toBeLessThanOrEqual(4);
  });
});

describe("clientKey", () => {
  it("keeps IPv4 as is and unwraps IPv4-mapped IPv6", () => {
    expect(clientKey("192.168.0.20")).toBe("192.168.0.20");
    expect(clientKey("::ffff:192.168.0.20")).toBe("192.168.0.20");
    expect(clientKey("::FFFF:10.0.0.1")).toBe("10.0.0.1");
  });

  it("counts IPv6 by /64, so a host can't rotate through its prefix", () => {
    expect(clientKey("2001:db8:1:2:aaaa:bbbb:cccc:dddd")).toBe("2001:db8:1:2::/64");
    expect(clientKey("2001:db8:1:2::1")).toBe("2001:db8:1:2::/64");
    expect(clientKey("2001:0db8:0001:0002:ffff::9")).toBe("2001:db8:1:2::/64");
    expect(clientKey("fe80::1%en0")).toBe("fe80:0:0:0::/64");
    expect(clientKey("::1")).toBe("0:0:0:0::/64");
    expect(clientKey("64:ff9b::192.0.2.1")).toBe("64:ff9b:0:0::/64");
  });

  it("maps anything unparseable to one shared key", () => {
    expect(clientKey(undefined)).toBe("unknown");
    expect(clientKey("")).toBe("unknown");
    expect(clientKey("not-an-ip")).toBe("unknown");
  });
});
