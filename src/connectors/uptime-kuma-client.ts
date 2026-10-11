import { io, type Socket } from "socket.io-client";
import { isPrivateIPv4 } from "./net.js";

/**
 * Minimal Uptime Kuma client.
 *
 * Uptime Kuma has no REST API for monitor control — its only management surface
 * is the socket.io channel its own web UI uses (`/metrics` and the API keys that
 * guard it are Prometheus-only). The event names below are the server's own
 * (`server/server.js`) and match what the community `uptime-kuma-api` Python
 * library documents: `login` → a `monitorList` push → `pauseMonitor(id)` /
 * `resumeMonitor(id)` / `getMonitorBeats(id, hours)`, each acknowledged with
 * `{ ok, msg? }`.
 *
 * One session per tool call: connect, log in, do the work, disconnect. Nothing
 * is cached across calls, and the password is used exactly once — in the `login`
 * payload — and never appears in an error, a result or a log.
 *
 * **2FA.** A Kuma account with TOTP enabled answers `login` with
 * `{ tokenRequired: true }`. This client supports 2FA-less accounts only and
 * turns that reply into a clear error rather than prompting for a code (there
 * is nowhere a code could come from without a secret transiting the chat).
 */

export interface KumaTag {
  name: string;
  value: string;
}

export interface KumaMonitor {
  id: number;
  name: string;
  type?: string;
  url?: string;
  hostname?: string;
  port?: number;
  /** false = paused (Kuma's `active`, normalised from 0/1/boolean). */
  active: boolean;
  /** Kuma marks a child inactive when its group is paused. */
  forceInactive: boolean;
  /** Under a Kuma maintenance window right now. */
  maintenance: boolean;
  parent: number | null;
  tags: KumaTag[];
}

export interface KumaBeat {
  /** 0 DOWN · 1 UP · 2 PENDING · 3 MAINTENANCE */
  status: number;
  time: string;
  msg?: string;
  ping?: number | null;
  important?: boolean;
  duration?: number;
}

export const BEAT_STATUS: Record<number, string> = { 0: "DOWN", 1: "UP", 2: "PENDING", 3: "MAINTENANCE" };

export interface KumaConnectOptions {
  baseUrl: string;
  username: string;
  password: string;
  insecureTLS?: boolean;
  /** Connect and per-ack timeout. */
  timeoutMs?: number;
}

export const DEFAULT_TIMEOUT_MS = 15_000;

/** How long to wait for the post-login `monitorList` push before asking for it. */
export const LIST_PUSH_GRACE_MS = 1_500;

/**
 * Where the Kuma password may be sent in clear. Same posture as the Pelican key
 * rule: https anywhere; plain http only to a LAN/loopback literal. Also refuses
 * a URL with embedded userinfo — the login belongs in the vault item, not the
 * target's options. Exported for testing.
 */
export function assertKumaTransportOk(base: string): URL {
  let url: URL;
  try {
    url = new URL(base);
  } catch {
    throw new Error(`Invalid Uptime Kuma URL '${base}'.`);
  }
  if (url.username || url.password) {
    throw new Error("The Uptime Kuma baseUrl must not embed credentials — the login belongs in the target's vault item.");
  }
  if (url.protocol === "https:") return url;
  if (url.protocol !== "http:") throw new Error(`Unsupported Uptime Kuma scheme '${url.protocol}' — use http (LAN only) or https.`);
  const h = url.hostname;
  if (!isPrivateIPv4(h) && h !== "localhost" && h !== "127.0.0.1" && h !== "[::1]") {
    throw new Error(
      `Refusing to send the Uptime Kuma password over plain http to '${h}' — that host is not a private LAN address. Use https (e.g. the tunnelled URL) or the instance's LAN IP.`,
    );
  }
  return url;
}

function toBool(v: unknown): boolean {
  return v === true || v === 1 || v === "1" || v === "true";
}
function optStr(v: unknown): string | undefined {
  return typeof v === "string" && v !== "" ? v : undefined;
}
function optNum(v: unknown): number | undefined {
  const n = typeof v === "number" ? v : typeof v === "string" && v !== "" ? Number(v) : NaN;
  return Number.isFinite(n) ? n : undefined;
}

/** Normalise one entry of Kuma's `monitorList` push. Exported for testing. */
export function normalizeMonitor(raw: unknown): KumaMonitor | null {
  if (!raw || typeof raw !== "object") return null;
  const r = raw as Record<string, unknown>;
  const id = optNum(r.id);
  if (id === undefined) return null;
  const tags: KumaTag[] = Array.isArray(r.tags)
    ? (r.tags as unknown[]).flatMap((t) => {
        if (!t || typeof t !== "object") return [];
        const tt = t as Record<string, unknown>;
        const name = optStr(tt.name) ?? "";
        const value = tt.value === null || tt.value === undefined ? "" : String(tt.value);
        return name || value ? [{ name, value }] : [];
      })
    : [];
  const parent = optNum(r.parent);
  return {
    id,
    name: optStr(r.name) ?? `#${id}`,
    type: optStr(r.type),
    url: optStr(r.url),
    hostname: optStr(r.hostname),
    port: optNum(r.port),
    // Kuma 1.x sends the raw column (0/1); 1.23+/2.x a boolean from isActive().
    active: toBool(r.active),
    forceInactive: toBool(r.forceInactive),
    maintenance: toBool(r.maintenance),
    parent: parent ?? null,
    tags,
  };
}

/** `name:value`, or just the name for a value-less tag. */
export function tagLabel(t: KumaTag): string {
  return t.value ? `${t.name}:${t.value}` : t.name;
}

/** Case/whitespace-insensitive comparison key. */
export function norm(s: string | undefined | null): string {
  return (s ?? "").trim().toLowerCase().replace(/\s+/g, " ");
}

/** The tag the owner puts on every monitor of a Pelican-managed game server. */
export const MANAGED_PELICAN_TAG = "managed:pelican";

export function isManagedByPelican(m: KumaMonitor): boolean {
  return m.tags.some((t) => norm(tagLabel(t)) === MANAGED_PELICAN_TAG);
}

/** The identities a Pelican server is known by. */
export interface ServerIdentity {
  name: string;
  identifier?: string;
  uuid?: string;
}

/**
 * Which monitors watch a Pelican server. Two ways in, both deliberate:
 *  - the monitor carries `managed:pelican` AND its name equals the server's
 *    name (the owner's convention — "Valheim" watches the server "Valheim"); or
 *  - a tag names the server explicitly: any tag whose VALUE is the server's
 *    short identifier or UUID (e.g. `server:f5eb47ac`), or the tag
 *    `server:<server name>` — which covers a monitor whose display name differs
 *    from the server's.
 * A tag value that merely equals the server's *name* is NOT enough (`wing:node`
 * says which node a monitor is on, not that it watches a server called "node").
 * A same-named monitor WITHOUT the managed tag is not matched either: the tag is
 * the opt-in that says "this monitor belongs to a game server Skeleton Key may
 * silence". `unmatchedSameName` reports those so the error can say exactly what
 * to tag. Exported for testing.
 */
export function monitorsForServer(monitors: KumaMonitor[], server: ServerIdentity): { matched: KumaMonitor[]; unmatchedSameName: KumaMonitor[] } {
  const ids = new Set([server.identifier, server.uuid].map(norm).filter((k) => k !== ""));
  const serverTag = `server:${norm(server.name)}`;
  const matched: KumaMonitor[] = [];
  const unmatchedSameName: KumaMonitor[] = [];
  for (const m of monitors) {
    const sameName = norm(m.name) === norm(server.name);
    const taggedForServer = m.tags.some((t) => ids.has(norm(t.value)) || norm(tagLabel(t)) === serverTag);
    if ((sameName && isManagedByPelican(m)) || taggedForServer) matched.push(m);
    else if (sameName) unmatchedSameName.push(m);
  }
  return { matched, unmatchedSameName };
}

/** A monitor URL with userinfo and query VALUES removed — a keyword monitor's
 *  URL can carry an API key, and a push URL a token. Exported for testing. */
export function redactMonitorUrl(u: string | undefined): string | undefined {
  if (!u) return undefined;
  try {
    const url = new URL(u);
    url.username = "";
    url.password = "";
    const keys = [...url.searchParams.keys()];
    url.search = "";
    return `${url.origin}${url.pathname}${keys.length ? `?${keys.map((k) => `${k}=…`).join("&")}` : ""}`;
  } catch {
    return "(unparseable url)";
  }
}

type Ack<T> = T & { ok?: boolean; msg?: string };

/**
 * One logged-in socket.io session. Create with `KumaSession.connect`, always
 * `close()` it (or use `withKuma`). Listeners for the server's pushes
 * (`monitorList`, `heartbeatList`) are registered BEFORE `login` is sent,
 * because the real server emits them from `afterLogin` without waiting for the
 * login ack to be delivered — they can arrive first.
 */
export class KumaSession {
  private monitorList: Record<string, unknown> | null = null;
  private listWaiters: ((list: Record<string, unknown>) => void)[] = [];
  private readonly heartbeats = new Map<number, KumaBeat[]>();
  private readonly baseUrl: string;

  private constructor(
    private readonly socket: Socket,
    private readonly timeoutMs: number,
    baseUrl: string,
  ) {
    this.baseUrl = baseUrl;
    socket.on("monitorList", (list: unknown) => {
      if (!list || typeof list !== "object") return;
      this.monitorList = list as Record<string, unknown>;
      const waiters = this.listWaiters;
      this.listWaiters = [];
      for (const w of waiters) w(this.monitorList);
    });
    socket.on("heartbeatList", (monitorID: unknown, list: unknown, overwrite: unknown) => {
      const id = optNum(monitorID);
      if (id === undefined || !Array.isArray(list)) return;
      const beats = list as KumaBeat[];
      const prev = overwrite ? [] : (this.heartbeats.get(id) ?? []);
      this.heartbeats.set(id, [...prev, ...beats].slice(-100));
    });
  }

  static async connect(opts: KumaConnectOptions): Promise<KumaSession> {
    const url = assertKumaTransportOk(opts.baseUrl);
    const timeoutMs = opts.timeoutMs ?? DEFAULT_TIMEOUT_MS;
    // Origin only: to socket.io-client a URL *path* is a namespace, and Kuma
    // serves from the root of its own host (it does not support sub-path
    // hosting), mounting socket.io at the default path.
    const socket = io(url.origin, {
      // WebSocket first (one round trip, works through Cloudflare);
      // long-polling is the fallback.
      path: "/socket.io",
      transports: ["websocket", "polling"],
      tryAllTransports: true,
      reconnection: false,
      forceNew: true,
      timeout: timeoutMs,
      // Per-target opt-in for a self-signed LAN cert — never process-global.
      rejectUnauthorized: !opts.insecureTLS,
    });
    const session = new KumaSession(socket, timeoutMs, opts.baseUrl);
    try {
      await session.waitConnected();
      await session.login(opts.username, opts.password);
    } catch (e) {
      session.close();
      throw e;
    }
    return session;
  }

  private waitConnected(): Promise<void> {
    return new Promise<void>((resolve, reject) => {
      const timer = setTimeout(() => {
        cleanup();
        reject(new Error(`Timed out after ${this.timeoutMs}ms connecting to Uptime Kuma at ${this.baseUrl}.`));
      }, this.timeoutMs);
      const onConnect = (): void => {
        cleanup();
        resolve();
      };
      const onError = (err: Error & { description?: unknown }): void => {
        cleanup();
        const desc = err.description instanceof Error ? ` (${err.description.message})` : "";
        reject(new Error(`Could not connect to Uptime Kuma at ${this.baseUrl}: ${err.message}${desc}.`));
      };
      const cleanup = (): void => {
        clearTimeout(timer);
        this.socket.off("connect", onConnect);
        this.socket.off("connect_error", onError);
      };
      this.socket.on("connect", onConnect);
      this.socket.on("connect_error", onError);
    });
  }

  /** Emit with an ack, bounded by the session timeout. Never includes the
   *  event's arguments in an error — `login` carries the password. */
  private async ack<T>(event: string, ...args: unknown[]): Promise<Ack<T>> {
    try {
      return (await this.socket.timeout(this.timeoutMs).emitWithAck(event, ...args)) as Ack<T>;
    } catch {
      throw new Error(`Uptime Kuma at ${this.baseUrl} did not answer '${event}' within ${this.timeoutMs}ms.`);
    }
  }

  private async login(username: string, password: string): Promise<void> {
    // No `token` key: the server treats a present-but-empty one as "no code"
    // anyway, and omitting it keeps the payload to exactly what is needed.
    const res = await this.ack<{ tokenRequired?: boolean; token?: string }>("login", { username, password });
    if (res.tokenRequired) {
      throw new Error(
        "This Uptime Kuma account has two-factor authentication enabled. Skeleton Key's Uptime Kuma connector supports 2FA-less accounts only " +
          "(a TOTP code would have to transit the chat, which is never allowed). Either disable 2FA on the account Skeleton Key logs in with, " +
          "or point the target's credentialRef at a dedicated Kuma account without 2FA.",
      );
    }
    if (!res.ok) {
      // Kuma's own text: "Incorrect username or password." / "Too frequently, try again later."
      throw new Error(`Uptime Kuma rejected the login: ${res.msg ?? "no reason given"}. Check the vault item's username/password (overwrite it via request_credential; never paste it in chat).`);
    }
  }

  private waitForList(ms: number): Promise<Record<string, unknown> | null> {
    if (this.monitorList) return Promise.resolve(this.monitorList);
    return new Promise((resolve) => {
      const timer = setTimeout(() => {
        this.listWaiters = this.listWaiters.filter((w) => w !== waiter);
        resolve(null);
      }, ms);
      const waiter = (list: Record<string, unknown>): void => {
        clearTimeout(timer);
        resolve(list);
      };
      this.listWaiters.push(waiter);
    });
  }

  /**
   * Every monitor, from the server's `monitorList` push. The real server sends
   * one right after login; if it has not arrived shortly, `getMonitorList` asks
   * for it (the list still arrives as an event, not in the ack). After a pause
   * or resume the server re-pushes the list, so a later call sees fresh state.
   */
  async monitors(): Promise<KumaMonitor[]> {
    let list = await this.waitForList(LIST_PUSH_GRACE_MS);
    if (!list) {
      const pending = this.waitForList(this.timeoutMs);
      // The ack is `{ok:true}` on every version that has one; the list itself
      // comes as an event, so the ack is not awaited on the critical path.
      void this.ack<Record<string, never>>("getMonitorList").catch(() => undefined);
      list = await pending;
    }
    if (!list) throw new Error(`Uptime Kuma at ${this.baseUrl} never sent its monitor list.`);
    return Object.values(list)
      .map(normalizeMonitor)
      .filter((m): m is KumaMonitor => m !== null)
      .sort((a, b) => a.id - b.id);
  }

  async pause(id: number): Promise<void> {
    const res = await this.ack<Record<string, never>>("pauseMonitor", id);
    if (!res.ok) throw new Error(`Uptime Kuma refused to pause monitor ${id}: ${res.msg ?? "no reason given"}`);
  }

  async resume(id: number): Promise<void> {
    const res = await this.ack<Record<string, never>>("resumeMonitor", id);
    if (!res.ok) throw new Error(`Uptime Kuma refused to resume monitor ${id}: ${res.msg ?? "no reason given"}`);
  }

  /** Heartbeats for one monitor over the last `hours` (oldest first). Falls back
   *  to the login-time `heartbeatList` push on a server without `getMonitorBeats`. */
  async beats(id: number, hours = 24): Promise<KumaBeat[]> {
    try {
      const res = await this.ack<{ data?: KumaBeat[] }>("getMonitorBeats", id, hours);
      if (res.ok && Array.isArray(res.data)) return res.data;
      if (res.ok === false && res.msg) throw new Error(`Uptime Kuma could not return heartbeats for monitor ${id}: ${res.msg}`);
    } catch (e) {
      if (!this.heartbeats.has(id)) throw e;
    }
    return this.heartbeats.get(id) ?? [];
  }

  close(): void {
    this.socket.removeAllListeners();
    this.socket.disconnect();
  }
}

/** Connect, run `fn`, and always disconnect. */
export async function withKuma<T>(opts: KumaConnectOptions, fn: (s: KumaSession) => Promise<T>): Promise<T> {
  const s = await KumaSession.connect(opts);
  try {
    return await fn(s);
  } finally {
    s.close();
  }
}
