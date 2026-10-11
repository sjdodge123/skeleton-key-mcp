import { createServer, type Server as HttpServer } from "node:http";
import type { AddressInfo } from "node:net";
import { Server, type Socket } from "socket.io";

/**
 * A fake Uptime Kuma: a real socket.io server speaking the handful of events
 * the connector uses, with the same ack shapes as `server/server.js`:
 *
 *   login({username,password}, cb)   → {ok:true, token} | {ok:false, msg} | {tokenRequired:true}
 *   getMonitorList(cb)               → emits `monitorList`, cb({ok:true})
 *   pauseMonitor(id, cb)             → {ok:true, msg:"Paused Successfully."}   (+ re-emits monitorList)
 *   resumeMonitor(id, cb)            → {ok:true, msg:"Resumed Successfully."}  (+ re-emits monitorList)
 *   getMonitorBeats(id, hours, cb)   → {ok:true, data:[beats]}
 *
 * Like the real server it pushes `monitorList` and `heartbeatList` right after
 * a successful login, and refuses everything else with "You are not logged in."
 * `log` records every event in order so tests can assert sequencing (e.g. the
 * pause happened BEFORE the power action and the resume AFTER).
 */

export interface FakeMonitor {
  id: number;
  name: string;
  type?: string;
  url?: string | null;
  hostname?: string | null;
  port?: number | null;
  /** Kuma's column: 1 active, 0 paused (the fake sends it raw, like 1.x). */
  active: 0 | 1;
  tags?: { name: string; value?: string | null }[];
  parent?: number | null;
}

export interface FakeBeat {
  status: number;
  time: string;
  msg?: string;
  ping?: number | null;
  important?: boolean;
}

export interface FakeKumaOptions {
  username?: string;
  password?: string;
  /** Answer login with {tokenRequired:true} (an account with 2FA on). */
  twofa?: boolean;
  monitors?: FakeMonitor[];
  beats?: Record<number, FakeBeat[]>;
  /** How a pause/resume is announced: 1.x re-sends the whole `monitorList`;
   *  2.x pushes `updateMonitorIntoList` with just the changed monitor. */
  listUpdates?: "monitorList" | "updateMonitorIntoList";
}

export interface FakeKuma {
  url: string;
  port: number;
  monitors: Map<number, FakeMonitor>;
  /** Every event received, in order: "login", "pauseMonitor:12", "getMonitorBeats:12", … */
  log: string[];
  /** Set to make pause/resume of these ids answer {ok:false, msg}. */
  failPause: Set<number>;
  failResume: Set<number>;
  /** Count of socket connections seen. */
  connections: number;
  /** Count of socket disconnections seen — every connection must end in one. */
  disconnections: number;
  /** Sockets currently open on the server. */
  clientsCount(): number;
  close(): Promise<void>;
}

export async function startFakeKuma(opts: FakeKumaOptions = {}): Promise<FakeKuma> {
  const username = opts.username ?? "admin";
  const password = opts.password ?? "kuma-pass";
  const monitors = new Map<number, FakeMonitor>((opts.monitors ?? []).map((m) => [m.id, { ...m }]));
  const beats = opts.beats ?? {};
  const log: string[] = [];
  const failPause = new Set<number>();
  const failResume = new Set<number>();

  let closed = false;
  const http: HttpServer = createServer();
  const io = new Server(http, { path: "/socket.io" });
  const fake: FakeKuma = {
    url: "",
    port: 0,
    monitors,
    log,
    failPause,
    failResume,
    connections: 0,
    disconnections: 0,
    clientsCount: () => io.engine.clientsCount,
    close: async () => {
      if (closed) return;
      closed = true;
      io.disconnectSockets(true);
      await io.close();
      await new Promise<void>((resolve) => http.close(() => resolve()));
    },
  };

  const monitorList = (): Record<string, unknown> => {
    const out: Record<string, unknown> = {};
    for (const m of monitors.values()) {
      out[String(m.id)] = {
        id: m.id,
        name: m.name,
        type: m.type ?? "http",
        url: m.url ?? null,
        hostname: m.hostname ?? null,
        port: m.port ?? null,
        active: m.active,
        forceInactive: false,
        maintenance: false,
        parent: m.parent ?? null,
        tags: (m.tags ?? []).map((t, i) => ({ id: i + 1, monitor_id: m.id, tag_id: i + 1, name: t.name, value: t.value ?? "", color: "#000" })),
      };
    }
    return out;
  };

  const announce = (socket: Socket, id: number): void => {
    if (opts.listUpdates === "updateMonitorIntoList") socket.emit("updateMonitorIntoList", { [String(id)]: monitorList()[String(id)] });
    else socket.emit("monitorList", monitorList());
  };

  io.on("connection", (socket: Socket & { loggedIn?: boolean }) => {
    fake.connections += 1;
    socket.on("disconnect", () => {
      fake.disconnections += 1;
    });
    socket.emit("info", { version: "1.23.16", latestVersion: "1.23.16", isContainer: true });

    const guard = (cb: unknown): cb is (res: unknown) => void => typeof cb === "function";
    const needLogin = (cb: (res: unknown) => void): boolean => {
      if (socket.loggedIn) return true;
      cb({ ok: false, msg: "You are not logged in." });
      return false;
    };

    socket.on("login", (data: { username?: string; password?: string; token?: string }, cb: unknown) => {
      log.push("login");
      if (!guard(cb)) return;
      if (data?.username !== username || data?.password !== password) {
        cb({ ok: false, msg: "Incorrect username or password.", msgi18n: true });
        return;
      }
      if (opts.twofa && !data.token) {
        cb({ tokenRequired: true });
        return;
      }
      socket.loggedIn = true;
      // Like afterLogin(): push the list and heartbeats, then ack.
      socket.emit("monitorList", monitorList());
      for (const m of monitors.values()) socket.emit("heartbeatList", m.id, (beats[m.id] ?? []).slice(-100), true);
      cb({ ok: true, token: "fake-jwt" });
    });

    socket.on("getMonitorList", (cb: unknown) => {
      log.push("getMonitorList");
      if (!guard(cb) || !needLogin(cb)) return;
      socket.emit("monitorList", monitorList());
      cb({ ok: true });
    });

    socket.on("getMonitor", (id: number, cb: unknown) => {
      log.push(`getMonitor:${id}`);
      if (!guard(cb) || !needLogin(cb)) return;
      const m = monitors.get(Number(id));
      if (!m) cb({ ok: false, msg: "Cannot read properties of null (reading 'toJSON')" });
      else cb({ ok: true, monitor: monitorList()[String(m.id)] });
    });

    socket.on("getMonitorBeats", (id: number, period: number, cb: unknown) => {
      log.push(`getMonitorBeats:${id}:${period}`);
      if (!guard(cb) || !needLogin(cb)) return;
      cb({ ok: true, data: beats[Number(id)] ?? [] });
    });

    socket.on("pauseMonitor", (id: number, cb: unknown) => {
      log.push(`pauseMonitor:${id}`);
      if (!guard(cb) || !needLogin(cb)) return;
      const m = monitors.get(Number(id));
      if (!m) return cb({ ok: false, msg: "Monitor not found." });
      if (failPause.has(m.id)) return cb({ ok: false, msg: "injected pause failure" });
      m.active = 0;
      announce(socket, m.id);
      cb({ ok: true, msg: "Paused Successfully.", msgi18n: true });
    });

    socket.on("resumeMonitor", (id: number, cb: unknown) => {
      log.push(`resumeMonitor:${id}`);
      if (!guard(cb) || !needLogin(cb)) return;
      const m = monitors.get(Number(id));
      if (!m) return cb({ ok: false, msg: "Monitor not found." });
      if (failResume.has(m.id)) return cb({ ok: false, msg: "injected resume failure" });
      m.active = 1;
      announce(socket, m.id);
      cb({ ok: true, msg: "Resumed Successfully.", msgi18n: true });
    });
  });

  await new Promise<void>((resolve) => http.listen(0, "127.0.0.1", () => resolve()));
  const { port } = http.address() as AddressInfo;
  fake.port = port;
  fake.url = `http://127.0.0.1:${port}`;
  return fake;
}

/** Wait until every connection the fake has seen has also disconnected. */
export async function settled(fake: FakeKuma, timeoutMs = 2000): Promise<{ connections: number; disconnections: number; open: number }> {
  const until = Date.now() + timeoutMs;
  while (Date.now() < until && (fake.clientsCount() > 0 || fake.disconnections < fake.connections)) {
    await new Promise((r) => setTimeout(r, 10));
  }
  return { connections: fake.connections, disconnections: fake.disconnections, open: fake.clientsCount() };
}
