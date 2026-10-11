import { z } from "zod";
import { randomBytes } from "node:crypto";
import { mkdir, readFile } from "node:fs/promises";
import path from "node:path";
import type { Connector, ConnectorTool, Credential, Target, ToolContext, ToolResult } from "./types.js";
import { deriveBaseUrl } from "./net.js";
import { paths } from "../config/paths.js";
import { writeFileAtomic } from "../lib/atomic-file.js";
import {
  BEAT_STATUS,
  KumaSession,
  withKuma,
  tagLabel,
  norm,
  redactMonitorUrl,
  type KumaBeat,
  type KumaConnectOptions,
  type KumaMonitor,
} from "./uptime-kuma-client.js";

/**
 * Uptime Kuma connector — monitor inventory and **notification suppression**.
 *
 * Why it exists: the owner's game servers are watched by Uptime Kuma monitors
 * that post "X is DOWN / UP" to Discord. Every deliberate bounce (a test boot, a
 * mod install, a world swap) therefore pages the whole channel unless the
 * monitors are paused first. This connector makes that pause/resume a first-
 * class, audited, approval-gated action — and the Pelican connector's
 * `power_action` drives it automatically via `suppressMonitors` (the
 * **white-glove rule**, see `docs/ARCHITECTURE.md`).
 *
 * Transport: socket.io, because Kuma has no REST API for monitor control (see
 * `uptime-kuma-client.ts`). The vault item holds a Kuma **login** (username +
 * password) — Kuma's API keys only guard `/metrics` and cannot pause anything.
 *
 * **`maintenance` is pause-based, not Kuma's maintenance-window feature.** It
 * pauses a named set of monitors and returns a handle; `end_maintenance`
 * resumes exactly the monitors that handle paused — never one that was already
 * paused before, never one it did not touch — and is idempotent. Handles are
 * persisted (`paths.kumaMaintenance`), so a Skeleton Key restart mid-window
 * cannot strand monitors paused with no record of why.
 */

const optionsSchema = z
  .object({
    /** Kuma base URL; if omitted, host/port form it (443/8443 ⇒ https, else http). */
    baseUrl: z.string().url().optional(),
    /** Skip TLS verification for THIS target only (self-signed LAN cert). */
    insecureTLS: z.boolean().default(false),
    /** Connect / per-request timeout. */
    timeoutMs: z.number().int().min(1000).max(120_000).default(15_000),
  })
  .default({});

type Options = z.infer<typeof optionsSchema>;

function options(target: Target): Options {
  return optionsSchema.parse(target.options ?? {});
}

export function baseUrl(target: Target): string {
  return deriveBaseUrl(target, { baseUrl: options(target).baseUrl, httpsPorts: [443, 8443] });
}

/** The login from the vault item. Username/password properties first, then
 *  same-named custom fields. Values go straight into the connect options and
 *  nowhere else. Exported for the Pelican integration. */
export function kumaConnectOptions(target: Target, cred: Credential): KumaConnectOptions {
  const username = cred.username ?? cred.fields["username"];
  const password = cred.password ?? cred.fields["password"];
  if (!username || !password) {
    throw new Error(
      `The vault item for Uptime Kuma target '${target.name}' needs a username AND a password (a Kuma login — Kuma's API keys only cover /metrics and cannot pause monitors). ` +
        `Fill it with request_credential (fields username + password); never paste it into chat.`,
    );
  }
  const o = options(target);
  return { baseUrl: baseUrl(target), username, password, insecureTLS: o.insecureTLS, timeoutMs: o.timeoutMs };
}

// --- Maintenance handles -----------------------------------------------------

export interface MaintenanceRecord {
  handle: string;
  /** Skeleton Key target name the handle was opened on. */
  target: string;
  /** Exactly the monitors this handle paused (already-paused ones excluded). */
  monitors: { id: number; name: string }[];
  note?: string;
  startedAt: string;
  endedAt?: string;
}

/** Ended handles kept for idempotent `end_maintenance` replies. */
export const ENDED_HANDLES_KEPT = 20;

/**
 * Tiny JSON store of maintenance handles. One file, read-modify-write, writes
 * serialised in-process and made durable with the same atomic writer as the
 * bootstrap store — a torn file here would mean "which monitors did I pause?"
 * is unanswerable after a crash, which is the failure this whole design exists
 * to prevent.
 */
function isMaintenanceRecord(h: unknown): h is MaintenanceRecord {
  if (!h || typeof h !== "object") return false;
  const r = h as Record<string, unknown>;
  return typeof r.handle === "string" && typeof r.target === "string" && Array.isArray(r.monitors) && typeof r.startedAt === "string";
}

export class MaintenanceStore {
  private chain: Promise<unknown> = Promise.resolve();
  constructor(readonly file: string) {}

  private async read(): Promise<MaintenanceRecord[]> {
    let text: string;
    try {
      text = await readFile(this.file, "utf8");
    } catch (e) {
      if ((e as NodeJS.ErrnoException).code === "ENOENT") return [];
      throw new Error(`Could not read the maintenance-handle store at ${this.file}: ${e instanceof Error ? e.message : String(e)}`);
    }
    let parsed: unknown;
    try {
      parsed = JSON.parse(text);
    } catch (e) {
      throw new Error(
        `The maintenance-handle store at ${this.file} is not valid JSON (${e instanceof Error ? e.message : String(e)}). ` +
          `Resume any paused monitors by hand (resume_monitor), then fix or delete the file.`,
      );
    }
    const handles = parsed && typeof parsed === "object" ? (parsed as { handles?: unknown }).handles : undefined;
    // Malformed entries are skipped rather than crashing every tool that reads
    // the store; a record is only trusted with the shape end_maintenance needs.
    return Array.isArray(handles) ? handles.filter(isMaintenanceRecord) : [];
  }

  private async write(handles: MaintenanceRecord[]): Promise<void> {
    await mkdir(path.dirname(this.file), { recursive: true });
    await writeFileAtomic(this.file, JSON.stringify({ handles }, null, 1), 0o600);
  }

  /** Serialised read-modify-write. */
  private update<T>(fn: (handles: MaintenanceRecord[]) => T | Promise<T>): Promise<T> {
    const run = async (): Promise<T> => {
      const handles = await this.read();
      const out = await fn(handles);
      await this.write(handles);
      return out;
    };
    const next = this.chain.then(run, run);
    this.chain = next.catch(() => undefined);
    return next;
  }

  list(): Promise<MaintenanceRecord[]> {
    return this.read();
  }

  async open(target: string): Promise<MaintenanceRecord[]> {
    return (await this.read()).filter((h) => h.target === target && !h.endedAt);
  }

  async get(handle: string): Promise<MaintenanceRecord | undefined> {
    return (await this.read()).find((h) => h.handle === handle);
  }

  add(rec: MaintenanceRecord): Promise<void> {
    return this.update((handles) => {
      handles.push(rec);
    });
  }

  /** Mark ended, pruning old ended records. */
  end(handle: string, endedAt: string): Promise<void> {
    return this.update((handles) => {
      const rec = handles.find((h) => h.handle === handle);
      if (rec) rec.endedAt = endedAt;
      const ended = handles.filter((h) => h.endedAt);
      if (ended.length > ENDED_HANDLES_KEPT) {
        const drop = new Set(ended.slice(0, ended.length - ENDED_HANDLES_KEPT).map((h) => h.handle));
        for (let i = handles.length - 1; i >= 0; i -= 1) if (drop.has(handles[i]!.handle)) handles.splice(i, 1);
      }
    });
  }
}

export function newHandle(): string {
  return `mw_${randomBytes(4).toString("hex")}`;
}

// --- Monitor selection -------------------------------------------------------

/** A monitor as a tool names it: a numeric id, or a name (exact, case-insensitive). */
const MONITOR_REF = z
  .union([z.number().int().positive(), z.string().min(1)])
  .describe("Monitor id (number) or exact monitor name (case-insensitive) from list_monitors.");

export type MonitorRef = z.infer<typeof MONITOR_REF>;

/** Resolve one ref against the live list. A name must be unambiguous. Exported for testing. */
export function resolveMonitor(monitors: KumaMonitor[], ref: MonitorRef): KumaMonitor {
  if (typeof ref === "number") {
    const m = monitors.find((x) => x.id === ref);
    if (!m) throw new Error(`No Uptime Kuma monitor has id ${ref}. Run list_monitors.`);
    return m;
  }
  const byName = monitors.filter((m) => norm(m.name) === norm(ref));
  if (byName.length === 1) return byName[0]!;
  if (byName.length > 1) {
    throw new Error(`Several monitors are named '${ref}' (ids ${byName.map((m) => m.id).join(", ")}) — refer to one by id.`);
  }
  if (/^\d+$/.test(ref.trim())) {
    const m = monitors.find((x) => x.id === Number(ref.trim()));
    if (m) return m;
  }
  const near = monitors.filter((m) => norm(m.name).includes(norm(ref))).slice(0, 8);
  throw new Error(
    `No Uptime Kuma monitor is named '${ref}'.${near.length ? ` Closest: ${near.map((m) => `'${m.name}' [${m.id}]`).join(", ")}.` : ""} Run list_monitors.`,
  );
}

/** Monitors carrying a tag given as `name` or `name:value`. Exported for testing. */
export function monitorsWithTag(monitors: KumaMonitor[], tag: string): KumaMonitor[] {
  const want = norm(tag);
  if (!want) return [];
  return monitors.filter((m) => m.tags.some((t) => norm(tagLabel(t)) === want || (!tag.includes(":") && norm(t.name) === want)));
}

// --- Rendering ----------------------------------------------------------------

function stateOf(m: KumaMonitor): string {
  if (!m.active) return "PAUSED";
  if (m.forceInactive) return "PAUSED (group paused)";
  if (m.maintenance) return "ACTIVE (in Kuma maintenance window)";
  return "ACTIVE";
}

function whereOf(m: KumaMonitor): string {
  const url = redactMonitorUrl(m.url);
  if (url) return url;
  if (m.hostname) return m.port ? `${m.hostname}:${m.port}` : m.hostname;
  return "";
}

function line(m: KumaMonitor): string {
  const where = whereOf(m);
  const tags = m.tags.length ? m.tags.map(tagLabel).join(", ") : "—";
  return `  [${m.id}] ${m.name} — ${m.type ?? "?"}${where ? ` ${where}` : ""} — ${stateOf(m)} — tags: ${tags}`;
}

/** Render the monitor list. Exported for testing. */
export function summarizeMonitors(target: string, monitors: KumaMonitor[], open: MaintenanceRecord[], query?: string): string {
  const q = query ? norm(query) : "";
  const shown = q ? monitors.filter((m) => norm(m.name).includes(q) || m.tags.some((t) => norm(tagLabel(t)).includes(q))) : monitors;
  const paused = shown.filter((m) => !m.active).length;
  const head = `Uptime Kuma monitors on ${target}${q ? ` matching '${query}'` : ""}: ${shown.length}${shown.length !== monitors.length ? ` of ${monitors.length}` : ""} (${paused} paused)`;
  const body = shown.length ? shown.map(line).join("\n") : "  (none)";
  const handles = open.length
    ? `\nOpen Skeleton Key maintenance handles on this target (end_maintenance resumes them):\n` +
      open.map((h) => `  ${h.handle} since ${h.startedAt}${h.note ? ` — ${h.note}` : ""}: ${h.monitors.map((m) => `${m.name} [${m.id}]`).join(", ") || "(nothing paused)"}`).join("\n")
    : "";
  return `${head}\n${body}${handles}`;
}

function fmtBeat(b: KumaBeat): string {
  const ping = typeof b.ping === "number" ? ` ${b.ping}ms` : "";
  const msg = b.msg ? ` "${String(b.msg).slice(0, 120)}"` : "";
  return `${BEAT_STATUS[b.status] ?? `status ${b.status}`} at ${b.time}${ping}${msg}`;
}

/** Render one monitor's status from its recent heartbeats. Exported for testing. */
export function summarizeStatus(target: string, m: KumaMonitor, beats: KumaBeat[], hours: number): string {
  const where = whereOf(m);
  const head = `Monitor [${m.id}] '${m.name}' (${m.type ?? "?"}${where ? ` ${where}` : ""}) on ${target}: ${stateOf(m)}`;
  if (!beats.length) return `${head}\n  No heartbeats in the last ${hours}h${m.active ? "" : " (paused — Kuma does not check a paused monitor)"}.`;
  const last = beats[beats.length - 1]!;
  const lastChange = [...beats].reverse().find((b) => b.important);
  const counts = new Map<number, number>();
  for (const b of beats) counts.set(b.status, (counts.get(b.status) ?? 0) + 1);
  const tally = [...counts.entries()].map(([s, n]) => `${n} ${BEAT_STATUS[s] ?? s}`).join(", ");
  return (
    `${head}\n  Latest beat: ${fmtBeat(last)}\n` +
    `  Last status change: ${lastChange ? fmtBeat(lastChange) : "none in window"}\n` +
    `  Last ${hours}h: ${beats.length} beats — ${tally}`
  );
}

// --- Tools ---------------------------------------------------------------------

const ok = (text: string): ToolResult => ({ text });

const WHITE_GLOVE =
  "WHITE-GLOVE RULE: before any MANUAL (out-of-schedule) start/stop/restart/reinstall/world swap of a monitored game server, or a reboot of its node, pause its monitors " +
  "and resume them once the action is verified — otherwise Discord gets 'DOWN/UP' posts for a deliberate bounce. Scheduled starts/stops must NOT be suppressed; those alerts are the feature. " +
  "For a Pelican power action prefer power_action with suppressMonitors:true, which does the pause → act → verify → resume cycle itself.";

/**
 * Build the tool set with an explicit handle store — the connector uses the
 * default file under the data dir; tests inject a temp file.
 */
export function buildUptimeKumaTools(store: MaintenanceStore): (target: Target) => ConnectorTool[] {
  // Every tool opens its own session and closes it; errors come back as results.
  function run(fn: (s: KumaSession, input: any, ctx: ToolContext) => Promise<string | ToolResult>) {
    return async (input: unknown, ctx: ToolContext): Promise<ToolResult> => {
      try {
        const opts = kumaConnectOptions(ctx.target, await ctx.getCredential());
        const out = await withKuma(opts, (s) => fn(s, input, ctx));
        return typeof out === "string" ? ok(out) : out;
      } catch (e) {
        return { text: `Uptime Kuma error: ${e instanceof Error ? e.message : String(e)}`, isError: true };
      }
    };
  }

  const refText = (ref: MonitorRef): string => (typeof ref === "number" ? `#${ref}` : `'${ref}'`);

  return (target: Target): ConnectorTool[] => [
    {
      name: "list_monitors",
      description:
        `List Uptime Kuma monitors on ${target.name}: id, name, type, url/host, ACTIVE or PAUSED, and tags (as name:value). ` +
        `Also lists any open Skeleton Key maintenance handles. Monitors of Pelican game servers carry the tag 'managed:pelican' and are named after the server.`,
      tier: "read",
      inputSchema: z.object({ query: z.string().optional().describe("Case-insensitive filter on name or tag, e.g. 'valheim' or 'managed:pelican'.") }),
      run: run(async (s, i) => {
        const monitors = await s.monitors();
        // A broken handle store must not hide the live list — that is exactly
        // when the operator needs to see what is paused.
        let open: MaintenanceRecord[] = [];
        let note = "";
        try {
          open = await store.open(target.name);
        } catch (e) {
          note = `\nWARNING: the maintenance-handle store could not be read (${e instanceof Error ? e.message : String(e)}) — open windows, if any, are not shown; the states above are live.`;
        }
        return summarizeMonitors(target.name, monitors, open, i.query) + note;
      }),
    },
    {
      name: "monitor_status",
      description: `Current status of one Uptime Kuma monitor on ${target.name} from its recent heartbeats: latest beat (UP/DOWN/PENDING), last status change, and a tally over the window.`,
      tier: "read",
      inputSchema: z.object({
        monitor: MONITOR_REF,
        hours: z.number().int().min(1).max(168).default(24).describe("Heartbeat window in hours (default 24)."),
      }),
      run: run(async (s, i) => {
        const m = resolveMonitor(await s.monitors(), i.monitor);
        return summarizeStatus(target.name, m, await s.beats(m.id, i.hours), i.hours);
      }),
    },
    {
      name: "pause_monitor",
      description:
        `Pause one Uptime Kuma monitor on ${target.name}: it stops checking and sends NO notifications until resumed. ` +
        `For a set of monitors around a window, use maintenance/end_maintenance instead so the resume is tracked. ${WHITE_GLOVE}`,
      tier: "execute",
      inputSchema: z.object({ monitor: MONITOR_REF }),
      confirm: (input, t) => `PAUSE Uptime Kuma monitor ${refText((input as { monitor: MonitorRef }).monitor)} on ${t.name} — no checks or notifications until resumed`,
      run: run(async (s, i) => {
        const m = resolveMonitor(await s.monitors(), i.monitor);
        if (!m.active) return `Monitor [${m.id}] '${m.name}' on ${target.name} is already paused — no change.`;
        await s.pause(m.id);
        return `Paused Uptime Kuma monitor [${m.id}] '${m.name}' on ${target.name}. It will not check or notify until resume_monitor — do not leave it this way after the work is done.`;
      }),
    },
    {
      name: "resume_monitor",
      description: `Resume a paused Uptime Kuma monitor on ${target.name}. If the service is down when it resumes, Kuma will report DOWN on the next check.`,
      tier: "execute",
      inputSchema: z.object({ monitor: MONITOR_REF }),
      confirm: (input, t) => `RESUME Uptime Kuma monitor ${refText((input as { monitor: MonitorRef }).monitor)} on ${t.name}`,
      run: run(async (s, i) => {
        const m = resolveMonitor(await s.monitors(), i.monitor);
        if (m.active) return `Monitor [${m.id}] '${m.name}' on ${target.name} is already active — no change.`;
        await s.resume(m.id);
        return `Resumed Uptime Kuma monitor [${m.id}] '${m.name}' on ${target.name}.`;
      }),
    },
    {
      name: "maintenance",
      description:
        `Open a notification-suppression window on ${target.name}: pauses the named monitors (by id/name and/or by tag) and returns a HANDLE. ` +
        `end_maintenance with that handle resumes exactly the monitors this call paused — monitors that were already paused are left alone and are NOT resumed by it. ` +
        `Pause-based (works on every Kuma version), not Kuma's own maintenance-window feature. Handles survive a Skeleton Key restart. ` +
        `Use tag 'managed:pelican' to cover every game server at once (e.g. a node reboot). ${WHITE_GLOVE}`,
      tier: "execute",
      inputSchema: z.object({
        monitors: z.array(MONITOR_REF).max(100).optional().describe("Monitors to pause, by id or exact name."),
        tag: z.string().trim().min(1).optional().describe("Also pause every monitor carrying this tag ('name' or 'name:value'), e.g. 'managed:pelican'."),
        note: z.string().max(200).optional().describe("Why — shown on the handle in list_monitors."),
      }),
      confirm: (input, t) => {
        const i = input as { monitors?: MonitorRef[]; tag?: string; note?: string };
        const parts = [
          ...(i.monitors?.length ? [`monitors [${i.monitors.map(refText).join(", ")}]`] : []),
          ...(i.tag ? [`every monitor tagged '${i.tag}'`] : []),
        ];
        return `PAUSE Uptime Kuma ${parts.join(" and ") || "(nothing selected)"} on ${t.name} as a maintenance window${i.note ? ` (${i.note})` : ""} — end_maintenance resumes exactly these`;
      },
      run: run(async (s, i) => {
        const refs: MonitorRef[] = i.monitors ?? [];
        if (!refs.length && !i.tag) throw new Error("Name at least one monitor (monitors) or a tag (tag).");
        const all = await s.monitors();
        const selected = new Map<number, KumaMonitor>();
        for (const ref of refs) {
          const m = resolveMonitor(all, ref);
          selected.set(m.id, m);
        }
        const notes: string[] = [];
        if (i.tag) {
          const tagged = monitorsWithTag(all, i.tag);
          if (!tagged.length) {
            if (!refs.length) throw new Error(`No monitor on ${target.name} carries the tag '${i.tag}'. Run list_monitors to see tags (shown as name:value).`);
            notes.push(`No monitor carries the tag '${i.tag}' — only the named monitors were considered.`);
          }
          for (const m of tagged) selected.set(m.id, m);
        }
        const paused: { id: number; name: string }[] = [];
        const skipped: KumaMonitor[] = [];
        const failed: string[] = [];
        for (const m of [...selected.values()].sort((a, b) => a.id - b.id)) {
          if (!m.active) {
            skipped.push(m);
            continue;
          }
          try {
            await s.pause(m.id);
            paused.push({ id: m.id, name: m.name });
          } catch (e) {
            failed.push(`[${m.id}] ${m.name}: ${e instanceof Error ? e.message : String(e)}`);
          }
        }
        const names = (xs: { id: number; name: string }[]): string => xs.map((m) => `${m.name} [${m.id}]`).join(", ");
        if (!paused.length && !failed.length) {
          return `Nothing to pause on ${target.name}: ${names(skipped)} ${skipped.length === 1 ? "is" : "are"} already paused. No handle minted (there is nothing for end_maintenance to resume).`;
        }
        const handle = newHandle();
        const startedAt = new Date().toISOString();
        if (paused.length) {
          try {
            await store.add({ handle, target: target.name, monitors: paused, note: i.note, startedAt });
          } catch (e) {
            // The pauses have happened and nothing durable says so — a window
            // nobody could end. Undo it now, on this still-open session, and
            // refuse; resume what WE paused without consulting any cached list.
            const back = await resumeUnconditionally(s, paused);
            const why = e instanceof Error ? e.message : String(e);
            const lead = back.failed.length ? `MONITORS STILL PAUSED on ${target.name}: ${back.failed.join("; ")}. Resume them now with resume_monitor. ` : "";
            throw new Error(
              `${lead}Could not record the maintenance handle (${why}), so the window was NOT opened` +
                `${back.resumed.length ? ` — rolled back: resumed ${names(back.resumed)}` : ""}. ` +
                `Fix the handle store (data volume full or read-only? corrupt file at ${store.file}?) and retry.`,
            );
          }
        }
        const text =
          `Maintenance ${paused.length ? handle : "NOT opened"} on ${target.name}: paused ${paused.length} monitor${paused.length === 1 ? "" : "s"}${paused.length ? ` — ${names(paused)}` : ""}.` +
          (skipped.length ? `\n  Left alone (already paused, not covered by this handle): ${names(skipped)}.` : "") +
          (failed.length ? `\n  FAILED to pause: ${failed.join("; ")}.` : "") +
          (notes.length ? `\n  ${notes.join(" ")}` : "") +
          (paused.length
            ? `\nWhen the work is verified, call end_maintenance with handle '${handle}' — it resumes exactly the ${paused.length} above and nothing else. Never leave a window open.`
            : "");
        return { text, isError: failed.length > 0 };
      }),
    },
    {
      name: "end_maintenance",
      description:
        `Close a maintenance window on ${target.name}: resumes exactly the monitors the handle paused (nothing else), reports each one, and is idempotent — ending a closed handle is a no-op. ` +
        `If some resumes fail the handle stays open so the same call can be retried.`,
      tier: "execute",
      inputSchema: z.object({ handle: z.string().min(1).describe("The handle returned by maintenance (mw_…).") }),
      confirm: (input, t) => `RESUME the Uptime Kuma monitors paused by maintenance handle '${(input as { handle: string }).handle}' on ${t.name}`,
      run: async (input, ctx) => {
        const { handle } = input as { handle: string };
        try {
          const rec = await store.get(handle);
          if (!rec) {
            const open = await store.open(ctx.target.name);
            throw new Error(
              `Unknown maintenance handle '${handle}'.` +
                (open.length
                  ? ` Open handles on ${ctx.target.name}: ${open.map((h) => `${h.handle} (${h.monitors.map((m) => m.name).join(", ")}, since ${h.startedAt})`).join("; ")}.`
                  : ` No maintenance window is open on ${ctx.target.name}.`) +
                ` If a handle was lost, resume the monitors directly with resume_monitor.`,
            );
          }
          if (rec.target !== ctx.target.name) throw new Error(`Handle '${handle}' belongs to target '${rec.target}', not '${ctx.target.name}' — end it there.`);
          if (rec.endedAt) return ok(`Maintenance ${handle} on ${ctx.target.name} already ended at ${rec.endedAt} — nothing to do.`);

          const opts = kumaConnectOptions(ctx.target, await ctx.getCredential());
          const { resumed, already, missing, failed } = await withKuma(opts, (s) => resumeExactly(s, rec.monitors));
          if (!failed.length) await store.end(handle, new Date().toISOString());
          const names = (xs: { id: number; name: string }[]): string => xs.map((m) => `${m.name} [${m.id}]`).join(", ");
          const text =
            `Maintenance ${handle} on ${ctx.target.name} ${failed.length ? "PARTIALLY ended" : "ended"}: resumed ${resumed.length} of ${rec.monitors.length} — ${names(resumed) || "none"}.` +
            (already.length ? `\n  Already active (resumed by someone else meanwhile): ${names(already)}.` : "") +
            (missing.length ? `\n  No longer exist in Kuma: ${names(missing)}.` : "") +
            (failed.length ? `\n  FAILED to resume: ${failed.join("; ")}. The handle stays open — retry end_maintenance '${handle}', or resume_monitor each one.` : "");
          return { text, isError: failed.length > 0 };
        } catch (e) {
          return { text: `Uptime Kuma error: ${e instanceof Error ? e.message : String(e)}`, isError: true };
        }
      },
    },
  ];
}

/**
 * Resume exactly `wanted`, checking the live list first so a monitor someone
 * already resumed is reported rather than poked, and one deleted since is
 * reported rather than failed. Never throws for a single monitor — every
 * outcome is in the report. Shared with the Pelican white-glove flow.
 */
export async function resumeExactly(
  s: KumaSession,
  wanted: { id: number; name: string }[],
): Promise<{ resumed: { id: number; name: string }[]; already: { id: number; name: string }[]; missing: { id: number; name: string }[]; failed: string[] }> {
  const live = new Map((await s.monitors()).map((m) => [m.id, m]));
  const resumed: { id: number; name: string }[] = [];
  const already: { id: number; name: string }[] = [];
  const missing: { id: number; name: string }[] = [];
  const failed: string[] = [];
  for (const w of wanted) {
    const m = live.get(w.id);
    if (!m) {
      missing.push(w);
      continue;
    }
    if (m.active) {
      already.push(w);
      continue;
    }
    try {
      await s.resume(w.id);
      resumed.push(w);
    } catch (e) {
      failed.push(`[${w.id}] ${w.name}: ${e instanceof Error ? e.message : String(e)}`);
    }
  }
  return { resumed, already, missing, failed };
}

/**
 * Resume exactly the monitors WE just paused, without consulting the session's
 * cached list — for rollbacks. The cache may be stale (Kuma 2.x pushes a
 * per-monitor update this client merges, but a rollback must not depend on
 * that), and we know these were active a moment ago because we paused them.
 * Never throws for a single monitor; failures are returned for the caller to
 * put under MONITORS STILL PAUSED.
 */
export async function resumeUnconditionally(s: KumaSession, paused: { id: number; name: string }[]): Promise<{ resumed: { id: number; name: string }[]; failed: string[] }> {
  const resumed: { id: number; name: string }[] = [];
  const failed: string[] = [];
  for (const m of paused) {
    try {
      await s.resume(m.id);
      resumed.push(m);
    } catch (e) {
      failed.push(`[${m.id}] ${m.name}: ${e instanceof Error ? e.message : String(e)}`);
    }
  }
  return { resumed, failed };
}

/** The process-wide handle store (under the data dir). */
export const defaultMaintenanceStore = new MaintenanceStore(paths.kumaMaintenance);

export const uptimeKumaConnector: Connector = {
  type: "uptime-kuma",
  label: "Uptime Kuma (monitors / notification suppression)",
  configSchema: optionsSchema,
  requiresCredential: true,
  buildTools: buildUptimeKumaTools(defaultMaintenanceStore),
};
