import { randomBytes } from "node:crypto";
import type { AppState } from "../app.js";
import { formSkeleton, type SnapshotProgress } from "./snapshot-service.js";

/**
 * In-memory registry of background `form_skeleton` jobs, one registry per
 * AppState. A skeleton can take minutes (it SSHes into every host and triggers
 * native backups), far longer than a typical MCP client's per-call timeout, so
 * `form_skeleton` starts the work here and returns at once; `skeleton_status`
 * polls. Only ONE job runs at a time per AppState — a second start while one is
 * running is answered with the running job (dedupe), so a client that timed out
 * and retried can never fan out into redundant snapshots and redundant native
 * backups on Pi-hole / UniFi / Home Assistant.
 *
 * Nothing here holds artifact bytes or secrets: a job record carries only ids,
 * timestamps, counters, target names, and the same metadata-only summary text
 * `formSkeleton` returns.
 */

export type SkeletonJobStatus = "running" | "done" | "failed";

export interface SkeletonJob {
  id: string;
  startedAt: number;
  finishedAt?: number;
  status: SkeletonJobStatus;
  progress: SnapshotProgress;
  skeletonId?: string;
  summary?: string;
  error?: string;
}

/** Bounded history so a long-lived server can't accumulate job records forever. */
export const MAX_JOB_HISTORY = 20;

interface JobRegistry {
  jobs: SkeletonJob[]; // newest last
  running?: { job: SkeletonJob; done: Promise<void> };
}

const registries = new WeakMap<AppState, JobRegistry>();

function registryFor(app: AppState): JobRegistry {
  let r = registries.get(app);
  if (!r) {
    r = { jobs: [] };
    registries.set(app, r);
  }
  return r;
}

/** The function that actually produces a skeleton; injectable for tests. */
export type SkeletonRunner = (app: AppState, onProgress: (p: SnapshotProgress) => void) => Promise<{ id: string; summary: string }>;

const defaultRunner: SkeletonRunner = (app, onProgress) => formSkeleton(app, undefined, undefined, onProgress);

/**
 * Start a background skeleton job, or return the one already running. The
 * returned `job` object is live — its fields update as the job progresses.
 * `started` is false when an existing running job was returned instead.
 */
export function startSkeletonJob(app: AppState, runner: SkeletonRunner = defaultRunner): { job: SkeletonJob; started: boolean } {
  const reg = registryFor(app);
  if (reg.running) return { job: reg.running.job, started: false };

  const job: SkeletonJob = {
    id: `job-${randomBytes(6).toString("hex")}`,
    startedAt: Date.now(),
    status: "running",
    progress: { targetsDone: 0, targetsTotal: app.registry.list().length },
  };
  reg.jobs.push(job);
  while (reg.jobs.length > MAX_JOB_HISTORY) reg.jobs.shift();

  audit(app, "ok", `job ${job.id} started (${job.progress.targetsTotal} target(s))`);

  // The background promise resolves on BOTH success and failure — failure is
  // recorded on the job — so it can never become an unhandled rejection.
  const done = (async () => {
    try {
      const { id, summary } = await runner(app, (p) => {
        job.progress = { ...p };
      });
      job.status = "done";
      job.skeletonId = id;
      job.summary = summary;
      audit(app, "ok", `job ${job.id} finished: skeleton ${id}`);
    } catch (e) {
      job.status = "failed";
      job.error = e instanceof Error ? e.message : String(e);
      audit(app, "error", `job ${job.id} failed: ${job.error}`);
    } finally {
      job.finishedAt = Date.now();
      if (reg.running?.job === job) reg.running = undefined;
    }
  })();
  reg.running = { job, done };
  return { job, started: true };
}

/**
 * Wait up to `ms` for a job to finish. Resolves (to the live job) when it
 * finishes or the wait elapses, whichever comes first — never rejects.
 */
export async function waitForSkeletonJob(app: AppState, job: SkeletonJob, ms: number): Promise<SkeletonJob> {
  const running = registryFor(app).running;
  if (job.status !== "running" || !running || running.job !== job || ms <= 0) return job;
  let timer: NodeJS.Timeout | undefined;
  const timeout = new Promise<void>((resolve) => {
    timer = setTimeout(resolve, ms);
  });
  try {
    await Promise.race([running.done, timeout]);
  } finally {
    if (timer) clearTimeout(timer);
  }
  return job;
}

/** Look up a job by id, or the most recent one when `id` is omitted. */
export function getSkeletonJob(app: AppState, id?: string): SkeletonJob | undefined {
  const reg = registryFor(app);
  if (id === undefined) return reg.jobs[reg.jobs.length - 1];
  return reg.jobs.find((j) => j.id === id);
}

/** Human-readable status report for a job (metadata only — no artifact bytes). */
export function describeSkeletonJob(job: SkeletonJob, now: number = Date.now()): string {
  const end = job.finishedAt ?? now;
  const elapsed = Math.max(0, Math.round((end - job.startedAt) / 1000));
  const p = job.progress;
  const head =
    `Skeleton job ${job.id}: ${job.status} (${elapsed}s${job.status === "running" ? " elapsed" : ""}), targets ${p.targetsDone}/${p.targetsTotal} done` +
    (job.status === "running" && p.currentTarget ? `, currently: ${p.currentTarget}` : "") +
    ".";
  if (job.status === "running") {
    return `${head}\nStill running — poll skeleton_status again in a few seconds. Do NOT call form_skeleton again; it would just return this same job.`;
  }
  if (job.status === "failed") return `${head}\nError: ${job.error ?? "unknown"}`;
  return `${head}\nFormed skeleton ${job.skeletonId}.\n\n${job.summary ?? ""}\n\nDownload it off-box from the admin web UI (TOTP-gated).`;
}

function audit(app: AppState, status: "ok" | "error", detail: string): void {
  try {
    app.audit.record({ ts: new Date().toISOString(), tool: "form_skeleton", target: "(global)", tier: "execute", args: {}, status, detail: detail.slice(0, 500) });
  } catch {
    /* audit is best-effort here; the job itself must not die on an audit write */
  }
}
