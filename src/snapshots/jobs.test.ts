import { describe, it, expect, vi } from "vitest";
import type { AppState } from "../app.js";
import { startSkeletonJob, waitForSkeletonJob, getSkeletonJob, describeSkeletonJob, MAX_JOB_HISTORY, type SkeletonRunner } from "./jobs.js";

/** A fresh fake AppState (the job registry is keyed per AppState instance). */
function fakeApp(targetCount = 2): { app: AppState; audit: any[] } {
  const audit: any[] = [];
  const app = {
    registry: { list: () => Array.from({ length: targetCount }, (_, i) => ({ name: `t${i + 1}`, type: "ssh", host: "h" })) },
    audit: { record: (e: any) => audit.push(e) },
  } as unknown as AppState;
  return { app, audit };
}

/** A runner whose completion the test controls. */
function controlledRunner() {
  let resolve!: (v: { id: string; summary: string }) => void;
  let reject!: (e: unknown) => void;
  let progress: ((p: { targetsDone: number; targetsTotal: number; currentTarget?: string }) => void) | undefined;
  const calls = { count: 0 };
  const runner: SkeletonRunner = (_app, onProgress) => {
    calls.count++;
    progress = onProgress;
    return new Promise((res, rej) => {
      resolve = res;
      reject = rej;
    });
  };
  return { runner, calls, finish: (v: { id: string; summary: string }) => resolve(v), fail: (e: unknown) => reject(e), progress: (p: any) => progress?.(p) };
}

describe("skeleton job registry", () => {
  it("dedupes: a second start while one is running returns the SAME job and does not run another snapshot", async () => {
    const { app } = fakeApp();
    const c = controlledRunner();
    const first = startSkeletonJob(app, c.runner);
    const second = startSkeletonJob(app, c.runner);
    expect(first.started).toBe(true);
    expect(second.started).toBe(false);
    expect(second.job.id).toBe(first.job.id);
    expect(c.calls.count).toBe(1);

    c.finish({ id: "skel-1", summary: "2 artifact(s)" });
    await waitForSkeletonJob(app, first.job, 1000);
    // Once finished, a new start is allowed again.
    const third = startSkeletonJob(app, c.runner);
    expect(third.started).toBe(true);
    expect(third.job.id).not.toBe(first.job.id);
    expect(c.calls.count).toBe(2);
    c.finish({ id: "skel-2", summary: "" });
    await waitForSkeletonJob(app, third.job, 1000);
  });

  it("waitForSkeletonJob returns early (still running) when the wait elapses, and with the result when it finishes in time", async () => {
    const { app } = fakeApp();
    const c = controlledRunner();
    const { job } = startSkeletonJob(app, c.runner);
    const early = await waitForSkeletonJob(app, job, 10);
    expect(early.status).toBe("running");

    setTimeout(() => c.finish({ id: "skel-x", summary: "ok" }), 5);
    const done = await waitForSkeletonJob(app, job, 1000);
    expect(done.status).toBe("done");
    expect(done.skeletonId).toBe("skel-x");
    expect(done.summary).toBe("ok");
    expect(done.finishedAt).toBeDefined();
  });

  it("tracks progress, reports via describeSkeletonJob before and after completion, and audits start/finish", async () => {
    const { app, audit } = fakeApp(3);
    const c = controlledRunner();
    const { job } = startSkeletonJob(app, c.runner);
    c.progress({ targetsDone: 1, targetsTotal: 3, currentTarget: "t2" });
    const running = describeSkeletonJob(job, job.startedAt + 7000);
    expect(running).toContain("running");
    expect(running).toContain("7s");
    expect(running).toContain("1/3");
    expect(running).toContain("currently: t2");
    expect(running).toContain("Do NOT call form_skeleton again");
    expect(getSkeletonJob(app)).toBe(job); // most recent
    expect(getSkeletonJob(app, job.id)).toBe(job);
    expect(getSkeletonJob(app, "nope")).toBeUndefined();

    c.finish({ id: "skel-done", summary: "3 artifact(s) from 3 target(s)" });
    await waitForSkeletonJob(app, job, 1000);
    const done = describeSkeletonJob(job);
    expect(done).toContain("done");
    expect(done).toContain("Formed skeleton skel-done");
    expect(done).toContain("3 artifact(s) from 3 target(s)");
    const details = audit.filter((e) => e.tool === "form_skeleton").map((e) => e.detail);
    expect(details.some((d: string) => d.includes("started"))).toBe(true);
    expect(details.some((d: string) => d.includes("finished: skeleton skel-done"))).toBe(true);
  });

  it("records a failure on the job (never an unhandled rejection) and frees the slot", async () => {
    const { app, audit } = fakeApp();
    const unhandled = vi.fn();
    process.on("unhandledRejection", unhandled);
    try {
      const c = controlledRunner();
      const { job } = startSkeletonJob(app, c.runner);
      c.fail(new Error("vault exploded"));
      const failed = await waitForSkeletonJob(app, job, 1000);
      expect(failed.status).toBe("failed");
      expect(failed.error).toBe("vault exploded");
      expect(describeSkeletonJob(job)).toContain("Error: vault exploded");
      expect(audit.some((e) => e.status === "error" && String(e.detail).includes("vault exploded"))).toBe(true);
      await new Promise((r) => setImmediate(r));
      expect(unhandled).not.toHaveBeenCalled();
      expect(startSkeletonJob(app, c.runner).started).toBe(true);
    } finally {
      process.off("unhandledRejection", unhandled);
    }
  });

  it("keeps a bounded history", async () => {
    const { app } = fakeApp();
    const instant: SkeletonRunner = async () => ({ id: "s", summary: "" });
    const ids: string[] = [];
    for (let i = 0; i < MAX_JOB_HISTORY + 5; i++) {
      const { job } = startSkeletonJob(app, instant);
      ids.push(job.id);
      await waitForSkeletonJob(app, job, 1000);
    }
    // The 5 oldest have been evicted; the newest MAX_JOB_HISTORY remain.
    for (const old of ids.slice(0, 5)) expect(getSkeletonJob(app, old)).toBeUndefined();
    for (const kept of ids.slice(5)) expect(getSkeletonJob(app, kept)).toBeDefined();
    expect(getSkeletonJob(app)!.id).toBe(ids[ids.length - 1]);
  });
});
