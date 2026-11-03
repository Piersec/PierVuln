import test from "node:test";
import assert from "node:assert/strict";
import { InitialScanScheduler } from "../src/initial-scan-scheduler";

test("a new company starts while another initial scan is running, then follows the interval", async () => {
  let now = 1_000;
  const scheduler = new InitialScanScheduler<{ key: string }>(300_000, () => now);
  const calls: string[] = [];
  let finishA!: () => void;
  const runner = async ({ key }: { key: string }) => { calls.push(key); if (key === "a") await new Promise<void>((resolve) => { finishA = resolve; }); };
  scheduler.reconcile([{ key: "a" }], ["a"]);
  assert.equal(scheduler.startDue(runner), 1);
  await Promise.resolve();
  scheduler.reconcile([{ key: "a" }, { key: "b" }], ["b"]);
  assert.equal(scheduler.startDue(runner), 1);
  await new Promise((resolve) => setImmediate(resolve));
  assert.deepEqual(calls, ["a", "b"]);
  assert.equal(scheduler.startDue(runner), 0);
  finishA(); await scheduler.idle();
  now += 299_999;
  assert.equal(scheduler.startDue(async () => {}), 0);
  now++;
  assert.equal(scheduler.startDue(async () => {}), 2);
  await scheduler.idle();
});

test("configuration changed during a running scan stays due after the old scan completes", async () => {
  const scheduler = new InitialScanScheduler<{ key: string; version: number }>(300_000, () => 100);
  let complete!: () => void;
  scheduler.reconcile([{ key: "a", version: 1 }], ["a"]);
  scheduler.startDue(async () => new Promise<void>((resolve) => { complete = resolve; }));
  await Promise.resolve();
  scheduler.reconcile([{ key: "a", version: 2 }], ["a"]);
  assert.equal(scheduler.startDue(async () => {}), 0);
  complete(); await scheduler.idle();
  const versions: number[] = [];
  assert.equal(scheduler.startDue(async (job) => { versions.push(job.version); }), 1);
  await scheduler.idle(); assert.deepEqual(versions, [2]);
});

test("new companies take priority over routine scans; failures retry without duplicating active work", async () => {
  let now = 100;
  const scheduler = new InitialScanScheduler<{ key: string }>(1000, () => now, 1);
  scheduler.reconcile([{ key: "old" }], ["old"]);
  scheduler.startDue(async () => {}); await scheduler.idle();
  now += 1000;
  scheduler.reconcile([{ key: "old" }, { key: "new" }], ["new"]);
  const calls: string[] = [];
  scheduler.startDue(async (job) => { calls.push(job.key); throw Error("temporary"); });
  await scheduler.idle(); assert.deepEqual(calls, ["new"]);
  scheduler.startDue(async (job) => { calls.push(job.key); }); await scheduler.idle();
  assert.deepEqual(calls, ["new", "old"]);
  scheduler.reconcile([{ key: "new" }], ["new"]);
  assert.equal(scheduler.startDue(async () => {}), 1); await scheduler.idle();
});
