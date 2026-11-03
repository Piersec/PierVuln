type Job = { key: string };
type Scheduled<T> = { job: T; due: number; generation: number; failures: number; initial: boolean };

export class InitialScanScheduler<T extends Job> {
  private readonly jobs = new Map<string, Scheduled<T>>();
  private readonly running = new Map<string, Promise<void>>();
  private generation = 0;

  constructor(private readonly intervalMs: number, private readonly now = Date.now, private readonly concurrency = 2,
    private readonly onFailure: (job: T, error: unknown, retryMs: number) => void = () => {}) {}

  reconcile(jobs: T[], changed: string[]) {
    const active = new Set(jobs.map((job) => job.key));
    for (const key of this.jobs.keys()) if (!active.has(key)) this.jobs.delete(key);
    const updated = new Set(changed);
    for (const job of jobs) {
      const previous = this.jobs.get(job.key);
      this.jobs.set(job.key, previous && !updated.has(job.key) ? { ...previous, job } : {
        job, due: 0, generation: ++this.generation, failures: 0, initial: true,
      });
    }
  }

  startDue(run: (job: T) => Promise<void>): number {
    let started = 0;
    const due = [...this.jobs.values()].filter((item) => item.due <= this.now())
      .sort((a, b) => Number(b.initial) - Number(a.initial) || a.due - b.due);
    for (const item of due) {
      const key = item.job.key;
      if (this.running.size >= this.concurrency) break;
      if (this.running.has(key)) continue;
      const task = Promise.resolve().then(() => run(item.job)).then(() => {
        const current = this.jobs.get(key);
        if (current?.generation === item.generation) this.jobs.set(key, { ...current, due: this.now() + this.intervalMs, failures: 0, initial: false });
      }).catch((error) => {
        const current = this.jobs.get(key);
        if (current?.generation !== item.generation) return;
        const failures = current.failures + 1;
        const retryMs = Math.min(900_000, 30_000 * 2 ** Math.min(failures - 1, 5));
        this.jobs.set(key, { ...current, due: this.now() + retryMs, failures });
        this.onFailure(item.job, error, retryMs);
      }).finally(() => { this.running.delete(key); });
      this.running.set(key, task);
      started++;
    }
    return started;
  }

  async idle() { await Promise.allSettled(this.running.values()); }
}
