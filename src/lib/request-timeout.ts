export async function withRequestTimeout<T>(
  read: (signal: AbortSignal) => PromiseLike<T>,
  signal?: AbortSignal,
  milliseconds = 25_000,
): Promise<T> {
  const deadline = new AbortController();
  const combined = signal ? AbortSignal.any([signal, deadline.signal]) : deadline.signal;
  const timer = setTimeout(() => deadline.abort(new Error("A consulta demorou demais. Os últimos dados foram mantidos.")), milliseconds);
  let onAbort: () => void = () => {};
  const interrupted = new Promise<never>((_, reject) => {
    onAbort = () => reject(combined.reason ?? new Error("Consulta interrompida."));
    if (combined.aborted) onAbort();
    else combined.addEventListener("abort", onAbort, { once: true });
  });
  try {
    return await Promise.race([Promise.resolve().then(() => {
      if (combined.aborted) throw combined.reason;
      return read(combined);
    }), interrupted]);
  } finally {
    clearTimeout(timer);
    combined.removeEventListener("abort", onAbort);
  }
}
