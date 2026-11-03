const networkCodes = new Set(["ERR_TLS_CERT_ALTNAME_INVALID", "UNABLE_TO_VERIFY_LEAF_SIGNATURE", "SELF_SIGNED_CERT_IN_CHAIN", "DEPTH_ZERO_SELF_SIGNED_CERT", "CERT_HAS_EXPIRED", "ECONNREFUSED", "ECONNRESET", "ETIMEDOUT", "ENOTFOUND", "EAI_AGAIN", "UND_ERR_CONNECT_TIMEOUT"]);

export function assetFailure(error: unknown): string {
  const message = error instanceof Error ? error.message : "Asset collection failed";
  const seen = new Set<unknown>();
  let current: unknown = error;
  while (current && typeof current === "object" && !seen.has(current)) {
    seen.add(current);
    const item = current as { code?: string; cause?: unknown };
    if (item.code && networkCodes.has(item.code)) return `${message.slice(0, 380)} (${item.code})`;
    current = item.cause;
  }
  return message.slice(0, 500);
}

export async function runAssetCollection(start: () => Promise<unknown>, collect: () => Promise<void>, fail: (message: string) => Promise<unknown>): Promise<void> {
  await start();
  try {
    await collect();
  } catch (error) {
    await fail(assetFailure(error)).catch(() => undefined);
    throw error;
  }
}
