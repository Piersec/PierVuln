export function isSyncBoundary(eventType: string, next: { status?: string }) {
  return eventType !== "UPDATE" || next.status !== "running";
}
