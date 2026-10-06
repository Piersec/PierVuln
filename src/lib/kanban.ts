export type KanbanFilters = {
  kev: string; epssMin: string; epssMax: string; cvssMin: string; cvssMax: string;
  criticalAsset: string; severity: string; dateFrom: string; dateTo: string;
};
export const emptyKanbanFilters: KanbanFilters = {
  kev: "", epssMin: "", epssMax: "", cvssMin: "", cvssMax: "", criticalAsset: "",
  severity: "", dateFrom: "", dateTo: "",
};
export function severityFromCvss(score: number | null): string {
  if (score == null || !Number.isFinite(score)) return "Unknown";
  return score >= 9 ? "Critical" : score >= 7 ? "High" : score >= 4 ? "Medium" : score >= 1 ? "Low" : score === 0 ? "Informational" : "Unknown";
}
export type KanbanSummary = {
  key: string; cve: string; tenantId: string; status: string; cvss: number | null;
  severity: string; hostCount: number; caseCount: number; criticalAsset: boolean;
  firstDetected: string; mandatory: boolean; score: number;
  intelligence?: { epss: number | null; kev: boolean | null };
};
