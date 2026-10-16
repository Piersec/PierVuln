export const compactCaseColumns = [
  "id",
  "finding_id",
  "tenant_id",
  "workflow_status",
  "created_at",
  "updated_at",
  "closed_at",
  "assigned_to",
  "finding_agent_id",
  "finding_agent_name",
  "finding_agent_groups",
  "finding_host_os",
  "finding_package_name",
  "finding_package_version",
  "finding_vulnerability_id",
  "finding_description",
  "finding_severity",
  "finding_cvss_base",
  "finding_reference_urls",
  "finding_source_state",
  "finding_first_detected_at",
  "finding_last_seen_at",
].join(",");

type CompactCaseRecord = Record<string, unknown> & {
  id: string;
  finding_id: string;
  tenant_id: string;
  workflow_status: string;
  created_at: string;
  updated_at: string;
  closed_at: string | null;
};

function nullableString(value: unknown): string | null {
  return typeof value === "string" ? value : null;
}

export function isMissingCompactCaseView(error: { code?: string } | null | undefined): boolean {
  return error?.code === "PGRST205";
}

export function normalizeCaseRows<T>(rows: unknown[]): T[] {
  return rows.map((value) => {
    if (!value || typeof value !== "object") return value as T;
    const row = value as Record<string, unknown>;
    if (row.wazuh_findings && typeof row.wazuh_findings === "object") return row as T;

    const compact = row as CompactCaseRecord;
    return {
      id: compact.id,
      finding_id: compact.finding_id,
      tenant_id: compact.tenant_id,
      workflow_status: compact.workflow_status,
      created_at: compact.created_at,
      updated_at: compact.updated_at,
      closed_at: compact.closed_at,
      assigned_to: nullableString(compact.assigned_to),
      wazuh_findings: {
        id: compact.finding_id,
        agent_id: nullableString(compact.finding_agent_id),
        agent_name: nullableString(compact.finding_agent_name),
        agent_groups: Array.isArray(compact.finding_agent_groups) ? compact.finding_agent_groups : [],
        host_os: nullableString(compact.finding_host_os),
        package_name: nullableString(compact.finding_package_name),
        package_version: nullableString(compact.finding_package_version),
        vulnerability_id: nullableString(compact.finding_vulnerability_id) ?? "UNKNOWN",
        description: nullableString(compact.finding_description),
        severity: nullableString(compact.finding_severity) ?? "Unknown",
        cvss_base: typeof compact.finding_cvss_base === "number" ? compact.finding_cvss_base : null,
        reference_urls: Array.isArray(compact.finding_reference_urls) ? compact.finding_reference_urls : [],
        source_state: nullableString(compact.finding_source_state) ?? "active",
        first_detected_at: nullableString(compact.finding_first_detected_at) ?? compact.created_at,
        last_seen_at: nullableString(compact.finding_last_seen_at) ?? compact.updated_at,
      },
    } as T;
  });
}
