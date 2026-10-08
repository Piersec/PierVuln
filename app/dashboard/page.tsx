import { VulnerabilityDashboard } from "@/src/components/vulnerability-dashboard";

export default async function DashboardPage({ searchParams }: {
  searchParams: Promise<{ company?: string | string[] }>;
}) {
  const company = (await searchParams).company;
  const initialCompanyId = typeof company === "string" && (company === "all" || /^[0-9a-f-]{36}$/i.test(company))
    ? company : undefined;
  return <VulnerabilityDashboard initialCompanyId={initialCompanyId} />;
}
