import type { Metadata } from "next";
import { VulnerabilityDashboard } from "@/src/components/vulnerability-dashboard";

export const metadata: Metadata = {
  title: "Alertas SOC · PierVuln",
  description: "Eventos de segurança recebidos e segregados por empresa.",
};

export default async function AlertsPage({ searchParams }: {
  searchParams: Promise<{ company?: string | string[] }>;
}) {
  const company = (await searchParams).company;
  const initialCompanyId = typeof company === "string" && (company === "all" || /^[0-9a-f-]{36}$/i.test(company))
    ? company : undefined;
  return <VulnerabilityDashboard view="alerts" initialCompanyId={initialCompanyId} />;
}
