import type { Metadata } from "next";
import { CollectionStatus } from "@/src/components/collection-status";

export const metadata: Metadata = {
  title: "Status da coleta · PierVuln",
  description: "Acompanhe a saúde das conexões e as sincronizações do Wazuh.",
};

export default function StatusPage() {
  return <CollectionStatus />;
}
