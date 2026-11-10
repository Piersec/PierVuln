import type { Metadata } from "next";
import { BookSocAlerts } from "@/src/components/book-soc-alerts";

export const metadata: Metadata = { title: "Alertas · Book SOC · PierVuln" };

export default function BookSocAlertsPage() {
  return <BookSocAlerts />;
}
