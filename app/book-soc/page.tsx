import type { Metadata } from "next";
import { BookSocOverview } from "@/src/components/book-soc-overview";

export const metadata: Metadata = { title: "Book SOC · PierVuln" };

export default function BookSocPage() {
  return <BookSocOverview />;
}
