import { Swords } from "lucide-react";

type NavSymbolProps = { kind: "vulnerabilities" | "cases" | "book" | "battle" | "status" | "admin" | "settings" };

export function NavSymbol({ kind }: NavSymbolProps) {
  if (kind === "battle") return <Swords className="nav-symbol" size={20} strokeWidth={1.7} aria-hidden="true" />;
  const paths = {
    vulnerabilities: <><rect x="3" y="3" width="7" height="7" rx="1" /><rect x="14" y="3" width="7" height="7" rx="1" /><rect x="3" y="14" width="7" height="7" rx="1" /><rect x="14" y="14" width="7" height="7" rx="1" /></>,
    cases: <><rect x="4" y="3" width="16" height="18" rx="2" /><path d="M8 8h8M8 12h8M8 16h5" /></>,
    book: <><path d="M12 5.5c-2.5-1.6-5.2-1.8-9-1.2v14c3.8-.6 6.5-.4 9 1.2 2.5-1.6 5.2-1.8 9-1.2v-14c-3.8-.6-6.5-.4-9 1.2Z" /><path d="M12 5.5v14" /></>,
    battle: null,
    status: <><path d="M3 12h4l2.5-5 4 10 2.5-5H21" /><path d="M3 5h18M3 19h18" /></>,
    admin: <><rect x="3" y="4" width="18" height="16" rx="2" /><path d="M3 10h18M9 10v10M14 14h4M14 17h4" /></>,
    settings: <><path d="M12 2.5 14 4l2.4-.4 1 2.2 2.3 1 .1 2.5 1.7 1.7-1.1 2.2.4 2.4-2.2 1-1 2.3-2.5.1-1.7 1.7-2.2-1.1-2.4.4-1-2.2-2.3-1-.1-2.5L3.7 12l1.1-2.2-.4-2.4 2.2-1 1-2.3 2.5-.1L12 2.5Z" /><circle cx="12" cy="12" r="3" /></>,
  };

  return <svg className="nav-symbol" width="20" height="20" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="1.7" strokeLinecap="round" strokeLinejoin="round" aria-hidden="true">{paths[kind]}</svg>;
}
