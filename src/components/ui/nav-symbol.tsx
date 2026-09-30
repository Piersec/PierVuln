type NavSymbolProps = { kind: "vulnerabilities" | "book" | "admin" };

export function NavSymbol({ kind }: NavSymbolProps) {
  const paths = {
    vulnerabilities: <><rect x="3" y="3" width="7" height="7" rx="1" /><rect x="14" y="3" width="7" height="7" rx="1" /><rect x="3" y="14" width="7" height="7" rx="1" /><rect x="14" y="14" width="7" height="7" rx="1" /></>,
    book: <><path d="M12 5.5c-2.5-1.6-5.2-1.8-9-1.2v14c3.8-.6 6.5-.4 9 1.2 2.5-1.6 5.2-1.8 9-1.2v-14c-3.8-.6-6.5-.4-9 1.2Z" /><path d="M12 5.5v14" /></>,
    admin: <><rect x="3" y="4" width="18" height="16" rx="2" /><path d="M3 10h18M9 10v10M14 14h4M14 17h4" /></>,
  };

  return <svg className="nav-symbol" width="20" height="20" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="1.7" strokeLinecap="round" strokeLinejoin="round" aria-hidden="true">{paths[kind]}</svg>;
}
