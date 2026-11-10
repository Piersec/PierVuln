"use client";

import Link from "next/link";
import { usePathname } from "next/navigation";
import { Button, Popover } from "@heroui/react";
import { ChevronRight } from "lucide-react";
import { useState } from "react";
import { NavSymbol } from "@/src/components/ui/nav-symbol";

type Entry = { label: string; path: string; icon: Parameters<typeof NavSymbol>[0]["kind"] };
const vulnerabilityItems: Entry[] = [
  { label: "Visão geral", path: "/dashboard", icon: "vulnerabilities" },
  { label: "Casos e Kanban", path: "/cases", icon: "cases" },
];
const socItems: Entry[] = [
  { label: "Visão geral", path: "/soc", icon: "analytics" },
  { label: "Analytics", path: "/soc-analytics", icon: "analytics" },
  { label: "Alertas", path: "/alertas", icon: "alerts" },
  { label: "Incidentes", path: "/incidentes", icon: "incidents" },
  { label: "Nível de risco", path: "/risk-level", icon: "risk" },
  { label: "Mapa de ameaças", path: "/threat-map", icon: "threat-map" },
  { label: "Integridade de arquivos", path: "/archives-integrity", icon: "fim" },
  { label: "Monitoria da coleta", path: "/monitoria-ngsoc", icon: "monitoring" },
];

export function WorkspaceNav({ companyId, isInternal = false }: { companyId?: string; isInternal?: boolean }) {
  const pathname = usePathname();
  const company = companyId;
  const href = (path: string) => company ? `${path}?company=${encodeURIComponent(company)}` : path;
  const current = pathname === "/alerts" ? "/alertas" : pathname === "/integridade-arquivos" ? "/archives-integrity" : pathname;
  return <nav className="workspace-nav workspace-nav-grouped" aria-label="Navegação principal">
    <NavGroup label="VMDR" title="Vulnerabilidades" icon="vulnerabilities" items={vulnerabilityItems} current={current} href={href}/>
    <NavGroup label="SOC" title="Operação SOC" icon="alerts" items={socItems} current={current} href={href}/>
    <Link className={`nav-root${current === "/assets" ? " active" : ""}`} href={href("/assets")} aria-current={current === "/assets" ? "page" : undefined}><NavSymbol kind="assets"/><span>Ativos</span></Link>
    <NavGroup label="Relatórios" title="Relatórios" icon="book" items={[{ label: "Book dos clientes", path: "/book", icon: "book" }, ...(isInternal ? [{ label: "Batalha", path: "/battle", icon: "battle" } as Entry] : [])]} current={current} href={href}/>
  </nav>;
}

function NavGroup({ label, title, icon, items, current, href }: { label: string; title: string; icon: Entry["icon"]; items: Entry[]; current: string; href: (path: string) => string }) {
  const [open, setOpen] = useState(false);
  const active = items.some((item) => item.path === current);
  return <Popover isOpen={open} onOpenChange={setOpen}>
    <Button variant="tertiary" className={`nav-root${active ? " active" : ""}`} aria-label={title}><NavSymbol kind={icon}/><span>{label}</span><ChevronRight className="nav-root-chevron" size={10} aria-hidden="true"/></Button>
    <Popover.Content placement="right top" offset={12} className="nav-tree-popover">
      <Popover.Dialog aria-label={title} className="nav-tree-dialog">
        <Popover.Heading>{title}</Popover.Heading>
        <div className="nav-tree-branches">{items.map((item) => <Link key={item.path} className={`nav-tree-link${current === item.path ? " active" : ""}`} href={href(item.path)} aria-current={current === item.path ? "page" : undefined} onClick={() => setOpen(false)}><NavSymbol kind={item.icon}/><span>{item.label}</span></Link>)}</div>
      </Popover.Dialog>
    </Popover.Content>
  </Popover>;
}
