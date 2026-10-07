"use client";

import { Button, Popover } from "@heroui/react";
import type { SupabaseClient } from "@supabase/supabase-js";
import { useEffect, useMemo, useState } from "react";
import { visibleText } from "@/src/lib/visible-text";

type Company = { id: string; name: string; slug: string; logo_dark_path?: string | null; logo_light_path?: string | null };
type Source = { id: string; name: string; mode: string; tenant_id: string | null };
type Mapping = { connection_id: string; tenant_id: string };
const logos: Record<string, string> = {
  amalog: "amalog", "bandeirante-deicmar": "bandeirante-deicmar", invista: "invista",
  "jean-piaget": "jean-piaget", maxipark: "maxipark", reliance: "reliance", unimar: "unimar", yamam: "yamam",
};

function CompanyLogo({ company, client }: { company: Company; client: SupabaseClient }) {
  const [failed, setFailed] = useState(false);
  const darkPath = company.logo_dark_path ?? company.logo_light_path;
  const lightPath = company.logo_light_path ?? company.logo_dark_path;
  if (darkPath && !failed) {
    const darkUrl = client.storage.from("company-logos").getPublicUrl(darkPath).data.publicUrl;
    const lightUrl = lightPath ? client.storage.from("company-logos").getPublicUrl(lightPath).data.publicUrl : darkUrl;
    return <><img className="company-logo-dark" src={darkUrl} alt="" onError={() => setFailed(true)} /><img className="company-logo-light" src={lightUrl} alt="" onError={() => setFailed(true)} /></>;
  }
  const key = company.slug.toLowerCase();
  const nameKey = company.name.toLowerCase().replace(/\s+/g, "-");
  const logo = logos[key] ?? logos[nameKey];
  return logo && !failed
    ? <img src={`/company-logos/${logo}.png`} alt="" onError={() => setFailed(true)} />
    : <span className="company-logo-fallback" aria-hidden="true">{visibleText(company.name).slice(0, 2).toUpperCase()}</span>;
}

export function CompanyPicker({ client, companies, value, onChange, isInternal }: {
  client: SupabaseClient; companies: Company[]; value: string; onChange: (id: string) => void; isInternal: boolean;
}) {
  const [open, setOpen] = useState(false);
  const [topology, setTopology] = useState<{ sources: Source[]; mappings: Mapping[] } | null>(null);
  const [error, setError] = useState(false);
  const [retry, setRetry] = useState(0);
  const companyIds = companies.map((company) => company.id).sort().join(",");
  useEffect(() => { setTopology(null); setError(false); }, [companyIds, isInternal]);
  useEffect(() => {
    if (!open || topology || error) return;
    let active = true;
    async function load() {
      try {
        const [sources, mappings] = await Promise.all([
          client.from("wazuh_connections").select("id,name,mode,tenant_id").eq("is_active", true),
          isInternal ? client.from("wazuh_agent_mappings").select("connection_id,tenant_id").eq("is_active", true)
            : Promise.resolve({ data: [] as Mapping[], error: null }),
        ]);
        if (!active) return;
        if (sources.error || mappings.error) { setError(true); return; }
        setTopology({ sources: sources.data ?? [], mappings: mappings.data ?? [] });
      } catch { if (active) setError(true); }
    }
    void load();
    return () => { active = false; };
  }, [client, companyIds, error, isInternal, open, retry, topology]);
  const groups = useMemo(() => {
    const used = new Set<string>();
    const shared = (topology?.sources ?? []).filter((source) => source.mode === "shared").flatMap((source) => {
      const mappedIds = new Set(topology?.mappings.filter((mapping) => mapping.connection_id === source.id).map((mapping) => mapping.tenant_id));
      const members = companies.filter((company) => mappedIds.has(company.id) && !used.has(company.id));
      members.forEach((company) => used.add(company.id));
      return members.length ? [{ source, members }] : [];
    });
    const dedicatedIds = new Set(topology?.sources.filter((source) => source.mode === "dedicated").map((source) => source.tenant_id));
    return { shared, remaining: companies.filter((company) => !used.has(company.id)), dedicatedIds };
  }, [companies, topology]);
  function choose(id: string) { onChange(id); setOpen(false); }
  function tile(company: Company, compact = false) {
    return <button type="button" key={company.id} className={`company-picker-tile${compact ? " compact" : ""}`} aria-label={`Selecionar ${visibleText(company.name)}`} aria-pressed={company.id === value} onClick={() => choose(company.id)}>
      <span className="company-picker-logo"><CompanyLogo company={company} client={client} /></span>
      <span className="company-picker-name">{visibleText(company.name)}</span>
      {company.id === value && <span className="company-picker-check" aria-hidden="true">✓</span>}
      {!compact && <small>{groups.dedicatedIds.has(company.id) ? "Fonte dedicada" : "Empresa"}</small>}
    </button>;
  }
  const selected = companies.find((company) => company.id === value);
  const compactPanel = groups.shared.length + groups.remaining.length <= 1;
  return <Popover isOpen={open} onOpenChange={setOpen}>
    <Button variant="secondary" className="company-picker-trigger" aria-label={`Selecionar empresa: ${selected ? visibleText(selected.name) : "Todas as empresas"}`}>
      {selected && <span className="company-picker-trigger-logo"><CompanyLogo key={selected.id} company={selected} client={client} /></span>}
      <span>{selected ? visibleText(selected.name) : "Todas as empresas"}</span><span className="company-picker-chevron" aria-hidden="true">⌄</span>
    </Button>
    <Popover.Content placement="bottom end" offset={10} className="company-picker-content" data-compact={compactPanel}>
      <Popover.Dialog className="company-picker-dialog" aria-label="Selecionar empresa do dashboard">
        <div className="company-picker-heading"><Popover.Heading>Selecionar empresa</Popover.Heading><Button variant="tertiary" isIconOnly aria-label="Fechar seleção de empresas" onPress={() => setOpen(false)}>×</Button></div>
        <button type="button" className="company-picker-all" aria-pressed={!value} onClick={() => choose("")}><span>Todas as empresas</span><small>{companies.length} {companies.length === 1 ? "empresa" : "empresas"}</small>{!value && <span aria-hidden="true">✓</span>}</button>
        {!topology && !error ? <div className="company-picker-loading" role="status">Carregando empresas e fontes…</div> : <>
          {error && <div className="company-picker-error"><span>Não foi possível agrupar as fontes. Você ainda pode selecionar uma empresa.</span><button type="button" onClick={() => { setError(false); setRetry((previous) => previous + 1); }}>Tentar novamente</button></div>}
          <div className="company-picker-grid">
            {groups.shared.map(({ source, members }) => <section className="company-picker-shared" key={source.id} aria-label={visibleText(source.name)}><div className="company-picker-shared-grid">{members.map((company) => tile(company, true))}</div><span className="company-picker-group-label">Compartilhado<small>{visibleText(source.name)}</small></span></section>)}
            {groups.remaining.map((company) => tile(company))}
          </div>
        </>}
      </Popover.Dialog>
    </Popover.Content>
  </Popover>;
}
