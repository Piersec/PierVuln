"use client";

import { useCallback, useEffect, useState, type FormEvent } from "react";
import { useAdmin } from "@/src/components/admin-console";

type Price = { id: string; name: string; setup_cents: number; monthly_cents: number; is_active: boolean };
type Lead = { id: string; company_name: string; contact_name: string; email: string; project_scope: string };
type Terms = { lead_id: string; plan_id: string; extra_ids: string[]; setup_cents: number; monthly_cents: number; revision: number };
type Data = { plans: Price[]; extras: Price[]; leads: Lead[]; terms: Terms[] };
const money = (cents: number) => (cents / 100).toLocaleString("pt-BR", { style: "currency", currency: "BRL" });

function cents(value: FormDataEntryValue | null) {
  const input = String(value ?? "").trim();
  if (!/^\d{1,9}([.,]\d{1,2})?$/.test(input)) throw new Error("Informe o preço em reais, com até duas casas decimais.");
  const [whole, fraction = ""] = input.replace(",", ".").split(".");
  return Number(whole) * 100 + Number(fraction.padEnd(2, "0"));
}

export function CommercialConsole() {
  const { client } = useAdmin();
  const [data, setData] = useState<Data | null>(null);
  const [error, setError] = useState("");
  const [notice, setNotice] = useState("");
  const [busy, setBusy] = useState(false);
  const [editor, setEditor] = useState<{ kind: "plans" | "extras"; row?: Price } | null>(null);
  const [leadEditor, setLeadEditor] = useState<Lead | "new" | null>(null);
  const load = useCallback(async () => {
    const results = await Promise.all([
      client.from("commercial_plans").select("*").order("name"),
      client.from("commercial_extras").select("*").order("name"),
      client.from("commercial_leads").select("*").order("created_at", { ascending: false }).limit(100),
    ]);
    const failure = results.find((result) => result.error)?.error;
    if (failure) throw new Error("Não foi possível consultar o módulo comercial. Tente novamente.");
    const leads = results[2].data ?? [];
    const terms = leads.length
      ? await client.from("commercial_lead_terms").select("*").in("lead_id", leads.map((lead) => lead.id))
      : { data: [], error: null };
    if (terms.error) throw new Error("Não foi possível carregar os valores das fichas.");
    setData({ plans: results[0].data ?? [], extras: results[1].data ?? [], leads, terms: terms.data ?? [] });
  }, [client]);
  useEffect(() => { void load().catch((cause: Error) => setError(cause.message)); }, [load]);

  async function mutate(action: () => Promise<void>) {
    if (busy) return;
    setBusy(true); setError(""); setNotice("");
    try { await action(); setNotice("Alteração salva."); await load(); }
    catch (cause) { setError(cause instanceof Error ? cause.message : "Não foi possível salvar."); }
    finally { setBusy(false); }
  }

  function savePrice(event: FormEvent<HTMLFormElement>) {
    event.preventDefault();
    const form = new FormData(event.currentTarget);
    const current = editor;
    if (!current) return;
    void mutate(async () => {
      const payload = { name: String(form.get("name")).trim(), setup_cents: cents(form.get("setup")), monthly_cents: cents(form.get("monthly")), is_active: form.has("active") };
      const query = current.row
        ? client.from(`commercial_${current.kind}`).update(payload).eq("id", current.row.id)
        : client.from(`commercial_${current.kind}`).insert(payload);
      const { error: failure } = await query.select("id").single();
      if (failure) throw new Error("Não foi possível salvar o preço.");
      setEditor(null);
    });
  }

  function saveLead(event: FormEvent<HTMLFormElement>) {
    event.preventDefault();
    const form = new FormData(event.currentTarget);
    const current = leadEditor;
    void mutate(async () => {
      const payload = { company_name: String(form.get("company")).trim(), contact_name: String(form.get("contact")).trim(), email: String(form.get("email")).trim(), project_scope: String(form.get("scope")).trim() };
      const query = current && current !== "new"
        ? client.from("commercial_leads").update(payload).eq("id", current.id)
        : client.from("commercial_leads").insert(payload);
      const { error: failure } = await query.select("id").single();
      if (failure) throw new Error("Não foi possível salvar o lead.");
      setLeadEditor(null);
    });
  }

  return <section className="commercial-console">
    <div className="page-heading"><div><h1>Comercial</h1><p>Planos, adicionais e ficha comercial dos leads.</p></div><button className="button button-primary" onClick={() => setLeadEditor("new")}>Novo lead</button></div>
    {error && <div className="inline-alert" role="alert">{error}<button className="button button-secondary" disabled={busy} onClick={() => void mutate(load)}>Tentar novamente</button></div>}
    {notice && <p role="status">{notice}</p>}
    <p className="muted-copy">Cadastro interno. Preços novos começam inativos; a seleção na ficha é recalculada pelo banco e mantém uma versão dos valores.</p>
    <div className="commercial-catalog">{(["plans", "extras"] as const).map((kind) => <section className="panel" key={kind}>
      <div className="panel-heading"><h2>{kind === "plans" ? "Planos" : "Adicionais"}</h2><button className="button button-secondary" onClick={() => setEditor({ kind })}>Adicionar</button></div>
      {!data ? <p role="status">{error ? "Catálogo indisponível." : "Carregando catálogo…"}</p> : !data[kind].length ? <p>Nenhum cadastro.</p> : data[kind].map((row) => <div className="commercial-price-row" key={row.id}><div><strong>{row.name}</strong><p>{money(row.setup_cents)} de implantação · {money(row.monthly_cents)}/mês · {row.is_active ? "Ativo" : "Inativo"}</p></div><button className="button button-secondary" onClick={() => setEditor({ kind, row })}>Editar</button></div>)}
    </section>)}</div>
    {editor && <section className="panel"><h2>{editor.row ? "Editar" : "Cadastrar"} {editor.kind === "plans" ? "plano" : "adicional"}</h2><form className="commercial-form" onSubmit={savePrice} key={`${editor.kind}-${editor.row?.id ?? "new"}`}>
      <label>Nome<input name="name" required maxLength={100} defaultValue={editor.row?.name} /></label>
      <label>Implantação (R$)<input name="setup" required inputMode="decimal" defaultValue={editor.row ? (editor.row.setup_cents / 100).toFixed(2) : "0,00"} /></label>
      <label>Mensalidade (R$)<input name="monthly" required inputMode="decimal" defaultValue={editor.row ? (editor.row.monthly_cents / 100).toFixed(2) : "0,00"} /></label>
      <label><input name="active" type="checkbox" defaultChecked={editor.row?.is_active ?? false} /> Disponível para seleção</label>
      <div><button type="button" className="button button-secondary" onClick={() => setEditor(null)}>Cancelar</button><button disabled={busy} className="button button-primary">Salvar</button></div>
    </form></section>}
    {leadEditor && <section className="panel"><h2>Ficha do lead</h2><form className="commercial-form" onSubmit={saveLead} key={typeof leadEditor === "string" ? "new" : leadEditor.id}>
      <label>Empresa<input name="company" required maxLength={200} defaultValue={leadEditor !== "new" ? leadEditor.company_name : ""} /></label>
      <label>Contato<input name="contact" required maxLength={200} defaultValue={leadEditor !== "new" ? leadEditor.contact_name : ""} /></label>
      <label>E-mail<input name="email" type="email" required maxLength={254} defaultValue={leadEditor !== "new" ? leadEditor.email : ""} /></label>
      <label>Escopo do projeto<textarea name="scope" maxLength={10000} defaultValue={leadEditor !== "new" ? leadEditor.project_scope : ""} /></label>
      <div><button type="button" className="button button-secondary" onClick={() => setLeadEditor(null)}>Cancelar</button><button disabled={busy} className="button button-primary">Salvar ficha</button></div>
    </form></section>}
    <section className="panel"><h2>Leads</h2><p className="muted-copy">Até 100 fichas recentes. Valores salvos só mudam após recalcular a seleção.</p>{data?.leads.map((lead) => {
      const terms = data.terms.find((item) => item.lead_id === lead.id);
      return <article className="commercial-lead" key={`${lead.id}-${terms?.revision ?? 0}`}><div className="panel-heading"><div><h3>{lead.company_name}</h3><p>{lead.contact_name} · {lead.email}</p></div><button className="button button-secondary" onClick={() => setLeadEditor(lead)}>Editar ficha</button></div><p>{lead.project_scope}</p>
        {terms && <p>Implantação: <strong>{money(terms.setup_cents)}</strong> · Mensalidade: <strong>{money(terms.monthly_cents)}</strong> · Revisão {terms.revision}</p>}
        <form className="commercial-form" onSubmit={(event) => {
          event.preventDefault(); const form = new FormData(event.currentTarget);
          void mutate(async () => { const { error: failure } = await client.rpc("set_commercial_lead_selection", { p_lead_id: lead.id, p_plan_id: form.get("plan"), p_extra_ids: form.getAll("extras") }); if (failure) throw new Error("Não foi possível calcular a seleção. Verifique se o plano e os adicionais estão ativos."); });
        }}><label>Plano<select name="plan" required defaultValue={terms?.plan_id ?? ""}><option value="" disabled>Selecione</option>{data.plans.filter((row) => row.is_active || row.id === terms?.plan_id).map((row) => <option value={row.id} key={row.id} disabled={!row.is_active}>{row.name}{row.is_active ? "" : " (inativo)"}</option>)}</select></label>
          <fieldset><legend>Adicionais</legend>{data.extras.filter((row) => row.is_active).map((row) => <label key={row.id}><input type="checkbox" name="extras" value={row.id} defaultChecked={terms?.extra_ids.includes(row.id)} /> {row.name} · {money(row.monthly_cents)}/mês</label>)}</fieldset><button className="button button-primary" disabled={busy}>Recalcular e salvar seleção</button>
        </form></article>;
    })}{data && !data.leads.length && <p>Nenhum lead cadastrado.</p>}</section>
  </section>;
}
