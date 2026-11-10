"use client";

import { useEffect, useMemo, useState, type FormEvent } from "react";
import { BookSocFrame, type FrameContext } from "@/src/components/book-soc-frame";
import { SectionHead } from "@/src/components/book-soc-parts";
import { DEFAULT_FILTERS, MAX_RANGE_DAYS, filterLabel, parseAlertsRequest, type AlertFilters, type AlertsResult } from "@/src/lib/book-soc/alerts";

type Result = AlertsResult & { consultadoEm: string };
type Params = { start: string; end: string; filtros: AlertFilters };
type Draft = { start: string; end: string; nivelMinimo: string; nivelMaximo: string; decoder: string; incluir: string; excluir: string };

const LEVELS = Array.from({ length: 17 }, (_, level) => level);

function isoDay(date: Date) {
  return `${date.getFullYear()}-${String(date.getMonth() + 1).padStart(2, "0")}-${String(date.getDate()).padStart(2, "0")}`;
}

function defaultParams(): Params {
  const now = new Date();
  return { start: isoDay(new Date(now.getFullYear(), now.getMonth(), 1)), end: isoDay(now), filtros: { ...DEFAULT_FILTERS } };
}

function toDraft(params: Params): Draft {
  const f = params.filtros;
  return {
    start: params.start, end: params.end, nivelMinimo: String(f.nivelMinimo), nivelMaximo: String(f.nivelMaximo),
    decoder: f.decoder ?? "", incluir: f.regrasIncluidas.join(", "), excluir: f.regrasExcluidas.join(", "),
  };
}

const splitRules = (text: string) => text.split(/[\s,;]+/).filter(Boolean);

function fromDraft(clientId: string, draft: Draft): Params | null {
  const request = parseAlertsRequest({
    client: clientId, start: draft.start, end: draft.end,
    filtros: {
      nivelMinimo: Number(draft.nivelMinimo), nivelMaximo: Number(draft.nivelMaximo), decoder: draft.decoder || null,
      regrasIncluidas: splitRules(draft.incluir), regrasExcluidas: splitRules(draft.excluir),
    },
  });
  return request ? { start: request.start, end: request.end, filtros: request.filtros } : null;
}

export function BookSocAlerts() {
  return (
    <BookSocFrame section="alertas" subtitle="Painel de alertas · ocorrências do período para revisão do SOC, direto do Wazuh">
      {(context) => <AlertsContent key={context.client.id} context={context} />}
    </BookSocFrame>
  );
}

function AlertsContent({ context }: { context: FrameContext }) {
  const { token, client } = context;
  const initial = useMemo(defaultParams, []);
  const [applied, setApplied] = useState<Params>(initial);
  const [draft, setDraft] = useState<Draft>(() => toDraft(initial));
  const [formError, setFormError] = useState("");
  const [result, setResult] = useState<Result | null>(null);
  const [decoders, setDecoders] = useState<{ nome: string; registros: number }[]>([]);
  const [error, setError] = useState("");
  const [loading, setLoading] = useState(client.alerts);

  useEffect(() => {
    if (!client.alerts) return;
    const controller = new AbortController();
    setLoading(true); setError("");
    void fetch("/api/book-soc/alertas", {
      method: "POST",
      headers: { "content-type": "application/json", authorization: `Bearer ${token}` },
      body: JSON.stringify({ client: client.id, start: applied.start, end: applied.end, filtros: applied.filtros }),
      signal: controller.signal,
    })
      .then(async (response) => {
        const body = await response.json().catch(() => null);
        if (!response.ok) throw new Error(body?.error ?? "Não foi possível concluir a consulta.");
        setResult(body as Result);
        setDecoders((body as Result).decoders);
      })
      .catch((caught: unknown) => {
        if (controller.signal.aborted) return;
        setResult(null);
        setError(caught instanceof Error ? caught.message : "Não foi possível concluir a consulta.");
      })
      .finally(() => { if (!controller.signal.aborted) setLoading(false); });
    return () => controller.abort();
  }, [token, client.id, client.alerts, applied]);

  const pending = JSON.stringify(draft) !== JSON.stringify(toDraft(applied));

  function apply(event: FormEvent) {
    event.preventDefault();
    const next = fromDraft(client.id, draft);
    if (!next) {
      setFormError(`Confira o período (até ${MAX_RANGE_DAYS} dias), os níveis (0–16, mínimo não maior que o máximo) e os IDs de regra (de 1 a 999999, até 20, sem repetir entre incluir e excluir).`);
      return;
    }
    setFormError("");
    setApplied(next);
  }

  if (!client.alerts) return <div className="inline-alert" role="alert">Alertas não estão configurados para este cliente.</div>;

  const decoderOptions = decoders.some((item) => item.nome === draft.decoder) || !draft.decoder ? decoders : [{ nome: draft.decoder, registros: 0 }, ...decoders];

  return (
    <div className="bsoc-stack">
      <details className="bsoc-card bsoc-params" open>
        <summary>
          <span><strong>Parâmetros dos alertas</strong><small>{filterLabel(applied.filtros)} · {applied.start} a {applied.end}</small></span>
        </summary>
        <form className="bsoc-form" onSubmit={apply} noValidate>
          <p className="bsoc-caption">Defina quais ocorrências entram neste painel. Sem seleção, o padrão é nível 12 ou superior. O nível da regra não define o risco para o negócio.</p>
          <div className="bsoc-fields">
            <label>Início do período<input type="date" value={draft.start} onChange={(e) => setDraft({ ...draft, start: e.target.value })} /></label>
            <label>Fim do período<input type="date" value={draft.end} onChange={(e) => setDraft({ ...draft, end: e.target.value })} /></label>
            <label>Nível mínimo
              <select value={draft.nivelMinimo} onChange={(e) => setDraft({ ...draft, nivelMinimo: e.target.value })}>
                {LEVELS.map((level) => <option key={level} value={level}>{level === DEFAULT_FILTERS.nivelMinimo ? `Padrão · ${level}` : level}</option>)}
              </select>
            </label>
            <label>Nível máximo
              <select value={draft.nivelMaximo} onChange={(e) => setDraft({ ...draft, nivelMaximo: e.target.value })}>
                {LEVELS.map((level) => <option key={level} value={level}>{level === DEFAULT_FILTERS.nivelMaximo ? `Padrão · ${level}` : level}</option>)}
              </select>
            </label>
            <label className="bsoc-field-wide">Origem do evento (decoder)
              <select value={draft.decoder} onChange={(e) => setDraft({ ...draft, decoder: e.target.value })}>
                <option value="">Todas as origens</option>
                {decoderOptions.map((item) => <option key={item.nome} value={item.nome}>{item.nome}</option>)}
              </select>
            </label>
            <label className="bsoc-field-wide">Incluir somente estas regras<input type="text" inputMode="numeric" placeholder="Ex.: 5710, 5712" value={draft.incluir} onChange={(e) => setDraft({ ...draft, incluir: e.target.value })} /></label>
            <label className="bsoc-field-wide">Excluir estas regras<input type="text" inputMode="numeric" placeholder="Ex.: 100001, 100002" value={draft.excluir} onChange={(e) => setDraft({ ...draft, excluir: e.target.value })} /></label>
          </div>
          <p className="bsoc-note">Opcional: até 20 IDs por campo, separados por vírgula. Com inclusão preenchida, somente essas regras são consideradas, junto aos demais filtros.</p>
          {formError && <div className="inline-alert" role="alert">{formError}</div>}
          <div className="bsoc-actions">
            <button type="submit" className="button button-primary" disabled={loading}>Aplicar e consultar</button>
            <button type="button" className="button button-secondary" onClick={() => { setDraft(toDraft({ ...applied, filtros: { ...DEFAULT_FILTERS } })); setFormError(""); }}>Restaurar padrão</button>
            <button type="button" className="button button-secondary" disabled={!pending} onClick={() => { setDraft(toDraft(applied)); setFormError(""); }}>Desfazer edição</button>
          </div>
          <p className="bsoc-status" role="status">{pending ? "Há edições pendentes: aplique para atualizar o painel." : "Filtros sem alterações."}</p>
        </form>
      </details>

      {error && <div className="inline-alert" role="alert">{error}</div>}
      {loading && <div className="admin-loading" role="status"><div className="spinner" />Consultando o Wazuh…</div>}

      {result && !loading && (
        <>
          <div className="bsoc-trio">
            <section className="bsoc-card bsoc-card--inset" aria-label="Ocorrências para revisão">
              <span className="bsoc-tag">Ocorrências para revisão</span>
              <strong className="bsoc-big">{result.revisao.toLocaleString("pt-BR")}</strong>
              <p className="bsoc-caption">Ocorrências conforme os parâmetros aplicados acima.</p>
            </section>
            <section className="bsoc-card bsoc-card--stat" aria-label="Alterações em Domain Admins">
              <span className="bsoc-tag">Alterações em Domain Admins</span>
              <strong className="bsoc-big bsoc-big--accent">{result.admins.toLocaleString("pt-BR")}</strong>
              <p className="bsoc-caption">Período completo da consulta, independente destes filtros. Valide autorização e finalidade com o SOC.</p>
            </section>
            <section className="bsoc-card bsoc-callout" aria-label="Da detecção à classificação">
              <h2>Da detecção à classificação</h2>
              <p className="bsoc-caption">A detecção técnica não confirma um incidente. Tratamento e classificação de negócio dependem da validação do SOC.</p>
            </section>
          </div>

          <section className="bsoc-card" aria-label="Ocorrências por regra">
            <SectionHead tag="Categoria / regra" title="Ocorrências por regra" side={`${result.regras.length} de até 20 regras`} />
            {result.regras.length === 0 ? (
              <p className="bsoc-empty">Nenhuma ocorrência atende aos parâmetros aplicados neste período.</p>
            ) : (
              <div className="bsoc-table-wrap">
                <table className="bsoc-table">
                  <thead>
                    <tr><th scope="col">Regra</th><th scope="col" className="is-num hide-narrow">Nível</th><th scope="col" className="is-num">Ocorrências</th><th scope="col" className="is-num hide-narrow">Participação</th></tr>
                  </thead>
                  <tbody>
                    {result.regras.map((rule) => (
                      <tr key={rule.id}>
                        <td><strong>{rule.id}</strong><span className="bsoc-rule-description">{rule.descricao ?? "Sem descrição na amostra"}</span></td>
                        <td className="is-num hide-narrow">{rule.nivel ?? "—"}</td>
                        <td className="is-num">{rule.registros.toLocaleString("pt-BR")}<span className="bsoc-sub">Nível {rule.nivel ?? "—"} · {percent(rule.participacao)}</span></td>
                        <td className="is-num hide-narrow">{percent(rule.participacao)}</td>
                      </tr>
                    ))}
                    {result.outrasRegras > 0 && (
                      <tr>
                        <td><strong>Outras regras</strong><span className="bsoc-rule-description">Fora das 20 com mais ocorrências</span></td>
                        <td className="is-num hide-narrow">—</td>
                        <td className="is-num">{result.outrasRegras.toLocaleString("pt-BR")}<span className="bsoc-sub">{percent(result.outrasRegras / Math.max(1, result.revisao))}</span></td>
                        <td className="is-num hide-narrow">{percent(result.outrasRegras / Math.max(1, result.revisao))}</td>
                      </tr>
                    )}
                  </tbody>
                </table>
              </div>
            )}
            <p className="bsoc-note">
              Volumetria total do período: {result.volume.toLocaleString("pt-BR")} registros; {result.escopo.toLocaleString("pt-BR")} no escopo da análise, sem os grupos de regra excluídos.
              Participação sobre as ocorrências para revisão. Consulta de {new Date(result.consultadoEm).toLocaleString("pt-BR")}. Não são ataques nem incidentes confirmados.
            </p>
          </section>
        </>
      )}
    </div>
  );
}

function percent(share: number) {
  return `${(share * 100).toLocaleString("pt-BR", { maximumFractionDigits: 1 })}%`;
}
