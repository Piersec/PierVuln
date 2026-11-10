"use client";

import { useEffect, useState } from "react";
import { BookSocFrame, type FrameContext } from "@/src/components/book-soc-frame";
import { BarList, SectionHead } from "@/src/components/book-soc-parts";
import { lastMonths, type Overview } from "@/src/lib/book-soc/overview";

type Result = Overview & { consultadoEm: string };

const SEVERITY_ORDER = ["Critical", "High", "Medium", "Low", "Informational", "Unknown", "-"];

export function BookSocOverview() {
  return (
    <BookSocFrame section="visao" subtitle="Visão executiva · estado atual das vulnerabilidades, direto do Wazuh">
      {(context) => <OverviewContent key={context.client.id} context={context} />}
    </BookSocFrame>
  );
}

function OverviewContent({ context }: { context: FrameContext }) {
  const [result, setResult] = useState<Result | null>(null);
  const [error, setError] = useState("");
  const [loading, setLoading] = useState(true);
  const { token, client } = context;

  useEffect(() => {
    const controller = new AbortController();
    setLoading(true); setError(""); setResult(null);
    void fetch("/api/book-soc/overview", {
      method: "POST",
      headers: { "content-type": "application/json", authorization: `Bearer ${token}` },
      body: JSON.stringify({ client: client.id }),
      signal: controller.signal,
    })
      .then(async (response) => {
        const body = await response.json().catch(() => null);
        if (!response.ok) throw new Error(body?.error ?? "Não foi possível concluir a consulta.");
        setResult(body as Result);
      })
      .catch((caught: unknown) => {
        if (controller.signal.aborted) return;
        setError(caught instanceof Error ? caught.message : "Não foi possível concluir a consulta.");
      })
      .finally(() => { if (!controller.signal.aborted) setLoading(false); });
    return () => controller.abort();
  }, [token, client.id]);

  if (error) return <div className="inline-alert" role="alert">{error}</div>;
  if (loading || !result) return <div className="admin-loading" role="status"><div className="spinner" />Consultando o Wazuh…</div>;

  const criticalHigh = result.porSeveridade.filter((item) => item.severidade === "Critical" || item.severidade === "High").reduce((sum, item) => sum + item.registros, 0);

  return (
    <div className="bsoc-stack">
      <div className="bsoc-hero">
        <section className="bsoc-card bsoc-card--inset" aria-label="Destaque">
          <span className="bsoc-tag">Destaque da visão</span>
          <strong className="bsoc-big">{result.total.toLocaleString("pt-BR")}</strong>
          <p className="bsoc-caption">registros de vulnerabilidade no estado atual deste cliente</p>
        </section>
        <section className="bsoc-card" aria-label="Situação atual">
          <SectionHead title="Situação atual" />
          <div className="bsoc-stats">
            <div><strong>{criticalHigh.toLocaleString("pt-BR")}</strong><span>críticas e altas</span></div>
            <div><strong>{result.hosts.toLocaleString("pt-BR")}</strong><span>hosts afetados</span></div>
            <div><strong>{result.cves.toLocaleString("pt-BR")}</strong><span>CVEs únicos</span></div>
          </div>
          <p className="bsoc-note">Fotografia da consulta de {new Date(result.consultadoEm).toLocaleString("pt-BR")}; não representa o fechamento histórico do mês.</p>
        </section>
      </div>

      <div className="bsoc-trio">
        <section className="bsoc-card" aria-label="Distribuição por severidade">
          <SectionHead tag="Distribuição por severidade" title="Registros por severidade" />
          <BarList label="Registros por severidade" rows={sortedSeverities(result).map((item) => ({ label: item.severidade === "-" ? "Sem severidade" : item.severidade, count: item.registros }))} />
          <p className="bsoc-note">Total de registros em cada severidade informada pela fonte.</p>
        </section>
        <section className="bsoc-card" aria-label="Tempo de exposição">
          <SectionHead tag="Faixa de tempo da exposição" title="Há quanto tempo constam" />
          <BarList label="Registros por faixa de idade" rows={result.idade.map((item) => ({ label: item.label, count: item.registros }))} />
          <p className="bsoc-note">Idade pela data de detecção registrada no índice. Se o Wazuh reindexa, essa data pode refletir a varredura mais recente e não a primeira detecção.</p>
        </section>
        <section className="bsoc-card" aria-label="Evolução por detecção">
          <SectionHead tag="Evolução temporal" title="Mês da detecção" side="Últimos 6 meses" />
          <BarList label="Registros por mês de detecção" rows={lastMonths(result.meses).map((item) => ({ label: monthLabel(item.key), count: item.registros }))} />
          <p className="bsoc-note">Agrupa os registros atuais pela data de detecção registrada. Não é o total histórico da fonte.</p>
        </section>
      </div>

      <section className="bsoc-card" aria-label="Concentração por vulnerabilidade">
        <SectionHead tag="Concentração por vulnerabilidade" title="Principais CVEs por ativos afetados" />
        <div className="bsoc-table-wrap">
          <table className="bsoc-table">
            <thead>
              <tr><th scope="col">CVE</th><th scope="col">Severidade</th><th scope="col" className="is-num">CVSS</th><th scope="col" className="is-num hide-narrow">Registros</th><th scope="col" className="is-num">Hosts</th></tr>
            </thead>
            <tbody>
              {result.topCves.map((item) => (
                <tr key={item.cve}>
                  <td><strong>{item.cve}</strong></td>
                  <td>{item.severidade}</td>
                  <td className="is-num">{item.cvss === null ? "—" : item.cvss.toFixed(1)}</td>
                  <td className="is-num hide-narrow">{item.registros.toLocaleString("pt-BR")}</td>
                  <td className="is-num">{item.hosts.toLocaleString("pt-BR")}</td>
                </tr>
              ))}
            </tbody>
          </table>
        </div>
        <p className="bsoc-note">Ordenado pelo número de hosts distintos afetados. O escopo do cliente é o da conta somente leitura dele no Wazuh.</p>
      </section>
    </div>
  );
}

function monthLabel(key: string) {
  const [year, month] = key.split("-").map(Number);
  return new Date(year, month - 1, 1).toLocaleDateString("pt-BR", { month: "short", year: "2-digit" }).replace(".", "");
}

function sortedSeverities(result: Overview) {
  const rank = (name: string) => { const index = SEVERITY_ORDER.indexOf(name); return index === -1 ? SEVERITY_ORDER.length : index; };
  return [...result.porSeveridade].sort((a, b) => rank(a.severidade) - rank(b.severidade) || a.severidade.localeCompare(b.severidade));
}
