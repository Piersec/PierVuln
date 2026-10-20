import { randomUUID } from "node:crypto";
import { createReadStream, createWriteStream } from "node:fs";
import { mkdtemp, rm, stat } from "node:fs/promises";
import { tmpdir } from "node:os";
import path from "node:path";
import { Readable } from "node:stream";
import { once } from "node:events";
import { pipeline } from "node:stream/promises";
import { createGunzip, createGzip } from "node:zlib";
import { createInterface } from "node:readline";
import ExcelJS from "exceljs";
import type { CellValue, Worksheet } from "exceljs";
import { createClient, type SupabaseClient } from "@supabase/supabase-js";

export const runtime = "nodejs";
export const maxDuration = 300;

const batchSize = 5_000;
const severityKeys = ["Critical", "High", "Medium", "Low", "Informational", "Unknown"] as const;
type SeverityKey = (typeof severityKeys)[number];
type SeverityCounts = Record<SeverityKey, number> & { total: number };
type ExportFinding = {
  finding_id: string;
  workflow_status: string;
  finding_agent_id: string | null;
  finding_agent_name: string | null;
  finding_host_os: string | null;
  finding_package_name: string | null;
  finding_package_version: string | null;
  finding_vulnerability_id: string;
  finding_description: string | null;
  finding_cvss_base: number | string | null;
  finding_reference_urls: string[] | null;
  finding_first_detected_at: string;
  finding_last_seen_at: string;
};
type ExportRow = {
  hostKey: string;
  hostName: string;
  osName: string;
  component: string;
  cve: string;
  description: string;
  severity: SeverityKey;
  score: number | null;
  reference: string;
  firstDetected: string;
  lastSeen: string;
  ageDays: number;
  workflowStatus: string;
};
type HistoryRow = {
  granularity: "weekly" | "monthly";
  period_start: string;
  period_end: string;
  total_findings: number;
  critical_count: number;
  high_count: number;
  medium_count: number;
  low_count: number;
  informational_count: number | null;
  unclassified_count: number | null;
  source_kind: string;
};
type GroupedAsset = SeverityCounts & { label: string };
type GroupedCve = {
  cve: string;
  severity: SeverityKey;
  cvss: number | null;
  description: string;
  firstDetected: string;
  ageDays: number;
  hosts: Map<string, string>;
  packages: Set<string>;
  references: Set<string>;
  statuses: Set<string>;
};
type CollectedInventory = {
  totals: SeverityCounts;
  hosts: Map<string, GroupedAsset>;
  software: Map<string, GroupedAsset>;
  cves: Map<string, GroupedCve>;
  affectedHostKeys: Set<string>;
  uniqueCves: Set<string>;
  ageCounts: number[];
  rowCount: number;
};

const colors = {
  dark: "FF111619",
  panel: "FF20272B",
  header: "FF293438",
  cyan: "FF48E9FF",
  white: "FFF6F7F7",
  line: "FFD6DCE0",
};

class ExportError extends Error {
  constructor(message: string, readonly status: number) {
    super(message);
  }
}

function emptySeverityCounts(): SeverityCounts {
  return { Critical: 0, High: 0, Medium: 0, Low: 0, Informational: 0, Unknown: 0, total: 0 };
}

function cleanText(value: unknown, maxLength = 32_000): string {
  if (typeof value !== "string") return "";
  const cleaned = value.replace(/[\u0000-\u0008\u000B\u000C\u000E-\u001F\uFFFE\uFFFF]/g, " ").trim();
  return cleaned.length > maxLength ? `${cleaned.slice(0, maxLength - 18)} [texto reduzido]` : cleaned;
}

function scoreValue(value: ExportFinding["finding_cvss_base"]): number | null {
  if (value === null || value === undefined || value === "") return null;
  const score = typeof value === "number" ? value : Number(value);
  return Number.isFinite(score) && score >= 0 && score <= 10 ? score : null;
}

function severityFor(score: number | null): SeverityKey {
  if (score === null) return "Unknown";
  if (score >= 9) return "Critical";
  if (score >= 7) return "High";
  if (score >= 4) return "Medium";
  if (score >= 1) return "Low";
  return "Informational";
}

function severityLabel(severity: SeverityKey): string {
  return ({ Critical: "Crítica", High: "Alta", Medium: "Média", Low: "Baixa", Informational: "Informativa", Unknown: "Sem classificação" })[severity];
}

function dateValue(value: string | null | undefined): Date | null {
  if (!value) return null;
  const date = new Date(value);
  return Number.isNaN(date.valueOf()) ? null : date;
}

function ageInDays(firstDetected: string, generatedAt: Date): number {
  const detected = dateValue(firstDetected);
  return detected ? Math.max(0, Math.floor((generatedAt.valueOf() - detected.valueOf()) / 86_400_000)) : 0;
}

function ageBand(ageDays: number): string {
  if (ageDays > 90) return ">90 Dias";
  if (ageDays >= 61) return "61-90 Dias";
  if (ageDays >= 31) return "31-60 Dias";
  return "<30 Dias";
}

function ageBandIndex(ageDays: number): number {
  return ageDays > 90 ? 0 : ageDays >= 61 ? 1 : ageDays >= 31 ? 2 : 3;
}

function incrementCounts(counts: SeverityCounts, severity: SeverityKey) {
  counts[severity] += 1;
  counts.total += 1;
}

function severityRank(severity: SeverityKey): number {
  return ({ Critical: 0, High: 1, Medium: 2, Low: 3, Informational: 4, Unknown: 5 })[severity];
}

function priorityRank(ageDays: number): number {
  return ageDays > 90 ? 0 : ageDays >= 61 ? 1 : ageDays >= 31 ? 2 : 3;
}

function workflowLabel(statuses: Set<string>): string {
  if (statuses.has("in_progress")) return "Em andamento";
  if (statuses.has("awaiting_validation")) return "Aguardando validação";
  if (statuses.has("resolved")) return "Resolvida pela fonte";
  return "Pendente";
}

function formatPeriod(row: HistoryRow): string {
  const start = new Date(`${row.period_start}T00:00:00Z`);
  const end = new Date(`${row.period_end}T00:00:00Z`);
  if (row.granularity === "monthly") {
    return new Intl.DateTimeFormat("pt-BR", { month: "short", year: "numeric", timeZone: "UTC" }).format(start).replace(".", "");
  }
  const short = new Intl.DateTimeFormat("pt-BR", { day: "2-digit", month: "short", timeZone: "UTC" });
  const year = new Intl.DateTimeFormat("pt-BR", { year: "numeric", timeZone: "UTC" }).format(end);
  return `Semana ${short.format(start)}–${short.format(end)}/${year}`;
}

function addTitle(sheet: Worksheet, title: string, width: number) {
  const row = sheet.addRow([title, ...Array.from({ length: Math.max(0, width - 1) }, () => null)]);
  row.height = 30;
  row.eachCell({ includeEmpty: true }, (cell) => {
    cell.fill = { type: "pattern", pattern: "solid", fgColor: { argb: colors.dark } };
    cell.font = { name: "Aptos Display", size: 17, bold: true, color: { argb: colors.white } };
    cell.alignment = { vertical: "middle" };
  });
  row.commit();
}

function addSection(sheet: Worksheet, title: string, width: number) {
  const row = sheet.addRow([title, ...Array.from({ length: Math.max(0, width - 1) }, () => null)]);
  row.height = 23;
  row.eachCell({ includeEmpty: true }, (cell) => {
    cell.fill = { type: "pattern", pattern: "solid", fgColor: { argb: colors.panel } };
    cell.font = { name: "Aptos", size: 12, bold: true, color: { argb: colors.cyan } };
    cell.alignment = { vertical: "middle" };
  });
  row.commit();
}

function addHeader(sheet: Worksheet, values: CellValue[]) {
  const row = sheet.addRow(values);
  row.height = 29;
  row.eachCell({ includeEmpty: true }, (cell) => {
    cell.fill = { type: "pattern", pattern: "solid", fgColor: { argb: colors.header } };
    cell.font = { name: "Aptos", size: 10, bold: true, color: { argb: colors.white } };
    cell.alignment = { vertical: "middle", wrapText: true };
    cell.border = { bottom: { style: "thin", color: { argb: colors.cyan } } };
  });
  row.commit();
}

function addDataRow(sheet: Worksheet, values: CellValue[]) {
  const row = sheet.addRow(values);
  row.eachCell({ includeEmpty: true }, (cell) => {
    cell.font = { name: "Aptos", size: 10, color: { argb: colors.dark } };
    cell.alignment = { vertical: "top", wrapText: true };
    cell.border = { bottom: { style: "hair", color: { argb: colors.line } } };
  });
  row.commit();
}

async function readPublicationMarker(client: SupabaseClient, signal: AbortSignal): Promise<string> {
  const { data, error } = await client.from("wazuh_connections")
    .select("id,published_sync_run_id")
    .order("id")
    .abortSignal(signal);
  if (error) throw new ExportError("Não foi possível confirmar a leitura atual da empresa.", 503);
  return JSON.stringify((data ?? []).map((row) => [row.id, row.published_sync_run_id]));
}

function toExportRow(finding: ExportFinding, generatedAt: Date): ExportRow {
  const score = scoreValue(finding.finding_cvss_base);
  const agentId = cleanText(finding.finding_agent_id, 256);
  const hostName = cleanText(finding.finding_agent_name, 512) || agentId || "Não informado";
  const packageName = cleanText(finding.finding_package_name, 1_000);
  const packageVersion = cleanText(finding.finding_package_version, 1_000);
  const reference = Array.isArray(finding.finding_reference_urls)
    ? finding.finding_reference_urls.map((value) => cleanText(value, 2_000)).find(Boolean) ?? ""
    : "";
  const firstDetected = finding.finding_first_detected_at;
  return {
    hostKey: agentId || hostName,
    hostName,
    osName: cleanText(finding.finding_host_os, 1_000) || "Não informado",
    component: [packageName, packageVersion].filter(Boolean).join(" ") || "Não informado",
    cve: cleanText(finding.finding_vulnerability_id, 80).toUpperCase() || "NÃO INFORMADO",
    description: cleanText(finding.finding_description),
    severity: severityFor(score),
    score,
    reference,
    firstDetected,
    lastSeen: finding.finding_last_seen_at,
    ageDays: ageInDays(firstDetected, generatedAt),
    workflowStatus: finding.workflow_status || "open",
  };
}

async function collectInventory(args: {
  client: SupabaseClient;
  companyId: string;
  archivePath: string;
  generatedAt: Date;
  signal: AbortSignal;
}): Promise<CollectedInventory> {
  const { client, companyId, archivePath, generatedAt, signal } = args;
  const inventory: CollectedInventory = {
    totals: emptySeverityCounts(),
    hosts: new Map(),
    software: new Map(),
    cves: new Map(),
    affectedHostKeys: new Set(),
    uniqueCves: new Set(),
    ageCounts: [0, 0, 0, 0],
    rowCount: 0,
  };
  const gzip = createGzip({ level: 6 });
  const outputDone = pipeline(gzip, createWriteStream(archivePath));
  let afterId: string | null = null;

  try {
    while (true) {
      if (signal.aborted) throw new ExportError("A exportação foi cancelada.", 499);
      const { data, error } = await client.rpc("get_report_export_batch", {
        p_company_id: companyId,
        p_after_id: afterId,
        p_limit: batchSize,
      }).abortSignal(signal);
      if (error) throw new ExportError("Não foi possível carregar todos os registros da empresa.", 503);
      if (!Array.isArray(data)) throw new ExportError("A leitura do relatório retornou um formato inválido.", 502);
      const rows = data as ExportFinding[];
      if (rows.length === 0) break;
      const archiveLines: string[] = [];

      for (const finding of rows) {
        const row = toExportRow(finding, generatedAt);
        archiveLines.push(JSON.stringify(row));
        inventory.rowCount += 1;
        inventory.affectedHostKeys.add(row.hostKey);
        incrementCounts(inventory.totals, row.severity);
        inventory.ageCounts[ageBandIndex(row.ageDays)] += 1;
        if (/^CVE-\d{4}-\d{4,19}$/.test(row.cve)) inventory.uniqueCves.add(row.cve);

        const host = inventory.hosts.get(row.hostKey) ?? { label: row.hostName, ...emptySeverityCounts() };
        incrementCounts(host, row.severity);
        inventory.hosts.set(row.hostKey, host);

        const software = inventory.software.get(row.component) ?? { label: row.component, ...emptySeverityCounts() };
        incrementCounts(software, row.severity);
        inventory.software.set(row.component, software);

        if (/^CVE-\d{4}-\d{4,19}$/.test(row.cve)) {
          const group = inventory.cves.get(row.cve) ?? {
            cve: row.cve,
            severity: row.severity,
            cvss: row.score,
            description: row.description,
            firstDetected: row.firstDetected,
            ageDays: row.ageDays,
            hosts: new Map<string, string>(),
            packages: new Set<string>(),
            references: new Set<string>(),
            statuses: new Set<string>(),
          };
          if (severityRank(row.severity) < severityRank(group.severity)) group.severity = row.severity;
          if (row.score !== null && (group.cvss === null || row.score > group.cvss)) group.cvss = row.score;
          if (!group.description && row.description) group.description = row.description;
          if (Date.parse(row.firstDetected) < Date.parse(group.firstDetected)) group.firstDetected = row.firstDetected;
          group.ageDays = Math.max(group.ageDays, row.ageDays);
          group.hosts.set(row.hostKey, row.hostName);
          group.packages.add(row.component);
          if (row.reference) group.references.add(row.reference);
          group.statuses.add(row.workflowStatus);
          inventory.cves.set(row.cve, group);
        }
      }

      if (!gzip.write(`${archiveLines.join("\n")}\n`)) await once(gzip, "drain");
      afterId = rows[rows.length - 1]?.finding_id ?? null;
      if (!afterId || rows.length < batchSize) break;
    }
    gzip.end();
    await outputDone;
    return inventory;
  } catch (error) {
    gzip.destroy(error instanceof Error ? error : new Error("Falha ao preparar o arquivo temporário."));
    await outputDone.catch(() => undefined);
    throw error;
  }
}

function sortCounts(a: GroupedAsset, b: GroupedAsset): number {
  return b.total - a.total || a.label.localeCompare(b.label);
}

function historyRowsForExcel(rows: HistoryRow[], generatedAt: Date): HistoryRow[] {
  return rows.filter((row) => {
    const date = new Date(`${row.period_start}T00:00:00Z`);
    return !Number.isNaN(date.valueOf()) && date.valueOf() <= generatedAt.valueOf();
  }).sort((a, b) => a.period_start.localeCompare(b.period_start) || a.granularity.localeCompare(b.granularity));
}

async function writeWorkbook(args: {
  archivePath: string;
  outputPath: string;
  companyName: string;
  inventory: CollectedInventory;
  history: HistoryRow[];
  snapshot: { refreshed_at: string; stale: boolean } | null;
  generatedAt: Date;
}) {
  const { archivePath, outputPath, companyName, inventory, history, snapshot, generatedAt } = args;
  const workbook = new ExcelJS.stream.xlsx.WorkbookWriter({
    filename: outputPath,
    useStyles: true,
    useSharedStrings: false,
    zip: { zlib: { level: 6 } },
  });
  workbook.creator = "PierVuln";
  workbook.subject = "Relatório de vulnerabilidades por empresa";
  workbook.title = `Relatório de vulnerabilidades — ${companyName}`;
  workbook.created = generatedAt;
  workbook.modified = generatedAt;

  const selectedHistory = historyRowsForExcel(history, generatedAt);
  const overview = workbook.addWorksheet("Visão Geral", { views: [{ state: "frozen", ySplit: 5 }] });
  overview.columns = [{ width: 25 }, { width: 18 }, { width: 16 }, { width: 16 }, { width: 16 }, { width: 16 }, { width: 16 }, { width: 18 }, { width: 21 }, { width: 16 }, { width: 16 }, { width: 24 }];
  addTitle(overview, "Gestão de Vulnerabilidades", 12);
  addDataRow(overview, ["Empresa", companyName, "Gerado em", generatedAt]);
  addDataRow(overview, ["Última leitura completa", dateValue(snapshot?.refreshed_at) ?? "Não disponível", "Estado da leitura", snapshot?.stale ? "Desatualizada" : "Atual"]);
  addSection(overview, "Resumo atual por severidade", 3);
  addHeader(overview, ["Severidade", "Quantidade", "% do total"]);
  const overviewSeverityRows: [string, number][] = [
    ["Crítica", inventory.totals.Critical],
    ["Alta", inventory.totals.High],
    ["Média", inventory.totals.Medium],
    ["Baixa", inventory.totals.Low],
    ["Informativa", inventory.totals.Informational],
    ["Sem classificação", inventory.totals.Unknown],
    ["Total exportado", inventory.rowCount],
  ];
  for (const [label, value] of overviewSeverityRows) {
    const row = overview.addRow([label, value, inventory.rowCount ? value / inventory.rowCount : 0]);
    row.getCell(2).numFmt = "#,##0";
    row.getCell(3).numFmt = "0.0%";
    row.commit();
  }
  addDataRow(overview, ["Hosts afetados", inventory.affectedHostKeys.size, "CVEs únicos", inventory.uniqueCves.size]);
  addSection(overview, "Histórico de snapshots", 12);
  addHeader(overview, ["Granularidade", "Período", "Total", "Crítica", "Alta", "Média", "Baixa", "Informativa", "Sem classificação", "Novas", "Corrigidas", "Origem"]);
  for (const item of selectedHistory) {
    addDataRow(overview, [
      item.granularity === "monthly" ? "Mensal" : "Semanal",
      formatPeriod(item),
      item.total_findings,
      item.critical_count,
      item.high_count,
      item.medium_count,
      item.low_count,
      item.informational_count,
      item.unclassified_count,
      null,
      null,
      item.source_kind === "report" ? "Relatório histórico" : "Snapshot agregado",
    ]);
  }
  addDataRow(overview, ["Nota", "O histórico disponível guarda totais agregados; novas e corrigidas não são calculadas sem eventos históricos completos."]);

  const assets = workbook.addWorksheet("Ativos e Softwares", { views: [{ state: "frozen", ySplit: 3 }] });
  assets.columns = Array.from({ length: 18 }, (_, index) => ({ width: index === 0 || index === 10 ? 36 : index === 7 || index === 17 ? 15 : 14 }));
  addTitle(assets, "Vulnerabilidades por ativo e software", 18);
  addSection(assets, "Ativos e pacotes", 18);
  const severityColumns = ["Low", "Medium", "High", "Critical", "Informational", "Unknown"] as const;
  const leftHeaders = ["Host", "Baixa", "Média", "Alta", "Crítica", "Informativa", "Sem classificação", "Total"];
  const rightHeaders = ["Componente vulnerável", "Baixa", "Média", "Alta", "Crítica", "Informativa", "Sem classificação", "Total"];
  const headerValues = new Array<CellValue>(18).fill(null);
  leftHeaders.forEach((value, index) => { headerValues[index] = value; });
  rightHeaders.forEach((value, index) => { headerValues[index + 10] = value; });
  const headers = assets.addRow(headerValues);
  headers.height = 29;
  headers.eachCell({ includeEmpty: true }, (cell, column) => {
    if ((column >= 1 && column <= 8) || (column >= 11 && column <= 18)) {
      cell.fill = { type: "pattern", pattern: "solid", fgColor: { argb: colors.header } };
      cell.font = { name: "Aptos", size: 10, bold: true, color: { argb: colors.white } };
      cell.alignment = { vertical: "middle", wrapText: true };
    }
  });
  headers.commit();

  const hostRows = [...inventory.hosts.values()].sort(sortCounts);
  const softwareRows = [...inventory.software.values()].sort(sortCounts);
  const countValues = (row: GroupedAsset) => [row.label, ...severityColumns.map((key) => row[key]), row.total];
  const alignedRows = Math.max(hostRows.length, softwareRows.length);
  for (let index = 0; index < alignedRows; index += 1) {
    const left = hostRows[index] ? countValues(hostRows[index]) : Array<CellValue>(8).fill(null);
    const right = softwareRows[index] ? countValues(softwareRows[index]) : Array<CellValue>(8).fill(null);
    addDataRow(assets, [...left, null, null, ...right]);
  }
  const hostTotals = emptySeverityCounts();
  const softwareTotals = emptySeverityCounts();
  for (const row of hostRows) {
    for (const severity of severityKeys) hostTotals[severity] += row[severity];
    hostTotals.total += row.total;
  }
  for (const row of softwareRows) {
    for (const severity of severityKeys) softwareTotals[severity] += row[severity];
    softwareTotals.total += row.total;
  }
  const assetTotalRow = assets.addRow(["Total Geral", ...severityColumns.map((key) => hostTotals[key]), hostTotals.total, null, null, "Total Geral", ...severityColumns.map((key) => softwareTotals[key]), softwareTotals.total]);
  assetTotalRow.eachCell((cell) => {
    cell.fill = { type: "pattern", pattern: "solid", fgColor: { argb: colors.panel } };
    cell.font = { name: "Aptos", size: 10, bold: true, color: { argb: colors.dark } };
  });
  assetTotalRow.commit();

  const exposure = workbook.addWorksheet("Tempo de Exposição", { views: [{ state: "frozen", ySplit: 5 }] });
  exposure.columns = [{ width: 18 }, { width: 28 }, { width: 20 }, { width: 55 }, { width: 20 }, { width: 12 }, { width: 21 }, { width: 21 }];
  addTitle(exposure, "Tempo de Exposição", 8);
  addHeader(exposure, [">90 Dias", "61–90 Dias", "31–60 Dias", "<30 Dias", "Hosts afetados", "CVEs únicos", "Registros ativos", "Sem classificação"]);
  const ageSummary = exposure.addRow([
    inventory.ageCounts[0], inventory.ageCounts[1], inventory.ageCounts[2], inventory.ageCounts[3],
    inventory.affectedHostKeys.size, inventory.uniqueCves.size, inventory.rowCount, inventory.totals.Unknown,
  ]);
  ageSummary.eachCell((cell) => { cell.font = { name: "Aptos", size: 12, bold: true, color: { argb: colors.dark } }; });
  ageSummary.commit();
  addSection(exposure, "Detalhamento dos registros ativos", 8);
  addHeader(exposure, ["Prioridade", "Host", "CVE", "Componente", "Severidade", "CVSS", "Primeira detecção", "Última detecção"]);

  const remediation = workbook.addWorksheet("Plano de Remediação", { views: [{ state: "frozen", ySplit: 7 }] });
  remediation.columns = [{ width: 16 }, { width: 18 }, { width: 20 }, { width: 70 }, { width: 55 }, { width: 70 }, { width: 45 }, { width: 52 }, { width: 24 }, { width: 3 }, { width: 24 }, { width: 14 }];
  const orderedGroups = [...inventory.cves.values()].sort((left, right) =>
    priorityRank(right.ageDays) - priorityRank(left.ageDays)
    || severityRank(left.severity) - severityRank(right.severity)
    || right.ageDays - left.ageDays
    || left.cve.localeCompare(right.cve),
  );
  const statusTotals = new Map<string, number>();
  for (const group of orderedGroups) {
    const label = workflowLabel(group.statuses);
    statusTotals.set(label, (statusTotals.get(label) ?? 0) + 1);
  }
  const planTitle = remediation.addRow(["Plano de Remediação", null, null, null, null, null, null, null, null, null, "Status das correções", null]);
  planTitle.height = 30;
  planTitle.eachCell({ includeEmpty: true }, (cell) => {
    cell.fill = { type: "pattern", pattern: "solid", fgColor: { argb: colors.dark } };
    cell.font = { name: "Aptos Display", size: 15, bold: true, color: { argb: colors.white } };
    cell.alignment = { vertical: "middle" };
  });
  planTitle.commit();
  const statusHeader = remediation.addRow([null, null, null, null, null, null, null, null, null, null, "Status", "Quantidade"]);
  statusHeader.height = 25;
  statusHeader.eachCell({ includeEmpty: true }, (cell, column) => {
    if (column >= 11) {
      cell.fill = { type: "pattern", pattern: "solid", fgColor: { argb: colors.header } };
      cell.font = { name: "Aptos", size: 10, bold: true, color: { argb: colors.white } };
    }
  });
  statusHeader.commit();
  for (const status of ["Pendente", "Em andamento", "Aguardando validação", "Resolvida pela fonte"]) {
    addDataRow(remediation, [null, null, null, null, null, null, null, null, null, null, status, statusTotals.get(status) ?? 0]);
  }
  const planHeader = remediation.addRow(["Prioridade", "Severidade", "CVE", "Descrição", "Risco", "Solução", "Referência", "Hosts Afetados", "Status", null, null, null]);
  planHeader.height = 29;
  planHeader.eachCell({ includeEmpty: true }, (cell, column) => {
    if (column <= 9 || column >= 11) {
      cell.fill = { type: "pattern", pattern: "solid", fgColor: { argb: colors.header } };
      cell.font = { name: "Aptos", size: 10, bold: true, color: { argb: colors.white } };
      cell.alignment = { vertical: "middle", wrapText: true };
    }
  });
  planHeader.commit();

  const report = workbook.addWorksheet("Report", { views: [{ state: "frozen", ySplit: 5 }] });
  report.columns = [{ width: 25 }, { width: 34 }, { width: 52 }, { width: 20 }, { width: 90 }, { width: 22 }, { width: 12 }, { width: 70 }];
  addTitle(report, "Gestão de Vulnerabilidades", 8);
  addHeader(report, ["Critical", "High", "Medium", "Low", "Informational", "Unclassified", "Ativos exportados", "Empresa"]);
  const summaryRow = report.addRow([
    inventory.totals.Critical,
    inventory.totals.High,
    inventory.totals.Medium,
    inventory.totals.Low,
    inventory.totals.Informational,
    inventory.totals.Unknown,
    inventory.rowCount,
    companyName,
  ]);
  summaryRow.eachCell((cell, column) => { if (column <= 7) cell.numFmt = "#,##0"; });
  summaryRow.commit();
  addSection(report, "REPORT DE VULNERABILIDADES (ENDPOINT)", 8);
  addHeader(report, ["Hostname", "Sistema Operacional", "Componente Vulnerável", "CVE", "Descrição", "Severidade", "CVSS", "Referência"]);

  const input = createReadStream(archivePath).pipe(createGunzip());
  const lines = createInterface({ input, crlfDelay: Infinity });
  for await (const line of lines) {
    if (!line) continue;
    const row = JSON.parse(line) as ExportRow;
    const detail = report.addRow([
      row.hostName,
      row.osName,
      row.component,
      row.cve,
      row.description,
      severityLabel(row.severity),
      row.score,
      row.reference,
    ]);
    detail.eachCell((cell) => { cell.alignment = { vertical: "top", wrapText: true }; });
    detail.commit();

    const age = exposure.addRow([
      ageBand(row.ageDays),
      row.hostName,
      row.cve,
      row.component,
      severityLabel(row.severity),
      row.score,
      dateValue(row.firstDetected),
      dateValue(row.lastSeen),
    ]);
    age.eachCell((cell, column) => {
      cell.alignment = { vertical: "top", wrapText: column === 4 };
      if (column === 6) cell.numFmt = "0.0";
      if (column === 7 || column === 8) cell.numFmt = "dd/mm/yyyy hh:mm";
    });
    age.commit();
  }

  for (const group of orderedGroups) {
    const status = workflowLabel(group.statuses);
    const packages = [...group.packages].filter((value) => value !== "Não informado").sort((a, b) => a.localeCompare(b));
    const packageSummary = packages.length > 12 ? `${packages.slice(0, 12).join(", ")} e mais ${packages.length - 12}` : packages.join(", ");
    const risk = "A exposição pode afetar a confidencialidade, integridade ou disponibilidade dos ativos conforme o contexto da vulnerabilidade.";
    const solution = packageSummary
      ? `Aplicar a atualização de segurança recomendada para ${packageSummary}. Validar a correção em ambiente controlado antes da implantação.`
      : "Aplicar a atualização de segurança recomendada pelo fabricante e validar a correção em ambiente controlado.";
    const detail = remediation.addRow([
      ageBand(group.ageDays),
      severityLabel(group.severity),
      group.cve,
      group.description || "A fonte não disponibilizou uma descrição.",
      risk,
      solution,
      [...group.references][0] ?? "",
      [...group.hosts.values()].sort((a, b) => a.localeCompare(b)).join(", "),
      status,
    ]);
    detail.eachCell((cell) => { cell.alignment = { vertical: "top", wrapText: true }; });
    detail.commit();
  }

  overview.autoFilter = `A15:L${Math.max(15, selectedHistory.length + 15)}`;
  assets.autoFilter = `A3:R${Math.max(3, alignedRows + 3)}`;
  exposure.autoFilter = `A5:H${inventory.rowCount + 5}`;
  remediation.autoFilter = `A7:I${orderedGroups.length + 7}`;
  report.autoFilter = `A5:H${inventory.rowCount + 5}`;
  overview.commit();
  assets.commit();
  exposure.commit();
  remediation.commit();
  report.commit();
  await workbook.commit();
}

export async function POST(request: Request) {
  const authorization = request.headers.get("authorization") ?? "";
  const token = authorization.match(/^Bearer\s+(.+)$/i)?.[1];
  if (!token) return Response.json({ error: "Entre novamente para exportar o relatório." }, { status: 401 });

  const body = await request.json().catch(() => null) as { companyId?: unknown } | null;
  if (!body || typeof body.companyId !== "string" || !/^[0-9a-f-]{36}$/i.test(body.companyId)) {
    return Response.json({ error: "Selecione uma empresa para exportar." }, { status: 400 });
  }

  const url = process.env.NEXT_PUBLIC_SUPABASE_URL;
  const key = process.env.NEXT_PUBLIC_SUPABASE_PUBLISHABLE_KEY;
  if (!url || !key) return Response.json({ error: "A exportação não está configurada no servidor." }, { status: 503 });

  const client = createClient(url, key, {
    global: { headers: { Authorization: `Bearer ${token}` } },
    auth: { autoRefreshToken: false, persistSession: false, detectSessionInUrl: false },
  });
  const { data: userData, error: authError } = await client.auth.getUser(token);
  if (authError || !userData.user) return Response.json({ error: "Sua sessão expirou. Entre novamente." }, { status: 401 });

  const { data: contextData, error: contextError } = await client.rpc("current_user_context");
  if (contextError) return Response.json({ error: "Não foi possível verificar o acesso à empresa." }, { status: 503 });
  const context = contextData as { is_internal_admin?: boolean; companies?: { id: string }[] } | null;
  const canAccess = Boolean(context?.is_internal_admin)
    || Boolean(context?.companies?.some((company) => company.id === body.companyId));
  if (!canAccess) return Response.json({ error: "Sua conta não tem acesso a esta empresa." }, { status: 403 });

  const { data: company, error: companyError } = await client.from("companies")
    .select("name,slug,is_active")
    .eq("id", body.companyId)
    .maybeSingle();
  if (companyError || !company || !company.is_active) {
    return Response.json({ error: "A empresa selecionada não está disponível para exportação." }, { status: 404 });
  }

  const tempDirectory = await mkdtemp(path.join(tmpdir(), "piervuln-export-"));
  const archivePath = path.join(tempDirectory, "inventory.ndjson.gz");
  const filePath = path.join(tempDirectory, `${randomUUID()}.xlsx`);
  const controller = new AbortController();
  const abort = () => controller.abort(request.signal.reason);
  if (request.signal.aborted) abort();
  else request.signal.addEventListener("abort", abort, { once: true });

  try {
    const markerBefore = await readPublicationMarker(client, controller.signal);
    const generatedAt = new Date();
    const [{ data: historyData, error: historyError }, { data: snapshot, error: snapshotError }] = await Promise.all([
      client.from("vulnerability_inventory_history")
        .select("granularity,period_start,period_end,total_findings,critical_count,high_count,medium_count,low_count,informational_count,unclassified_count,source_kind")
        .eq("tenant_id", body.companyId)
        .order("period_start", { ascending: true })
        .abortSignal(controller.signal),
      client.from("vulnerability_overview_snapshots")
        .select("refreshed_at,stale")
        .eq("tenant_id", body.companyId)
        .abortSignal(controller.signal)
        .maybeSingle()
    ]);
    if (historyError || snapshotError) throw new ExportError("Não foi possível carregar o histórico do relatório.", 503);

    const inventory = await collectInventory({ client, companyId: body.companyId, archivePath, generatedAt, signal: controller.signal });
    const markerAfter = await readPublicationMarker(client, controller.signal);
    if (markerBefore !== markerAfter) throw new ExportError("A leitura da empresa mudou durante a exportação. Tente gerar o arquivo novamente.", 409);

    await writeWorkbook({
      archivePath,
      outputPath: filePath,
      companyName: company.name,
      inventory,
      history: (historyData ?? []) as HistoryRow[],
      snapshot: snapshot ? { refreshed_at: snapshot.refreshed_at, stale: snapshot.stale } : null,
      generatedAt,
    });

    const fileInfo = await stat(filePath);
    const stream = createReadStream(filePath);
    const cleanup = () => { void rm(tempDirectory, { recursive: true, force: true }); };
    stream.once("close", cleanup);
    stream.once("error", cleanup);
    request.signal.removeEventListener("abort", abort);
    const date = new Intl.DateTimeFormat("en-CA", { timeZone: "America/Sao_Paulo", year: "numeric", month: "2-digit", day: "2-digit" }).format(generatedAt);
    const filename = `PierVuln-${cleanText(company.slug, 80).replace(/[^a-z0-9-]/gi, "-")}-${date}.xlsx`;
    return new Response(Readable.toWeb(stream) as ReadableStream<Uint8Array>, {
      status: 200,
      headers: {
        "Content-Type": "application/vnd.openxmlformats-officedocument.spreadsheetml.sheet",
        "Content-Disposition": `attachment; filename="${filename}"; filename*=UTF-8''${encodeURIComponent(filename)}`,
        "Content-Length": String(fileInfo.size),
        "Cache-Control": "private, no-store, max-age=0",
        "X-Report-Record-Count": String(inventory.rowCount),
      },
    });
  } catch (error) {
    request.signal.removeEventListener("abort", abort);
    await rm(tempDirectory, { recursive: true, force: true });
    const status = error instanceof ExportError ? error.status : 500;
    const message = error instanceof ExportError ? error.message : "Não foi possível gerar o arquivo Excel.";
    return Response.json({ error: message }, { status });
  }
}
