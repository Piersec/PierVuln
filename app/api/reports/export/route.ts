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
import type { CellValue, Row, Worksheet } from "exceljs";
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
  dark: "FF262626",
  panel: "FF353535",
  header: "FF444444",
  white: "FFFFFFFF",
  line: "FF656565",
  critical: "FF91243E",
  high: "FFC83B42",
  medium: "FFA65300",
  low: "FF147568",
};
const cellBorders = {
  top: { style: "thin" as const, color: { argb: colors.line } },
  left: { style: "thin" as const, color: { argb: colors.line } },
  bottom: { style: "thin" as const, color: { argb: colors.line } },
  right: { style: "thin" as const, color: { argb: colors.line } },
};
const styleCache = new Map<string, {
  fill: NonNullable<ExcelJS.Style["fill"]>;
  font: NonNullable<ExcelJS.Style["font"]>;
  alignment: NonNullable<ExcelJS.Style["alignment"]>;
}>();

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

function styleCell(row: Row, column: number, options: { fill?: string; size?: number; bold?: boolean; align?: "left" | "center"; wrap?: boolean } = {}) {
  const cell = row.getCell(column);
  const key = `${options.fill ?? colors.panel}/${options.size ?? 12}/${options.bold ?? false}/${options.align ?? "center"}/${options.wrap ?? true}`;
  let style = styleCache.get(key);
  if (!style) {
    style = {
      fill: { type: "pattern", pattern: "solid", fgColor: { argb: options.fill ?? colors.panel } },
      font: { name: "Trebuchet MS", size: options.size ?? 12, bold: options.bold ?? false, color: { argb: colors.white } },
      alignment: { horizontal: options.align ?? "center", vertical: "middle", wrapText: options.wrap ?? true },
    };
    styleCache.set(key, style);
  }
  cell.fill = style.fill;
  cell.font = style.font;
  cell.alignment = style.alignment;
  cell.border = cellBorders;
}

function styleRange(row: Row, start: number, end: number, options: Parameters<typeof styleCell>[2] = {}) {
  for (let column = start; column <= end; column += 1) styleCell(row, column, options);
}

function titleRow(sheet: Worksheet, title: string, end: number, start = 3) {
  const row = sheet.addRow([]);
  row.height = 87;
  styleRange(row, 1, end, { fill: colors.dark, size: 26, bold: true });
  row.getCell(start).value = title;
  sheet.mergeCells(1, start, 1, end);
  row.commit();
}

function spacer(sheet: Worksheet, height = 33) {
  const row = sheet.addRow([]);
  row.height = height;
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
      if (error) {
        console.error("[reports/export] batch read failed", { code: error.code });
        if (error.code === "57014") {
          throw new ExportError("A consulta excedeu o tempo do banco. Tente exportar novamente em instantes.", 503);
        }
        throw new ExportError("Não foi possível carregar todos os registros da empresa.", 503);
      }
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
      afterId = rows.reduce((cursor, row) => row.finding_id > cursor ? row.finding_id : cursor, afterId ?? "");
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
  const overview = workbook.addWorksheet("Visão Geral", { views: [{ state: "frozen", ySplit: 3 }] });
  overview.columns = [15.7, 20.9, 20.9, 20.9, 15.7, 20.9, 20.9, 20.9, 20.9, 20.9, 15.7, 20.7, 20.7].map((width) => ({ width }));
  titleRow(overview, "Gestão de Vulnerabilidades", 13, 4);
  spacer(overview);
  const overviewHeader = overview.addRow([null, "Severidade", "Quantidade", "% variação", null, "Mês", "Corrigidas", "Novas", "Total", "Variação", null, "Última alteração"]);
  overviewHeader.height = 39;
  styleRange(overviewHeader, 2, 4, { fill: colors.panel, bold: true });
  styleRange(overviewHeader, 6, 10, { fill: colors.panel, bold: true });
  styleRange(overviewHeader, 12, 13, { fill: colors.panel, bold: true });
  overviewHeader.commit();
  const severitySummary: [string, number, string][] = [
    ["Low", inventory.totals.Low, colors.low],
    ["Medium", inventory.totals.Medium, colors.medium],
    ["High", inventory.totals.High, colors.high],
    ["Critical", inventory.totals.Critical, colors.critical],
    ["Informational", inventory.totals.Informational, colors.header],
    ["Unknown", inventory.totals.Unknown, colors.header],
  ];
  const monthlyHistory = selectedHistory.filter((item) => item.granularity === "monthly").slice(-12);
  const summaryRows = Math.max(severitySummary.length, monthlyHistory.length, 4);
  for (let index = 0; index < summaryRows; index += 1) {
    const severity = severitySummary[index];
    const historyItem = monthlyHistory[index];
    const row = overview.addRow([]);
    row.height = 39;
    if (severity) {
      row.getCell(2).value = severity[0];
      row.getCell(3).value = severity[1];
      row.getCell(3).numFmt = "#,##0";
      row.getCell(4).value = "—";
      styleRange(row, 2, 4, { fill: severity[2], bold: true });
    }
    if (historyItem) {
      row.getCell(6).value = formatPeriod(historyItem);
      row.getCell(7).value = "—";
      row.getCell(8).value = "—";
      row.getCell(9).value = historyItem.total_findings;
      row.getCell(9).numFmt = "#,##0";
      row.getCell(10).value = "—";
      styleRange(row, 6, 10, { fill: colors.panel });
    }
    if (index === 0) {
      row.getCell(12).value = dateValue(snapshot?.refreshed_at) ?? "Não disponível";
      row.getCell(12).numFmt = "dd/mm/yyyy hh:mm";
      row.getCell(13).value = companyName;
      styleRange(row, 12, 13);
    }
    row.commit();
  }
  spacer(overview);
  const overviewTotal = overview.addRow([null, "Total exportado", inventory.rowCount, null, null, "Hosts afetados", inventory.affectedHostKeys.size, null, "CVEs únicos", inventory.uniqueCves.size]);
  overviewTotal.height = 39;
  styleRange(overviewTotal, 2, 3, { fill: colors.header, bold: true });
  styleRange(overviewTotal, 6, 7, { fill: colors.header, bold: true });
  styleRange(overviewTotal, 9, 10, { fill: colors.header, bold: true });
  overviewTotal.commit();
  const overviewNote = overview.addRow([null, "Variação, novas e corrigidas aparecem como — quando não há histórico de eventos para calcular esses valores."]);
  overviewNote.height = 39;
  styleRange(overviewNote, 2, 10, { fill: colors.dark, align: "left" });
  overview.mergeCells(overviewNote.number, 2, overviewNote.number, 10);
  overviewNote.commit();

  const assets = workbook.addWorksheet("Ativos e Softwares", { views: [{ state: "frozen", ySplit: 4 }] });
  assets.columns = [13.7, 18.7, 18.7, 18.7, 18.7, 18.7, 18.7, 13.7, 27.7, 18.7, 18.7, 18.7, 18.7, 18.7].map((width) => ({ width }));
  titleRow(assets, "Gestão de Vulnerabilidades", 14, 4);
  spacer(assets);
  const assetSection = assets.addRow([]);
  assetSection.height = 39;
  assetSection.getCell(2).value = "Vulnerabilidades por Host";
  assetSection.getCell(9).value = "Vulnerabilidades por Software";
  styleRange(assetSection, 2, 7, { fill: colors.dark, bold: true });
  styleRange(assetSection, 9, 14, { fill: colors.dark, bold: true });
  assets.mergeCells(3, 2, 3, 7);
  assets.mergeCells(3, 9, 3, 14);
  assetSection.commit();
  const severityColumns = ["Low", "Medium", "High", "Critical"] as const;
  const headers = assets.addRow([null, "Host", "Low", "Medium", "High", "Critical", "Total", null, "Pacote", "Low", "Medium", "High", "Critical", "Total"]);
  headers.height = 39;
  styleRange(headers, 2, 7, { fill: colors.panel, bold: true });
  styleRange(headers, 9, 14, { fill: colors.panel, bold: true });
  for (const [column, fill] of [[3, colors.low], [4, colors.medium], [5, colors.high], [6, colors.critical], [10, colors.low], [11, colors.medium], [12, colors.high], [13, colors.critical]] as const) styleCell(headers, column, { fill, bold: true });
  headers.commit();

  const hostRows = [...inventory.hosts.values()].sort(sortCounts);
  const softwareRows = [...inventory.software.values()].sort(sortCounts);
  const countValues = (row: GroupedAsset) => [row.label, ...severityColumns.map((key) => row[key]), row.total];
  const alignedRows = Math.max(hostRows.length, softwareRows.length);
  for (let index = 0; index < alignedRows; index += 1) {
    const left = hostRows[index] ? countValues(hostRows[index]) : Array<CellValue>(6).fill(null);
    const right = softwareRows[index] ? countValues(softwareRows[index]) : Array<CellValue>(6).fill(null);
    const row = assets.addRow([null, ...left, null, ...right]);
    row.height = 39;
    if (hostRows[index]) styleRange(row, 2, 7);
    if (softwareRows[index]) styleRange(row, 9, 14);
    row.commit();
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
  const assetTotalRow = assets.addRow([null, "Total Geral", ...severityColumns.map((key) => hostTotals[key]), hostTotals.total, null, "Total Geral", ...severityColumns.map((key) => softwareTotals[key]), softwareTotals.total]);
  assetTotalRow.height = 39;
  styleRange(assetTotalRow, 2, 7, { fill: colors.header, bold: true });
  styleRange(assetTotalRow, 9, 14, { fill: colors.header, bold: true });
  assetTotalRow.commit();

  const exposure = workbook.addWorksheet("Tempo de Exposição", { views: [{ state: "frozen", ySplit: 6 }] });
  exposure.columns = Array.from({ length: 8 }, () => ({ width: 30.7 }));
  titleRow(exposure, "Tempo de Exposição", 8);
  spacer(exposure);
  const ageHeader = exposure.addRow([">90 Dias", "61-90 Dias", "31-60 Dias", "<30 Dias", null, null, "Hosts Afetados", "CVEs Únicos"]);
  ageHeader.height = 45;
  styleRange(ageHeader, 1, 4, { bold: true, size: 16 });
  styleCell(ageHeader, 1, { fill: colors.critical, bold: true, size: 16 });
  styleCell(ageHeader, 2, { fill: colors.high, bold: true, size: 16 });
  styleCell(ageHeader, 3, { fill: colors.medium, bold: true, size: 16 });
  styleCell(ageHeader, 4, { fill: colors.low, bold: true, size: 16 });
  styleRange(ageHeader, 7, 8, { fill: colors.panel, bold: true, size: 16 });
  ageHeader.commit();
  const ageSummary = exposure.addRow([inventory.ageCounts[0], inventory.ageCounts[1], inventory.ageCounts[2], inventory.ageCounts[3], null, null, inventory.affectedHostKeys.size, inventory.uniqueCves.size]);
  ageSummary.height = 45;
  styleRange(ageSummary, 1, 4, { fill: colors.panel, bold: true, size: 18 });
  styleRange(ageSummary, 7, 8, { fill: colors.panel, bold: true, size: 18 });
  ageSummary.commit();
  spacer(exposure);
  const ageDetailHeader = exposure.addRow(["Prioridade", "Host", "CVE", "Componente", "Severidade", "CVSS", "Primeira Detecção", "Última Detecção"]);
  ageDetailHeader.height = 39;
  styleRange(ageDetailHeader, 1, 8, { fill: colors.panel, bold: true });
  ageDetailHeader.commit();

  const remediation = workbook.addWorksheet("Plano de Remediação", { views: [{ state: "frozen", ySplit: 3 }] });
  remediation.columns = [25.7, 25.7, 25.7, 56.7, 35.7, 35.7, 25.7, 35.7, 20.7, 15.7, 20.7, 20.7].map((width) => ({ width }));
  const orderedGroups = [...inventory.cves.values()].sort((left, right) =>
    priorityRank(left.ageDays) - priorityRank(right.ageDays)
    || severityRank(left.severity) - severityRank(right.severity)
    || right.ageDays - left.ageDays
    || left.cve.localeCompare(right.cve),
  );
  const statusTotals = new Map<string, number>();
  for (const group of orderedGroups) {
    const label = workflowLabel(group.statuses);
    statusTotals.set(label, (statusTotals.get(label) ?? 0) + 1);
  }
  const planTitle = remediation.addRow([]);
  planTitle.height = 87;
  styleRange(planTitle, 1, 12, { fill: colors.dark, size: 26, bold: true });
  planTitle.getCell(3).value = "Plano de Remediação";
  planTitle.getCell(11).value = "Status das correções";
  remediation.mergeCells(1, 3, 1, 9);
  planTitle.getCell(11).font = { name: "Trebuchet MS", size: 16, bold: true, color: { argb: colors.white } };
  planTitle.commit();
  const planStatus = remediation.addRow([]);
  planStatus.height = 45;
  planStatus.getCell(11).value = "Pendente";
  planStatus.getCell(12).value = statusTotals.get("Pendente") ?? 0;
  styleCell(planStatus, 11, { fill: colors.critical, bold: true });
  styleCell(planStatus, 12, { fill: colors.panel, bold: true });
  planStatus.commit();
  const planHeader = remediation.addRow(["Prioridade", "Severidade", "CVE", "Descrição", "Risco", "Solução", "Referência", "Hosts Afetados", "Status", null, "Em andamento", statusTotals.get("Em andamento") ?? 0]);
  planHeader.height = 45;
  styleRange(planHeader, 1, 9, { fill: colors.panel, bold: true });
  styleCell(planHeader, 11, { fill: colors.medium, bold: true });
  styleCell(planHeader, 12, { fill: colors.panel, bold: true });
  planHeader.commit();

  const report = workbook.addWorksheet("Report", { views: [{ state: "frozen", ySplit: 7 }] });
  report.columns = [28.7, 28.7, 28.7, 28.7, 80.9, 25.7, 25.7, 60.3].map((width) => ({ width }));
  titleRow(report, "Gestão de Vulnerabilidades", 8);
  spacer(report, 45);
  const severityHeader = report.addRow(["Critical", "High", "Medium", "Low", null, "Última alteração"]);
  severityHeader.height = 45;
  for (const [column, fill] of [[1, colors.critical], [2, colors.high], [3, colors.medium], [4, colors.low]] as const) styleCell(severityHeader, column, { fill, bold: true, size: 16 });
  styleRange(severityHeader, 6, 7, { fill: colors.panel, bold: true });
  severityHeader.commit();
  const summaryRow = report.addRow([
    inventory.totals.Critical, inventory.totals.High, inventory.totals.Medium, inventory.totals.Low,
    null, dateValue(snapshot?.refreshed_at) ?? "Não disponível", companyName,
  ]);
  summaryRow.height = 45;
  styleRange(summaryRow, 1, 4, { fill: colors.panel, bold: true, size: 18 });
  styleRange(summaryRow, 6, 7, { fill: colors.panel });
  summaryRow.getCell(6).numFmt = "dd/mm/yyyy hh:mm";
  summaryRow.commit();
  spacer(report);
  const reportSection = report.addRow(["REPORT DE VULNERABILIDADES (ENDPOINT)"]);
  reportSection.height = 42;
  styleRange(reportSection, 1, 8, { fill: colors.dark, bold: true, size: 16 });
  report.mergeCells(6, 1, 6, 8);
  reportSection.commit();
  const reportHeader = report.addRow(["Hostname", "Sistema Operacional", "Componente Vulnerável", "CVE", "Descrição", "Severidade", "CVSS", "Referência"]);
  reportHeader.height = 42;
  styleRange(reportHeader, 1, 8, { fill: colors.panel, bold: true });
  reportHeader.commit();

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
      row.severity,
      row.score,
      row.reference,
    ]);
    detail.height = 36;
    styleRange(detail, 1, 8);
    detail.getCell(7).numFmt = "0.0";
    if (/^https?:\/\//i.test(row.reference)) detail.getCell(8).value = { text: row.reference, hyperlink: row.reference };
    detail.commit();

    const age = exposure.addRow([
      ageBand(row.ageDays),
      row.hostName,
      row.cve,
      row.component,
      row.severity,
      row.score,
      dateValue(row.firstDetected),
      dateValue(row.lastSeen),
    ]);
    age.height = 39;
    styleRange(age, 1, 8);
    age.getCell(6).numFmt = "0.0";
    age.getCell(7).numFmt = "mm-yyyy";
    age.getCell(8).numFmt = "mm-yyyy";
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
      group.severity,
      group.cve,
      group.description || "A fonte não disponibilizou uma descrição.",
      risk,
      solution,
      [...group.references][0] ?? "",
      [...group.hosts.values()].sort((a, b) => a.localeCompare(b)).join(", "),
      status,
    ]);
    detail.height = Math.min(180, Math.max(39, Math.ceil(group.description.length / 56) * 15));
    styleRange(detail, 1, 9);
    const reference = [...group.references][0];
    if (reference && /^https?:\/\//i.test(reference)) detail.getCell(7).value = { text: "Link Oficial", hyperlink: reference };
    if (detail.number === 4) {
      detail.getCell(11).value = "Aguardando validação";
      detail.getCell(12).value = statusTotals.get("Aguardando validação") ?? 0;
      styleRange(detail, 11, 12, { fill: colors.panel, bold: true });
    }
    if (detail.number === 5) {
      detail.getCell(11).value = "Resolvida pela fonte";
      detail.getCell(12).value = statusTotals.get("Resolvida pela fonte") ?? 0;
      styleRange(detail, 11, 12, { fill: colors.panel, bold: true });
    }
    detail.commit();
  }

  exposure.autoFilter = `A6:H${inventory.rowCount + 6}`;
  remediation.autoFilter = `A3:I${orderedGroups.length + 3}`;
  report.autoFilter = `A7:H${inventory.rowCount + 7}`;
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
