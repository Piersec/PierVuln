"use client";

import { useEffect, useRef, useState } from "react";
import { createPortal } from "react-dom";
import type { SupabaseClient } from "@supabase/supabase-js";
import { SlideToConfirm } from "@/src/components/ui/slide-to-confirm";
import { AssetDeleteCapability } from "@/src/components/asset-delete-capability";

export type RemovalAsset = { connection_id: string; tenant_id: string; agent_id: string; agent_name: string; ip_address: string | null; registered_at: string | null };
export type AssetActionTarget = { asset: RemovalAsset; x: number; y: number };
type Request = { id: string; agent_name: string; status: string; is_demo: boolean; result_code: string | null; reason: string; created_at: string };
const statuses: Record<string, string> = { pending: "Pedido recebido", executing: "Excluindo na origem", succeeded: "Concluído", failed: "Não excluído", uncertain: "Resultado incerto — verifique na origem", canceled: "Cancelado" };
const results: Record<string, string> = { source_confirmed: "A origem confirmou a exclusão do ID solicitado.", demo_simulated: "Simulação concluída. Nenhuma chamada foi enviada a um servidor real.", source_denied: "A credencial da API não permite esta operação. O ativo foi mantido no site.", identity_changed: "A identificação do ativo mudou. A operação foi bloqueada.", network_uncertain: "A conexão caiu após o envio. Nenhuma exclusão será reenviada automaticamente. Confira o ativo na origem.", source_failed: "A origem não confirmou a exclusão. Confira o ativo na origem antes de qualquer nova tentativa.", preflight_failed: "Não foi possível validar o ativo na origem. A exclusão não foi enviada.", expired: "O coletor não iniciou a operação dentro do prazo.", worker_timeout: "O coletor não confirmou o resultado. Confira na origem; não haverá reenvio automático.", authorization_changed: "A permissão do solicitante mudou. A exclusão foi bloqueada.", user_canceled: "O pedido foi cancelado antes do envio." };

export function AssetRemoval({ client, target, onDismiss, companyName, onRemoved }: { client: SupabaseClient; target: AssetActionTarget | null; onDismiss: () => void; companyName: (id: string) => string; onRemoved: () => void }) {
  const menu = useRef<HTMLDivElement>(null);
  const dialog = useRef<HTMLDialogElement>(null);
  const [selected, setSelected] = useState<RemovalAsset | null>(null);
  const [confirmation, setConfirmation] = useState("");
  const [reason, setReason] = useState("");
  const [busy, setBusy] = useState(false);
  const [error, setError] = useState("");
  const [requestId, setRequestId] = useState("");
  const [jobId, setJobId] = useState("");
  const [job, setJob] = useState<Request | null>(null);
  const notified = useRef("");
  const removed = useRef(onRemoved);
  removed.current = onRemoved;

  useEffect(() => {
    if (!target) return;
    const dismiss = (event: PointerEvent) => { if (!menu.current?.contains(event.target as Node)) onDismiss(); };
    const key = (event: KeyboardEvent) => { if (event.key === "Escape") onDismiss(); };
    window.addEventListener("pointerdown", dismiss);
    window.addEventListener("keydown", key);
    return () => { window.removeEventListener("pointerdown", dismiss); window.removeEventListener("keydown", key); };
  }, [target, onDismiss]);
  useEffect(() => { if (selected) dialog.current?.showModal(); }, [selected]);
  useEffect(() => {
    if (!jobId) return;
    let alive = true;
    const poll = async () => {
      const { data, error } = await client.from("asset_deletion_requests").select("id,agent_name,status,is_demo,result_code,reason,created_at").eq("id", jobId).single();
      if (!alive) return;
      if (error) { setError("Não foi possível consultar o resultado. Consulte as solicitações abaixo da lista; não reenvie a exclusão."); return; }
      setJob(data as Request);
      if (data.status === "succeeded" && notified.current !== data.id) { notified.current = data.id; removed.current(); }
    };
    void poll();
    const timer = window.setInterval(() => void poll(), 2500);
    return () => { alive = false; window.clearInterval(timer); };
  }, [client, jobId]);

  function open(asset: RemovalAsset) {
    setSelected(asset); setConfirmation(""); setReason(""); setError(""); setJob(null); setJobId(""); setRequestId(crypto.randomUUID()); onDismiss();
  }
  function close() { if (!busy) { dialog.current?.close(); setSelected(null); setJobId(""); } }
  async function confirm() {
    if (!selected || busy || jobId || confirmation !== `EXCLUIR ${selected.agent_name}` || reason.trim().length < 10) return false;
    setBusy(true); setError("");
    try {
      const { data, error } = await client.rpc("request_asset_deletion", { p_request_id: requestId, p_connection_id: selected.connection_id, p_tenant_id: selected.tenant_id, p_agent_id: selected.agent_id, p_confirmation: confirmation, p_reason: reason.trim(), p_expected_registration: selected.registered_at, p_expected_ip: selected.ip_address });
      if (error) throw error;
      setJobId(String(data)); return true;
    } catch (caught) {
      const message = (caught as { message?: string }).message;
      setError(message?.includes("Coletor") || message?.includes("confirmação") || message?.includes("Somente") || message?.includes("identificação") ? message : "Não foi possível confirmar o pedido. Nenhum reenvio automático será feito. Consulte as solicitações abaixo da lista.");
      return false;
    } finally { setBusy(false); }
  }
  return <>
    {target && createPortal(<div ref={menu} className="asset-context-menu" role="menu" aria-label={`Ações de ${target.asset.agent_name}`} style={{ left: Math.max(8, Math.min(target.x, window.innerWidth - 250)), top: Math.max(8, Math.min(target.y, window.innerHeight - 70)) }}><button type="button" role="menuitem" autoFocus onClick={() => open(target.asset)}>Remover ativo na origem…</button></div>, document.body)}
    {selected && <dialog ref={dialog} className="asset-removal-dialog" onCancel={(event) => { event.preventDefault(); close(); }} aria-labelledby="asset-removal-title">
      <h2 id="asset-removal-title">Remover ativo na origem</h2>
      <AssetDeleteCapability client={client} connectionId={selected.connection_id} tenantId={selected.tenant_id} compact />
      <p>{companyName(selected.tenant_id).startsWith("Demonstração") ? "Simulação: nenhum agente real será excluído." : "Remove o agente no Manager e interrompe seu monitoramento."}</p>
      <dl><dt>Empresa</dt><dd>{companyName(selected.tenant_id)}</dd><dt>Ativo</dt><dd>{selected.agent_name}</dd><dt>ID</dt><dd>{selected.agent_id}</dd><dt>IP</dt><dd>{selected.ip_address || "Não informado"}</dd></dl>
      <details className="asset-removal-details"><summary>O que acontece após excluir?</summary><p>O ativo sai do site após a confirmação da origem. O histórico de alertas e incidentes será preservado. O software instalado no equipamento não será desinstalado.</p></details>
      {jobId ? <div className="asset-removal-result" role="status"><strong>{job ? statuses[job.status] : "Consultando pedido…"}</strong><p>{job?.result_code ? results[job.result_code] : "O coletor valida a identidade do ativo antes de enviar a exclusão. Você pode fechar esta janela e acompanhar o pedido abaixo da lista."}</p>{job?.status === "pending" && <button className="button button-secondary" onClick={async () => { const { error } = await client.rpc("cancel_asset_deletion", { p_id: jobId }); if (error) setError("Não foi possível cancelar. O coletor pode já ter iniciado a exclusão."); }}>Cancelar pedido pendente</button>}</div> : <><label>Motivo da exclusão · mínimo de 10 caracteres<textarea rows={2} minLength={10} maxLength={1000} aria-describedby="asset-removal-reason-help" aria-invalid={reason.length > 0 && reason.trim().length < 10} value={reason} disabled={busy} onChange={(event) => setReason(event.target.value)} placeholder="Descreva o motivo da exclusão"/><small id="asset-removal-reason-help" className="asset-removal-reason-help" aria-live="polite">{reason.trim().length < 10 ? `Faltam ${10 - reason.trim().length} caracteres para liberar a exclusão.` : "Mínimo atingido."} <span>{reason.trim().length}/1000</span></small></label><label>Digite <strong>EXCLUIR {selected.agent_name}</strong><input autoComplete="off" spellCheck={false} value={confirmation} disabled={busy} onChange={(event) => setConfirmation(event.target.value)}/></label></>}
      {error && <p className="inline-alert" role="alert">{error}</p>}
      <footer><button autoFocus className="button button-secondary" disabled={busy} onClick={close}>{jobId ? "Fechar" : "Cancelar"}</button>{!jobId && <div className="asset-removal-danger"><SlideToConfirm onConfirm={confirm} disabled={confirmation !== `EXCLUIR ${selected.agent_name}` || reason.trim().length < 10 || !selected.registered_at} busy={busy}/></div>}</footer>
    </dialog>}
  </>;
}

export function AssetRemovalHistory({ client, companyId, enabled }: { client: SupabaseClient; companyId: string; enabled: boolean }) {
  const [rows, setRows] = useState<Request[]>([]);
  const [error, setError] = useState(false);
  useEffect(() => {
    if (!enabled) return;
    let alive = true;
    const load = async () => {
      let query = client.from("asset_deletion_requests").select("id,agent_name,status,is_demo,result_code,reason,created_at").order("created_at", { ascending: false }).limit(10);
      if (companyId) query = query.eq("tenant_id", companyId);
      const result = await query;
      if (alive) { setError(Boolean(result.error)); if (result.data) setRows(result.data as Request[]); }
    };
    void load(); const timer = window.setInterval(() => { if (document.visibilityState === "visible") void load(); }, 10_000);
    return () => { alive = false; window.clearInterval(timer); };
  }, [client, companyId, enabled]);
  if (!enabled) return null;
  return <details className="asset-removal-history">
    <summary>Histórico de exclusões <span>Últimas 10 solicitações</span></summary>
    {error && <p role="alert">Não foi possível consultar as solicitações.</p>}
    {!rows.length && !error && <p>Nenhuma solicitação de exclusão.</p>}
    <div className="asset-removal-history-list">{rows.map((row) => <article key={row.id}>
      <div className="asset-removal-history-heading"><strong>{row.agent_name}{row.is_demo ? " · Simulação" : ""}</strong><span className="asset-removal-status" data-state={row.status}>{statuses[row.status]}</span></div>
      <p className="asset-removal-history-reason">{row.reason}</p>
      <div className="asset-removal-history-meta"><time dateTime={row.created_at}>{new Date(row.created_at).toLocaleString("pt-BR")}</time>{row.status === "pending" && <button className="button button-secondary" onClick={async () => { const { error } = await client.rpc("cancel_asset_deletion", { p_id: row.id }); if (error) setError(true); }}>Cancelar pedido</button>}</div>
      <small>{row.result_code ? results[row.result_code] : row.status === "pending" ? "A exclusão será iniciada na próxima checagem, feita a cada 10 segundos." : "Confirmando exclusão na origem…"}</small>
    </article>)}</div>
  </details>;
}
