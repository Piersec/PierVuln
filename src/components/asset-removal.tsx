"use client";

import { useEffect, useRef, useState } from "react";
import { createPortal } from "react-dom";
import type { SupabaseClient } from "@supabase/supabase-js";
import { SlideToConfirm } from "@/src/components/ui/slide-to-confirm";
import { AssetDeleteCapability } from "@/src/components/asset-delete-capability";

export type RemovalAsset = {
  connection_id: string;
  tenant_id: string;
  agent_id: string;
  agent_name: string;
  ip_address: string | null;
  registered_at: string | null;
  status: string;
  is_critical: boolean;
};
export type AssetActionTarget = { asset: RemovalAsset; x: number; y: number; canManageCritical: boolean; canRemove: boolean };
type Request = { id: string; agent_name: string; status: string; is_demo: boolean; result_code: string | null; reason: string; created_at: string; vulnerability_count: number | null };
type Preview = { is_critical: boolean; active_vulnerabilities: number };
const statuses: Record<string, string> = { pending: "Pedido recebido", executing: "Excluindo na origem", succeeded: "Concluído", failed: "Não excluído", uncertain: "Resultado incerto — verifique na origem", canceled: "Cancelado" };
const results: Record<string, string> = { source_confirmed: "A origem confirmou a exclusão do ID solicitado.", demo_simulated: "Simulação concluída. Nenhuma chamada foi enviada a um servidor real.", critical_protected: "O ativo foi marcado como crítico antes da exclusão. A operação foi bloqueada.", source_denied: "A credencial da API não permite esta operação. O ativo foi mantido no site.", identity_changed: "A identificação do ativo mudou. A operação foi bloqueada.", network_uncertain: "A conexão caiu após o envio. Nenhuma exclusão será reenviada automaticamente. Confira o ativo na origem.", source_failed: "A origem não confirmou a exclusão. Confira o ativo na origem antes de qualquer nova tentativa.", preflight_failed: "Não foi possível validar o ativo na origem. A exclusão não foi enviada.", expired: "O coletor não iniciou a operação dentro do prazo.", worker_timeout: "O coletor não confirmou o resultado. Confira na origem; não haverá reenvio automático.", authorization_changed: "A permissão do solicitante mudou. A exclusão foi bloqueada.", user_canceled: "O pedido foi cancelado antes do envio." };

export function AssetRemoval({ client, target, onDismiss, companyName, onCriticalChange, onRemoved }: {
  client: SupabaseClient;
  target: AssetActionTarget | null;
  onDismiss: () => void;
  companyName: (id: string) => string;
  onCriticalChange: (asset: Pick<RemovalAsset, "tenant_id" | "agent_id" | "agent_name">, nextValue: boolean) => Promise<boolean>;
  onRemoved: () => void;
}) {
  const menu = useRef<HTMLDivElement>(null);
  const dialog = useRef<HTMLDialogElement>(null);
  const criticalDialog = useRef<HTMLDialogElement>(null);
  const [selected, setSelected] = useState<RemovalAsset | null>(null);
  const [criticalTarget, setCriticalTarget] = useState<AssetActionTarget | null>(null);
  const [confirmation, setConfirmation] = useState("");
  const [reason, setReason] = useState("");
  const [busy, setBusy] = useState(false);
  const [error, setError] = useState("");
  const [requestId, setRequestId] = useState("");
  const [jobId, setJobId] = useState("");
  const [job, setJob] = useState<Request | null>(null);
  const [preview, setPreview] = useState<number | null>(null);
  const [previewLoading, setPreviewLoading] = useState(false);
  const [previewError, setPreviewError] = useState("");
  const [previewCritical, setPreviewCritical] = useState(false);
  const [criticalBusy, setCriticalBusy] = useState(false);
  const [criticalError, setCriticalError] = useState("");
  const [mfaStage, setMfaStage] = useState<"ready" | "verify" | "enroll">("ready");
  const [mfaCode, setMfaCode] = useState("");
  const [mfaFactorId, setMfaFactorId] = useState("");
  const [mfaChallengeId, setMfaChallengeId] = useState("");
  const [mfaQrCode, setMfaQrCode] = useState("");
  const [mfaSecret, setMfaSecret] = useState("");
  const [newMfaFactor, setNewMfaFactor] = useState(false);
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
  useEffect(() => { if (criticalTarget) criticalDialog.current?.showModal(); }, [criticalTarget]);
  useEffect(() => {
    if (!selected) return;
    let alive = true;
    setPreview(null); setPreviewError(""); setPreviewCritical(false); setPreviewLoading(true);
    void (async () => {
      try {
        const { data, error: queryError } = await client.rpc("get_asset_deletion_preview", {
          p_connection_id: selected.connection_id,
          p_tenant_id: selected.tenant_id,
          p_agent_id: selected.agent_id,
          p_expected_registration: selected.registered_at,
          p_expected_ip: selected.ip_address,
        });
        if (!alive) return;
        if (queryError || !data) {
          setPreviewError("Não foi possível calcular as vulnerabilidades. Atualize a lista antes de excluir.");
          return;
        }
        const result = data as Preview;
        setPreviewCritical(result.is_critical);
        if (result.is_critical) setPreviewError("Este ativo está marcado como crítico. Desative a classificação com MFA antes de excluir.");
        else if (!Number.isSafeInteger(result.active_vulnerabilities) || result.active_vulnerabilities < 0) setPreviewError("A contagem de vulnerabilidades não está disponível. Atualize a lista antes de excluir.");
        else setPreview(result.active_vulnerabilities);
      } catch {
        if (alive) setPreviewError("Não foi possível calcular as vulnerabilidades. Atualize a lista antes de excluir.");
      } finally {
        if (alive) setPreviewLoading(false);
      }
    })();
    return () => { alive = false; };
  }, [client, selected]);
  useEffect(() => {
    if (!jobId) return;
    let alive = true;
    const poll = async () => {
      const { data, error } = await client.from("asset_deletion_requests").select("id,agent_name,status,is_demo,result_code,reason,created_at,vulnerability_count").eq("id", jobId).single();
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
  function closeCritical() {
    if (criticalBusy) return;
    criticalDialog.current?.close();
    if (newMfaFactor && mfaFactorId) void client.auth.mfa.unenroll({ factorId: mfaFactorId });
    setCriticalTarget(null); setMfaCode(""); setMfaFactorId(""); setMfaChallengeId(""); setMfaQrCode(""); setMfaSecret(""); setNewMfaFactor(false); setMfaStage("ready"); setCriticalError("");
  }
  async function startMfa() {
    if (!criticalTarget || criticalBusy) return;
    setCriticalBusy(true); setCriticalError("");
    try {
      const { data, error: factorsError } = await client.auth.mfa.listFactors();
      if (factorsError) throw factorsError;
      let factor = data.totp[0];
      if (!factor) {
        const { data: enrolled, error: enrollError } = await client.auth.mfa.enroll({ factorType: "totp", issuer: "PierVuln", friendlyName: "Desbloqueio de ativo crítico" });
        if (enrollError) throw enrollError;
        factor = { id: enrolled.id, factor_type: "totp", status: "verified", created_at: "", updated_at: "" };
        setNewMfaFactor(true); setMfaQrCode(enrolled.totp.qr_code); setMfaSecret(enrolled.totp.secret);
      }
      const { data: challenge, error: challengeError } = await client.auth.mfa.challenge({ factorId: factor.id });
      if (challengeError) throw challengeError;
      setMfaFactorId(factor.id); setMfaChallengeId(challenge.id); setMfaStage(newMfaFactor || !data.totp[0] ? "enroll" : "verify");
    } catch {
      setCriticalError("Não foi possível iniciar o MFA. Confira a autenticação da conta e tente novamente.");
    } finally { setCriticalBusy(false); }
  }
  async function verifyMfaAndSave() {
    if (!criticalTarget || criticalBusy || !mfaFactorId || !mfaChallengeId || !/^\d{6,8}$/.test(mfaCode.trim())) return;
    setCriticalBusy(true); setCriticalError("");
    try {
      const { error: verifyError } = await client.auth.mfa.verify({ factorId: mfaFactorId, challengeId: mfaChallengeId, code: mfaCode.trim() });
      if (verifyError) throw verifyError;
      const saved = await onCriticalChange(criticalTarget.asset, false);
      if (!saved) throw new Error("classification_save_failed");
      setNewMfaFactor(false); criticalDialog.current?.close(); setCriticalTarget(null);
      setMfaCode(""); setMfaFactorId(""); setMfaChallengeId(""); setMfaQrCode(""); setMfaSecret(""); setMfaStage("ready");
    } catch {
      setCriticalError("Código inválido ou não foi possível salvar. Confira o código e tente novamente.");
    } finally { setCriticalBusy(false); }
  }
  async function changeCritical(nextValue: boolean) {
    if (!criticalTarget || criticalBusy) return;
    if (!nextValue) { await startMfa(); return; }
    setCriticalBusy(true); setCriticalError("");
    try {
      const saved = await onCriticalChange(criticalTarget.asset, true);
      if (!saved) throw new Error("classification_save_failed");
      criticalDialog.current?.close(); setCriticalTarget(null);
    } catch {
      setCriticalError("Não foi possível salvar a classificação deste ativo.");
    } finally { setCriticalBusy(false); }
  }
  async function confirm() {
    if (!selected || busy || jobId || preview === null || previewLoading || previewError || previewCritical || selected.is_critical || confirmation !== `EXCLUIR ${selected.agent_name}` || reason.trim().length < 10) return false;
    setBusy(true); setError("");
    try {
      const { data, error } = await client.rpc("request_asset_deletion", { p_request_id: requestId, p_connection_id: selected.connection_id, p_tenant_id: selected.tenant_id, p_agent_id: selected.agent_id, p_confirmation: confirmation, p_reason: reason.trim(), p_expected_registration: selected.registered_at, p_expected_ip: selected.ip_address });
      if (error) throw error;
      setJobId(String(data)); return true;
    } catch (caught) {
      const message = (caught as { message?: string }).message;
      setError(message?.includes("Coletor") || message?.includes("confirmação") || message?.includes("Somente") || message?.includes("identificação") || message?.includes("crítico") ? message : "Não foi possível confirmar o pedido. Nenhum reenvio automático será feito. Consulte as solicitações abaixo da lista.");
      return false;
    } finally { setBusy(false); }
  }

  return <>
    {target && createPortal(<div ref={menu} className="asset-context-menu" role="menu" aria-label={`Ações de ${target.asset.agent_name}`} style={{ left: Math.max(8, Math.min(target.x, window.innerWidth - 270)), top: Math.max(8, Math.min(target.y, window.innerHeight - 100)) }}>
      {target.canManageCritical && <button className="asset-context-critical" type="button" role="menuitem" autoFocus onClick={() => { setCriticalTarget(target); setMfaStage("ready"); setMfaCode(""); setCriticalError(""); setMfaFactorId(""); setMfaChallengeId(""); setMfaQrCode(""); setMfaSecret(""); setNewMfaFactor(false); onDismiss(); }}>{target.asset.is_critical ? "Desativar ativo crítico…" : "Marcar como ativo crítico"}</button>}
      {target.canRemove && <button type="button" role="menuitem" disabled={target.asset.is_critical} title={target.asset.is_critical ? "Desative a classificação crítica com MFA antes de excluir." : undefined} onClick={() => open(target.asset)}>{target.asset.is_critical ? "Bloqueado: ativo crítico" : "Remover ativo na origem…"}</button>}
    </div>, document.body)}
    {criticalTarget && <dialog ref={criticalDialog} className="asset-removal-dialog asset-critical-dialog" onCancel={(event) => { event.preventDefault(); closeCritical(); }} aria-labelledby="asset-critical-title">
      <h2 id="asset-critical-title">{criticalTarget.asset.is_critical ? "Desativar ativo crítico" : "Marcar ativo como crítico"}</h2>
      <p>{criticalTarget.asset.agent_name} · ID {criticalTarget.asset.agent_id}</p>
      {criticalTarget.asset.is_critical ? <>
        <p>Desativar esta classificação exige um código de autenticação multifator. Sem MFA, a classificação continua ativa e a exclusão segue bloqueada.</p>
        {mfaStage === "ready" && <button className="button button-destructive" type="button" disabled={criticalBusy} onClick={() => void changeCritical(false)}>{criticalBusy ? "Preparando MFA…" : "Continuar com MFA"}</button>}
        {mfaStage === "enroll" && <div className="asset-mfa-enroll">
          <p>Configure um app autenticador. Escaneie o QR ou informe a chave manualmente.</p>
          {mfaQrCode && <img alt="QR para configurar autenticação multifator" src={`data:image/svg+xml;utf8,${encodeURIComponent(mfaQrCode)}`} />}
          <label>Chave manual<input readOnly type="text" value={mfaSecret} autoComplete="off" /></label>
        </div>}
        {mfaStage !== "ready" && <label>Código do app autenticador<input autoComplete="one-time-code" inputMode="numeric" pattern="[0-9]*" maxLength={8} value={mfaCode} onChange={(event) => setMfaCode(event.target.value.replace(/\D/g, "").slice(0, 8))} /></label>}
        {mfaStage === "enroll" && <p>O MFA será ativado ao validar o código e, em seguida, autorizará esta alteração.</p>}
      </> : <p>Este ativo ficará protegido contra exclusão enquanto estiver marcado como crítico.</p>}
      {criticalError && <p className="inline-alert" role="alert">{criticalError}</p>}
      <footer><button className="button button-secondary" disabled={criticalBusy} onClick={closeCritical}>Cancelar</button>
        {!criticalTarget.asset.is_critical && <button className="button button-primary" type="button" disabled={criticalBusy} onClick={() => void changeCritical(true)}>{criticalBusy ? "Salvando…" : "Marcar como crítico"}</button>}
        {mfaStage !== "ready" && <button className="button button-primary" type="button" disabled={criticalBusy || !/^\d{6,8}$/.test(mfaCode.trim())} onClick={() => void verifyMfaAndSave()}>{criticalBusy ? "Verificando…" : "Validar e desativar"}</button>}
      </footer>
    </dialog>}
    {selected && <dialog ref={dialog} className="asset-removal-dialog" onCancel={(event) => { event.preventDefault(); close(); }} aria-labelledby="asset-removal-title">
      <h2 id="asset-removal-title">Remover ativo na origem</h2>
      <AssetDeleteCapability client={client} connectionId={selected.connection_id} tenantId={selected.tenant_id} compact />
      <p>{companyName(selected.tenant_id).startsWith("Demonstração") ? "Simulação: nenhum agente real será excluído." : "Remove o agente no Manager e interrompe seu monitoramento."}</p>
      {selected.status === "active" && <p className="asset-removal-active-warning" role="note">Este ativo está ativo. Como o serviço continua rodando na máquina, ele pode voltar à lista após a próxima coleta.</p>}
      <dl><dt>Empresa</dt><dd>{companyName(selected.tenant_id)}</dd><dt>Ativo</dt><dd>{selected.agent_name}</dd><dt>ID</dt><dd>{selected.agent_id}</dd><dt>IP</dt><dd>{selected.ip_address || "Não informado"}</dd></dl>
      <details className="asset-removal-details"><summary>O que acontece após excluir?</summary><p>O ativo sai do site após a confirmação da origem. As vulnerabilidades abertas saem dos indicadores ativos; o histórico de alertas e incidentes será preservado. O software instalado no equipamento não será desinstalado.</p></details>
      {jobId ? <div className="asset-removal-result" role="status"><strong>{job ? statuses[job.status] : "Consultando pedido…"}</strong><p>{job?.result_code ? results[job.result_code] : "O coletor valida a identidade do ativo antes de enviar a exclusão. Você pode fechar esta janela e acompanhar o pedido abaixo da lista."}</p>{job?.status === "succeeded" && job.vulnerability_count !== null && <p className="asset-removal-count-result">{job.vulnerability_count.toLocaleString("pt-BR")} vulnerabilidades saíram da lista de ativas. Histórico preservado.</p>}{job?.status === "pending" && <button className="button button-secondary" onClick={async () => { const { error } = await client.rpc("cancel_asset_deletion", { p_id: jobId }); if (error) setError("Não foi possível cancelar. O coletor pode já ter iniciado a exclusão."); }}>Cancelar pedido pendente</button>}</div> : <>
        <p className="asset-removal-vulnerability-count" aria-live="polite">{previewLoading ? "Calculando vulnerabilidades…" : preview !== null ? `Esta exclusão removerá ${preview.toLocaleString("pt-BR")} vulnerabilidades dos indicadores ativos. O histórico será preservado.` : previewError || "A contagem de vulnerabilidades está indisponível."}</p>
        <label>Motivo da exclusão · mínimo de 10 caracteres<textarea rows={2} minLength={10} maxLength={1000} aria-describedby="asset-removal-reason-help" aria-invalid={reason.length > 0 && reason.trim().length < 10} value={reason} disabled={busy} onChange={(event) => setReason(event.target.value)} placeholder="Descreva o motivo da exclusão"/><small id="asset-removal-reason-help" className="asset-removal-reason-help" aria-live="polite">{reason.trim().length < 10 ? `Faltam ${10 - reason.trim().length} caracteres para liberar a exclusão.` : "Mínimo atingido."} <span>{reason.trim().length}/1000</span></small></label>
        <label>Digite <strong>EXCLUIR {selected.agent_name}</strong><input autoComplete="off" spellCheck={false} value={confirmation} disabled={busy} onChange={(event) => setConfirmation(event.target.value)}/></label>
      </>}
      {error && <p className="inline-alert" role="alert">{error}</p>}
      <footer><button autoFocus className="button button-secondary" disabled={busy} onClick={close}>{jobId ? "Fechar" : "Cancelar"}</button>{!jobId && <div className="asset-removal-danger"><SlideToConfirm onConfirm={confirm} disabled={confirmation !== `EXCLUIR ${selected.agent_name}` || reason.trim().length < 10 || !selected.registered_at || selected.is_critical || previewCritical || preview === null || previewLoading || Boolean(previewError)} busy={busy}/></div>}</footer>
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
      let query = client.from("asset_deletion_requests").select("id,agent_name,status,is_demo,result_code,reason,created_at,vulnerability_count").order("created_at", { ascending: false }).limit(10);
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
      {row.status === "succeeded" && row.vulnerability_count !== null && <p className="asset-removal-count-result">{row.vulnerability_count.toLocaleString("pt-BR")} vulnerabilidades saíram da lista de ativas. Histórico preservado.</p>}
      <div className="asset-removal-history-meta"><time dateTime={row.created_at}>{new Date(row.created_at).toLocaleString("pt-BR")}</time>{row.status === "pending" && <button className="button button-secondary" onClick={async () => { const { error } = await client.rpc("cancel_asset_deletion", { p_id: row.id }); if (error) setError(true); }}>Cancelar pedido</button>}</div>
      <small>{row.result_code ? results[row.result_code] : row.status === "pending" ? "A exclusão será iniciada na próxima checagem, feita a cada 10 segundos." : "Confirmando exclusão na origem…"}</small>
    </article>)}</div>
  </details>;
}
