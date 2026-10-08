"use client";

import { useEffect, useRef, useState } from "react";
import { TriangleAlert } from "lucide-react";
import type { SupabaseClient } from "@supabase/supabase-js";
import type { AdminCompany } from "@/src/lib/admin";
import { visibleText } from "@/src/lib/visible-text";
import { SlideToConfirm } from "@/src/components/ui/slide-to-confirm";

export function CompanyDataDeletionDialog({ company, client, close, onQueued }: {
  company: AdminCompany; client: SupabaseClient; close: () => void; onQueued: () => void;
}) {
  const dialog = useRef<HTMLDialogElement>(null);
  const submitting = useRef(false);
  const [confirmation, setConfirmation] = useState("");
  const [busy, setBusy] = useState(false);
  const [error, setError] = useState("");
  useEffect(() => { dialog.current?.showModal(); }, []);

  async function confirm() {
    if (submitting.current || confirmation.trim() !== company.name) return false;
    submitting.current = true;
    setBusy(true); setError("");
    const controller = new AbortController();
    const timeout = setTimeout(() => controller.abort(), 15_000);
    try {
      const { data, error: requestError } = await client.rpc("request_company_data_deletion", {
        p_tenant_id: company.id, p_confirmation: confirmation.trim(),
      }).abortSignal(controller.signal);
      if (requestError || !data?.id) throw new Error("Não foi possível iniciar a limpeza. Confira sua sessão e tente novamente.");
      onQueued();
      return true;
    } catch (failure) {
      setError((failure as Error).message);
      return false;
    } finally {
      clearTimeout(timeout);
      submitting.current = false;
      setBusy(false);
    }
  }

  return <dialog ref={dialog} className="admin-dialog" aria-labelledby="delete-company-title"
    onCancel={(event) => { event.preventDefault(); if (!busy) close(); }}>
    <div className="company-deletion-content">
      <h2 id="delete-company-title" className="company-deletion-title"><TriangleAlert size={24} aria-hidden="true" />Apagar dados de {visibleText(company.name)}</h2>
      <p>Esta ação apaga permanentemente as vulnerabilidades, casos, histórico e comentários da empresa.</p>
      <p>A empresa será desativada e a coleta será desligada. O cadastro, os usuários e seus vínculos serão preservados.</p>
      <p className="muted-copy">A limpeza apaga os registros em lotes e depois compacta as tabelas compartilhadas para recuperar espaço em disco. A compactação pode bloquear temporariamente consultas nessas tabelas. Acompanhe as duas etapas na lista de empresas.</p>
      <label>Digite <strong>{visibleText(company.name)}</strong> para confirmar
        <input value={confirmation} onChange={(event) => setConfirmation(event.target.value)} disabled={busy}
          autoFocus autoComplete="off" spellCheck={false} aria-describedby="delete-company-instructions" />
      </label>
      <small id="delete-company-instructions" className="muted-copy">Depois, deslize até o final. Pelo teclado, use Tab e Enter no botão de confirmação.</small>
      {error && <p className="company-deletion-error" role="alert">{error}</p>}
      <div className="admin-dialog-footer">
        <button type="button" className="button button-secondary" disabled={busy} onClick={close}>Cancelar</button>
        <SlideToConfirm onConfirm={confirm} disabled={confirmation.trim() !== company.name} busy={busy} width={280} />
      </div>
    </div>
  </dialog>;
}
