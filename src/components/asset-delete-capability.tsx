"use client";

import { useEffect, useState } from "react";
import type { SupabaseClient } from "@supabase/supabase-js";

type Capability = { status: "allowed" | "restricted" | "denied" | "unknown" | "demo"; reason: string; checked_at: string | null };
const labels = { allowed: "Liberada", restricted: "Liberada com restrições", denied: "Sem permissão", unknown: "Ainda não verificada", demo: "Simulação local" };

export function AssetDeleteCapability({ client, connectionId, tenantId }: { client: SupabaseClient; connectionId: string; tenantId: string }) {
  const [state, setState] = useState<Capability | null>(null);
  const [failed, setFailed] = useState(false);
  useEffect(() => {
    const controller = new AbortController();
    setState(null); setFailed(false);
    const load = async () => {
      try {
        const result = await client.rpc("get_asset_delete_capability", { p_connection: connectionId, p_tenant: tenantId }).abortSignal(controller.signal);
        if (controller.signal.aborted) return;
        if (result.error) throw result.error;
        setState(result.data as Capability); setFailed(false);
      } catch { if (!controller.signal.aborted) setFailed(true); }
    };
    void load();
    const timer = window.setInterval(() => { if (document.visibilityState === "visible") void load(); }, 30_000);
    return () => { controller.abort(); window.clearInterval(timer); };
  }, [client, connectionId, tenantId]);
  return <div role="status" className="asset-delete-capability">
    <p>Exclusão na origem · <code>agent:delete</code>: <strong data-state={failed ? "unknown" : state?.status}>{failed ? "Verificação indisponível" : state ? labels[state.status] : "Consultando permissão…"}</strong></p>
    {state?.status === "denied" && <p className="muted-copy">Libere agent:delete na conta do Manager desta empresa para permitir a exclusão.</p>}
    {state?.status === "restricted" && <p className="muted-copy">A política limita agentes ou grupos. O Manager validará a permissão para o ativo escolhido.</p>}
    {state?.status === "unknown" && <p className="muted-copy">{state.reason === "authentication_failed" ? "A conta não autenticou no Manager. Confira as credenciais." : state.reason === "policies_unavailable" ? "A API não permitiu consultar as políticas efetivas." : "Aguardando uma consulta recente do coletor ao Manager."}</p>}
    {state?.checked_at && <small className="muted-copy">Última verificação: {new Date(state.checked_at).toLocaleString("pt-BR")} · consulta automática pelo coletor.</small>}
  </div>;
}
