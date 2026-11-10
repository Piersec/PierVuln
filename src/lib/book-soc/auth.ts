// Acesso ao Book SOC: mesmo login do PierVuln, restrito à equipe interna.
// O banco é usado só para identificar o usuário; nenhum dado do Book passa por ele.
import { createClient } from "@supabase/supabase-js";

export async function requireInternal(request: Request): Promise<Response | null> {
  const url = process.env.NEXT_PUBLIC_SUPABASE_URL;
  const key = process.env.NEXT_PUBLIC_SUPABASE_PUBLISHABLE_KEY;
  const token = request.headers.get("authorization")?.match(/^Bearer (.+)$/i)?.[1];
  if (!url || !key || !token) return Response.json({ error: "Sessão necessária." }, { status: 401 });

  const scoped = createClient(url, key, { global: { headers: { Authorization: `Bearer ${token}` } }, auth: { persistSession: false } });
  const { data, error } = await scoped.rpc("current_user_context");
  if (error) return Response.json({ error: "Não foi possível verificar o acesso." }, { status: 502 });
  if ((data as { is_internal_admin?: boolean } | null)?.is_internal_admin !== true) {
    return Response.json({ error: "Acesso restrito à equipe Pier." }, { status: 403 });
  }
  return null;
}
