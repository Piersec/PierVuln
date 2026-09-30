import "jsr:@supabase/functions-js/edge-runtime.d.ts";
import { createClient } from "@supabase/supabase-js";

const url = Deno.env.get("SUPABASE_URL")!;
const publicKey = Deno.env.get("SUPABASE_ANON_KEY")!;
const serviceKey = Deno.env.get("SUPABASE_SERVICE_ROLE_KEY")!;
const admin = createClient(url, serviceKey, { auth: { autoRefreshToken: false, persistSession: false } });

function json(status: number, body: Record<string, unknown>) {
  return new Response(status === 204 ? null : JSON.stringify(body), {
    status,
    headers: {
      "content-type": "application/json; charset=utf-8",
      "cache-control": "no-store",
      "access-control-allow-origin": "*",
      "access-control-allow-headers": "authorization, apikey, content-type, x-client-info",
      "access-control-allow-methods": "POST, OPTIONS",
    },
  });
}

Deno.serve(async (request) => {
  if (request.method === "OPTIONS") return json(204, {});
  if (request.method !== "POST") return json(405, { error: "Método inválido." });
  const token = request.headers.get("authorization")?.match(/^Bearer\s+(.+)$/i)?.[1];
  if (!token) return json(401, { error: "Entre novamente para continuar." });

  const userClient = createClient(url, publicKey, {
    auth: { autoRefreshToken: false, persistSession: false },
    global: { headers: { Authorization: `Bearer ${token}` } },
  });
  const identity = await userClient.auth.getUser(token);
  const user = identity.data.user;
  if (identity.error || !user?.email) return json(401, { error: "Sua sessão não pôde ser validada. Entre novamente." });

  let input: { password?: unknown; confirmation?: unknown };
  try { input = await request.json(); }
  catch { return json(400, { error: "Confirmação inválida." }); }
  const password = input.password;
  const confirmation = input.confirmation;
  if (typeof password !== "string" || !password || password.length > 256
    || typeof confirmation !== "string" || confirmation.trim().toLocaleLowerCase() !== user.email.toLocaleLowerCase()) {
    return json(400, { error: "Confirme o e-mail e informe sua senha atual." });
  }

  const verifiedFactors = user.factors?.filter((factor) => factor.status === "verified") ?? [];
  if (verifiedFactors.length) {
    try {
      const encoded = token.split(".")[1]?.replace(/-/g, "+").replace(/_/g, "/");
      if (!encoded) throw new Error("Missing JWT payload");
      const payload = JSON.parse(atob(encoded.padEnd(Math.ceil(encoded.length / 4) * 4, "="))) as { aal?: string };
      if (payload.aal !== "aal2") return json(403, { error: "Conclua a verificação multifator antes de excluir a conta." });
    } catch { return json(403, { error: "Não foi possível validar a verificação multifator." }); }
  }

  const passwordClient = createClient(url, publicKey, { auth: { autoRefreshToken: false, persistSession: false } });
  const verifiedPassword = await passwordClient.auth.signInWithPassword({ email: user.email, password });
  if (verifiedPassword.error || verifiedPassword.data.user?.id !== user.id) return json(403, { error: "A senha atual não confere." });

  const guard = await admin.rpc("can_delete_user_account", { p_user_id: user.id });
  if (guard.error) return json(503, { error: "Não foi possível verificar sua conta. Tente novamente." });
  if (guard.data !== true) return json(409, { error: "Esta é a última conta administrativa. Defina outro administrador antes de excluí-la." });

  const bucket = admin.storage.from("profile-avatars");
  for (let batch = 0; batch < 20; batch++) {
    const listed = await bucket.list(user.id, { limit: 100, offset: 0 });
    if (listed.error) return json(503, { error: "Não foi possível remover sua foto. Tente novamente." });
    const paths = (listed.data ?? []).filter((item) => item.name && item.id).map((item) => `${user.id}/${item.name}`);
    if (!paths.length) break;
    const removed = await bucket.remove(paths);
    if (removed.error) return json(503, { error: "Não foi possível remover sua foto. Tente novamente." });
    if (batch === 19) return json(409, { error: "Há muitos arquivos associados à conta. Fale com o suporte para concluir a exclusão." });
  }

  const deleted = await admin.auth.admin.deleteUser(user.id);
  if (deleted.error) return json(503, { error: "Não foi possível excluir a conta. Tente novamente." });
  return json(200, { success: true });
});
