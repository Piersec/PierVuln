"use client";

import Link from "next/link";
import { FormEvent, useEffect, useState } from "react";
import { getSupabaseBrowserClient } from "@/src/lib/supabase/client";

export default function LoginPage() {
  const supabase = getSupabaseBrowserClient();
  const [email, setEmail] = useState("");
  const [password, setPassword] = useState("");
  const [newPassword, setNewPassword] = useState("");
  const [isInvite, setIsInvite] = useState(false);
  const [hasSession, setHasSession] = useState(false);
  const [busy, setBusy] = useState(false);
  const [notice, setNotice] = useState("");

  useEffect(() => {
    if (!supabase) return;
    setIsInvite(new URLSearchParams(window.location.search).has("invite"));
    void supabase.auth.getSession().then(({ data }) => setHasSession(Boolean(data.session)));
  }, [supabase]);

  async function onSignIn(event: FormEvent<HTMLFormElement>) {
    event.preventDefault();
    if (!supabase) return;
    setBusy(true);
    setNotice("");
    const { error } = await supabase.auth.signInWithPassword({ email, password });
    if (error) setNotice("Não foi possível entrar. Confira o e-mail e a senha ou peça um novo convite à equipe.");
    else window.location.assign("/");
    setBusy(false);
  }

  async function onSetPassword(event: FormEvent<HTMLFormElement>) {
    event.preventDefault();
    if (!supabase) return;
    setBusy(true);
    setNotice("");
    const { error } = await supabase.auth.updateUser({ password: newPassword });
    if (error) setNotice("Não foi possível salvar a senha. Abra novamente o link de convite ou fale com a equipe.");
    else window.location.assign("/");
    setBusy(false);
  }

  if (!supabase) {
    return <main className="auth-shell"><section className="auth-card"><Brand /><h1>Configure o Supabase</h1><p>Defina a URL do projeto e a chave publicável no arquivo <code>.env.local</code>.</p></section></main>;
  }

  return (
    <main className="auth-shell">
      <a className="skip-link" href="#login-content">Pular para o formulário</a>
      <section className="auth-card" id="login-content" tabIndex={-1}>
        <Brand />
        <h1>{isInvite && hasSession ? "Crie sua senha" : "Entrar no painel"}</h1>
        <p>{isInvite ? "Seu acesso foi enviado pela equipe. Defina uma senha para continuar." : "Entre com o e-mail associado ao seu convite."}</p>
        {isInvite && hasSession ? (
          <form onSubmit={onSetPassword} className="form-stack">
            <label>Nova senha<input type="password" minLength={10} autoComplete="new-password" required value={newPassword} onChange={(e) => setNewPassword(e.target.value)} /></label>
            <button className="button button-primary" disabled={busy}>{busy ? "Salvando…" : "Salvar senha"}</button>
          </form>
        ) : (
          <form onSubmit={onSignIn} className="form-stack">
            <label>E-mail<input type="email" autoComplete="email" required value={email} onChange={(e) => setEmail(e.target.value)} /></label>
            <label>Senha<input type="password" autoComplete="current-password" required value={password} onChange={(e) => setPassword(e.target.value)} /></label>
            <button className="button button-primary" disabled={busy}>{busy ? "Entrando…" : "Entrar"}</button>
          </form>
        )}
        {notice && <p className="form-notice" role="status">{notice}</p>}
        <Link href="/" className="back-link">Voltar ao painel</Link>
      </section>
      <aside className="auth-rail" aria-label="Sobre o PierVuln">
        <div className="auth-rail-content"><span className="auth-rail-label">PIERVULN / OPERAÇÕES</span><h2>Uma leitura clara da exposição.</h2><p>Consulte os achados reportados pelo Wazuh e acompanhe o tratamento com o histórico de cada caso.</p><div className="auth-rail-foot"><span className="status-mark" aria-hidden="true"/>Acesso por convite</div></div>
      </aside>
    </main>
  );
}

function Brand() {
  return <div className="brand"><span className="brand-mark">P</span><span>Pier<span className="brand-light">Vuln</span></span></div>;
}
