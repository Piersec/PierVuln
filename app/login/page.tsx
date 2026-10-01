"use client";

import Link from "next/link";
import { useRouter } from "next/navigation";
import { FormEvent, useEffect, useRef, useState } from "react";
import HCaptcha from "@hcaptcha/react-hcaptcha";
import { Brand } from "@/src/components/brand";
import { getSupabaseBrowserClient } from "@/src/lib/supabase/client";
import { BentoCard, BentoGrid } from "@/src/components/ui/bento-grid";
import { hasInviteLink } from "@/src/lib/temporary-auth-flow";
import { HCAPTCHA_SITE_KEY } from "@/src/lib/auth-captcha";

const inviteHashAtLoad = typeof window !== "undefined" && hasInviteLink() ? window.location.hash : "";

export default function LoginPage() {
  const router = useRouter();
  const supabase = getSupabaseBrowserClient();
  const [email, setEmail] = useState("");
  const [password, setPassword] = useState("");
  const [busy, setBusy] = useState(false);
  const [notice, setNotice] = useState("");
  const [captchaToken, setCaptchaToken] = useState("");
  const captcha = useRef<HCaptcha>(null);

  useEffect(() => {
    if (!supabase) return;
    if (new URLSearchParams(window.location.search).has("invite")) {
      window.location.replace(`/onboarding${inviteHashAtLoad || window.location.hash}`);
      return;
    }
    const { data } = supabase.auth.onAuthStateChange((event) => {
      if (event === "PASSWORD_RECOVERY") window.location.replace("/reset-password?mode=update");
    });
    return () => data.subscription.unsubscribe();
  }, [supabase]);

  async function onSignIn(event: FormEvent<HTMLFormElement>) {
    event.preventDefault();
    if (!supabase) return;
    if (!captchaToken) { setNotice("Confirme o desafio de segurança para entrar."); return; }
    setBusy(true);
    setNotice("");
    try {
      const { error } = await supabase.auth.signInWithPassword({ email, password, options: { captchaToken } });
      if (error) setNotice(error.code === "captcha_failed"
        ? "Não foi possível validar o desafio de segurança. Tente novamente."
        : "Não foi possível entrar. Confira o e-mail e a senha ou peça um novo convite à equipe.");
      else router.replace("/");
    } catch {
      setNotice("Não foi possível conectar. Verifique sua conexão e tente novamente.");
    } finally {
      setCaptchaToken("");
      captcha.current?.resetCaptcha();
      setBusy(false);
    }
  }

  if (!supabase) {
    return <main className="auth-shell"><section className="auth-card"><Brand /><h1>Configure o Supabase</h1><p>Defina a URL do projeto e a chave publicável no arquivo <code>.env.local</code>.</p></section></main>;
  }

  return (
    <main className="auth-shell">
      <a className="skip-link" href="#login-content">Pular para o formulário</a>
      <section className="auth-card" id="login-content" tabIndex={-1}>
        <Brand />
        <h1>Entrar no painel</h1>
        <p>Entre com o e-mail associado ao seu convite.</p>
        <form onSubmit={onSignIn} className="form-stack">
          <label>E-mail<input type="email" autoComplete="email" required value={email} onChange={(e) => setEmail(e.target.value)} /></label>
          <label>Senha<input type="password" autoComplete="current-password" required value={password} onChange={(e) => setPassword(e.target.value)} /></label>
          <div className="auth-captcha"><HCaptcha ref={captcha} sitekey={HCAPTCHA_SITE_KEY} theme="dark" onVerify={setCaptchaToken} onExpire={() => setCaptchaToken("")} onError={() => { setCaptchaToken(""); setNotice("O desafio de segurança falhou. Recarregue a página e tente novamente."); }} /></div>
          <button className="button button-primary" disabled={busy || !captchaToken}>{busy ? "Entrando…" : "Entrar"}</button>
        </form>
        {notice && <p className="form-notice" role="status">{notice}</p>}
        <Link href="/reset-password" className="back-link">Esqueci minha senha</Link>
        <Link href="/" className="back-link">Voltar ao painel</Link>
      </section>
      <aside className="auth-rail" aria-label="Sobre o PierVuln">
        <div className="auth-rail-content">
          <span className="auth-rail-label">PIERVULN / OPERAÇÕES</span>
          <h2>Uma leitura clara da exposição.</h2>
          <p>Consulte as vulnerabilidades identificadas e acompanhe o tratamento com o histórico de cada caso.</p>
          <BentoGrid className="auth-bento" aria-label="O que você acompanha no PierVuln">
            <BentoCard className="auth-feature auth-feature-source"><span>Fonte de dados</span><strong>Indexador</strong><small>Estado da última leitura completa sempre visível.</small></BentoCard>
            <BentoCard className="auth-feature"><span>Tratamento</span><strong>Fluxo de casos</strong><small>Da abertura à validação.</small></BentoCard>
            <BentoCard className="auth-feature"><span>Registro</span><strong>Histórico</strong><small>Contexto e comentários no mesmo lugar.</small></BentoCard>
          </BentoGrid>
          <div className="auth-rail-foot"><span className="status-mark" aria-hidden="true"/>Acesso por convite</div>
        </div>
      </aside>
    </main>
  );
}
