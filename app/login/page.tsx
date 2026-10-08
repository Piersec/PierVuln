"use client";

import "./login.css";
import Link from "next/link";
import { useRouter } from "next/navigation";
import { FormEvent, useEffect, useRef, useState } from "react";
import { Turnstile, type TurnstileInstance } from "@marsidev/react-turnstile";
import { Brand } from "@/src/components/brand";
import { LoginPreview } from "@/src/components/login-preview";
import { Eye, EyeOff } from "lucide-react";
import { getSupabaseBrowserClient } from "@/src/lib/supabase/client";
import { hasInviteLink } from "@/src/lib/temporary-auth-flow";
import { TURNSTILE_SITE_KEY } from "@/src/lib/auth-captcha";

const inviteHashAtLoad = typeof window !== "undefined" && hasInviteLink() ? window.location.hash : "";
const captchaRefreshAfterMs = 4 * 60_000;

export default function LoginPage() {
  const router = useRouter();
  const supabase = getSupabaseBrowserClient();
  const [email, setEmail] = useState("");
  const [password, setPassword] = useState("");
  const [showPassword, setShowPassword] = useState(false);
  const [busy, setBusy] = useState(false);
  const [notice, setNotice] = useState("");
  const [captchaToken, setCaptchaToken] = useState("");
  const captcha = useRef<TurnstileInstance>(null);
  const submitting = useRef(false);
  const captchaIssuedAt = useRef(0);

  function acceptCaptcha(token: string) {
    captchaIssuedAt.current = Date.now();
    setCaptchaToken(token);
    setNotice((current) => current.includes("desafio de segurança") ? "" : current);
  }

  useEffect(() => {
    if (!captchaToken) return;
    const timer = setTimeout(() => {
      if (submitting.current) return;
      captchaIssuedAt.current = 0;
      setCaptchaToken("");
      captcha.current?.reset();
    }, Math.max(0, captchaRefreshAfterMs - (Date.now() - captchaIssuedAt.current)));
    return () => clearTimeout(timer);
  }, [captchaToken]);

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
    if (!supabase || submitting.current) return;
    if (!captchaToken) { setNotice("Confirme o desafio de segurança para entrar."); return; }
    if (Date.now() - captchaIssuedAt.current >= captchaRefreshAfterMs) {
      captchaIssuedAt.current = 0;
      setCaptchaToken("");
      captcha.current?.reset();
      setNotice("O desafio de segurança expirou. Aguarde a nova confirmação para entrar.");
      return;
    }
    const token = captchaToken;
    submitting.current = true;
    captchaIssuedAt.current = 0;
    setCaptchaToken("");
    setBusy(true);
    setNotice("");
    try {
      const { error } = await supabase.auth.signInWithPassword({ email, password, options: { captchaToken: token } });
      if (error) setNotice(error.code === "captcha_failed"
        ? "O desafio de segurança expirou ou já foi utilizado. Aguarde a nova confirmação e tente entrar novamente."
        : "Não foi possível entrar. Confira o e-mail e a senha ou peça um novo convite à equipe.");
      else router.replace("/dashboard");
    } catch {
      setNotice("Não foi possível conectar. Verifique sua conexão e tente novamente.");
    } finally {
      captchaIssuedAt.current = 0;
      setCaptchaToken("");
      captcha.current?.reset();
      submitting.current = false;
      setBusy(false);
    }
  }

  if (!supabase) {
    return <main className="auth-shell"><section className="auth-card"><Brand /><h1>Configure o Supabase</h1><p>Defina a URL do projeto e a chave publicável no arquivo <code>.env.local</code>.</p></section></main>;
  }

  return (
    <main className="login-shell">
      <a className="skip-link" href="#login-content">Pular para o formulário</a>
      <section className="login-card" id="login-content" tabIndex={-1}>
        <Brand markSrc="/login/mascot.png" />
        <h1 className="sr-only">Entrar no painel</h1>
        <form onSubmit={onSignIn} className="login-form" aria-busy={busy}>
          <label htmlFor="login-email">E-mail<input id="login-email" type="email" autoComplete="email" placeholder="nome@empresa.com.br" required disabled={busy} value={email} onChange={(e) => setEmail(e.target.value)} /></label>
          <label htmlFor="login-password">Senha<span className="login-password-field"><input id="login-password" aria-label="Senha" type={showPassword ? "text" : "password"} autoComplete="current-password" placeholder="Sua senha" required disabled={busy} value={password} onChange={(e) => setPassword(e.target.value)} /><button className="login-password-toggle" type="button" aria-label={showPassword ? "Ocultar senha" : "Mostrar senha"} aria-pressed={showPassword} onClick={() => setShowPassword((current) => !current)}>{showPassword ? <EyeOff size={18} /> : <Eye size={18} />}</button></span></label>
          <div className="auth-captcha"><Turnstile ref={captcha} siteKey={TURNSTILE_SITE_KEY} options={{ theme: "dark", size: "flexible", refreshExpired: "auto" }} onSuccess={acceptCaptcha} onExpire={() => { captchaIssuedAt.current = 0; setCaptchaToken(""); }} onError={() => { captchaIssuedAt.current = 0; setCaptchaToken(""); setNotice("O desafio de segurança falhou. Recarregue a página e tente novamente."); }} /></div>
          <button className="button login-submit" disabled={busy || !captchaToken}>{busy ? "Entrando…" : "Entrar"}</button>
        </form>
        {notice && <p className="form-notice" role="status">{notice}</p>}
        <Link href="/reset-password" className="login-recovery">Esqueci minha senha</Link>
      </section>
      <LoginPreview />
    </main>
  );
}
