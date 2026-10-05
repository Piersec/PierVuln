"use client";

import Link from "next/link";
import { FormEvent, useEffect, useRef, useState } from "react";
import { Turnstile, type TurnstileInstance } from "@marsidev/react-turnstile";
import { Brand } from "@/src/components/brand";
import { getSupabaseBrowserClient } from "@/src/lib/supabase/client";
import { clearTemporaryAuthFlow, grantTemporaryAuthFlow, hasTemporaryAuthFlow } from "@/src/lib/temporary-auth-flow";
import { TURNSTILE_SITE_KEY } from "@/src/lib/auth-captcha";

type Step = "checking" | "request" | "sent" | "update" | "invalid" | "done";

export default function ResetPasswordPage() {
  const supabase = getSupabaseBrowserClient();
  const [step, setStep] = useState<Step>("checking");
  const [email, setEmail] = useState("");
  const [recoveryCode, setRecoveryCode] = useState("");
  const [password, setPassword] = useState("");
  const [confirmation, setConfirmation] = useState("");
  const [busy, setBusy] = useState(false);
  const [notice, setNotice] = useState("");
  const [captchaToken, setCaptchaToken] = useState("");
  const captcha = useRef<TurnstileInstance>(null);

  useEffect(() => {
    if (!supabase) return;
    let active = true;
    const params = new URLSearchParams(window.location.search);
    const hash = new URLSearchParams(window.location.hash.slice(1));
    const invalid = params.has("error") || hash.has("error");
    const enteringRecoveryCode = params.get("mode") === "verify";
    const updating = params.get("mode") === "update" || hash.get("type") === "recovery";
    const { data: listener } = supabase.auth.onAuthStateChange((event, session) => {
      if (!active || invalid) return;
      if (event === "PASSWORD_RECOVERY" && session) {
        if (!grantTemporaryAuthFlow("recovery", session.user.id)) { setStep("invalid"); return; }
        window.history.replaceState(null, "", "/reset-password?mode=update");
        setStep("update");
      }
      if (event === "SIGNED_OUT") { clearTemporaryAuthFlow(); setStep((current) => current === "update" ? "invalid" : current); }
    });

    async function initialize() {
      if (invalid) {
        window.history.replaceState(null, "", "/reset-password?mode=update");
        if (active) setStep("invalid");
        return;
      }
      if (enteringRecoveryCode) { if (active) setStep("sent"); return; }
      if (!updating) { if (active) setStep("request"); return; }
      try {
        const { data, error } = await supabase!.auth.getUser();
        if (active) setStep(!error && data.user && hasTemporaryAuthFlow("recovery", data.user.id) ? "update" : "invalid");
      } catch {
        if (active) setStep("invalid");
      }
    }
    void initialize();
    return () => { active = false; listener.subscription.unsubscribe(); };
  }, [supabase]);

  useEffect(() => {
    if (!supabase || step !== "update") return;
    const timer = window.setInterval(() => {
      void supabase.auth.getSession().then(({ data }) => {
        if (!data.session || !hasTemporaryAuthFlow("recovery", data.session.user.id)) {
          clearTemporaryAuthFlow(); setStep("invalid");
        }
      });
    }, 15_000);
    return () => window.clearInterval(timer);
  }, [step, supabase]);

  async function requestReset(event: FormEvent<HTMLFormElement>) {
    event.preventDefault();
    if (!supabase || busy) return;
    if (!captchaToken) { setNotice("Confirme o desafio de segurança para solicitar o link."); return; }
    setBusy(true);
    setNotice("");
    try {
      const { error } = await supabase.auth.resetPasswordForEmail(email.trim(), {
        redirectTo: `${window.location.origin}/reset-password?mode=update`,
        captchaToken,
      });
      if (error) {
        setNotice(error.status === 429
          ? "Muitas solicitações. Aguarde alguns minutos e tente novamente."
          : "Não foi possível solicitar o link. Tente novamente em alguns instantes.");
      } else setStep("sent");
    } catch {
      setNotice("Não foi possível conectar. Verifique sua conexão e tente novamente.");
    } finally { setCaptchaToken(""); captcha.current?.reset(); setBusy(false); }
  }

  async function verifyRecoveryCode(event: FormEvent<HTMLFormElement>) {
    event.preventDefault();
    if (!supabase || busy || !email.trim() || !recoveryCode.trim()) return;
    setBusy(true);
    setNotice("");
    try {
      const { data, error } = await supabase.auth.verifyOtp({
        email: email.trim(),
        token: recoveryCode.trim(),
        type: "recovery",
      });
      if (error || !data.session || !grantTemporaryAuthFlow("recovery", data.session.user.id)) {
        setNotice("Código inválido ou expirado. Solicite um novo código e tente novamente.");
        return;
      }
      window.history.replaceState(null, "", "/reset-password?mode=update");
      setStep("update");
    } catch {
      setNotice("Não foi possível validar o código. Verifique sua conexão e tente novamente.");
    } finally { setBusy(false); }
  }

  async function savePassword(event: FormEvent<HTMLFormElement>) {
    event.preventDefault();
    if (!supabase || busy || step !== "update") return;
    const identity = await supabase.auth.getUser();
    if (identity.error || !identity.data.user || !hasTemporaryAuthFlow("recovery", identity.data.user.id)) {
      clearTemporaryAuthFlow(); setStep("invalid"); return;
    }
    if (password.length < 12 || !/[a-z]/.test(password) || !/[A-Z]/.test(password)
      || !/\d/.test(password) || !/[^A-Za-z0-9]/.test(password)) {
      setNotice("Use ao menos 12 caracteres, com maiúscula, minúscula, número e símbolo.");
      return;
    }
    if (password !== confirmation) { setNotice("As senhas não coincidem."); return; }
    setBusy(true);
    setNotice("");
    try {
      const { error } = await supabase.auth.updateUser({ password });
      if (error) {
        if (error.status === 401 || error.status === 403 || error.code === "session_not_found") setStep("invalid");
        else setNotice(error.code === "same_password"
          ? "Escolha uma senha diferente da atual."
          : "Não foi possível salvar. Use uma senha diferente e tente novamente ou solicite outro link.");
        return;
      }
      setPassword("");
      setConfirmation("");
      setStep("done");
      clearTemporaryAuthFlow();
      window.history.replaceState(null, "", "/reset-password");
      await supabase.auth.signOut({ scope: "local" });
    } catch {
      setNotice("Não foi possível conectar. Verifique sua conexão e tente novamente.");
    } finally { setBusy(false); }
  }

  return (
    <main className="auth-shell">
      <a className="skip-link" href="#reset-content">Pular para o formulário</a>
      <section className="auth-card" id="reset-content" tabIndex={-1}>
        <Brand />
        <h1>{step === "update" ? "Defina sua nova senha" : step === "done" ? "Senha atualizada" : "Recuperar acesso"}</h1>
        {!supabase ? <p role="alert">A recuperação de senha está indisponível. Fale com a equipe para restabelecer o acesso.</p> : <>
          {step === "checking" && <p role="status">Verificando seu link…</p>}
          {step === "request" && <>
            <p>Informe o e-mail da sua conta para receber um código de redefinição de senha.</p>
            <form onSubmit={requestReset} className="form-stack" aria-busy={busy}>
              <label>E-mail<input type="email" autoComplete="email" required disabled={busy} value={email} onChange={(event) => setEmail(event.target.value)} /></label>
              <div className="auth-captcha"><Turnstile ref={captcha} siteKey={TURNSTILE_SITE_KEY} options={{ theme: "dark" }} onSuccess={setCaptchaToken} onExpire={() => setCaptchaToken("")} onError={() => { setCaptchaToken(""); setNotice("O desafio de segurança falhou. Recarregue a página e tente novamente."); }} /></div>
              <button className="button button-primary" disabled={busy || !captchaToken}>{busy ? "Solicitando…" : "Enviar código de recuperação"}</button>
            </form>
          </>}
          {step === "sent" && <>
            <p role="status">{email.trim() ? `Informe o código enviado para ${email.trim()}.` : "Informe o e-mail da conta e o código recebido."} Confira também a pasta de spam.</p>
            <form onSubmit={verifyRecoveryCode} className="form-stack" aria-busy={busy}>
              <label>E-mail<input type="email" autoComplete="email" required disabled={busy} value={email} onChange={(event) => setEmail(event.target.value)} /></label>
              <label>Código recebido por e-mail<input type="text" inputMode="numeric" autoComplete="one-time-code" maxLength={8} required disabled={busy} value={recoveryCode} onChange={(event) => setRecoveryCode(event.target.value.replace(/\D/g, ""))} /></label>
              <button className="button button-primary" disabled={busy || !recoveryCode.trim()}>{busy ? "Validando…" : "Validar código"}</button>
            </form>
            <button className="button button-secondary" onClick={() => { window.history.replaceState(null, "", "/reset-password"); setNotice(""); setRecoveryCode(""); setStep("request"); }}>Solicitar outro código</button>
          </>}
          {step === "update" && <>
            <p id="password-help">Use ao menos 12 caracteres, com letra maiúscula, minúscula, número e símbolo.</p>
            <form onSubmit={savePassword} className="form-stack" aria-busy={busy}>
              <label>Nova senha<input type="password" autoComplete="new-password" aria-describedby="password-help" minLength={12} required disabled={busy} value={password} onChange={(event) => setPassword(event.target.value)} /></label>
              <label>Confirme a nova senha<input type="password" autoComplete="new-password" minLength={12} required disabled={busy} value={confirmation} onChange={(event) => setConfirmation(event.target.value)} /></label>
              <button className="button button-primary" disabled={busy}>{busy ? "Salvando…" : "Salvar nova senha"}</button>
            </form>
          </>}
          {step === "invalid" && <>
            <p role="alert">Este link expirou ou não é válido. Solicite um novo link para redefinir sua senha.</p>
            <button className="button button-primary" onClick={() => { window.history.replaceState(null, "", "/reset-password"); setNotice(""); setStep("request"); }}>Solicitar novo link</button>
          </>}
          {step === "done" && <p role="status">Sua nova senha foi salva. Entre novamente para acessar o painel.</p>}
          {notice && <p className="form-notice" role="alert">{notice}</p>}
        </>}
        <Link href="/login" className="back-link">Voltar ao login</Link>
      </section>
      <aside className="auth-rail" aria-label="Recuperação de acesso ao PierVuln">
        <div className="auth-rail-content">
          <h2>Retome o acompanhamento dos seus casos.</h2>
          <p>Abra o link enviado ao e-mail da sua conta e escolha uma nova senha para voltar ao PierVuln.</p>
        </div>
      </aside>
    </main>
  );
}
