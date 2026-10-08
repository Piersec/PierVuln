"use client";

import Link from "next/link";
import { Button } from "@heroui/react";
import { FormEvent, useEffect, useRef, useState } from "react";
import type { Session } from "@supabase/supabase-js";
import { Brand } from "@/src/components/brand";
import Rays from "@/src/components/light-rays";
import { SignaturePad } from "@/src/components/ui/signature-pad";
import { getSupabaseBrowserClient } from "@/src/lib/supabase/client";
import { clearTemporaryAuthFlow, grantTemporaryAuthFlow, hasInviteLink, hasTemporaryAuthFlow } from "@/src/lib/temporary-auth-flow";

type Step = "welcome" | "password" | "signature" | "preparing";
const inviteAccessToken = typeof window !== "undefined" && hasInviteLink()
  ? new URLSearchParams(window.location.hash.slice(1)).get("access_token") : null;

function strongPassword(value: string) {
  return value.length >= 12 && /[a-z]/.test(value) && /[A-Z]/.test(value)
    && /\d/.test(value) && /[^A-Za-z0-9]/.test(value);
}

export default function OnboardingPage() {
  const supabase = getSupabaseBrowserClient();
  const [session, setSession] = useState<Session | null>(null);
  const [checking, setChecking] = useState(true);
  const [step, setStep] = useState<Step>("welcome");
  const [password, setPassword] = useState("");
  const [confirmation, setConfirmation] = useState("");
  const [inviteEmail, setInviteEmail] = useState("");
  const [inviteCode, setInviteCode] = useState("");
  const [notice, setNotice] = useState("");
  const [busy, setBusy] = useState(false);
  const acceptingInvite = useRef(false);
  const [reduceMotion, setReduceMotion] = useState(false);

  useEffect(() => {
    if (!supabase) { setChecking(false); return; }
    let active = true;
    async function checkInvite() {
      const identity = await supabase!.auth.getUser();
      const current = identity.data.user;
      if (!active) return;
      if (identity.error || !current) { setSession(null); setChecking(false); return; }
      const profile = await supabase!.from("user_profiles").select("onboarding_completed_at").eq("id", current.id).single();
      if (!active) return;
      if (profile.error || !profile.data || profile.data.onboarding_completed_at) {
        clearTemporaryAuthFlow(); setSession(null); setChecking(false); return;
      }
      const result = await supabase!.auth.getSession();
      if (!active) return;
      const linkedToken = inviteAccessToken ?? (hasInviteLink() ? new URLSearchParams(window.location.hash.slice(1)).get("access_token") : null);
      if (linkedToken && result.data.session?.access_token === linkedToken) {
        grantTemporaryAuthFlow("invite", current.id);
        window.history.replaceState(null, "", "/onboarding");
      }
      if (!hasTemporaryAuthFlow("invite", current.id)) { setSession(null); setChecking(false); return; }
      setSession(result.data.session?.user.id === current.id ? result.data.session : null);
      setChecking(false);
    }
    void checkInvite();
    const { data } = supabase.auth.onAuthStateChange((event, nextSession) => {
      if (event === "PASSWORD_RECOVERY") {
        window.location.replace("/reset-password?mode=update");
        return;
      }
      if (event === "SIGNED_OUT") { clearTemporaryAuthFlow(); setSession(null); setChecking(false); }
      if (event === "SIGNED_IN" && nextSession && !acceptingInvite.current) void checkInvite();
    });
    const media = window.matchMedia("(prefers-reduced-motion: reduce)");
    setReduceMotion(media.matches);
    const onMotion = () => setReduceMotion(media.matches);
    media.addEventListener("change", onMotion);
    return () => { active = false; data.subscription.unsubscribe(); media.removeEventListener("change", onMotion); };
  }, [supabase]);

  async function acceptInvite(event: FormEvent<HTMLFormElement>) {
    event.preventDefault();
    if (!supabase || busy || !inviteEmail.trim() || !inviteCode.trim()) return;
    acceptingInvite.current = true;
    setBusy(true);
    setNotice("");
    try {
      const { data, error } = await supabase.auth.verifyOtp({
        email: inviteEmail.trim(),
        token: inviteCode.trim(),
        type: "invite",
      });
      if (error || !data.session) {
        setNotice("Código inválido ou expirado. Peça à equipe Pier para reenviar o convite.");
        return;
      }
      const { data: profile, error: profileError } = await supabase
        .from("user_profiles").select("onboarding_completed_at").eq("id", data.session.user.id).single();
      if (profileError || !profile || profile.onboarding_completed_at) {
        await supabase.auth.signOut({ scope: "local" });
        setNotice("Este convite não está mais pendente. Fale com a equipe Pier para revisar seu acesso.");
        return;
      }
      if (!grantTemporaryAuthFlow("invite", data.session.user.id)) {
        await supabase.auth.signOut({ scope: "local" });
        setNotice("Não foi possível abrir o convite neste navegador. Ative o armazenamento local e tente novamente.");
        return;
      }
      setSession(data.session);
      setNotice("");
      window.history.replaceState(null, "", "/onboarding");
    } catch {
      setNotice("Não foi possível validar o convite. Verifique sua conexão e tente novamente.");
    } finally {
      acceptingInvite.current = false;
      setBusy(false);
      setChecking(false);
    }
  }

  useEffect(() => {
    if (step !== "preparing") return;
    const timer = window.setTimeout(() => window.location.assign("/dashboard"), 3500);
    return () => window.clearTimeout(timer);
  }, [step]);

  useEffect(() => {
    if (!session || step === "preparing") return;
    const timer = window.setInterval(() => {
      if (!hasTemporaryAuthFlow("invite", session.user.id)) { setSession(null); setNotice(""); }
    }, 15_000);
    return () => window.clearInterval(timer);
  }, [session, step]);

  async function savePassword(event: FormEvent<HTMLFormElement>) {
    event.preventDefault();
    if (!supabase || !session || !hasTemporaryAuthFlow("invite", session.user.id)) { setNotice("Seu convite expirou. Peça um novo link à equipe."); return; }
    if (!strongPassword(password)) { setNotice("Use ao menos 12 caracteres, com maiúscula, minúscula, número e símbolo."); return; }
    if (password !== confirmation) { setNotice("As senhas não coincidem."); return; }
    setBusy(true);
    setNotice("");
    const { error } = await supabase.auth.updateUser({ password });
    setBusy(false);
    if (error) { setNotice("Não foi possível salvar a senha. Abra novamente o link do convite ou fale com a equipe."); return; }
    setPassword("");
    setConfirmation("");
    setStep("signature");
  }

  async function completeOnboarding() {
    if (!supabase || !session || !hasTemporaryAuthFlow("invite", session.user.id)) { setNotice("Seu convite expirou. Peça um novo link à equipe."); return; }
    setBusy(true); setNotice("");
    const result = await supabase.from("user_profiles").update({ onboarding_completed_at: new Date().toISOString() })
      .eq("id", session.user.id).is("onboarding_completed_at", null).select("id").single();
    setBusy(false);
    if (result.error || !result.data) { setNotice("Não foi possível concluir. Tente novamente."); return; }
    clearTemporaryAuthFlow();
    setStep("preparing");
  }

  const name = typeof session?.user.user_metadata?.full_name === "string"
    ? session.user.user_metadata.full_name.trim() : "";

  return (
    <main className="onboarding-shell">
      <a className="skip-link" href="#onboarding-content">Pular para o conteúdo</a>
      <div className="onboarding-rays" aria-hidden="true"><Rays backgroundColor="#090a0b" raysColor={{ mode: "single", color: "#67e260" }} intensity={8} rays={24} reach={20} animation={{ animate: !reduceMotion, speed: 5 }} style={{ zIndex: 0 }} /></div>
      <div className="onboarding-shade" aria-hidden="true" />
      <header className="onboarding-header"><Brand /><span className="onboarding-header-note">EQUIPE PIER</span></header>
      <section className="onboarding-card" id="onboarding-content" tabIndex={-1}>
        {checking ? <p role="status">Abrindo seu convite…</p> : !session ? <><span className="onboarding-kicker">CONVITE</span><h1>Confirme seu convite.</h1><p>Informe o e-mail que recebeu o convite e o código enviado. Assim, filtros de segurança do e-mail não consomem seu acesso antes da hora.</p><form className="onboarding-form" onSubmit={acceptInvite} aria-busy={busy}><label>E-mail<input required type="email" autoComplete="email" value={inviteEmail} onChange={(event) => setInviteEmail(event.target.value)} /></label><label>Código do convite<input required type="text" inputMode="numeric" autoComplete="one-time-code" maxLength={8} value={inviteCode} onChange={(event) => setInviteCode(event.target.value.replace(/\D/g, ""))} /></label><button className="button button-primary" disabled={busy || !inviteEmail.trim() || !inviteCode.trim()}>{busy ? "Validando…" : "Validar convite"}</button></form>{notice && <p className="onboarding-notice" role="alert">{notice}</p>}<Link className="button button-secondary" href="/login">Ir para o login</Link></> : <>
          <div className="onboarding-progress" aria-label="Etapas do onboarding"><span className="is-current" /><span className={step !== "welcome" ? "is-current" : ""} /><span className={step === "signature" || step === "preparing" ? "is-current" : ""} /><span className={step === "preparing" ? "is-current" : ""} /></div>
          {step === "welcome" && <><span className="onboarding-kicker">01 / BOAS-VINDAS</span><h1>Seja bem-vindo(a){name ? `, ${name}` : ""}.</h1><p>Seu espaço na equipe Pier está pronto para começar. Vamos proteger seu acesso em alguns passos.</p><Button className="button button-primary" onPress={() => setStep("password")}>Começar <span aria-hidden="true">→</span></Button></>}
          {step === "password" && <><span className="onboarding-kicker">02 / SEGURANÇA</span><h1>Crie uma senha forte.</h1><p>Use ao menos 12 caracteres, com letra maiúscula, minúscula, número e símbolo.</p><form className="onboarding-form" onSubmit={savePassword}><label>Senha<input required minLength={12} type="password" autoComplete="new-password" value={password} onChange={(event) => setPassword(event.target.value)} /></label><label>Confirme a senha<input required minLength={12} type="password" autoComplete="new-password" value={confirmation} onChange={(event) => setConfirmation(event.target.value)} /></label><Button className="button button-primary" type="submit" isDisabled={busy}>{busy ? "Salvando…" : "Salvar e continuar"}</Button></form>{notice && <p className="onboarding-notice" role="alert">{notice}</p>}</>}
          {step === "signature" && <><span className="onboarding-kicker">03 / SUA MARCA</span><h1>Deixe sua assinatura.</h1><p>Este gesto faz parte das boas-vindas. A assinatura não é salva nem enviada.</p><div className="onboarding-signature"><SignaturePad /></div><Button className="button button-primary" isDisabled={busy} onPress={() => void completeOnboarding()}>{busy ? "Concluindo…" : "Concluir"} <span aria-hidden="true">→</span></Button>{notice && <p className="onboarding-notice" role="alert">{notice}</p>}</>}
          {step === "preparing" && <><span className="onboarding-kicker">04 / TUDO PRONTO</span><div className="onboarding-spinner" aria-hidden="true" /><h1>Estamos preparando tudo.</h1><p>Seu painel será aberto em instantes.</p><Link className="onboarding-direct" href="/dashboard">Abrir painel agora <span aria-hidden="true">→</span></Link></>}
        </>}
      </section>
      <footer className="onboarding-footer">PierVuln <span>·</span> Acesso por convite</footer>
    </main>
  );
}
