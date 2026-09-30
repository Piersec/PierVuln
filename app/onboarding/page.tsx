"use client";

import Link from "next/link";
import { Button } from "@heroui/react";
import { FormEvent, useEffect, useState } from "react";
import type { Session } from "@supabase/supabase-js";
import Rays from "@/src/components/light-rays";
import { SignaturePad } from "@/src/components/ui/signature-pad";
import { getSupabaseBrowserClient } from "@/src/lib/supabase/client";

type Step = "welcome" | "password" | "signature" | "preparing";

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
  const [notice, setNotice] = useState("");
  const [busy, setBusy] = useState(false);
  const [reduceMotion, setReduceMotion] = useState(false);

  useEffect(() => {
    if (!supabase) { setChecking(false); return; }
    void supabase.auth.getSession().then(({ data }) => { setSession(data.session); setChecking(false); });
    const { data } = supabase.auth.onAuthStateChange((_event, nextSession) => {
      setSession(nextSession);
      setChecking(false);
    });
    const media = window.matchMedia("(prefers-reduced-motion: reduce)");
    setReduceMotion(media.matches);
    const onMotion = () => setReduceMotion(media.matches);
    media.addEventListener("change", onMotion);
    return () => { data.subscription.unsubscribe(); media.removeEventListener("change", onMotion); };
  }, [supabase]);

  useEffect(() => {
    if (step !== "preparing") return;
    const timer = window.setTimeout(() => window.location.assign("/"), 3500);
    return () => window.clearTimeout(timer);
  }, [step]);

  async function savePassword(event: FormEvent<HTMLFormElement>) {
    event.preventDefault();
    if (!supabase || !strongPassword(password)) { setNotice("Use ao menos 12 caracteres, com maiúscula, minúscula, número e símbolo."); return; }
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

  const name = typeof session?.user.user_metadata?.full_name === "string"
    ? session.user.user_metadata.full_name.trim() : "";

  return (
    <main className="onboarding-shell">
      <a className="skip-link" href="#onboarding-content">Pular para o conteúdo</a>
      <div className="onboarding-rays" aria-hidden="true"><Rays backgroundColor="#090a0b" raysColor={{ mode: "single", color: "#67e260" }} intensity={8} rays={24} reach={20} animation={{ animate: !reduceMotion, speed: 5 }} style={{ zIndex: 0 }} /></div>
      <div className="onboarding-shade" aria-hidden="true" />
      <header className="onboarding-header"><span className="brand"><span className="brand-mark">P</span><span>Pier<span className="brand-light">Vuln</span></span></span><span className="onboarding-header-note">EQUIPE PIER</span></header>
      <section className="onboarding-card" id="onboarding-content" tabIndex={-1}>
        {checking ? <p role="status">Abrindo seu convite…</p> : !session ? <><span className="onboarding-kicker">CONVITE</span><h1>Abra o link do seu e-mail.</h1><p>Para iniciar o onboarding, acesse o convite enviado pela equipe Pier.</p><Link className="button button-secondary" href="/login">Ir para o login</Link></> : <>
          <div className="onboarding-progress" aria-label="Etapas do onboarding"><span className="is-current" /><span className={step !== "welcome" ? "is-current" : ""} /><span className={step === "signature" || step === "preparing" ? "is-current" : ""} /><span className={step === "preparing" ? "is-current" : ""} /></div>
          {step === "welcome" && <><span className="onboarding-kicker">01 / BOAS-VINDAS</span><h1>Seja bem-vindo(a){name ? `, ${name}` : ""}.</h1><p>Seu espaço na equipe Pier está pronto para começar. Vamos proteger seu acesso em alguns passos.</p><Button className="button button-primary" onPress={() => setStep("password")}>Começar <span aria-hidden="true">→</span></Button></>}
          {step === "password" && <><span className="onboarding-kicker">02 / SEGURANÇA</span><h1>Crie uma senha forte.</h1><p>Use ao menos 12 caracteres, com letra maiúscula, minúscula, número e símbolo.</p><form className="onboarding-form" onSubmit={savePassword}><label>Senha<input required minLength={12} type="password" autoComplete="new-password" value={password} onChange={(event) => setPassword(event.target.value)} /></label><label>Confirme a senha<input required minLength={12} type="password" autoComplete="new-password" value={confirmation} onChange={(event) => setConfirmation(event.target.value)} /></label><Button className="button button-primary" type="submit" isDisabled={busy}>{busy ? "Salvando…" : "Salvar e continuar"}</Button></form>{notice && <p className="onboarding-notice" role="alert">{notice}</p>}</>}
          {step === "signature" && <><span className="onboarding-kicker">03 / SUA MARCA</span><h1>Deixe sua assinatura.</h1><p>Este gesto faz parte das boas-vindas. A assinatura não é salva nem enviada.</p><div className="onboarding-signature"><SignaturePad /></div><Button className="button button-primary" onPress={() => setStep("preparing")}>Concluir <span aria-hidden="true">→</span></Button></>}
          {step === "preparing" && <><span className="onboarding-kicker">04 / TUDO PRONTO</span><div className="onboarding-spinner" aria-hidden="true" /><h1>Estamos preparando tudo.</h1><p>Seu painel será aberto em instantes.</p><Link className="onboarding-direct" href="/">Abrir painel agora <span aria-hidden="true">→</span></Link></>}
        </>}
      </section>
      <footer className="onboarding-footer">PierVuln <span>·</span> Acesso por convite</footer>
    </main>
  );
}
