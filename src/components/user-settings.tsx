"use client";

import Link from "next/link";
import { Button, Switch } from "@heroui/react";
import { Turnstile, type TurnstileInstance } from "@marsidev/react-turnstile";
import { useEffect, useRef, useState, type ChangeEvent, type FormEvent } from "react";
import type { User } from "@supabase/supabase-js";
import { Brand } from "@/src/components/brand";
import { NavSymbol } from "@/src/components/ui/nav-symbol";
import { UserAvatar, profileUpdatedEvent } from "@/src/components/user-avatar";
import { useSiteNotifications } from "@/src/components/site-notifications";
import { notificationTypes, type NotificationType } from "@/src/lib/notification-types";
import { getSupabaseBrowserClient } from "@/src/lib/supabase/client";
import { TURNSTILE_SITE_KEY } from "@/src/lib/auth-captcha";

type Profile = { display_name: string; avatar_path: string | null };
const avatarBucket = "profile-avatars";

async function prepareAvatar(file: File): Promise<Blob> {
  if (!["image/png", "image/jpeg", "image/webp"].includes(file.type)) throw new Error("Escolha uma imagem PNG, JPEG ou WebP.");
  if (file.size > 5 * 1024 * 1024) throw new Error("A imagem deve ter no máximo 5 MB.");
  const bitmap = await createImageBitmap(file);
  try {
    const canvas = document.createElement("canvas");
    canvas.width = 512;
    canvas.height = 512;
    const context = canvas.getContext("2d");
    if (!context) throw new Error("Não foi possível preparar a imagem.");
    const side = Math.min(bitmap.width, bitmap.height);
    context.drawImage(bitmap, (bitmap.width - side) / 2, (bitmap.height - side) / 2, side, side, 0, 0, 512, 512);
    const blob = await new Promise<Blob | null>((resolve) => canvas.toBlob(resolve, "image/webp", 0.85));
    if (!blob || blob.size > 2 * 1024 * 1024) throw new Error("Não foi possível compactar a imagem para o perfil.");
    return blob;
  } finally { bitmap.close(); }
}

function strongPassword(value: string) {
  return value.length >= 12 && /[a-z]/.test(value) && /[A-Z]/.test(value)
    && /\d/.test(value) && /[^A-Za-z0-9]/.test(value);
}

export function UserSettings() {
  const client = getSupabaseBrowserClient();
  const { notify, disabledNotificationTypes, setNotificationTypeEnabled } = useSiteNotifications();
  const fileInput = useRef<HTMLInputElement>(null);
  const deleteDialog = useRef<HTMLDialogElement>(null);
  const passwordCaptcha = useRef<TurnstileInstance>(null);
  const deleteCaptcha = useRef<TurnstileInstance>(null);
  const [user, setUser] = useState<User | null>(null);
  const [isInternal, setIsInternal] = useState(false);
  const [profile, setProfile] = useState<Profile | null>(null);
  const [name, setName] = useState("");
  const [status, setStatus] = useState<"loading" | "ready" | "signed-out" | "error">("loading");
  const [profileBusy, setProfileBusy] = useState(false);
  const [passwordBusy, setPasswordBusy] = useState(false);
  const [preferenceBusy, setPreferenceBusy] = useState<NotificationType | null>(null);
  const [profileMessage, setProfileMessage] = useState("");
  const [passwordMessage, setPasswordMessage] = useState("");
  const [passwordCaptchaToken, setPasswordCaptchaToken] = useState("");
  const [preferenceMessage, setPreferenceMessage] = useState("");
  const [currentPassword, setCurrentPassword] = useState("");
  const [newPassword, setNewPassword] = useState("");
  const [confirmPassword, setConfirmPassword] = useState("");
  const [deleteEmail, setDeleteEmail] = useState("");
  const [deletePassword, setDeletePassword] = useState("");
  const [deleteBusy, setDeleteBusy] = useState(false);
  const [deleteOpen, setDeleteOpen] = useState(false);
  const [deleteMessage, setDeleteMessage] = useState("");
  const [deleteCaptchaToken, setDeleteCaptchaToken] = useState("");

  useEffect(() => {
    if (!client) { setStatus("error"); return; }
    let active = true;
    async function load() {
      const identity = await client!.auth.getUser();
      if (!active) return;
      if (identity.error || !identity.data.user) { setStatus("signed-out"); return; }
      const current = identity.data.user;
      const [profileResult, contextResult] = await Promise.all([
        client!.from("user_profiles").select("display_name,avatar_path").eq("id", current.id).single(),
        client!.rpc("current_user_context"),
      ]);
      if (!active) return;
      if (profileResult.error || !profileResult.data || contextResult.error) { setStatus("error"); return; }
      setUser(current);
      setProfile(profileResult.data);
      setName(profileResult.data.display_name ?? "");
      setIsInternal(contextResult.data?.is_internal_admin === true);
      setStatus("ready");
    }
    void load();
    const { data } = client.auth.onAuthStateChange((event) => {
      if (event === "SIGNED_OUT" && active) { setUser(null); setProfile(null); setStatus("signed-out"); }
    });
    return () => { active = false; data.subscription.unsubscribe(); };
  }, [client]);

  async function saveName(event: FormEvent<HTMLFormElement>) {
    event.preventDefault();
    if (!client || !user) return;
    const value = name.trim();
    if (!value || value.length > 160) { setProfileMessage("Informe um nome de até 160 caracteres."); return; }
    setProfileBusy(true); setProfileMessage("");
    const { data, error } = await client.from("user_profiles").update({ display_name: value }).eq("id", user.id).select("display_name").single();
    setProfileBusy(false);
    if (error || !data) { setProfileMessage("Não foi possível salvar o nome."); notify({ title: "Não foi possível salvar o perfil.", error: true, key: "profile" }); return; }
    setName(data.display_name);
    setProfile((previous) => previous ? { ...previous, display_name: data.display_name } : previous);
    setProfileMessage("Nome atualizado.");
    notify({ title: "Nome do perfil atualizado.", key: "profile" });
  }

  async function uploadAvatar(event: ChangeEvent<HTMLInputElement>) {
    const file = event.target.files?.[0];
    event.target.value = "";
    if (!file || !client || !user || !profile) return;
    setProfileBusy(true); setProfileMessage("");
    let path: string | null = null;
    try {
      const image = await prepareAvatar(file);
      path = `${user.id}/${crypto.randomUUID()}.webp`;
      const uploaded = await client.storage.from(avatarBucket).upload(path, image, { contentType: "image/webp", upsert: false });
      if (uploaded.error) throw uploaded.error;
      const saved = await client.from("user_profiles").update({ avatar_path: path }).eq("id", user.id).select("avatar_path").single();
      if (saved.error || !saved.data) throw saved.error ?? new Error("Falha ao salvar a foto.");
      const oldPath = profile.avatar_path;
      setProfile((previous) => previous ? { ...previous, avatar_path: path } : previous);
      window.dispatchEvent(new Event(profileUpdatedEvent));
      if (oldPath && oldPath !== path) void client.storage.from(avatarBucket).remove([oldPath]);
      setProfileMessage("Foto atualizada.");
      notify({ title: "Foto do perfil atualizada.", key: "profile" });
    } catch (error) {
      if (path) void client.storage.from(avatarBucket).remove([path]);
      setProfileMessage(error instanceof Error ? error.message : "Não foi possível enviar a foto.");
      notify({ title: "Não foi possível atualizar a foto.", error: true, key: "profile" });
    } finally { setProfileBusy(false); }
  }

  async function removeAvatar() {
    if (!client || !user || !profile?.avatar_path) return;
    setProfileBusy(true); setProfileMessage("");
    const oldPath = profile.avatar_path;
    const saved = await client.from("user_profiles").update({ avatar_path: null }).eq("id", user.id).select("avatar_path").single();
    setProfileBusy(false);
    if (saved.error || !saved.data) { setProfileMessage("Não foi possível remover a foto."); return; }
    setProfile((previous) => previous ? { ...previous, avatar_path: null } : previous);
    window.dispatchEvent(new Event(profileUpdatedEvent));
    void client.storage.from(avatarBucket).remove([oldPath]);
    setProfileMessage("Foto removida.");
    notify({ title: "Foto do perfil removida.", key: "profile" });
  }

  async function toggleNotification(type: NotificationType, enabled: boolean) {
    setPreferenceBusy(type); setPreferenceMessage("");
    try {
      await setNotificationTypeEnabled(type, enabled);
      setPreferenceMessage(`${notificationTypes.find((item) => item.id === type)?.label} ${enabled ? "ativadas" : "desativadas"}.`);
    } catch (error) { setPreferenceMessage(error instanceof Error ? error.message : "Não foi possível salvar a preferência."); }
    finally { setPreferenceBusy(null); }
  }

  async function changePassword(event: FormEvent<HTMLFormElement>) {
    event.preventDefault();
    if (!client || !user?.email) return;
    if (!passwordCaptchaToken) { setPasswordMessage("Confirme o desafio de segurança."); return; }
    if (!strongPassword(newPassword)) { setPasswordMessage("Use ao menos 12 caracteres, com maiúscula, minúscula, número e símbolo."); return; }
    if (newPassword !== confirmPassword) { setPasswordMessage("As novas senhas não coincidem."); return; }
    if (currentPassword === newPassword) { setPasswordMessage("Escolha uma senha diferente da atual."); return; }
    setPasswordBusy(true); setPasswordMessage("");
    try {
      const verified = await client.auth.signInWithPassword({ email: user.email, password: currentPassword, options: { captchaToken: passwordCaptchaToken } });
      if (verified.error) { setPasswordMessage("A senha atual está incorreta."); return; }
      const changed = await client.auth.updateUser({ password: newPassword });
      if (changed.error) { setPasswordMessage("Não foi possível alterar a senha. Tente novamente ou use a recuperação de acesso."); return; }
      setCurrentPassword(""); setNewPassword(""); setConfirmPassword("");
      setPasswordMessage("Senha alterada com sucesso.");
      notify({ title: "Senha da conta alterada.", key: "security" });
    } catch { setPasswordMessage("Não foi possível conectar. Tente novamente."); }
    finally { setPasswordCaptchaToken(""); passwordCaptcha.current?.reset(); setPasswordBusy(false); }
  }

  async function signOut() {
    if (!client) return;
    const { error } = await client.auth.signOut();
    if (error) notify({ title: "Não foi possível encerrar a sessão.", error: true, key: "auth-session" });
  }

  function closeDeleteDialog() {
    if (deleteBusy) return;
    deleteDialog.current?.close();
    setDeleteOpen(false);
    setDeleteEmail(""); setDeletePassword(""); setDeleteMessage("");
    setDeleteCaptchaToken(""); deleteCaptcha.current?.reset();
  }

  async function deleteAccount(event: FormEvent<HTMLFormElement>) {
    event.preventDefault();
    if (!client || !user?.email || deleteBusy) return;
    if (!deleteCaptchaToken) { setDeleteMessage("Confirme o desafio de segurança."); return; }
    if (deleteEmail.trim().toLowerCase() !== user.email.toLowerCase() || !deletePassword) {
      setDeleteMessage("Digite seu e-mail e sua senha atual para confirmar.");
      return;
    }
    setDeleteBusy(true); setDeleteMessage("");
    try {
      const { data, error } = await client.functions.invoke("delete-account", {
        body: { confirmation: deleteEmail.trim(), password: deletePassword, captchaToken: deleteCaptchaToken },
      });
      if (error || data?.success !== true) {
        let message = typeof data?.error === "string" ? data.error : "Não foi possível excluir a conta. Tente novamente.";
        if (error && "context" in error && error.context instanceof Response) {
          const response = await error.context.json().catch(() => null);
          if (typeof response?.error === "string") message = response.error;
        }
        setDeleteMessage(message);
        return;
      }
      try { await client.auth.signOut({ scope: "local" }); } catch { /* The account has already been removed. */ }
      try {
        localStorage.removeItem(`piervuln:notifications:v1:${user.id}:history`);
        localStorage.removeItem(`piervuln:notifications:v1:${user.id}:muted`);
      } catch { /* Private browsing may block local storage. */ }
      window.location.replace("/login");
    } catch {
      setDeleteMessage("Não foi possível conectar. Tente novamente.");
    } finally { setDeleteCaptchaToken(""); deleteCaptcha.current?.reset(); setDeleteBusy(false); }
  }

  if (status === "loading") return <main className="loading-screen"><Brand /><div className="spinner" /><p>Preparando configurações…</p></main>;
  if (status === "signed-out") return <main className="auth-shell"><section className="auth-card"><Brand /><h1>Entre para configurar sua conta</h1><p>As preferências são individuais e só ficam disponíveis após o acesso.</p><Link className="button button-primary" href="/login">Entrar</Link></section></main>;
  if (status === "error" || !user || !profile) return <main className="auth-shell"><section className="auth-card"><Brand /><h1>Configurações indisponíveis</h1><p>Não foi possível carregar seus dados agora.</p><Button className="button button-secondary" onPress={() => window.location.reload()}>Tentar novamente</Button></section></main>;

  return <main className="app-shell settings-shell">
    <a className="skip-link" href="#settings-content">Pular para configurações</a>
    <aside className={`sidebar${isInternal ? " has-admin" : ""}`}>
      <Brand />
      <nav className="workspace-nav" aria-label="Navegação principal">
        <div className="nav-caption">WORKSPACE</div>
        <Link className="nav-link" href="/" aria-label="Vulnerabilidades" title="Vulnerabilidades"><NavSymbol kind="vulnerabilities" /><span className="nav-label">Vulnerabilidades</span></Link>
        <Link className="nav-link" href="/cases" aria-label="Casos" title="Casos de vulnerabilidade"><NavSymbol kind="cases" /><span className="nav-label">Casos</span></Link>
        <Link className="nav-link" href="/book" aria-label="Book dos Clientes" title="Book dos Clientes"><NavSymbol kind="book" /><span className="nav-label">Book dos Clientes</span></Link>
        <Link className="nav-link" href="/status" aria-label="Status" title="Status"><NavSymbol kind="status" /><span className="nav-label">Status</span></Link>
        {isInternal && <Link className="nav-link" href="/admin" aria-label="Administração" title="Administração"><NavSymbol kind="admin" /><span className="nav-label">Administração</span></Link>}
        <Link className="nav-link active" href="/settings" aria-current="page" aria-label="Configurações" title="Configurações"><NavSymbol kind="settings" /><span className="nav-label">Configurações</span></Link>
      </nav>
      <div className="sidebar-bottom"><UserAvatar userId={user.id} fallback={name || user.email || "U"} /><div className="user-info"><strong>{name || user.email}</strong><span>{isInternal ? "Equipe Pier" : "Minha conta"}</span></div><button className="sidebar-signout" onClick={() => void signOut()}>Sair</button></div>
    </aside>

    <section className="main-column" id="settings-content" tabIndex={-1}>
      <header className="topbar"><div className="breadcrumb">PierVuln <span>/</span> <strong>Configurações</strong></div></header>
      <div className="content-wrap settings-content">
        <div className="page-heading"><div><span className="page-kicker">CONTA / PREFERÊNCIAS</span><h1>Configurações</h1><p>Cuide do seu perfil, escolha os avisos que recebe e proteja seu acesso.</p></div></div>

        <section className="settings-section" aria-labelledby="profile-title">
          <div className="settings-section-heading"><div><span className="settings-index">01 / IDENTIDADE</span><h2 id="profile-title">Seu perfil</h2><p>Esta foto e este nome representam sua conta no PierVuln.</p></div></div>
          <div className="settings-profile-row"><UserAvatar userId={user.id} fallback={name || user.email || "U"} large /><div><strong>{profile.display_name || user.email}</strong><span>{user.email}</span><div className="settings-avatar-actions"><input ref={fileInput} type="file" accept="image/png,image/jpeg,image/webp" className="sr-only" aria-label="Escolher foto do perfil" onChange={(event) => void uploadAvatar(event)} /><Button variant="secondary" isDisabled={profileBusy} onPress={() => fileInput.current?.click()}>Trocar foto</Button>{profile.avatar_path && <Button variant="ghost" isDisabled={profileBusy} onPress={() => void removeAvatar()}>Remover foto</Button>}</div><small>PNG, JPEG ou WebP, até 5 MB. A foto é recortada para um quadrado.</small></div></div>
          <form className="settings-form" onSubmit={(event) => void saveName(event)}><label htmlFor="settings-name">Nome de exibição</label><div className="settings-field-action"><input id="settings-name" value={name} maxLength={160} required onChange={(event) => setName(event.target.value)} /><Button type="submit" isDisabled={profileBusy || name.trim() === profile.display_name}>Salvar nome</Button></div></form>
          {profileMessage && <p className="settings-feedback" role="status">{profileMessage}</p>}
        </section>

        <section className="settings-section" aria-labelledby="notifications-title">
          <div className="settings-section-heading"><div><span className="settings-index">02 / AVISOS</span><h2 id="notifications-title">Notificações</h2><p>Desative tipos inteiros de aviso. Isso interrompe novos toasts e novas entradas na central; o histórico existente permanece.</p></div></div>
          <div className="settings-toggle-list">{notificationTypes.map((item) => <Switch key={item.id} className="settings-toggle" isSelected={!disabledNotificationTypes.includes(item.id)} isDisabled={preferenceBusy !== null} onChange={(enabled) => void toggleNotification(item.id, enabled)}>
            <Switch.Content><span className="settings-toggle-copy"><strong>{item.label}</strong><small>{item.description}</small></span><Switch.Control><Switch.Thumb /></Switch.Control></Switch.Content>
          </Switch>)}</div>
          {preferenceMessage && <p className="settings-feedback" role="status">{preferenceMessage}</p>}
          <p className="settings-note">Dentro da central de notificações, você ainda pode silenciar somente o toast de um aviso específico.</p>
        </section>

        <section className="settings-section" aria-labelledby="security-title">
          <div className="settings-section-heading"><div><span className="settings-index">03 / ACESSO</span><h2 id="security-title">Segurança</h2><p>Atualize sua senha usando a senha atual para confirmar a alteração.</p></div></div>
          <form className="settings-password-form" onSubmit={(event) => void changePassword(event)}>
            <label>Senha atual<input type="password" autoComplete="current-password" required value={currentPassword} onChange={(event) => setCurrentPassword(event.target.value)} /></label>
            <label>Nova senha<input type="password" autoComplete="new-password" minLength={12} required value={newPassword} onChange={(event) => setNewPassword(event.target.value)} /></label>
            <label>Confirme a nova senha<input type="password" autoComplete="new-password" minLength={12} required value={confirmPassword} onChange={(event) => setConfirmPassword(event.target.value)} /></label>
            <p>Use ao menos 12 caracteres, com maiúscula, minúscula, número e símbolo.</p>
            <div className="auth-captcha"><Turnstile ref={passwordCaptcha} siteKey={TURNSTILE_SITE_KEY} options={{ theme: "dark" }} onSuccess={setPasswordCaptchaToken} onExpire={() => setPasswordCaptchaToken("")} onError={() => { setPasswordCaptchaToken(""); setPasswordMessage("O desafio de segurança falhou. Recarregue a página e tente novamente."); }} /></div>
            <Button type="submit" isDisabled={passwordBusy || !passwordCaptchaToken}>{passwordBusy ? "Salvando…" : "Alterar senha"}</Button>
          </form>
          {passwordMessage && <p className="settings-feedback" role="status">{passwordMessage}</p>}
          <div className="settings-mfa"><div><strong>Autenticação multifator</strong><p>Uma segunda etapa de verificação para entrar na conta.</p></div><span>Em breve</span></div>
        </section>

        <section className="settings-section settings-danger" aria-labelledby="danger-title">
          <div className="settings-section-heading"><div><span className="settings-index">04 / ZONA DE PERIGO</span><h2 id="danger-title">Zona de perigo</h2><p>Encerrar sua conta é uma ação permanente. Os registros operacionais da empresa precisam ser preservados.</p></div></div>
          <div className="settings-danger-row"><div><strong>Excluir minha conta</strong><p>Remove seu acesso e seu perfil pessoal. Casos e auditoria da empresa permanecem.</p></div><Button variant="danger-soft" onPress={() => { setDeleteOpen(true); deleteDialog.current?.showModal(); }}>Excluir conta</Button></div>
        </section>
      </div>
    </section>
    <dialog ref={deleteDialog} className="admin-dialog settings-delete-dialog" aria-labelledby="delete-account-title" onCancel={(event) => { if (deleteBusy) event.preventDefault(); else closeDeleteDialog(); }}>
      <div className="admin-dialog-header"><h2 id="delete-account-title">Excluir minha conta</h2><Button variant="ghost" isDisabled={deleteBusy} aria-label="Fechar" onPress={closeDeleteDialog}>Fechar</Button></div>
      <form className="admin-editor-form" onSubmit={(event) => void deleteAccount(event)}>
        <p>Essa ação remove permanentemente seu acesso, perfil e foto. Casos e registros de auditoria da empresa continuam disponíveis, sem vínculo com sua conta.</p>
        <p>Para confirmar, digite <strong>{user.email}</strong> e sua senha atual.</p>
        <fieldset disabled={deleteBusy}>
          <label>E-mail de confirmação<input type="email" autoComplete="off" required value={deleteEmail} onChange={(event) => setDeleteEmail(event.target.value)} /></label>
          <label>Senha atual<input type="password" autoComplete="current-password" required value={deletePassword} onChange={(event) => setDeletePassword(event.target.value)} /></label>
        </fieldset>
        {deleteOpen && <div className="auth-captcha"><Turnstile ref={deleteCaptcha} siteKey={TURNSTILE_SITE_KEY} options={{ theme: "dark" }} onSuccess={setDeleteCaptchaToken} onExpire={() => setDeleteCaptchaToken("")} onError={() => { setDeleteCaptchaToken(""); setDeleteMessage("O desafio de segurança falhou. Recarregue a página e tente novamente."); }} /></div>}
        {deleteMessage && <p className="settings-delete-error" role="alert">{deleteMessage}</p>}
        <div className="admin-dialog-footer"><Button variant="secondary" isDisabled={deleteBusy} onPress={closeDeleteDialog}>Cancelar</Button><Button type="submit" variant="danger" isDisabled={deleteBusy || deleteEmail.trim().toLowerCase() !== user.email?.toLowerCase() || !deletePassword || !deleteCaptchaToken}>{deleteBusy ? "Excluindo…" : "Excluir minha conta"}</Button></div>
      </form>
    </dialog>
  </main>;
}
