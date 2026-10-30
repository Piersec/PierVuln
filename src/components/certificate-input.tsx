"use client";
import { useId, useRef, useState } from "react";
import { visibleText } from "@/src/lib/visible-text";
type Inspection = { pem: string; certificates: { subject: string; expiresAt: string; fingerprint: string }[] };
export function CertificateInput({ name, label, saved = false, required = false }: { name: string; label: string; saved?: boolean; required?: boolean }) {
  const id = useId(); const file = useRef<HTMLInputElement>(null); const text = useRef<HTMLTextAreaElement>(null);
  const sequence = useRef(0); const [result, setResult] = useState<Inspection | null>(null);
  const [filename, setFilename] = useState(""); const [error, setError] = useState(""); const [busy, setBusy] = useState(false);
  function reset() {
    sequence.current++; setResult(null); setFilename(""); setError(""); setBusy(false);
    if (file.current) { file.current.value = ""; file.current.setCustomValidity(""); }
    if (text.current) { text.current.value = ""; text.current.setCustomValidity(""); }
  }
  async function inspect(bytes: Uint8Array, filename: string) {
    const request = ++sequence.current; setBusy(true); setResult(null); setError(""); setFilename(filename);
    file.current?.setCustomValidity("Aguarde a validação do certificado.");
    try {
      if (!bytes.length || bytes.length > 65536) throw new Error("Selecione um certificado de até 64 KB.");
      if (/PRIVATE KEY|OPENSSH|<key>/i.test(new TextDecoder().decode(bytes))) throw new Error("Envie somente o certificado público, sem chave privada.");
      const response = await fetch("/api/certificates/inspect", { method: "POST", body: new Blob([new Uint8Array(bytes)]), signal: AbortSignal.timeout(15000) });
      const data = await response.json(); if (!response.ok) throw new Error(data.error || "Não foi possível validar o certificado.");
      if (request !== sequence.current) return;
      setResult(data); file.current?.setCustomValidity(""); text.current?.setCustomValidity("");
    } catch (cause) {
      if (request !== sequence.current) return;
      const message = cause instanceof Error ? cause.message : "Falha ao validar certificado.";
      setError(message); file.current?.setCustomValidity(message); text.current?.setCustomValidity(message);
    } finally { if (request === sequence.current) setBusy(false); }
  }
  return <section className="certificate-input" aria-labelledby={id}>
    <strong id={id}>{label}</strong>
    <input type="hidden" name={name} value={result?.pem ?? ""} />
    <label className="certificate-file-label" htmlFor={id + "-file"}>Selecionar arquivo
      <input ref={file} id={id + "-file"} type="file" accept=".pem,.txt,.crt,.cer,.der" required={required && !saved && !result} aria-describedby={id + "-state"} onChange={(event) => {
        const selected = event.target.files?.[0]; if (!selected) return;
        if (text.current) text.current.value = "";
        if (selected.size > 65536) { void inspect(new Uint8Array(), selected.name); return; }
        const readSequence = ++sequence.current;
        setBusy(true); setResult(null); setFilename(selected.name); setError("");
        file.current?.setCustomValidity("Aguarde a validação do certificado.");
        void selected.arrayBuffer().then((buffer) => {
          if (readSequence === sequence.current) return inspect(new Uint8Array(buffer), selected.name);
        }).catch(() => {
          if (readSequence !== sequence.current) return;
          const message = "Não foi possível ler o arquivo. Selecione novamente.";
          setBusy(false); setError(message); file.current?.setCustomValidity(message);
        });
      }} />
    </label>
    <p className="muted-copy">PEM, TXT, CRT, CER ou DER · até 64 KB. A aplicação converte para ca.pem.</p>
    <div id={id + "-state"} role="status" aria-live="polite">
      {busy ? <p>Validando certificado…</p> : error ? <p className="certificate-error">{error}</p> : result ? <>
        <p><strong>{visibleText(filename)}</strong> · pronto como ca.pem · {result.certificates.length} certificado(s)</p>
        {result.certificates.map((cert) => <p className="muted-copy" key={cert.fingerprint}>{visibleText(cert.subject.split("\n").find((line) => line.startsWith("CN=")) ?? cert.subject)} · válido até {new Date(cert.expiresAt).toLocaleDateString("pt-BR")}</p>)}
        <a className="button button-secondary" href={"data:application/x-pem-file;charset=utf-8," + encodeURIComponent(result.pem)} download="ca.pem">Baixar ca.pem</a>
      </> : <p className="muted-copy">{saved ? "Certificado salvo. Selecione outro arquivo para substituir." : "Nenhum arquivo selecionado. Ao editar, o certificado salvo será mantido."}</p>}
    </div>
    {(filename || error) && <button className="button button-secondary" type="button" onClick={reset}>Cancelar alteração</button>}
    <details><summary>Avançado: colar certificado</summary><label>Conteúdo do certificado<textarea ref={text} rows={4} maxLength={65536} placeholder="-----BEGIN CERTIFICATE-----" onChange={(event) => {
      const value = event.target.value;
      if (!value.trim()) { reset(); return; }
      void inspect(new TextEncoder().encode(value), "Certificado colado");
    }} /></label></details>
  </section>;
}
