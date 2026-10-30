import { X509Certificate } from "node:crypto";
export const runtime = "nodejs";
const limit = 65536;
export async function POST(request: Request) {
  if (Number(request.headers.get("content-length") ?? 0) > limit) return Response.json({ error: "O arquivo deve ter até 64 KB." }, { status: 413 });
  const reader = request.body?.getReader();
  if (!reader) return Response.json({ error: "Selecione um certificado." }, { status: 400 });
  const chunks: Uint8Array[] = []; let size = 0;
  for (;;) {
    const { value, done } = await reader.read(); if (done) break;
    size += value.length;
    if (size > limit) { await reader.cancel(); return Response.json({ error: "O arquivo deve ter até 64 KB." }, { status: 413 }); }
    chunks.push(value);
  }
  try {
    const bytes = Buffer.concat(chunks); const text = (bytes[0] === 255 && bytes[1] === 254 ? new TextDecoder("utf-16le").decode(bytes) : bytes[0] === 254 && bytes[1] === 255 ? new TextDecoder("utf-16be").decode(bytes) : bytes.toString("utf8")).replace(/^\uFEFF/, "").trim();
    if (/PRIVATE KEY|OPENSSH|<key>/i.test(text)) throw new Error("Envie somente o certificado público, sem chave privada.");
    const blocks = text.match(/-----BEGIN CERTIFICATE-----[\s\S]*?-----END CERTIFICATE-----/g);
    if (blocks && text.replace(/-----BEGIN CERTIFICATE-----[\s\S]*?-----END CERTIFICATE-----/g, "").trim()) throw new Error("O arquivo deve conter somente certificados, sem outros textos.");
    const certificates = blocks ? blocks.map((block) => new X509Certificate(block))
      : [new X509Certificate(/^[A-Za-z0-9+/=\s]+$/.test(text) ? Buffer.from(text.replace(/\s/g, ""), "base64") : bytes)];
    const now = Date.now();
    if (certificates.some((cert) => Date.parse(cert.validTo) < now)) throw new Error("O certificado está expirado. Envie um certificado vigente.");
    if (certificates.some((cert) => Date.parse(cert.validFrom) > now)) throw new Error("O certificado ainda não está válido.");
    const pem = certificates.map((cert) => cert.toString().trim()).join("\n") + "\n";
    if (Buffer.byteLength(pem) > limit) throw new Error("O certificado convertido excede 64 KB.");
    return Response.json({ pem, certificates: certificates.map((cert) => ({ subject: cert.subject, expiresAt: cert.validTo, fingerprint: cert.fingerprint256 })) }, { headers: { "cache-control": "no-store" } });
  } catch (error) {
    const known = error instanceof Error && /Envie|arquivo|certificado|convertido/.test(error.message);
    return Response.json({ error: known ? (error as Error).message : "Não foi encontrado um certificado válido. Use PEM, TXT com certificado, CRT, CER ou DER." }, { status: 400 });
  }
}
