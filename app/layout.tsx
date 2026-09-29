import type { Metadata } from "next";
import "./globals.css";

export const metadata: Metadata = {
  title: "PierVuln · Gestão de vulnerabilidades",
  description: "Painel seguro de vulnerabilidades sincronizadas do Wazuh.",
};

export default function RootLayout({ children }: Readonly<{ children: React.ReactNode }>) {
  return (
    <html lang="pt-BR">
      <body>{children}</body>
    </html>
  );
}
