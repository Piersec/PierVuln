import type { Metadata } from "next";
import localFont from "next/font/local";
import "./globals.css";
import "./microinteractions.css";
import { SiteNotifications } from "@/src/components/site-notifications";

const plexSans = localFont({
  src: [
    { path: "./fonts/ibm-plex-sans-400.ttf", weight: "400", style: "normal" },
    { path: "./fonts/ibm-plex-sans-500.ttf", weight: "500", style: "normal" },
    { path: "./fonts/ibm-plex-sans-600.ttf", weight: "600", style: "normal" },
    { path: "./fonts/ibm-plex-sans-700.ttf", weight: "700", style: "normal" },
  ],
  variable: "--font-sans",
  display: "swap",
});

const plexMono = localFont({
  src: [
    { path: "./fonts/ibm-plex-mono-400.ttf", weight: "400", style: "normal" },
    { path: "./fonts/ibm-plex-mono-500.ttf", weight: "500", style: "normal" },
    { path: "./fonts/ibm-plex-mono-600.ttf", weight: "600", style: "normal" },
  ],
  variable: "--font-mono",
  display: "swap",
});

export const metadata: Metadata = {
  title: "PierVuln · Gestão de vulnerabilidades",
  description: "Painel seguro de vulnerabilidades sincronizadas da fonte de dados.",
};

export default function RootLayout({ children }: Readonly<{ children: React.ReactNode }>) {
  return (
    <html lang="pt-BR">
      <body className={`${plexSans.variable} ${plexMono.variable}`}><SiteNotifications>{children}</SiteNotifications></body>
    </html>
  );
}
