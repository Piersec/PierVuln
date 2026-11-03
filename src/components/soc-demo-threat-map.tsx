"use client";

import { useEffect, useMemo, useRef, useState } from "react";
import type { Map as LeafletMap } from "leaflet";
import "leaflet/dist/leaflet.css";

type Location = { city: string; country: string; lat: number; lng: number };
export type DemoMapRoute = { origin: Location; destination: Location; severity: string; count: number };
const labels: Record<string, string> = { critical: "Crítico", high: "Alto", medium: "Médio", low: "Baixo", informational: "Informativo", unknown: "Sem classificação" };
const colors: Record<string, string> = { critical: "#ff6c9a", high: "#ff777e", medium: "#ffb454", low: "#f5dc65", informational: "#71d8f0", unknown: "#d4d7da" };
const valid = (point: Location) => Number.isFinite(point.lat) && Number.isFinite(point.lng) && Math.abs(point.lat) <= 85 && Math.abs(point.lng) <= 180;

export function SocDemoThreatMap({ routes }: { routes: DemoMapRoute[] }) {
  const container = useRef<HTMLDivElement>(null);
  const map = useRef<LeafletMap | null>(null);
  const [country, setCountry] = useState("");
  const [severity, setSeverity] = useState("");
  const [selected, setSelected] = useState<DemoMapRoute | null>(null);
  const [error, setError] = useState("");
  const [ready, setReady] = useState(false);
  const countries = useMemo(() => [...new Set(routes.map((route) => route.origin.country))].sort((a, b) => a.localeCompare(b, "pt-BR")), [routes]);
  const visible = useMemo(() => routes.filter((route) => valid(route.origin) && valid(route.destination) && (!country || route.origin.country === country) && (!severity || route.severity === severity)), [routes, country, severity]);
  const total = visible.reduce((sum, route) => sum + route.count, 0);

  useEffect(() => {
    let disposed = false;
    let instance: LeafletMap | undefined;
    let resize: ResizeObserver | undefined;
    setReady(false);
    setError("");
    setSelected(null);
    void import("leaflet").then((L) => {
      if (disposed || !container.current) return;
      instance = L.map(container.current, { minZoom: 1, maxZoom: 9, scrollWheelZoom: false, worldCopyJump: true }).setView([15, 0], 2);
      map.current = instance;
      instance.zoomControl.setPosition("bottomright");
      const tiles = L.tileLayer("https://tile.openstreetmap.org/{z}/{x}/{y}.png", {
        attribution: '&copy; <a href="https://www.openstreetmap.org/copyright">OpenStreetMap contributors</a>',
        maxZoom: 19,
      }).addTo(instance);
      tiles.on("tileerror", () => { if (!disposed) setError("O mapa-base não carregou. As rotas simuladas continuam disponíveis; verifique a conexão."); });
      tiles.on("load", () => { if (!disposed) setReady(true); });
      const points: [number, number][] = [];
      for (const route of visible) {
        const from: [number, number] = [route.origin.lat, route.origin.lng];
        const to: [number, number] = [route.destination.lat, route.destination.lng];
        points.push(from, to);
        const color = colors[route.severity] ?? colors.unknown;
        const text = `${route.origin.city}, ${route.origin.country} → ${route.destination.city}: ${route.count.toLocaleString("pt-BR")} alertas · ${labels[route.severity] ?? route.severity} · Simulação`;
        const tooltip = document.createElement("span");
        tooltip.textContent = text;
        const line = L.polyline([from, to], { color, weight: 2, opacity: .65, className: "soc-demo-route" }).addTo(instance);
        line.bindTooltip(tooltip);
        line.on("click", () => setSelected(route));
        const marker = L.circleMarker(from, { radius: Math.min(15, 5 + Math.sqrt(route.count)), color, fillColor: color, fillOpacity: .8, weight: 2 }).addTo(instance);
        marker.bindTooltip(tooltip.cloneNode(true) as HTMLElement);
        marker.on("click", () => setSelected(route));
        L.circleMarker(to, { radius: 6, color: "#71d8f0", fillColor: "#71d8f0", fillOpacity: 1, weight: 2 }).addTo(instance);
      }
      if (points.length) instance.fitBounds(L.latLngBounds(points), { padding: [40, 40], maxZoom: 4 });
      resize = new ResizeObserver(() => instance?.invalidateSize());
      resize.observe(container.current);
      setReady(true);
    }).catch(() => { if (!disposed) setError("Não foi possível iniciar o mapa. Recarregue a página para tentar novamente."); });
    return () => { disposed = true; resize?.disconnect(); instance?.remove(); map.current = null; };
  }, [visible]);

  return <section className="soc-demo-map" aria-label="Mapa interativo de ameaças simuladas">
    <header><div><strong>Mapa de ameaças · Demonstração</strong><p>Origens, destinos e rotas fictícios para testar a visualização.</p></div><span>{total.toLocaleString("pt-BR")} alertas</span></header>
    <div className="soc-demo-map-filters">
      <label>Origem<select value={country} onChange={(event) => setCountry(event.target.value)}><option value="">Todos os países</option>{countries.map((name) => <option key={name}>{name}</option>)}</select></label>
      <label>Severidade<select value={severity} onChange={(event) => setSeverity(event.target.value)}><option value="">Todas</option>{Object.entries(labels).map(([value, label]) => <option key={value} value={value}>{label}</option>)}</select></label>
      <button className="button button-secondary" onClick={() => { setCountry(""); setSeverity(""); map.current?.setView([15, 0], 2); }}>Visão mundial</button>
    </div>
    <div className="soc-demo-map-stage" ref={container} aria-label="Use as setas para mover o mapa e os botões mais e menos para aproximar e afastar." />
    {error && <p className="soc-demo-map-message" role="alert">{error}</p>}
    {!ready && !error && <p className="soc-demo-map-message" role="status">Carregando mapa…</p>}
    {ready && !visible.length && <p className="soc-demo-map-message" role="status">Nenhuma rota corresponde aos filtros.</p>}
    <footer><span>{selected ? `${selected.origin.city} → ${selected.destination.city} · ${selected.count.toLocaleString("pt-BR")} alertas · ${labels[selected.severity]}` : "Clique em uma origem ou rota para ver os detalhes. Coordenadas simuladas, sem geolocalização dos IPs."}</span><div className="soc-demo-map-legend">{Object.entries(labels).map(([key, label]) => <span key={key}><i style={{ background: colors[key] }}/>{label}</span>)}</div></footer>
  </section>;
}
