"use client";

import { type HTMLAttributes, type MouseEvent, type ReactNode } from "react";

type SpotlightCardProps = HTMLAttributes<HTMLElement> & {
  children: ReactNode;
  spotlightColor?: string;
};

export function trackSpotlight(event: MouseEvent<HTMLElement>, spotlightColor = "rgb(72 233 255 / 8%)") {
  if (!window.matchMedia("(hover: hover) and (pointer: fine)").matches || window.matchMedia("(prefers-reduced-motion: reduce)").matches) return;
  const card = event.currentTarget;
  const rect = card.getBoundingClientRect();
  card.style.setProperty("--spotlight-x", `${event.clientX - rect.left}px`);
  card.style.setProperty("--spotlight-y", `${event.clientY - rect.top}px`);
  card.style.setProperty("--spotlight-color", spotlightColor);
}

export function SpotlightCard({ children, className = "", spotlightColor, onMouseMove, ...props }: SpotlightCardProps) {
  return <article {...props} onMouseMove={(event) => { trackSpotlight(event, spotlightColor); onMouseMove?.(event); }} className={`bento-card spotlight-card ${className}`.trim()}>{children}</article>;
}
