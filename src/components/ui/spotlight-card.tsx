"use client";

import { useRef, type HTMLAttributes, type MouseEvent, type ReactNode } from "react";

type SpotlightCardProps = HTMLAttributes<HTMLElement> & {
  children: ReactNode;
  spotlightColor?: string;
};

// Adapted from React Bits Spotlight Card; the light follows the pointer only on this feature tile.
export function SpotlightCard({ children, className = "", spotlightColor = "rgb(87 220 229 / 16%)", ...props }: SpotlightCardProps) {
  const cardRef = useRef<HTMLElement>(null);

  function handleMouseMove(event: MouseEvent<HTMLElement>) {
    const card = cardRef.current;
    if (!card) return;
    const rect = card.getBoundingClientRect();
    card.style.setProperty("--spotlight-x", `${event.clientX - rect.left}px`);
    card.style.setProperty("--spotlight-y", `${event.clientY - rect.top}px`);
    card.style.setProperty("--spotlight-color", spotlightColor);
  }

  return <article ref={cardRef} onMouseMove={handleMouseMove} className={`bento-card spotlight-card ${className}`.trim()} {...props}>{children}</article>;
}
