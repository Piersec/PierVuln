import type { HTMLAttributes, ReactNode } from "react";
import { SpotlightCard } from "./spotlight-card";

type BentoGridProps = HTMLAttributes<HTMLElement> & { children: ReactNode };
type BentoCardProps = HTMLAttributes<HTMLElement> & { children: ReactNode };

// Adapted from Magic UI's Bento Grid for PierVuln's existing CSS system.
export function BentoGrid({ children, className = "", ...props }: BentoGridProps) {
  return <section className={`bento-grid ${className}`.trim()} {...props}>{children}</section>;
}

export function BentoCard({ children, className = "", ...props }: BentoCardProps) {
  return <SpotlightCard className={className} {...props}>{children}</SpotlightCard>;
}
