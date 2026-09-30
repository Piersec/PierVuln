import type { HTMLAttributes, ReactNode } from "react";

type BentoGridProps = HTMLAttributes<HTMLElement> & { children: ReactNode };
type BentoCardProps = HTMLAttributes<HTMLElement> & { children: ReactNode };

// Adapted from Magic UI's Bento Grid for PierVuln's existing CSS system.
export function BentoGrid({ children, className = "", ...props }: BentoGridProps) {
  return <section className={`bento-grid ${className}`.trim()} {...props}>{children}</section>;
}

export function BentoCard({ children, className = "", ...props }: BentoCardProps) {
  return <article className={`bento-card ${className}`.trim()} {...props}>{children}</article>;
}
