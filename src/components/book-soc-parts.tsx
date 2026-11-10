// Peças visuais comuns das páginas do Book SOC.

export function SectionHead({ tag, title, side }: { tag?: string; title: string; side?: string }) {
  return (
    <div className="bsoc-section-head">
      <div>{tag && <span className="bsoc-tag">{tag}</span>}<h2>{title}</h2></div>
      {side && <small>{side}</small>}
    </div>
  );
}

export function BarList({ rows, label }: { rows: { label: string; count: number }[]; label: string }) {
  const max = Math.max(1, ...rows.map((row) => row.count));
  return (
    <ul className="bsoc-bars" aria-label={label}>
      {rows.map((row) => (
        <li key={row.label}>
          <span className="bsoc-bar-label">{row.label}</span>
          <span className="bsoc-bar-track" aria-hidden="true"><span className="bsoc-bar-fill" style={{ width: `${Math.round((row.count / max) * 100)}%` }} /></span>
          <strong className="bsoc-bar-value">{row.count.toLocaleString("pt-BR")}</strong>
        </li>
      ))}
    </ul>
  );
}
