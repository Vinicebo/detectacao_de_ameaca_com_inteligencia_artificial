import type { Severity } from '../api/types';

export function SeverityBadge({ severity }: { severity: Severity }) {
  return <span className={`severity ${severity}`}>{severity}</span>;
}

export function CategoryTags({ categories }: { categories: string[] }) {
  if (categories.length === 0) return <span style={{ color: 'var(--text-faint)' }}>—</span>;
  return (
    <>
      {categories.map((category) => (
        <span className="tag" key={category}>
          {category}
        </span>
      ))}
    </>
  );
}

/** Horário local em formato curto — o log vem em UTC. */
export function formatTime(iso: string): string {
  return new Date(iso).toLocaleTimeString('pt-BR', { hour12: false });
}

export function formatDateTime(iso: string): string {
  return new Date(iso).toLocaleString('pt-BR', { hour12: false });
}

export function BarList({
  items,
  color = 'var(--accent)',
}: {
  items: { label: string; value: number }[];
  color?: string;
}) {
  const max = Math.max(...items.map((item) => item.value), 1);
  return (
    <div>
      {items.map((item) => (
        <div className="bar-row" key={item.label}>
          <span className="mono">{item.label}</span>
          <div className="bar-track">
            <div
              className="bar-fill"
              style={{ width: `${(item.value / max) * 100}%`, background: color }}
            />
          </div>
          <span className="bar-value">{item.value}</span>
        </div>
      ))}
    </div>
  );
}

export function EmptyState({ children }: { children: React.ReactNode }) {
  return <div className="empty">{children}</div>;
}

export function ErrorBanner({ error }: { error: unknown }) {
  const message = error instanceof Error ? error.message : String(error);
  return <div className="error-banner">{message}</div>;
}
