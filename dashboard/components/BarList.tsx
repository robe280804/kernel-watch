import type { Count } from '@/lib/types';

// BarList renders a /stats breakdown (by_severity, by_scope, by_rule,
// top_containers) as horizontal bars sized relative to the largest count. Pure
// CSS — no charting dependency. When `severityColors` is set, bars are tinted by
// their key so the severity chart reads at a glance.
export function BarList({
  counts,
  severityColors = false,
}: {
  counts: Count[] | null | undefined;
  severityColors?: boolean;
}) {
  const rows = counts ?? [];
  if (rows.length === 0) {
    return <p className="muted">No data in this window.</p>;
  }
  const max = Math.max(...rows.map((r) => r.count), 1);
  return (
    <div className="barlist">
      {rows.map((r) => {
        const pct = Math.max((r.count / max) * 100, 2);
        const fillClass = severityColors ? `fill-${r.key}` : '';
        return (
          <div className="barlist-row" key={r.key || '(none)'}>
            <span className="barlist-key" title={r.key}>
              {r.key || '(none)'}
            </span>
            <div className="barlist-track">
              <div className={`barlist-fill ${fillClass}`} style={{ width: `${pct}%` }} />
            </div>
            <span className="barlist-count">{r.count}</span>
          </div>
        );
      })}
    </div>
  );
}
