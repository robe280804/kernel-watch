import type { Alert } from '@/lib/types';

function fmtTime(ts: string): string {
  // Render in UTC to match the daemon's timestamps; avoid locale drift.
  const d = new Date(ts);
  if (Number.isNaN(d.getTime())) return ts;
  return d.toISOString().replace('T', ' ').replace('.000Z', 'Z').slice(0, 19) + 'Z';
}

function detailsSummary(a: Alert): string {
  if (a.cmdline) return a.cmdline;
  if (a.details && Object.keys(a.details).length > 0) {
    return Object.entries(a.details)
      .map(([k, v]) => `${k}=${typeof v === 'object' ? JSON.stringify(v) : String(v)}`)
      .join('  ');
  }
  return '';
}

export function AlertTable({ alerts }: { alerts: Alert[] }) {
  if (alerts.length === 0) {
    return <p className="muted">No alerts match these filters.</p>;
  }
  return (
    <div className="table-wrap">
      <table>
        <thead>
          <tr>
            <th>Time (UTC)</th>
            <th>Sev</th>
            <th>Scope</th>
            <th>Rule</th>
            <th>Container</th>
            <th>Process</th>
            <th>Parent</th>
            <th>Reason / command</th>
          </tr>
        </thead>
        <tbody>
          {alerts.map((a) => {
            const scope = a.scope || 'container';
            const detail = detailsSummary(a);
            return (
              <tr key={a.id}>
                <td className="mono">{fmtTime(a.timestamp)}</td>
                <td>
                  <span className={`sev sev-${a.severity}`}>{a.severity}</span>
                </td>
                <td>
                  <span className="badge">{scope}</span>
                </td>
                <td className="mono">{a.rule_id || '—'}</td>
                <td>{a.container_name || (scope === 'host' ? '(host)' : '—')}</td>
                <td className="mono">{a.process_name || '—'}</td>
                <td className="mono">{a.parent_name || '—'}</td>
                <td>
                  <div>{a.reason}</div>
                  {detail ? <div className="mono muted">{detail}</div> : null}
                </td>
              </tr>
            );
          })}
        </tbody>
      </table>
    </div>
  );
}
