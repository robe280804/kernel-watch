import { kwGet } from '@/lib/kw-client';
import type { StatsResult } from '@/lib/types';
import { BarList } from '@/components/BarList';

export const dynamic = 'force-dynamic'; // always reflect live data, never cache

const RANGES = [
  { value: '1h', label: 'Last hour' },
  { value: '24h', label: 'Last 24h' },
  { value: '168h', label: 'Last 7 days' },
  { value: '720h', label: 'Last 30 days' },
];

export default async function OverviewPage({
  searchParams,
}: {
  searchParams: Promise<{ since?: string }>;
}) {
  const { since: rawSince } = await searchParams;
  const since = RANGES.some((r) => r.value === rawSince) ? rawSince! : '24h';
  const res = await kwGet<StatsResult>(`/api/v1/stats?since=${since}`);

  return (
    <>
      <h1>Overview</h1>

      <form method="GET" className="toolbar">
        <div className="field">
          <label htmlFor="since">Time window</label>
          <select id="since" name="since" defaultValue={since}>
            {RANGES.map((r) => (
              <option key={r.value} value={r.value}>
                {r.label}
              </option>
            ))}
          </select>
        </div>
        <button type="submit">Apply</button>
      </form>

      {!res.ok || !res.data ? (
        <div className="error">{res.error ?? 'failed to load stats'}</div>
      ) : (
        <>
          <div className="grid grid-cards">
            <div className="card">
              <div className="stat-value">{res.data.total}</div>
              <div className="stat-label">Total alerts</div>
            </div>
            {(res.data.by_severity ?? []).map((c) => (
              <div className="card" key={c.key}>
                <div className="stat-value">{c.count}</div>
                <div className="stat-label">
                  <span className={`sev sev-${c.key}`}>{c.key}</span>
                </div>
              </div>
            ))}
          </div>

          <div className="grid grid-2 spacer">
            <div className="card">
              <h2>By severity</h2>
              <BarList counts={res.data.by_severity} severityColors />
            </div>
            <div className="card">
              <h2>By scope</h2>
              <BarList counts={res.data.by_scope} />
            </div>
            <div className="card">
              <h2>By rule</h2>
              <BarList counts={res.data.by_rule} />
            </div>
            <div className="card">
              <h2>Top containers</h2>
              <BarList counts={res.data.top_containers} />
            </div>
          </div>
        </>
      )}
    </>
  );
}
