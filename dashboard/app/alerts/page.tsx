import { kwGet } from '@/lib/kw-client';
import type { AlertsResponse } from '@/lib/types';
import { AlertTable } from '@/components/AlertTable';

export const dynamic = 'force-dynamic';

type Filters = {
  since?: string;
  scope?: string;
  severity?: string;
  container?: string;
  rule?: string;
  limit?: string;
};

const SEVERITIES = ['', 'low', 'medium', 'high', 'critical'];
const SCOPES = ['', 'container', 'host'];

export default async function AlertsPage({
  searchParams,
}: {
  searchParams: Promise<Filters>;
}) {
  const f = await searchParams;
  const since = f.since?.trim() || '24h';
  const limit = f.limit?.trim() || '100';

  const qs = new URLSearchParams({ since, limit });
  if (f.scope) qs.set('scope', f.scope);
  if (f.severity) qs.set('severity', f.severity);
  if (f.container) qs.set('container', f.container.trim());
  if (f.rule) qs.set('rule', f.rule.trim());

  const res = await kwGet<AlertsResponse>(`/api/v1/alerts?${qs.toString()}`);

  return (
    <>
      <h1>Alerts &amp; Incidents</h1>

      <form method="GET" className="toolbar">
        <div className="field">
          <label htmlFor="since">Since</label>
          <input id="since" name="since" defaultValue={since} placeholder="24h" />
        </div>
        <div className="field">
          <label htmlFor="scope">Scope</label>
          <select id="scope" name="scope" defaultValue={f.scope ?? ''}>
            {SCOPES.map((s) => (
              <option key={s} value={s}>
                {s || 'any'}
              </option>
            ))}
          </select>
        </div>
        <div className="field">
          <label htmlFor="severity">Severity</label>
          <select id="severity" name="severity" defaultValue={f.severity ?? ''}>
            {SEVERITIES.map((s) => (
              <option key={s} value={s}>
                {s || 'any'}
              </option>
            ))}
          </select>
        </div>
        <div className="field">
          <label htmlFor="container">Container</label>
          <input id="container" name="container" defaultValue={f.container ?? ''} />
        </div>
        <div className="field">
          <label htmlFor="rule">Rule</label>
          <input
            id="rule"
            name="rule"
            defaultValue={f.rule ?? ''}
            placeholder="e.g. network_tool"
          />
        </div>
        <div className="field">
          <label htmlFor="limit">Limit</label>
          <input id="limit" name="limit" defaultValue={limit} />
        </div>
        <button type="submit">Filter</button>
      </form>

      {!res.ok || !res.data ? (
        <div className="error">{res.error ?? 'failed to load alerts'}</div>
      ) : (
        <>
          <p className="muted">
            {res.data.count} alert{res.data.count === 1 ? '' : 's'} shown.
          </p>
          <AlertTable alerts={res.data.alerts ?? []} />
        </>
      )}
    </>
  );
}
