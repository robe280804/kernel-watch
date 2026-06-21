'use client';

import { useCallback, useEffect, useState } from 'react';
import type { NewSuppression, SuppressionRule, SuppressionsResponse } from '@/lib/types';

const EMPTY: NewSuppression = {
  rule_id: '',
  scope: '',
  container_name: '',
  process_name: '',
  substr: '',
  reason: '',
};

function fmtTime(ts?: string): string {
  if (!ts) return '—';
  const d = new Date(ts);
  return Number.isNaN(d.getTime()) ? ts : d.toISOString().slice(0, 19) + 'Z';
}

export function SuppressionsManager() {
  const [rules, setRules] = useState<SuppressionRule[]>([]);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState<string | null>(null);
  const [form, setForm] = useState<NewSuppression>(EMPTY);
  const [submitting, setSubmitting] = useState(false);

  const load = useCallback(async () => {
    setLoading(true);
    setError(null);
    try {
      const res = await fetch('/api/suppressions', { cache: 'no-store' });
      const body = (await res.json()) as SuppressionsResponse & { error?: string };
      if (!res.ok) throw new Error(body.error ?? `failed (status ${res.status})`);
      setRules(body.suppressions ?? []);
    } catch (e) {
      setError(e instanceof Error ? e.message : 'failed to load suppressions');
    } finally {
      setLoading(false);
    }
  }, []);

  useEffect(() => {
    void load();
  }, [load]);

  const setField = (k: keyof NewSuppression, v: string) =>
    setForm((prev) => ({ ...prev, [k]: v }));

  const submit = async (e: React.FormEvent) => {
    e.preventDefault();
    setSubmitting(true);
    setError(null);
    // Drop empty strings so the server sees only the fields the operator set.
    const payload: NewSuppression = {};
    (Object.keys(form) as (keyof NewSuppression)[]).forEach((k) => {
      const v = form[k]?.trim();
      if (v) payload[k] = v;
    });
    try {
      const res = await fetch('/api/suppressions', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify(payload),
      });
      const body = (await res.json()) as { error?: string };
      if (!res.ok) throw new Error(body.error ?? `failed (status ${res.status})`);
      setForm(EMPTY);
      await load();
    } catch (e) {
      setError(e instanceof Error ? e.message : 'failed to add suppression');
    } finally {
      setSubmitting(false);
    }
  };

  const remove = async (id?: string) => {
    if (!id) return;
    setError(null);
    try {
      const res = await fetch(`/api/suppressions/${encodeURIComponent(id)}`, {
        method: 'DELETE',
      });
      if (!res.ok && res.status !== 204) {
        const body = (await res.json().catch(() => ({}))) as { error?: string };
        throw new Error(body.error ?? `failed (status ${res.status})`);
      }
      await load();
    } catch (e) {
      setError(e instanceof Error ? e.message : 'failed to delete suppression');
    }
  };

  return (
    <>
      {error ? <div className="error">{error}</div> : null}

      <div className="card">
        <h2>Add suppression</h2>
        <p className="muted" style={{ marginTop: 0 }}>
          Set at least one of <span className="mono">rule_id</span>,{' '}
          <span className="mono">container_name</span>,{' '}
          <span className="mono">process_name</span>, or <span className="mono">substr</span>.
          Fields are ANDed; scope/hostname only narrow. The daemon hot-reloads on save.
        </p>
        <form onSubmit={submit} className="form-grid">
          <div>
            <label htmlFor="rule_id">Rule ID</label>
            <input
              id="rule_id"
              value={form.rule_id}
              onChange={(e) => setField('rule_id', e.target.value)}
              placeholder="network_tool"
            />
          </div>
          <div>
            <label htmlFor="s_scope">Scope</label>
            <select
              id="s_scope"
              value={form.scope}
              onChange={(e) => setField('scope', e.target.value)}
            >
              <option value="">any</option>
              <option value="container">container</option>
              <option value="host">host</option>
            </select>
          </div>
          <div>
            <label htmlFor="container_name">Container name</label>
            <input
              id="container_name"
              value={form.container_name}
              onChange={(e) => setField('container_name', e.target.value)}
              placeholder="smart_move_nginx"
            />
          </div>
          <div>
            <label htmlFor="process_name">Process name</label>
            <input
              id="process_name"
              value={form.process_name}
              onChange={(e) => setField('process_name', e.target.value)}
              placeholder="curl"
            />
          </div>
          <div>
            <label htmlFor="substr">Substring (name/image/cmdline/ancestry)</label>
            <input
              id="substr"
              value={form.substr}
              onChange={(e) => setField('substr', e.target.value)}
              placeholder="healthcheck"
            />
          </div>
          <div>
            <label htmlFor="reason">Reason (note)</label>
            <input
              id="reason"
              value={form.reason}
              onChange={(e) => setField('reason', e.target.value)}
              placeholder="why this is a false positive"
            />
          </div>
          <div>
            <button type="submit" disabled={submitting}>
              {submitting ? 'Adding…' : 'Add suppression'}
            </button>
          </div>
        </form>
      </div>

      <div className="spacer">
        <h2>Active suppressions{loading ? ' (loading…)' : ` (${rules.length})`}</h2>
        {rules.length === 0 && !loading ? (
          <p className="muted">No suppressions configured.</p>
        ) : (
          <div className="table-wrap">
            <table>
              <thead>
                <tr>
                  <th>Rule</th>
                  <th>Scope</th>
                  <th>Container</th>
                  <th>Process</th>
                  <th>Substr</th>
                  <th>Reason</th>
                  <th>Created</th>
                  <th></th>
                </tr>
              </thead>
              <tbody>
                {rules.map((r) => (
                  <tr key={r.id}>
                    <td className="mono">{r.rule_id || 'any'}</td>
                    <td>{r.scope || 'any'}</td>
                    <td>{r.container_name || '—'}</td>
                    <td className="mono">{r.process_name || '—'}</td>
                    <td className="mono">{r.substr || '—'}</td>
                    <td>{r.reason || '—'}</td>
                    <td className="mono muted">{fmtTime(r.created_at)}</td>
                    <td className="row-actions">
                      <button className="danger" onClick={() => remove(r.id)}>
                        Delete
                      </button>
                    </td>
                  </tr>
                ))}
              </tbody>
            </table>
          </div>
        )}
      </div>
    </>
  );
}
