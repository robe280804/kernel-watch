import { kwGet } from '@/lib/kw-client';
import type { AlertsResponse } from '@/lib/types';

// Only forward the params the KernelWatch /api/v1/alerts endpoint understands,
// so the browser cannot smuggle arbitrary query string through the proxy.
const ALLOWED = ['since', 'scope', 'severity', 'container', 'rule', 'limit'] as const;

// GET /api/alerts?... -> proxies KernelWatch GET /api/v1/alerts
export async function GET(request: Request) {
  const incoming = new URL(request.url).searchParams;
  const out = new URLSearchParams();
  for (const key of ALLOWED) {
    const v = incoming.get(key);
    if (v) out.set(key, v);
  }
  const qs = out.toString();
  const res = await kwGet<AlertsResponse>(`/api/v1/alerts${qs ? `?${qs}` : ''}`);
  if (!res.ok) {
    return Response.json({ error: res.error }, { status: res.status });
  }
  return Response.json(res.data);
}
