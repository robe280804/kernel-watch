import { kwGet } from '@/lib/kw-client';
import type { StatsResult } from '@/lib/types';

// GET /api/stats?since=24h -> proxies KernelWatch GET /api/v1/stats
export async function GET(request: Request) {
  const since = new URL(request.url).searchParams.get('since') ?? '24h';
  const res = await kwGet<StatsResult>(`/api/v1/stats?since=${encodeURIComponent(since)}`);
  if (!res.ok) {
    return Response.json({ error: res.error }, { status: res.status });
  }
  return Response.json(res.data);
}
