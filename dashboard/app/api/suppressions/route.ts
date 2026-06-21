import { kwGet, kwPost } from '@/lib/kw-client';
import type { NewSuppression, SuppressionRule, SuppressionsResponse } from '@/lib/types';

// GET /api/suppressions -> list active suppression rules
export async function GET() {
  const res = await kwGet<SuppressionsResponse>('/api/v1/suppressions');
  if (!res.ok) {
    return Response.json({ error: res.error }, { status: res.status });
  }
  return Response.json(res.data);
}

// POST /api/suppressions -> add a suppression rule. The daemon hot-reloads the
// detector on success (no restart needed). Server-side validation is the source
// of truth; we only do a cheap "at least one primary field" pre-check to give a
// friendlier error before the round trip.
export async function POST(request: Request) {
  let body: NewSuppression;
  try {
    body = (await request.json()) as NewSuppression;
  } catch {
    return Response.json({ error: 'invalid JSON body' }, { status: 400 });
  }

  const hasPrimary =
    [body.rule_id, body.container_name, body.process_name, body.substr]
      .some((v) => typeof v === 'string' && v.trim() !== '');
  if (!hasPrimary) {
    return Response.json(
      {
        error:
          'set at least one of rule_id, container_name, process_name, substr (scope/hostname only narrow a rule)',
      },
      { status: 400 },
    );
  }

  const res = await kwPost<SuppressionRule>('/api/v1/suppressions', body);
  if (!res.ok) {
    return Response.json({ error: res.error }, { status: res.status });
  }
  return Response.json(res.data, { status: 201 });
}
