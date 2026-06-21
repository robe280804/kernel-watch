import { kwDelete } from '@/lib/kw-client';

// DELETE /api/suppressions/{id} -> remove a suppression rule.
export async function DELETE(
  _request: Request,
  { params }: { params: Promise<{ id: string }> },
) {
  const { id } = await params;
  const res = await kwDelete<null>(`/api/v1/suppressions/${encodeURIComponent(id)}`);
  if (!res.ok) {
    return Response.json({ error: res.error }, { status: res.status });
  }
  return new Response(null, { status: 204 });
}
