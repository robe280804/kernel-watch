import { SuppressionsManager } from '@/components/SuppressionsManager';

export const dynamic = 'force-dynamic';

export default function SuppressionsPage() {
  return (
    <>
      <h1>Suppressions</h1>
      <SuppressionsManager />
    </>
  );
}
