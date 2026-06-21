'use client';

import Link from 'next/link';
import { usePathname } from 'next/navigation';

// NavLink highlights the active route. Exact match for "/", prefix match for the
// rest so /alerts stays active on nested routes.
export function NavLink({ href, children }: { href: string; children: React.ReactNode }) {
  const pathname = usePathname();
  const active = href === '/' ? pathname === '/' : pathname.startsWith(href);
  return (
    <Link href={href} className={`nav-link${active ? ' active' : ''}`}>
      {children}
    </Link>
  );
}
