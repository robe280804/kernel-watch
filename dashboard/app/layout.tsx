import './globals.css';
import type { Metadata } from 'next';
import { NavLink } from '@/components/NavLink';

export const metadata: Metadata = {
  title: 'KernelWatch Dashboard',
  description: 'Alerts, incidents, and suppressions for KernelWatch',
};

export default function RootLayout({ children }: { children: React.ReactNode }) {
  return (
    <html lang="en">
      <body>
        <nav className="nav">
          <span className="nav-brand">🛡 KernelWatch</span>
          <NavLink href="/">Overview</NavLink>
          <NavLink href="/alerts">Alerts</NavLink>
          <NavLink href="/suppressions">Suppressions</NavLink>
        </nav>
        <main className="container">{children}</main>
      </body>
    </html>
  );
}
