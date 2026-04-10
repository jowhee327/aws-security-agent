import { NavLink, Outlet } from 'react-router-dom';
import type { DashboardData } from '../types';

const navItems = [
  { to: '/', label: 'Overview', icon: '📊' },
  { to: '/trends', label: 'Trends', icon: '📈' },
  { to: '/findings', label: 'Findings', icon: '🔍' },
];

export default function Layout({ data }: { data: DashboardData | null }) {
  const lastScan = data?.lastScan;
  const scanTime = lastScan
    ? new Date(lastScan.scanEnd).toLocaleString()
    : '—';
  const accountId = lastScan?.accountId ?? '—';

  return (
    <div className="flex min-h-screen">
      {/* Desktop Sidebar */}
      <aside className="hidden lg:flex fixed top-0 left-0 h-screen w-64 bg-slate-800 border-r border-slate-700 flex-col z-10">
        <div className="p-6 border-b border-slate-700">
          <h1 className="text-xl font-bold text-slate-50 flex items-center gap-2">
            <span>🛡️</span> AWS Security
          </h1>
        </div>

        <nav className="flex-1 p-4 space-y-1">
          {navItems.map(({ to, label, icon }) => (
            <NavLink
              key={to}
              to={to}
              end={to === '/'}
              className={({ isActive }) =>
                `flex items-center gap-3 px-4 py-3 rounded-lg text-sm font-medium transition-colors ${
                  isActive
                    ? 'bg-blue-500/20 text-blue-400 border border-blue-500/30'
                    : 'text-slate-400 hover:text-slate-200 hover:bg-slate-700/50'
                }`
              }
            >
              <span>{icon}</span>
              {label}
            </NavLink>
          ))}
        </nav>

        <div className="p-4 border-t border-slate-700 text-xs text-slate-500 space-y-1">
          <p>Last scan: {scanTime}</p>
          <p>Account: {accountId}</p>
        </div>
      </aside>

      {/* Mobile top bar */}
      <div className="lg:hidden fixed top-0 left-0 right-0 bg-slate-800 border-b border-slate-700 p-4 z-10">
        <div className="flex items-center justify-between">
          <h1 className="text-lg font-bold text-slate-50 flex items-center gap-2">
            <span>🛡️</span> AWS Security
          </h1>
          <nav className="flex gap-4">
            {navItems.map(({ to, label, icon }) => (
              <NavLink
                key={to}
                to={to}
                end={to === '/'}
                className={({ isActive }) =>
                  `text-sm font-medium transition-colors ${
                    isActive
                      ? 'text-blue-400'
                      : 'text-slate-400 hover:text-slate-200'
                  }`
                }
              >
                <span>{icon}</span> {label}
              </NavLink>
            ))}
          </nav>
        </div>
      </div>

      {/* Main content */}
      <main className="lg:ml-64 mt-16 lg:mt-0 flex-1 p-8">
        <Outlet />
      </main>
    </div>
  );
}
