import { NavLink, Outlet } from 'react-router-dom';
import { useI18n } from '../i18n';
import type { DashboardData } from '../types';

export default function Layout({ data }: { data: DashboardData | null }) {
  const { lang, setLang, t } = useI18n();
  const lastScan = data?.lastScan;
  const scanTime = lastScan
    ? new Date(lastScan.scanEnd).toLocaleString()
    : '—';
  const accountId = lastScan?.accountId ?? '—';

  const navItems = [
    { to: '/', label: t('nav.overview'), icon: '📊' },
    { to: '/trends', label: t('nav.trends'), icon: '📈' },
    { to: '/findings', label: t('nav.findings'), icon: '🔍' },
  ];

  return (
    <div className="flex min-h-screen">
      {/* Desktop Sidebar */}
      <aside className="hidden lg:flex fixed top-0 left-0 h-screen w-56 bg-slate-800 border-r border-slate-700 flex-col z-10">
        <div className="p-5 border-b border-slate-700">
          <div className="flex items-center gap-2.5">
            <span className="text-2xl leading-none">🛡️</span>
            <h1 className="text-lg font-bold text-slate-50 flex-1">{t('nav.title')}</h1>
            <button
              onClick={() => setLang(lang === 'en' ? 'zh' : 'en')}
              className="text-xs px-2 py-1 rounded border border-slate-600 text-slate-400 hover:text-slate-200 hover:border-slate-400 transition-colors shrink-0"
            >
              {lang === 'en' ? '中文' : 'EN'}
            </button>
          </div>
        </div>

        <nav className="flex-1 px-3 py-4 space-y-1">
          {navItems.map(({ to, label, icon }) => (
            <NavLink
              key={to}
              to={to}
              end={to === '/'}
              className={({ isActive }) =>
                `flex items-center gap-3 px-4 py-2.5 rounded-lg text-sm font-medium transition-colors ${
                  isActive
                    ? 'bg-blue-500/20 text-blue-400 border border-blue-500/30'
                    : 'text-slate-400 hover:text-slate-200 hover:bg-slate-700/50 border border-transparent'
                }`
              }
            >
              <span className="w-5 text-center">{icon}</span>
              {label}
            </NavLink>
          ))}
        </nav>

        <div className="p-4 border-t border-slate-700 text-xs text-slate-500 space-y-1">
          <p>{t('nav.lastScan')}: {scanTime}</p>
          <p>{t('nav.account')}: {accountId}</p>
        </div>
      </aside>

      {/* Mobile top bar */}
      <div className="lg:hidden fixed top-0 left-0 right-0 bg-slate-800 border-b border-slate-700 p-4 z-10">
        <div className="flex items-center justify-between">
          <h1 className="text-lg font-bold text-slate-50 flex items-center gap-2">
            <span>🛡️</span> {t('nav.title')}
          </h1>
          <div className="flex items-center gap-4">
            <button
              onClick={() => setLang(lang === 'en' ? 'zh' : 'en')}
              className="text-xs px-2 py-1 rounded border border-slate-600 text-slate-400 hover:text-slate-200 hover:border-slate-400 transition-colors"
            >
              {lang === 'en' ? '中文' : 'EN'}
            </button>
            <nav className="flex gap-4">
              {navItems.map(({ to, label, icon }) => (
                <NavLink
                  key={to}
                  to={to}
                  end={to === '/'}
                  className={({ isActive }) =>
                    `flex items-center gap-1.5 text-sm font-medium transition-colors ${
                      isActive
                        ? 'text-blue-400'
                        : 'text-slate-400 hover:text-slate-200'
                    }`
                  }
                >
                  <span>{icon}</span>
                  {label}
                </NavLink>
              ))}
            </nav>
          </div>
        </div>
      </div>

      {/* Main content */}
      <main className="lg:ml-56 mt-16 lg:mt-0 flex-1 p-8">
        <Outlet />
      </main>
    </div>
  );
}
