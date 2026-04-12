import { HashRouter, Routes, Route } from 'react-router-dom';
import { useData } from './hooks/useData';
import { I18nProvider } from './i18n';
import Layout from './components/Layout';
import Overview from './pages/Overview';
import Trends from './pages/Trends';
import Findings from './pages/Findings';

export default function App() {
  const { data, loading, error } = useData();

  if (loading) {
    return (
      <div className="flex items-center justify-center min-h-screen bg-slate-900">
        <div className="text-slate-400 text-lg">Loading dashboard...</div>
      </div>
    );
  }

  if (error) {
    return (
      <div className="flex items-center justify-center min-h-screen bg-slate-900">
        <div className="text-red-400 text-lg">Error: {error}</div>
      </div>
    );
  }

  return (
    <I18nProvider>
      <HashRouter>
        <Routes>
          <Route element={<Layout data={data} />}>
            <Route path="/" element={<Overview data={data!} />} />
            <Route path="/trends" element={<Trends data={data!} />} />
            <Route path="/findings" element={<Findings data={data!} />} />
          </Route>
        </Routes>
      </HashRouter>
    </I18nProvider>
  );
}
