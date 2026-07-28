import React, { useState } from 'react';
import { Navbar } from './components/Navbar';
import { DashboardPage } from './pages/DashboardPage';
import { InventoryGraphPage } from './pages/InventoryGraphPage';
import { CloudServersPage } from './pages/CloudServersPage';
import { ApiServerHubPage } from './pages/ApiServerHubPage';
import { TargetsPage } from './pages/TargetsPage';
import { ScansPage } from './pages/ScansPage';
import { AssetsPage } from './pages/AssetsPage';
import { FindingsPage } from './pages/FindingsPage';
import { ReportsPage } from './pages/ReportsPage';

export const App: React.FC = () => {
  const [activeTab, setActiveTab] = useState<string>('dashboard');

  return (
    <div className="min-h-screen bg-slate-950 text-slate-100 flex flex-col font-sans">
      <Navbar activeTab={activeTab} setActiveTab={setActiveTab} />
      <main className="flex-1 max-w-7xl w-full mx-auto px-4 sm:px-6 lg:px-8 py-8">
        {activeTab === 'dashboard' && <DashboardPage onNavigate={(tab) => setActiveTab(tab)} />}
        {activeTab === 'inventory-graph' && <InventoryGraphPage />}
        {activeTab === 'cloud-servers' && <CloudServersPage />}
        {activeTab === 'api-hub' && <ApiServerHubPage onNavigateScans={() => setActiveTab('scans')} />}
        {activeTab === 'targets' && <TargetsPage onNavigateScans={() => setActiveTab('scans')} />}
        {activeTab === 'scans' && <ScansPage />}
        {activeTab === 'assets' && <AssetsPage />}
        {activeTab === 'findings' && <FindingsPage />}
        {activeTab === 'reports' && <ReportsPage />}
      </main>
      <footer className="border-t border-slate-800 bg-slate-950 py-6 text-center text-xs font-mono text-slate-500">
        Enterprise Cryptographic Discovery Platform • Post-Quantum Migration Readiness Hub
      </footer>
    </div>
  );
};
