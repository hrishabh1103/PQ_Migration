import React, { useState } from 'react';
import { AppShell } from './components/shell/AppShell';
import { DashboardPage } from './pages/DashboardPage';
import { InventoryGraphPage } from './pages/InventoryGraphPage';
import { CloudServersPage } from './pages/CloudServersPage';
import { ApiServerHubPage } from './pages/ApiServerHubPage';
import { TargetsPage } from './pages/TargetsPage';
import { ScansPage } from './pages/ScansPage';
import { AssetsPage } from './pages/AssetsPage';
import { FindingsPage } from './pages/FindingsPage';
import { ReportsPage } from './pages/ReportsPage';
import { LinuxCollectorPage } from './pages/LinuxCollectorPage';
import { AWSConnectorPage } from './pages/AWSConnectorPage';
import { KubernetesConnectorPage } from './pages/KubernetesConnectorPage';
import { AzureConnectorPage } from './pages/AzureConnectorPage';
import { PqcReadinessPage } from './pages/PqcReadinessPage';

export const App: React.FC = () => {
  const [activeTab, setActiveTab] = useState<string>('dashboard');

  return (
    <AppShell activeTab={activeTab} onNavigate={(tab) => setActiveTab(tab)}>
      {activeTab === 'dashboard' && <DashboardPage onNavigate={(tab) => setActiveTab(tab)} />}
      {activeTab === 'inventory-graph' && <InventoryGraphPage />}
      {activeTab === 'linux-collector' && <LinuxCollectorPage />}
      {activeTab === 'aws-connector' && <AWSConnectorPage />}
      {activeTab === 'kubernetes-connector' && <KubernetesConnectorPage onNavigate={(tab) => setActiveTab(tab)} />}
      {activeTab === 'azure-connector' && <AzureConnectorPage onNavigate={(tab) => setActiveTab(tab)} />}
      {activeTab === 'cloud-servers' && <CloudServersPage />}
      {activeTab === 'api-hub' && <ApiServerHubPage onNavigateScans={() => setActiveTab('scans')} />}
      {activeTab === 'targets' && <TargetsPage onNavigateScans={() => setActiveTab('scans')} />}
      {activeTab === 'scans' && <ScansPage />}
      {activeTab === 'assets' && <AssetsPage />}
      {activeTab === 'findings' && <FindingsPage />}
      {activeTab === 'pqc-readiness' && <PqcReadinessPage onNavigateGraph={() => setActiveTab('inventory-graph')} />}
      {activeTab === 'reports' && <ReportsPage />}
    </AppShell>
  );
};
