import React, { useState } from 'react';
import { 
  Cloud, ShieldCheck, RefreshCw, Layers, Cpu, Key, 
  Activity, CheckCircle2, Lock
} from 'lucide-react';

interface CapabilityStatus {
  dimension: string;
  capability: string;
  module: string;
  status: string;
  label: string;
}

interface InventoryCounts {
  tenants: number;
  subscriptions: number;
  resource_groups: number;
  vms: number;
  disks: number;
  storage_accounts: number;
  key_vaults: number;
  keys: number;
  certificates: number;
  app_gateways: number;
  sql_databases: number;
}

export const AzureConnectorPage: React.FC<{ onNavigate?: (tab: string) => void }> = () => {
  const [tenantStatus] = useState<string>('CONNECTED');
  const [subscriptionId] = useState<string>('00000000-0000-0000-0000-000000000000');
  const [isSyncing, setIsSyncing] = useState<boolean>(false);
  const [activeTab, setActiveTab] = useState<'overview' | 'coverage' | 'inventory'>('overview');

  const [counts] = useState<InventoryCounts>({
    tenants: 1,
    subscriptions: 2,
    resource_groups: 8,
    vms: 18,
    disks: 24,
    storage_accounts: 12,
    key_vaults: 5,
    keys: 32,
    certificates: 14,
    app_gateways: 4,
    sql_databases: 6
  });

  const [capabilities] = useState<CapabilityStatus[]>([
    { dimension: 'AZURE_IDENTITY', capability: 'CLOUD_IDENTITY', module: 'AzureIdentityModule', status: 'SCANNED', label: 'Tenant & Subscriptions' },
    { dimension: 'AZURE_RESOURCE_GROUPS', capability: 'CLOUD_RESOURCE_GROUP', module: 'AzureResourceGroupModule', status: 'SCANNED', label: 'Resource Groups' },
    { dimension: 'AZURE_REGIONS', capability: 'CLOUD_RESOURCE', module: 'AzureRegionModule', status: 'SCANNED', label: 'Spatial Regions' },
    { dimension: 'AZURE_VM', capability: 'CLOUD_COMPUTE', module: 'AzureVMModule', status: 'SCANNED', label: 'Virtual Machines' },
    { dimension: 'AZURE_MANAGED_DISKS', capability: 'CLOUD_STORAGE', module: 'AzureVMModule', status: 'SCANNED', label: 'Managed Disks' },
    { dimension: 'AZURE_STORAGE_ACCOUNTS', capability: 'CLOUD_STORAGE', module: 'AzureStorageModule', status: 'SCANNED', label: 'Storage Accounts' },
    { dimension: 'AZURE_BLOB_ENCRYPTION', capability: 'ENCRYPTION_CONFIGURATION', module: 'AzureStorageModule', status: 'SCANNED', label: 'Blob SSE Configuration' },
    { dimension: 'AZURE_KEY_VAULT', capability: 'KMS', module: 'AzureKeyVaultModule', status: 'SCANNED', label: 'Key Vault Instances' },
    { dimension: 'AZURE_KEY_VAULT_KEYS', capability: 'KMS', module: 'AzureKeyVaultModule', status: 'SCANNED', label: 'Key Vault Keys & Versions' },
    { dimension: 'AZURE_KEY_VAULT_CERTS', capability: 'CERTIFICATE', module: 'AzureKeyVaultModule', status: 'SCANNED', label: 'Key Vault Certificates' },
    { dimension: 'AZURE_APP_GATEWAY', capability: 'CLOUD_LOAD_BALANCER', module: 'AzureAppGatewayModule', status: 'SCANNED', label: 'Application Gateways' },
    { dimension: 'AZURE_APP_GATEWAY_TLS', capability: 'TLS_CONFIGURATION', module: 'AzureAppGatewayModule', status: 'SCANNED', label: 'App Gateway TLS Policies' },
    { dimension: 'AZURE_SQL_SERVERS', capability: 'CLOUD_DATABASE', module: 'AzureSqlModule', status: 'SCANNED', label: 'Azure SQL Servers' },
    { dimension: 'AZURE_SQL_TDE', capability: 'ENCRYPTION_CONFIGURATION', module: 'AzureSqlModule', status: 'SCANNED', label: 'Transparent Data Encryption (TDE)' },
    { dimension: 'AZURE_FRONT_DOOR', capability: 'CLOUD_CDN', module: 'AzureFrontDoorModule', status: 'SCANNED', label: 'Front Door & CDN Profiles' },
    { dimension: 'AZURE_NETWORK', capability: 'CLOUD_NETWORK', module: 'AzureNetworkModule', status: 'SCANNED', label: 'VNets & Public Endpoints' }
  ]);

  const handleTriggerSync = () => {
    setIsSyncing(true);
    setTimeout(() => {
      setIsSyncing(false);
    }, 2000);
  };

  return (
    <div className="p-6 space-y-6">
      {/* Header Banner */}
      <div className="flex flex-col md:flex-row justify-between items-start md:items-center bg-slate-900 border border-slate-800 rounded-xl p-6 shadow-xl">
        <div className="flex items-center space-x-4">
          <div className="p-3 bg-sky-500/10 border border-sky-500/20 rounded-lg text-sky-400">
            <Cloud className="w-8 h-8" />
          </div>
          <div>
            <div className="flex items-center space-x-3">
              <h1 className="text-2xl font-bold text-white tracking-tight">Azure Cryptographic Discovery</h1>
              <span className="px-2.5 py-0.5 rounded-full text-xs font-semibold bg-emerald-500/10 text-emerald-400 border border-emerald-500/20 flex items-center gap-1">
                <CheckCircle2 className="w-3.5 h-3.5" />
                {tenantStatus}
              </span>
            </div>
            <p className="text-sm text-slate-400 mt-1">
              Active Subscription: <span className="font-mono text-slate-300">{subscriptionId}</span>
            </p>
          </div>
        </div>

        <div className="mt-4 md:mt-0 flex items-center space-x-3">
          <button
            onClick={handleTriggerSync}
            disabled={isSyncing}
            className="flex items-center space-x-2 px-4 py-2 bg-sky-600 hover:bg-sky-500 text-white rounded-lg text-sm font-medium transition shadow-lg shadow-sky-600/20 disabled:opacity-50"
          >
            <RefreshCw className={`w-4 h-4 ${isSyncing ? 'animate-spin' : ''}`} />
            <span>{isSyncing ? 'Syncing Azure...' : 'Trigger Azure Sync'}</span>
          </button>
        </div>
      </div>

      {/* Security & Boundary Alert */}
      <div className="bg-slate-900/50 border border-sky-500/30 rounded-xl p-4 flex items-start space-x-3 text-sm">
        <Lock className="w-5 h-5 text-sky-400 flex-shrink-0 mt-0.5" />
        <div>
          <span className="font-semibold text-sky-300">Strict Read-Only & Metadata Boundary Enforced: </span>
          <span className="text-slate-300">
            Key Vault discovery inspects key metadata, key versions, and X.509 public certificates only. Secret retrieval, private key exports, and cryptographic operations are prohibited by least-privilege RBAC.
          </span>
        </div>
      </div>

      {/* Metrics Bar */}
      <div className="grid grid-cols-2 md:grid-cols-4 gap-4">
        <div className="bg-slate-900 border border-slate-800 rounded-xl p-4">
          <div className="flex items-center justify-between text-slate-400 mb-2">
            <span className="text-xs font-medium">Resource Groups</span>
            <Layers className="w-4 h-4 text-sky-400" />
          </div>
          <div className="text-2xl font-bold text-white">{counts.resource_groups}</div>
        </div>

        <div className="bg-slate-900 border border-slate-800 rounded-xl p-4">
          <div className="flex items-center justify-between text-slate-400 mb-2">
            <span className="text-xs font-medium">Virtual Machines</span>
            <Cpu className="w-4 h-4 text-purple-400" />
          </div>
          <div className="text-2xl font-bold text-white">{counts.vms}</div>
        </div>

        <div className="bg-slate-900 border border-slate-800 rounded-xl p-4">
          <div className="flex items-center justify-between text-slate-400 mb-2">
            <span className="text-xs font-medium">Key Vault Keys & Versions</span>
            <Key className="w-4 h-4 text-amber-400" />
          </div>
          <div className="text-2xl font-bold text-white">{counts.keys}</div>
        </div>

        <div className="bg-slate-900 border border-slate-800 rounded-xl p-4">
          <div className="flex items-center justify-between text-slate-400 mb-2">
            <span className="text-xs font-medium">X.509 Certificates</span>
            <ShieldCheck className="w-4 h-4 text-emerald-400" />
          </div>
          <div className="text-2xl font-bold text-white">{counts.certificates}</div>
        </div>
      </div>

      {/* Navigation Tabs */}
      <div className="flex border-b border-slate-800">
        <button
          onClick={() => setActiveTab('overview')}
          className={`px-4 py-2 text-sm font-medium border-b-2 transition ${
            activeTab === 'overview'
              ? 'border-sky-500 text-sky-400'
              : 'border-transparent text-slate-400 hover:text-slate-200'
          }`}
        >
          Overview & Security
        </button>
        <button
          onClick={() => setActiveTab('coverage')}
          className={`px-4 py-2 text-sm font-medium border-b-2 transition ${
            activeTab === 'coverage'
              ? 'border-sky-500 text-sky-400'
              : 'border-transparent text-slate-400 hover:text-slate-200'
          }`}
        >
          16-Capability Matrix ({capabilities.length})
        </button>
      </div>

      {/* Tab Content */}
      {activeTab === 'overview' && (
        <div className="grid grid-cols-1 md:grid-cols-2 gap-6">
          <div className="bg-slate-900 border border-slate-800 rounded-xl p-6 space-y-4">
            <h2 className="text-lg font-semibold text-white flex items-center gap-2">
              <Cloud className="w-5 h-5 text-sky-400" />
              Administrative Scope
            </h2>
            <div className="space-y-3 text-sm">
              <div className="flex justify-between py-2 border-b border-slate-800">
                <span className="text-slate-400">Entra ID Tenant</span>
                <span className="font-mono text-slate-200">11111111-1111-1111-1111-111111111111</span>
              </div>
              <div className="flex justify-between py-2 border-b border-slate-800">
                <span className="text-slate-400">Subscription</span>
                <span className="font-mono text-slate-200">00000000-0000-0000-0000-000000000000</span>
              </div>
              <div className="flex justify-between py-2 border-b border-slate-800">
                <span className="text-slate-400">Credential Chain</span>
                <span className="text-emerald-400 font-medium">DefaultAzureCredential (CLI / Managed Identity)</span>
              </div>
              <div className="flex justify-between py-2">
                <span className="text-slate-400">RBAC Role</span>
                <span className="text-sky-400 font-medium">Custom ReadOnly Discovery Role</span>
              </div>
            </div>
          </div>

          <div className="bg-slate-900 border border-slate-800 rounded-xl p-6 space-y-4">
            <h2 className="text-lg font-semibold text-white flex items-center gap-2">
              <Activity className="w-5 h-5 text-emerald-400" />
              Cryptographic Discovery Features
            </h2>
            <ul className="space-y-2 text-sm text-slate-300">
              <li className="flex items-center gap-2">
                <CheckCircle2 className="w-4 h-4 text-emerald-400" />
                Key Vault Key & Version Identity Tracking
              </li>
              <li className="flex items-center gap-2">
                <CheckCircle2 className="w-4 h-4 text-emerald-400" />
                Key Vault Cert Resource vs X.509 CryptoObject Fingerprint Separation
              </li>
              <li className="flex items-center gap-2">
                <CheckCircle2 className="w-4 h-4 text-emerald-400" />
                Customer-Managed Keys vs Platform-Managed Encryption Semantics
              </li>
              <li className="flex items-center gap-2">
                <CheckCircle2 className="w-4 h-4 text-emerald-400" />
                Cross-Cloud Compute & Certificate Correlation
              </li>
            </ul>
          </div>
        </div>
      )}

      {activeTab === 'coverage' && (
        <div className="bg-slate-900 border border-slate-800 rounded-xl p-6">
          <h2 className="text-lg font-semibold text-white mb-4">16-Capability Azure Discovery Matrix</h2>
          <div className="overflow-x-auto">
            <table className="w-full text-left text-sm text-slate-300">
              <thead className="bg-slate-800/50 text-slate-400 uppercase text-xs">
                <tr>
                  <th className="px-4 py-3">Dimension ID</th>
                  <th className="px-4 py-3">Frontend Label</th>
                  <th className="px-4 py-3">Azure Module</th>
                  <th className="px-4 py-3">Plugin Capability</th>
                  <th className="px-4 py-3">Status</th>
                </tr>
              </thead>
              <tbody className="divide-y divide-slate-800">
                {capabilities.map((cap, idx) => (
                  <tr key={idx} className="hover:bg-slate-800/30">
                    <td className="px-4 py-3 font-mono text-xs text-sky-400">{cap.dimension}</td>
                    <td className="px-4 py-3 font-medium text-white">{cap.label}</td>
                    <td className="px-4 py-3 text-slate-400">{cap.module}</td>
                    <td className="px-4 py-3 font-mono text-xs text-slate-400">{cap.capability}</td>
                    <td className="px-4 py-3">
                      <span className="px-2 py-0.5 rounded text-xs font-semibold bg-emerald-500/10 text-emerald-400 border border-emerald-500/20">
                        {cap.status}
                      </span>
                    </td>
                  </tr>
                ))}
              </tbody>
            </table>
          </div>
        </div>
      )}
    </div>
  );
};
export default AzureConnectorPage;
