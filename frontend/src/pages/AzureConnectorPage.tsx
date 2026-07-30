import React, { useState, useEffect } from 'react';
import { 
  Cloud, ShieldCheck, RefreshCw, Layers, Cpu, Key, 
  Activity, CheckCircle2, Lock, AlertTriangle, XCircle
} from 'lucide-react';
import { PageHeader } from '../components/common/PageHeader';

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
  const [tenantStatus, setTenantStatus] = useState<string>('NOT_CONNECTED');
  const [subscriptionId, setSubscriptionId] = useState<string>('NONE');
  const [statusMessage, setStatusMessage] = useState<string | null>(null);
  const [isSyncing, setIsSyncing] = useState<boolean>(false);
  const [selectedTargetId, setSelectedTargetId] = useState<string>('');

  const [counts, setCounts] = useState<InventoryCounts>({
    tenants: 0,
    subscriptions: 0,
    resource_groups: 0,
    vms: 0,
    disks: 0,
    storage_accounts: 0,
    key_vaults: 0,
    keys: 0,
    certificates: 0,
    app_gateways: 0,
    sql_databases: 0
  });

  const [capabilities, setCapabilities] = useState<CapabilityStatus[]>([
    { dimension: 'AZURE_IDENTITY', capability: 'CLOUD_IDENTITY', module: 'AzureIdentityModule', status: 'NOT_SCANNED', label: 'Tenant & Subscriptions' },
    { dimension: 'AZURE_RESOURCE_GROUPS', capability: 'CLOUD_RESOURCE_GROUP', module: 'AzureResourceGroupModule', status: 'NOT_SCANNED', label: 'Resource Groups' },
    { dimension: 'AZURE_REGIONS', capability: 'CLOUD_RESOURCE', module: 'AzureRegionModule', status: 'NOT_SCANNED', label: 'Spatial Regions' },
    { dimension: 'AZURE_VM', capability: 'CLOUD_COMPUTE', module: 'AzureVMModule', status: 'NOT_SCANNED', label: 'Virtual Machines' },
    { dimension: 'AZURE_MANAGED_DISKS', capability: 'CLOUD_STORAGE', module: 'AzureVMModule', status: 'NOT_SCANNED', label: 'Managed Disks' },
    { dimension: 'AZURE_STORAGE_ACCOUNTS', capability: 'CLOUD_STORAGE', module: 'AzureStorageModule', status: 'NOT_SCANNED', label: 'Storage Accounts' },
    { dimension: 'AZURE_BLOB_ENCRYPTION', capability: 'ENCRYPTION_CONFIGURATION', module: 'AzureStorageModule', status: 'NOT_SCANNED', label: 'Blob SSE Configuration' },
    { dimension: 'AZURE_KEY_VAULT', capability: 'KMS', module: 'AzureKeyVaultModule', status: 'NOT_SCANNED', label: 'Key Vault Instances' },
    { dimension: 'AZURE_KEY_VAULT_KEYS', capability: 'KMS', module: 'AzureKeyVaultModule', status: 'NOT_SCANNED', label: 'Key Vault Keys & Versions' },
    { dimension: 'AZURE_KEY_VAULT_CERTS', capability: 'CERTIFICATE', module: 'AzureKeyVaultModule', status: 'NOT_SCANNED', label: 'Key Vault Certificates' },
    { dimension: 'AZURE_APP_GATEWAY', capability: 'CLOUD_LOAD_BALANCER', module: 'AzureAppGatewayModule', status: 'NOT_SCANNED', label: 'Application Gateways' },
    { dimension: 'AZURE_APP_GATEWAY_TLS', capability: 'TLS_CONFIGURATION', module: 'AzureAppGatewayModule', status: 'NOT_SCANNED', label: 'App Gateway TLS Policies' },
    { dimension: 'AZURE_SQL_SERVERS', capability: 'CLOUD_DATABASE', module: 'AzureSqlModule', status: 'NOT_SCANNED', label: 'Azure SQL Servers' },
    { dimension: 'AZURE_SQL_TDE', capability: 'ENCRYPTION_CONFIGURATION', module: 'AzureSqlModule', status: 'NOT_SCANNED', label: 'Transparent Data Encryption (TDE)' },
    { dimension: 'AZURE_FRONT_DOOR', capability: 'CLOUD_CDN', module: 'AzureFrontDoorModule', status: 'NOT_SCANNED', label: 'Front Door & CDN Profiles' },
    { dimension: 'AZURE_NETWORK', capability: 'CLOUD_NETWORK', module: 'AzureNetworkModule', status: 'NOT_SCANNED', label: 'VNets & Public Endpoints' }
  ]);

  useEffect(() => {
    checkAzureCredentials();
  }, []);

  const checkAzureCredentials = async () => {
    setStatusMessage('Checking Azure SDK credentials & Environment configuration...');
    try {
      const res = await fetch('/api/v1/targets');
      if (res.ok) {
        const list = await res.json();
        const azureTargets = list.filter((t: any) => t.target_type === 'AZURE_SUBSCRIPTION' || t.target_type === 'AZURE_TENANT');
        if (azureTargets.length > 0) {
          setSelectedTargetId(azureTargets[0].id);
          setSubscriptionId(azureTargets[0].target_value);
          setTenantStatus('CONNECTED');
          setStatusMessage(`Azure Target registered: ${azureTargets[0].target_value}`);
          return;
        }
      }
      setTenantStatus('AUTHENTICATION_REQUIRED');
      setSubscriptionId('NONE');
      setStatusMessage('No active Azure credentials/subscription target found. Status: AUTHENTICATION_REQUIRED.');
    } catch (e) {
      setTenantStatus('AUTHENTICATION_REQUIRED');
      setSubscriptionId('NONE');
      setStatusMessage(`Azure credential validation error: ${e}`);
    }
  };

  const handleTriggerSync = async () => {
    if (!selectedTargetId) {
      setStatusMessage('Authentication required: Register an AZURE_SUBSCRIPTION target with valid Azure SDK credentials.');
      return;
    }
    setIsSyncing(true);
    setStatusMessage('Initiating Azure multi-module discovery sync...');
    try {
      const res = await fetch('/api/v1/connectors/azure/sync', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ target_id: selectedTargetId })
      });
      if (res.ok) {
        setStatusMessage('Azure sync completed successfully.');
      } else {
        const err = await res.json();
        setStatusMessage(`Azure sync error: ${err.detail || 'Sync failed'}`);
      }
    } catch (e) {
      setStatusMessage(`Sync exception: ${e}`);
    } finally {
      setIsSyncing(false);
    }
  };

  const getStatusBadge = (status: string) => {
    switch (status) {
      case 'SCANNED':
        return <span className="px-2.5 py-1 text-xs font-semibold rounded-md bg-emerald-500/10 text-emerald-400 border border-emerald-500/20 flex items-center gap-1"><CheckCircle2 className="w-3.5 h-3.5" /> SCANNED</span>;
      case 'PARTIALLY_SCANNED':
        return <span className="px-2.5 py-1 text-xs font-semibold rounded-md bg-amber-500/10 text-amber-400 border border-amber-500/20 flex items-center gap-1"><AlertTriangle className="w-3.5 h-3.5" /> PARTIAL</span>;
      case 'FAILED':
        return <span className="px-2.5 py-1 text-xs font-semibold rounded-md bg-rose-500/10 text-rose-400 border border-rose-500/20 flex items-center gap-1"><XCircle className="w-3.5 h-3.5" /> FAILED</span>;
      default:
        return <span className="px-2.5 py-1 text-xs font-semibold rounded-md bg-slate-500/10 text-slate-400 border border-slate-500/20">NOT SCANNED</span>;
    }
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
              <span className={`px-2.5 py-0.5 rounded-full text-xs font-semibold border ${tenantStatus === 'CONNECTED' ? 'bg-emerald-500/10 text-emerald-400 border-emerald-500/20' : 'bg-rose-500/10 text-rose-400 border-rose-500/20'}`}>
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
            disabled={isSyncing || tenantStatus !== 'CONNECTED'}
            className="px-4 py-2 bg-sky-600 hover:bg-sky-500 text-white font-medium rounded-xl text-sm transition-colors flex items-center space-x-2 shadow-lg shadow-sky-950/40 disabled:opacity-50"
          >
            <RefreshCw className={`w-4 h-4 ${isSyncing ? 'animate-spin' : ''}`} />
            <span>{isSyncing ? 'Syncing...' : 'Trigger Azure Sync'}</span>
          </button>
        </div>
      </div>

      {statusMessage && (
        <div className="p-3 bg-slate-950 border border-slate-800 rounded-xl font-mono text-xs text-sky-400">
          {statusMessage}
        </div>
      )}

      {/* Resource Inventory Breakdown */}
      <div className="grid grid-cols-2 md:grid-cols-4 lg:grid-cols-6 gap-4">
        <div className="bg-slate-900 border border-slate-800 p-4 rounded-xl">
          <div className="text-[10px] font-mono text-slate-400 uppercase">Resource Groups</div>
          <div className="text-2xl font-bold text-slate-100 mt-1 font-mono">{counts.resource_groups}</div>
        </div>
        <div className="bg-slate-900 border border-slate-800 p-4 rounded-xl">
          <div className="text-[10px] font-mono text-slate-400 uppercase">Virtual Machines</div>
          <div className="text-2xl font-bold text-slate-100 mt-1 font-mono">{counts.vms}</div>
        </div>
        <div className="bg-slate-900 border border-slate-800 p-4 rounded-xl">
          <div className="text-[10px] font-mono text-slate-400 uppercase">Key Vault Keys</div>
          <div className="text-2xl font-bold text-sky-400 mt-1 font-mono">{counts.keys}</div>
        </div>
        <div className="bg-slate-900 border border-slate-800 p-4 rounded-xl">
          <div className="text-[10px] font-mono text-slate-400 uppercase">Certificates</div>
          <div className="text-2xl font-bold text-emerald-400 mt-1 font-mono">{counts.certificates}</div>
        </div>
        <div className="bg-slate-900 border border-slate-800 p-4 rounded-xl">
          <div className="text-[10px] font-mono text-slate-400 uppercase">App Gateways</div>
          <div className="text-2xl font-bold text-slate-100 mt-1 font-mono">{counts.app_gateways}</div>
        </div>
        <div className="bg-slate-900 border border-slate-800 p-4 rounded-xl">
          <div className="text-[10px] font-mono text-slate-400 uppercase">SQL Databases</div>
          <div className="text-2xl font-bold text-indigo-400 mt-1 font-mono">{counts.sql_databases}</div>
        </div>
      </div>

      {/* Capability Grid */}
      <div className="bg-slate-900 border border-slate-800 rounded-xl p-6">
        <h3 className="text-base font-bold text-slate-100 mb-4 flex items-center">
          <ShieldCheck className="w-4.5 h-4.5 mr-2 text-sky-400" /> Azure 16-Dimension Capability Coverage
        </h3>
        <div className="grid grid-cols-1 md:grid-cols-2 lg:grid-cols-4 gap-4">
          {capabilities.map((item) => (
            <div key={item.dimension} className="bg-slate-950 border border-slate-800 rounded-lg p-3.5 flex flex-col justify-between">
              <div className="flex items-center justify-between mb-2">
                <span className="text-[10px] font-mono text-slate-400 uppercase">{item.dimension}</span>
                {getStatusBadge(item.status)}
              </div>
              <h4 className="text-xs font-semibold text-slate-200">{item.label}</h4>
              <p className="text-[10px] font-mono text-slate-500 mt-1">{item.module}</p>
            </div>
          ))}
        </div>
      </div>
    </div>
  );
};
