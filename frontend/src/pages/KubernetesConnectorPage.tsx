import React, { useState } from 'react';
import { 
  Server, ShieldCheck, RefreshCw, Layers, Cpu, Box, 
  Activity, CheckCircle2, AlertTriangle, Key, Search, ExternalLink
} from 'lucide-react';

interface CapabilityStatus {
  capability: string;
  status: string;
}

interface InventoryCounts {
  workloads: number;
  pods: number;
  services: number;
  ingresses: number;
  certificates: number;
  secret_metadata: number;
}

export const KubernetesConnectorPage: React.FC<{ onNavigate?: (tab: string) => void }> = ({ onNavigate }) => {
  const [clusterStatus] = useState<string>('CONNECTED');
  const [gitVersion] = useState<string>('v1.30.2');
  const [isSyncing, setIsSyncing] = useState<boolean>(false);
  const [activeTab, setActiveTab] = useState<'overview' | 'coverage' | 'inventory'>('overview');
  const [searchTerm, setSearchTerm] = useState<string>('');

  const [counts] = useState<InventoryCounts>({
    workloads: 14,
    pods: 42,
    services: 18,
    ingresses: 8,
    certificates: 6,
    secret_metadata: 24
  });

  const [capabilities] = useState<CapabilityStatus[]>([
    { capability: 'cluster_identity', status: 'SCANNED' },
    { capability: 'nodes', status: 'SCANNED' },
    { capability: 'namespaces', status: 'SCANNED' },
    { capability: 'workloads', status: 'SCANNED' },
    { capability: 'pods', status: 'SCANNED' },
    { capability: 'services', status: 'SCANNED' },
    { capability: 'ingress', status: 'SCANNED' },
    { capability: 'gateway_api', status: 'NOT_APPLICABLE' },
    { capability: 'certificates', status: 'SCANNED' },
    { capability: 'secret_metadata', status: 'SCANNED' },
    { capability: 'configmaps', status: 'SCANNED' },
    { capability: 'rbac', status: 'SCANNED' },
    { capability: 'cert_manager', status: 'SCANNED' },
    { capability: 'service_mesh', status: 'SCANNED' },
    { capability: 'encryption_at_rest', status: 'UNKNOWN' }
  ]);

  const handleTriggerSync = () => {
    setIsSyncing(true);
    setTimeout(() => {
      setIsSyncing(false);
    }, 2000);
  };

  const getStatusBadge = (status: string) => {
    switch (status) {
      case 'SCANNED':
        return <span className="px-2.5 py-1 text-xs font-semibold rounded-md bg-emerald-500/10 text-emerald-400 border border-emerald-500/20 flex items-center gap-1"><CheckCircle2 className="w-3.5 h-3.5" /> SCANNED</span>;
      case 'PARTIALLY_SCANNED':
        return <span className="px-2.5 py-1 text-xs font-semibold rounded-md bg-amber-500/10 text-amber-400 border border-amber-500/20 flex items-center gap-1"><AlertTriangle className="w-3.5 h-3.5" /> PARTIAL</span>;
      case 'FAILED':
        return <span className="px-2.5 py-1 text-xs font-semibold rounded-md bg-rose-500/10 text-rose-400 border border-rose-500/20 flex items-center gap-1"><AlertTriangle className="w-3.5 h-3.5" /> FAILED</span>;
      case 'NOT_APPLICABLE':
        return <span className="px-2.5 py-1 text-xs font-semibold rounded-md bg-slate-500/10 text-slate-400 border border-slate-500/20">N/A</span>;
      default:
        return <span className="px-2.5 py-1 text-xs font-semibold rounded-md bg-cyan-500/10 text-cyan-400 border border-cyan-500/20">UNKNOWN</span>;
    }
  };

  return (
    <div className="p-8 space-y-8 max-w-7xl mx-auto">
      {/* 1. Header & Actions */}
      <div className="flex flex-col md:flex-row md:items-center md:justify-between gap-4 bg-slate-900/60 border border-slate-800 p-6 rounded-2xl backdrop-blur-md">
        <div className="flex items-center space-x-4">
          <div className="p-3 bg-cyan-500/10 border border-cyan-500/30 rounded-xl text-cyan-400">
            <Server className="w-8 h-8" />
          </div>
          <div>
            <div className="flex items-center space-x-3">
              <h1 className="text-2xl font-bold text-slate-100">Kubernetes Connector</h1>
              <span className="px-2.5 py-0.5 text-xs font-mono font-semibold rounded-full bg-cyan-500/20 text-cyan-300 border border-cyan-500/30">
                v1.0.0 (Read-Only)
              </span>
            </div>
            <p className="text-sm text-slate-400 mt-1">
              Enterprise Kubernetes Cryptographic Discovery & Zero-Secret Inventory Sync
            </p>
          </div>
        </div>

        <div className="flex items-center space-x-3">
          <button
            onClick={handleTriggerSync}
            disabled={isSyncing}
            className="px-5 py-2.5 bg-gradient-to-r from-cyan-500 to-blue-600 hover:from-cyan-400 hover:to-blue-500 text-white font-medium text-sm rounded-xl shadow-lg shadow-cyan-500/20 flex items-center space-x-2 transition-all disabled:opacity-50"
          >
            <RefreshCw className={`w-4 h-4 ${isSyncing ? 'animate-spin' : ''}`} />
            <span>{isSyncing ? 'Syncing Cluster...' : 'Trigger Discovery Sync'}</span>
          </button>
        </div>
      </div>

      {/* 2. Cluster Identity & Status Banner */}
      <div className="grid grid-cols-1 md:grid-cols-4 gap-4">
        <div className="bg-slate-900/40 border border-slate-800 p-5 rounded-xl flex items-center space-x-4">
          <div className="p-3 bg-emerald-500/10 text-emerald-400 rounded-lg">
            <ShieldCheck className="w-6 h-6" />
          </div>
          <div>
            <div className="text-xs text-slate-400 font-mono uppercase">API Status</div>
            <div className="text-lg font-bold text-slate-200 mt-0.5">{clusterStatus}</div>
          </div>
        </div>

        <div className="bg-slate-900/40 border border-slate-800 p-5 rounded-xl flex items-center space-x-4">
          <div className="p-3 bg-blue-500/10 text-blue-400 rounded-lg">
            <Cpu className="w-6 h-6" />
          </div>
          <div>
            <div className="text-xs text-slate-400 font-mono uppercase">K8s Version</div>
            <div className="text-lg font-bold text-slate-200 mt-0.5">{gitVersion}</div>
          </div>
        </div>

        <div className="bg-slate-900/40 border border-slate-800 p-5 rounded-xl flex items-center space-x-4">
          <div className="p-3 bg-indigo-500/10 text-indigo-400 rounded-lg">
            <Layers className="w-6 h-6" />
          </div>
          <div>
            <div className="text-xs text-slate-400 font-mono uppercase">Discovered Workloads</div>
            <div className="text-lg font-bold text-slate-200 mt-0.5">{counts.workloads} Deployments</div>
          </div>
        </div>

        <div className="bg-slate-900/40 border border-slate-800 p-5 rounded-xl flex items-center space-x-4">
          <div className="p-3 bg-amber-500/10 text-amber-400 rounded-lg">
            <Key className="w-6 h-6" />
          </div>
          <div>
            <div className="text-xs text-slate-400 font-mono uppercase">Secret Metadata</div>
            <div className="text-lg font-bold text-slate-200 mt-0.5">{counts.secret_metadata} Objects</div>
          </div>
        </div>
      </div>

      {/* 3. Navigation Tabs */}
      <div className="flex border-b border-slate-800 space-x-6">
        <button
          onClick={() => setActiveTab('overview')}
          className={`pb-3 text-sm font-medium transition-colors border-b-2 ${
            activeTab === 'overview'
              ? 'border-cyan-400 text-cyan-400'
              : 'border-transparent text-slate-400 hover:text-slate-200'
          }`}
        >
          Overview & Metrics
        </button>
        <button
          onClick={() => setActiveTab('coverage')}
          className={`pb-3 text-sm font-medium transition-colors border-b-2 ${
            activeTab === 'coverage'
              ? 'border-cyan-400 text-cyan-400'
              : 'border-transparent text-slate-400 hover:text-slate-200'
          }`}
        >
          15-Capability Coverage Matrix
        </button>
      </div>

      {/* 4. Tab Contents */}
      {activeTab === 'overview' && (
        <div className="space-y-6">
          <div className="grid grid-cols-1 md:grid-cols-3 gap-6">
            <div className="bg-slate-900/40 border border-slate-800 p-6 rounded-xl space-y-3">
              <div className="text-sm font-bold text-slate-300 flex items-center space-x-2">
                <Box className="w-4 h-4 text-cyan-400" />
                <span>Pods & Containers</span>
              </div>
              <div className="text-3xl font-extrabold text-white">{counts.pods}</div>
              <p className="text-xs text-slate-400">Canonical identity derived via metadata.uid + Cluster ID</p>
            </div>

            <div className="bg-slate-900/40 border border-slate-800 p-6 rounded-xl space-y-3">
              <div className="text-sm font-bold text-slate-300 flex items-center space-x-2">
                <Activity className="w-4 h-4 text-emerald-400" />
                <span>Services & Ingresses</span>
              </div>
              <div className="text-3xl font-extrabold text-white">{counts.services + counts.ingresses}</div>
              <p className="text-xs text-slate-400">Mapped via SERVICE EXPOSES WORKLOAD and INGRESS EXPOSES SERVICE</p>
            </div>

            <div className="bg-slate-900/40 border border-slate-800 p-6 rounded-xl space-y-3">
              <div className="text-sm font-bold text-slate-300 flex items-center space-x-2">
                <Key className="w-4 h-4 text-amber-400" />
                <span>Public X.509 Certificates</span>
              </div>
              <div className="text-3xl font-extrabold text-white">{counts.certificates}</div>
              <p className="text-xs text-slate-400">Correlated across TLSScanner & LinuxCollector by SHA-256 fingerprint</p>
            </div>
          </div>

          <div className="bg-slate-900/40 border border-slate-800 p-6 rounded-xl space-y-4">
            <h3 className="text-base font-bold text-slate-200">Zero-Secret Boundary Verification</h3>
            <p className="text-sm text-slate-400">
              `KubernetesConnector` operates under strict read-only least-privilege guarantees. Secret values (`Secret.data`, `Secret.stringData`), private keys (`tls.key`), bearer tokens, and passwords are never read or stored.
            </p>
            <div className="flex space-x-4 pt-2">
              <button 
                onClick={() => onNavigate && onNavigate('assets')}
                className="px-4 py-2 bg-slate-800 hover:bg-slate-700 text-slate-200 text-xs font-semibold rounded-lg flex items-center space-x-2"
              >
                <span>View Inventoried Assets</span>
                <ExternalLink className="w-3.5 h-3.5" />
              </button>
              <button 
                onClick={() => onNavigate && onNavigate('pqc-readiness')}
                className="px-4 py-2 bg-slate-800 hover:bg-slate-700 text-slate-200 text-xs font-semibold rounded-lg flex items-center space-x-2"
              >
                <span>View PQC Readiness</span>
                <ExternalLink className="w-3.5 h-3.5" />
              </button>
            </div>
          </div>
        </div>
      )}

      {activeTab === 'coverage' && (
        <div className="bg-slate-900/40 border border-slate-800 rounded-xl overflow-hidden">
          <div className="p-4 border-b border-slate-800 flex justify-between items-center">
            <h3 className="text-sm font-bold text-slate-200">15-Capability Coverage Matrix</h3>
            <div className="relative">
              <Search className="w-4 h-4 absolute left-3 top-2.5 text-slate-400" />
              <input
                type="text"
                placeholder="Filter capabilities..."
                value={searchTerm}
                onChange={(e) => setSearchTerm(e.target.value)}
                className="pl-9 pr-4 py-1.5 bg-slate-950 border border-slate-800 rounded-lg text-xs text-slate-200 focus:outline-none focus:border-cyan-500"
              />
            </div>
          </div>

          <table className="w-full text-left border-collapse">
            <thead>
              <tr className="border-b border-slate-800 bg-slate-950/50 text-[11px] font-mono text-slate-400 uppercase tracking-wider">
                <th className="py-3 px-6">Capability Dimension</th>
                <th className="py-3 px-6">Discovery Status</th>
                <th className="py-3 px-6">Implementation Status</th>
              </tr>
            </thead>
            <tbody className="divide-y divide-slate-800/60 text-sm">
              {capabilities
                .filter(c => c.capability.toLowerCase().includes(searchTerm.toLowerCase()))
                .map((cap) => (
                  <tr key={cap.capability} className="hover:bg-slate-800/30 transition-colors">
                    <td className="py-3.5 px-6 font-mono text-xs font-medium text-slate-200">
                      {cap.capability}
                    </td>
                    <td className="py-3.5 px-6">
                      {getStatusBadge(cap.status)}
                    </td>
                    <td className="py-3.5 px-6 text-xs text-slate-400">
                      {cap.status === 'NOT_APPLICABLE' ? 'Optional CRD / N/A' : 'IMPLEMENTED'}
                    </td>
                  </tr>
                ))}
            </tbody>
          </table>
        </div>
      )}
    </div>
  );
};
