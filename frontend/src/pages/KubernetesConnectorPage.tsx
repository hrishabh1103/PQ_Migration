import React, { useState, useEffect } from 'react';
import { 
  Server, ShieldCheck, RefreshCw, Layers, Cpu, Box, 
  Activity, CheckCircle2, AlertTriangle, Key, Search, ExternalLink, XCircle
} from 'lucide-react';
import { PageHeader } from '../components/common/PageHeader';

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
  const [clusterStatus, setClusterStatus] = useState<string>('NOT_CONNECTED');
  const [gitVersion, setGitVersion] = useState<string>('UNKNOWN');
  const [statusMessage, setStatusMessage] = useState<string | null>(null);
  const [isSyncing, setIsSyncing] = useState<boolean>(false);
  const [activeTab, setActiveTab] = useState<'overview' | 'coverage' | 'inventory'>('overview');
  const [searchTerm, setSearchTerm] = useState<string>('');
  const [targets, setTargets] = useState<any[]>([]);
  const [selectedTargetId, setSelectedTargetId] = useState<string>('');

  const [counts, setCounts] = useState<InventoryCounts>({
    workloads: 0,
    pods: 0,
    services: 0,
    ingresses: 0,
    certificates: 0,
    secret_metadata: 0
  });

  const [capabilities, setCapabilities] = useState<CapabilityStatus[]>([
    { capability: 'cluster_identity', status: 'NOT_SCANNED' },
    { capability: 'nodes', status: 'NOT_SCANNED' },
    { capability: 'namespaces', status: 'NOT_SCANNED' },
    { capability: 'workloads', status: 'NOT_SCANNED' },
    { capability: 'pods', status: 'NOT_SCANNED' },
    { capability: 'services', status: 'NOT_SCANNED' },
    { capability: 'ingress', status: 'NOT_SCANNED' },
    { capability: 'gateway_api', status: 'NOT_APPLICABLE' },
    { capability: 'certificates', status: 'NOT_SCANNED' },
    { capability: 'secret_metadata', status: 'NOT_SCANNED' },
    { capability: 'configmaps', status: 'NOT_SCANNED' },
    { capability: 'rbac', status: 'NOT_SCANNED' },
    { capability: 'cert_manager', status: 'NOT_SCANNED' },
    { capability: 'service_mesh', status: 'NOT_SCANNED' },
    { capability: 'encryption_at_rest', status: 'UNKNOWN' }
  ]);

  useEffect(() => {
    fetchTargetsAndValidate();
  }, []);

  const fetchTargetsAndValidate = async () => {
    try {
      const res = await fetch('/api/v1/targets');
      if (res.ok) {
        const list = await res.json();
        const k8sTargets = list.filter((t: any) => t.target_type === 'KUBERNETES_CLUSTER' || t.target_type === 'KUBERNETES_NAMESPACE');
        setTargets(k8sTargets);
        if (k8sTargets.length > 0) {
          const tid = k8sTargets[0].id;
          setSelectedTargetId(tid);
          await validateAndFetchInventory(tid);
          return;
        }
      }
      await validateAndFetchInventory('');
    } catch (e) {
      setClusterStatus('NOT_CONNECTED');
      setGitVersion('UNKNOWN');
      setStatusMessage(`Validation failed: ${e}`);
    }
  };

  const validateAndFetchInventory = async (targetId: string) => {
    setStatusMessage('Validating Kubernetes API server connection...');
    try {
      const valRes = await fetch('/api/v1/connectors/kubernetes/validate', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ in_cluster: false })
      });

      if (valRes.ok) {
        const valData = await valRes.json();
        if (valData.validated) {
          setClusterStatus('CONNECTED');
          setGitVersion(valData.git_version || 'UNKNOWN');
          setStatusMessage(`Connected to Kubernetes cluster (${valData.git_version || 'v1.xx'})`);

          if (targetId) {
            fetchInventoryData(targetId);
          }
          return;
        }
      }
      setClusterStatus('NOT_CONNECTED');
      setGitVersion('UNKNOWN');
      setStatusMessage('Kubernetes API server unreachable or invalid kubeconfig');
    } catch (err) {
      setClusterStatus('NOT_CONNECTED');
      setGitVersion('UNKNOWN');
      setStatusMessage('Kubernetes validation failed: CONNECTION_FAILED');
    }
  };

  const fetchInventoryData = async (targetId: string) => {
    try {
      const [invRes, covRes] = await Promise.all([
        fetch(`/api/v1/connectors/kubernetes/inventory/${targetId}`),
        fetch(`/api/v1/connectors/kubernetes/coverage/${targetId}`)
      ]);

      if (invRes.ok) {
        const invData = await invRes.json();
        if (invData.counts) setCounts(invData.counts);
      }
      if (covRes.ok) {
        const covData = await covRes.json();
        if (covData.capabilities) setCapabilities(covData.capabilities);
      }
    } catch (e) {
      console.error('Failed to fetch K8s inventory:', e);
    }
  };

  const handleTriggerSync = async () => {
    if (!selectedTargetId) {
      setStatusMessage('No Kubernetes Target selected. Register a KUBERNETES_CLUSTER target first.');
      return;
    }
    setIsSyncing(true);
    setStatusMessage('Executing read-only Kubernetes discovery across 15 dimensions...');
    try {
      const res = await fetch('/api/v1/connectors/kubernetes/sync', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ target_id: selectedTargetId })
      });

      if (res.ok) {
        setStatusMessage('Kubernetes discovery sync complete. Refreshing inventory...');
        await validateAndFetchInventory(selectedTargetId);
      } else {
        const err = await res.json();
        setStatusMessage(`Sync failed: ${err.detail || 'API error'}`);
      }
    } catch (e) {
      setStatusMessage(`Sync error: ${e}`);
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
      case 'NOT_APPLICABLE':
        return <span className="px-2.5 py-1 text-xs font-semibold rounded-md bg-slate-500/10 text-slate-400 border border-slate-500/20">N/A</span>;
      default:
        return <span className="px-2.5 py-1 text-xs font-semibold rounded-md bg-slate-500/10 text-slate-400 border border-slate-500/20">NOT SCANNED</span>;
    }
  };

  return (
    <div className="p-8 space-y-8 max-w-7xl mx-auto">
      {/* Header & Actions */}
      <div className="flex flex-col md:flex-row md:items-center md:justify-between gap-4 bg-slate-900/60 border border-slate-800 p-6 rounded-2xl backdrop-blur-md">
        <div className="flex items-center space-x-4">
          <div className="p-3 bg-cyan-500/10 border border-cyan-500/30 rounded-xl text-cyan-400">
            <Server className="w-8 h-8" />
          </div>
          <div>
            <div className="flex items-center space-x-3">
              <h1 className="text-2xl font-bold text-slate-100">Kubernetes Connector</h1>
              <span className={`px-2.5 py-0.5 text-xs font-mono font-semibold rounded-full border ${clusterStatus === 'CONNECTED' ? 'bg-emerald-500/20 text-emerald-300 border-emerald-500/30' : 'bg-rose-500/20 text-rose-300 border-rose-500/30'}`}>
                API STATUS: {clusterStatus}
              </span>
              <span className="px-2.5 py-0.5 text-xs font-mono font-semibold rounded-full bg-cyan-500/20 text-cyan-300 border border-cyan-500/30">
                K8S VERSION: {gitVersion}
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
            disabled={isSyncing || clusterStatus !== 'CONNECTED'}
            className="px-4 py-2 bg-cyan-600 hover:bg-cyan-500 text-white font-medium rounded-xl text-sm transition-colors flex items-center space-x-2 shadow-lg shadow-cyan-950/40 disabled:opacity-50"
          >
            <RefreshCw className={`w-4 h-4 ${isSyncing ? 'animate-spin' : ''}`} />
            <span>{isSyncing ? 'Syncing...' : 'Trigger K8s Discovery Sync'}</span>
          </button>
        </div>
      </div>

      {statusMessage && (
        <div className="p-3 bg-slate-950 border border-slate-800 rounded-xl font-mono text-xs text-cyan-400">
          {statusMessage}
        </div>
      )}

      {/* Overview Metric Cards */}
      <div className="grid grid-cols-2 md:grid-cols-3 lg:grid-cols-6 gap-4">
        <div className="bg-slate-900 border border-slate-800 p-4 rounded-xl">
          <div className="text-[10px] font-mono text-slate-400 uppercase">Workloads</div>
          <div className="text-2xl font-bold text-slate-100 mt-1 font-mono">{counts.workloads}</div>
          <div className="text-[10px] text-slate-400 mt-0.5">Deployments/StatefulSets</div>
        </div>
        <div className="bg-slate-900 border border-slate-800 p-4 rounded-xl">
          <div className="text-[10px] font-mono text-slate-400 uppercase">Pods & Containers</div>
          <div className="text-2xl font-bold text-slate-100 mt-1 font-mono">{counts.pods}</div>
          <div className="text-[10px] text-slate-400 mt-0.5">Active pod spec items</div>
        </div>
        <div className="bg-slate-900 border border-slate-800 p-4 rounded-xl">
          <div className="text-[10px] font-mono text-slate-400 uppercase">Services</div>
          <div className="text-2xl font-bold text-slate-100 mt-1 font-mono">{counts.services}</div>
          <div className="text-[10px] text-slate-400 mt-0.5">Network endpoints</div>
        </div>
        <div className="bg-slate-900 border border-slate-800 p-4 rounded-xl">
          <div className="text-[10px] font-mono text-slate-400 uppercase">Ingresses</div>
          <div className="text-2xl font-bold text-slate-100 mt-1 font-mono">{counts.ingresses}</div>
          <div className="text-[10px] text-slate-400 mt-0.5">TLS termination rules</div>
        </div>
        <div className="bg-slate-900 border border-slate-800 p-4 rounded-xl">
          <div className="text-[10px] font-mono text-slate-400 uppercase">Certificates</div>
          <div className="text-2xl font-bold text-cyan-400 mt-1 font-mono">{counts.certificates}</div>
          <div className="text-[10px] text-slate-400 mt-0.5">X.509 secret material</div>
        </div>
        <div className="bg-slate-900 border border-slate-800 p-4 rounded-xl">
          <div className="text-[10px] font-mono text-slate-400 uppercase">Secret Metadata</div>
          <div className="text-2xl font-bold text-indigo-400 mt-1 font-mono">{counts.secret_metadata}</div>
          <div className="text-[10px] text-slate-400 mt-0.5">Zero secret data leaked</div>
        </div>
      </div>

      {/* 15 Capability Coverage Grid */}
      <div className="bg-slate-900 border border-slate-800 rounded-xl p-6">
        <h3 className="text-base font-bold text-slate-100 mb-4 flex items-center">
          <ShieldCheck className="w-4.5 h-4.5 mr-2 text-indigo-400" /> Kubernetes 15-Capability Discovery Coverage
        </h3>
        <div className="grid grid-cols-1 md:grid-cols-3 lg:grid-cols-5 gap-4">
          {capabilities.map((item) => (
            <div key={item.capability} className="bg-slate-950 border border-slate-800 rounded-lg p-3.5 flex flex-col justify-between">
              <div className="flex items-center justify-between mb-2">
                <span className="text-[10px] font-mono text-slate-400 uppercase">{item.capability}</span>
                {getStatusBadge(item.status)}
              </div>
              <h4 className="text-xs font-semibold text-slate-200 capitalize">{item.capability.replace('_', ' ')}</h4>
            </div>
          ))}
        </div>
      </div>
    </div>
  );
};
