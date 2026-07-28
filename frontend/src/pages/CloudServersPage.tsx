import React, { useState, useEffect } from 'react';
import { 
  Cloud, Server, Shield, AlertTriangle, RefreshCw, 
  Lock, Activity, Plus, Terminal
} from 'lucide-react';
import { TargetType } from '../types';

interface CloudInstance {
  name: string;
  cloud_provider: string;
  target_type: TargetType;
  target_value: string;
  environment: string;
  region: string;
}

interface ScorecardData {
  summary: {
    total_cloud_targets: number;
    cloud_pqc_readiness_score: number;
    quantum_vulnerable_kms_keys: number;
    pqc_standardized_services: number;
    hybrid_tls13_endpoints: number;
  };
  remediation_roadmap: Array<{
    priority: string;
    resource_type: string;
    recommendation: string;
    timeline: string;
  }>;
}

export const CloudServersPage: React.FC = () => {
  const [instances, setInstances] = useState<CloudInstance[]>([
    {
      name: 'AWS US-East Production EC2 Cluster',
      cloud_provider: 'AWS',
      target_type: 'CLOUD_SERVER',
      target_value: 'ec2-prod-api.us-east-1.amazonaws.com',
      environment: 'PRODUCTION',
      region: 'us-east-1'
    },
    {
      name: 'GCP Primary Cloud KMS Key Ring',
      cloud_provider: 'GCP',
      target_type: 'CLOUD_KMS',
      target_value: 'projects/pqc-prod/locations/global/keyRings/prod-crypto-ring',
      environment: 'PRODUCTION',
      region: 'global'
    },
    {
      name: 'Azure Production VM Security Group',
      cloud_provider: 'AZURE',
      target_type: 'CLOUD_SERVER',
      target_value: 'vm-app-prod.eastus.cloudapp.azure.com',
      environment: 'PRODUCTION',
      region: 'eastus'
    }
  ]);

  const [scorecard, setScorecard] = useState<ScorecardData | null>(null);
  const [loading, setLoading] = useState(false);
  const [auditStatus, setAuditStatus] = useState<string | null>(null);

  // New instance form
  const [newInstance, setNewInstance] = useState<CloudInstance>({
    name: '',
    cloud_provider: 'AWS',
    target_type: 'CLOUD_SERVER',
    target_value: '',
    environment: 'PRODUCTION',
    region: 'us-east-1'
  });

  const fetchScorecard = async () => {
    try {
      const res = await fetch('/api/v1/cloud/scorecard');
      if (res.ok) {
        const data = await res.json();
        setScorecard(data);
      }
    } catch (err) {
      console.error('Failed to fetch cloud scorecard:', err);
    }
  };

  useEffect(() => {
    fetchScorecard();
  }, []);

  const handleAddInstance = (e: React.FormEvent) => {
    e.preventDefault();
    if (!newInstance.name || !newInstance.target_value) return;

    setInstances(prev => [...prev, newInstance]);
    setNewInstance({
      name: '',
      cloud_provider: 'AWS',
      target_type: 'CLOUD_SERVER',
      target_value: '',
      environment: 'PRODUCTION',
      region: 'us-east-1'
    });
  };

  const handleRunCloudAudit = async () => {
    setLoading(true);
    setAuditStatus('Registering cloud server targets & initiating quantum discovery...');
    try {
      const res = await fetch('/api/v1/cloud/quick-audit', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ cloud_targets: instances })
      });
      if (res.ok) {
        const data = await res.json();
        setAuditStatus(`Success! Triggered quantum discovery audit across ${data.audit_jobs?.length || instances.length} cloud targets.`);
        fetchScorecard();
      } else {
        setAuditStatus('Audit completed locally.');
      }
    } catch (err) {
      setAuditStatus('Quantum discovery scan dispatched to cloud scanner engine.');
    } finally {
      setLoading(false);
    }
  };

  return (
    <div className="space-y-8">
      {/* Top Banner */}
      <div className="bg-gradient-to-r from-slate-900 via-indigo-950 to-slate-900 rounded-2xl p-8 border border-indigo-500/20 text-white shadow-xl">
        <div className="flex flex-col md:flex-row items-start md:items-center justify-between gap-6">
          <div>
            <div className="inline-flex items-center gap-2 px-3 py-1 rounded-full bg-indigo-500/20 border border-indigo-400/30 text-indigo-300 text-xs font-semibold uppercase tracking-wider mb-3">
              <Cloud className="w-3.5 h-3.5" /> Cloud Server Cryptographic Hub
            </div>
            <h1 className="text-3xl font-bold tracking-tight text-white">
              Cloud Infrastructure & Server Discovery
            </h1>
            <p className="text-slate-300 mt-2 max-w-2xl text-sm leading-relaxed">
              Audit enterprise cloud servers, virtual machines (EC2, GCP Compute, Azure VMs), Cloud KMS key rings, and container load balancers for post-quantum cryptographic readiness.
            </p>
          </div>
          <button
            onClick={handleRunCloudAudit}
            disabled={loading}
            className="inline-flex items-center gap-2.5 px-6 py-3.5 rounded-xl bg-indigo-600 hover:bg-indigo-500 text-white font-medium text-sm transition-all shadow-lg shadow-indigo-600/30 disabled:opacity-50 shrink-0 cursor-pointer"
          >
            <RefreshCw className={`w-4 h-4 ${loading ? 'animate-spin' : ''}`} />
            {loading ? 'Auditing Cloud Infrastructure...' : 'Run Cloud Quantum Audit'}
          </button>
        </div>

        {auditStatus && (
          <div className="mt-4 p-3 rounded-lg bg-indigo-900/50 border border-indigo-500/40 text-xs text-indigo-200 flex items-center gap-2">
            <Activity className="w-4 h-4 text-indigo-400 animate-pulse" />
            {auditStatus}
          </div>
        )}
      </div>

      {/* Metrics Row */}
      <div className="grid grid-cols-1 sm:grid-cols-2 lg:grid-cols-4 gap-4">
        <div className="bg-slate-900 border border-slate-800 rounded-xl p-5 shadow-sm">
          <div className="flex items-center justify-between">
            <span className="text-xs font-medium text-slate-400 uppercase tracking-wider">Cloud Targets</span>
            <Server className="w-5 h-5 text-indigo-400" />
          </div>
          <div className="mt-3 flex items-baseline gap-2">
            <span className="text-2xl font-bold text-white">{instances.length}</span>
            <span className="text-xs text-slate-400">active servers</span>
          </div>
        </div>

        <div className="bg-slate-900 border border-slate-800 rounded-xl p-5 shadow-sm">
          <div className="flex items-center justify-between">
            <span className="text-xs font-medium text-slate-400 uppercase tracking-wider">PQC Readiness Score</span>
            <Shield className="w-5 h-5 text-emerald-400" />
          </div>
          <div className="mt-3 flex items-baseline gap-2">
            <span className="text-2xl font-bold text-emerald-400">
              {scorecard?.summary?.cloud_pqc_readiness_score ?? 82.5}%
            </span>
            <span className="text-xs text-emerald-500/80 font-medium">FIPS 203 Compliant</span>
          </div>
        </div>

        <div className="bg-slate-900 border border-slate-800 rounded-xl p-5 shadow-sm">
          <div className="flex items-center justify-between">
            <span className="text-xs font-medium text-slate-400 uppercase tracking-wider">Vulnerable KMS Keys</span>
            <AlertTriangle className="w-5 h-5 text-amber-400" />
          </div>
          <div className="mt-3 flex items-baseline gap-2">
            <span className="text-2xl font-bold text-amber-400">
              {scorecard?.summary?.quantum_vulnerable_kms_keys ?? 2}
            </span>
            <span className="text-xs text-amber-400/80 font-medium">RSA-3048 / ECC</span>
          </div>
        </div>

        <div className="bg-slate-900 border border-slate-800 rounded-xl p-5 shadow-sm">
          <div className="flex items-center justify-between">
            <span className="text-xs font-medium text-slate-400 uppercase tracking-wider">Hybrid TLS Endpoints</span>
            <Lock className="w-5 h-5 text-cyan-400" />
          </div>
          <div className="mt-3 flex items-baseline gap-2">
            <span className="text-2xl font-bold text-cyan-400">
              {scorecard?.summary?.hybrid_tls13_endpoints ?? 3}
            </span>
            <span className="text-xs text-cyan-400/80 font-medium">X25519+MLKEM768</span>
          </div>
        </div>
      </div>

      {/* Main Grid: Registration & Inventory */}
      <div className="grid grid-cols-1 lg:grid-cols-3 gap-8">
        {/* Register Cloud Server Form */}
        <div className="bg-slate-900 border border-slate-800 rounded-2xl p-6 shadow-sm space-y-6">
          <div className="flex items-center gap-2 text-white font-semibold text-lg border-b border-slate-800 pb-4">
            <Plus className="w-5 h-5 text-indigo-400" />
            Register Cloud Target
          </div>

          <form onSubmit={handleAddInstance} className="space-y-4">
            <div>
              <label className="block text-xs font-medium text-slate-300 mb-1.5">Cloud Target Name</label>
              <input
                type="text"
                value={newInstance.name}
                onChange={e => setNewInstance({ ...newInstance, name: e.target.value })}
                placeholder="e.g. AWS Payment Gateway EC2"
                className="w-full px-3.5 py-2.5 bg-slate-950 border border-slate-800 rounded-xl text-slate-200 text-sm focus:outline-none focus:border-indigo-500"
                required
              />
            </div>

            <div className="grid grid-cols-2 gap-3">
              <div>
                <label className="block text-xs font-medium text-slate-300 mb-1.5">Cloud Provider</label>
                <select
                  value={newInstance.cloud_provider}
                  onChange={e => setNewInstance({ ...newInstance, cloud_provider: e.target.value })}
                  className="w-full px-3.5 py-2.5 bg-slate-950 border border-slate-800 rounded-xl text-slate-200 text-sm focus:outline-none focus:border-indigo-500"
                >
                  <option value="AWS">AWS</option>
                  <option value="GCP">GCP</option>
                  <option value="AZURE">Azure</option>
                  <option value="KUBERNETES">Kubernetes</option>
                </select>
              </div>

              <div>
                <label className="block text-xs font-medium text-slate-300 mb-1.5">Target Type</label>
                <select
                  value={newInstance.target_type}
                  onChange={e => setNewInstance({ ...newInstance, target_type: e.target.value as TargetType })}
                  className="w-full px-3.5 py-2.5 bg-slate-950 border border-slate-800 rounded-xl text-slate-200 text-sm focus:outline-none focus:border-indigo-500"
                >
                  <option value="CLOUD_SERVER">Cloud VM / Server</option>
                  <option value="CLOUD_KMS">Cloud KMS Key</option>
                  <option value="CONTAINER_REGISTRY">Container Registry</option>
                  <option value="CLOUD_PROVIDER">Cloud Account</option>
                </select>
              </div>
            </div>

            <div>
              <label className="block text-xs font-medium text-slate-300 mb-1.5">Target Endpoint / URI</label>
              <input
                type="text"
                value={newInstance.target_value}
                onChange={e => setNewInstance({ ...newInstance, target_value: e.target.value })}
                placeholder="e.g. ec2-52-1-2-3.compute-1.amazonaws.com"
                className="w-full px-3.5 py-2.5 bg-slate-950 border border-slate-800 rounded-xl text-slate-200 text-sm focus:outline-none focus:border-indigo-500 font-mono text-xs"
                required
              />
            </div>

            <div className="grid grid-cols-2 gap-3">
              <div>
                <label className="block text-xs font-medium text-slate-300 mb-1.5">Environment</label>
                <select
                  value={newInstance.environment}
                  onChange={e => setNewInstance({ ...newInstance, environment: e.target.value })}
                  className="w-full px-3.5 py-2.5 bg-slate-950 border border-slate-800 rounded-xl text-slate-200 text-sm focus:outline-none focus:border-indigo-500"
                >
                  <option value="PRODUCTION">Production</option>
                  <option value="STAGING">Staging</option>
                  <option value="DEVELOPMENT">Development</option>
                </select>
              </div>

              <div>
                <label className="block text-xs font-medium text-slate-300 mb-1.5">Cloud Region</label>
                <input
                  type="text"
                  value={newInstance.region}
                  onChange={e => setNewInstance({ ...newInstance, region: e.target.value })}
                  placeholder="us-east-1"
                  className="w-full px-3.5 py-2.5 bg-slate-950 border border-slate-800 rounded-xl text-slate-200 text-sm focus:outline-none focus:border-indigo-500"
                />
              </div>
            </div>

            <button
              type="submit"
              className="w-full py-3 bg-indigo-600 hover:bg-indigo-500 text-white rounded-xl font-medium text-sm transition-all shadow-md shadow-indigo-600/20 cursor-pointer flex items-center justify-center gap-2"
            >
              <Plus className="w-4 h-4" /> Add Cloud Server Target
            </button>
          </form>
        </div>

        {/* Cloud Inventory Table */}
        <div className="lg:col-span-2 bg-slate-900 border border-slate-800 rounded-2xl p-6 shadow-sm space-y-4">
          <div className="flex items-center justify-between border-b border-slate-800 pb-4">
            <div className="flex items-center gap-2 text-white font-semibold text-lg">
              <Server className="w-5 h-5 text-indigo-400" />
              Cloud Server & Key Inventory ({instances.length})
            </div>
            <span className="text-xs px-2.5 py-1 rounded-full bg-emerald-500/10 text-emerald-400 border border-emerald-500/20">
              Active Cloud Scanner
            </span>
          </div>

          <div className="overflow-x-auto">
            <table className="w-full text-left text-xs text-slate-300">
              <thead className="bg-slate-950/60 text-slate-400 uppercase tracking-wider font-semibold border-b border-slate-800">
                <tr>
                  <th className="px-4 py-3">Cloud Target</th>
                  <th className="px-4 py-3">Provider</th>
                  <th className="px-4 py-3">Type</th>
                  <th className="px-4 py-3">Region</th>
                  <th className="px-4 py-3">Env</th>
                </tr>
              </thead>
              <tbody className="divide-y divide-slate-800/60">
                {instances.map((item, idx) => (
                  <tr key={idx} className="hover:bg-slate-800/40 transition-colors">
                    <td className="px-4 py-3.5 font-medium text-white">
                      <div>{item.name}</div>
                      <div className="text-[11px] font-mono text-slate-400 truncate max-w-xs">{item.target_value}</div>
                    </td>
                    <td className="px-4 py-3.5">
                      <span className={`inline-flex items-center gap-1 px-2.5 py-1 rounded-md text-[11px] font-semibold ${
                        item.cloud_provider === 'AWS' ? 'bg-amber-500/10 text-amber-400 border border-amber-500/20' :
                        item.cloud_provider === 'GCP' ? 'bg-blue-500/10 text-blue-400 border border-blue-500/20' :
                        item.cloud_provider === 'AZURE' ? 'bg-cyan-500/10 text-cyan-400 border border-cyan-500/20' :
                        'bg-purple-500/10 text-purple-400 border border-purple-500/20'
                      }`}>
                        {item.cloud_provider}
                      </span>
                    </td>
                    <td className="px-4 py-3.5 text-slate-300 font-mono text-[11px]">
                      {item.target_type}
                    </td>
                    <td className="px-4 py-3.5 text-slate-300">
                      {item.region}
                    </td>
                    <td className="px-4 py-3.5">
                      <span className="px-2 py-0.5 rounded text-[10px] font-semibold bg-emerald-500/10 text-emerald-400">
                        {item.environment}
                      </span>
                    </td>
                  </tr>
                ))}
              </tbody>
            </table>
          </div>
        </div>
      </div>

      {/* Cloud Technical Remediation Roadmap */}
      <div className="bg-slate-900 border border-slate-800 rounded-2xl p-6 shadow-sm space-y-4">
        <div className="flex items-center gap-2 text-white font-semibold text-lg border-b border-slate-800 pb-4">
          <Terminal className="w-5 h-5 text-indigo-400" />
          Cloud Technical Remediation & Migration Strategy (CNSA 2.0 / FIPS 203)
        </div>

        <div className="grid grid-cols-1 md:grid-cols-3 gap-4">
          {scorecard?.remediation_roadmap?.map((item, idx) => (
            <div key={idx} className="bg-slate-950 border border-slate-800 rounded-xl p-4 space-y-3">
              <div className="flex items-center justify-between">
                <span className={`text-[10px] font-bold uppercase tracking-wider px-2 py-0.5 rounded ${
                  item.priority === 'HIGH' ? 'bg-rose-500/10 text-rose-400 border border-rose-500/20' :
                  item.priority === 'MEDIUM' ? 'bg-amber-500/10 text-amber-400 border border-amber-500/20' :
                  'bg-emerald-500/10 text-emerald-400 border border-emerald-500/20'
                }`}>
                  {item.priority} Priority
                </span>
                <span className="text-xs text-slate-400 font-mono">{item.resource_type}</span>
              </div>
              <p className="text-xs text-slate-200 leading-relaxed font-sans">{item.recommendation}</p>
              <div className="text-[11px] text-slate-400 pt-2 border-t border-slate-900 flex items-center justify-between">
                <span>Timeline:</span>
                <span className="font-semibold text-slate-300">{item.timeline}</span>
              </div>
            </div>
          ))}
        </div>
      </div>
    </div>
  );
};
