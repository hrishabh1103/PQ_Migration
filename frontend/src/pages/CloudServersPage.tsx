import React, { useState, useEffect } from 'react';
import { 
  Cloud, Server, RefreshCw, 
  Activity, Plus, Shield
} from 'lucide-react';
import { PageHeader } from '../components/common/PageHeader';
import { InstanceReportModal } from '../components/reports/InstanceReportModal';
import { useInstanceReport } from '../components/reports/useInstanceReport';

interface CloudInstance {
  id?: string;
  name: string;
  cloud_provider: string;
  target_type: string;
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
  const { selectedAssetId, openReport, closeReport } = useInstanceReport();
  const [instances, setInstances] = useState<CloudInstance[]>([]);
  const [scorecard, setScorecard] = useState<ScorecardData | null>(null);
  const [loading, setLoading] = useState<boolean>(false);
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

  const fetchScorecardAndTargets = async () => {
    setLoading(true);
    try {
      const [scRes, tRes] = await Promise.all([
        fetch('/api/v1/cloud/scorecard'),
        fetch('/api/v1/targets')
      ]);

      if (scRes.ok) {
        const data = await scRes.json();
        setScorecard(data);
      }

      if (tRes.ok) {
        const list = await tRes.json();
        const cloudList = list
          .filter((t: any) => ['CLOUD_SERVER', 'CLOUD_KMS', 'CLOUD_PROVIDER', 'CONTAINER_REGISTRY', 'AZURE_SUBSCRIPTION'].includes(t.target_type))
          .map((t: any) => ({
            id: t.id,
            name: t.name,
            cloud_provider: t.name?.includes('AZURE') ? 'AZURE' : (t.name?.includes('AWS') ? 'AWS' : 'MULTI-CLOUD'),
            target_type: t.target_type,
            target_value: t.target_value,
            environment: t.environment || 'PRODUCTION',
            region: 'global'
          }));
        setInstances(cloudList);
      }
    } catch (err) {
      console.error('Failed to fetch cloud infrastructure data:', err);
    } finally {
      setLoading(false);
    }
  };

  useEffect(() => {
    fetchScorecardAndTargets();
  }, []);

  const handleAddInstance = async (e: React.FormEvent) => {
    e.preventDefault();
    if (!newInstance.name || !newInstance.target_value) return;

    try {
      const res = await fetch('/api/v1/cloud/register-instance', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify(newInstance)
      });

      if (res.ok) {
        await fetchScorecardAndTargets();
        setNewInstance({
          name: '',
          cloud_provider: 'AWS',
          target_type: 'CLOUD_SERVER',
          target_value: '',
          environment: 'PRODUCTION',
          region: 'us-east-1'
        });
        setAuditStatus(`Cloud target '${newInstance.name}' registered successfully.`);
      }
    } catch (e) {
      setAuditStatus(`Failed to register target: ${e}`);
    }
  };

  const handleRunQuickAudit = async () => {
    if (instances.length === 0) {
      setAuditStatus('No registered cloud targets available to audit.');
      return;
    }

    setAuditStatus('Initiating real multi-cloud cryptographic audit...');
    try {
      const res = await fetch('/api/v1/cloud/quick-audit', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ cloud_targets: instances })
      });

      if (res.ok) {
        setAuditStatus('Cloud audit jobs dispatched. Refreshing posture...');
        setTimeout(fetchScorecardAndTargets, 2000);
      } else {
        setAuditStatus('Cloud quick audit failed.');
      }
    } catch (err) {
      setAuditStatus(`Cloud audit error: ${err}`);
    }
  };

  return (
    <div className="space-y-6">
      {/* Reusable Page Header */}
      <PageHeader
        title="Cloud Infrastructure & Servers"
        description="Unified cryptographic posture audit across cloud VMs, KMS keys, and load balancers."
        icon={Cloud}
        badge="Zero Secret Leakage"
        breadcrumbs={[{ label: 'Discovery' }, { label: 'Cloud Infrastructure' }]}
        actions={
          <button
            onClick={fetchScorecardAndTargets}
            className="p-2.5 rounded-xl border border-slate-700 bg-slate-800 text-slate-300 hover:text-white transition"
          >
            <RefreshCw className={`w-4 h-4 ${loading ? 'animate-spin' : ''}`} />
          </button>
        }
      />

      {/* Summary Scorecard Grid */}
      <div className="grid grid-cols-1 md:grid-cols-2 lg:grid-cols-5 gap-4">
        <div className="bg-slate-900 border border-slate-800 rounded-xl p-4">
          <span className="text-[10px] font-mono text-slate-400 uppercase">Cloud Targets</span>
          <div className="text-2xl font-extrabold font-mono text-slate-100 mt-1">
            {scorecard?.summary.total_cloud_targets ?? 0}
          </div>
          <span className="text-[10px] text-slate-400">Persisted infrastructure targets</span>
        </div>

        <div className="bg-slate-900 border border-slate-800 rounded-xl p-4">
          <span className="text-[10px] font-mono text-slate-400 uppercase">Cloud PQC Score</span>
          <div className="text-2xl font-extrabold font-mono text-cyan-400 mt-1">
            {scorecard?.summary.total_cloud_targets === 0 ? 'UNKNOWN' : `${scorecard?.summary.cloud_pqc_readiness_score}%`}
          </div>
          <span className="text-[10px] text-slate-400">Post-quantum readiness index</span>
        </div>

        <div className="bg-slate-900 border border-slate-800 rounded-xl p-4">
          <span className="text-[10px] font-mono text-slate-400 uppercase">Vulnerable KMS Keys</span>
          <div className="text-2xl font-extrabold font-mono text-rose-400 mt-1">
            {scorecard?.summary.quantum_vulnerable_kms_keys ?? 0}
          </div>
          <span className="text-[10px] text-slate-400">RSA / ECC KMS keys</span>
        </div>

        <div className="bg-slate-900 border border-slate-800 rounded-xl p-4">
          <span className="text-[10px] font-mono text-slate-400 uppercase">PQC Standardized Services</span>
          <div className="text-2xl font-extrabold font-mono text-emerald-400 mt-1">
            {scorecard?.summary.pqc_standardized_services ?? 0}
          </div>
          <span className="text-[10px] text-slate-400">ML-KEM / ML-DSA standard</span>
        </div>

        <div className="bg-slate-900 border border-slate-800 rounded-xl p-4">
          <span className="text-[10px] font-mono text-slate-400 uppercase">Hybrid TLS Endpoints</span>
          <div className="text-2xl font-extrabold font-mono text-indigo-400 mt-1">
            {scorecard?.summary.hybrid_tls13_endpoints ?? 0}
          </div>
          <span className="text-[10px] text-slate-400">X25519+MLKEM768 active</span>
        </div>
      </div>

      {/* Target Registration & Action Panel */}
      <div className="grid grid-cols-1 lg:grid-cols-3 gap-6">
        <div className="bg-slate-900 border border-slate-800 rounded-xl p-5">
          <h3 className="text-sm font-semibold text-slate-200 mb-3 flex items-center">
            <Plus className="w-4 h-4 mr-2 text-cyan-400" /> Register Cloud Instance / Service
          </h3>
          <form onSubmit={handleAddInstance} className="space-y-3">
            <div>
              <label className="text-[10px] font-mono text-slate-400 uppercase">Target Name</label>
              <input
                type="text"
                value={newInstance.name}
                onChange={e => setNewInstance({ ...newInstance, name: e.target.value })}
                placeholder="e.g. AWS US-East EC2 API"
                className="w-full bg-slate-950 border border-slate-800 rounded-lg px-3 py-1.5 text-xs text-slate-200 focus:outline-none focus:border-cyan-500 mt-1"
              />
            </div>
            <div>
              <label className="text-[10px] font-mono text-slate-400 uppercase">Target Host / Identifier</label>
              <input
                type="text"
                value={newInstance.target_value}
                onChange={e => setNewInstance({ ...newInstance, target_value: e.target.value })}
                placeholder="e.g. ec2-prod.us-east-1.amazonaws.com"
                className="w-full bg-slate-950 border border-slate-800 rounded-lg px-3 py-1.5 text-xs text-slate-200 focus:outline-none focus:border-cyan-500 mt-1"
              />
            </div>
            <div className="grid grid-cols-2 gap-2">
              <div>
                <label className="text-[10px] font-mono text-slate-400 uppercase">Provider</label>
                <select
                  value={newInstance.cloud_provider}
                  onChange={e => setNewInstance({ ...newInstance, cloud_provider: e.target.value })}
                  className="w-full bg-slate-950 border border-slate-800 rounded-lg px-2 py-1.5 text-xs text-slate-200 focus:outline-none mt-1"
                >
                  <option value="AWS">AWS</option>
                  <option value="AZURE">AZURE</option>
                  <option value="KUBERNETES">KUBERNETES</option>
                </select>
              </div>
              <div>
                <label className="text-[10px] font-mono text-slate-400 uppercase">Environment</label>
                <select
                  value={newInstance.environment}
                  onChange={e => setNewInstance({ ...newInstance, environment: e.target.value })}
                  className="w-full bg-slate-950 border border-slate-800 rounded-lg px-2 py-1.5 text-xs text-slate-200 focus:outline-none mt-1"
                >
                  <option value="PRODUCTION">PRODUCTION</option>
                  <option value="STAGING">STAGING</option>
                  <option value="DEVELOPMENT">DEVELOPMENT</option>
                </select>
              </div>
            </div>
            <button
              type="submit"
              className="w-full bg-cyan-600 hover:bg-cyan-500 text-white font-medium py-2 rounded-lg text-xs transition-colors mt-2"
            >
              Register Target
            </button>
          </form>
        </div>

        <div className="bg-slate-900 border border-slate-800 rounded-xl p-5 lg:col-span-2 flex flex-col justify-between">
          <div>
            <div className="flex items-center justify-between mb-3">
              <h3 className="text-sm font-semibold text-slate-200 flex items-center">
                <Server className="w-4 h-4 mr-2 text-indigo-400" /> Discovered Infrastructure Targets ({instances.length})
              </h3>
              <button
                onClick={handleRunQuickAudit}
                disabled={instances.length === 0}
                className="px-4 py-1.5 bg-emerald-600 hover:bg-emerald-500 text-white text-xs font-medium rounded-lg transition-colors disabled:opacity-50 flex items-center space-x-1.5"
              >
                <Activity className="w-3.5 h-3.5" />
                <span>Run Infrastructure Audit</span>
              </button>
            </div>

            {instances.length === 0 ? (
              <div className="py-12 text-center text-slate-500 text-xs font-mono">
                No cloud targets registered yet. Register a cloud target above or trigger connector sync.
              </div>
            ) : (
              <div className="overflow-x-auto">
                <table className="w-full text-left text-xs font-mono text-slate-300">
                  <thead className="bg-slate-950 text-slate-400 uppercase text-[10px] tracking-wider border-b border-slate-800">
                    <tr>
                      <th className="p-2.5">Name</th>
                      <th className="p-2.5">Provider</th>
                      <th className="p-2.5">Type</th>
                      <th className="p-2.5">Target Value</th>
                      <th className="p-2.5">Environment</th>
                      <th className="p-2.5 text-right">Actions</th>
                    </tr>
                  </thead>
                  <tbody className="divide-y divide-slate-800/60">
                    {instances.map((inst, idx) => (
                      <tr key={inst.id || idx} className="hover:bg-slate-800/40">
                        <td className="p-2.5 font-semibold text-slate-100">{inst.name}</td>
                        <td className="p-2.5">
                          <span className="px-2 py-0.5 rounded bg-cyan-500/10 text-cyan-400 border border-cyan-500/20 text-[10px]">
                            {inst.cloud_provider}
                          </span>
                        </td>
                        <td className="p-2.5 text-slate-400">{inst.target_type}</td>
                        <td className="p-2.5 text-slate-300 truncate max-w-xs">{inst.target_value}</td>
                        <td className="p-2.5 text-slate-400">{inst.environment}</td>
                        <td className="p-2.5 text-right">
                          {inst.id && (
                            <button
                              onClick={() => openReport(inst.id)}
                              className="px-2.5 py-1 rounded bg-cyan-500/10 hover:bg-cyan-500/20 text-cyan-400 border border-cyan-500/20 text-xs font-mono inline-flex items-center space-x-1"
                            >
                              <Shield className="w-3 h-3" />
                              <span>Report</span>
                            </button>
                          )}
                        </td>
                      </tr>
                    ))}
                  </tbody>
                </table>
              </div>
            )}
          </div>

          {auditStatus && (
            <p className="text-xs font-mono text-cyan-400 mt-3 bg-slate-950 p-2.5 rounded border border-slate-800">
              {auditStatus}
            </p>
          )}
        </div>
      </div>

      {/* Shared Instance Report Modal */}
      <InstanceReportModal assetId={selectedAssetId} onClose={closeReport} />
    </div>
  );
};
