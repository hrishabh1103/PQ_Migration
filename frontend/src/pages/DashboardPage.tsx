import React, { useEffect, useState } from 'react';
import { DashboardStats } from '../types';
import { fetchDashboardStats } from '../services/api';
import { Database, Network, KeyRound, Play, RefreshCw, Sparkles, AlertCircle, Plus } from 'lucide-react';
import { PageHeader } from '../components/common/PageHeader';

interface DashboardPageProps {
  onNavigate: (tab: string) => void;
}

export const DashboardPage: React.FC<DashboardPageProps> = ({ onNavigate }) => {
  const [stats, setStats] = useState<DashboardStats | null>(null);
  const [loading, setLoading] = useState<boolean>(true);
  const [error, setError] = useState<string | null>(null);

  const loadStats = async () => {
    try {
      setLoading(true);
      setError(null);
      const data = await fetchDashboardStats();
      setStats(data);
    } catch (err: any) {
      setError(err.message || 'Failed to connect to backend server');
    } finally {
      setLoading(false);
    }
  };

  useEffect(() => {
    loadStats();
  }, []);

  if (loading) {
    return (
      <div className="flex items-center justify-center min-h-[60vh]">
        <div className="flex items-center space-x-3 text-cyan-400 font-mono">
          <RefreshCw className="w-6 h-6 animate-spin" />
          <span>Connecting to Q-Discovery Engine...</span>
        </div>
      </div>
    );
  }

  const algoDist = stats?.algorithm_distribution || {};
  const maxAlgoCount = Math.max(...Object.values(algoDist), 1);

  const scanDist = stats?.scan_status_distribution || {};
  const totalScans = stats?.scan_jobs_count || 0;

  return (
    <div className="space-y-6">
      {/* Page Header */}
      <PageHeader
        title="Enterprise Cryptographic Inventory"
        description="Continuous, zero-trust discovery and normalization of cryptographic primitives, cipher suites, keys, and certificates across authorized targets."
        icon={Sparkles}
        badge="PQC READINESS"
        actions={
          <>
            <button
              onClick={loadStats}
              className="p-2.5 rounded-xl border border-slate-700 bg-slate-800/80 text-slate-300 hover:text-white hover:border-slate-600 transition"
              title="Refresh Dashboard"
            >
              <RefreshCw className="w-4 h-4" />
            </button>
            <button
              onClick={() => onNavigate('targets')}
              className="flex items-center space-x-2 px-4 py-2.5 rounded-xl bg-gradient-to-r from-cyan-500 to-blue-600 hover:from-cyan-400 hover:to-blue-500 text-white font-medium text-sm shadow-lg shadow-cyan-500/20 transition"
            >
              <Plus className="w-4 h-4" />
              <span>New Discovery</span>
            </button>
          </>
        }
      />

      {error && (
        <div className="p-4 rounded-xl bg-rose-500/10 border border-rose-500/30 text-rose-300 flex items-center space-x-3 text-sm">
          <AlertCircle className="w-5 h-5 flex-shrink-0" />
          <span>{error}</span>
        </div>
      )}

      {/* Top Summary Metric Cards */}
      <div className="grid grid-cols-1 sm:grid-cols-2 lg:grid-cols-4 gap-5">
        <div
          onClick={() => onNavigate('targets')}
          className="glass-panel-interactive p-6 rounded-2xl cursor-pointer group"
        >
          <div className="flex items-center justify-between">
            <span className="text-xs font-mono text-slate-400 uppercase tracking-wider">Authorized Targets</span>
            <div className="p-2.5 rounded-xl bg-cyan-500/10 text-cyan-400 border border-cyan-500/20 group-hover:scale-110 transition-transform">
              <Network className="w-5 h-5" />
            </div>
          </div>
          <div className="mt-4">
            <div className="text-3xl font-bold text-white tracking-tight">{stats?.authorized_targets_count || 0}</div>
            <p className="text-xs text-slate-400 mt-1">Configured scope endpoints</p>
          </div>
        </div>

        <div
          onClick={() => onNavigate('assets')}
          className="glass-panel-interactive p-6 rounded-2xl cursor-pointer group"
        >
          <div className="flex items-center justify-between">
            <span className="text-xs font-mono text-slate-400 uppercase tracking-wider">Inventoried Assets</span>
            <div className="p-2.5 rounded-xl bg-indigo-500/10 text-indigo-400 border border-indigo-500/20 group-hover:scale-110 transition-transform">
              <Database className="w-5 h-5" />
            </div>
          </div>
          <div className="mt-4">
            <div className="text-3xl font-bold text-white tracking-tight">{stats?.assets_count || 0}</div>
            <p className="text-xs text-slate-400 mt-1">Hosts, Services, Processes</p>
          </div>
        </div>

        <div
          onClick={() => onNavigate('findings')}
          className="glass-panel-interactive p-6 rounded-2xl cursor-pointer group"
        >
          <div className="flex items-center justify-between">
            <span className="text-xs font-mono text-slate-400 uppercase tracking-wider">Crypto Findings</span>
            <div className="p-2.5 rounded-xl bg-purple-500/10 text-purple-400 border border-purple-500/20 group-hover:scale-110 transition-transform">
              <KeyRound className="w-5 h-5" />
            </div>
          </div>
          <div className="mt-4">
            <div className="text-3xl font-bold text-white tracking-tight">{stats?.findings_count || 0}</div>
            <p className="text-xs text-slate-400 mt-1">Normalized cryptographic items</p>
          </div>
        </div>

        <div
          onClick={() => onNavigate('scans')}
          className="glass-panel-interactive p-6 rounded-2xl cursor-pointer group"
        >
          <div className="flex items-center justify-between">
            <span className="text-xs font-mono text-slate-400 uppercase tracking-wider">Active Scans</span>
            <div className="p-2.5 rounded-xl bg-emerald-500/10 text-emerald-400 border border-emerald-500/20 group-hover:scale-110 transition-transform">
              <Play className="w-5 h-5" />
            </div>
          </div>
          <div className="mt-4">
            <div className="text-3xl font-bold text-white tracking-tight">{stats?.scan_jobs_count || 0}</div>
            <p className="text-xs text-slate-400 mt-1">Discovery job executions</p>
          </div>
        </div>
      </div>

      {/* Two Column Section: Algorithm Distribution & Scan Status */}
      <div className="grid grid-cols-1 lg:grid-cols-3 gap-6">
        <div className="lg:col-span-2 glass-panel p-6 rounded-2xl border border-slate-800">
          <div className="flex items-center justify-between mb-6">
            <div>
              <h3 className="text-base font-bold text-white">Algorithm Distribution</h3>
              <p className="text-xs text-slate-400 mt-0.5">Top observed algorithms across inventoried targets</p>
            </div>
            <span className="text-xs font-mono px-2.5 py-1 rounded bg-slate-800 text-slate-400 border border-slate-700">
              {Object.keys(algoDist).length} Unique Taxonomies
            </span>
          </div>

          <div className="space-y-4">
            {Object.entries(algoDist).length === 0 ? (
              <div className="py-12 text-center text-slate-500 text-sm font-mono">
                No algorithms inventoried yet. Start a discovery job to populate data.
              </div>
            ) : (
              Object.entries(algoDist).map(([algo, count]) => {
                const percentage = Math.round((count / maxAlgoCount) * 100);
                const isQuantumSafe = algo.includes('ML-KEM') || algo.includes('ML-DSA') || algo.includes('SLH-DSA') || algo.includes('Kyber');
                return (
                  <div key={algo} className="space-y-1.5">
                    <div className="flex justify-between text-xs">
                      <span className="font-mono text-slate-300 flex items-center space-x-2">
                        <span>{algo}</span>
                        {isQuantumSafe && (
                          <span className="px-1.5 py-0.5 rounded text-[10px] bg-emerald-500/10 text-emerald-400 border border-emerald-500/20">
                            PQC SAFE
                          </span>
                        )}
                      </span>
                      <span className="font-mono text-slate-400">{count} occurrences</span>
                    </div>
                    <div className="w-full bg-slate-950 rounded-full h-2 overflow-hidden border border-slate-800">
                      <div
                        className={`h-full rounded-full transition-all duration-500 ${
                          isQuantumSafe ? 'bg-emerald-500' : 'bg-cyan-500'
                        }`}
                        style={{ width: `${percentage}%` }}
                      />
                    </div>
                  </div>
                );
              })
            )}
          </div>
        </div>

        <div className="glass-panel p-6 rounded-2xl border border-slate-800 flex flex-col justify-between">
          <div>
            <h3 className="text-base font-bold text-white mb-1">Scan Status Distribution</h3>
            <p className="text-xs text-slate-400 mb-6">Historical status of discovery runs</p>

            <div className="space-y-3">
              {['COMPLETED', 'RUNNING', 'FAILED', 'PENDING'].map((statusKey) => {
                const count = scanDist[statusKey] || 0;
                const pct = totalScans > 0 ? Math.round((count / totalScans) * 100) : 0;
                return (
                  <div key={statusKey} className="p-3 rounded-xl bg-slate-950 border border-slate-800/80 flex items-center justify-between">
                    <span className="text-xs font-mono text-slate-300">{statusKey}</span>
                    <div className="flex items-center space-x-3">
                      <span className="text-xs font-bold text-white">{count}</span>
                      <span className="text-xs text-slate-500 font-mono w-10 text-right">{pct}%</span>
                    </div>
                  </div>
                );
              })}
            </div>
          </div>

          <div className="mt-6 pt-4 border-t border-slate-800/80 text-xs text-slate-400 flex items-center justify-between">
            <span>Orchestration Status:</span>
            <span className="font-mono text-emerald-400 flex items-center space-x-1">
              <span className="w-2 h-2 rounded-full bg-emerald-400 animate-pulse"></span>
              <span>READY</span>
            </span>
          </div>
        </div>
      </div>
    </div>
  );
};
