import React, { useEffect, useState } from 'react';
import { DashboardStats } from '../types';
import { fetchDashboardStats, createTarget, createScan } from '../services/api';
import { Database, Network, KeyRound, Play, RefreshCw, Sparkles, AlertCircle } from 'lucide-react';

interface DashboardPageProps {
  onNavigate: (tab: string) => void;
}

export const DashboardPage: React.FC<DashboardPageProps> = ({ onNavigate }) => {
  const [stats, setStats] = useState<DashboardStats | null>(null);
  const [loading, setLoading] = useState<boolean>(true);
  const [error, setError] = useState<string | null>(null);
  const [launching, setLaunching] = useState<boolean>(false);
  const [launchMsg, setLaunchMsg] = useState<string | null>(null);

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

  const handleQuickLaunchMock = async () => {
    try {
      setLaunching(true);
      setLaunchMsg('Registering demo.internal target...');
      // Register demo.internal target
      const target = await createTarget({
        name: 'Demo Internal Target',
        target_type: 'HOSTNAME',
        target_value: 'demo.internal',
        is_authorized: true,
        environment: 'DEVELOPMENT'
      });

      setLaunchMsg('Triggering MockScanner job...');
      await createScan(target.id, ['mock-scanner']);

      setLaunchMsg('Scan triggered successfully!');
      setTimeout(() => {
        setLaunchMsg(null);
        setLaunching(false);
        loadStats();
        onNavigate('scans');
      }, 1200);
    } catch (err: any) {
      setError(`Launch failed: ${err.message}`);
      setLaunching(false);
    }
  };

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
    <div className="space-y-8">
      {/* Header Banner */}
      <div className="glass-panel p-6 sm:p-8 rounded-2xl border border-cyan-500/20 bg-gradient-to-r from-slate-900 via-slate-900 to-cyan-950/40 relative overflow-hidden">
        <div className="relative z-10 flex flex-col md:flex-row md:items-center justify-between gap-6">
          <div>
            <div className="flex items-center space-x-2 text-cyan-400 font-mono text-xs mb-2">
              <Sparkles className="w-4 h-4" />
              <span>POST-QUANTUM CRYPTOGRAPHIC DISCOVERY</span>
            </div>
            <h1 className="text-2xl sm:text-3xl font-bold text-white tracking-tight">
              Enterprise Cryptographic Inventory
            </h1>
            <p className="text-slate-400 text-sm mt-1 max-w-2xl">
              Continuous, zero-trust discovery and normalization of cryptographic primitives, cipher suites, keys, and certificates across authorized targets.
            </p>
          </div>
          <div className="flex items-center space-x-3">
            <button
              onClick={loadStats}
              className="p-2.5 rounded-xl border border-slate-700 bg-slate-800/80 text-slate-300 hover:text-white hover:border-slate-600 transition"
              title="Refresh Dashboard"
            >
              <RefreshCw className="w-5 h-5" />
            </button>
            <button
              onClick={handleQuickLaunchMock}
              disabled={launching}
              className="flex items-center space-x-2 px-4 py-2.5 rounded-xl bg-gradient-to-r from-cyan-500 to-blue-600 hover:from-cyan-400 hover:to-blue-500 text-white font-medium text-sm shadow-lg shadow-cyan-500/20 transition disabled:opacity-50"
            >
              <Play className="w-4 h-4 fill-white" />
              <span>{launching ? 'Executing...' : 'Run Mock Scan (demo.internal)'}</span>
            </button>
          </div>
        </div>
      </div>

      {launchMsg && (
        <div className="p-4 rounded-xl bg-cyan-500/10 border border-cyan-500/30 text-cyan-300 flex items-center space-x-3 font-mono text-sm">
          <RefreshCw className="w-4 h-4 animate-spin" />
          <span>{launchMsg}</span>
        </div>
      )}

      {error && (
        <div className="p-4 rounded-xl bg-rose-500/10 border border-rose-500/30 text-rose-300 flex items-center space-x-3 text-sm">
          <AlertCircle className="w-5 h-5 flex-shrink-0" />
          <span>{error}</span>
        </div>
      )}

      {/* Metric Cards Grid */}
      <div className="grid grid-cols-1 sm:grid-cols-2 lg:grid-cols-4 gap-4 sm:gap-6">
        <div 
          onClick={() => onNavigate('assets')}
          className="glass-panel-interactive p-6 rounded-2xl cursor-pointer"
        >
          <div className="flex items-center justify-between">
            <span className="text-xs font-medium text-slate-400 uppercase tracking-wider">Discovered Assets</span>
            <div className="p-2 bg-indigo-500/10 rounded-lg text-indigo-400">
              <Database className="w-5 h-5" />
            </div>
          </div>
          <div className="mt-4 flex items-baseline justify-between">
            <span className="text-3xl font-extrabold text-white font-mono">{stats?.assets_count ?? 0}</span>
            <span className="text-xs text-indigo-400 font-medium">Systems / Hosts</span>
          </div>
        </div>

        <div 
          onClick={() => onNavigate('assets')}
          className="glass-panel-interactive p-6 rounded-2xl cursor-pointer"
        >
          <div className="flex items-center justify-between">
            <span className="text-xs font-medium text-slate-400 uppercase tracking-wider">Active Services</span>
            <div className="p-2 bg-sky-500/10 rounded-lg text-sky-400">
              <Network className="w-5 h-5" />
            </div>
          </div>
          <div className="mt-4 flex items-baseline justify-between">
            <span className="text-3xl font-extrabold text-white font-mono">{stats?.services_count ?? 0}</span>
            <span className="text-xs text-sky-400 font-medium">Ports & Endpoints</span>
          </div>
        </div>

        <div 
          onClick={() => onNavigate('findings')}
          className="glass-panel-interactive p-6 rounded-2xl cursor-pointer"
        >
          <div className="flex items-center justify-between">
            <span className="text-xs font-medium text-slate-400 uppercase tracking-wider">Crypto Findings</span>
            <div className="p-2 bg-cyan-500/10 rounded-lg text-cyan-400">
              <KeyRound className="w-5 h-5" />
            </div>
          </div>
          <div className="mt-4 flex items-baseline justify-between">
            <span className="text-3xl font-extrabold text-white font-mono">{stats?.findings_count ?? 0}</span>
            <span className="text-xs text-cyan-400 font-medium">Observations</span>
          </div>
        </div>

        <div 
          onClick={() => onNavigate('scans')}
          className="glass-panel-interactive p-6 rounded-2xl cursor-pointer"
        >
          <div className="flex items-center justify-between">
            <span className="text-xs font-medium text-slate-400 uppercase tracking-wider">Total Scan Jobs</span>
            <div className="p-2 bg-emerald-500/10 rounded-lg text-emerald-400">
              <Play className="w-5 h-5" />
            </div>
          </div>
          <div className="mt-4 flex items-baseline justify-between">
            <span className="text-3xl font-extrabold text-white font-mono">{stats?.scan_jobs_count ?? 0}</span>
            <span className="text-xs text-emerald-400 font-medium">Executions</span>
          </div>
        </div>
      </div>

      {/* Distribution Charts Section */}
      <div className="grid grid-cols-1 lg:grid-cols-3 gap-6">
        {/* Algorithm Distribution Breakdown */}
        <div className="lg:col-span-2 glass-panel p-6 rounded-2xl space-y-6">
          <div className="flex items-center justify-between border-b border-slate-800 pb-4">
            <div>
              <h2 className="text-lg font-bold text-white">Cryptographic Algorithm Distribution</h2>
              <p className="text-xs text-slate-400">Inventory counts across algorithm families</p>
            </div>
            <span className="text-xs font-mono text-cyan-400 bg-cyan-500/10 px-2.5 py-1 rounded-md border border-cyan-500/20">
              Real-time DB Counts
            </span>
          </div>

          <div className="space-y-3">
            {Object.entries(algoDist).map(([algo, count]) => {
              const pct = maxAlgoCount > 0 ? (count / maxAlgoCount) * 100 : 0;
              const isPqc = algo.includes('ML-KEM') || algo.includes('ML-DSA');
              return (
                <div key={algo} className="space-y-1">
                  <div className="flex justify-between text-xs font-mono">
                    <span className={`font-semibold ${isPqc ? 'text-emerald-400' : 'text-slate-300'}`}>
                      {algo} {isPqc && '(PQC Standard)'}
                    </span>
                    <span className="text-slate-400">{count} findings</span>
                  </div>
                  <div className="w-full h-2.5 bg-slate-900 rounded-full overflow-hidden border border-slate-800">
                    <div
                      className={`h-full rounded-full transition-all duration-500 ${
                        isPqc
                          ? 'bg-gradient-to-r from-emerald-500 to-teal-400'
                          : count > 0
                          ? 'bg-gradient-to-r from-cyan-500 to-blue-500'
                          : 'bg-slate-800'
                      }`}
                      style={{ width: `${pct}%` }}
                    />
                  </div>
                </div>
              );
            })}
          </div>
        </div>

        {/* Scan Status Distribution */}
        <div className="glass-panel p-6 rounded-2xl space-y-6 flex flex-col justify-between">
          <div>
            <div className="flex items-center justify-between border-b border-slate-800 pb-4 mb-6">
              <h2 className="text-lg font-bold text-white">Scan Job Status</h2>
              <span className="text-xs text-slate-400 font-mono">{totalScans} Total</span>
            </div>

            <div className="space-y-4">
              {Object.entries(scanDist).map(([status, count]) => {
                let badgeStyle = 'bg-slate-800 text-slate-400';
                if (status === 'Completed') badgeStyle = 'bg-emerald-500/10 text-emerald-400 border border-emerald-500/30';
                if (status === 'Running') badgeStyle = 'bg-cyan-500/10 text-cyan-400 border border-cyan-500/30 animate-pulse';
                if (status === 'Pending') badgeStyle = 'bg-amber-500/10 text-amber-400 border border-amber-500/30';
                if (status === 'Failed') badgeStyle = 'bg-rose-500/10 text-rose-400 border border-rose-500/30';

                return (
                  <div key={status} className="flex items-center justify-between p-3 rounded-xl bg-slate-900/50 border border-slate-800">
                    <div className="flex items-center space-x-3">
                      <span className={`px-2.5 py-1 rounded-lg text-xs font-mono font-semibold ${badgeStyle}`}>
                        {status}
                      </span>
                    </div>
                    <span className="text-base font-bold font-mono text-white">{count}</span>
                  </div>
                );
              })}
            </div>
          </div>

          <div className="pt-4 border-t border-slate-800">
            <button
              onClick={() => onNavigate('targets')}
              className="w-full py-2.5 rounded-xl border border-slate-700 bg-slate-900 text-slate-300 hover:text-white hover:border-cyan-500/40 text-xs font-medium transition flex items-center justify-center space-x-2"
            >
              <span>Manage Authorized Targets</span>
            </button>
          </div>
        </div>
      </div>
    </div>
  );
};
