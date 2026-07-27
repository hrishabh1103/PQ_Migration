import React, { useEffect, useState } from 'react';
import { AuthorizedTarget, TargetType } from '../types';
import { fetchTargets, createTarget, createScan } from '../services/api';
import { Target, Plus, Play, CheckCircle, XCircle, RefreshCw, AlertCircle } from 'lucide-react';

interface TargetsPageProps {
  onNavigateScans: () => void;
}

export const TargetsPage: React.FC<TargetsPageProps> = ({ onNavigateScans }) => {
  const [targets, setTargets] = useState<AuthorizedTarget[]>([]);
  const [loading, setLoading] = useState<boolean>(true);
  const [error, setError] = useState<string | null>(null);

  // Modal State
  const [isModalOpen, setIsModalOpen] = useState<boolean>(false);
  const [name, setName] = useState<string>('Internal Gateway');
  const [targetType, setTargetType] = useState<TargetType>('HOSTNAME');
  const [targetValue, setTargetValue] = useState<string>('demo.internal');
  const [environment, setEnvironment] = useState<string>('DEVELOPMENT');
  const [creating, setCreating] = useState<boolean>(false);

  const loadTargets = async () => {
    try {
      setLoading(true);
      const data = await fetchTargets();
      setTargets(data);
    } catch (err: any) {
      setError(err.message || 'Failed to load targets');
    } finally {
      setLoading(false);
    }
  };

  useEffect(() => {
    loadTargets();
  }, []);

  const handleCreateTarget = async (e: React.FormEvent) => {
    e.preventDefault();
    try {
      setCreating(true);
      await createTarget({
        name,
        target_type: targetType,
        target_value: targetValue,
        is_authorized: true,
        environment
      });
      setIsModalOpen(false);
      loadTargets();
    } catch (err: any) {
      setError(err.message || 'Error creating target');
    } finally {
      setCreating(false);
    }
  };

  const handleTriggerScan = async (targetId: string) => {
    try {
      await createScan(targetId, ['mock-scanner']);
      onNavigateScans();
    } catch (err: any) {
      setError(`Failed to trigger scan: ${err.message}`);
    }
  };

  return (
    <div className="space-y-6">
      {/* Header */}
      <div className="flex flex-col sm:flex-row sm:items-center justify-between gap-4 pb-4 border-b border-slate-800">
        <div>
          <h1 className="text-2xl font-bold text-white flex items-center space-x-3">
            <Target className="w-6 h-6 text-cyan-400" />
            <span>Authorized Scan Targets</span>
          </h1>
          <p className="text-slate-400 text-sm mt-1">
            Explicitly approved target scopes and endpoints authorized for discovery scans.
          </p>
        </div>
        <button
          onClick={() => setIsModalOpen(true)}
          className="flex items-center space-x-2 px-4 py-2.5 rounded-xl bg-cyan-500 hover:bg-cyan-400 text-slate-950 font-semibold text-sm transition shadow-lg shadow-cyan-500/20"
        >
          <Plus className="w-4 h-4" />
          <span>Register Target</span>
        </button>
      </div>

      {error && (
        <div className="p-4 rounded-xl bg-rose-500/10 border border-rose-500/30 text-rose-300 flex items-center space-x-3 text-sm">
          <AlertCircle className="w-5 h-5 flex-shrink-0" />
          <span>{error}</span>
        </div>
      )}

      {loading ? (
        <div className="p-12 text-center text-slate-400 font-mono flex items-center justify-center space-x-3">
          <RefreshCw className="w-5 h-5 animate-spin text-cyan-400" />
          <span>Loading authorized targets...</span>
        </div>
      ) : targets.length === 0 ? (
        <div className="glass-panel p-12 rounded-2xl text-center space-y-4">
          <Target className="w-12 h-12 text-slate-600 mx-auto" />
          <h3 className="text-lg font-bold text-slate-300">No Authorized Targets Registered</h3>
          <p className="text-slate-400 text-sm max-w-md mx-auto">
            Register your first target (e.g. <code className="text-cyan-400 font-mono">demo.internal</code>) to start discovery scanning.
          </p>
          <button
            onClick={() => setIsModalOpen(true)}
            className="px-4 py-2 bg-cyan-500 text-slate-950 rounded-xl font-medium text-sm hover:bg-cyan-400 transition"
          >
            Register Demo Target
          </button>
        </div>
      ) : (
        <div className="glass-panel rounded-2xl overflow-hidden">
          <div className="overflow-x-auto">
            <table className="w-full text-left border-collapse">
              <thead>
                <tr className="border-b border-slate-800 bg-slate-900/50 text-slate-400 text-xs font-mono uppercase">
                  <th className="p-4">Target Name</th>
                  <th className="p-4">Type</th>
                  <th className="p-4">Value / Address</th>
                  <th className="p-4">Authorization</th>
                  <th className="p-4">Environment</th>
                  <th className="p-4 text-right">Actions</th>
                </tr>
              </thead>
              <tbody className="divide-y divide-slate-800 text-sm">
                {targets.map((t) => (
                  <tr key={t.id} className="hover:bg-slate-900/40 transition">
                    <td className="p-4 font-semibold text-white">{t.name}</td>
                    <td className="p-4 font-mono text-xs text-cyan-400">{t.target_type}</td>
                    <td className="p-4 font-mono text-slate-300">{t.target_value}</td>
                    <td className="p-4">
                      {t.is_authorized ? (
                        <span className="inline-flex items-center space-x-1.5 px-2.5 py-1 rounded-full text-xs font-medium bg-emerald-500/10 text-emerald-400 border border-emerald-500/30">
                          <CheckCircle className="w-3.5 h-3.5" />
                          <span>Authorized</span>
                        </span>
                      ) : (
                        <span className="inline-flex items-center space-x-1.5 px-2.5 py-1 rounded-full text-xs font-medium bg-rose-500/10 text-rose-400 border border-rose-500/30">
                          <XCircle className="w-3.5 h-3.5" />
                          <span>Revoked</span>
                        </span>
                      )}
                    </td>
                    <td className="p-4">
                      <span className="px-2.5 py-1 rounded-md text-xs font-mono bg-slate-800 text-slate-300 border border-slate-700">
                        {t.environment}
                      </span>
                    </td>
                    <td className="p-4 text-right">
                      <button
                        onClick={() => handleTriggerScan(t.id)}
                        className="inline-flex items-center space-x-1.5 px-3 py-1.5 rounded-lg bg-cyan-500/10 text-cyan-400 border border-cyan-500/30 hover:bg-cyan-500/20 text-xs font-medium transition"
                      >
                        <Play className="w-3.5 h-3.5 fill-cyan-400" />
                        <span>Run Scan</span>
                      </button>
                    </td>
                  </tr>
                ))}
              </tbody>
            </table>
          </div>
        </div>
      )}

      {/* Modal Dialog */}
      {isModalOpen && (
        <div className="fixed inset-0 z-50 flex items-center justify-center p-4 bg-slate-950/80 backdrop-blur-sm">
          <div className="glass-panel p-6 sm:p-8 rounded-2xl max-w-md w-full border border-slate-800 space-y-6 shadow-2xl">
            <h2 className="text-xl font-bold text-white">Register Authorized Scan Target</h2>
            <form onSubmit={handleCreateTarget} className="space-y-4">
              <div>
                <label className="block text-xs font-mono text-slate-400 mb-1">Target Name</label>
                <input
                  type="text"
                  required
                  value={name}
                  onChange={(e) => setName(e.target.value)}
                  className="w-full px-3 py-2 rounded-xl bg-slate-900 border border-slate-800 text-white focus:outline-none focus:border-cyan-500 text-sm font-sans"
                />
              </div>

              <div>
                <label className="block text-xs font-mono text-slate-400 mb-1">Target Type</label>
                <select
                  value={targetType}
                  onChange={(e) => setTargetType(e.target.value as TargetType)}
                  className="w-full px-3 py-2 rounded-xl bg-slate-900 border border-slate-800 text-white focus:outline-none focus:border-cyan-500 text-sm font-sans"
                >
                  <option value="HOSTNAME">HOSTNAME</option>
                  <option value="IP_RANGE">IP_RANGE</option>
                  <option value="CIDR">CIDR</option>
                  <option value="URL">URL</option>
                  <option value="REPOSITORY">REPOSITORY</option>
                  <option value="CERT_STORE">CERT_STORE</option>
                </select>
              </div>

              <div>
                <label className="block text-xs font-mono text-slate-400 mb-1">Target Value / Domain</label>
                <input
                  type="text"
                  required
                  value={targetValue}
                  onChange={(e) => setTargetValue(e.target.value)}
                  placeholder="e.g. demo.internal"
                  className="w-full px-3 py-2 rounded-xl bg-slate-900 border border-slate-800 text-white focus:outline-none focus:border-cyan-500 text-sm font-mono"
                />
              </div>

              <div>
                <label className="block text-xs font-mono text-slate-400 mb-1">Environment</label>
                <select
                  value={environment}
                  onChange={(e) => setEnvironment(e.target.value)}
                  className="w-full px-3 py-2 rounded-xl bg-slate-900 border border-slate-800 text-white focus:outline-none focus:border-cyan-500 text-sm font-sans"
                >
                  <option value="DEVELOPMENT">DEVELOPMENT</option>
                  <option value="STAGING">STAGING</option>
                  <option value="PRODUCTION">PRODUCTION</option>
                </select>
              </div>

              <div className="flex justify-end space-x-3 pt-4 border-t border-slate-800">
                <button
                  type="button"
                  onClick={() => setIsModalOpen(false)}
                  className="px-4 py-2 rounded-xl text-slate-400 hover:text-white text-sm"
                >
                  Cancel
                </button>
                <button
                  type="submit"
                  disabled={creating}
                  className="px-4 py-2 rounded-xl bg-cyan-500 hover:bg-cyan-400 text-slate-950 font-semibold text-sm transition"
                >
                  {creating ? 'Registering...' : 'Save Target'}
                </button>
              </div>
            </form>
          </div>
        </div>
      )}
    </div>
  );
};
