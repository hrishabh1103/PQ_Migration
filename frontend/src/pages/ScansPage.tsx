import React, { useEffect, useState } from 'react';
import { ScanJob, AuthorizedTarget } from '../types';
import { fetchScans, fetchTargets, createScan, deleteScan, clearAllScans, downloadInventoryArchive } from '../services/api';
import { Play, RefreshCw, CheckCircle, Clock, XCircle, AlertCircle, Cpu, Trash2, Download, AlertTriangle, Shield } from 'lucide-react';
import { PageHeader } from '../components/common/PageHeader';
import { InstanceReportModal } from '../components/reports/InstanceReportModal';
import { useInstanceReport } from '../components/reports/useInstanceReport';

const AVAILABLE_SCANNERS = [
  { id: 'all', name: 'All Scanners (Complete Discovery)' },
  { id: 'tls-scanner', name: 'TLS & Network Scanner' },
  { id: 'certificate-scanner', name: 'X.509 Certificate Scanner' },
  { id: 'ssh-scanner', name: 'SSH Host & KEX Scanner' },
  { id: 'source-code-scanner', name: 'Source Code Crypto Scanner' },
  { id: 'dependency-scanner', name: 'Package Dependency Scanner' },
  { id: 'mock-scanner', name: 'Mock Development Scanner' },
];

export const ScansPage: React.FC = () => {
  const { selectedAssetId, openReport, closeReport } = useInstanceReport();
  const [scans, setScans] = useState<ScanJob[]>([]);
  const [targets, setTargets] = useState<AuthorizedTarget[]>([]);
  const [loading, setLoading] = useState<boolean>(true);
  const [error, setError] = useState<string | null>(null);
  const [selectedTargetId, setSelectedTargetId] = useState<string>('');
  const [selectedScannerId, setSelectedScannerId] = useState<string>('all');
  const [showClearModal, setShowClearModal] = useState<boolean>(false);
  const [actionSuccess, setActionSuccess] = useState<string | null>(null);

  const loadData = async () => {
    try {
      setLoading(true);
      const [scansData, targetsData] = await Promise.all([fetchScans(), fetchTargets()]);
      setScans(scansData);
      setTargets(targetsData);
      if (targetsData.length > 0 && !selectedTargetId) {
        setSelectedTargetId(targetsData[0].id);
      }
    } catch (err: any) {
      setError(err.message || 'Failed to load scan jobs');
    } finally {
      setLoading(false);
    }
  };

  useEffect(() => {
    loadData();
    const interval = setInterval(loadData, 4000);
    return () => clearInterval(interval);
  }, []);

  const handleLaunchScan = async () => {
    if (!selectedTargetId) return;
    try {
      const scanners = selectedScannerId === 'all' 
        ? ['tls-scanner', 'certificate-scanner', 'ssh-scanner', 'source-code-scanner', 'dependency-scanner', 'mock-scanner']
        : [selectedScannerId];
      await createScan(selectedTargetId, scanners);
      loadData();
    } catch (err: any) {
      setError(`Failed to trigger scan: ${err.message}`);
    }
  };

  const handleDeleteSingleScan = async (scanId: string) => {
    try {
      setError(null);
      await deleteScan(scanId);
      setActionSuccess(`Scan job ${scanId.substring(0, 8)} deleted.`);
      loadData();
      setTimeout(() => setActionSuccess(null), 3000);
    } catch (err: any) {
      setError(err.message || 'Failed to delete scan job');
    }
  };

  const handleConfirmClearAll = async () => {
    try {
      setError(null);
      const res = await clearAllScans();
      setShowClearModal(false);
      setActionSuccess(res.message);
      loadData();
      setTimeout(() => setActionSuccess(null), 4000);
    } catch (err: any) {
      setError(err.message || 'Failed to clear scan history');
    }
  };

  const getTargetName = (targetId: string) => {
    const t = targets.find((item) => item.id === targetId);
    return t ? t.name : targetId;
  };

  return (
    <div className="space-y-6">
      <PageHeader
        title="Scan Jobs & Executions"
        description="Real-time execution status, archive management, and history of discovery orchestrations."
        icon={Play}
        breadcrumbs={[{ label: 'Discovery' }, { label: 'Scans' }]}
        actions={
          <div className="flex flex-wrap items-center gap-3">
            <select
              value={selectedTargetId}
              onChange={(e) => setSelectedTargetId(e.target.value)}
              className="px-3 py-2 rounded-xl bg-slate-950 border border-slate-800 text-white text-xs font-mono focus:outline-none focus:border-cyan-500"
            >
              {targets.map((t) => (
                <option key={t.id} value={t.id}>
                  {t.name} ({t.target_value})
                </option>
              ))}
            </select>

            <select
              value={selectedScannerId}
              onChange={(e) => setSelectedScannerId(e.target.value)}
              className="px-3 py-2 rounded-xl bg-slate-950 border border-slate-800 text-cyan-400 text-xs font-mono focus:outline-none focus:border-cyan-500"
            >
              {AVAILABLE_SCANNERS.map((s) => (
                <option key={s.id} value={s.id}>
                  {s.name}
                </option>
              ))}
            </select>

            <button
              onClick={handleLaunchScan}
              disabled={!selectedTargetId}
              className="flex items-center space-x-2 px-4 py-2 rounded-xl bg-gradient-to-r from-cyan-500 to-blue-600 hover:from-cyan-400 hover:to-blue-500 text-white font-medium text-xs transition shadow-lg shadow-cyan-500/20 disabled:opacity-50"
            >
              <Play className="w-3.5 h-3.5 fill-white" />
              <span>Trigger Scan</span>
            </button>

            <button
              onClick={downloadInventoryArchive}
              className="flex items-center space-x-1.5 px-3 py-2 rounded-xl border border-slate-700 bg-slate-900 hover:border-cyan-500/40 text-slate-300 hover:text-white text-xs font-mono transition"
              title="Download full JSON archive of all targets, scans, and findings"
            >
              <Download className="w-3.5 h-3.5 text-cyan-400" />
              <span>Save Archive (.json)</span>
            </button>

            <button
              onClick={() => setShowClearModal(true)}
              disabled={scans.length === 0}
              className="flex items-center space-x-1.5 px-3 py-2 rounded-xl border border-rose-500/30 bg-rose-500/10 hover:bg-rose-500/20 text-rose-300 text-xs font-mono transition disabled:opacity-40"
              title="Clear all previous scan history and findings"
            >
              <Trash2 className="w-3.5 h-3.5 text-rose-400" />
              <span>Clear Scan History</span>
            </button>
          </div>
        }
      />

      {actionSuccess && (
        <div className="p-4 rounded-xl bg-emerald-500/10 border border-emerald-500/30 text-emerald-300 text-sm font-mono flex items-center space-x-2">
          <CheckCircle className="w-4 h-4 text-emerald-400 flex-shrink-0" />
          <span>{actionSuccess}</span>
        </div>
      )}

      {error && (
        <div className="p-4 rounded-xl bg-rose-500/10 border border-rose-500/30 text-rose-300 flex items-center space-x-3 text-sm">
          <AlertCircle className="w-5 h-5 flex-shrink-0" />
          <span>{error}</span>
        </div>
      )}

      {/* Confirmation Modal for Clear History */}
      {showClearModal && (
        <div className="fixed inset-0 z-50 bg-slate-950/80 backdrop-blur-sm flex items-center justify-center p-4">
          <div className="glass-panel p-6 rounded-2xl max-w-md w-full border border-slate-800 space-y-4">
            <div className="flex items-center space-x-3 text-rose-400">
              <AlertTriangle className="w-6 h-6 flex-shrink-0" />
              <h3 className="text-lg font-bold text-white">Clear All Scan History?</h3>
            </div>
            <p className="text-slate-300 text-sm leading-relaxed">
              This action will purge all previous scan execution logs and discovered findings from the database.
            </p>
            <div className="p-3 rounded-xl bg-slate-900 border border-slate-800 text-xs font-mono text-cyan-300">
              💡 Tip: Click <strong>"Download Backup Archive"</strong> below to save a copy before clearing.
            </div>
            <div className="flex flex-wrap items-center justify-end gap-3 pt-2">
              <button
                onClick={downloadInventoryArchive}
                className="px-3.5 py-2 rounded-xl bg-slate-900 border border-cyan-500/40 text-cyan-300 hover:text-white text-xs font-mono transition"
              >
                Download Backup Archive
              </button>
              <button
                onClick={() => setShowClearModal(false)}
                className="px-4 py-2 rounded-xl bg-slate-800 hover:bg-slate-700 text-slate-300 text-xs font-medium transition"
              >
                Cancel
              </button>
              <button
                onClick={handleConfirmClearAll}
                className="px-4 py-2 rounded-xl bg-rose-600 hover:bg-rose-500 text-white font-medium text-xs transition"
              >
                Clear History
              </button>
            </div>
          </div>
        </div>
      )}

      {loading && scans.length === 0 ? (
        <div className="p-12 text-center text-slate-400 font-mono flex items-center justify-center space-x-3">
          <RefreshCw className="w-5 h-5 animate-spin text-cyan-400" />
          <span>Fetching scan jobs...</span>
        </div>
      ) : scans.length === 0 ? (
        <div className="glass-panel p-12 rounded-2xl text-center space-y-4">
          <Play className="w-12 h-12 text-slate-600 mx-auto" />
          <h3 className="text-lg font-bold text-slate-300">No Scan Jobs Executed</h3>
          <p className="text-slate-400 text-sm max-w-md mx-auto">
            Select an authorized target and click "Trigger Scan" to start discovering assets.
          </p>
        </div>
      ) : (
        <div className="glass-panel rounded-2xl overflow-hidden">
          <div className="overflow-x-auto">
            <table className="w-full text-left border-collapse">
              <thead>
                <tr className="border-b border-slate-800 bg-slate-900/50 text-slate-400 text-xs font-mono uppercase">
                  <th className="p-4">Scan Job ID</th>
                  <th className="p-4">Authorized Target</th>
                  <th className="p-4">Requested Scanners</th>
                  <th className="p-4">Status</th>
                  <th className="p-4">Findings Summary</th>
                  <th className="p-4 text-right">Actions / Time</th>
                </tr>
              </thead>
              <tbody className="divide-y divide-slate-800 text-sm">
                {scans.map((s) => {
                  let statusBadge = (
                    <span className="inline-flex items-center space-x-1.5 px-2.5 py-1 rounded-full text-xs font-medium bg-slate-800 text-slate-400">
                      <Clock className="w-3.5 h-3.5" />
                      <span>Pending</span>
                    </span>
                  );
                  if (s.status === 'COMPLETED') {
                    statusBadge = (
                      <span className="inline-flex items-center space-x-1.5 px-2.5 py-1 rounded-full text-xs font-medium bg-emerald-500/10 text-emerald-400 border border-emerald-500/30">
                        <CheckCircle className="w-3.5 h-3.5" />
                        <span>Completed</span>
                      </span>
                    );
                  } else if (s.status === 'RUNNING') {
                    statusBadge = (
                      <span className="inline-flex items-center space-x-1.5 px-2.5 py-1 rounded-full text-xs font-medium bg-cyan-500/10 text-cyan-400 border border-cyan-500/30 animate-pulse">
                        <RefreshCw className="w-3.5 h-3.5 animate-spin" />
                        <span>Running</span>
                      </span>
                    );
                  } else if (s.status === 'FAILED') {
                    statusBadge = (
                      <span className="inline-flex items-center space-x-1.5 px-2.5 py-1 rounded-full text-xs font-medium bg-rose-500/10 text-rose-400 border border-rose-500/30">
                        <XCircle className="w-3.5 h-3.5" />
                        <span>Failed</span>
                      </span>
                    );
                  }

                  return (
                    <tr key={s.id} className="hover:bg-slate-900/40 transition">
                      <td className="p-4 font-mono text-xs text-cyan-400 font-semibold">{s.id.substring(0, 8)}...</td>
                      <td className="p-4 text-white font-medium">{getTargetName(s.target_id)}</td>
                      <td className="p-4 font-mono text-xs text-slate-300">
                        <div className="flex items-center space-x-1">
                          <Cpu className="w-3.5 h-3.5 text-cyan-400" />
                          <span>{(s.requested_scanners || []).join(', ')}</span>
                        </div>
                      </td>
                      <td className="p-4">{statusBadge}</td>
                      <td className="p-4 font-mono text-xs">
                        {s.stats_json?.findings_found !== undefined ? (
                          <div className="flex items-center space-x-3 text-slate-300">
                            <span className="text-indigo-400 font-semibold">{s.stats_json.assets_found ?? 0} assets</span>
                            <span className="text-sky-400 font-semibold">{s.stats_json.services_found ?? 0} services</span>
                            <span className="text-cyan-400 font-bold">{s.stats_json.findings_found ?? 0} findings</span>
                          </div>
                        ) : (
                          <span className="text-slate-500">In Progress...</span>
                        )}
                      </td>
                      <td className="p-4 text-right font-mono text-xs text-slate-400">
                        <div className="flex items-center justify-end space-x-3">
                          <span>{s.completed_at ? new Date(s.completed_at).toLocaleTimeString() : s.started_at ? new Date(s.started_at).toLocaleTimeString() : 'Queued'}</span>
                          {s.target_id && (
                            <button
                              onClick={() => openReport(s.target_id)}
                              className="px-2.5 py-1 rounded bg-cyan-500/10 hover:bg-cyan-500/20 text-cyan-400 border border-cyan-500/20 text-xs font-mono inline-flex items-center space-x-1"
                              title="Inspect target instance report"
                            >
                              <Shield className="w-3.5 h-3.5" />
                              <span>Report</span>
                            </button>
                          )}
                          <button
                            onClick={() => handleDeleteSingleScan(s.id)}
                            className="p-1.5 rounded-lg bg-slate-800 hover:bg-rose-500/20 text-slate-400 hover:text-rose-400 transition"
                            title="Delete this scan job"
                          >
                            <Trash2 className="w-3.5 h-3.5" />
                          </button>
                        </div>
                      </td>
                    </tr>
                  );
                })}
              </tbody>
            </table>
          </div>
        </div>
      )}

      {/* Shared Instance Report Modal */}
      <InstanceReportModal assetId={selectedAssetId} onClose={closeReport} />
    </div>
  );
};

