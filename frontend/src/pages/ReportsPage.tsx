import React, { useEffect, useState } from 'react';
import { fetchRemediationReport, downloadRemediationMarkdown, downloadCycloneDXCBOM, downloadInventoryArchive, clearAllScans } from '../services/api';
import { FileDown, AlertTriangle, CheckCircle2, RefreshCw, Cpu, BookOpen, Download, Trash2, Shield } from 'lucide-react';

import { PageHeader } from '../components/common/PageHeader';
import { InstanceReportModal } from '../components/reports/InstanceReportModal';
import { useInstanceReport } from '../components/reports/useInstanceReport';

export const ReportsPage: React.FC = () => {
  const { selectedAssetId, openReport, closeReport } = useInstanceReport();
  const [report, setReport] = useState<any>(null);
  const [loading, setLoading] = useState<boolean>(true);
  const [error, setError] = useState<string | null>(null);
  const [showClearModal, setShowClearModal] = useState<boolean>(false);
  const [actionSuccess, setActionSuccess] = useState<string | null>(null);

  const loadReport = async () => {
    try {
      setLoading(true);
      const data = await fetchRemediationReport();
      setReport(data);
    } catch (err: any) {
      setError(err.message || 'Failed to load report');
    } finally {
      setLoading(false);
    }
  };

  const handleClearHistory = async () => {
    try {
      setError(null);
      const res = await clearAllScans();
      setShowClearModal(false);
      setActionSuccess(res.message);
      loadReport();
      setTimeout(() => setActionSuccess(null), 4000);
    } catch (err: any) {
      setError(err.message || 'Failed to clear scan history');
    }
  };

  useEffect(() => {
    loadReport();
  }, []);

  if (loading) {
    return (
      <div className="p-12 text-center text-slate-400 font-mono flex items-center justify-center space-x-3">
        <RefreshCw className="w-5 h-5 animate-spin text-cyan-400" />
        <span>Evaluating PQC migration risks and generating remediation document...</span>
      </div>
    );
  }

  const summary = report?.summary || {};
  const vulns = report?.vulnerabilities || [];

  return (
    <div className="space-y-6">
      <PageHeader
        title="PQC Migration Reports & Documents"
        description="Download audit report documents, export CycloneDX 1.6 Cryptographic Bill of Materials (CBOM), or review remediation roadmaps."
        icon={BookOpen}
        breadcrumbs={[{ label: 'Reports' }, { label: 'Remediation Roadmap' }]}
        actions={
          <div className="flex items-center space-x-2">
            <button
              onClick={() => downloadRemediationMarkdown()}
              className="px-3.5 py-2 rounded-xl bg-cyan-500 hover:bg-cyan-400 text-slate-950 font-semibold text-xs font-mono transition flex items-center space-x-1.5 shadow-lg shadow-cyan-500/20"
            >
              <Download className="w-3.5 h-3.5" />
              <span>Download Report (.md)</span>
            </button>
            <button
              onClick={() => downloadCycloneDXCBOM()}
              className="px-3.5 py-2 rounded-xl bg-emerald-500 hover:bg-emerald-400 text-slate-950 font-semibold text-xs font-mono transition flex items-center space-x-1.5 shadow-lg shadow-emerald-500/20"
            >
              <FileDown className="w-3.5 h-3.5" />
              <span>Export CBOM 1.6 (.json)</span>
            </button>
            <button
              onClick={() => downloadInventoryArchive()}
              className="px-3.5 py-2 rounded-xl bg-indigo-600 hover:bg-indigo-500 text-white font-semibold text-xs font-mono transition flex items-center space-x-1.5 shadow-lg shadow-indigo-600/20"
            >
              <Download className="w-3.5 h-3.5" />
              <span>Export Archive (.json)</span>
            </button>
            <button
              onClick={() => setShowClearModal(true)}
              className="p-2 rounded-xl bg-rose-500/10 hover:bg-rose-500/20 text-rose-400 border border-rose-500/30 transition"
              title="Clear all scan history"
            >
              <Trash2 className="w-4 h-4" />
            </button>
          </div>
        }
      />

      {actionSuccess && (
        <div className="p-4 rounded-xl bg-emerald-500/10 border border-emerald-500/30 text-emerald-300 flex items-center space-x-2 text-xs font-mono">
          <CheckCircle2 className="w-4 h-4 text-emerald-400 flex-shrink-0" />
          <span>{actionSuccess}</span>
        </div>
      )}

      {error && (
        <div className="p-4 rounded-xl bg-rose-500/10 border border-rose-500/30 text-rose-300 flex items-center space-x-2 text-xs font-mono">
          <AlertTriangle className="w-4 h-4 text-rose-400 flex-shrink-0" />
          <span>{error}</span>
        </div>
      )}

      {/* Confirmation Modal */}
      {showClearModal && (
        <div className="fixed inset-0 z-50 bg-slate-950/80 backdrop-blur-sm flex items-center justify-center p-4">
          <div className="glass-panel p-6 rounded-2xl max-w-md w-full border border-slate-800 space-y-4">
            <div className="flex items-center space-x-3 text-rose-400">
              <AlertTriangle className="w-6 h-6 flex-shrink-0" />
              <h3 className="text-lg font-bold text-white">Clear All Reports & Findings?</h3>
            </div>
            <p className="text-slate-300 text-sm leading-relaxed">
              This action will reset report findings and clear previous scan executions from the database.
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
                onClick={handleClearHistory}
                className="px-4 py-2 rounded-xl bg-rose-600 hover:bg-rose-500 text-white font-medium text-xs transition"
              >
                Clear History
              </button>
            </div>
          </div>
        </div>
      )}

      {/* Summary Cards */}
      <div className="grid grid-cols-1 sm:grid-cols-2 lg:grid-cols-5 gap-4">
        <div className="glass-panel p-4 rounded-2xl">
          <span className="text-xs text-slate-400 font-mono">Critical Flaws</span>
          <div className="text-2xl font-bold font-mono text-rose-400 mt-1">{summary.severity_counts?.CRITICAL || 0}</div>
        </div>
        <div className="glass-panel p-4 rounded-2xl">
          <span className="text-xs text-slate-400 font-mono">High Risk</span>
          <div className="text-2xl font-bold font-mono text-amber-400 mt-1">{summary.severity_counts?.HIGH || 0}</div>
        </div>
        <div className="glass-panel p-4 rounded-2xl">
          <span className="text-xs text-slate-400 font-mono">Medium Risk</span>
          <div className="text-2xl font-bold font-mono text-sky-400 mt-1">{summary.severity_counts?.MEDIUM || 0}</div>
        </div>
        <div className="glass-panel p-4 rounded-2xl">
          <span className="text-xs text-slate-400 font-mono">Low / Review</span>
          <div className="text-2xl font-bold font-mono text-slate-300 mt-1">{summary.severity_counts?.LOW || 0}</div>
        </div>
        <div className="glass-panel p-4 rounded-2xl">
          <span className="text-xs text-slate-400 font-mono">PQC Compliant / Safe</span>
          <div className="text-2xl font-bold font-mono text-emerald-400 mt-1">{summary.severity_counts?.INFO || 0}</div>
        </div>
      </div>

      {/* Vulnerabilities & Mitigation Cards */}
      <div className="space-y-4">
        <h2 className="text-lg font-bold text-white flex items-center space-x-2">
          <BookOpen className="w-5 h-5 text-cyan-400" />
          <span>Discovered Flaws & Actionable Mitigation Strategies</span>
        </h2>

        {vulns.length === 0 ? (
          <div className="glass-panel p-12 rounded-2xl text-center space-y-3">
            <CheckCircle2 className="w-12 h-12 text-emerald-400 mx-auto" />
            <h3 className="text-lg font-bold text-white">Zero Quantum Flaws Found</h3>
            <p className="text-slate-400 text-sm">Run discovery scans against target hosts, code, or dependencies to evaluate vulnerabilities.</p>
          </div>
        ) : (
          vulns.map((v: any, idx: number) => {
            let sevBadge = 'bg-slate-800 text-slate-300 border-slate-700';
            if (v.severity === 'CRITICAL') sevBadge = 'bg-rose-500/10 text-rose-400 border-rose-500/30';
            if (v.severity === 'HIGH') sevBadge = 'bg-amber-500/10 text-amber-400 border-amber-500/30';
            if (v.severity === 'MEDIUM') sevBadge = 'bg-sky-500/10 text-sky-400 border-sky-500/30';
            if (v.severity === 'INFO') sevBadge = 'bg-emerald-500/10 text-emerald-400 border-emerald-500/30';

            return (
              <div key={idx} className="glass-panel p-6 rounded-2xl space-y-4 border border-slate-800 hover:border-slate-700 transition">
                <div className="flex flex-col sm:flex-row sm:items-center justify-between gap-2 border-b border-slate-800 pb-4">
                  <div className="flex items-center space-x-3">
                    <span className={`px-2.5 py-1 rounded-full text-xs font-mono border font-semibold ${sevBadge}`}>
                      {v.severity}
                    </span>
                    <h3 className="text-lg font-bold text-white font-mono">{v.raw_algorithm}</h3>
                    <span className="text-xs font-mono text-slate-400">on <strong className="text-slate-200">{v.asset}</strong></span>
                  </div>
                  <div className="flex items-center space-x-2">
                    {v.asset_id && (
                      <button
                        onClick={() => openReport(v.asset_id)}
                        className="px-2.5 py-1 rounded bg-cyan-500/10 hover:bg-cyan-500/20 text-cyan-400 border border-cyan-500/20 text-xs font-mono flex items-center space-x-1"
                      >
                        <Shield className="w-3.5 h-3.5" />
                        <span>Inspect Report</span>
                      </button>
                    )}
                    <span className="text-xs font-mono text-cyan-400 bg-cyan-500/10 px-2.5 py-1 rounded-md border border-cyan-500/20">
                      {v.cnsa_timeline}
                    </span>
                  </div>
                </div>

                <div className="grid grid-cols-1 md:grid-cols-2 gap-4 text-xs font-mono">
                  <div className="p-4 rounded-xl bg-slate-950/60 border border-slate-800 space-y-2">
                    <span className="text-rose-400 font-bold flex items-center space-x-1">
                      <AlertTriangle className="w-4 h-4" />
                      <span>Cryptographic Flaw Description</span>
                    </span>
                    <p className="text-slate-300 leading-relaxed font-sans">{v.flaw_description}</p>
                  </div>

                  <div className="p-4 rounded-xl bg-slate-950/60 border border-slate-800 space-y-2">
                    <span className="text-emerald-400 font-bold flex items-center space-x-1">
                      <Cpu className="w-4 h-4" />
                      <span>Technical Mitigation & PQC Replacement</span>
                    </span>
                    <p className="text-slate-300 leading-relaxed font-sans">{v.mitigation_strategy}</p>
                    <div className="pt-2 text-cyan-300 font-mono">
                      Target Replacement: <span className="font-bold underline">{v.recommended_pqc_replacement}</span>
                    </div>
                  </div>
                </div>

                <div className="text-xs font-mono text-slate-400">
                  <span>Location: <code className="text-slate-300">{v.location}</code></span>
                </div>
              </div>
            );
          })
        )}
      </div>

      {/* Shared Instance Report Modal */}
      <InstanceReportModal assetId={selectedAssetId} onClose={closeReport} />
    </div>
  );
};
