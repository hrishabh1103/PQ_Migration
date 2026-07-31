import React, { useEffect, useState } from 'react';
import { CryptoFinding } from '../types';
import { fetchFindings } from '../services/api';
import { FileText, KeyRound, RefreshCw, AlertCircle, Eye, Shield } from 'lucide-react';

import { PageHeader } from '../components/common/PageHeader';
import { InstanceReportModal } from '../components/reports/InstanceReportModal';
import { useInstanceReport } from '../components/reports/useInstanceReport';

export const FindingsPage: React.FC = () => {
  const { selectedAssetId, openReport, closeReport } = useInstanceReport();
  const [findings, setFindings] = useState<CryptoFinding[]>([]);
  const [loading, setLoading] = useState<boolean>(true);
  const [error, setError] = useState<string | null>(null);
  const [selectedFinding, setSelectedFinding] = useState<CryptoFinding | null>(null);

  const loadFindings = async () => {
    try {
      setLoading(true);
      setError(null);
      const data = await fetchFindings();
      setFindings(data);
    } catch (err: any) {
      setError(`Failed to fetch findings: ${err.message || err}. Ensure backend server is active at http://localhost:8000.`);
    } finally {
      setLoading(false);
    }
  };

  useEffect(() => {
    loadFindings();
  }, []);

  return (
    <div className="space-y-6">
      {/* Reusable Page Header */}
      <PageHeader
        title="Cryptographic Findings & Provenance"
        description="Factual observation records with evidence snippets, scanner source, location, and SHA-256 evidence hashes."
        icon={FileText}
        breadcrumbs={[{ label: 'Inventory' }, { label: 'Crypto Findings' }]}
        actions={
          <button
            onClick={loadFindings}
            className="p-2.5 rounded-xl border border-slate-700 bg-slate-800 text-slate-300 hover:text-white transition"
          >
            <RefreshCw className="w-4 h-4" />
          </button>
        }
      />

      {error && (
        <div className="p-4 rounded-xl bg-rose-500/10 border border-rose-500/30 text-rose-300 flex items-center space-x-3 text-sm">
          <AlertCircle className="w-5 h-5 flex-shrink-0" />
          <span>{error}</span>
        </div>
      )}

      {loading ? (
        <div className="p-12 text-center text-slate-500 font-mono flex items-center justify-center space-x-3">
          <RefreshCw className="w-5 h-5 animate-spin" />
          <span>Loading cryptographic findings...</span>
        </div>
      ) : findings.length === 0 ? (
        <div className="glass-panel p-12 text-center text-slate-400 rounded-2xl border border-slate-800 font-mono">
          No cryptographic findings recorded yet. Execute discovery scans or connectors to populate observations.
        </div>
      ) : (
        <div className="glass-panel rounded-2xl border border-slate-800 overflow-hidden shadow-xl">
          <div className="overflow-x-auto">
            <table className="w-full text-left border-collapse">
              <thead>
                <tr className="border-b border-slate-800 bg-slate-900/50 text-[11px] font-mono font-semibold uppercase tracking-wider text-slate-400">
                  <th className="p-4">Raw Algorithm</th>
                  <th className="p-4">Type</th>
                  <th className="p-4">Scanner Source</th>
                  <th className="p-4">Location Identifier</th>
                  <th className="p-4 text-right">Actions</th>
                </tr>
              </thead>
              <tbody className="divide-y divide-slate-800/60 text-xs font-mono text-slate-300">
                {findings.map((f) => {
                  return (
                    <tr key={f.id} className="hover:bg-slate-900/40 transition">
                      <td className="p-4 font-bold text-slate-100 flex items-center space-x-2">
                        <KeyRound className="w-4 h-4 text-cyan-400 flex-shrink-0" />
                        <span>{f.raw_algorithm_name}</span>
                      </td>
                      <td className="p-4 text-slate-400">
                        <span className="px-2 py-0.5 rounded bg-slate-800 text-[10px] font-mono text-slate-300 border border-slate-700">
                          {f.finding_type}
                        </span>
                      </td>
                      <td className="p-4 text-slate-400">
                        <span className="text-cyan-400">{f.scanner_id}</span> ({f.scanner_version})
                      </td>
                      <td className="p-4 text-slate-400 truncate max-w-xs" title={f.location_identifier}>
                        {f.location_identifier}
                      </td>
                      <td className="p-4 text-right space-x-2">
                        {f.asset_id && (
                          <button
                            onClick={() => openReport(f.asset_id)}
                            className="inline-flex items-center space-x-1 px-2.5 py-1.5 rounded-lg bg-cyan-500/10 text-cyan-400 hover:bg-cyan-500/20 border border-cyan-500/20 text-xs font-medium transition"
                          >
                            <Shield className="w-3.5 h-3.5" />
                            <span>Report</span>
                          </button>
                        )}
                        <button
                          onClick={() => setSelectedFinding(f)}
                          className="inline-flex items-center space-x-1.5 px-3 py-1.5 rounded-lg bg-slate-800 text-slate-300 hover:text-white border border-slate-700 hover:border-slate-600 text-xs font-medium transition"
                        >
                          <Eye className="w-3.5 h-3.5" />
                          <span>View Evidence</span>
                        </button>
                      </td>
                    </tr>
                  );
                })}
              </tbody>
            </table>
          </div>
        </div>
      )}

      {/* Evidence Modal */}
      {selectedFinding && (
        <div className="fixed inset-0 z-50 flex items-center justify-center p-4 bg-slate-950/80 backdrop-blur-sm">
          <div className="glass-panel p-6 sm:p-8 rounded-2xl max-w-2xl w-full border border-slate-800 space-y-6 shadow-2xl">
            <div className="flex items-center justify-between border-b border-slate-800 pb-4">
              <div>
                <span className="text-xs font-mono text-cyan-400 uppercase">Cryptographic Finding Provenance</span>
                <h2 className="text-lg font-bold text-white font-mono">{selectedFinding.raw_algorithm_name}</h2>
              </div>
              <button
                onClick={() => setSelectedFinding(null)}
                className="text-slate-400 hover:text-white text-sm"
              >
                ✕
              </button>
            </div>

            <div className="space-y-4 text-xs font-mono">
              <div className="grid grid-cols-2 gap-4 p-4 rounded-xl bg-slate-900/60 border border-slate-800">
                <div>
                  <span className="text-slate-500">Scanner Source:</span>
                  <div className="text-slate-200 font-bold">{selectedFinding.scanner_id} ({selectedFinding.scanner_version})</div>
                </div>
                <div>
                  <span className="text-slate-500">Confidence Level:</span>
                  <div className="text-emerald-400 font-bold">{selectedFinding.confidence}</div>
                </div>
                <div className="col-span-2">
                  <span className="text-slate-500">Location Identifier:</span>
                  <div className="text-slate-200">{selectedFinding.location_identifier}</div>
                </div>
                <div className="col-span-2">
                  <span className="text-slate-500">Evidence SHA-256 Hash:</span>
                  <div className="text-cyan-400">{selectedFinding.evidence_hash}</div>
                </div>
              </div>

              <div>
                <span className="text-slate-400 font-bold block mb-1">Sanitized Evidence Snippet</span>
                <pre className="p-4 rounded-xl bg-slate-950 border border-slate-800 text-slate-300 overflow-x-auto whitespace-pre-wrap">
                  {selectedFinding.evidence_snippet}
                </pre>
              </div>
            </div>

            <div className="flex justify-between items-center pt-4 border-t border-slate-800">
              {selectedFinding.asset_id ? (
                <button
                  onClick={() => {
                    const id = selectedFinding.asset_id;
                    setSelectedFinding(null);
                    openReport(id);
                  }}
                  className="px-3 py-1.5 rounded-xl bg-cyan-500/10 text-cyan-400 hover:bg-cyan-500/20 border border-cyan-500/20 text-xs font-medium flex items-center space-x-1.5"
                >
                  <Shield className="w-3.5 h-3.5" />
                  <span>Inspect Asset Instance Report</span>
                </button>
              ) : <div />}
              <button
                onClick={() => setSelectedFinding(null)}
                className="px-4 py-2 rounded-xl bg-slate-800 text-slate-300 hover:text-white text-xs font-medium"
              >
                Close
              </button>
            </div>
          </div>
        </div>
      )}

      {/* Shared Instance Report Modal */}
      <InstanceReportModal assetId={selectedAssetId} onClose={closeReport} />
    </div>
  );
};
