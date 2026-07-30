import React, { useEffect, useState } from 'react';
import { CryptoFinding } from '../types';
import { fetchFindings } from '../services/api';
import { FileText, KeyRound, Hash, RefreshCw, AlertCircle, Eye } from 'lucide-react';

import { PageHeader } from '../components/common/PageHeader';

export const FindingsPage: React.FC = () => {
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
        <div className="p-12 text-center text-slate-400 font-mono flex items-center justify-center space-x-3">
          <RefreshCw className="w-5 h-5 animate-spin text-cyan-400" />
          <span>Loading cryptographic findings...</span>
        </div>
      ) : findings.length === 0 ? (
        <div className="glass-panel p-12 rounded-2xl text-center space-y-4">
          <FileText className="w-12 h-12 text-slate-600 mx-auto" />
          <h3 className="text-lg font-bold text-slate-300">No Cryptographic Findings Recorded</h3>
          <p className="text-slate-400 text-sm max-w-md mx-auto">
            Execute a discovery scan job to populate the cryptographic inventory.
          </p>
        </div>
      ) : (
        <div className="glass-panel rounded-2xl overflow-hidden">
          <div className="overflow-x-auto">
            <table className="w-full text-left border-collapse">
              <thead>
                <tr className="border-b border-slate-800 bg-slate-900/50 text-slate-400 text-xs font-mono uppercase">
                  <th className="p-4">Observed Algorithm</th>
                  <th className="p-4">Normalized Standard</th>
                  <th className="p-4">Quantum Safety Status</th>
                  <th className="p-4">Finding Type</th>
                  <th className="p-4">Location Identifier</th>
                  <th className="p-4">Scanner & Hash</th>
                  <th className="p-4 text-right">Evidence</th>
                </tr>
              </thead>
              <tbody className="divide-y divide-slate-800 text-sm">
                {findings.map((f) => {
                  const algo = f.normalized_algorithm;
                  const status = algo?.quantum_safety_status || 'UNKNOWN';

                  let statusBadge = 'bg-slate-800 text-slate-300 border-slate-700';
                  if (status === 'QUANTUM_VULNERABLE') statusBadge = 'bg-rose-500/10 text-rose-400 border-rose-500/30';
                  if (status === 'PQC_STANDARDIZED') statusBadge = 'bg-emerald-500/10 text-emerald-400 border-emerald-500/30';
                  if (status === 'PQC_CANDIDATE') statusBadge = 'bg-teal-500/10 text-teal-300 border-teal-500/30';
                  if (status === 'HYBRID') statusBadge = 'bg-indigo-500/10 text-indigo-300 border-indigo-500/30';
                  if (status === 'SYMMETRIC' || status === 'HASH') statusBadge = 'bg-cyan-500/10 text-cyan-400 border-cyan-500/30';

                  return (
                    <tr key={f.id} className="hover:bg-slate-900/40 transition">
                      <td className="p-4">
                        <div className="flex items-center space-x-2 font-mono font-bold text-white">
                          <KeyRound className="w-4 h-4 text-cyan-400" />
                          <span>{f.raw_algorithm_name}</span>
                        </div>
                      </td>
                      <td className="p-4 font-mono text-xs text-slate-300">
                        {algo ? (
                          <div>
                            <span className="font-semibold text-cyan-300">{algo.canonical_id}</span>
                            <div className="text-[11px] text-slate-400">{algo.canonical_family} {algo.implementation_variant ? `(${algo.implementation_variant})` : ''}</div>
                          </div>
                        ) : (
                          <span className="text-slate-500">Unnormalized</span>
                        )}
                      </td>
                      <td className="p-4">
                        <span className={`px-2.5 py-1 rounded-full text-xs font-mono border ${statusBadge}`}>
                          {status}
                        </span>
                      </td>
                      <td className="p-4 font-mono text-xs text-slate-400">{f.finding_type}</td>
                      <td className="p-4 font-mono text-xs text-slate-300">{f.location_identifier}</td>
                      <td className="p-4 font-mono text-xs">
                        <div className="text-slate-300">{f.scanner_id} v{f.scanner_version}</div>
                        <div className="text-[11px] text-slate-400 flex items-center space-x-1 mt-0.5">
                          <Hash className="w-3 h-3 text-cyan-400" />
                          <span>{f.evidence_hash.substring(0, 12)}...</span>
                        </div>
                      </td>
                      <td className="p-4 text-right">
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

            <div className="flex justify-end pt-4 border-t border-slate-800">
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
    </div>
  );
};
