import React, { useEffect, useState } from 'react';
import { Shield, CheckCircle, AlertTriangle, XCircle, FileText, Download, Lock, ExternalLink, Activity, ArrowRight, RefreshCw, X } from 'lucide-react';

interface InstanceReportModalProps {
  assetId: string | null;
  onClose: () => void;
}

export const InstanceReportModal: React.FC<InstanceReportModalProps> = ({ assetId, onClose }) => {
  const [report, setReport] = useState<any | null>(null);
  const [loading, setLoading] = useState<boolean>(true);
  const [error, setError] = useState<string | null>(null);

  useEffect(() => {
    if (assetId) {
      fetchReport(assetId);
    }
  }, [assetId]);

  const fetchReport = async (id: string) => {
    setLoading(true);
    setError(null);
    try {
      const res = await fetch(`/api/v1/reports/instance/${id}`);
      if (res.ok) {
        const data = await res.json();
        setReport(data);
      } else {
        const err = await res.json();
        setError(err.detail || 'Failed to fetch instance report');
      }
    } catch (e: any) {
      setError(`Failed to connect to report engine: ${e}`);
    } finally {
      setLoading(false);
    }
  };

  if (!assetId) return null;

  const getRiskColor = (tier: string) => {
    switch (tier?.toUpperCase()) {
      case 'CRITICAL':
      case 'HIGH':
        return 'text-rose-400 bg-rose-500/10 border-rose-500/30';
      case 'MEDIUM':
        return 'text-amber-400 bg-amber-500/10 border-amber-500/30';
      default:
        return 'text-emerald-400 bg-emerald-500/10 border-emerald-500/30';
    }
  };

  const getBadgeStyle = (badge: string) => {
    switch (badge?.toUpperCase()) {
      case 'KEY EXCHANGE':
        return 'bg-blue-500/15 text-blue-400 border-blue-500/30';
      case 'CERTIFICATE':
        return 'bg-amber-500/15 text-amber-400 border-amber-500/30';
      case 'FORWARD SECRECY':
        return 'bg-purple-500/15 text-purple-400 border-purple-500/30';
      case 'EXPOSURE':
        return 'bg-emerald-500/15 text-emerald-400 border-emerald-500/30';
      case 'REGULATORY':
        return 'bg-indigo-500/15 text-indigo-400 border-indigo-500/30';
      case 'SIGNATURE':
        return 'bg-orange-500/15 text-orange-400 border-orange-500/30';
      default:
        return 'bg-slate-500/15 text-slate-300 border-slate-700';
    }
  };

  const downloadCBOM = () => {
    if (!report?.cyclonedx_cbom) return;
    const jsonStr = JSON.stringify(report.cyclonedx_cbom, null, 2);
    const blob = new Blob([jsonStr], { type: 'application/json' });
    const url = URL.createObjectURL(blob);
    const a = document.createElement('a');
    a.href = url;
    a.download = `cbom-1.6-${report.endpoint_name}.json`;
    a.click();
    URL.revokeObjectURL(url);
  };

  return (
    <div className="fixed inset-0 z-50 flex items-center justify-center p-4 bg-slate-950/80 backdrop-blur-md overflow-y-auto">
      <div className="relative w-full max-w-6xl bg-slate-900 border border-slate-800 rounded-2xl shadow-2xl overflow-hidden my-8 max-h-[90vh] flex flex-col">
        {/* Header Bar */}
        <div className="flex items-center justify-between px-6 py-4 border-b border-slate-800 bg-slate-950/50">
          <div className="flex items-center space-x-3">
            <span className="inline-flex items-center px-2.5 py-1 rounded-md text-xs font-mono font-semibold bg-cyan-500/10 text-cyan-400 border border-cyan-500/20">
              <Activity className="w-3.5 h-3.5 mr-1.5 animate-pulse" /> LIVE DISCOVERY HANDSHAKE · {report?.endpoint_name || 'Target Asset'}
            </span>
            <span className="inline-flex items-center px-2.5 py-1 rounded-md text-xs font-mono font-medium bg-emerald-500/10 text-emerald-400 border border-emerald-500/20">
              ● COMPLETE
            </span>
          </div>
          <button
            onClick={onClose}
            className="p-1.5 rounded-lg text-slate-400 hover:text-slate-200 hover:bg-slate-800 transition-colors"
          >
            <X className="w-5 h-5" />
          </button>
        </div>

        {/* Content Body */}
        <div className="p-6 overflow-y-auto space-y-6 flex-1 font-sans">
          {loading ? (
            <div className="flex flex-col items-center justify-center py-20 space-y-3">
              <RefreshCw className="w-8 h-8 text-cyan-400 animate-spin" />
              <p className="text-sm font-mono text-slate-400">Evaluating PQC Primitives & Exposure Timeline...</p>
            </div>
          ) : error ? (
            <div className="p-4 bg-rose-500/10 border border-rose-500/20 rounded-xl text-rose-400 text-sm">
              {error}
            </div>
          ) : report ? (
            <div className="grid grid-cols-1 lg:grid-cols-12 gap-8">
              {/* Left Column: Analysis & Categorized Cards */}
              <div className="lg:col-span-7 space-y-6">
                {/* Score & Primary Headline Card */}
                <div className="p-6 bg-slate-950/60 border border-slate-800/80 rounded-xl space-y-4">
                  <div className="flex items-start justify-between">
                    {/* Score Meter */}
                    <div className="flex items-center space-x-4">
                      <div className="relative w-20 h-20 flex items-center justify-center rounded-full bg-slate-900 border-4 border-cyan-500/30 shadow-inner">
                        <div className="text-center">
                          <span className="text-2xl font-extrabold font-mono text-cyan-300">{report.pqc_score}</span>
                          <span className="block text-[10px] font-mono text-slate-400">/ 100</span>
                        </div>
                      </div>
                      <div>
                        <span className={`inline-block px-2.5 py-0.5 rounded-md text-[11px] font-mono font-bold border ${getRiskColor(report.risk_tier)}`}>
                          RISK TIER · {report.risk_tier}
                        </span>
                        <h2 className="text-xl font-bold text-slate-100 mt-1">{report.headline}</h2>
                      </div>
                    </div>
                  </div>
                  <p className="text-xs text-slate-400 font-mono leading-relaxed border-t border-slate-800/60 pt-3">
                    {report.subtitle}
                  </p>
                </div>

                {/* Categorized Risk Breakdown Section Cards */}
                <div className="space-y-4">
                  {report.sections.map((sec: any, idx: number) => (
                    <div key={idx} className="p-4 bg-slate-950/40 border border-slate-800/60 rounded-xl space-y-2">
                      <div className="flex items-center space-x-2">
                        <span className={`px-2 py-0.5 rounded text-[10px] font-mono font-bold border uppercase tracking-wider ${getBadgeStyle(sec.badge)}`}>
                          {sec.badge}
                        </span>
                        <h4 className="text-xs font-semibold text-slate-200">{sec.title}</h4>
                      </div>
                      <p className="text-xs text-slate-400 leading-relaxed pl-1">{sec.description}</p>
                    </div>
                  ))}
                </div>

                {/* Executive Summary Callout */}
                <div className="p-4 bg-cyan-950/20 border border-cyan-800/30 rounded-xl space-y-2">
                  <h4 className="text-xs font-mono font-semibold text-cyan-300 flex items-center">
                    <Shield className="w-3.5 h-3.5 mr-1.5 text-cyan-400" /> Executive Assessment Summary
                  </h4>
                  <p className="text-xs text-slate-300 leading-relaxed font-sans">{report.executive_summary}</p>
                </div>
              </div>

              {/* Right Column: Cryptographic Exposure Map Timeline */}
              <div className="lg:col-span-5 space-y-6">
                <div className="p-5 bg-slate-950/60 border border-slate-800/80 rounded-xl space-y-4">
                  <div className="flex items-center justify-between border-b border-slate-800/80 pb-3">
                    <h3 className="text-xs font-mono font-bold text-slate-200 uppercase tracking-wider flex items-center">
                      <Activity className="w-4 h-4 mr-2 text-cyan-400" /> [CRYPTOGRAPHIC EXPOSURE MAP]
                    </h3>
                    <span className="text-[10px] font-mono text-slate-400">CycloneDX 1.6 · preview</span>
                  </div>

                  {/* Vertical Timeline Nodes */}
                  <div className="relative pl-6 space-y-4 before:absolute before:left-2.5 before:top-2 before:bottom-2 before:w-0.5 before:bg-slate-800">
                    {report.exposure_map.map((node: any, idx: number) => (
                      <div key={node.id} className="relative bg-slate-900 border border-slate-800/80 rounded-lg p-3 space-y-1">
                        <span className="absolute -left-6 top-3.5 w-2.5 h-2.5 rounded-full bg-cyan-400 ring-4 ring-slate-950" />
                        <div className="flex items-center justify-between">
                          <span className="text-xs font-mono font-semibold text-slate-200 truncate">{node.title}</span>
                          {node.status_badge && (
                            <span className="px-1.5 py-0.5 rounded text-[9px] font-mono bg-cyan-500/10 text-cyan-300 border border-cyan-500/20">
                              {node.status_badge}
                            </span>
                          )}
                        </div>
                        <p className="text-[11px] font-mono text-slate-400">{node.subtitle}</p>
                        {node.progress_percent !== undefined && (
                          <div className="w-full bg-slate-950 rounded-full h-1.5 overflow-hidden mt-1">
                            <div className="bg-rose-500 h-full rounded-full" style={{ width: `${node.progress_percent}%` }} />
                          </div>
                        )}
                      </div>
                    ))}
                  </div>
                </div>

                {/* Locked / Detailed Report Section */}
                <div className="p-5 bg-slate-950/80 border border-slate-800 rounded-xl space-y-3">
                  <h4 className="text-xs font-mono font-bold text-slate-300 flex items-center uppercase tracking-wider">
                    <Lock className="w-3.5 h-3.5 mr-2 text-amber-400" /> [LOCKED · DETAILED REPORT ACTIONS]
                  </h4>
                  <ul className="space-y-2 text-xs font-sans text-slate-400">
                    <li className="flex items-center text-slate-300">
                      <Lock className="w-3 h-3 mr-2 text-amber-400 flex-shrink-0" /> Per-asset migration plan — what to change, in what order
                    </li>
                    <li className="flex items-center text-slate-300">
                      <Lock className="w-3 h-3 mr-2 text-amber-400 flex-shrink-0" /> Signed Cryptographic Bill of Materials (CycloneDX 1.6)
                    </li>
                    <li className="flex items-center text-slate-300">
                      <Lock className="w-3 h-3 mr-2 text-amber-400 flex-shrink-0" /> Board-ready PDF tagged to DST/NQM milestones (M1/M2/M3)
                    </li>
                    <li className="flex items-center text-slate-300">
                      <Lock className="w-3 h-3 mr-2 text-amber-400 flex-shrink-0" /> Dependency graph + harvest-now-decrypt-later analysis
                    </li>
                  </ul>

                  <div className="pt-2 flex flex-col space-y-2">
                    <button
                      onClick={downloadCBOM}
                      className="w-full flex items-center justify-center px-4 py-2 bg-cyan-600 hover:bg-cyan-500 text-white font-medium text-xs rounded-lg transition-colors shadow-lg shadow-cyan-950/40 font-mono"
                    >
                      <Download className="w-3.5 h-3.5 mr-2" /> Export CycloneDX 1.6 CBOM
                    </button>
                  </div>
                </div>
              </div>
            </div>
          ) : null}
        </div>
      </div>
    </div>
  );
};
