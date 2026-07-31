import React, { useEffect, useState } from 'react';
import {
  Shield, AlertTriangle, XCircle, Download, Activity,
  RefreshCw, X, Database, Search, CheckCircle, Info
} from 'lucide-react';

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
      setReport(null);
      setError(null);
      setLoading(true);
      fetchReport(assetId);
    }
  }, [assetId]);

  const fetchReport = async (id: string) => {
    try {
      const res = await fetch(`/api/v1/reports/instance/${id}`);
      if (res.ok) {
        setReport(await res.json());
      } else {
        const err = await res.json().catch(() => ({}));
        setError(err.detail || `HTTP ${res.status}: Failed to fetch instance report`);
      }
    } catch (e: any) {
      setError(`Failed to connect to report engine: ${e.message || e}`);
    } finally {
      setLoading(false);
    }
  };

  if (!assetId) return null;

  // ── Risk tier styling ──────────────────────────────────────────────
  const getRiskStyle = (tier: string) => {
    switch (tier?.toUpperCase()) {
      case 'CRITICAL': return 'text-rose-300 bg-rose-500/10 border-rose-500/30';
      case 'HIGH':     return 'text-rose-400 bg-rose-500/10 border-rose-500/30';
      case 'MEDIUM':   return 'text-amber-400 bg-amber-500/10 border-amber-500/30';
      case 'LOW':      return 'text-emerald-400 bg-emerald-500/10 border-emerald-500/30';
      default:         return 'text-slate-400 bg-slate-700/30 border-slate-600/30'; // UNKNOWN → gray
    }
  };

  const getBadgeStyle = (badge: string) => {
    switch (badge?.toUpperCase()) {
      case 'KEY EXCHANGE': return 'bg-blue-500/15 text-blue-400 border-blue-500/30';
      case 'CERTIFICATE':  return 'bg-amber-500/15 text-amber-400 border-amber-500/30';
      case 'EXPOSURE':     return 'bg-rose-500/15 text-rose-400 border-rose-500/30';
      case 'SIGNATURE':    return 'bg-orange-500/15 text-orange-400 border-orange-500/30';
      default:             return 'bg-slate-700/20 text-slate-400 border-slate-700/40';
    }
  };

  const getStatusIcon = (status: string) => {
    switch (status?.toUpperCase()) {
      case 'ASSESSED':           return <CheckCircle className="w-4 h-4 text-emerald-400" />;
      case 'PARTIALLY_ASSESSED': return <AlertTriangle className="w-4 h-4 text-amber-400" />;
      default:                   return <XCircle className="w-4 h-4 text-slate-500" />;
    }
  };

  const downloadCBOM = () => {
    if (!report?.cbom) return;
    const blob = new Blob([JSON.stringify(report.cbom, null, 2)], { type: 'application/json' });
    const url = URL.createObjectURL(blob);
    const a = document.createElement('a');
    a.href = url;
    a.download = `cbom-1.6-${report.asset?.name || assetId}.json`;
    a.click();
    URL.revokeObjectURL(url);
  };

  const assessment = report?.assessment;
  const isNotAssessed = !report || assessment?.status === 'NOT_ASSESSED';

  return (
    <div className="fixed inset-0 z-50 flex items-center justify-center p-4 bg-slate-950/85 backdrop-blur-md overflow-y-auto">
      <div className="relative w-full max-w-6xl bg-slate-900 border border-slate-800 rounded-2xl shadow-2xl overflow-hidden my-8 max-h-[92vh] flex flex-col">

        {/* ── Header Bar ─────────────────────────────────────────────── */}
        <div className="flex items-center justify-between px-6 py-4 border-b border-slate-800 bg-slate-950/60 flex-shrink-0">
          <div className="flex items-center space-x-3 min-w-0">
            <span className="inline-flex items-center px-2.5 py-1 rounded-md text-xs font-mono font-semibold bg-cyan-500/10 text-cyan-400 border border-cyan-500/20 flex-shrink-0">
              {report?.header_label
                ? <><Activity className="w-3.5 h-3.5 mr-1.5 flex-shrink-0" />{report.header_label}</>
                : <><Search className="w-3.5 h-3.5 mr-1.5 flex-shrink-0" />LOADING...</>
              }
            </span>
            {report && (
              <span className={`inline-flex items-center px-2.5 py-1 rounded-md text-xs font-mono font-medium border flex-shrink-0 ${
                isNotAssessed
                  ? 'bg-slate-700/30 text-slate-400 border-slate-600/30'
                  : 'bg-emerald-500/10 text-emerald-400 border-emerald-500/20'
              }`}>
                {getStatusIcon(assessment?.status)}
                <span className="ml-1.5">{assessment?.status ?? 'NOT_ASSESSED'}</span>
              </span>
            )}
            {report?.asset?.name && (
              <span className="text-xs font-mono text-slate-500 truncate">· {report.asset.name}</span>
            )}
          </div>
          <button
            onClick={onClose}
            className="p-1.5 rounded-lg text-slate-400 hover:text-slate-200 hover:bg-slate-800 transition-colors flex-shrink-0"
          >
            <X className="w-5 h-5" />
          </button>
        </div>

        {/* ── Content Body ───────────────────────────────────────────── */}
        <div className="p-6 overflow-y-auto space-y-6 flex-1 font-sans">

          {/* Loading State */}
          {loading && (
            <div className="flex flex-col items-center justify-center py-24 space-y-3">
              <RefreshCw className="w-8 h-8 text-cyan-400 animate-spin" />
              <p className="text-sm font-mono text-slate-400">Evaluating cryptographic evidence...</p>
            </div>
          )}

          {/* Error State */}
          {!loading && error && (
            <div className="p-5 bg-rose-500/10 border border-rose-500/20 rounded-xl text-rose-400 text-sm space-y-2">
              <div className="flex items-center space-x-2 font-semibold">
                <XCircle className="w-4 h-4 flex-shrink-0" />
                <span>Report Error</span>
              </div>
              <p className="text-xs text-rose-300/80 font-mono">{error}</p>
            </div>
          )}

          {/* ── NOT ASSESSED ─────────────────────────────────────────── */}
          {!loading && !error && report && isNotAssessed && (
            <div className="grid grid-cols-1 lg:grid-cols-12 gap-8">
              {/* Left: Not assessed info */}
              <div className="lg:col-span-7 space-y-5">

                {/* Asset info */}
                <div className="p-5 bg-slate-950/60 border border-slate-800/80 rounded-xl space-y-3">
                  <div className="flex items-center space-x-2 text-slate-400">
                    <Database className="w-4 h-4 text-slate-500" />
                    <span className="text-xs font-mono font-semibold text-slate-300 uppercase tracking-wider">Asset</span>
                  </div>
                  <div className="space-y-1.5">
                    <p className="text-sm font-semibold text-slate-100 break-all">{report.asset?.name}</p>
                    <div className="flex flex-wrap gap-2 text-xs font-mono text-slate-500">
                      <span className="px-2 py-0.5 rounded bg-slate-800 border border-slate-700">{report.asset?.asset_type}</span>
                      {report.asset?.provider && <span className="px-2 py-0.5 rounded bg-slate-800 border border-slate-700">{report.asset.provider}</span>}
                      {report.asset?.region && <span className="px-2 py-0.5 rounded bg-slate-800 border border-slate-700">{report.asset.region}</span>}
                      <span className="px-2 py-0.5 rounded bg-slate-800 border border-slate-700">{report.asset?.eligibility_type}</span>
                    </div>
                  </div>
                </div>

                {/* Not assessed banner */}
                <div className="p-5 bg-slate-800/30 border border-slate-700/50 rounded-xl space-y-3">
                  <div className="flex items-center space-x-2">
                    <XCircle className="w-5 h-5 text-slate-500 flex-shrink-0" />
                    <h3 className="text-sm font-semibold text-slate-300">PQC READINESS: NOT ASSESSED</h3>
                  </div>
                  <p className="text-xs text-slate-400 leading-relaxed">
                    No cryptographic evidence has been collected for this asset. A PQC readiness score requires observed
                    cryptographic primitives (TLS handshake, certificate, key exchange, encryption configuration, or key metadata).
                  </p>
                  <div className="pt-1 border-t border-slate-800/60">
                    <p className="text-[11px] font-mono text-slate-500">
                      Eligibility type: <span className="text-slate-400">{report.asset?.eligibility_type}</span>
                    </p>
                    <p className="text-[11px] font-mono text-slate-500 mt-0.5">
                      0 vulnerabilities + 0 evidence ≠ quantum-safe. Absence of findings is not a positive result.
                    </p>
                  </div>
                </div>

                {/* Aggregate view for account/region */}
                {report.aggregate && (
                  <div className="p-5 bg-slate-950/50 border border-slate-800 rounded-xl space-y-3">
                    <h4 className="text-xs font-mono font-semibold text-slate-300 uppercase tracking-wider flex items-center">
                      <Activity className="w-3.5 h-3.5 mr-2 text-cyan-400" />
                      Child Resource Overview
                    </h4>
                    <div className="grid grid-cols-2 gap-3 text-xs font-mono">
                      {[
                        { label: 'Total Resources', value: report.aggregate.total_resources, color: 'text-slate-300' },
                        { label: 'Assessed', value: report.aggregate.assessed_resources, color: 'text-emerald-400' },
                        { label: 'Partially Assessed', value: report.aggregate.partially_assessed_resources, color: 'text-amber-400' },
                        { label: 'Not Assessed', value: report.aggregate.unassessed_resources, color: 'text-slate-500' },
                        { label: 'Vulnerable Resources', value: report.aggregate.vulnerable_resources, color: 'text-rose-400' },
                        { label: 'Coverage', value: `${report.aggregate.coverage_percentage}%`, color: 'text-cyan-400' },
                      ].map(item => (
                        <div key={item.label} className="p-3 bg-slate-900 rounded-lg border border-slate-800">
                          <p className="text-slate-500 text-[10px] uppercase tracking-wider">{item.label}</p>
                          <p className={`text-lg font-bold mt-0.5 ${item.color}`}>{item.value}</p>
                        </div>
                      ))}
                    </div>
                  </div>
                )}
              </div>

              {/* Right: how to get assessed */}
              <div className="lg:col-span-5 space-y-5">
                <div className="p-5 bg-slate-950/60 border border-slate-800 rounded-xl space-y-3">
                  <h4 className="text-xs font-mono font-semibold text-slate-300 uppercase tracking-wider flex items-center">
                    <Info className="w-3.5 h-3.5 mr-2 text-cyan-400" />
                    How to Obtain Assessment
                  </h4>
                  <ul className="space-y-2.5 text-xs text-slate-400">
                    <li className="flex items-start space-x-2">
                      <span className="w-1.5 h-1.5 rounded-full bg-cyan-500 mt-1.5 flex-shrink-0" />
                      <span>For TLS endpoints: run a <span className="text-cyan-300 font-mono">TLS Scanner</span> scan against the hostname/IP.</span>
                    </li>
                    <li className="flex items-start space-x-2">
                      <span className="w-1.5 h-1.5 rounded-full bg-cyan-500 mt-1.5 flex-shrink-0" />
                      <span>For Linux hosts: run the <span className="text-cyan-300 font-mono">Linux Collector</span> to gather cryptographic configuration.</span>
                    </li>
                    <li className="flex items-start space-x-2">
                      <span className="w-1.5 h-1.5 rounded-full bg-cyan-500 mt-1.5 flex-shrink-0" />
                      <span>For AWS KMS keys: the AWS connector must discover KMS key metadata.</span>
                    </li>
                    <li className="flex items-start space-x-2">
                      <span className="w-1.5 h-1.5 rounded-full bg-cyan-500 mt-1.5 flex-shrink-0" />
                      <span>AWS account and region entities are inventory containers — they aggregate child assessments.</span>
                    </li>
                  </ul>
                </div>
              </div>
            </div>
          )}

          {/* ── ASSESSED / PARTIALLY ASSESSED ───────────────────────── */}
          {!loading && !error && report && !isNotAssessed && (
            <div className="grid grid-cols-1 lg:grid-cols-12 gap-8">

              {/* Left: Score + Sections + Summary */}
              <div className="lg:col-span-7 space-y-6">

                {/* Score Card */}
                <div className="p-6 bg-slate-950/60 border border-slate-800/80 rounded-xl space-y-4">
                  <div className="flex items-start justify-between">
                    <div className="flex items-center space-x-4">
                      {/* Score Gauge */}
                      <div className={`relative w-20 h-20 flex items-center justify-center rounded-full bg-slate-900 border-4 shadow-inner ${
                        assessment?.score === null
                          ? 'border-slate-700/50'
                          : assessment?.score >= 80 ? 'border-emerald-500/40'
                            : assessment?.score >= 60 ? 'border-amber-500/40'
                            : 'border-rose-500/40'
                      }`}>
                        <div className="text-center">
                          {assessment?.score !== null ? (
                            <>
                              <span className="text-2xl font-extrabold font-mono text-cyan-300">{assessment.score}</span>
                              <span className="block text-[10px] font-mono text-slate-400">/ 100</span>
                            </>
                          ) : (
                            <span className="text-xs font-mono text-slate-500 text-center leading-tight">NOT<br/>ASSESSED</span>
                          )}
                        </div>
                      </div>
                      <div>
                        <span className={`inline-block px-2.5 py-0.5 rounded-md text-[11px] font-mono font-bold border ${getRiskStyle(assessment?.risk_tier)}`}>
                          RISK TIER · {assessment?.risk_tier ?? 'UNKNOWN'}
                        </span>
                        <h2 className="text-lg font-bold text-slate-100 mt-1">
                          {report.sections?.[0]?.title ?? 'Cryptographic Assessment'}
                        </h2>
                        <p className="text-xs text-slate-500 font-mono mt-0.5">{report.asset?.eligibility_type}</p>
                      </div>
                    </div>
                  </div>

                  {/* Asset metadata */}
                  <div className="flex flex-wrap gap-1.5 pt-2 border-t border-slate-800/60">
                    {report.asset?.provider && (
                      <span className="px-2 py-0.5 rounded text-[10px] font-mono bg-slate-800 border border-slate-700 text-slate-400">{report.asset.provider}</span>
                    )}
                    {report.asset?.region && (
                      <span className="px-2 py-0.5 rounded text-[10px] font-mono bg-slate-800 border border-slate-700 text-slate-400">{report.asset.region}</span>
                    )}
                    {report.asset?.asset_type && (
                      <span className="px-2 py-0.5 rounded text-[10px] font-mono bg-slate-800 border border-slate-700 text-slate-400">{report.asset.asset_type}</span>
                    )}
                  </div>
                </div>

                {/* Risk Breakdown Sections */}
                {report.sections?.length > 0 && (
                  <div className="space-y-3">
                    {report.sections.map((sec: any, idx: number) => (
                      <div key={idx} className="p-4 bg-slate-950/40 border border-slate-800/60 rounded-xl space-y-1.5">
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
                )}

                {/* Executive Summary */}
                {report.executive_summary && (
                  <div className="p-4 bg-cyan-950/20 border border-cyan-800/30 rounded-xl space-y-2">
                    <h4 className="text-xs font-mono font-semibold text-cyan-300 flex items-center">
                      <Shield className="w-3.5 h-3.5 mr-1.5 text-cyan-400" />Executive Assessment Summary
                    </h4>
                    <p className="text-xs text-slate-300 leading-relaxed">{report.executive_summary}</p>
                  </div>
                )}

                {/* Evidence Provenance Table */}
                {report.provenance?.length > 0 && (
                  <div className="p-5 bg-slate-950/50 border border-slate-800 rounded-xl space-y-3">
                    <h4 className="text-xs font-mono font-semibold text-slate-300 uppercase tracking-wider flex items-center">
                      <Database className="w-3.5 h-3.5 mr-2 text-cyan-400" />Evidence Provenance
                    </h4>
                    <div className="overflow-x-auto">
                      <table className="w-full text-xs font-mono">
                        <thead>
                          <tr className="text-slate-500 border-b border-slate-800 text-left">
                            <th className="py-1.5 pr-3 font-medium">Algorithm</th>
                            <th className="py-1.5 pr-3 font-medium">Type</th>
                            <th className="py-1.5 pr-3 font-medium">Source</th>
                            <th className="py-1.5 pr-3 font-medium">Confidence</th>
                            <th className="py-1.5 font-medium">Target</th>
                          </tr>
                        </thead>
                        <tbody className="divide-y divide-slate-800/50">
                          {report.provenance.map((p: any, idx: number) => (
                            <tr key={idx} className="text-slate-300 hover:bg-slate-800/30 transition-colors">
                              <td className="py-2 pr-3 text-cyan-300">{p.raw_algorithm}</td>
                              <td className="py-2 pr-3 text-slate-400">{p.finding_type?.replace(/_/g, ' ')}</td>
                              <td className="py-2 pr-3 text-emerald-400">{p.source}</td>
                              <td className="py-2 pr-3">
                                <span className={`px-1.5 py-0.5 rounded text-[9px] border ${
                                  p.confidence === 'HIGH'   ? 'text-emerald-400 border-emerald-500/30 bg-emerald-500/10' :
                                  p.confidence === 'MEDIUM' ? 'text-amber-400 border-amber-500/30 bg-amber-500/10' :
                                                              'text-slate-400 border-slate-600/30 bg-slate-700/20'
                                }`}>{p.confidence}</span>
                              </td>
                              <td className="py-2 text-slate-500 truncate max-w-[180px]" title={p.target}>{p.target}</td>
                            </tr>
                          ))}
                        </tbody>
                      </table>
                    </div>
                  </div>
                )}
              </div>

              {/* Right: Exposure Map + Evidence Summary + CBOM */}
              <div className="lg:col-span-5 space-y-5">

                {/* Evidence Summary */}
                <div className="p-5 bg-slate-950/60 border border-slate-800/80 rounded-xl space-y-3">
                  <h3 className="text-xs font-mono font-bold text-slate-200 uppercase tracking-wider flex items-center">
                    <Activity className="w-4 h-4 mr-2 text-cyan-400" />Evidence Summary
                  </h3>
                  <div className="grid grid-cols-2 gap-2 text-xs font-mono">
                    {[
                      { label: 'Total Evidence', value: report.evidence_summary?.total ?? 0, color: 'text-cyan-300' },
                      { label: 'Primitives', value: report.evidence_summary?.primitive_count ?? 0, color: 'text-slate-300' },
                      { label: 'Vulnerable', value: report.evidence_summary?.vulnerable_count ?? 0, color: 'text-rose-400' },
                      { label: 'Resistant', value: report.evidence_summary?.resistant_count ?? 0, color: 'text-emerald-400' },
                      { label: 'Hybrid', value: report.evidence_summary?.hybrid_count ?? 0, color: 'text-blue-400' },
                      { label: 'Unknown', value: report.evidence_summary?.unknown_count ?? 0, color: 'text-slate-500' },
                    ].map(item => (
                      <div key={item.label} className="p-2.5 bg-slate-900 rounded-lg border border-slate-800">
                        <p className="text-slate-600 text-[9px] uppercase tracking-wider">{item.label}</p>
                        <p className={`text-xl font-bold font-mono mt-0.5 ${item.color}`}>{item.value}</p>
                      </div>
                    ))}
                  </div>
                </div>

                {/* Cryptographic Exposure Map */}
                <div className="p-5 bg-slate-950/60 border border-slate-800/80 rounded-xl space-y-4">
                  <h3 className="text-xs font-mono font-bold text-slate-200 uppercase tracking-wider">
                    [CRYPTOGRAPHIC EXPOSURE MAP]
                  </h3>
                  {report.exposure_map?.length > 0 ? (
                    <div className="relative pl-6 space-y-3 before:absolute before:left-2.5 before:top-2 before:bottom-2 before:w-0.5 before:bg-slate-800">
                      {report.exposure_map.map((node: any) => (
                        <div key={node.id} className="relative bg-slate-900 border border-slate-800/80 rounded-lg p-3 space-y-1">
                          <span className="absolute -left-6 top-3.5 w-2.5 h-2.5 rounded-full bg-cyan-400 ring-4 ring-slate-950" />
                          <div className="flex items-center justify-between">
                            <span className="text-xs font-mono font-semibold text-slate-200 truncate">{node.title}</span>
                            {node.status_badge && (
                              <span className={`px-1.5 py-0.5 rounded text-[9px] font-mono border flex-shrink-0 ml-2 ${
                                node.color === 'rose'
                                  ? 'bg-rose-500/10 text-rose-300 border-rose-500/20'
                                  : 'bg-cyan-500/10 text-cyan-300 border-cyan-500/20'
                              }`}>
                                {node.status_badge}
                              </span>
                            )}
                          </div>
                          <p className="text-[11px] font-mono text-slate-500">{node.subtitle}</p>
                        </div>
                      ))}
                    </div>
                  ) : (
                    <p className="text-xs font-mono text-slate-500 italic">No cryptographic exposure path has been discovered.</p>
                  )}
                </div>

                {/* CBOM Export — only when evidence exists */}
                {report.cbom ? (
                  <div className="p-4 bg-slate-950/80 border border-slate-800 rounded-xl space-y-3">
                    <h4 className="text-xs font-mono font-bold text-slate-300 uppercase tracking-wider">
                      [CycloneDX 1.6 CBOM]
                    </h4>
                    <p className="text-[11px] text-slate-500 font-mono">
                      {report.evidence_summary?.primitive_count ?? 0} cryptographic component(s) discovered.
                      Export CBOM for SBOM toolchain integration.
                    </p>
                    <button
                      onClick={downloadCBOM}
                      className="w-full flex items-center justify-center px-4 py-2 bg-cyan-600 hover:bg-cyan-500 text-white font-medium text-xs rounded-lg transition-colors shadow-lg shadow-cyan-950/40 font-mono"
                    >
                      <Download className="w-3.5 h-3.5 mr-2" />Export CycloneDX 1.6 CBOM
                    </button>
                  </div>
                ) : (
                  <div className="p-4 bg-slate-950/40 border border-slate-800/50 rounded-xl">
                    <p className="text-xs font-mono text-slate-600">
                      CBOM export unavailable — no cryptographic components discovered.
                    </p>
                  </div>
                )}

              </div>
            </div>
          )}
        </div>
      </div>
    </div>
  );
};
