import React, { useEffect, useState } from 'react';
import { fetchRemediationReport, downloadRemediationMarkdown, downloadCycloneDXCBOM } from '../services/api';
import { FileDown, ShieldAlert, AlertTriangle, CheckCircle2, RefreshCw, Cpu, BookOpen, Layers } from 'lucide-react';

export const ReportsPage: React.FC = () => {
  const [report, setReport] = useState<any>(null);
  const [loading, setLoading] = useState<boolean>(true);
  const [error, setError] = useState<string | null>(null);

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

  const summary = report?.summary || { total_findings: 0, quantum_vulnerable_count: 0, severity_counts: {} };
  const vulns = report?.vulnerabilities || [];

  return (
    <div className="space-y-6">
      {/* Header */}
      <div className="flex flex-col sm:flex-row sm:items-center justify-between gap-4 pb-4 border-b border-slate-800">
        <div>
          <h1 className="text-2xl font-bold text-white flex items-center space-x-3">
            <ShieldAlert className="w-6 h-6 text-cyan-400" />
            <span>PQC Migration Risk & Remediation Report</span>
          </h1>
          <p className="text-slate-400 text-sm mt-1">
            Automated analysis of cryptographic flaws, NIST FIPS 203/204/205 compliance, and mitigation strategies.
          </p>
        </div>

        <div className="flex items-center space-x-3">
          <button
            onClick={downloadCycloneDXCBOM}
            className="flex items-center space-x-2 px-3.5 py-2 rounded-xl border border-slate-700 bg-slate-900 hover:border-cyan-500/40 text-slate-300 hover:text-white text-xs font-mono transition"
          >
            <Layers className="w-3.5 h-3.5 text-cyan-400" />
            <span>Export CycloneDX 1.6 CBOM (.json)</span>
          </button>

          <button
            onClick={downloadRemediationMarkdown}
            className="flex items-center space-x-2 px-4 py-2 rounded-xl bg-gradient-to-r from-cyan-500 to-blue-600 hover:from-cyan-400 hover:to-blue-500 text-white font-medium text-xs transition shadow-lg shadow-cyan-500/20"
          >
            <FileDown className="w-4 h-4 fill-white" />
            <span>Download Audit Report (.md)</span>
          </button>
        </div>
      </div>

      {error && (
        <div className="p-4 rounded-xl bg-rose-500/10 border border-rose-500/30 text-rose-300 text-sm">
          {error}
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
                  <span className="text-xs font-mono text-cyan-400 bg-cyan-500/10 px-2.5 py-1 rounded-md border border-cyan-500/20">
                    {v.cnsa_timeline}
                  </span>
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
    </div>
  );
};
