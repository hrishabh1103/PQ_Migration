import React, { useState, useEffect } from 'react';
import { ShieldAlert, AlertTriangle, CheckCircle, Info, HelpCircle, Network, ArrowRight, FileText } from 'lucide-react';
import { PageHeader } from '../components/common/PageHeader';
import { InstanceReportModal } from '../components/reports/InstanceReportModal';
import { useInstanceReport } from '../components/reports/useInstanceReport';

interface SummaryData {
  policy: {
    policy_id: string;
    policy_version: string;
    description: string;
    standards: string[];
  };
  total_assets_inventoried: number;
  total_assets_assessed: number;
  quantum_exposure_breakdown: {
    QUANTUM_VULNERABLE: number;
    QUANTUM_RESISTANT: number;
    HYBRID: number;
    UNKNOWN: number;
  };
  asset_readiness_breakdown: {
    READY: number;
    PARTIALLY_READY: number;
    NOT_READY: number;
    INCOMPLETE_COVERAGE: number;
    UNKNOWN: number;
  };
  critical_priority_items: number;
}

interface PriorityItem {
  assessment_id: string;
  asset_id: string;
  asset_name: string;
  asset_type: string;
  priority_score: number;
  category: string;
  quantum_exposure: string;
  readiness_result: string;
  confidence: string;
  known_factors: string[];
  unknown_factors: string[];
  rationale: string;
  policy_version: string;
  assessed_at: string;
}

interface PqcReadinessPageProps {
  onNavigateGraph?: () => void;
}

export const PqcReadinessPage: React.FC<PqcReadinessPageProps> = ({ onNavigateGraph }) => {
  const { selectedAssetId, openReport, closeReport } = useInstanceReport();
  const [summary, setSummary] = useState<SummaryData | null>(null);
  const [priorities, setPriorities] = useState<PriorityItem[]>([]);
  const [loading, setLoading] = useState<boolean>(true);
  const [error, setError] = useState<string | null>(null);

  useEffect(() => {
    fetchReadinessData();
  }, []);

  const fetchReadinessData = async () => {
    try {
      setLoading(true);
      const [sumRes, prioRes] = await Promise.all([
        fetch('/api/v1/readiness/summary'),
        fetch('/api/v1/readiness/assets')
      ]);

      if (sumRes.ok) {
        setSummary(await sumRes.json());
      }
      if (prioRes.ok) {
        setPriorities(await prioRes.json());
      }
    } catch (err: any) {
      setError(`Failed to fetch PQC readiness assessments: ${err.message || err}`);
    } finally {
      setLoading(false);
    }
  };

  const getCategoryBadge = (category: string) => {
    switch (category?.toUpperCase()) {
      case 'CRITICAL': return <span className="px-2 py-0.5 rounded text-[10px] font-bold font-mono bg-rose-500/20 text-rose-300 border border-rose-500/30">CRITICAL</span>;
      case 'HIGH':     return <span className="px-2 py-0.5 rounded text-[10px] font-bold font-mono bg-rose-500/15 text-rose-400 border border-rose-500/30">HIGH</span>;
      case 'MEDIUM':   return <span className="px-2 py-0.5 rounded text-[10px] font-bold font-mono bg-amber-500/15 text-amber-400 border border-amber-500/30">MEDIUM</span>;
      case 'LOW':      return <span className="px-2 py-0.5 rounded text-[10px] font-bold font-mono bg-emerald-500/15 text-emerald-400 border border-emerald-500/30">LOW</span>;
      default:         return <span className="px-2 py-0.5 rounded text-[10px] font-bold font-mono bg-slate-700/40 text-slate-400 border border-slate-600/30">UNASSESSED</span>;
    }
  };

  const getReadinessBadge = (result: string) => {
    switch (result?.toUpperCase()) {
      case 'READY':              return <span className="px-2 py-0.5 rounded text-[10px] font-mono bg-emerald-500/10 text-emerald-400 border border-emerald-500/20">READY</span>;
      case 'PARTIALLY_READY':    return <span className="px-2 py-0.5 rounded text-[10px] font-mono bg-amber-500/10 text-amber-400 border border-amber-500/20">PARTIALLY READY</span>;
      case 'NOT_READY':          return <span className="px-2 py-0.5 rounded text-[10px] font-mono bg-rose-500/10 text-rose-400 border border-rose-500/20">NOT READY</span>;
      case 'INCOMPLETE_COVERAGE':return <span className="px-2 py-0.5 rounded text-[10px] font-mono bg-indigo-500/10 text-indigo-400 border border-indigo-500/20">INCOMPLETE COVERAGE</span>;
      default:                   return <span className="px-2 py-0.5 rounded text-[10px] font-mono bg-slate-800 text-slate-400">UNKNOWN</span>;
    }
  };

  return (
    <div className="space-y-6">
      <PageHeader
        title="PQC Migration Readiness Engine"
        description="NIST FIPS 203 / 204 / 205 Policy-Driven Post-Quantum Migration Prioritization"
      />

      {loading && (
        <div className="p-8 text-center text-slate-400 font-mono flex items-center justify-center space-x-2">
          <FileText className="w-5 h-5 animate-pulse text-cyan-400" />
          <span>Evaluating PQC Migration Readiness...</span>
        </div>
      )}

      {error && (
        <div className="p-4 bg-rose-500/10 border border-rose-500/30 rounded-xl text-rose-300 text-sm flex items-center">
          <AlertTriangle className="w-4 h-4 mr-2 flex-shrink-0" />
          <span>{error}</span>
        </div>
      )}

      {/* SUMMARY OVERVIEW CARDS */}
      <div className="grid grid-cols-1 md:grid-cols-2 lg:grid-cols-4 gap-4">
        <div className="bg-slate-900 border border-slate-800 rounded-xl p-5">
          <div className="text-xs font-mono text-slate-400 mb-1">Total Inventoried Assets</div>
          <div className="text-2xl font-bold text-slate-100">{summary?.total_assets_inventoried ?? 0}</div>
          <div className="text-[11px] text-slate-500 mt-2 font-mono">Assessed: {summary?.total_assets_assessed ?? 0}</div>
        </div>

        <div className="bg-slate-900 border border-slate-800 rounded-xl p-5">
          <div className="text-xs font-mono text-slate-400 mb-1">Quantum Exposure</div>
          <div className="flex items-baseline space-x-2">
            <span className="text-2xl font-bold text-rose-400">{summary?.quantum_exposure_breakdown?.QUANTUM_VULNERABLE ?? 0}</span>
            <span className="text-xs text-slate-400 font-mono">vulnerable</span>
          </div>
          <div className="text-[11px] text-slate-500 mt-2 font-mono">
            Resistant: {summary?.quantum_exposure_breakdown?.QUANTUM_RESISTANT ?? 0} | Hybrid: {summary?.quantum_exposure_breakdown?.HYBRID ?? 0}
          </div>
        </div>

        <div className="bg-slate-900 border border-slate-800 rounded-xl p-5">
          <div className="text-xs font-mono text-slate-400 mb-1">PQC Readiness State</div>
          <div className="flex items-baseline space-x-2">
            <span className="text-2xl font-bold text-emerald-400">{summary?.asset_readiness_breakdown?.READY ?? 0}</span>
            <span className="text-xs text-slate-400 font-mono">READY</span>
          </div>
          <div className="text-[11px] text-slate-500 mt-2 font-mono">
            Not Ready: {summary?.asset_readiness_breakdown?.NOT_READY ?? 0} | Partially: {summary?.asset_readiness_breakdown?.PARTIALLY_READY ?? 0}
          </div>
        </div>

        <div className="bg-slate-900 border border-slate-800 rounded-xl p-5">
          <div className="text-xs font-mono text-slate-400 mb-1">Critical Priority Targets</div>
          <div className="text-2xl font-bold text-rose-400">{summary?.critical_priority_items ?? 0}</div>
          <div className="text-[11px] text-slate-500 mt-2 font-mono">Requires Immediate Migration</div>
        </div>
      </div>

      {/* MIGRATION PRIORITY SCOREBOARD */}
      <div className="bg-slate-900 border border-slate-800 rounded-xl p-6">
        <div className="flex items-center justify-between mb-5">
          <div>
            <h3 className="text-lg font-bold text-slate-100 flex items-center">
              <ShieldAlert className="w-5 h-5 mr-2 text-rose-400" /> Migration Priority Scoreboard
            </h3>
            <p className="text-xs text-slate-400 mt-1">
              Evidence-based cryptographic readiness score computed via NIST PQC policy guidelines.
            </p>
          </div>
          {onNavigateGraph && (
            <button
              onClick={onNavigateGraph}
              className="px-3.5 py-1.5 bg-slate-800 hover:bg-slate-700 text-cyan-300 text-xs font-mono font-medium rounded-lg border border-slate-700 transition-colors flex items-center space-x-1.5"
            >
              <Network className="w-3.5 h-3.5" />
              <span>Explore Knowledge Graph</span>
              <ArrowRight className="w-3 h-3" />
            </button>
          )}
        </div>

        {priorities.length === 0 ? (
          <div className="py-12 text-center text-slate-500 text-sm font-mono">
            No migration priority items evaluated yet.
          </div>
        ) : (
          <div className="space-y-4">
            {priorities.map((item) => (
              <div key={item.assessment_id} className="bg-slate-950 border border-slate-800 rounded-xl p-5 space-y-3">
                <div className="flex items-start justify-between">
                  <div>
                    <div className="flex items-center space-x-2">
                      <span className="text-sm font-bold text-slate-100">{item.asset_name}</span>
                      <span className="text-xs font-mono text-slate-500">({item.asset_type})</span>
                      {getCategoryBadge(item.category)}
                      {getReadinessBadge(item.readiness_result)}
                    </div>
                    <p className="text-xs font-mono text-slate-400 mt-1">
                      Priority Score: <span className="text-cyan-300 font-bold">{item.priority_score}/100</span> | Confidence: <span className="text-slate-300">{item.confidence}</span> | Policy: {item.policy_version}
                    </p>
                  </div>
                  <button
                    onClick={() => openReport(item.asset_id)}
                    className="px-3 py-1 bg-cyan-500/10 hover:bg-cyan-500/20 text-cyan-400 border border-cyan-500/20 text-xs font-medium rounded-lg transition-colors flex items-center space-x-1.5"
                  >
                    <FileText className="w-3.5 h-3.5" />
                    <span>Inspect Report</span>
                  </button>
                </div>

                {/* WHY THIS IS PRIORITIZED */}
                <div className="bg-slate-900 border border-slate-800/80 rounded-lg p-3.5 space-y-2">
                  <h4 className="text-xs font-bold text-slate-200 uppercase tracking-wider flex items-center">
                    <Info className="w-3.5 h-3.5 mr-1.5 text-cyan-400" /> Rationale & Factor Analysis
                  </h4>
                  <p className="text-xs text-slate-300 font-mono leading-relaxed">{item.rationale}</p>

                  <div className="grid grid-cols-1 md:grid-cols-2 gap-3 pt-2 text-xs font-mono">
                    <div>
                      <span className="text-[10px] text-emerald-400 uppercase font-semibold block mb-1">Known Factors</span>
                      <ul className="space-y-1">
                        {item.known_factors.map((kf, i) => (
                          <li key={i} className="text-slate-300 text-[11px] flex items-center">
                            <CheckCircle className="w-3 h-3 text-emerald-400 mr-1.5 flex-shrink-0" />
                            <span>{kf}</span>
                          </li>
                        ))}
                      </ul>
                    </div>

                    <div>
                      <span className="text-[10px] text-amber-400 uppercase font-semibold block mb-1">Unknown / Preserved Factors</span>
                      <ul className="space-y-1">
                        {item.unknown_factors.length === 0 ? (
                          <li className="text-slate-500 text-[11px]">None</li>
                        ) : (
                          item.unknown_factors.map((uf, i) => (
                            <li key={i} className="text-slate-400 text-[11px] flex items-center">
                              <HelpCircle className="w-3 h-3 text-amber-400 mr-1.5 flex-shrink-0" />
                              <span>{uf}</span>
                            </li>
                          ))
                        )}
                      </ul>
                    </div>
                  </div>
                </div>
              </div>
            ))}
          </div>
        )}
      </div>

      {/* Shared Instance Report Modal */}
      <InstanceReportModal assetId={selectedAssetId} onClose={closeReport} />
    </div>
  );
};
