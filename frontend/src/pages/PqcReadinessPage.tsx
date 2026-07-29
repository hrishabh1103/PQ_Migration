import React, { useState, useEffect } from 'react';
import { ShieldAlert, AlertTriangle, CheckCircle, Info, HelpCircle, Network, ArrowRight, ShieldCheck } from 'lucide-react';
import { PageHeader } from '../components/common/PageHeader';

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
  const [summary, setSummary] = useState<SummaryData | null>(null);
  const [priorities, setPriorities] = useState<PriorityItem[]>([]);

  useEffect(() => {
    fetchReadinessData();
  }, []);

  const fetchReadinessData = async () => {
    try {
      const [sRes, pRes] = await Promise.all([
        fetch('/api/v1/readiness/summary'),
        fetch('/api/v1/readiness/migration-priorities')
      ]);

      if (sRes.ok) {
        const sData = await sRes.json();
        setSummary(sData);
      }
      if (pRes.ok) {
        const pData = await pRes.json();
        setPriorities(pData);
      }
    } catch (err) {
      console.error('Failed to load PQC Readiness data:', err);
    }
  };

  const getCategoryBadge = (cat: string) => {
    switch (cat) {
      case 'CRITICAL':
        return <span className="px-2.5 py-0.5 rounded-full text-xs font-semibold bg-rose-500/10 text-rose-400 border border-rose-500/20">CRITICAL</span>;
      case 'HIGH':
        return <span className="px-2.5 py-0.5 rounded-full text-xs font-semibold bg-amber-500/10 text-amber-400 border border-amber-500/20">HIGH</span>;
      case 'MEDIUM':
        return <span className="px-2.5 py-0.5 rounded-full text-xs font-semibold bg-yellow-500/10 text-yellow-400 border border-yellow-500/20">MEDIUM</span>;
      default:
        return <span className="px-2.5 py-0.5 rounded-full text-xs font-semibold bg-slate-500/10 text-slate-400 border border-slate-500/20">LOW</span>;
    }
  };

  const getReadinessBadge = (state: string) => {
    switch (state) {
      case 'READY':
        return <span className="px-2 py-0.5 rounded text-[10px] font-mono bg-emerald-500/10 text-emerald-400 border border-emerald-500/20">READY</span>;
      case 'PARTIALLY_READY':
        return <span className="px-2 py-0.5 rounded text-[10px] font-mono bg-cyan-500/10 text-cyan-400 border border-cyan-500/20">PARTIALLY READY</span>;
      case 'NOT_READY':
        return <span className="px-2 py-0.5 rounded text-[10px] font-mono bg-rose-500/10 text-rose-400 border border-rose-500/20">NOT READY</span>;
      case 'INCOMPLETE_COVERAGE':
        return <span className="px-2 py-0.5 rounded text-[10px] font-mono bg-amber-500/10 text-amber-400 border border-amber-500/20">INCOMPLETE COVERAGE</span>;
      default:
        return <span className="px-2 py-0.5 rounded text-[10px] font-mono bg-slate-500/10 text-slate-400 border border-slate-500/20">UNKNOWN</span>;
    }
  };

  return (
    <div className="space-y-6">
      {/* Page Header */}
      <PageHeader
        title="Post-Quantum Cryptographic Readiness & Migration Engine"
        description="Provider-independent entity correlation, purpose-aware PQC classification, coverage-aware asset readiness, and versioned policy assessment."
        icon={ShieldAlert}
        badge={summary ? `Policy ${summary.policy.policy_id}:${summary.policy.policy_version}` : 'PQC Engine V1'}
        breadcrumbs={[{ label: 'Migration' }, { label: 'PQC Readiness' }]}
      />

      {/* Summary Cards */}
      <div className="grid grid-cols-1 md:grid-cols-4 gap-4">
        <div className="bg-slate-900 border border-slate-800 rounded-xl p-5">
          <div className="flex items-center justify-between mb-2">
            <span className="text-xs font-mono text-slate-400 uppercase">Quantum-Vulnerable</span>
            <AlertTriangle className="w-4 h-4 text-rose-400" />
          </div>
          <div className="text-2xl font-bold text-rose-400">
            {summary ? summary.quantum_exposure_breakdown.QUANTUM_VULNERABLE : 0}
          </div>
          <p className="text-[11px] text-slate-500 mt-1">Shor's algorithm exposed assets</p>
        </div>

        <div className="bg-slate-900 border border-slate-800 rounded-xl p-5">
          <div className="flex items-center justify-between mb-2">
            <span className="text-xs font-mono text-slate-400 uppercase">Hybrid / PQC Usage</span>
            <ShieldCheck className="w-4 h-4 text-emerald-400" />
          </div>
          <div className="text-2xl font-bold text-emerald-400">
            {summary ? summary.quantum_exposure_breakdown.HYBRID + summary.quantum_exposure_breakdown.QUANTUM_RESISTANT : 0}
          </div>
          <p className="text-[11px] text-slate-500 mt-1">ML-KEM / ML-DSA transitioned</p>
        </div>

        <div className="bg-slate-900 border border-slate-800 rounded-xl p-5">
          <div className="flex items-center justify-between mb-2">
            <span className="text-xs font-mono text-slate-400 uppercase">Incomplete Coverage</span>
            <Info className="w-4 h-4 text-amber-400" />
          </div>
          <div className="text-2xl font-bold text-amber-400">
            {summary ? summary.asset_readiness_breakdown.INCOMPLETE_COVERAGE : 0}
          </div>
          <p className="text-[11px] text-slate-500 mt-1">Assets requiring further scan scope</p>
        </div>

        <div className="bg-slate-900 border border-slate-800 rounded-xl p-5">
          <div className="flex items-center justify-between mb-2">
            <span className="text-xs font-mono text-slate-400 uppercase">Critical Priorities</span>
            <ShieldAlert className="w-4 h-4 text-cyan-400" />
          </div>
          <div className="text-2xl font-bold text-cyan-400">
            {summary ? summary.critical_priority_items : 0}
          </div>
          <p className="text-[11px] text-slate-500 mt-1">Migration score ≥ 60</p>
        </div>
      </div>

      {/* Migration Priority & Rationale List */}
      <div className="bg-slate-900 border border-slate-800 rounded-xl p-6">
        <div className="flex items-center justify-between mb-4">
          <div>
            <h3 className="text-base font-bold text-slate-100 flex items-center">
              <ShieldAlert className="w-4.5 h-4.5 mr-2 text-cyan-400" /> Prioritized Migration Action Items ({priorities.length})
            </h3>
            <p className="text-xs text-slate-400 mt-1">
              Purpose-aware migration priority combining quantum vulnerability, HNDL relevance, exposure, and coverage confidence.
            </p>
          </div>
          {onNavigateGraph && (
            <button
              onClick={onNavigateGraph}
              className="px-3 py-1.5 bg-slate-800 hover:bg-slate-700 text-cyan-400 text-xs font-mono rounded-lg transition-colors flex items-center space-x-1.5"
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
    </div>
  );
};
