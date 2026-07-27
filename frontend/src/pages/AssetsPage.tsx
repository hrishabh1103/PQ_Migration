import React, { useEffect, useState } from 'react';
import { Asset, CryptoFinding } from '../types';
import { fetchAssets, fetchFindings } from '../services/api';
import { Database, Network, KeyRound, ShieldAlert, ChevronRight, RefreshCw, AlertCircle } from 'lucide-react';

export const AssetsPage: React.FC = () => {
  const [assets, setAssets] = useState<Asset[]>([]);
  const [findings, setFindings] = useState<CryptoFinding[]>([]);
  const [selectedAssetId, setSelectedAssetId] = useState<string | null>(null);
  const [loading, setLoading] = useState<boolean>(true);
  const [error, setError] = useState<string | null>(null);

  const loadData = async () => {
    try {
      setLoading(true);
      const [assetsData, findingsData] = await Promise.all([fetchAssets(), fetchFindings()]);
      setAssets(assetsData);
      setFindings(findingsData);
      if (assetsData.length > 0 && !selectedAssetId) {
        setSelectedAssetId(assetsData[0].id);
      }
    } catch (err: any) {
      setError(err.message || 'Failed to load assets inventory');
    } finally {
      setLoading(false);
    }
  };

  useEffect(() => {
    loadData();
  }, []);

  const selectedAsset = assets.find((a) => a.id === selectedAssetId);
  const assetFindings = findings.filter((f) => f.asset_id === selectedAssetId);

  return (
    <div className="space-y-6">
      {/* Header */}
      <div className="flex flex-col sm:flex-row sm:items-center justify-between gap-4 pb-4 border-b border-slate-800">
        <div>
          <h1 className="text-2xl font-bold text-white flex items-center space-x-3">
            <Database className="w-6 h-6 text-indigo-400" />
            <span>Discovered Asset Hierarchy</span>
          </h1>
          <p className="text-slate-400 text-sm mt-1">
            System assets, active services, protocols, and associated cryptographic primitives.
          </p>
        </div>

        <button
          onClick={loadData}
          className="p-2.5 rounded-xl border border-slate-700 bg-slate-800 text-slate-300 hover:text-white transition self-start sm:self-auto"
        >
          <RefreshCw className="w-4 h-4" />
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
          <span>Loading asset hierarchy...</span>
        </div>
      ) : assets.length === 0 ? (
        <div className="glass-panel p-12 rounded-2xl text-center space-y-4">
          <Database className="w-12 h-12 text-slate-600 mx-auto" />
          <h3 className="text-lg font-bold text-slate-300">No Discovered Assets</h3>
          <p className="text-slate-400 text-sm max-w-md mx-auto">
            Execute a scan job targeting an authorized target to discover assets, services, and cryptographic findings.
          </p>
        </div>
      ) : (
        <div className="grid grid-cols-1 lg:grid-cols-3 gap-6">
          {/* Asset List Sidebar */}
          <div className="glass-panel p-4 rounded-2xl space-y-3">
            <h2 className="text-xs font-mono uppercase tracking-wider text-slate-400 px-2">System Assets ({assets.length})</h2>
            <div className="space-y-2">
              {assets.map((asset) => {
                const isSelected = asset.id === selectedAssetId;
                return (
                  <div
                    key={asset.id}
                    onClick={() => setSelectedAssetId(asset.id)}
                    className={`p-3.5 rounded-xl cursor-pointer transition flex items-center justify-between border ${
                      isSelected
                        ? 'bg-cyan-500/10 border-cyan-500/40 text-white shadow-lg shadow-cyan-500/10'
                        : 'bg-slate-900/40 border-slate-800 text-slate-300 hover:border-slate-700'
                    }`}
                  >
                    <div className="space-y-1">
                      <div className="font-bold font-mono text-sm flex items-center space-x-2">
                        <Database className="w-4 h-4 text-cyan-400" />
                        <span>{asset.hostname || asset.ip_address || 'Unidentified Host'}</span>
                      </div>
                      <div className="text-xs text-slate-400 font-mono flex items-center space-x-2">
                        <span>IP: {asset.ip_address || '127.0.0.1'}</span>
                        <span>•</span>
                        <span className="text-slate-400">{asset.services?.length || 0} Services</span>
                      </div>
                    </div>
                    <ChevronRight className={`w-4 h-4 ${isSelected ? 'text-cyan-400' : 'text-slate-600'}`} />
                  </div>
                );
              })}
            </div>
          </div>

          {/* Asset Detail & Tree View */}
          {selectedAsset && (
            <div className="lg:col-span-2 glass-panel p-6 sm:p-8 rounded-2xl space-y-6">
              {/* Asset Header Info */}
              <div className="border-b border-slate-800 pb-6">
                <div className="flex items-center justify-between">
                  <div>
                    <span className="text-xs font-mono px-2.5 py-1 rounded-md bg-cyan-500/10 text-cyan-400 border border-cyan-500/20">
                      {selectedAsset.asset_type}
                    </span>
                    <h2 className="text-2xl font-extrabold text-white font-mono mt-2">
                      {selectedAsset.hostname || selectedAsset.ip_address}
                    </h2>
                  </div>
                  <div className="text-right text-xs font-mono text-slate-400">
                    <div>Environment: <span className="text-slate-200">{selectedAsset.environment}</span></div>
                    <div>OS: <span className="text-slate-200">{selectedAsset.operating_system || 'N/A'}</span></div>
                  </div>
                </div>
              </div>

              {/* Exact Acceptance Requirement Tree View */}
              <div className="space-y-4">
                <h3 className="text-xs font-mono uppercase tracking-wider text-slate-400 flex items-center space-x-2">
                  <ShieldAlert className="w-4 h-4 text-cyan-400" />
                  <span>Service & Cryptographic Finding Provenance Tree</span>
                </h3>

                <div className="p-6 rounded-2xl bg-slate-950 border border-slate-800 font-mono text-sm space-y-4">
                  {/* Root Asset Node */}
                  <div className="flex items-center space-x-2 text-cyan-400 font-bold text-base">
                    <Database className="w-5 h-5 text-cyan-400" />
                    <span>{selectedAsset.hostname || selectedAsset.ip_address}</span>
                  </div>

                  {/* Services List */}
                  {selectedAsset.services.length === 0 ? (
                    <div className="pl-6 text-slate-500 text-xs italic">No active network services recorded.</div>
                  ) : (
                    selectedAsset.services.map((srv) => {
                      const tlsVer = srv.metadata_json?.tls_version || '1.3';
                      const serviceFindings = assetFindings.filter((f) => f.service_id === srv.id || !f.service_id);

                      return (
                        <div key={srv.id} className="pl-6 space-y-3 border-l-2 border-slate-800 ml-2">
                          {/* Service Branch */}
                          <div className="flex items-center space-x-2 text-sky-300 font-semibold">
                            <span>└──</span>
                            <Network className="w-4 h-4 text-sky-400" />
                            <span>{srv.application_protocol} :{srv.port}</span>
                            <span className="text-xs text-slate-400">({srv.service_name})</span>
                          </div>

                          {/* Transport / Application Protocol Sub-branch */}
                          <div className="pl-8 space-y-2 border-l-2 border-slate-800 ml-3">
                            <div className="flex items-center space-x-2 text-indigo-300">
                              <span>└──</span>
                              <span className="px-2 py-0.5 rounded bg-indigo-500/10 text-indigo-400 text-xs border border-indigo-500/20">
                                TLS {tlsVer}
                              </span>
                            </div>

                            {/* Cryptographic Findings Primitives */}
                            <div className="pl-8 space-y-2 border-l-2 border-slate-800 ml-3 pt-1">
                              {serviceFindings.map((f, idx) => {
                                const isLast = idx === serviceFindings.length - 1;
                                const algo = f.normalized_algorithm;
                                const status = algo?.quantum_safety_status || 'UNKNOWN';

                                let badgeColor = 'bg-slate-800 text-slate-300 border-slate-700';
                                if (status === 'QUANTUM_VULNERABLE') badgeColor = 'bg-rose-500/10 text-rose-400 border-rose-500/30';
                                if (status === 'PQC_STANDARDIZED') badgeColor = 'bg-emerald-500/10 text-emerald-400 border-emerald-500/30';
                                if (status === 'PQC_CANDIDATE') badgeColor = 'bg-teal-500/10 text-teal-300 border-teal-500/30';
                                if (status === 'HYBRID') badgeColor = 'bg-indigo-500/10 text-indigo-300 border-indigo-500/30';
                                if (status === 'SYMMETRIC' || status === 'HASH') badgeColor = 'bg-cyan-500/10 text-cyan-400 border-cyan-500/30';

                                return (
                                  <div key={f.id} className="flex items-center space-x-3 text-xs">
                                    <span className="text-slate-600 font-mono">{isLast ? '└──' : '├──'}</span>
                                    <KeyRound className="w-3.5 h-3.5 text-cyan-400 flex-shrink-0" />
                                    <span className="font-bold text-white font-mono">{f.raw_algorithm_name}</span>
                                    <span className="text-slate-500 text-[11px]">({f.finding_type})</span>
                                    <span className={`px-2 py-0.5 rounded text-[10px] font-mono border ${badgeColor}`}>
                                      {status}
                                    </span>
                                  </div>
                                );
                              })}
                            </div>
                          </div>
                        </div>
                      );
                    })
                  )}
                </div>
              </div>
            </div>
          )}
        </div>
      )}
    </div>
  );
};
