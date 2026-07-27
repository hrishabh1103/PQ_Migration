import React, { useEffect, useState } from 'react';
import { AuthorizedTarget, CryptoFinding } from '../types';
import { fetchTargets, fetchFindings, bulkRegisterApiServers, uploadOpenApiSpec } from '../services/api';
import { Server, Plus, Upload, Play, CheckCircle2, AlertCircle, Sparkles } from 'lucide-react';

interface ApiServerHubPageProps {
  onNavigateScans: () => void;
}

export const ApiServerHubPage: React.FC<ApiServerHubPageProps> = ({ onNavigateScans }) => {
  const [targets, setTargets] = useState<AuthorizedTarget[]>([]);
  const [findings, setFindings] = useState<CryptoFinding[]>([]);
  const [error, setError] = useState<string | null>(null);

  // Bulk input state
  const [bulkName, setBulkName] = useState<string>('Production API Gateway Cluster');
  const [rawEndpoints, setRawEndpoints] = useState<string>(
    'https://api.company.com\nhttps://auth.company.com/v1\nhttps://payments.internal.net:8443\n10.0.0.15:22'
  );
  const [environment, setEnvironment] = useState<string>('PRODUCTION');
  const [processing, setProcessing] = useState<boolean>(false);
  const [successMsg, setSuccessMsg] = useState<string | null>(null);

  const loadData = async () => {
    try {
      const [tData, fData] = await Promise.all([fetchTargets(), fetchFindings()]);
      setTargets(tData);
      setFindings(fData);
    } catch (err: any) {
      setError(err.message || 'Failed to load API hub data');
    }
  };

  useEffect(() => {
    loadData();
  }, []);

  const handleBulkSubmit = async (e: React.FormEvent) => {
    e.preventDefault();
    const list = rawEndpoints
      .split('\n')
      .map((s) => s.trim())
      .filter((s) => s.length > 0);

    if (list.length === 0) {
      setError('Please enter at least one valid server or API endpoint URL.');
      return;
    }

    try {
      setProcessing(true);
      setError(null);
      const result = await bulkRegisterApiServers(bulkName, list, environment);
      setSuccessMsg(result.message);
      loadData();
      setTimeout(() => {
        setSuccessMsg(null);
        onNavigateScans();
      }, 1500);
    } catch (err: any) {
      setError(err.message || 'Failed to register API endpoints');
    } finally {
      setProcessing(false);
    }
  };

  const handleFileUpload = async (e: React.ChangeEvent<HTMLInputElement>) => {
    const file = e.target.files?.[0];
    if (!file) return;

    try {
      setProcessing(true);
      setError(null);
      const result = await uploadOpenApiSpec(file, environment);
      setSuccessMsg(result.message);
      loadData();
      setTimeout(() => {
        setSuccessMsg(null);
        onNavigateScans();
      }, 1500);
    } catch (err: any) {
      setError(err.message || 'Failed to import OpenAPI spec');
    } finally {
      setProcessing(false);
    }
  };

  return (
    <div className="space-y-8">
      {/* Header */}
      <div className="glass-panel p-6 sm:p-8 rounded-2xl border border-cyan-500/20 bg-gradient-to-r from-slate-900 via-slate-900 to-indigo-950/40 relative overflow-hidden">
        <div className="relative z-10 flex flex-col md:flex-row md:items-center justify-between gap-6">
          <div>
            <div className="flex items-center space-x-2 text-cyan-400 font-mono text-xs mb-2">
              <Server className="w-4 h-4" />
              <span>TEAM API & SERVER DISCOVERY HUB</span>
            </div>
            <h1 className="text-2xl sm:text-3xl font-bold text-white tracking-tight">
              Enterprise Server & API Quantum Testing Center
            </h1>
            <p className="text-slate-400 text-sm mt-1 max-w-2xl">
              Register all company API servers, backend endpoints, and infrastructure IPs. Automatically execute quantum status verification and generate team PQC migration action plans.
            </p>
          </div>
        </div>
      </div>

      {successMsg && (
        <div className="p-4 rounded-xl bg-emerald-500/10 border border-emerald-500/30 text-emerald-300 flex items-center space-x-3 text-sm font-mono">
          <CheckCircle2 className="w-5 h-5 flex-shrink-0" />
          <span>{successMsg}</span>
        </div>
      )}

      {error && (
        <div className="p-4 rounded-xl bg-rose-500/10 border border-rose-500/30 text-rose-300 flex items-center space-x-3 text-sm">
          <AlertCircle className="w-5 h-5 flex-shrink-0" />
          <span>{error}</span>
        </div>
      )}

      {/* Main Grid: Bulk Importer + OpenAPI File Import */}
      <div className="grid grid-cols-1 lg:grid-cols-3 gap-6">
        {/* Bulk Server Textarea Importer */}
        <div className="lg:col-span-2 glass-panel p-6 rounded-2xl space-y-4 border border-slate-800">
          <div className="flex items-center justify-between border-b border-slate-800 pb-3">
            <h2 className="text-lg font-bold text-white flex items-center space-x-2">
              <Plus className="w-5 h-5 text-cyan-400" />
              <span>Bulk API & Server Registration</span>
            </h2>
            <span className="text-xs font-mono text-slate-400">Paste Endpoints or IPs</span>
          </div>

          <form onSubmit={handleBulkSubmit} className="space-y-4">
            <div className="grid grid-cols-1 sm:grid-cols-2 gap-4">
              <div>
                <label className="block text-xs font-mono text-slate-400 mb-1">Cluster / Service Name</label>
                <input
                  type="text"
                  required
                  value={bulkName}
                  onChange={(e) => setBulkName(e.target.value)}
                  className="w-full px-3 py-2 rounded-xl bg-slate-900 border border-slate-800 text-white text-sm focus:outline-none focus:border-cyan-500"
                />
              </div>

              <div>
                <label className="block text-xs font-mono text-slate-400 mb-1">Environment</label>
                <select
                  value={environment}
                  onChange={(e) => setEnvironment(e.target.value)}
                  className="w-full px-3 py-2 rounded-xl bg-slate-900 border border-slate-800 text-white text-sm focus:outline-none focus:border-cyan-500"
                >
                  <option value="PRODUCTION">PRODUCTION</option>
                  <option value="STAGING">STAGING</option>
                  <option value="DEVELOPMENT">DEVELOPMENT</option>
                </select>
              </div>
            </div>

            <div>
              <label className="block text-xs font-mono text-slate-400 mb-1">
                Server Endpoints & API URLs (One per line)
              </label>
              <textarea
                rows={5}
                required
                value={rawEndpoints}
                onChange={(e) => setRawEndpoints(e.target.value)}
                placeholder="https://api.company.com&#10;https://auth.company.com/v1&#10;10.0.0.1:443"
                className="w-full p-3 rounded-xl bg-slate-950 border border-slate-800 text-cyan-300 font-mono text-xs focus:outline-none focus:border-cyan-500"
              />
            </div>

            <div className="flex justify-end">
              <button
                type="submit"
                disabled={processing}
                className="flex items-center space-x-2 px-5 py-2.5 rounded-xl bg-gradient-to-r from-cyan-500 to-blue-600 hover:from-cyan-400 hover:to-blue-500 text-white font-medium text-sm transition shadow-lg shadow-cyan-500/20 disabled:opacity-50"
              >
                <Play className="w-4 h-4 fill-white" />
                <span>{processing ? 'Processing...' : 'Register Servers & Run Quantum Discovery'}</span>
              </button>
            </div>
          </form>
        </div>

        {/* OpenAPI Specification Importer */}
        <div className="glass-panel p-6 rounded-2xl space-y-4 border border-slate-800 flex flex-col justify-between">
          <div>
            <div className="flex items-center justify-between border-b border-slate-800 pb-3 mb-4">
              <h2 className="text-lg font-bold text-white flex items-center space-x-2">
                <Upload className="w-5 h-5 text-indigo-400" />
                <span>Import OpenAPI Spec</span>
              </h2>
              <span className="text-xs font-mono text-slate-400">JSON Format</span>
            </div>

            <p className="text-xs text-slate-400 leading-relaxed mb-4">
              Upload an OpenAPI/Swagger <code className="text-cyan-400 font-mono">.json</code> file to automatically extract all server host URLs and run discovery scans.
            </p>

            <label className="flex flex-col items-center justify-center p-6 border-2 border-dashed border-slate-800 hover:border-cyan-500/50 rounded-2xl cursor-pointer bg-slate-950/50 transition">
              <Upload className="w-8 h-8 text-cyan-400 mb-2" />
              <span className="text-xs font-mono text-slate-300 font-medium">Click to select OpenAPI file</span>
              <span className="text-[11px] text-slate-500 mt-1">supports OpenAPI 3.0 / Swagger 2.0</span>
              <input type="file" accept=".json" onChange={handleFileUpload} className="hidden" />
            </label>
          </div>

          <div className="pt-4 border-t border-slate-800 text-[11px] font-mono text-slate-500 flex items-center space-x-2">
            <Sparkles className="w-3.5 h-3.5 text-cyan-400 flex-shrink-0" />
            <span>Auto-detects API gateway domains and backend TLS ports.</span>
          </div>
        </div>
      </div>

      {/* Server Quantum Status Table */}
      <div className="glass-panel rounded-2xl overflow-hidden">
        <div className="p-4 border-b border-slate-800 bg-slate-900/50 flex items-center justify-between">
          <h2 className="text-sm font-bold text-white font-mono uppercase tracking-wider flex items-center space-x-2">
            <Server className="w-4 h-4 text-cyan-400" />
            <span>Registered Team API & Server Quantum Inventory</span>
          </h2>
          <span className="text-xs font-mono text-slate-400">{targets.length} Total Targets</span>
        </div>

        <div className="overflow-x-auto">
          <table className="w-full text-left border-collapse">
            <thead>
              <tr className="border-b border-slate-800 text-slate-400 text-xs font-mono uppercase">
                <th className="p-4">Server / Target Name</th>
                <th className="p-4">Endpoint Address</th>
                <th className="p-4">Environment</th>
                <th className="p-4">Discovered Primitives</th>
                <th className="p-4">Team Quantum Status</th>
                <th className="p-4 text-right">Team Migration Strategy</th>
              </tr>
            </thead>
            <tbody className="divide-y divide-slate-800 text-sm">
              {targets.length === 0 ? (
                <tr>
                  <td colSpan={6} className="p-8 text-center text-slate-500 font-mono">
                    No servers registered yet. Use the bulk form above to add your team's API endpoints.
                  </td>
                </tr>
              ) : (
                targets.map((t) => {
                  const targetFindings = findings.filter(
                    (f) => f.location_identifier.includes(t.target_value) || f.raw_algorithm_name
                  );
                  const hasVulnerable = targetFindings.some(
                    (f) => f.normalized_algorithm?.quantum_safety_status === 'QUANTUM_VULNERABLE'
                  );
                  const hasPqc = targetFindings.some(
                    (f) => f.normalized_algorithm?.quantum_safety_status === 'PQC_STANDARDIZED' || f.normalized_algorithm?.quantum_safety_status === 'HYBRID'
                  );

                  let statusBadge = (
                    <span className="inline-flex items-center space-x-1.5 px-2.5 py-1 rounded-full text-xs font-mono bg-rose-500/10 text-rose-400 border border-rose-500/30">
                      <AlertCircle className="w-3 h-3" />
                      <span>Vulnerable (RSA/ECDSA)</span>
                    </span>
                  );
                  if (hasPqc) {
                    statusBadge = (
                      <span className="inline-flex items-center space-x-1.5 px-2.5 py-1 rounded-full text-xs font-mono bg-emerald-500/10 text-emerald-400 border border-emerald-500/30">
                        <CheckCircle2 className="w-3 h-3" />
                        <span>Quantum-Resistant</span>
                      </span>
                    );
                  }

                  return (
                    <tr key={t.id} className="hover:bg-slate-900/40 transition">
                      <td className="p-4 font-bold text-white">{t.name}</td>
                      <td className="p-4 font-mono text-xs text-cyan-300">{t.target_value}</td>
                      <td className="p-4">
                        <span className="px-2 py-0.5 rounded text-xs font-mono bg-slate-800 text-slate-300 border border-slate-700">
                          {t.environment}
                        </span>
                      </td>
                      <td className="p-4 font-mono text-xs">
                        <div className="flex flex-wrap gap-1">
                          {targetFindings.slice(0, 3).map((f) => (
                            <span key={f.id} className="px-2 py-0.5 rounded bg-slate-900 text-slate-300 border border-slate-800">
                              {f.raw_algorithm_name}
                            </span>
                          ))}
                        </div>
                      </td>
                      <td className="p-4">{statusBadge}</td>
                      <td className="p-4 text-right font-mono text-xs text-indigo-300">
                        {hasVulnerable ? (
                          <span>Enable Hybrid X25519+MLKEM768 & ML-DSA-65</span>
                        ) : (
                          <span>Compliant / Monitor FIPS updates</span>
                        )}
                      </td>
                    </tr>
                  );
                })
              )}
            </tbody>
          </table>
        </div>
      </div>
    </div>
  );
};
