import React, { useState, useEffect } from 'react';
import { Server, Terminal, Shield, RefreshCw, Play, CheckCircle, AlertTriangle, XCircle, Info } from 'lucide-react';
import { PageHeader } from '../components/common/PageHeader';

interface CoverageItem {
  capability: string;
  plugin_id: string;
  status: string;
  findings_count: number;
  last_evaluated_at: string | null;
}

interface TargetItem {
  id: string;
  target_value: string;
  target_type: string;
  environment: string;
}

export const LinuxCollectorPage: React.FC = () => {
  const [targets, setTargets] = useState<TargetItem[]>([]);
  const [selectedTargetId, setSelectedTargetId] = useState<string>('');
  const [newTargetValue, setNewTargetValue] = useState<string>('localhost');
  const [isRegistering, setIsRegistering] = useState<boolean>(false);
  const [isCollecting, setIsCollecting] = useState<boolean>(false);
  const [coverageData, setCoverageData] = useState<CoverageItem[]>([]);
  const [statusMessage, setStatusMessage] = useState<string | null>(null);

  useEffect(() => {
    fetchTargets();
  }, []);

  useEffect(() => {
    if (selectedTargetId) {
      fetchCoverage(selectedTargetId);
    }
  }, [selectedTargetId]);

  const fetchTargets = async () => {
    try {
      const res = await fetch('/api/v1/targets');
      if (res.ok) {
        const data = await res.json();
        setTargets(data);
        if (data.length > 0 && !selectedTargetId) {
          setSelectedTargetId(data[0].id);
        }
      }
    } catch (err) {
      console.error('Failed to fetch targets:', err);
    }
  };

  const fetchCoverage = async (targetId: string) => {
    try {
      const res = await fetch(`/api/v1/collectors/linux/coverage/${targetId}`);
      if (res.ok) {
        const data = await res.json();
        setCoverageData(data.coverage || []);
      }
    } catch (err) {
      console.error('Failed to fetch coverage:', err);
    }
  };

  const handleRegisterTarget = async (e: React.FormEvent) => {
    e.preventDefault();
    if (!newTargetValue.trim()) return;

    setIsRegistering(true);
    try {
      const res = await fetch('/api/v1/targets', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({
          target_value: newTargetValue,
          target_type: 'CLOUD_SERVER',
          environment: 'PRODUCTION',
          description: 'Linux Server Collector Target'
        })
      });

      if (res.ok) {
        const created = await res.json();
        await fetchTargets();
        setSelectedTargetId(created.id);
        setStatusMessage(`Target '${newTargetValue}' registered successfully.`);
      }
    } catch (err) {
      setStatusMessage(`Registration failed: ${err}`);
    } finally {
      setIsRegistering(false);
    }
  };

  const handleRunCollection = async () => {
    if (!selectedTargetId) return;

    setIsCollecting(true);
    setStatusMessage('Initiating Linux Collector discovery modules...');
    try {
      const res = await fetch('/api/v1/collectors/linux/run', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ target_id: selectedTargetId, plugin_id: 'linux-host' })
      });

      if (res.ok) {
        setStatusMessage('Linux Host Collection completed. Refreshing coverage state...');
        setTimeout(() => {
          fetchCoverage(selectedTargetId);
          setIsCollecting(false);
        }, 1500);
      } else {
        setStatusMessage('Collection request returned error.');
        setIsCollecting(false);
      }
    } catch (err) {
      setStatusMessage(`Collection failed: ${err}`);
      setIsCollecting(false);
    }
  };

  const getStatusBadge = (status: string) => {
    switch (status) {
      case 'SCANNED':
        return <span className="inline-flex items-center px-2.5 py-0.5 rounded-full text-xs font-medium bg-emerald-500/10 text-emerald-400 border border-emerald-500/20"><CheckCircle className="w-3 h-3 mr-1" /> SCANNED</span>;
      case 'PARTIALLY_SCANNED':
        return <span className="inline-flex items-center px-2.5 py-0.5 rounded-full text-xs font-medium bg-amber-500/10 text-amber-400 border border-amber-500/20"><AlertTriangle className="w-3 h-3 mr-1" /> PARTIAL</span>;
      case 'FAILED':
        return <span className="inline-flex items-center px-2.5 py-0.5 rounded-full text-xs font-medium bg-rose-500/10 text-rose-400 border border-rose-500/20"><XCircle className="w-3 h-3 mr-1" /> FAILED</span>;
      case 'NOT_APPLICABLE':
        return <span className="inline-flex items-center px-2.5 py-0.5 rounded-full text-xs font-medium bg-slate-500/10 text-slate-400 border border-slate-500/20"><Info className="w-3 h-3 mr-1" /> N/A</span>;
      default:
        return <span className="inline-flex items-center px-2.5 py-0.5 rounded-full text-xs font-medium bg-blue-500/10 text-blue-400 border border-blue-500/20"><Info className="w-3 h-3 mr-1" /> NOT SCANNED</span>;
    }
  };

  const moduleCapabilities = [
    { cap: 'HOST_INVENTORY', name: 'Host & System Identity', desc: 'Hostname, FQDN, Linux OS Distribution, Kernel version' },
    { cap: 'CRYPTO_LIBRARY', name: 'Crypto Libraries & Packages', desc: 'OpenSSL, LibreSSL, OpenSSH, GnuTLS, NSS, BouncyCastle' },
    { cap: 'CRYPTO_CONFIGURATION', name: 'OpenSSL & OpenSSH Config', desc: 'FIPS provider, sshd_config KEX & cipher policy' },
    { cap: 'SERVICE_INVENTORY', name: 'Listening Services', desc: 'Listening TCP/UDP ports, PIDs, process linkage' },
    { cap: 'PROCESS_INVENTORY', name: 'Crypto Processes', desc: 'sshd, nginx, apache, java, python runtimes (sanitized)' },
    { cap: 'X509', name: 'Public X.509 Certificates', desc: 'Bounded certificate stores, subject, issuer, validity, SANs' },
    { cap: 'KEYSTORE', name: 'System & Application Keystores', desc: 'JKS, PKCS#12, truststores metadata' },
    { cap: 'SYSTEM_CRYPTO_POLICY', name: 'System Cryptographic Policy', desc: 'RHEL/Fedora system-wide crypto policy state' }
  ];

  return (
    <div className="space-y-6">
      {/* Reusable Page Header with Breadcrumbs */}
      <PageHeader
        title="Linux Host Collector"
        description="Production-oriented read-only metadata discovery for Linux servers & cryptographic posture."
        icon={Server}
        badge="LocalTransport Bounded"
        breadcrumbs={[{ label: 'Discovery' }, { label: 'Linux Collector' }]}
      />

      {/* Target Registration & Action Bar */}
      <div className="grid grid-cols-1 lg:grid-cols-3 gap-6">
        <div className="bg-slate-900 border border-slate-800 rounded-xl p-5">
          <h3 className="text-sm font-semibold text-slate-200 mb-3 flex items-center">
            <Terminal className="w-4 h-4 mr-2 text-cyan-400" /> Register Linux Target
          </h3>
          <form onSubmit={handleRegisterTarget} className="space-y-3">
            <input
              type="text"
              value={newTargetValue}
              onChange={(e) => setNewTargetValue(e.target.value)}
              placeholder="e.g. localhost or 127.0.0.1"
              className="w-full bg-slate-950 border border-slate-800 rounded-lg px-3 py-2 text-sm text-slate-200 focus:outline-none focus:border-cyan-500"
            />
            <button
              type="submit"
              disabled={isRegistering}
              className="w-full bg-cyan-600 hover:bg-cyan-500 text-white font-medium py-2 rounded-lg text-sm transition-colors disabled:opacity-50"
            >
              {isRegistering ? 'Registering...' : 'Register Target'}
            </button>
          </form>
        </div>

        <div className="bg-slate-900 border border-slate-800 rounded-xl p-5 lg:col-span-2 flex flex-col justify-between">
          <div>
            <h3 className="text-sm font-semibold text-slate-200 mb-3 flex items-center">
              <Play className="w-4 h-4 mr-2 text-emerald-400" /> Initiate Host Collection
            </h3>
            <div className="flex items-center space-x-4">
              <select
                value={selectedTargetId}
                onChange={(e) => setSelectedTargetId(e.target.value)}
                className="bg-slate-950 border border-slate-800 rounded-lg px-3 py-2 text-sm text-slate-200 flex-grow focus:outline-none"
              >
                {targets.map((t) => (
                  <option key={t.id} value={t.id}>
                    {t.target_value} ({t.environment})
                  </option>
                ))}
              </select>
              <button
                onClick={handleRunCollection}
                disabled={isCollecting || !selectedTargetId}
                className="bg-emerald-600 hover:bg-emerald-500 text-white font-medium px-5 py-2 rounded-lg text-sm transition-colors flex items-center space-x-2 disabled:opacity-50"
              >
                {isCollecting ? (
                  <>
                    <RefreshCw className="w-4 h-4 animate-spin" />
                    <span>Collecting...</span>
                  </>
                ) : (
                  <>
                    <Play className="w-4 h-4" />
                    <span>Run Linux Collector</span>
                  </>
                )}
              </button>
            </div>
          </div>
          {statusMessage && (
            <p className="text-xs font-mono text-cyan-400 mt-3 bg-slate-950 p-2 rounded border border-slate-800">
              {statusMessage}
            </p>
          )}
        </div>
      </div>

      {/* 13-Module Coverage Status Grid */}
      <div className="bg-slate-900 border border-slate-800 rounded-xl p-6">
        <h3 className="text-lg font-bold text-slate-100 mb-4 flex items-center">
          <Shield className="w-5 h-5 mr-2 text-indigo-400" /> Discovery Module Coverage Status
        </h3>
        <div className="grid grid-cols-1 md:grid-cols-2 lg:grid-cols-4 gap-4">
          {moduleCapabilities.map((item) => {
            const cov = coverageData.find((c) => c.capability === item.cap);
            const status = cov ? cov.status : 'NOT_SCANNED';
            const count = cov ? cov.findings_count : 0;

            return (
              <div key={item.cap} className="bg-slate-950 border border-slate-800 rounded-lg p-4 flex flex-col justify-between">
                <div>
                  <div className="flex items-center justify-between mb-2">
                    <span className="text-xs font-mono text-slate-400">{item.cap}</span>
                    {getStatusBadge(status)}
                  </div>
                  <h4 className="text-sm font-semibold text-slate-200">{item.name}</h4>
                  <p className="text-xs text-slate-400 mt-1">{item.desc}</p>
                </div>
                <div className="mt-3 pt-2 border-t border-slate-900 flex justify-between items-center text-xs text-slate-400">
                  <span>Observations: <strong className="text-slate-200">{count}</strong></span>
                  <span className="font-mono text-[10px] text-slate-400">
                    {cov?.last_evaluated_at ? new Date(cov.last_evaluated_at).toLocaleTimeString() : 'Never'}
                  </span>
                </div>
              </div>
            );
          })}
        </div>
      </div>
    </div>
  );
};
