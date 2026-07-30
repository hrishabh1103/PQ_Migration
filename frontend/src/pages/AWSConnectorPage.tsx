import React, { useState, useEffect } from 'react';
import { Cloud, Shield, CheckCircle, AlertTriangle, XCircle, Info, RefreshCw, Play, Key } from 'lucide-react';
import { PageHeader } from '../components/common/PageHeader';

interface AWSIdentity {
  account_id: string;
  arn: string;
  user_id: string;
  partition: string;
  validated: boolean;
  error?: string;
}

interface CoverageItem {
  name: string;
  service: string;
  capability: string;
  status: string;
}

interface AWSResource {
  id: string;
  asset_type: string;
  asset_category: string;
  provider_resource_id: string;
  external_id: string;
  hostname: string;
  region: string;
  metadata: Record<string, any>;
}

export const AWSConnectorPage: React.FC = () => {
  const [regionName, setRegionName] = useState<string>('us-east-1');
  const [selectedRegions, setSelectedRegions] = useState<string[]>(['us-east-1', 'ap-south-1']);
  const [identity, setIdentity] = useState<AWSIdentity | null>(null);
  const [isValidating, setIsValidating] = useState<boolean>(false);
  const [isSyncing, setIsSyncing] = useState<boolean>(false);
  const [syncStatus, setSyncStatus] = useState<string | null>(null);
  const [coverage, setCoverage] = useState<CoverageItem[]>([]);
  const [resources, setResources] = useState<AWSResource[]>([]);
  const [targetsList, setTargetsList] = useState<any[]>([]);
  const [targetId, setTargetId] = useState<string>('');

  useEffect(() => {
    fetchTargetsAndCoverage();
  }, []);

  const fetchTargetsAndCoverage = async () => {
    try {
      const tRes = await fetch('/api/v1/targets');
      if (tRes.ok) {
        const targets = await tRes.json();
        setTargetsList(targets);
        const awsTarget = targets.find((t: any) => t.target_type === 'CLOUD_PROVIDER') || targets[0];
        if (awsTarget) {
          const tId = awsTarget.id;
          setTargetId(tId);
          fetchCoverage(tId);
          fetchInventory(tId);
        }
      }
    } catch (err) {
      console.error('Failed to fetch targets:', err);
    }
  };

  const handleTargetChange = (tId: string) => {
    setTargetId(tId);
    fetchCoverage(tId);
    fetchInventory(tId);
  };

  const fetchCoverage = async (tId: string) => {
    try {
      const res = await fetch(`/api/v1/connectors/aws/coverage/${tId}`);
      if (res.ok) {
        const data = await res.json();
        setCoverage(data.coverage || []);
      }
    } catch (err) {
      console.error('Failed to fetch AWS coverage:', err);
    }
  };

  const fetchInventory = async (tId: string) => {
    try {
      const res = await fetch(`/api/v1/connectors/aws/inventory/${tId}`);
      if (res.ok) {
        const data = await res.json();
        setResources(data.assets || []);
      }
    } catch (err) {
      console.error('Failed to fetch AWS inventory:', err);
    }
  };

  const handleValidateIdentity = async () => {
    setIsValidating(true);
    setSyncStatus('Validating AWS STS caller identity...');
    try {
      const res = await fetch('/api/v1/connectors/aws/validate', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ region_name: regionName })
      });
      if (res.ok) {
        const data = await res.json();
        setIdentity(data);
        setSyncStatus(`STS Caller Identity Validated! Account ID: ${data.account_id}`);
      } else {
        const err = await res.json();
        setSyncStatus(`Validation Error: ${err.detail}`);
      }
    } catch (e: any) {
      setSyncStatus(`Connection failed: ${e}`);
    } finally {
      setIsValidating(false);
    }
  };

  const handleTriggerSync = async () => {
    setIsSyncing(true);
    setSyncStatus('Initiating AWS Connector read-only discovery sync across authorized regions...');
    try {
      let activeTargetId = targetId;

      if (!activeTargetId) {
        // Auto-register AWS target if none exists yet
        const regRes = await fetch('/api/v1/targets', {
          method: 'POST',
          headers: { 'Content-Type': 'application/json' },
          body: JSON.stringify({
            name: `AWS Cloud Account (${identity?.account_id || 'Primary'})`,
            target_type: 'CLOUD_PROVIDER',
            target_value: identity?.account_id || 'aws-account',
            is_authorized: true,
            environment: 'PRODUCTION'
          })
        });
        if (regRes.ok) {
          const newTarget = await regRes.json();
          activeTargetId = newTarget.id;
          setTargetId(newTarget.id);
        }
      }

      const res = await fetch('/api/v1/connectors/aws/sync', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ target_id: activeTargetId, allowed_regions: selectedRegions })
      });

      if (res.ok) {
        setSyncStatus('AWS Discovery Sync completed successfully. Refreshing coverage & inventory...');
        setTimeout(() => {
          if (activeTargetId) {
            fetchCoverage(activeTargetId);
            fetchInventory(activeTargetId);
          }
          setIsSyncing(false);
        }, 1500);
      } else {
        const err = await res.json();
        setSyncStatus(`Sync failed: ${err.detail}`);
        setIsSyncing(false);
      }
    } catch (e: any) {
      setSyncStatus(`Sync error: ${e}`);
      setIsSyncing(false);
    }
  };

  const toggleRegion = (reg: string) => {
    if (selectedRegions.includes(reg)) {
      if (selectedRegions.length > 1) {
        setSelectedRegions(selectedRegions.filter((r) => r !== reg));
      }
    } else {
      setSelectedRegions([...selectedRegions, reg]);
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
      default:
        return <span className="inline-flex items-center px-2.5 py-0.5 rounded-full text-xs font-medium bg-slate-500/10 text-slate-400 border border-slate-500/20"><Info className="w-3 h-3 mr-1" /> NOT SCANNED</span>;
    }
  };

  return (
    <div className="space-y-6">
      {/* Reusable Page Header */}
      <PageHeader
        title="AWS Cloud Cryptographic Discovery Connector"
        description="Read-only discovery of AWS KMS key specifications, X.509 ACM certificates, ELBv2 SSL policies, S3 encryption, RDS storage encryption, and CloudFront TLS configurations."
        icon={Cloud}
        badge="AWSConnector V1"
        breadcrumbs={[{ label: 'Discovery' }, { label: 'AWS Connector' }]}
      />

      {/* Identity Validation & Sync Controls */}
      <div className="grid grid-cols-1 lg:grid-cols-3 gap-6">
        <div className="bg-slate-900 border border-slate-800 rounded-xl p-5">
          <h3 className="text-sm font-semibold text-slate-200 mb-3 flex items-center">
            <Shield className="w-4 h-4 mr-2 text-cyan-400" /> STS Identity Validation
          </h3>
          <div className="space-y-3">
            <div>
              <label className="block text-xs font-mono text-slate-400 mb-1">Default Region</label>
              <input
                type="text"
                value={regionName}
                onChange={(e) => setRegionName(e.target.value)}
                className="w-full bg-slate-950 border border-slate-800 rounded-lg px-3 py-2 text-xs text-slate-200 font-mono focus:outline-none focus:border-cyan-500"
              />
            </div>
            <button
              onClick={handleValidateIdentity}
              disabled={isValidating}
              className="w-full bg-cyan-600 hover:bg-cyan-500 text-white font-medium py-2 rounded-lg text-xs transition-colors disabled:opacity-50"
            >
              {isValidating ? 'Validating STS...' : 'Validate Caller Identity'}
            </button>
            {identity && (
              <div className="p-3 bg-slate-950 border border-slate-800 rounded-lg text-xs space-y-1 font-mono">
                <div className="text-emerald-400 font-semibold flex items-center">
                  <CheckCircle className="w-3.5 h-3.5 mr-1" /> Identity Validated
                </div>
                <div className="text-slate-300">Account: <span className="text-cyan-300">{identity.account_id}</span></div>
                <div className="text-slate-400 truncate" title={identity.arn}>ARN: {identity.arn}</div>
              </div>
            )}
          </div>
        </div>

        <div className="bg-slate-900 border border-slate-800 rounded-xl p-5 lg:col-span-2 flex flex-col justify-between">
          <div>
            <h3 className="text-sm font-semibold text-slate-200 mb-3 flex items-center">
              <Play className="w-4 h-4 mr-2 text-emerald-400" /> Region Allowlist & Discovery Sync
            </h3>
            <div className="space-y-3">
              {targetsList.length > 0 && (
                <div>
                  <label className="block text-xs font-mono text-slate-400 mb-1">Target Account / Provider Scope</label>
                  <select
                    value={targetId}
                    onChange={(e) => handleTargetChange(e.target.value)}
                    className="w-full bg-slate-950 border border-slate-800 rounded-lg px-3 py-2 text-xs text-cyan-300 font-mono focus:outline-none focus:border-cyan-500"
                  >
                    {targetsList.map((t: any) => (
                      <option key={t.id} value={t.id}>
                        {t.name} ({t.target_value}) [{t.target_type}]
                      </option>
                    ))}
                  </select>
                </div>
              )}

              <div>
                <label className="block text-xs font-mono text-slate-400 mb-1">Authorized AWS Regions</label>
                <div className="flex flex-wrap gap-2">
                  {['us-east-1', 'us-west-2', 'eu-west-1', 'ap-south-1'].map((reg) => (
                    <button
                      key={reg}
                      onClick={() => toggleRegion(reg)}
                      className={`px-3 py-1.5 rounded-lg text-xs font-mono transition-all ${
                        selectedRegions.includes(reg)
                          ? 'bg-cyan-500/20 text-cyan-400 border border-cyan-500/40 font-semibold'
                          : 'bg-slate-950 text-slate-400 border border-slate-800 hover:border-slate-700'
                      }`}
                    >
                      {reg} {selectedRegions.includes(reg) ? '✓' : ''}
                    </button>
                  ))}
                </div>
              </div>

              <div className="pt-2">
                <button
                  onClick={handleTriggerSync}
                  disabled={isSyncing || !targetId}
                  className="bg-emerald-600 hover:bg-emerald-500 text-white font-medium px-6 py-2.5 rounded-lg text-sm transition-colors flex items-center space-x-2 disabled:opacity-50"
                >
                  {isSyncing ? (
                    <>
                      <RefreshCw className="w-4 h-4 animate-spin" />
                      <span>Syncing AWS Services...</span>
                    </>
                  ) : (
                    <>
                      <Play className="w-4 h-4" />
                      <span>Trigger AWS Discovery Sync</span>
                    </>
                  )}
                </button>
              </div>
            </div>
          </div>

          {syncStatus && (
            <p className="text-xs font-mono text-cyan-400 mt-3 bg-slate-950 p-2.5 rounded border border-slate-800">
              {syncStatus}
            </p>
          )}
        </div>
      </div>

      {/* AWS Service Coverage Grid */}
      <div className="bg-slate-900 border border-slate-800 rounded-xl p-6">
        <h3 className="text-base font-bold text-slate-100 mb-4 flex items-center">
          <Shield className="w-4.5 h-4.5 mr-2 text-indigo-400" /> AWS Service Discovery Coverage
        </h3>
        <div className="grid grid-cols-1 md:grid-cols-2 lg:grid-cols-5 gap-4">
          {coverage.map((item) => (
            <div key={item.name} className="bg-slate-950 border border-slate-800 rounded-lg p-3.5 flex flex-col justify-between">
              <div>
                <div className="flex items-center justify-between mb-2">
                  <span className="text-[10px] font-mono text-slate-400 uppercase">{item.service}</span>
                  {getStatusBadge(item.status)}
                </div>
                <h4 className="text-xs font-semibold text-slate-200">{item.name}</h4>
              </div>
              <div className="mt-3 text-[10px] font-mono text-cyan-400/80">
                {item.capability}
              </div>
            </div>
          ))}
        </div>
      </div>

      {/* Discovered AWS Resources & KMS Key Inventory Table */}
      <div className="bg-slate-900 border border-slate-800 rounded-xl p-6">
        <div className="flex items-center justify-between mb-4">
          <h3 className="text-base font-bold text-slate-100 flex items-center">
            <Key className="w-4.5 h-4.5 mr-2 text-cyan-400" /> Discovered AWS Inventory Assets ({resources.length})
          </h3>
          <span className="text-xs font-mono text-slate-400">Provider: AWS</span>
        </div>

        {resources.length === 0 ? (
          <div className="py-12 text-center text-slate-500 text-sm font-mono">
            No AWS resources discovered yet. Trigger AWS Discovery Sync to populate data.
          </div>
        ) : (
          <div className="overflow-x-auto">
            <table className="w-full text-left text-xs font-mono text-slate-300">
              <thead className="bg-slate-950 text-slate-400 uppercase text-[10px] tracking-wider border-b border-slate-800">
                <tr>
                  <th className="p-3">Asset Type</th>
                  <th className="p-3">Provider Resource ARN / ID</th>
                  <th className="p-3">Region</th>
                  <th className="p-3">Metadata</th>
                </tr>
              </thead>
              <tbody className="divide-y divide-slate-800/60">
                {resources.map((res) => (
                  <tr key={res.id} className="hover:bg-slate-800/40">
                    <td className="p-3">
                      <span className="px-2 py-0.5 rounded bg-cyan-500/10 text-cyan-400 border border-cyan-500/20 text-[10px]">
                        {res.asset_type}
                      </span>
                    </td>
                    <td className="p-3 font-semibold text-slate-100 truncate max-w-xs" title={res.provider_resource_id}>
                      {res.provider_resource_id}
                    </td>
                    <td className="p-3 text-slate-400">{res.region}</td>
                    <td className="p-3 text-slate-400 truncate max-w-md" title={JSON.stringify(res.metadata)}>
                      {JSON.stringify(res.metadata)}
                    </td>
                  </tr>
                ))}
              </tbody>
            </table>
          </div>
        )}
      </div>
    </div>
  );
};
