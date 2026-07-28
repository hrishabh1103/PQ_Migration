import React, { useState, useEffect } from 'react';
import { 
  Network, Server, Shield, Database, Activity, RefreshCw, 
  Filter, Info, ChevronRight
} from 'lucide-react';

interface NodeItem {
  id: string;
  entity_type: string;
  entity_id: string;
  label: string;
  category: string;
  details: Record<string, any>;
}

interface EdgeItem {
  id: string;
  source: string;
  target: string;
  label: string;
  type: string;
  confidence?: string;
}

export const InventoryGraphPage: React.FC = () => {
  const [nodes, setNodes] = useState<NodeItem[]>([
    {
      id: 'Asset:asset-1',
      entity_type: 'Asset',
      entity_id: 'asset-1',
      label: 'payment-gateway-prod.company.com',
      category: 'HOST',
      details: { environment: 'PRODUCTION', status: 'ACTIVE', os: 'Ubuntu 22.04' }
    },
    {
      id: 'Service:service-1',
      entity_type: 'Service',
      entity_id: 'service-1',
      label: 'https:443',
      category: 'SERVICE',
      details: { protocol: 'HTTPS', port: 443 }
    },
    {
      id: 'CryptoObject:cert-1',
      entity_type: 'CryptoObject',
      entity_id: 'cert-1',
      label: 'RSA-2048 (DigiCert TLS Cert)',
      category: 'CERTIFICATE',
      details: { provider: 'DigiCert', identity_key: 'sha256:a1b2c3d4' }
    },
    {
      id: 'CryptoObject:algo-1',
      entity_type: 'CryptoObject',
      entity_id: 'algo-1',
      label: 'X25519 (Key Exchange)',
      category: 'ALGORITHM',
      details: { provider: 'OpenSSL', identity_key: 'algo:x25519' }
    },
    {
      id: 'DataAsset:da-1',
      entity_type: 'DataAsset',
      entity_id: 'da-1',
      label: 'Payment Cards Data',
      category: 'DATA_ASSET',
      details: { classification: 'RESTRICTED', criticality: 'HIGH' }
    }
  ]);

  const [edges, setEdges] = useState<EdgeItem[]>([
    { id: 'e1', source: 'Service:service-1', target: 'Asset:asset-1', label: 'RUNS_ON', type: 'RELATIONSHIP' },
    { id: 'e2', source: 'Service:service-1', target: 'CryptoObject:cert-1', label: 'TERMINATES_TLS_AT', type: 'RELATIONSHIP' },
    { id: 'e3', source: 'Service:service-1', target: 'CryptoObject:algo-1', label: 'USES', type: 'RELATIONSHIP' },
    { id: 'e4', source: 'Asset:asset-1', target: 'DataAsset:da-1', label: 'STORES_DATA', type: 'DATA_FLOW' }
  ]);

  const [selectedNode, setSelectedNode] = useState<NodeItem | null>(nodes[0]);
  const [filterNodeType, setFilterNodeType] = useState<string>('ALL');
  const [filterRelType, setFilterRelType] = useState<string>('ALL');
  const [depth, setDepth] = useState<number>(1);
  const [loading, setLoading] = useState<boolean>(false);

  const fetchGraphData = async () => {
    setLoading(true);
    try {
      const res = await fetch(`/api/v1/graph/entity/Asset/asset-1?depth=${depth}`);
      if (res.ok) {
        const data = await res.json();
        if (data.nodes && data.nodes.length > 0) {
          setNodes(data.nodes);
        }
        if (data.edges && data.edges.length > 0) {
          setEdges(data.edges);
        }
      }
    } catch (err) {
      console.error('Failed to load entity graph:', err);
    } finally {
      setLoading(false);
    }
  };

  useEffect(() => {
    fetchGraphData();
  }, [depth]);

  const filteredNodes = nodes.filter(n => {
    if (filterNodeType === 'ALL') return true;
    return n.entity_type === filterNodeType || n.category === filterNodeType;
  });

  const filteredEdges = edges.filter(e => {
    if (filterRelType === 'ALL') return true;
    return e.label === filterRelType || e.type === filterRelType;
  });

  return (
    <div className="space-y-6">
      {/* Page Header */}
      <div className="bg-slate-900 border border-slate-800 rounded-2xl p-6 shadow-sm flex flex-col md:flex-row items-start md:items-center justify-between gap-4">
        <div>
          <div className="inline-flex items-center gap-2 px-3 py-1 rounded-full bg-cyan-500/10 border border-cyan-500/20 text-cyan-400 text-xs font-semibold uppercase tracking-wider mb-2">
            <Network className="w-3.5 h-3.5" /> Enterprise Topology Explorer
          </div>
          <h1 className="text-2xl font-bold text-white tracking-tight">
            Enterprise Cryptographic Inventory Graph
          </h1>
          <p className="text-xs text-slate-400 mt-1 max-w-2xl">
            Interactive multi-depth topology visualizing relationships between enterprise Assets, Services, CryptoObjects (keys, certs, algorithms), and Data Assets.
          </p>
        </div>

        <div className="flex items-center gap-3">
          <div className="flex items-center gap-2 bg-slate-950 px-3 py-1.5 rounded-xl border border-slate-800 text-xs text-slate-300">
            <span>Traversal Depth:</span>
            <select
              value={depth}
              onChange={e => setDepth(Number(e.target.value))}
              className="bg-slate-900 text-cyan-400 font-semibold px-2 py-0.5 rounded border border-slate-700 outline-none"
            >
              <option value={1}>1 Hop</option>
              <option value={2}>2 Hops</option>
              <option value={3}>3 Hops (Max)</option>
            </select>
          </div>
          <button
            onClick={fetchGraphData}
            disabled={loading}
            className="px-4 py-2 bg-cyan-600 hover:bg-cyan-500 text-white rounded-xl font-medium text-xs flex items-center gap-2 transition-all cursor-pointer"
          >
            <RefreshCw className={`w-3.5 h-3.5 ${loading ? 'animate-spin' : ''}`} />
            Refresh Graph
          </button>
        </div>
      </div>

      {/* Filters Toolbar */}
      <div className="bg-slate-900/60 border border-slate-800/80 rounded-xl p-4 flex flex-wrap items-center justify-between gap-4 text-xs">
        <div className="flex items-center gap-4 flex-wrap">
          <div className="flex items-center gap-2">
            <Filter className="w-4 h-4 text-slate-400" />
            <span className="font-semibold text-slate-300">Filter Nodes:</span>
            <select
              value={filterNodeType}
              onChange={e => setFilterNodeType(e.target.value)}
              className="bg-slate-950 border border-slate-800 rounded-lg px-2.5 py-1.5 text-slate-200 outline-none"
            >
              <option value="ALL">All Node Types ({nodes.length})</option>
              <option value="Asset">Assets</option>
              <option value="Service">Services</option>
              <option value="CERTIFICATE">Certificates</option>
              <option value="ALGORITHM">Algorithms</option>
              <option value="DATA_ASSET">Data Assets</option>
            </select>
          </div>

          <div className="flex items-center gap-2">
            <span className="font-semibold text-slate-300">Filter Relationships:</span>
            <select
              value={filterRelType}
              onChange={e => setFilterRelType(e.target.value)}
              className="bg-slate-950 border border-slate-800 rounded-lg px-2.5 py-1.5 text-slate-200 outline-none"
            >
              <option value="ALL">All Relationships ({edges.length})</option>
              <option value="RUNS_ON">RUNS_ON</option>
              <option value="TERMINATES_TLS_AT">TERMINATES_TLS_AT</option>
              <option value="USES">USES</option>
              <option value="DATA_FLOW">DATA_FLOW</option>
            </select>
          </div>
        </div>

        <div className="text-slate-400 font-mono text-[11px]">
          Nodes: <span className="text-cyan-400 font-semibold">{filteredNodes.length}</span> | Edges: <span className="text-indigo-400 font-semibold">{filteredEdges.length}</span>
        </div>
      </div>

      {/* Main Canvas & Detail Sidebar */}
      <div className="grid grid-cols-1 lg:grid-cols-3 gap-6">
        {/* Interactive Graph Canvas */}
        <div className="lg:col-span-2 bg-slate-950 border border-slate-800 rounded-2xl p-6 shadow-inner min-h-[480px] flex flex-col justify-between relative overflow-hidden">
          {/* Subtle Grid Background */}
          <div className="absolute inset-0 bg-[radial-gradient(#1e293b_1px,transparent_1px)] [background-size:16px_16px] opacity-40 pointer-events-none" />

          {/* Canvas Header */}
          <div className="relative z-10 flex items-center justify-between text-xs text-slate-400">
            <span className="flex items-center gap-2 font-mono">
              <Activity className="w-4 h-4 text-emerald-400 animate-pulse" /> Live Graph Canvas
            </span>
            <span>Click any node to inspect details</span>
          </div>

          {/* Graph Nodes Representation */}
          <div className="relative z-10 my-auto py-8 grid grid-cols-1 sm:grid-cols-2 md:grid-cols-3 gap-4">
            {filteredNodes.map((n) => {
              const isSelected = selectedNode?.id === n.id;
              const isCrypto = n.entity_type === 'CryptoObject';
              const isData = n.entity_type === 'DataAsset';
              const isAsset = n.entity_type === 'Asset';

              return (
                <div
                  key={n.id}
                  onClick={() => setSelectedNode(n)}
                  className={`p-4 rounded-xl border transition-all cursor-pointer shadow-md ${
                    isSelected
                      ? 'bg-slate-900 border-cyan-400 ring-2 ring-cyan-400/30 scale-105'
                      : 'bg-slate-900/80 border-slate-800 hover:border-slate-700 hover:bg-slate-900'
                  }`}
                >
                  <div className="flex items-center justify-between mb-2">
                    <span className={`p-1.5 rounded-lg text-xs font-semibold ${
                      isAsset ? 'bg-indigo-500/10 text-indigo-400' :
                      isCrypto ? 'bg-cyan-500/10 text-cyan-400' :
                      isData ? 'bg-emerald-500/10 text-emerald-400' :
                      'bg-purple-500/10 text-purple-400'
                    }`}>
                      {isAsset ? <Server className="w-4 h-4" /> :
                       isCrypto ? <Shield className="w-4 h-4" /> :
                       isData ? <Database className="w-4 h-4" /> :
                       <Network className="w-4 h-4" />}
                    </span>
                    <span className="text-[10px] font-mono px-2 py-0.5 rounded bg-slate-950 text-slate-400 border border-slate-800">
                      {n.category}
                    </span>
                  </div>

                  <div className="font-semibold text-xs text-white truncate" title={n.label}>
                    {n.label}
                  </div>
                  <div className="text-[11px] font-mono text-slate-400 mt-1 truncate">
                    ID: {n.entity_id}
                  </div>
                </div>
              );
            })}
          </div>

          {/* Graph Edges Indicator */}
          <div className="relative z-10 border-t border-slate-900 pt-4 flex flex-wrap items-center gap-3 text-[11px]">
            <span className="text-slate-400 font-semibold">Active Edges:</span>
            {filteredEdges.map(e => (
              <span key={e.id} className="px-2.5 py-1 rounded bg-slate-900 border border-slate-800 text-slate-300 flex items-center gap-1.5 font-mono">
                <span className="text-cyan-400 font-semibold">{e.label}</span>
                <ChevronRight className="w-3 h-3 text-slate-600" />
              </span>
            ))}
          </div>
        </div>

        {/* Selected Entity Inspector Sidebar */}
        <div className="bg-slate-900 border border-slate-800 rounded-2xl p-6 space-y-5 shadow-sm">
          <div className="flex items-center gap-2 border-b border-slate-800 pb-4 text-white font-semibold text-base">
            <Info className="w-4 h-4 text-cyan-400" />
            Entity Inspector
          </div>

          {selectedNode ? (
            <div className="space-y-4 text-xs">
              <div>
                <span className="text-slate-400 block text-[11px]">Entity Label</span>
                <span className="text-sm font-bold text-white block mt-0.5">{selectedNode.label}</span>
              </div>

              <div className="grid grid-cols-2 gap-3 pt-2 border-t border-slate-800">
                <div>
                  <span className="text-slate-400 block text-[10px] uppercase tracking-wider">Entity Type</span>
                  <span className="font-mono font-semibold text-cyan-400">{selectedNode.entity_type}</span>
                </div>
                <div>
                  <span className="text-slate-400 block text-[10px] uppercase tracking-wider">Category</span>
                  <span className="font-mono font-semibold text-indigo-400">{selectedNode.category}</span>
                </div>
              </div>

              <div className="pt-2 border-t border-slate-800">
                <span className="text-slate-400 block text-[10px] uppercase tracking-wider mb-2">Entity Properties</span>
                <div className="bg-slate-950 border border-slate-800 rounded-xl p-3 space-y-1.5 font-mono text-[11px]">
                  {Object.entries(selectedNode.details).map(([k, v]) => (
                    <div key={k} className="flex items-center justify-between text-slate-300">
                      <span className="text-slate-400">{k}:</span>
                      <span className="text-slate-200 font-semibold">{String(v)}</span>
                    </div>
                  ))}
                </div>
              </div>

              <div className="pt-2 border-t border-slate-800 space-y-2">
                <span className="text-slate-400 block text-[10px] uppercase tracking-wider">Connected Relationships</span>
                {edges.filter(e => e.source === selectedNode.id || e.target === selectedNode.id).map(rel => (
                  <div key={rel.id} className="p-2.5 rounded-lg bg-slate-950 border border-slate-800 flex items-center justify-between text-[11px]">
                    <span className="text-cyan-400 font-mono font-semibold">{rel.label}</span>
                    <span className="text-slate-400 text-[10px]">{rel.type}</span>
                  </div>
                ))}
              </div>
            </div>
          ) : (
            <div className="py-12 text-center text-xs text-slate-400">
              Select any node on the graph canvas to view details.
            </div>
          )}
        </div>
      </div>
    </div>
  );
};
