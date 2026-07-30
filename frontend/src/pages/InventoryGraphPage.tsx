import React, { useState, useEffect } from 'react';
import { 
  Network, Server, Shield, Database, Activity, RefreshCw, 
  Info, ChevronRight, Search, Layers, AlertCircle, Eye
} from 'lucide-react';
import { PageHeader } from '../components/common/PageHeader';

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

interface OptionItem {
  id: string;
  label: string;
}

export const InventoryGraphPage: React.FC = () => {
  const [selectedEntityType, setSelectedEntityType] = useState<string>('GLOBAL');
  const [selectedEntityId, setSelectedEntityId] = useState<string>('');
  const [entityOptions, setEntityOptions] = useState<OptionItem[]>([]);

  const [nodes, setNodes] = useState<NodeItem[]>([]);
  const [edges, setEdges] = useState<EdgeItem[]>([]);
  const [selectedNode, setSelectedNode] = useState<NodeItem | null>(null);

  const [depth, setDepth] = useState<number>(1);
  const [loading, setLoading] = useState<boolean>(false);
  const [error, setError] = useState<string | null>(null);

  useEffect(() => {
    fetchOptionsForType(selectedEntityType);
  }, [selectedEntityType]);

  useEffect(() => {
    fetchGraphData();
  }, [selectedEntityType, selectedEntityId, depth]);

  const fetchOptionsForType = async (entityType: string) => {
    if (entityType === 'GLOBAL') {
      setEntityOptions([]);
      setSelectedEntityId('');
      return;
    }
    try {
      if (entityType === 'Asset') {
        const res = await fetch('/api/v1/assets');
        if (res.ok) {
          const data = await res.json();
          const opts = data.map((a: any) => ({
            id: a.id,
            label: a.hostname || a.ip_address || a.provider_resource_id || a.id.substring(0, 8)
          }));
          setEntityOptions(opts);
          if (opts.length > 0) setSelectedEntityId(opts[0].id);
        }
      } else if (entityType === 'CryptoObject') {
        const res = await fetch('/api/v1/crypto-objects');
        if (res.ok) {
          const data = await res.json();
          const opts = data.map((c: any) => ({
            id: c.id,
            label: `${c.canonical_name} (${c.object_type})`
          }));
          setEntityOptions(opts);
          if (opts.length > 0) setSelectedEntityId(opts[0].id);
        }
      } else {
        setEntityOptions([]);
        setSelectedEntityId('');
      }
    } catch (e) {
      console.error('Failed to fetch entity options:', e);
    }
  };

  const fetchGraphData = async () => {
    setLoading(true);
    setError(null);
    try {
      let url = '/api/v1/graph/overview';
      if (selectedEntityType !== 'GLOBAL' && selectedEntityId) {
        url = `/api/v1/graph/entity/${selectedEntityType}/${selectedEntityId}?depth=${depth}`;
      }

      const res = await fetch(url);
      if (res.ok) {
        const data = await res.json();
        setNodes(data.nodes || []);
        setEdges(data.edges || []);
        setSelectedNode(data.nodes?.length > 0 ? data.nodes[0] : null);
      } else {
        const err = await res.json();
        setError(`Graph API error: ${err.detail || res.statusText}`);
        setNodes([]);
        setEdges([]);
      }
    } catch (e: any) {
      setError(`Failed to connect to Graph API: ${e}`);
      setNodes([]);
      setEdges([]);
    } finally {
      setLoading(false);
    }
  };

  return (
    <div className="space-y-6">
      {/* Reusable Page Header */}
      <PageHeader
        title="Cryptographic Inventory & Relationship Graph"
        description="Interactive visualization of discovered assets, services, certificates, and cryptographic algorithm dependencies."
        icon={Network}
        breadcrumbs={[{ label: 'Inventory' }, { label: 'Relationship Graph' }]}
        actions={
          <button
            onClick={fetchGraphData}
            className="p-2.5 rounded-xl border border-slate-700 bg-slate-800 text-slate-300 hover:text-white transition"
          >
            <RefreshCw className={`w-4 h-4 ${loading ? 'animate-spin' : ''}`} />
          </button>
        }
      />

      {/* Graph Filter & Entity Selection Bar */}
      <div className="bg-slate-900 border border-slate-800 rounded-xl p-4 flex flex-col md:flex-row items-center justify-between gap-4 font-mono text-xs">
        <div className="flex flex-wrap items-center gap-3 w-full md:w-auto">
          <div className="flex items-center space-x-2">
            <span className="text-slate-400 uppercase text-[10px]">Graph Mode:</span>
            <select
              value={selectedEntityType}
              onChange={(e) => setSelectedEntityType(e.target.value)}
              className="bg-slate-950 border border-slate-800 rounded-lg px-3 py-1.5 text-slate-200 focus:outline-none focus:border-cyan-500"
            >
              <option value="GLOBAL">Global Overview Graph</option>
              <option value="Asset">Asset Subgraph</option>
              <option value="CryptoObject">CryptoObject Subgraph</option>
            </select>
          </div>

          {selectedEntityType !== 'GLOBAL' && (
            <div className="flex items-center space-x-2">
              <span className="text-slate-400 uppercase text-[10px]">Entity ID:</span>
              <select
                value={selectedEntityId}
                onChange={(e) => setSelectedEntityId(e.target.value)}
                className="bg-slate-950 border border-slate-800 rounded-lg px-3 py-1.5 text-slate-200 focus:outline-none focus:border-cyan-500 max-w-xs truncate"
              >
                {entityOptions.length === 0 ? (
                  <option value="">No entities found</option>
                ) : (
                  entityOptions.map((opt) => (
                    <option key={opt.id} value={opt.id}>
                      {opt.label}
                    </option>
                  ))
                )}
              </select>
            </div>
          )}

          {selectedEntityType !== 'GLOBAL' && (
            <div className="flex items-center space-x-2">
              <span className="text-slate-400 uppercase text-[10px]">Traversal Depth:</span>
              <select
                value={depth}
                onChange={(e) => setDepth(parseInt(e.target.value))}
                className="bg-slate-950 border border-slate-800 rounded-lg px-2 py-1.5 text-slate-200 focus:outline-none"
              >
                <option value={1}>1 Hop</option>
                <option value={2}>2 Hops</option>
                <option value={3}>3 Hops</option>
              </select>
            </div>
          )}
        </div>

        <div className="text-slate-400 text-[11px]">
          Nodes: <strong className="text-cyan-400">{nodes.length}</strong> | Edges: <strong className="text-emerald-400">{edges.length}</strong>
        </div>
      </div>

      {error && (
        <div className="p-4 rounded-xl bg-rose-500/10 border border-rose-500/30 text-rose-300 flex items-center space-x-3 text-sm">
          <AlertCircle className="w-5 h-5 flex-shrink-0" />
          <span>{error}</span>
        </div>
      )}

      {/* Graph Visualizer Canvas & Detail Sidebar */}
      {loading ? (
        <div className="p-16 text-center text-slate-400 font-mono flex items-center justify-center space-x-3">
          <RefreshCw className="w-5 h-5 animate-spin text-cyan-400" />
          <span>Building relationship graph topology...</span>
        </div>
      ) : nodes.length === 0 ? (
        <div className="bg-slate-900/60 border border-slate-800 p-12 rounded-2xl text-center space-y-3 font-mono">
          <Network className="w-12 h-12 text-slate-600 mx-auto" />
          <h3 className="text-base font-bold text-slate-300">No Discovered Relationships</h3>
          <p className="text-slate-400 text-xs max-w-md mx-auto">
            Execute a discovery scan job or connector sync to populate inventory relationships.
          </p>
        </div>
      ) : (
        <div className="grid grid-cols-1 lg:grid-cols-12 gap-6">
          {/* Node Canvas List */}
          <div className="lg:col-span-8 bg-slate-900 border border-slate-800 rounded-2xl p-6 space-y-4">
            <h3 className="text-xs font-mono uppercase tracking-wider text-slate-400 flex items-center">
              <Layers className="w-4 h-4 mr-2 text-cyan-400" /> Graph Nodes ({nodes.length})
            </h3>
            <div className="grid grid-cols-1 sm:grid-cols-2 gap-3 max-h-[500px] overflow-y-auto pr-2">
              {nodes.map((node) => {
                const isSelected = selectedNode?.id === node.id;
                return (
                  <div
                    key={node.id}
                    onClick={() => setSelectedNode(node)}
                    className={`p-3.5 rounded-xl border cursor-pointer transition flex flex-col justify-between ${
                      isSelected
                        ? 'bg-cyan-500/10 border-cyan-500/40 text-white shadow-lg shadow-cyan-500/10'
                        : 'bg-slate-950 border-slate-800 text-slate-300 hover:border-slate-700'
                    }`}
                  >
                    <div>
                      <div className="flex items-center justify-between mb-1">
                        <span className="text-[10px] font-mono px-2 py-0.5 rounded bg-cyan-500/10 text-cyan-400 border border-cyan-500/20">
                          {node.entity_type}
                        </span>
                        <span className="text-[9px] font-mono text-slate-500 truncate max-w-[100px]">{node.category}</span>
                      </div>
                      <h4 className="text-xs font-bold font-mono text-slate-100 truncate mt-1">{node.label}</h4>
                    </div>
                  </div>
                );
              })}
            </div>

            {/* Edge Connections List */}
            <div className="pt-4 border-t border-slate-800 space-y-2">
              <h4 className="text-xs font-mono uppercase tracking-wider text-slate-400">Relationships ({edges.length})</h4>
              <div className="space-y-1.5 max-h-[180px] overflow-y-auto pr-2 font-mono text-[11px]">
                {edges.map((edge) => (
                  <div key={edge.id} className="p-2 bg-slate-950 border border-slate-800/80 rounded flex items-center justify-between">
                    <span className="text-cyan-400 truncate max-w-[180px]">{edge.source}</span>
                    <span className="px-2 py-0.5 rounded bg-indigo-500/10 text-indigo-300 border border-indigo-500/20 text-[10px]">
                      {edge.label}
                    </span>
                    <span className="text-emerald-400 truncate max-w-[180px]">{edge.target}</span>
                  </div>
                ))}
              </div>
            </div>
          </div>

          {/* Node Inspector Sidebar */}
          <div className="lg:col-span-4 bg-slate-900 border border-slate-800 rounded-2xl p-6 space-y-4">
            <h3 className="text-xs font-mono uppercase tracking-wider text-slate-400 flex items-center">
              <Eye className="w-4 h-4 mr-2 text-indigo-400" /> Node Inspector
            </h3>
            {selectedNode ? (
              <div className="space-y-3 font-mono text-xs">
                <div className="p-3 bg-slate-950 border border-slate-800 rounded-xl space-y-1">
                  <div className="text-[10px] text-slate-400 uppercase">Entity Label</div>
                  <div className="text-sm font-bold text-slate-100">{selectedNode.label}</div>
                </div>
                <div className="p-3 bg-slate-950 border border-slate-800 rounded-xl space-y-1">
                  <div className="text-[10px] text-slate-400 uppercase">Entity Type</div>
                  <div className="text-slate-200">{selectedNode.entity_type}</div>
                </div>
                <div className="p-3 bg-slate-950 border border-slate-800 rounded-xl space-y-1">
                  <div className="text-[10px] text-slate-400 uppercase">Entity UUID</div>
                  <div className="text-slate-300 text-[10px] break-all">{selectedNode.entity_id}</div>
                </div>
              </div>
            ) : (
              <div className="text-slate-500 text-xs font-mono">Select a node from the canvas to inspect details.</div>
            )}
          </div>
        </div>
      )}
    </div>
  );
};
