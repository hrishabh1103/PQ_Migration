import React, { useState, useEffect } from 'react';
import { 
  Network, Server, Shield, Database, Activity, RefreshCw, 
  Info, ChevronRight, Search, Layers, AlertCircle
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

interface AssetOption {
  id: string;
  hostname: string | null;
  ip_address: string | null;
  asset_type: string;
}

export const InventoryGraphPage: React.FC = () => {
  const [availableAssets, setAvailableAssets] = useState<AssetOption[]>([]);
  const [selectedEntityType, setSelectedEntityType] = useState<string>('Asset');
  const [selectedEntityId, setSelectedEntityId] = useState<string>('');
  const [customEntityIdInput, setCustomEntityIdInput] = useState<string>('');

  const [nodes, setNodes] = useState<NodeItem[]>([]);
  const [edges, setEdges] = useState<EdgeItem[]>([]);
  const [selectedNode, setSelectedNode] = useState<NodeItem | null>(null);

  const [filterNodeType, setFilterNodeType] = useState<string>('ALL');
  const [filterRelType, setFilterRelType] = useState<string>('ALL');
  const [depth, setDepth] = useState<number>(1);
  const [loading, setLoading] = useState<boolean>(false);
  const [error, setError] = useState<string | null>(null);

  // Fetch registered assets for the dropdown selector on load
  useEffect(() => {
    const loadAssets = async () => {
      try {
        const res = await fetch('/api/v1/assets');
        if (res.ok) {
          const data: AssetOption[] = await res.json();
          setAvailableAssets(data);
          if (data.length > 0) {
            setSelectedEntityId(data[0].id);
          }
        }
      } catch (err) {
        console.error('Failed to load assets list:', err);
      }
    };
    loadAssets();
  }, []);

  // Fetch graph data whenever root entity or depth changes
  const fetchGraphData = async () => {
    const targetId = selectedEntityId || customEntityIdInput.trim();
    if (!targetId) {
      setNodes([]);
      setEdges([]);
      setSelectedNode(null);
      return;
    }

    setLoading(true);
    setError(null);
    try {
      let url = `/api/v1/graph/entity/${selectedEntityType}/${targetId}?depth=${depth}`;
      if (filterRelType !== 'ALL') {
        url += `&relationship_type=${encodeURIComponent(filterRelType)}`;
      }
      if (filterNodeType !== 'ALL') {
        url += `&node_type=${encodeURIComponent(filterNodeType)}`;
      }

      const res = await fetch(url);
      if (!res.ok) {
        if (res.status === 404) {
          setError(`Entity ${selectedEntityType}:${targetId} not found in inventory.`);
        } else {
          setError(`Failed to fetch graph data (HTTP ${res.status}).`);
        }
        setNodes([]);
        setEdges([]);
        setSelectedNode(null);
        return;
      }

      const data = await res.json();
      const fetchedNodes: NodeItem[] = data.nodes || [];
      const fetchedEdges: EdgeItem[] = data.edges || [];

      setNodes(fetchedNodes);
      setEdges(fetchedEdges);

      if (fetchedNodes.length > 0) {
        setSelectedNode(fetchedNodes[0]);
      } else {
        setSelectedNode(null);
      }
    } catch (err) {
      console.error('Failed to load entity graph:', err);
      setError('Network error connecting to Graph API.');
      setNodes([]);
      setEdges([]);
      setSelectedNode(null);
    } finally {
      setLoading(false);
    }
  };

  useEffect(() => {
    if (selectedEntityId || customEntityIdInput.trim()) {
      fetchGraphData();
    }
  }, [selectedEntityType, selectedEntityId, depth, filterRelType, filterNodeType]);

  const filteredNodes = nodes.filter(n => {
    if (filterNodeType === 'ALL') return true;
    return n.entity_type.toUpperCase() === filterNodeType.toUpperCase();
  });

  const filteredEdges = edges.filter(e => {
    if (filterRelType === 'ALL') return true;
    return e.label.toUpperCase() === filterRelType.toUpperCase();
  });

  const getCategoryIcon = (category: string) => {
    switch (category.toUpperCase()) {
      case 'HOST':
      case 'SERVER':
      case 'CLOUD_VM':
      case 'ASSET':
        return <Server className="w-5 h-5 text-blue-400" />;
      case 'SERVICE':
        return <Activity className="w-5 h-5 text-green-400" />;
      case 'CERTIFICATE':
      case 'ALGORITHM':
      case 'CRYPTOOBJECT':
        return <Shield className="w-5 h-5 text-amber-400" />;
      case 'DATA_ASSET':
      case 'DATAASSET':
        return <Database className="w-5 h-5 text-purple-400" />;
      default:
        return <Network className="w-5 h-5 text-slate-400" />;
    }
  };

  return (
    <div className="space-y-6">
      {/* Top Controls Bar */}
      <div className="bg-slate-900 border border-slate-800 rounded-xl p-6 shadow-xl">
        <div className="flex flex-col lg:flex-row lg:items-center justify-between gap-4">
          <div>
            <h1 className="text-2xl font-bold text-white flex items-center gap-3">
              <Network className="w-7 h-7 text-indigo-400" />
              Enterprise Inventory Topology Graph
            </h1>
            <p className="text-slate-400 text-sm mt-1">
              Explore interconnected discovery relationships across Assets, Services, CryptoObjects, and Data Assets.
            </p>
          </div>

          <div className="flex items-center gap-3">
            <button
              onClick={fetchGraphData}
              disabled={loading}
              className="flex items-center gap-2 px-4 py-2 bg-indigo-600 hover:bg-indigo-500 disabled:opacity-50 text-white rounded-lg text-sm font-medium transition-colors"
            >
              <RefreshCw className={`w-4 h-4 ${loading ? 'animate-spin' : ''}`} />
              Refresh Graph
            </button>
          </div>
        </div>

        {/* Root Entity Selector Bar */}
        <div className="mt-6 pt-6 border-t border-slate-800 grid grid-cols-1 md:grid-cols-4 gap-4">
          <div>
            <label className="block text-xs font-semibold text-slate-400 uppercase tracking-wider mb-2">
              Root Entity Type
            </label>
            <select
              value={selectedEntityType}
              onChange={(e) => setSelectedEntityType(e.target.value)}
              className="w-full bg-slate-800 border border-slate-700 text-white rounded-lg px-3 py-2 text-sm focus:outline-none focus:border-indigo-500"
            >
              <option value="Asset">Asset</option>
              <option value="Service">Service</option>
              <option value="CryptoObject">CryptoObject</option>
              <option value="DataAsset">DataAsset</option>
            </select>
          </div>

          <div>
            <label className="block text-xs font-semibold text-slate-400 uppercase tracking-wider mb-2">
              Select Discovered Asset
            </label>
            <select
              value={selectedEntityId}
              onChange={(e) => {
                setSelectedEntityId(e.target.value);
                setCustomEntityIdInput('');
              }}
              className="w-full bg-slate-800 border border-slate-700 text-white rounded-lg px-3 py-2 text-sm focus:outline-none focus:border-indigo-500"
            >
              {availableAssets.length === 0 ? (
                <option value="">No Discovered Assets Found</option>
              ) : (
                availableAssets.map((ast) => (
                  <option key={ast.id} value={ast.id}>
                    {ast.hostname || ast.ip_address || ast.id.slice(0, 8)} ({ast.asset_type})
                  </option>
                ))
              )}
            </select>
          </div>

          <div>
            <label className="block text-xs font-semibold text-slate-400 uppercase tracking-wider mb-2">
              Or Enter Entity UUID
            </label>
            <div className="relative">
              <input
                type="text"
                placeholder="Paste UUID..."
                value={customEntityIdInput}
                onChange={(e) => {
                  setCustomEntityIdInput(e.target.value);
                  setSelectedEntityId('');
                }}
                className="w-full bg-slate-800 border border-slate-700 text-white rounded-lg pl-9 pr-3 py-2 text-sm focus:outline-none focus:border-indigo-500"
              />
              <Search className="w-4 h-4 text-slate-500 absolute left-3 top-2.5" />
            </div>
          </div>

          <div>
            <label className="block text-xs font-semibold text-slate-400 uppercase tracking-wider mb-2">
              Traversal Depth
            </label>
            <div className="flex items-center gap-2">
              {[1, 2, 3].map((d) => (
                <button
                  key={d}
                  onClick={() => setDepth(d)}
                  className={`flex-1 py-2 rounded-lg text-sm font-semibold transition-colors ${
                    depth === d
                      ? 'bg-indigo-600 text-white'
                      : 'bg-slate-800 text-slate-400 hover:bg-slate-700'
                  }`}
                >
                  {d} Hop{d > 1 ? 's' : ''}
                </button>
              ))}
            </div>
          </div>
        </div>
      </div>

      {/* Main Canvas & Detail Inspector */}
      <div className="grid grid-cols-1 lg:grid-cols-3 gap-6">
        {/* Left 2 Cols: Interactive Graph Visualizer */}
        <div className="lg:col-span-2 bg-slate-900 border border-slate-800 rounded-xl p-6 shadow-xl flex flex-col min-h-[500px]">
          <div className="flex items-center justify-between pb-4 border-b border-slate-800 mb-4">
            <h2 className="text-lg font-semibold text-white flex items-center gap-2">
              <Layers className="w-5 h-5 text-indigo-400" />
              Connected Entity Topology ({nodes.length} Nodes, {edges.length} Edges)
            </h2>
            <div className="flex items-center gap-3">
              <span className="text-xs text-slate-400">Filter Nodes:</span>
              <select
                value={filterNodeType}
                onChange={(e) => setFilterNodeType(e.target.value)}
                className="bg-slate-800 border border-slate-700 text-slate-300 rounded text-xs px-2 py-1"
              >
                <option value="ALL">All Entity Types</option>
                <option value="ASSET">Assets Only</option>
                <option value="SERVICE">Services Only</option>
                <option value="CRYPTOOBJECT">CryptoObjects Only</option>
                <option value="DATAASSET">Data Assets Only</option>
              </select>

              <span className="text-xs text-slate-400">Filter Edges:</span>
              <select
                value={filterRelType}
                onChange={(e) => setFilterRelType(e.target.value)}
                className="bg-slate-800 border border-slate-700 text-slate-300 rounded text-xs px-2 py-1"
              >
                <option value="ALL">All Relationship Types</option>
                <option value="RUNS_ON">RUNS_ON</option>
                <option value="TERMINATES_TLS_AT">TERMINATES_TLS_AT</option>
                <option value="USES">USES</option>
                <option value="STORES_DATA">STORES_DATA</option>
              </select>
            </div>
          </div>

          {/* Graph Display State */}
          {loading ? (
            <div className="flex-1 flex flex-col items-center justify-center text-slate-400 py-16">
              <RefreshCw className="w-8 h-8 animate-spin text-indigo-400 mb-3" />
              <p className="text-sm font-medium">Traversing entity graph...</p>
            </div>
          ) : error ? (
            <div className="flex-1 flex flex-col items-center justify-center text-rose-400 py-16">
              <AlertCircle className="w-10 h-10 mb-3" />
              <p className="text-base font-semibold">{error}</p>
              <p className="text-xs text-slate-500 mt-1">Select a valid entity from the dropdown above to view its graph.</p>
            </div>
          ) : nodes.length === 0 ? (
            <div className="flex-1 flex flex-col items-center justify-center text-slate-500 py-16">
              <Network className="w-12 h-12 mb-3 text-slate-600" />
              <p className="text-base font-semibold text-slate-400">No Graph Relationships Found</p>
              <p className="text-xs text-slate-500 mt-1 max-w-md text-center">
                Run a scanner job or register targets to discover assets, services, and cryptographic relationships.
              </p>
            </div>
          ) : (
            <div className="flex-1 space-y-4 overflow-y-auto max-h-[600px] pr-2">
              <div className="grid grid-cols-1 md:grid-cols-2 gap-4">
                {filteredNodes.map((n) => {
                  const isSelected = selectedNode?.id === n.id;
                  return (
                    <div
                      key={n.id}
                      onClick={() => setSelectedNode(n)}
                      className={`p-4 rounded-xl border cursor-pointer transition-all ${
                        isSelected
                          ? 'bg-indigo-950/40 border-indigo-500 ring-2 ring-indigo-500/30'
                          : 'bg-slate-800/60 border-slate-700/60 hover:bg-slate-800 hover:border-slate-600'
                      }`}
                    >
                      <div className="flex items-start gap-3">
                        <div className="p-2.5 rounded-lg bg-slate-900 border border-slate-700">
                          {getCategoryIcon(n.category)}
                        </div>
                        <div className="flex-1 min-w-0">
                          <div className="flex items-center justify-between">
                            <span className="text-xs font-semibold text-indigo-400 uppercase tracking-wider">
                              {n.entity_type}
                            </span>
                            <ChevronRight className={`w-4 h-4 ${isSelected ? 'text-indigo-400' : 'text-slate-600'}`} />
                          </div>
                          <h3 className="text-sm font-medium text-white truncate mt-1">
                            {n.label}
                          </h3>
                          <p className="text-xs text-slate-400 mt-1 truncate">
                            ID: {n.entity_id}
                          </p>
                        </div>
                      </div>
                    </div>
                  );
                })}
              </div>

              {/* Edge Relationship Connections Sub-panel */}
              {filteredEdges.length > 0 && (
                <div className="mt-6 pt-4 border-t border-slate-800">
                  <h3 className="text-xs font-semibold text-slate-400 uppercase tracking-wider mb-3">
                    Discovered Graph Edges ({filteredEdges.length})
                  </h3>
                  <div className="space-y-2">
                    {filteredEdges.map((e) => (
                      <div key={e.id} className="p-3 bg-slate-800/40 border border-slate-700/40 rounded-lg text-xs flex items-center justify-between">
                        <span className="text-slate-300 font-mono">{e.source}</span>
                        <span className="px-2 py-0.5 rounded bg-indigo-950 text-indigo-300 font-semibold border border-indigo-800/50">
                          {e.label}
                        </span>
                        <span className="text-slate-300 font-mono">{e.target}</span>
                      </div>
                    ))}
                  </div>
                </div>
              )}
            </div>
          )}
        </div>

        {/* Right 1 Col: Selected Node Detail Inspector */}
        <div className="bg-slate-900 border border-slate-800 rounded-xl p-6 shadow-xl flex flex-col justify-between">
          <div>
            <div className="pb-4 border-b border-slate-800 mb-4 flex items-center justify-between">
              <h2 className="text-lg font-semibold text-white flex items-center gap-2">
                <Info className="w-5 h-5 text-indigo-400" />
                Entity Details
              </h2>
            </div>

            {selectedNode ? (
              <div className="space-y-4">
                <div className="p-4 bg-slate-800/60 rounded-xl border border-slate-700/60">
                  <div className="flex items-center gap-3 mb-3">
                    {getCategoryIcon(selectedNode.category)}
                    <div>
                      <span className="text-xs font-semibold text-indigo-400 uppercase">
                        {selectedNode.entity_type}
                      </span>
                      <h3 className="text-base font-bold text-white leading-tight">
                        {selectedNode.label}
                      </h3>
                    </div>
                  </div>
                  <p className="text-xs text-slate-400 font-mono break-all bg-slate-900 p-2 rounded border border-slate-800">
                    {selectedNode.id}
                  </p>
                </div>

                <div className="space-y-3">
                  <h4 className="text-xs font-semibold text-slate-400 uppercase tracking-wider">
                    Entity Metadata
                  </h4>
                  <div className="bg-slate-800/40 border border-slate-800 rounded-xl p-4 space-y-2 text-xs">
                    <div className="flex justify-between py-1 border-b border-slate-800">
                      <span className="text-slate-400">Entity Type</span>
                      <span className="text-slate-200 font-medium">{selectedNode.entity_type}</span>
                    </div>
                    <div className="flex justify-between py-1 border-b border-slate-800">
                      <span className="text-slate-400">Category</span>
                      <span className="text-slate-200 font-medium">{selectedNode.category}</span>
                    </div>

                    {Object.entries(selectedNode.details || {}).map(([key, val]) => (
                      <div key={key} className="flex justify-between py-1 border-b border-slate-800 last:border-0">
                        <span className="text-slate-400 capitalize">{key.replace('_', ' ')}</span>
                        <span className="text-slate-200 font-medium truncate max-w-[150px]">
                          {String(val)}
                        </span>
                      </div>
                    ))}
                  </div>
                </div>
              </div>
            ) : (
              <div className="py-16 text-center text-slate-500">
                <Info className="w-8 h-8 mx-auto mb-2 text-slate-600" />
                <p className="text-sm">Select a node in the graph to inspect metadata details.</p>
              </div>
            )}
          </div>

          <div className="mt-6 pt-4 border-t border-slate-800 text-xs text-slate-500 flex items-center gap-2">
            <Shield className="w-4 h-4 text-indigo-400" />
            V2.1 Hardened Graph Traversal Engine
          </div>
        </div>
      </div>
    </div>
  );
};
