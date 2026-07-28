import React from 'react';
import { ShieldAlert, ChevronLeft, ChevronRight } from 'lucide-react';
import { NAVIGATION_CONFIG, NavItem, NavSection } from '../../config/navigation';

interface SidebarProps {
  activeTab: string;
  onNavigate: (tab: string) => void;
  collapsed: boolean;
  onToggleCollapse: () => void;
}

export const Sidebar: React.FC<SidebarProps> = ({
  activeTab,
  onNavigate,
  collapsed,
  onToggleCollapse
}) => {
  const sections: { key: NavSection; title: string }[] = [
    { key: 'DISCOVERY', title: 'DISCOVERY' },
    { key: 'INVENTORY', title: 'INVENTORY' },
    { key: 'MIGRATION', title: 'MIGRATION' }
  ];

  const overviewItem = NAVIGATION_CONFIG.find((item) => !item.section);

  const getSectionItems = (secKey: NavSection) => {
    return NAVIGATION_CONFIG.filter((item) => item.section === secKey);
  };

  return (
    <aside
      className={`hidden md:flex flex-col bg-slate-950 border-r border-slate-800 transition-all duration-300 h-screen sticky top-0 z-50 select-none ${
        collapsed ? 'w-[68px]' : 'w-[240px]'
      }`}
    >
      {/* 1. Desktop Brand Identity Header */}
      <div className="h-[64px] border-b border-slate-800/80 flex items-center justify-between px-4">
        <div
          className="flex items-center space-x-3 cursor-pointer overflow-hidden min-w-0"
          onClick={() => onNavigate('dashboard')}
          title="Q-DISCOVERY Platform Overview"
        >
          <div className="p-2 bg-cyan-500/10 border border-cyan-500/30 rounded-xl text-cyan-400 flex-shrink-0">
            <ShieldAlert className="w-5 h-5" />
          </div>
          {!collapsed && (
            <div className="flex flex-col min-w-0">
              <span className="text-base font-bold bg-gradient-to-r from-cyan-400 via-sky-400 to-indigo-400 bg-clip-text text-transparent truncate">
                Q-DISCOVERY
              </span>
              <span className="text-[10px] font-mono text-slate-400 tracking-wider uppercase truncate">
                Post-Quantum Readiness
              </span>
            </div>
          )}
        </div>

        {!collapsed && (
          <button
            onClick={onToggleCollapse}
            className="p-1 rounded-lg text-slate-500 hover:text-slate-200 hover:bg-slate-900 transition-colors"
            title="Collapse Sidebar"
          >
            <ChevronLeft className="w-4 h-4" />
          </button>
        )}
      </div>

      {/* 2. Navigation Items List */}
      <div className="flex-1 overflow-y-auto py-4 px-2 space-y-6">
        {/* Overview Item */}
        {overviewItem && (
          <div>
            <SidebarNavItem
              item={overviewItem}
              isActive={activeTab === overviewItem.id}
              collapsed={collapsed}
              onNavigate={onNavigate}
            />
          </div>
        )}

        {/* Section Groups */}
        {sections.map((sec) => {
          const items = getSectionItems(sec.key);
          if (items.length === 0) return null;

          return (
            <div key={sec.key} className="space-y-1">
              {!collapsed ? (
                <div className="px-3 pb-1 text-[11px] font-mono font-semibold text-slate-500 uppercase tracking-wider">
                  {sec.title}
                </div>
              ) : (
                <div className="h-px bg-slate-800/80 my-2 mx-2" />
              )}

              {items.map((item) => (
                <SidebarNavItem
                  key={item.id}
                  item={item}
                  isActive={activeTab === item.id}
                  collapsed={collapsed}
                  onNavigate={onNavigate}
                />
              ))}
            </div>
          );
        })}
      </div>

      {/* 3. Collapsed Footer Toggle Button */}
      {collapsed && (
        <div className="p-2 border-t border-slate-800/80 flex justify-center">
          <button
            onClick={onToggleCollapse}
            className="p-2 rounded-lg text-slate-400 hover:text-cyan-400 hover:bg-slate-900 transition-colors"
            title="Expand Sidebar"
          >
            <ChevronRight className="w-5 h-5" />
          </button>
        </div>
      )}
    </aside>
  );
};

interface SidebarNavItemProps {
  item: NavItem;
  isActive: boolean;
  collapsed: boolean;
  onNavigate: (tab: string) => void;
}

const SidebarNavItem: React.FC<SidebarNavItemProps> = ({
  item,
  isActive,
  collapsed,
  onNavigate
}) => {
  const Icon = item.icon;

  return (
    <button
      onClick={() => onNavigate(item.id)}
      title={collapsed ? item.label : undefined}
      className={`w-full flex items-center space-x-3 px-3 py-2.5 rounded-lg text-xs font-medium transition-all ${
        isActive
          ? 'bg-cyan-500/10 text-cyan-400 border-l-2 border-cyan-400 font-semibold'
          : 'text-slate-400 hover:text-slate-200 hover:bg-slate-900/80'
      }`}
    >
      <Icon className={`w-4.5 h-4.5 flex-shrink-0 ${isActive ? 'text-cyan-400' : 'text-slate-400'}`} />
      {!collapsed && <span className="truncate">{item.label}</span>}
      {!collapsed && item.badge && (
        <span className="ml-auto px-1.5 py-0.5 rounded text-[10px] font-mono bg-cyan-500/20 text-cyan-300">
          {item.badge}
        </span>
      )}
    </button>
  );
};
