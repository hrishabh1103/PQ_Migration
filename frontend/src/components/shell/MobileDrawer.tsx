import React, { useEffect } from 'react';
import { ShieldAlert, X } from 'lucide-react';
import { NAVIGATION_CONFIG, NavSection } from '../../config/navigation';

interface MobileDrawerProps {
  isOpen: boolean;
  onClose: () => void;
  activeTab: string;
  onNavigate: (tab: string) => void;
}

export const MobileDrawer: React.FC<MobileDrawerProps> = ({
  isOpen,
  onClose,
  activeTab,
  onNavigate
}) => {
  useEffect(() => {
    const handleKeyDown = (e: KeyboardEvent) => {
      if (e.key === 'Escape' && isOpen) {
        onClose();
      }
    };
    window.addEventListener('keydown', handleKeyDown);
    return () => window.removeEventListener('keydown', handleKeyDown);
  }, [isOpen, onClose]);

  if (!isOpen) return null;

  const sections: { key: NavSection; title: string }[] = [
    { key: 'DISCOVERY', title: 'DISCOVERY' },
    { key: 'INVENTORY', title: 'INVENTORY' },
    { key: 'MIGRATION', title: 'MIGRATION' }
  ];

  const overviewItem = NAVIGATION_CONFIG.find((item) => !item.section);

  const handleItemClick = (id: string) => {
    onNavigate(id);
    onClose();
  };

  return (
    <div className="md:hidden fixed inset-0 z-50 flex">
      {/* Backdrop */}
      <div
        className="fixed inset-0 bg-slate-950/80 backdrop-blur-sm transition-opacity"
        onClick={onClose}
        aria-hidden="true"
      />

      {/* Drawer Content */}
      <div className="relative w-4/5 max-w-xs bg-slate-950 border-r border-slate-800 h-full flex flex-col z-10 shadow-2xl">
        {/* Header */}
        <div className="h-[64px] border-b border-slate-800 px-4 flex items-center justify-between">
          <div className="flex items-center space-x-3">
            <div className="p-2 bg-cyan-500/10 border border-cyan-500/30 rounded-xl text-cyan-400">
              <ShieldAlert className="w-5 h-5" />
            </div>
            <div>
              <span className="text-base font-bold bg-gradient-to-r from-cyan-400 to-indigo-400 bg-clip-text text-transparent">
                Q-DISCOVERY
              </span>
              <span className="block text-[10px] font-mono text-slate-400">Post-Quantum Readiness</span>
            </div>
          </div>
          <button
            onClick={onClose}
            className="p-1.5 rounded-lg text-slate-400 hover:text-slate-200 hover:bg-slate-900"
            aria-label="Close Menu"
          >
            <X className="w-5 h-5" />
          </button>
        </div>

        {/* Navigation List */}
        <div className="flex-1 overflow-y-auto p-4 space-y-6">
          {overviewItem && (
            <button
              onClick={() => handleItemClick(overviewItem.id)}
              className={`w-full flex items-center space-x-3 px-3 py-2.5 rounded-lg text-sm font-medium transition-all ${
                activeTab === overviewItem.id
                  ? 'bg-cyan-500/10 text-cyan-400 border-l-2 border-cyan-400 font-semibold'
                  : 'text-slate-400 hover:text-slate-200 hover:bg-slate-900'
              }`}
            >
              <overviewItem.icon className="w-5 h-5 text-cyan-400" />
              <span>{overviewItem.label}</span>
            </button>
          )}

          {sections.map((sec) => {
            const items = NAVIGATION_CONFIG.filter((i) => i.section === sec.key);
            return (
              <div key={sec.key} className="space-y-1">
                <div className="px-3 pb-1 text-xs font-mono font-semibold text-slate-500 tracking-wider">
                  {sec.title}
                </div>
                {items.map((item) => {
                  const Icon = item.icon;
                  const isActive = activeTab === item.id;
                  return (
                    <button
                      key={item.id}
                      onClick={() => handleItemClick(item.id)}
                      className={`w-full flex items-center space-x-3 px-3 py-2.5 rounded-lg text-sm font-medium transition-all ${
                        isActive
                          ? 'bg-cyan-500/10 text-cyan-400 border-l-2 border-cyan-400 font-semibold'
                          : 'text-slate-400 hover:text-slate-200 hover:bg-slate-900'
                      }`}
                    >
                      <Icon className={`w-5 h-5 ${isActive ? 'text-cyan-400' : 'text-slate-400'}`} />
                      <span>{item.label}</span>
                    </button>
                  );
                })}
              </div>
            );
          })}
        </div>
      </div>
    </div>
  );
};
