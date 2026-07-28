import React, { useEffect, useState } from 'react';
import { Menu, Search, ShieldAlert, Activity, BookOpen, HelpCircle } from 'lucide-react';

interface TopHeaderProps {
  onToggleSidebar: () => void;
  onOpenMobileNav: () => void;
}

export const TopHeader: React.FC<TopHeaderProps> = ({ onToggleSidebar, onOpenMobileNav }) => {
  const [healthStatus, setHealthStatus] = useState<string>('HEALTHY');

  useEffect(() => {
    fetch('/api/v1/health')
      .then((res) => (res.ok ? res.json() : null))
      .then((data) => {
        if (data && data.status) {
          setHealthStatus(data.status.toUpperCase());
        }
      })
      .catch(() => setHealthStatus('ONLINE'));
  }, []);

  return (
    <header className="h-[64px] border-b border-slate-800 bg-slate-950/90 backdrop-blur-md sticky top-0 z-40 flex items-center justify-between px-4 sm:px-6">
      {/* Left Controls: Sidebar Toggle & Mobile Brand */}
      <div className="flex items-center space-x-3">
        {/* Mobile menu trigger */}
        <button
          onClick={onOpenMobileNav}
          className="md:hidden p-2 rounded-lg text-slate-400 hover:text-slate-200 hover:bg-slate-900 focus:outline-none"
          aria-label="Open Mobile Menu"
        >
          <Menu className="w-5 h-5" />
        </button>

        {/* Desktop sidebar toggle button */}
        <button
          onClick={onToggleSidebar}
          className="hidden md:flex p-2 rounded-lg text-slate-400 hover:text-slate-200 hover:bg-slate-900 focus:outline-none transition-colors"
          title="Toggle Sidebar"
          aria-label="Toggle Sidebar"
        >
          <Menu className="w-5 h-5" />
        </button>

        {/* Mobile Brand Identity */}
        <div className="md:hidden flex items-center space-x-2">
          <div className="p-1.5 bg-cyan-500/10 border border-cyan-500/30 rounded-lg text-cyan-400">
            <ShieldAlert className="w-5 h-5" />
          </div>
          <span className="text-base font-bold bg-gradient-to-r from-cyan-400 to-indigo-400 bg-clip-text text-transparent">
            Q-DISCOVERY
          </span>
        </div>
      </div>

      {/* Global Search Placeholder */}
      <div className="hidden md:flex items-center flex-1 max-w-md mx-6">
        <div className="relative w-full">
          <Search className="w-4 h-4 text-slate-500 absolute left-3 top-1/2 -translate-y-1/2" />
          <input
            type="text"
            placeholder="Search targets, assets, certificates, or ciphers... (Press '/' to focus)"
            className="w-full bg-slate-900/80 border border-slate-800 rounded-lg pl-9 pr-4 py-1.5 text-xs text-slate-200 placeholder-slate-500 focus:outline-none focus:border-cyan-500/50 transition-all"
            disabled
          />
        </div>
      </div>

      {/* Right Controls: Health Status, Docs & System Info */}
      <div className="flex items-center space-x-3 sm:space-x-4">
        {/* Backend Health Badge */}
        <div className="flex items-center space-x-2 px-2.5 py-1 bg-slate-900 border border-slate-800 rounded-full text-xs font-mono">
          <Activity className="w-3.5 h-3.5 text-emerald-400 animate-pulse" />
          <span className="text-slate-400 hidden sm:inline">Engine:</span>
          <span className="text-emerald-400 font-semibold">{healthStatus}</span>
        </div>

        {/* Documentation Action */}
        <a
          href="/docs"
          target="_blank"
          rel="noreferrer"
          className="hidden sm:flex items-center space-x-1.5 text-xs text-slate-400 hover:text-slate-200 transition-colors"
          title="Open API Documentation"
        >
          <BookOpen className="w-4 h-4 text-cyan-400" />
          <span>Docs</span>
        </a>

        {/* Help Action */}
        <button
          className="p-1.5 rounded-lg text-slate-400 hover:text-slate-200 hover:bg-slate-900 transition-colors"
          title="Platform Overview & Help"
        >
          <HelpCircle className="w-4.5 h-4.5" />
        </button>
      </div>
    </header>
  );
};
