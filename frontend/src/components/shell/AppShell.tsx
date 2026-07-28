import React, { useState, useEffect } from 'react';
import { TopHeader } from './TopHeader';
import { Sidebar } from './Sidebar';
import { MobileDrawer } from './MobileDrawer';

interface AppShellProps {
  activeTab: string;
  onNavigate: (tab: string) => void;
  children: React.ReactNode;
}

export const AppShell: React.FC<AppShellProps> = ({
  activeTab,
  onNavigate,
  children
}) => {
  const [collapsed, setCollapsed] = useState<boolean>(() => {
    const saved = localStorage.getItem('qdiscovery_sidebar_collapsed');
    return saved ? JSON.parse(saved) : false;
  });

  const [mobileOpen, setMobileOpen] = useState<boolean>(false);

  useEffect(() => {
    localStorage.setItem('qdiscovery_sidebar_collapsed', JSON.stringify(collapsed));
  }, [collapsed]);

  const handleToggleCollapse = () => {
    setCollapsed((prev) => !prev);
  };

  return (
    <div className="min-h-screen bg-slate-950 text-slate-100 flex overflow-x-hidden">
      {/* Desktop Sidebar */}
      <Sidebar
        activeTab={activeTab}
        onNavigate={onNavigate}
        collapsed={collapsed}
        onToggleCollapse={handleToggleCollapse}
      />

      {/* Mobile Drawer Overlay */}
      <MobileDrawer
        isOpen={mobileOpen}
        onClose={() => setMobileOpen(false)}
        activeTab={activeTab}
        onNavigate={onNavigate}
      />

      {/* Main Content Area */}
      <div className="flex-1 flex flex-col min-w-0">
        <TopHeader
          onToggleSidebar={handleToggleCollapse}
          onOpenMobileNav={() => setMobileOpen(true)}
        />

        <main className="flex-1 max-w-7xl w-full mx-auto px-4 sm:px-6 lg:px-8 py-6">
          {children}
        </main>

        <footer className="border-t border-slate-800/80 bg-slate-950 py-4 text-center text-xs font-mono text-slate-500">
          Enterprise Cryptographic Discovery Platform • Post-Quantum Migration Readiness Hub
        </footer>
      </div>
    </div>
  );
};
