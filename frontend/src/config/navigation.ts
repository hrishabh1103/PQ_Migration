import { 
  LayoutDashboard, Target, Play, Server, Cloud, Cpu, 
  Database, FileText, Network, FileDown, ShieldAlert, LucideIcon 
} from 'lucide-react';

export type NavSection = 'DISCOVERY' | 'INVENTORY' | 'MIGRATION';

export interface NavItem {
  id: string;
  label: string;
  icon: LucideIcon;
  section?: NavSection;
  badge?: string;
  description?: string;
}

export const NAVIGATION_CONFIG: NavItem[] = [
  // Overview Item
  {
    id: 'dashboard',
    label: 'Dashboard',
    icon: LayoutDashboard,
    description: 'Post-Quantum Cryptographic Posture Overview'
  },
  // DISCOVERY Section
  {
    id: 'targets',
    label: 'Targets',
    icon: Target,
    section: 'DISCOVERY',
    description: 'Authorized Discovery Targets & Scope'
  },
  {
    id: 'scans',
    label: 'Scans',
    icon: Play,
    section: 'DISCOVERY',
    description: 'Active & Historical Discovery Jobs'
  },
  {
    id: 'linux-collector',
    label: 'Linux Collector',
    icon: Server,
    section: 'DISCOVERY',
    description: 'Read-only Linux Host Cryptographic Collector'
  },
  {
    id: 'aws-connector',
    label: 'AWS Connector',
    icon: Cloud,
    section: 'DISCOVERY',
    description: 'Read-only AWS Cloud Cryptographic Discovery Connector'
  },
  {
    id: 'cloud-servers',
    label: 'Cloud Servers',
    icon: Cloud,
    section: 'DISCOVERY',
    description: 'Cloud Infrastructure & Endpoint Audit'
  },
  {
    id: 'api-hub',
    label: 'API & Server Hub',
    icon: Cpu,
    section: 'DISCOVERY',
    description: 'API Specification & Server Discovery Hub'
  },
  // INVENTORY Section
  {
    id: 'assets',
    label: 'Assets',
    icon: Database,
    section: 'INVENTORY',
    description: 'Inventoried Hosts, Services & Process Assets'
  },
  {
    id: 'findings',
    label: 'Crypto Findings',
    icon: FileText,
    section: 'INVENTORY',
    description: 'Normalized Cryptographic Observations'
  },
  {
    id: 'inventory-graph',
    label: 'Inventory Graph',
    icon: Network,
    section: 'INVENTORY',
    description: 'Enterprise Knowledge Graph Topology'
  },
  // MIGRATION Section
  {
    id: 'pqc-readiness',
    label: 'PQC Readiness',
    icon: ShieldAlert,
    section: 'MIGRATION',
    description: 'Enterprise Correlation & PQC Readiness Engine'
  },
  {
    id: 'reports',
    label: 'Reports & Readiness',
    icon: FileDown,
    section: 'MIGRATION',
    description: 'Risk Analysis & CycloneDX 1.6 CBOM Export'
  }
];
