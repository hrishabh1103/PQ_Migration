import { AuthorizedTarget, TargetCreateInput, ScanJob, Asset, CryptoFinding, DashboardStats } from '../types';

const API_BASE = '/api/v1';

export async function fetchHealth() {
  const res = await fetch(`${API_BASE}/health`);
  if (!res.ok) throw new Error('Health check failed');
  return res.json();
}

export async function fetchDashboardStats(): Promise<DashboardStats> {
  const res = await fetch(`${API_BASE}/stats/dashboard`);
  if (!res.ok) throw new Error('Failed to fetch dashboard stats');
  return res.json();
}

export async function fetchTargets(): Promise<AuthorizedTarget[]> {
  const res = await fetch(`${API_BASE}/targets`);
  if (!res.ok) throw new Error('Failed to fetch targets');
  return res.json();
}

export async function fetchTargetById(id: string): Promise<AuthorizedTarget> {
  const res = await fetch(`${API_BASE}/targets/${id}`);
  if (!res.ok) throw new Error(`Failed to fetch target ${id}`);
  return res.json();
}

export async function createTarget(input: TargetCreateInput): Promise<AuthorizedTarget> {
  const res = await fetch(`${API_BASE}/targets`, {
    method: 'POST',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify(input),
  });
  if (!res.ok) throw new Error('Failed to create target');
  return res.json();
}

export async function fetchScans(): Promise<ScanJob[]> {
  const res = await fetch(`${API_BASE}/scans`);
  if (!res.ok) throw new Error('Failed to fetch scan jobs');
  return res.json();
}

export async function fetchScanById(id: string): Promise<ScanJob> {
  const res = await fetch(`${API_BASE}/scans/${id}`);
  if (!res.ok) throw new Error(`Failed to fetch scan job ${id}`);
  return res.json();
}

export async function createScan(targetId: string, requestedScanners: string[] = ['mock-scanner']): Promise<ScanJob> {
  const res = await fetch(`${API_BASE}/scans`, {
    method: 'POST',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify({
      target_id: targetId,
      requested_scanners: requestedScanners
    }),
  });
  if (!res.ok) throw new Error('Failed to trigger scan');
  return res.json();
}

export async function fetchAssets(): Promise<Asset[]> {
  const res = await fetch(`${API_BASE}/assets`);
  if (!res.ok) throw new Error('Failed to fetch assets');
  return res.json();
}

export async function fetchAssetById(id: string): Promise<Asset> {
  const res = await fetch(`${API_BASE}/assets/${id}`);
  if (!res.ok) throw new Error(`Failed to fetch asset ${id}`);
  return res.json();
}

export async function fetchFindings(): Promise<CryptoFinding[]> {
  const res = await fetch(`${API_BASE}/findings`);
  if (!res.ok) throw new Error('Failed to fetch findings');
  return res.json();
}

export async function fetchFindingById(id: string): Promise<CryptoFinding> {
  const res = await fetch(`${API_BASE}/findings/${id}`);
  if (!res.ok) throw new Error(`Failed to fetch finding ${id}`);
  return res.json();
}

export async function fetchRemediationReport() {
  const res = await fetch(`${API_BASE}/reports/remediation`);
  if (!res.ok) throw new Error('Failed to fetch remediation report');
  return res.json();
}

export function downloadRemediationMarkdown() {
  window.open(`${API_BASE}/reports/export/markdown`, '_blank');
}

export function downloadCycloneDXCBOM() {
  window.open(`${API_BASE}/cbom/export`, '_blank');
}
