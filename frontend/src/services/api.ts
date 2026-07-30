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

export async function bulkRegisterApiServers(name: string, endpoints: string[], environment: string = 'PRODUCTION') {
  const res = await fetch(`${API_BASE}/api-hub/bulk-register`, {
    method: 'POST',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify({
      name,
      endpoints,
      environment,
      run_immediate_scan: true
    }),
  });
  if (!res.ok) throw new Error('Failed to register API servers');
  return res.json();
}

export async function uploadOpenApiSpec(file: File, environment: string = 'PRODUCTION') {
  const formData = new FormData();
  formData.append('file', file);
  const res = await fetch(`${API_BASE}/api-hub/import-openapi?environment=${environment}`, {
    method: 'POST',
    body: formData,
  });
  if (!res.ok) throw new Error('Failed to upload OpenAPI spec');
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

export function downloadInventoryArchive() {
  window.open(`${API_BASE}/scans/export/archive`, '_blank');
}

export async function deleteScan(scanId: string) {
  const res = await fetch(`${API_BASE}/scans/${scanId}`, {
    method: 'DELETE',
  });
  if (!res.ok) throw new Error(`Failed to delete scan ${scanId}`);
  return res.json();
}

export async function clearAllScans() {
  const res = await fetch(`${API_BASE}/scans`, {
    method: 'DELETE',
  });
  if (!res.ok) throw new Error('Failed to clear scan history');
  return res.json();
}

