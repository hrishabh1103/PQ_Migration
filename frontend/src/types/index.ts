export type TargetType = 'HOSTNAME' | 'IP_RANGE' | 'CIDR' | 'URL' | 'REPOSITORY' | 'CERT_STORE';

export type ScanStatus = 'PENDING' | 'RUNNING' | 'COMPLETED' | 'FAILED' | 'CANCELLED';

export type AssetType = 'HOST' | 'SERVER' | 'APPLICATION' | 'SOURCE_REPOSITORY' | 'CONTAINER';

export type TransportProtocol = 'TCP' | 'UDP' | 'NONE';

export type ApplicationProtocol = 'HTTPS' | 'TLS' | 'SSH' | 'HTTP' | 'UNKNOWN';

export type FindingType = 
  | 'CERTIFICATE_PUBLIC_KEY' 
  | 'KEY_EXCHANGE' 
  | 'SYMMETRIC_CIPHER' 
  | 'HASH_FUNCTION' 
  | 'SIGNATURE_ALGORITHM' 
  | 'LIBRARY_DEPENDENCY';

export type FindingPurpose = 'AUTHENTICATION' | 'KEY_EXCHANGE' | 'ENCRYPTION' | 'INTEGRITY' | 'DIGITAL_SIGNATURE' | 'UNKNOWN';

export type FindingConfidence = 'HIGH' | 'MEDIUM' | 'LOW';

export type QuantumSafetyStatus = 
  | 'QUANTUM_VULNERABLE' 
  | 'PQC_STANDARDIZED' 
  | 'PQC_CANDIDATE' 
  | 'HYBRID' 
  | 'SYMMETRIC' 
  | 'HASH' 
  | 'LEGACY' 
  | 'DEPRECATED' 
  | 'UNKNOWN';

export interface AuthorizedTarget {
  id: string;
  name: string;
  target_type: TargetType;
  target_value: string;
  is_authorized: boolean;
  environment: string;
  created_at: string;
  updated_at: string;
}

export interface TargetCreateInput {
  name: string;
  target_type: TargetType;
  target_value: string;
  is_authorized: boolean;
  environment: string;
}

export interface ScanJob {
  id: string;
  target_id: string;
  status: ScanStatus;
  requested_scanners: string[];
  started_at?: string;
  completed_at?: string;
  error_message?: string;
  stats_json: {
    assets_found?: number;
    services_found?: number;
    findings_found?: number;
  };
}

export interface Service {
  id: string;
  asset_id: string;
  port?: number;
  transport_protocol: TransportProtocol;
  application_protocol: ApplicationProtocol;
  service_name: string;
  metadata_json: Record<string, any>;
  first_seen_at: string;
  last_seen_at: string;
}

export interface Asset {
  id: string;
  target_id: string;
  hostname?: string;
  ip_address?: string;
  asset_type: AssetType;
  environment: string;
  operating_system?: string;
  metadata_json: Record<string, any>;
  first_seen_at: string;
  last_seen_at: string;
  services: Service[];
}

export interface NormalizedAlgorithm {
  canonical_id: string;
  name: string;
  observed_name: string;
  canonical_family: string;
  canonical_variant: string;
  implementation_variant?: string;
  primitive_type: string;
  quantum_safety_status: QuantumSafetyStatus;
  estimated_security_bits?: number;
  nist_standard_status?: string;
}

export interface CryptoFinding {
  id: string;
  scan_job_id: string;
  asset_id: string;
  service_id?: string;
  scanner_id: string;
  scanner_version: string;
  finding_type: FindingType;
  raw_algorithm_name: string;
  normalized_algorithm_id: string;
  purpose: FindingPurpose;
  location_identifier: string;
  evidence_snippet: string;
  evidence_hash: string;
  confidence: FindingConfidence;
  metadata_json: Record<string, any>;
  first_seen_at: string;
  last_seen_at: string;
  normalized_algorithm?: NormalizedAlgorithm;
}

export interface DashboardStats {
  assets_count: number;
  services_count: number;
  findings_count: number;
  scan_jobs_count: number;
  algorithm_distribution: Record<string, number>;
  scan_status_distribution: Record<string, number>;
}
