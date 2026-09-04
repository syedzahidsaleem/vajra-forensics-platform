// TypeScript type definitions matching Vajra Rust backend crates

export type AppMode = 'forensic' | 'sanitization';

export type ScreenId =
  | 'dashboard'
  | 'devices'
  | 'acquisition'
  | 'recovery'
  | 'hex'
  | 'sanitization'
  | 'reports'
  | 'audit';

export type MediaType =
  | 'HDD'
  | 'SSD'
  | 'NVMe'
  | 'USB'
  | 'SD'
  | 'Optical'
  | 'Virtual'
  | 'Unknown';

export interface DeviceDescriptor {
  path: string;
  name?: string;
  model: string;
  serial: string;
  vendor?: string;
  size_bytes: number;
  block_size: number;
  media_type: MediaType;
  read_only: boolean;
  is_system_disk: boolean;
  is_write_blocked?: boolean;
  bus_type?: string;
  partitions?: PartitionInfo[];
}

export interface PartitionInfo {
  index: number;
  offset_bytes: number;
  size_bytes: number;
  filesystem?: string;
  label?: string;
}

export interface DeviceFingerprint {
  path: string;
  sha256_hash: string;
  size_bytes: number;
  serial: string;
  model: string;
  vendor?: string;
  sector_sample_hash?: string;
  computed_at: string;
}

export interface SmartHealthSnapshot {
  device_path: string;
  overall_health: 'PASSED' | 'WARNING' | 'FAILED' | 'UNKNOWN';
  temperature_celsius?: number;
  power_on_hours?: number;
  reallocated_sectors?: number;
  pending_sectors?: number;
  wear_level_percent?: number;
  nvme_critical_warning?: number;
  is_failing: boolean;
  recommendation: string;
}

export type CaseStatus = 'Active' | 'Closed';

export interface CaseRecord {
  case_id: string;
  case_name: string;
  investigator_id: string;
  created_at: string;
  status: CaseStatus;
  notes?: string;
  evidence_count?: number;
}

export interface EvidenceItemRecord {
  evidence_id: string;
  case_id: string;
  source_path: string;
  media_type: MediaType;
  size_bytes: number;
  sha256_hash: string;
  added_at: string;
  description: string;
  custody_holder?: string;
}

export type CustodyEventType =
  | 'Acquisition'
  | 'Transfer'
  | 'Analysis'
  | 'Storage'
  | 'CourtPresentation'
  | 'Destruction'
  | 'Release';

export interface CustodyEvent {
  event_id: string;
  evidence_id: string;
  timestamp: string;
  event_type: CustodyEventType;
  operator_from: string;
  operator_to: string;
  location: string;
  purpose: string;
  notes?: string;
}

export type AcquisitionProfile = 'Physical' | 'Logical' | 'Partial';
export type ImageFormat = 'RAW' | 'E01';

export interface AcquisitionConfig {
  source_device_path: string;
  destination_path: string;
  image_name: string;
  profile: AcquisitionProfile;
  format: ImageFormat;
  segment_size_mb: number;
  compute_sha256: boolean;
  compute_md5: boolean;
  case_id: string;
  evidence_id: string;
  examiner: string;
  notes?: string;
}

export interface AcquisitionProgress {
  state: 'idle' | 'running' | 'paused' | 'completed' | 'error';
  bytes_processed: number;
  total_bytes: number;
  progress_percent: number;
  current_speed_mbps: number;
  elapsed_seconds: number;
  estimated_remaining_seconds: number;
  bad_sectors_count: number;
  sha256_checksum?: string;
  error_message?: string;
}

export interface BadSectorBlock {
  lba: number;
  length_sectors: number;
  error_type: string;
}

export type SanitizeMethod =
  | 'CryptoErase'
  | 'BlockErase'
  | 'OverwriteZeros'
  | 'OverwriteRandom'
  | 'DoD522022M'
  | 'NistClear'
  | 'NistPurge'
  | 'FirmwareSecureErase';

export interface SanitizationRecommendation {
  device_path: string;
  media_type: MediaType;
  recommended_method: SanitizeMethod;
  assurance_level: 'High' | 'Moderate' | 'Low';
  rationale: string;
  passes_required: number;
  estimated_duration_minutes: number;
  is_os_disk_blocked: boolean;
}

export interface SanitizationGateState {
  gate_id: string;
  device_path: string;
  device_serial: string;
  fingerprint: DeviceFingerprint;
  step: 1 | 2 | 3 | 4 | 5 | 6 | 7;
  initial_confirmed: boolean;
  recommendation_viewed: boolean;
  second_confirmed: boolean;
  serial_typed_match: boolean;
  execution_token?: string;
}

export interface PassVerificationStatus {
  pass_number: number;
  total_passes: number;
  pattern_description: string;
  percent_complete: number;
  bytes_verified: number;
  total_bytes: number;
  status: 'pending' | 'in_progress' | 'verified' | 'failed';
  error_count: number;
}

export interface SanitizationCertificate {
  certificate_id: string;
  case_id: string;
  device_fingerprint: DeviceFingerprint;
  method_applied: SanitizeMethod;
  passes_executed: number;
  layers_verified: string[];
  operator_id: string;
  completed_at: string;
  digital_signature: string;
  certificate_pdf_path?: string;
}

export type ReportType =
  | 'ForensicExamination'
  | 'Acquisition'
  | 'Recovery'
  | 'SanitizationCertificate'
  | 'DeviceHealth'
  | 'ChainOfCustody';

export interface ReportSummary {
  report_id: string;
  report_type: ReportType;
  case_id: string;
  title: string;
  created_at: string;
  operator_id: string;
  signed: boolean;
  json_path: string;
  pdf_path?: string;
}

export interface VerificationCheckResult {
  check_name: string;
  passed: boolean;
  details: string;
}

export interface ReportVerificationResult {
  report_id: string;
  valid: boolean;
  signature_verified: boolean;
  audit_chain_intact: boolean;
  hash_matches: boolean;
  timestamp_verified: boolean;
  checks: VerificationCheckResult[];
}
