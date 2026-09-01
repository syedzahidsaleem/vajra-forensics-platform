/**
 * Vajra Forensics & Sanitization Platform — Tauri IPC Canonical Type Definitions
 * Location: crates/vajra-tauri-app/ui/src/types/vajra.ts
 *
 * Single source of truth for Tauri IPC types shared across all frontend screens:
 * - Hari Priya's screens: Recovery Browser, Hex Explorer, Storage Visualizer
 * - Nitya's screens: Dashboard, Sanitization Console, Acquisition Wizard
 *
 * Field names strictly match Rust serde output (snake_case).
 */

import { invoke } from '@tauri-apps/api/tauri';

// =============================================================================
// FROM vajra-carve (types.rs, confidence.rs)
// =============================================================================

/** Recovery Tier classification (§25, §26, §27) */
export type RecoveryTier = "Tier1Metadata" | "Tier2Signature" | "Tier3Fragmented";

/** Detailed fragmentation parameters for Tier-3 reassembled artifacts (§31) */
export interface FragmentationDetail {
  gap_size_sectors: number;
  fragment_1: [number, number];
  fragment_2: [number, number];
}

/** Named tunable weight constants for recovery confidence scoring (§29) */
export const WEIGHT_HEADER_FOOTER: number = 0.20;
export const WEIGHT_STRUCTURAL: number = 0.25;
export const WEIGHT_METADATA: number = 0.20;
export const WEIGHT_ENTROPY: number = 0.15;
export const WEIGHT_FRAGMENTATION: number = 0.15;
export const WEIGHT_OVERWRITE: number = 0.05;

/** Component signal breakdown of recovery confidence (§29) */
export interface ConfidenceBreakdown {
  header_footer_integrity: number;
  structural_validity: number;
  metadata_cross_reference: number;
  entropy_consistency: number;
  entropy_explainability: string | null;
  fragmentation_confidence: number;
  overwrite_probability: number;
}

/** Canonical Recovered Artifact Record (§31) */
export interface RecoveredArtifact {
  id: number;
  recovery_method: RecoveryTier;
  source_locations: [number, number][];
  original_path: string | null;
  filename_guess: string | null;
  file_type: string;
  confidence_score: number;
  confidence_breakdown: ConfidenceBreakdown;
  fragmentation_detail: FragmentationDetail | null;
  recovered_bytes: number;
  expected_total_bytes: number | null;
  content_hash: string;
  recovery_limitations: string | null;
}

// =============================================================================
// FROM vajra-core (fs.rs, media_type.rs, sanitize.rs, write_blocker.rs)
// =============================================================================

/** Metadata confidence level evaluating survival and allocation status (§25, §29) */
export type MetadataConfidence = "Low" | "Reconstructed" | "Partial" | "Confirmed";

/** Supported filesystem classifications for partition detection and parser dispatch */
export type FilesystemType =
  | "Ntfs"
  | "Ext4"
  | "Fat12"
  | "Fat16"
  | "Fat32"
  | "ExFat"
  | "Apfs"
  | "HfsPlus"
  | "Unknown";

/** Data block location mapping on underlying block source (discriminated union) (§25) */
export type DataLocation =
  | { type: "Resident"; data: number[] }
  | { type: "Contiguous"; start_lba: number; block_count: number }
  | { type: "Fragmented"; extents: [number, number][] }
  | { type: "Unresolved" };

/** Canonical recoverable file entry produced by Tier-1 filesystem parsers (§25) */
export interface RecoverableFileEntry {
  id: number;
  original_path: string | null;
  filename: string | null;
  size_bytes: number | null;
  created: string | null;
  modified: string | null;
  accessed: string | null;
  deleted: boolean;
  data_location: DataLocation;
  metadata_confidence: MetadataConfidence;
  source_filesystem: FilesystemType;
}

/** Classification of underlying storage medium (§16, §33a, §35) */
export type MediaType =
  | "Hdd"
  | "SataSsd"
  | "Nvme"
  | "Sed"
  | "Usb"
  | "SdCard"
  | "ForensicImage";

/** Method by which write protection or hardware write-blocker was detected */
export type WriteBlockerDetectionMethod =
  | "KnownVidPid"
  | "OsQuery"
  | "ScsiCommand"
  | "ManualOverride";

/** Metadata identifying a detected hardware or software write blocker (§24) */
export interface WriteBlockerMetadata {
  vendor: string | null;
  model: string | null;
  vid: number | null;
  pid: number | null;
  detection_method: WriteBlockerDetectionMethod;
  is_hardware_blocked: boolean;
  is_os_read_only: boolean;
}

/** Sanitization method supported by storage hardware or software overwrite engines (§33a-§35) */
export type SanitizeMethod =
  | "AtaSecureErase"
  | "AtaEnhancedSecureErase"
  | "NvmeSanitizeBlock"
  | "NvmeSanitizeCrypto"
  | "NvmeFormat"
  | "CryptographicErase"
  | "HostOverwriteSinglePass"
  | { type: "HostOverwriteMultiPass"; passes: number }
  | "ScsiSanitizeOverwrite"
  | "ScsiSanitizeCrypto";

// =============================================================================
// FROM vajra-device (descriptor.rs, fingerprint.rs, health.rs)
// =============================================================================

/** Normalized metadata descriptor for a physical storage device (§23) */
export interface DeviceDescriptor {
  path: string;
  device_index: number;
  manufacturer: string;
  model: string;
  serial: string;
  capacity_bytes: number;
  logical_block_size: number;
  physical_block_size: number;
  media_type: MediaType;
  interface: string;
  partition_table: string;
  is_system_disk: boolean;
  is_read_only: boolean;
  is_write_blocked: boolean;
  write_blocker_info: WriteBlockerMetadata | null;
  boundary_sample: number[];
}

/** Unique hardware identity fingerprint for a storage device (§23) */
export interface DeviceFingerprint {
  manufacturer: string;
  model: string;
  serial: string;
  capacity_bytes: number;
  interface: string;
  sha256_hash: string;
}

/** Operational health status classification */
export type HealthStatus = "Good" | "Warning" | "Critical" | "Unknown";

/** Parsed ATA SMART attribute (§23) */
export interface SmartAttribute {
  id: number;
  name: string;
  current: number;
  worst: number;
  threshold: number;
  raw_value: number;
  failing_now: boolean;
}

/** Detailed NVMe SMART / Health Information Log fields (§23) */
export interface NvmeHealthInfo {
  critical_warnings: number;
  temperature_celsius: number;
  available_spare_percent: number;
  available_spare_threshold: number;
  percentage_used: number;
  data_units_read: number;
  data_units_written: number;
  host_read_commands: number;
  host_write_commands: number;
  controller_busy_time_minutes: number;
  power_cycles: number;
  power_on_hours: number;
  unsafe_shutdowns: number;
  media_errors: number;
  error_log_entries: number;
}

/** Key HDD health diagnostic indicators (§23) */
export interface HddHealthInfo {
  reallocated_sectors: number;
  pending_sectors: number;
  uncorrectable_sectors: number;
  power_on_hours: number;
  temperature_celsius: number;
  raw_read_error_rate: number;
}

/** Host Protected Area (HPA) and Device Configuration Overlay (DCO) diagnostic details (§35) */
export interface HpaDcoInfo {
  hpa_detected: boolean;
  dco_detected: boolean;
  user_lba_capacity: number;
  native_max_lba: number;
  hidden_sectors: number;
}

/** Complete diagnostic health report for a storage device (§23) */
export interface DeviceHealthSummary {
  status: HealthStatus;
  media_type: MediaType;
  smart_attributes: SmartAttribute[];
  nvme_health: NvmeHealthInfo | null;
  hdd_health: HddHealthInfo | null;
  hpa_dco_info: HpaDcoInfo | null;
  recommendation: string;
}

// =============================================================================
// FROM vajra-erase (gate.rs, verify/mod.rs, decision_engine.rs)
// =============================================================================

/** Unforgeable authorization capability token required by destructive operations (§43) */
export interface SanitizationAuthorizationToken {
  token_id: string;
  target_path: string;
  target_serial: string;
  target_fingerprint: string;
  operator_id: string;
  authorized_at: string;
}

/** Phase 1 pending authorization ticket reference (§43) */
export interface PendingSanitizationTicket {
  ticket_id: string;
  target_path: string;
  target_serial: string;
  initiated_at: string;
}

/** Overall Sanitization Assurance Level (§37, §38) */
export type OverallAssurance = "High" | "Medium" | "Low" | "Failed";

/** Layer 1 Verification: Command-Level Result (§37) */
export interface Layer1Result {
  passed: boolean;
  command_status_code: number | null;
  message: string;
}

/** Layer 2 Verification: Device Status Result (§37) */
export interface Layer2Result {
  passed: boolean;
  status_code: string;
  message: string;
}

/** Layer 3 Verification: Deterministic Bounded Sample Result (§37) */
export interface Layer3Result {
  passed: boolean;
  verified_sectors_count: number;
  unverified_or_mismatched_count: number;
  message: string;
}

/** Statistical sampling parameters for Layer 4 verification (§37) */
export interface StatisticalParams {
  total_sectors_n: number;
  confidence_c: number;
  assumed_defect_rate_p: number;
  computed_sample_size_n: number;
}

/** Layer 4 Verification: Statistical Sampling Result (§37) */
export interface Layer4Result {
  passed: boolean;
  params: StatisticalParams;
  sampled_sectors_count: number;
  non_conforming_sectors_count: number;
  message: string;
}

/** Layer 5 Verification: Independent Recovery Engine Scan Result (§37) */
export interface Layer5Result {
  passed: boolean;
  recovered_artifacts_count: number;
  recovered_artifact_ids: number[];
  message: string;
}

/** Comprehensive 5-Layer Verification Report (§37) */
export interface MultiLayerVerificationReport {
  layer1: Layer1Result;
  layer2: Layer2Result;
  layer3: Layer3Result;
  layer4: Layer4Result;
  layer5: Layer5Result;
  overall_assurance: OverallAssurance;
  summary_reason: string;
}

/** Structured recommendation output from the Sanitization Decision Engine (§34) */
export interface SanitizationRecommendation {
  device_summary: string;
  media_type: MediaType;
  is_sed: boolean;
  recommended_method: SanitizeMethod;
  recommended_label: string;
  reason: string;
  alternative_available: string | null;
  not_recommended: string | null;
  residual_risk_warning: string | null;
}

// =============================================================================
// FROM vajra-case-db (models.rs)
// =============================================================================

/** Forensic case lifecycle status (§22) */
export type CaseStatus = "Active" | "Closed";

/** Case record in the Evidence Vault (§22) */
export interface CaseRecord {
  case_id: string;
  case_name: string;
  investigator_id: string;
  created_at: string;
  status: CaseStatus;
}

// =============================================================================
// FROM vajra-tauri-app (main.rs)
// =============================================================================

/** Storage Block Visualization payload structure (§32) */
export interface StorageMapData {
  total_blocks: number;
  block_size: number;
  allocated_ranges: [number, number][];
  unallocated_ranges: [number, number][];
  bad_sector_ranges: [number, number][];
  recovered_fragment_ranges: [number, number][];
}

// =============================================================================
// TYPED TAURI IPC COMMAND INVOKE WRAPPERS
// =============================================================================

// Device Commands (§23, §24)

export const listDevices = (): Promise<DeviceDescriptor[]> =>
  invoke<DeviceDescriptor[]>('list_devices');

export const getDeviceFingerprint = (
  device_path: string
): Promise<DeviceFingerprint> =>
  invoke<DeviceFingerprint>('get_device_fingerprint', { device_path });

export const getDeviceHealth = (
  device_path: string
): Promise<DeviceHealthSummary> =>
  invoke<DeviceHealthSummary>('get_device_health', { device_path });

// Recovery Commands (§25–§32)

export const runRecoveryPipeline = (
  source_path: string,
  enable_tier1: boolean,
  enable_tier2: boolean,
  enable_tier3: boolean
): Promise<RecoveredArtifact[]> =>
  invoke<RecoveredArtifact[]>('run_recovery_pipeline', {
    source_path,
    enable_tier1,
    enable_tier2,
    enable_tier3,
  });

export const getArtifactPayload = (
  source_path: string,
  artifact_id: number
): Promise<number[]> =>
  invoke<number[]>('get_artifact_payload', { source_path, artifact_id });

export const readRawSectors = (
  source_path: string,
  start_lba: number,
  block_count: number
): Promise<number[]> =>
  invoke<number[]>('read_raw_sectors', { source_path, start_lba, block_count });

export const getStorageMap = (
  source_path: string
): Promise<StorageMapData> =>
  invoke<StorageMapData>('get_storage_map', { source_path });

// Sanitization Commands (§33a–§38, §43)

export const getSanitizationRecommendation = (
  device_path: string
): Promise<SanitizationRecommendation> =>
  invoke<SanitizationRecommendation>('get_sanitization_recommendation', { device_path });

export const beginSanitizationGate = (
  device_path: string,
  operator_id: string,
  typed_serial: string
): Promise<PendingSanitizationTicket> =>
  invoke<PendingSanitizationTicket>('begin_sanitization_gate', {
    device_path,
    operator_id,
    typed_serial,
  });

export const finalizeSanitizationGate = (
  ticket_id: string,
  pre_exec_confirm: boolean
): Promise<SanitizationAuthorizationToken> =>
  invoke<SanitizationAuthorizationToken>('finalize_sanitization_gate', {
    ticket_id,
    pre_exec_confirm,
  });

export const executeSanitization = (
  token: SanitizationAuthorizationToken,
  method_name: string
): Promise<string> =>
  invoke<string>('execute_sanitization', { token, method_name });

export const verifySanitizationResult = (
  device_path: string,
  token: SanitizationAuthorizationToken
): Promise<MultiLayerVerificationReport> =>
  invoke<MultiLayerVerificationReport>('verify_sanitization_result', {
    device_path,
    token,
  });

// Case & Reporting Commands (§17, §22, §41)

export const createCase = (
  name: string,
  examiner: string,
  db_path: string
): Promise<string> =>
  invoke<string>('create_case', { name, examiner, db_path });

export const listCases = (
  db_path: string
): Promise<CaseRecord[]> =>
  invoke<CaseRecord[]>('list_cases', { db_path });

export const generateReport = (
  db_path: string,
  case_id: string,
  report_type: string,
  out_dir: string
): Promise<string> =>
  invoke<string>('generate_report', { db_path, case_id, report_type, out_dir });
