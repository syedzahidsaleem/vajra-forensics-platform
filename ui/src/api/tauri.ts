// Typed Tauri IPC bridge for Vajra Forensics Platform
// Calls real Rust commands in Tauri runtime, with realistic local fallbacks when previewing in browser

import {
  DeviceDescriptor,
  DeviceFingerprint,
  SmartHealthSnapshot,
  CaseRecord,
  EvidenceItemRecord,
  CustodyEvent,
  AcquisitionConfig,
  AcquisitionProgress,
  SanitizationRecommendation,
  SanitizationCertificate,
  ReportSummary,
  ReportVerificationResult,
  ReportType,
} from '../types';

declare global {
  interface Window {
    __TAURI_INTERNALS__?: unknown;
    __TAURI__?: unknown;
  }
}

const isTauri = (): boolean => {
  return typeof window !== 'undefined' && (!!window.__TAURI_INTERNALS__ || !!window.__TAURI__);
};

async function invokeTauri<T>(cmd: string, args: Record<string, unknown> = {}): Promise<T> {
  if (isTauri()) {
    try {
      // Dynamic import to avoid build breaks outside Tauri runtime
      const { invoke } = await import('@tauri-apps/api/core');
      return await invoke<T>(cmd, args);
    } catch (err) {
      console.warn(`[Tauri IPC] Command '${cmd}' failed:`, err);
      throw err;
    }
  }
  return mockHandler<T>(cmd, args);
}

// -------------------------------------------------------------
// Real IPC API methods wrapping backend
// -------------------------------------------------------------

export const tauriApi = {
  // Device Layer
  async listDevices(): Promise<DeviceDescriptor[]> {
    return invokeTauri<DeviceDescriptor[]>('list_devices');
  },

  async getDeviceFingerprint(devicePath: string): Promise<DeviceFingerprint> {
    return invokeTauri<DeviceFingerprint>('get_device_fingerprint', { devicePath });
  },

  async getDeviceHealth(devicePath: string): Promise<SmartHealthSnapshot> {
    return invokeTauri<SmartHealthSnapshot>('get_device_health', { devicePath });
  },

  // Case & Evidence Vault
  async listCases(): Promise<CaseRecord[]> {
    return invokeTauri<CaseRecord[]>('list_cases');
  },

  async createCase(
    caseId: string,
    caseName: string,
    investigatorId: string,
    notes?: string
  ): Promise<CaseRecord> {
    return invokeTauri<CaseRecord>('create_case', { caseId, caseName, investigatorId, notes });
  },

  async closeCase(caseId: string): Promise<boolean> {
    return invokeTauri<boolean>('close_case', { caseId });
  },

  async listEvidence(caseId: string): Promise<EvidenceItemRecord[]> {
    return invokeTauri<EvidenceItemRecord[]>('list_evidence', { caseId });
  },

  async addEvidence(
    caseId: string,
    sourcePath: string,
    description: string
  ): Promise<EvidenceItemRecord> {
    return invokeTauri<EvidenceItemRecord>('add_evidence', { caseId, sourcePath, description });
  },

  async getCustodyHistory(evidenceId: string): Promise<CustodyEvent[]> {
    return invokeTauri<CustodyEvent[]>('get_custody_history', { evidenceId });
  },

  async recordCustodyEvent(
    event: Omit<CustodyEvent, 'event_id' | 'timestamp'>
  ): Promise<CustodyEvent> {
    return invokeTauri<CustodyEvent>('record_custody_event', { event });
  },

  // Acquisition Wizard
  async startAcquisition(config: AcquisitionConfig): Promise<{ jobId: string }> {
    return invokeTauri<{ jobId: string }>('start_acquisition', { config });
  },

  async getAcquisitionProgress(jobId: string): Promise<AcquisitionProgress> {
    return invokeTauri<AcquisitionProgress>('get_acquisition_progress', { jobId });
  },

  async listAcquisitionCheckpoints(caseId: string): Promise<any[]> {
    return invokeTauri<any[]>('list_acquisition_checkpoints', { caseId });
  },

  async resumeAcquisition(opId: string): Promise<any> {
    return invokeTauri<any>('resume_acquisition', { opId });
  },

  // Sanitization Safety Gate
  async getSanitizationRecommendation(
    devicePath: string
  ): Promise<SanitizationRecommendation> {
    return invokeTauri<SanitizationRecommendation>('get_sanitization_recommendation', {
      devicePath,
    });
  },

  async beginSanitizationGate(
    devicePath: string
  ): Promise<{ gateId: string; fingerprint: DeviceFingerprint }> {
    return invokeTauri<{ gateId: string; fingerprint: DeviceFingerprint }>(
      'begin_sanitization_gate',
      { devicePath }
    );
  },

  async finalizeSanitizationGate(
    gateId: string,
    typedSerial: string
  ): Promise<{ token: string }> {
    return invokeTauri<{ token: string }>('finalize_sanitization_gate', {
      gateId,
      typedSerial,
    });
  },

  async executeSanitization(
    token: string,
    method: string
  ): Promise<SanitizationCertificate> {
    return invokeTauri<SanitizationCertificate>('execute_sanitization', { token, method });
  },

  async sanitizeFile(filePath: string, passes: number): Promise<any> {
    return invokeTauri<any>('sanitize_file', { filePath, passes });
  },

  async sanitizeUnallocatedSlack(volumePath: string): Promise<any> {
    return invokeTauri<any>('sanitize_unallocated_slack', { volumePath });
  },

  // Report Center
  async listReports(caseId: string): Promise<ReportSummary[]> {
    return invokeTauri<ReportSummary[]>('list_reports', { caseId });
  },

  async generateReport(
    caseId: string,
    reportType: ReportType,
    notes?: string,
    evidenceId?: string
  ): Promise<ReportSummary> {
    return invokeTauri<ReportSummary>('generate_report', {
      caseId,
      reportType,
      notes,
      evidenceId,
    });
  },

  async verifyReport(reportPath: string): Promise<ReportVerificationResult> {
    return invokeTauri<ReportVerificationResult>('verify_report', { reportPath });
  },

  async exportReportHtml(reportId: string, outputPath?: string): Promise<string> {
    return invokeTauri<string>('export_report_html', { reportId, outputPath });
  },
};

// -------------------------------------------------------------
// Realistic Browser Mock Fallback (for web dev preview & smoke tests)
// -------------------------------------------------------------

const mockCases: CaseRecord[] = [
  {
    case_id: 'CASE-2026-001',
    case_name: 'Operation Trident Vault',
    investigator_id: 'INV-4402-NITYA',
    created_at: '2026-08-15 09:30:00 UTC',
    status: 'Active',
    notes: 'Physical digital media seizure under judicial warrant W-2026-88',
    evidence_count: 3,
  },
  {
    case_id: 'CASE-2026-002',
    case_name: 'Cyber Incident Alpha',
    investigator_id: 'INV-4402-NITYA',
    created_at: '2026-08-20 14:15:00 UTC',
    status: 'Closed',
    notes: 'Completed examination. Final report verified and signed.',
    evidence_count: 1,
  },
];

const mockDevices: DeviceDescriptor[] = [
  {
    path: '\\\\.\\PhysicalDrive0',
    model: 'Samsung SSD 990 PRO 2TB',
    serial: 'S75SNX0W102938K',
    vendor: 'Samsung',
    size_bytes: 2000398934016,
    block_size: 512,
    media_type: 'NVMe',
    read_only: false,
    is_system_disk: true,
    is_write_blocked: false,
    bus_type: 'NVMe',
  },
  {
    path: '\\\\.\\PhysicalDrive1',
    model: 'Kingston DataTraveler 3.0',
    serial: '0014D118C526EB7170000049',
    vendor: 'Kingston',
    size_bytes: 32014925824,
    block_size: 512,
    media_type: 'USB',
    read_only: true,
    is_system_disk: false,
    is_write_blocked: true,
    bus_type: 'USB',
  },
  {
    path: '\\\\.\\PhysicalDrive2',
    model: 'Seagate Barracuda ST1000DM010',
    serial: 'W9A482XQ',
    vendor: 'Seagate',
    size_bytes: 1000204886016,
    block_size: 4096,
    media_type: 'HDD',
    read_only: false,
    is_system_disk: false,
    is_write_blocked: false,
    bus_type: 'SATA',
  },
];

async function mockHandler<T>(cmd: string, args: Record<string, unknown>): Promise<T> {
  // Smooth simulated response
  await new Promise((r) => setTimeout(r, 60));

  switch (cmd) {
    case 'list_devices':
      return mockDevices as unknown as T;

    case 'get_device_fingerprint': {
      const path = (args.devicePath as string) || '\\\\.\\PhysicalDrive1';
      const dev = mockDevices.find((d) => d.path === path) || mockDevices[1];
      const res: DeviceFingerprint = {
        path: dev.path,
        sha256_hash: '26c5b60090d8a218db45eb1142ff6cc3976c3621effd7b7d45042232f6ddc9f3',
        size_bytes: dev.size_bytes,
        serial: dev.serial,
        model: dev.model,
        vendor: dev.vendor,
        sector_sample_hash: '9f86d081884c7d659a2feaa0c55ad015a3bf4f1b2b0b822cd15d6c15b0f00a08',
        computed_at: new Date().toISOString(),
      };
      return res as unknown as T;
    }

    case 'get_device_health': {
      const path = (args.devicePath as string) || '\\\\.\\PhysicalDrive0';
      const res: SmartHealthSnapshot = {
        device_path: path,
        overall_health: 'PASSED',
        temperature_celsius: 38,
        power_on_hours: 1420,
        reallocated_sectors: 0,
        pending_sectors: 0,
        wear_level_percent: 99,
        is_failing: false,
        recommendation:
          'Drive is in optimal operating condition. Suitable for direct imaging or cryptographic sanitization.',
      };
      return res as unknown as T;
    }

    case 'list_cases':
      return mockCases as unknown as T;

    case 'create_case': {
      const newCase: CaseRecord = {
        case_id: args.caseId as string,
        case_name: args.caseName as string,
        investigator_id: args.investigatorId as string,
        created_at: new Date().toISOString(),
        status: 'Active',
        notes: (args.notes as string) || '',
        evidence_count: 0,
      };
      mockCases.unshift(newCase);
      return newCase as unknown as T;
    }

    case 'close_case': {
      const target = mockCases.find((c) => c.case_id === args.caseId);
      if (target) target.status = 'Closed';
      return true as unknown as T;
    }

    case 'list_evidence': {
      const items: EvidenceItemRecord[] = [
        {
          evidence_id: 'EVID-001',
          case_id: (args.caseId as string) || 'CASE-2026-001',
          source_path: '\\\\.\\PhysicalDrive1',
          media_type: 'USB',
          size_bytes: 32014925824,
          sha256_hash: '8f434346648f6b96df89dda901c5176b10a6d83961dd3c1ac88b59b2dc327aa4',
          added_at: '2026-08-15 10:05:00 UTC',
          description: 'Seized 32GB Kingston Thumb Drive (Target suspect device)',
          custody_holder: 'INV-4402-NITYA',
        },
      ];
      return items as unknown as T;
    }

    case 'add_evidence': {
      const item: EvidenceItemRecord = {
        evidence_id: 'EVID-' + Math.floor(Math.random() * 1000),
        case_id: (args.caseId as string) || 'CASE-2026-001',
        source_path: (args.sourcePath as string) || '\\\\.\\PhysicalDrive1',
        media_type: 'USB',
        size_bytes: 32014925824,
        sha256_hash: '8f434346648f6b96df89dda901c5176b10a6d83961dd3c1ac88b59b2dc327aa4',
        added_at: new Date().toISOString(),
        description: (args.description as string) || 'Registered forensic media',
        custody_holder: 'INV-4402-NITYA',
      };
      return item as unknown as T;
    }

    case 'get_custody_history': {
      const evId = (args.evidenceId as string) || 'EVID-001';
      const events: CustodyEvent[] = [
        {
          event_id: 'CUST-001',
          evidence_id: evId,
          timestamp: '2026-08-15 10:05:00 UTC',
          event_type: 'Acquisition',
          operator_from: 'Field Officer S. Rao',
          operator_to: 'INV-4402-NITYA',
          location: 'Evidence Lockbox Alpha',
          purpose: 'Initial acquisition and digital preservation',
        },
        {
          event_id: 'CUST-002',
          evidence_id: evId,
          timestamp: '2026-08-15 14:30:00 UTC',
          event_type: 'Transfer',
          operator_from: 'INV-4402-NITYA',
          operator_to: 'Digital Forensics Lab Vault A',
          location: 'Secure Cabinet 4',
          purpose: 'Physical storage following bit-stream imaging',
        },
      ];
      return events as unknown as T;
    }

    case 'start_acquisition': {
      return { jobId: 'ACQ-JOB-9921' } as unknown as T;
    }

    case 'get_acquisition_progress': {
      const progress: AcquisitionProgress = {
        state: 'running',
        bytes_processed: 24576000000,
        total_bytes: 32014925824,
        progress_percent: 76,
        current_speed_mbps: 185.4,
        elapsed_seconds: 132,
        estimated_remaining_seconds: 40,
        bad_sectors_count: 0,
        sha256_checksum: '8f434346648f6b96df89dda901c5176b10a6d83961dd3c1ac88b59b2dc327aa4',
      };
      return progress as unknown as T;
    }

    case 'get_sanitization_recommendation': {
      const devPath = (args.devicePath as string) || '\\\\.\\PhysicalDrive2';
      const dev = mockDevices.find((d) => d.path === devPath) || mockDevices[2];
      const isSystem = dev.is_system_disk;
      const rec: SanitizationRecommendation = {
        device_path: dev.path,
        media_type: dev.media_type,
        recommended_method: dev.media_type === 'NVMe' ? 'CryptoErase' : 'NistClear',
        assurance_level: 'High',
        rationale:
          dev.media_type === 'NVMe'
            ? 'NIST SP 800-88 Rev 1 Purge: NVMe Cryptographic Erase invalidates media encryption keys instantaneously without flash wear.'
            : 'NIST SP 800-88 Rev 1 Clear: Single pass pseudo-random overwrite with read-back verification across all addressable LBAs.',
        passes_required: dev.media_type === 'NVMe' ? 1 : 1,
        estimated_duration_minutes: dev.media_type === 'NVMe' ? 1 : 45,
        is_os_disk_blocked: isSystem,
      };
      return rec as unknown as T;
    }

    case 'begin_sanitization_gate': {
      const devPath = (args.devicePath as string) || '\\\\.\\PhysicalDrive2';
      const dev = mockDevices.find((d) => d.path === devPath) || mockDevices[2];
      return {
        gateId: 'GATE-9842-' + Date.now(),
        fingerprint: {
          path: dev.path,
          sha256_hash: '26c5b60090d8a218db45eb1142ff6cc3976c3621effd7b7d45042232f6ddc9f3',
          size_bytes: dev.size_bytes,
          serial: dev.serial,
          model: dev.model,
          vendor: dev.vendor,
          computed_at: new Date().toISOString(),
        },
      } as unknown as T;
    }

    case 'finalize_sanitization_gate': {
      return { token: 'AUTH-TOKEN-VAJRA-GATE-VERIFIED-991204' } as unknown as T;
    }

    case 'execute_sanitization': {
      const cert: SanitizationCertificate = {
        certificate_id: 'CERT-VAJRA-SAN-998241',
        case_id: 'CASE-2026-001',
        device_fingerprint: {
          path: '\\\\.\\PhysicalDrive2',
          sha256_hash: '26c5b60090d8a218db45eb1142ff6cc3976c3621effd7b7d45042232f6ddc9f3',
          size_bytes: 1000204886016,
          serial: 'W9A482XQ',
          model: 'Seagate Barracuda ST1000DM010',
          vendor: 'Seagate',
          computed_at: new Date().toISOString(),
        },
        method_applied: 'NistClear',
        passes_executed: 1,
        operator_id: 'INV-4402-NITYA',
        completed_at: new Date().toISOString(),
        digital_signature: 'ED25519-SIG-88F9B0019A42C10148E',
        layers_verified: [
          'Layer 1: Controller Register Command Return Code (0x00)',
          'Layer 2: Multi-Sample Boundary LBA Read-Back',
          'Layer 3: Chi-Square Uniform Randomness & Zero Entropy',
          'Layer 4: Residual Filesystem Artifact Scanner',
          'Layer 5: Deep Recovery Sweep Carve (0 files recovered)',
        ],
      };
      return cert as unknown as T;
    }

    case 'list_reports': {
      const reports: ReportSummary[] = [
        {
          report_id: 'REP-2026-001',
          report_type: 'ForensicExamination',
          case_id: (args.caseId as string) || 'CASE-2026-001',
          title: 'Forensic Acquisition & Examination Report',
          created_at: '2026-08-16 11:20:00 UTC',
          operator_id: 'INV-4402-NITYA',
          signed: true,
          json_path: './reports/REP-2026-001.json',
          pdf_path: './reports/REP-2026-001.pdf',
        },
        {
          report_id: 'REP-2026-002',
          report_type: 'ChainOfCustody',
          case_id: (args.caseId as string) || 'CASE-2026-001',
          title: 'Evidence Vault Chain-of-Custody Ledger',
          created_at: '2026-08-16 11:25:00 UTC',
          operator_id: 'INV-4402-NITYA',
          signed: true,
          json_path: './reports/REP-2026-002.json',
        },
      ];
      return reports as unknown as T;
    }

    case 'generate_report': {
      const rep: ReportSummary = {
        report_id: 'REP-' + Math.floor(Math.random() * 10000),
        report_type: (args.reportType as ReportType) || 'ForensicExamination',
        case_id: (args.caseId as string) || 'CASE-2026-001',
        title: `${args.reportType || 'Forensic'} Report`,
        created_at: new Date().toISOString(),
        operator_id: 'INV-4402-NITYA',
        signed: true,
        json_path: './reports/generated_report.json',
        pdf_path: './reports/generated_report.pdf',
      };
      return rep as unknown as T;
    }

    case 'verify_report': {
      const res: ReportVerificationResult = {
        report_id: 'REP-2026-001',
        valid: true,
        signature_verified: true,
        audit_chain_intact: true,
        hash_matches: true,
        timestamp_verified: true,
        checks: [
          {
            check_name: 'X.509 / Ed25519 Digital Signature',
            passed: true,
            details: 'Valid signature from operator INV-4402-NITYA',
          },
          {
            check_name: 'Sequential Hash Chain Integrity',
            passed: true,
            details: 'All 42 audit links validated with zero breaks',
          },
          {
            check_name: 'Content SHA-256 Hash Verification',
            passed: true,
            details: 'Report payload matches signed cryptographic digest',
          },
          {
            check_name: 'RFC 3161 Trusted Timestamp',
            passed: true,
            details: 'Timestamped by TSA authority, valid token',
          },
        ],
      };
      return res as unknown as T;
    }

    case 'export_report_html': {
      return './reports/REP-2026-001.html' as unknown as T;
    }

    case 'run_recovery_pipeline': {
      return [
        {
          id: 1,
          recovery_method: 'Tier2Signature',
          source_locations: [[2048, 256], [4096, 128]],
          original_path: 'C:\\Users\\Suspect\\Documents\\evidence.pdf',
          filename_guess: 'evidence.pdf',
          file_type: 'pdf',
          confidence_score: 0.87,
          confidence_breakdown: {
            header_footer_integrity: 0.95,
            structural_validity: 0.92,
            metadata_cross_reference: 0.88,
            entropy_consistency: 0.79,
            entropy_explainability: 'Consistent with PDF document structure',
            fragmentation_confidence: 0.85,
            overwrite_probability: 0.82,
          },
          fragmentation_detail: null,
          recovered_bytes: 204800,
          expected_total_bytes: 204800,
          content_hash: 'a1b2c3d4e5f6a1b2c3d4e5f6a1b2c3d4e5f6a1b2c3d4e5f6a1b2c3d4e5f6a1b2',
          recovery_limitations: null,
        },
        {
          id: 2,
          recovery_method: 'Tier3Fragmented',
          source_locations: [[8192, 64], [16384, 48]],
          original_path: null,
          filename_guess: 'recovered_image_002.jpg',
          file_type: 'jpeg',
          confidence_score: 0.61,
          confidence_breakdown: {
            header_footer_integrity: 0.90,
            structural_validity: 0.70,
            metadata_cross_reference: 0.45,
            entropy_consistency: 0.65,
            entropy_explainability: null,
            fragmentation_confidence: 0.55,
            overwrite_probability: 0.42,
          },
          fragmentation_detail: {
            gap_size_sectors: 100,
            fragment_1: [8192, 64],
            fragment_2: [16384, 48],
          },
          recovered_bytes: 57344,
          expected_total_bytes: 81920,
          content_hash: 'b2c3d4e5f6a1b2c3d4e5f6a1b2c3d4e5f6a1b2c3d4e5f6a1b2c3d4e5f6a1b2c3',
          recovery_limitations: 'Fragment gap of 100 sectors reconstructed using entropy interpolation. Payload may contain corrupted regions between LBA 8256 and 16384.',
        },
        {
          id: 3,
          recovery_method: 'Tier1Metadata',
          source_locations: [[32768, 512]],
          original_path: 'C:\\Users\\Suspect\\AppData\\Local\\chat.sqlite',
          filename_guess: 'chat.sqlite',
          file_type: 'sqlite',
          confidence_score: 0.94,
          confidence_breakdown: {
            header_footer_integrity: 0.99,
            structural_validity: 0.98,
            metadata_cross_reference: 0.95,
            entropy_consistency: 0.91,
            entropy_explainability: 'SQLite magic number confirmed. Page size validated.',
            fragmentation_confidence: 0.95,
            overwrite_probability: 0.89,
          },
          fragmentation_detail: null,
          recovered_bytes: 262144,
          expected_total_bytes: 262144,
          content_hash: 'c3d4e5f6a1b2c3d4e5f6a1b2c3d4e5f6a1b2c3d4e5f6a1b2c3d4e5f6a1b2c3d4',
          recovery_limitations: null,
        },
      ] as unknown as T;
    }

    case 'read_raw_sectors': {
      const bytes = new Array(2048).fill(0).map((_, i) => {
        if (i < 4) return [0xFF, 0xD8, 0xFF, 0xE0][i];
        return Math.floor(Math.random() * 256);
      });
      return bytes as unknown as T;
    }

    case 'get_storage_map': {
      return {
        total_blocks: 3907029168,
        block_size: 512,
        allocated_ranges: [[0, 2000000000], [2500000000, 1000000000]],
        unallocated_ranges: [[2000000000, 500000000]],
        bad_sector_ranges: [[1500000000, 2000], [2800000000, 500]],
        recovered_fragment_ranges: [[8192, 256], [16384, 128], [32768, 512]],
      } as unknown as T;
    }

    default:
      return {} as T;
  }
}
