// Polyfill for Tauri IPC in web browser dev environment
if (typeof window !== 'undefined' && !(window as any).__TAURI_IPC__) {
  (window as any).__TAURI_IPC__ = async (message: any) => {
    const cmd = message?.cmd || message;
    console.log('[Mock Tauri IPC]', cmd, message);
    return handleMockCommand(cmd, message);
  };
}

export function handleMockCommand(cmd: string, args: any): any {
  switch (cmd) {
    case 'get_storage_map':
      return Promise.resolve({
        total_blocks: 2097152, // 1 GB drive space (2097152 * 512 sectors)
        block_size: 512,
        allocated_ranges: [
          [0, 104857],
          [209715, 314572],
          [629145, 419430],
          [1258291, 524288],
        ],
        unallocated_ranges: [
          [104857, 104858],
          [524287, 104858],
          [1048575, 209716],
          [1782579, 314573],
        ],
        bad_sector_ranges: [
          [150000, 128],
          [800000, 256],
          [1850000, 64],
        ],
        recovered_fragment_ranges: [
          [250000, 4096],
          [700000, 8192],
          [1350000, 16384],
        ],
      });

    case 'run_recovery_pipeline':
      return Promise.resolve([
        {
          id: 101,
          recovery_method: 'Tier1Metadata',
          source_locations: [[250000, 4096]],
          original_path: '/Documents/SecretKey.docx',
          filename_guess: 'SecretKey.docx',
          file_type: 'DOCX',
          confidence_score: 0.95,
          confidence_breakdown: {
            header_footer_integrity: 1.0,
            structural_validity: 0.9,
            metadata_cross_reference: 1.0,
            entropy_consistency: 0.9,
            entropy_explainability: 'Valid document entropy',
            fragmentation_confidence: 1.0,
            overwrite_probability: 0.0,
          },
          fragmentation_detail: null,
          recovered_bytes: 2097152,
          expected_total_bytes: 2097152,
          content_hash: 'e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855',
          recovery_limitations: null,
        },
        {
          id: 102,
          recovery_method: 'Tier3Fragmented',
          source_locations: [[700000, 4096], [1350000, 12288]],
          original_path: '/Photos/Evidence.jpg',
          filename_guess: 'Evidence_Fragmented.jpg',
          file_type: 'JPEG',
          confidence_score: 0.82,
          confidence_breakdown: {
            header_footer_integrity: 0.95,
            structural_validity: 0.8,
            metadata_cross_reference: 0.7,
            entropy_consistency: 0.85,
            entropy_explainability: 'JPEG stream entropy matched across gap',
            fragmentation_confidence: 0.75,
            overwrite_probability: 0.05,
          },
          fragmentation_detail: {
            gap_size_sectors: 645904,
            fragment_1: [700000, 4096],
            fragment_2: [1350000, 12288],
          },
          recovered_bytes: 8388608,
          expected_total_bytes: 8388608,
          content_hash: '9f86d081884c7d659a2feaa0c55ad015a3bf4f1b2b0b822cd15d6c15b0f00a08',
          recovery_limitations: 'Discontiguous 2-extent fragment reassembled',
        },
      ]);

    case 'read_raw_sectors':
      const bytes = new Array(512 * (args?.block_count || 1)).fill(0);
      return Promise.resolve(bytes);

    default:
      return Promise.resolve(null);
  }
}
