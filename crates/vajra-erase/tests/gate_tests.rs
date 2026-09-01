//! Automated Tests for Device Identity Confirmation Gate (§43).

use vajra_core::media_type::MediaType;
use vajra_core::write_blocker::WriteBlockerMetadata;
use vajra_device::DeviceDescriptor;
use vajra_erase::gate::DeviceConfirmationGate;
use vajra_erase::error::GateError;

fn create_mock_descriptor(is_system: bool, has_write_blocker: bool) -> DeviceDescriptor {
    DeviceDescriptor {
        path: "/dev/mock_disk_eval".to_string(),
        device_index: 0,
        manufacturer: "Micron".to_string(),
        model: "7450_PRO".to_string(),
        serial: "MICRON-SN-778899".to_string(),
        capacity_bytes: 960_000_000_000,
        logical_block_size: 512,
        physical_block_size: 4096,
        media_type: MediaType::Nvme,
        interface: "NVMe".to_string(),
        partition_table: "GPT".to_string(),
        is_system_disk: is_system,
        is_read_only: false,
        is_write_blocked: has_write_blocker,
        write_blocker_info: if has_write_blocker {
            Some(WriteBlockerMetadata::from_vid_pid("Tableau", "T8u Forensic Bridge", 0x0E55, 0x0200))
        } else {
            None
        },
        boundary_sample: vec![0u8; 512],
    }
}

#[test]
fn test_system_disk_unconditional_hard_refusal() {
    let dev = create_mock_descriptor(true, false);
    let result = DeviceConfirmationGate::begin(&dev, "operator_1", "MICRON-SN-778899", true);
    assert!(matches!(result, Err(GateError::SystemDiskRefusal(_))));
}

#[test]
fn test_write_blocker_unconditional_refusal() {
    let dev = create_mock_descriptor(false, true);
    let result = DeviceConfirmationGate::begin(&dev, "operator_1", "MICRON-SN-778899", true);
    assert!(matches!(result, Err(GateError::WriteBlockerRefusal(_))));
}

#[test]
fn test_serial_mismatch_refusal() {
    let dev = create_mock_descriptor(false, false);
    let result = DeviceConfirmationGate::begin(&dev, "operator_1", "WRONG_SERIAL", true);
    assert!(matches!(result, Err(GateError::SerialMismatch { .. })));
}

#[test]
fn test_temporal_separation_enforcement() {
    let dev = create_mock_descriptor(false, false);

    // Step 1: Must call begin() to get PendingSanitization
    let pending = DeviceConfirmationGate::begin(&dev, "operator_1", "MICRON-SN-778899", true)
        .expect("begin() must succeed with matching serial and initial confirm");

    // Step 2: Finalize requires pre-execution reconfirmation
    let token = pending.finalize(true).expect("finalize() must yield SanitizationAuthorizationToken");
    assert_eq!(token.target_serial(), "MICRON-SN-778899");
    assert_eq!(token.operator_id(), "operator_1");
}

#[test]
fn test_gate_bypass_resistance_single_call_impossibility() {
    let dev = create_mock_descriptor(false, false);

    // 1. Initial confirmation rejected -> no PendingSanitization ticket
    let res_init_rejected = DeviceConfirmationGate::begin(&dev, "operator_1", "MICRON-SN-778899", false);
    assert!(matches!(res_init_rejected, Err(GateError::InitialConfirmationRejected)));

    // 2. Pre-execution reconfirmation rejected -> PendingSanitization consumed, no SanitizationAuthorizationToken
    let pending = DeviceConfirmationGate::begin(&dev, "operator_1", "MICRON-SN-778899", true).unwrap();
    let res_pre_rejected = pending.finalize(false);
    assert!(matches!(res_pre_rejected, Err(GateError::PreExecConfirmationRejected)));

    // 3. Confirm that DeviceConfirmationGate exposes NO single-step method to obtain a token
    // (Enforced at type-level: DeviceConfirmationGate only has begin(), and PendingSanitization::finalize() consumes self)
}
