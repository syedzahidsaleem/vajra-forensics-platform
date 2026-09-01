//! Module 1: NIST SP 800-88 / IEEE 2883 Media Sanitization Engine (§33a–§38, §43).
//!
//! Provides the unbypassable device identity confirmation gate (§43), the Sanitization
//! Decision Engine (§34), multi-layer verification with recovery-based Layer 5 override (§37),
//! and cryptographically signed Sanitization Certificates (§38).

pub mod certificate;
pub mod decision_engine;
pub mod error;
pub mod gate;
pub mod methods;
pub mod mock;
pub mod verify;

pub use certificate::SanitizationCertificate;
pub use decision_engine::{SanitizationDecisionEngine, SanitizationRecommendation};
pub use error::{EraseError, GateError};
pub use gate::{DeviceConfirmationGate, PendingSanitization, SanitizationAuthorizationToken};
pub use methods::execute_sanitization_destructive;
pub use mock::MockWritableDevice;
pub use verify::{
    verify_sanitization, MultiLayerVerificationReport, OverallAssurance,
};

#[cfg(test)]
mod tests {
    use super::*;
    use vajra_core::media_type::MediaType;
    use vajra_core::sanitize::SanitizeMethod;
    use vajra_device::DeviceDescriptor;

    fn make_test_device(is_system: bool, serial: &str) -> DeviceDescriptor {
        DeviceDescriptor {
            path: "/dev/mock_disk0".to_string(),
            device_index: 0,
            manufacturer: "Samsung".to_string(),
            model: "PM9A3".to_string(),
            serial: serial.to_string(),
            capacity_bytes: 1_920_000_000_000,
            logical_block_size: 512,
            physical_block_size: 4096,
            media_type: MediaType::Nvme,
            interface: "NVMe".to_string(),
            partition_table: "GPT".to_string(),
            is_system_disk: is_system,
            is_read_only: false,
            is_write_blocked: false,
            write_blocker_info: None,
            boundary_sample: vec![0u8; 512],
        }
    }

    #[test]
    fn test_gate_system_disk_hard_refusal() {
        let dev = make_test_device(true, "SN-SYS-12345");
        let res = DeviceConfirmationGate::begin(&dev, "operator_1", "SN-SYS-12345", true);
        assert!(matches!(res, Err(GateError::SystemDiskRefusal(_))));
    }

    #[test]
    fn test_gate_serial_mismatch_refusal() {
        let dev = make_test_device(false, "SN-TARGET-9988");
        let res = DeviceConfirmationGate::begin(&dev, "operator_1", "SN-WRONG-SERIAL", true);
        assert!(matches!(res, Err(GateError::SerialMismatch { .. })));
    }

    #[test]
    fn test_gate_two_phase_token_issuance() {
        let dev = make_test_device(false, "SN-TARGET-9988");

        // Phase 1
        let pending = DeviceConfirmationGate::begin(&dev, "operator_1", "SN-TARGET-9988", true)
            .expect("Phase 1 must succeed");

        // Phase 2 rejected
        // Note: we test that pre_exec_confirm = false fails
        let dev2 = make_test_device(false, "SN-TARGET-9988");
        let pending2 = DeviceConfirmationGate::begin(&dev2, "operator_1", "SN-TARGET-9988", true).unwrap();
        assert!(matches!(pending2.finalize(false), Err(GateError::PreExecConfirmationRejected)));

        // Phase 2 accepted -> Token issued
        let token = pending.finalize(true).expect("Phase 2 must issue token");
        assert_eq!(token.target_serial(), "SN-TARGET-9988");
        assert_eq!(token.operator_id(), "operator_1");
    }

    #[test]
    fn test_decision_engine_nvme_recommendation() {
        let dev = make_test_device(false, "SN-NVME-001");
        let supported = vec![SanitizeMethod::NvmeSanitizeBlock, SanitizeMethod::HostOverwriteSinglePass];
        let rec = SanitizationDecisionEngine::recommend(&dev, &supported);

        assert_eq!(rec.recommended_method, SanitizeMethod::NvmeSanitizeBlock);
        assert!(rec.render_display().contains("RECOMMENDED SANITIZATION"));
        assert!(rec.render_display().contains("NVMe controller-native Sanitize command"));
    }
}
