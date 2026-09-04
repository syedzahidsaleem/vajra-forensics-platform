pub mod commands;
pub mod state;

#[cfg_attr(mobile, tauri::mobile_entry_point)]
pub fn run() {
    tauri::Builder::default()
        .setup(|app| {
            if cfg!(debug_assertions) {
                app.handle().plugin(
                    tauri_plugin_log::Builder::default()
                        .level(log::LevelFilter::Info)
                        .build(),
                )?;
            }
            Ok(())
        })
        .invoke_handler(tauri::generate_handler![
            // Device layer
            commands::devices::list_devices,
            commands::devices::get_device_fingerprint,
            commands::devices::get_device_health,
            // Evidence Vault & Cases
            commands::cases::list_cases,
            commands::cases::create_case,
            commands::cases::close_case,
            commands::cases::list_evidence,
            commands::cases::add_evidence,
            commands::cases::get_custody_history,
            // Acquisition
            commands::acquire::start_acquisition,
            commands::acquire::get_acquisition_progress,
            commands::acquire::list_acquisition_checkpoints,
            commands::acquire::resume_acquisition,
            // Sanitization
            commands::sanitize::get_sanitization_recommendation,
            commands::sanitize::begin_sanitization_gate,
            commands::sanitize::finalize_sanitization_gate,
            commands::sanitize::execute_sanitization,
            commands::sanitize::sanitize_file,
            commands::sanitize::sanitize_unallocated_slack,
            // Reports & Independent Verifier
            commands::reports::list_reports,
            commands::reports::generate_report,
            commands::reports::verify_report,
            commands::reports::export_report_html,
        ])
        .run(tauri::generate_context!())
        .expect("error while running tauri application");
}
