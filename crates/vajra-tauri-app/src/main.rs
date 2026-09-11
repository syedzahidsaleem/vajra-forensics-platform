//! Tauri shell, IPC commands, Safety/Policy Engine enforcement (§13, §43a).
#![cfg_attr(not(debug_assertions), windows_subsystem = "windows")]

fn main() {
    vajra_tauri_app::run();
}
