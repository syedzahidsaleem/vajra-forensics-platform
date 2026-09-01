//! vajra-verify CLI binary (§42).
//!
//! Minimal standalone verification tool for third-party auditing of .vjr reports.

use std::env;
use std::path::Path;
use std::process;
use vajra_verify::verify_report_file;

fn print_usage() {
    println!("Vajra Independent Report Verifier (§42)\n");
    println!("USAGE:");
    println!("  vajra-verify <REPORT_FILE.vjr> [--evidence <EVIDENCE_PATH>]\n");
    println!("ARGUMENTS:");
    println!("  <REPORT_FILE.vjr>       Path to signed Vajra report package (.vjr)");
    println!("  --evidence <PATH>       Optional: Path to raw evidence image for hash validation\n");
    println!("EXAMPLES:");
    println!("  vajra-verify forensic_exam_report.vjr");
    println!("  vajra-verify acquisition_report.vjr --evidence /evidence/case01_disk.raw\n");
}

fn main() {
    let args: Vec<String> = env::args().collect();
    if args.len() < 2 || args[1] == "-h" || args[1] == "--help" {
        print_usage();
        process::exit(1);
    }

    let report_path_str = &args[1];
    let mut evidence_path_str: Option<&String> = None;

    let mut i = 2;
    while i < args.len() {
        if args[i] == "--evidence" && i + 1 < args.len() {
            evidence_path_str = Some(&args[i + 1]);
            i += 2;
        } else {
            i += 1;
        }
    }

    let report_path = Path::new(report_path_str);
    if !report_path.exists() {
        eprintln!("[-] Error: Report file '{}' does not exist.", report_path_str);
        process::exit(1);
    }

    let ev_path = evidence_path_str.map(Path::new);

    match verify_report_file(report_path, ev_path) {
        Ok(report) => {
            println!("{}", report.format_summary());
            if report.overall_valid {
                process::exit(0);
            } else {
                process::exit(1);
            }
        }
        Err(e) => {
            eprintln!("[-] Fatal Error during verification: {}", e);
            process::exit(1);
        }
    }
}
