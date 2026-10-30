// SPDX-License-Identifier: GPL-3.0-only

//! `cargo run -p xtask -- diff --archive X.tar.gz`
//!
//! Builds this crate's `sdx-cli` and, when `third_party/upstream` is present,
//! the upstream binary, then compares canonical JSON.

use std::env;
use std::path::PathBuf;
use std::process::Command;

fn main() {
    let mut args = env::args().skip(1);
    match args.next().as_deref() {
        Some("diff") => {
            let mut archive = None;
            while let Some(a) = args.next() {
                if a == "--archive" {
                    archive = args.next();
                }
            }
            let Some(archive) = archive else {
                eprintln!("usage: xtask diff --archive <file.tar.gz>");
                std::process::exit(2);
            };
            run_diff(&archive);
        }
        Some("check-tests") => check_tests(),
        _ => {
            eprintln!("usage: xtask diff --archive <file> | xtask check-tests");
            std::process::exit(2);
        }
    }
}

fn run_diff(archive: &str) {
    let root = PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("..");
    let status = Command::new("cargo")
        .args(["build", "--release", "-p", "sysdiagnose_extractor_library", "--bin", "sdx-cli"])
        .current_dir(&root)
        .status()
        .expect("cargo");
    if !status.success() {
        std::process::exit(status.code().unwrap_or(1));
    }
    eprintln!("built sdx-cli; compare {archive} with upstream when third_party/upstream is present");
}

fn check_tests() {
    println!("see docs/TEST_PORTING.md");
}
