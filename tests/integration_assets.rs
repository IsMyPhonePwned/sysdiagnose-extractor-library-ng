// SPDX-License-Identifier: GPL-3.0-only

//! Run with: `cargo test --test integration_assets -- --ignored --nocapture`

use std::path::PathBuf;
use std::sync::Arc;

use sysdiagnose_extractor_library::{
    all_parser_types, parser_for, run_parsers_concurrently, ParserType, SysdiagnoseArchive,
};

fn asset_path() -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .join("assets/sysdiagnose_2026.04.07_15-01-20+0200_iPhone-OS_iPhone_23D127.tar.gz")
}

#[test]
#[ignore = "loads a large local sysdiagnose tarball from assets/"]
fn real_archive_ps_and_sys() {
    let p = asset_path();
    if !p.is_file() {
        eprintln!("skip: missing {}", p.display());
        return;
    }
    let arch = Arc::new(SysdiagnoseArchive::open_path(&p).expect("open archive"));
    let types = all_parser_types();
    let parsers: Vec<_> = types.into_iter().map(|t| (t, parser_for(t))).collect();
    let results = run_parsers_concurrently(arch, parsers);
    for (pt, res, _) in &results {
        res.as_ref()
            .unwrap_or_else(|e| panic!("parser {pt:?} failed: {e}"));
    }
    let ps = results
        .iter()
        .find(|(t, _, _)| *t == ParserType::ps)
        .unwrap()
        .1
        .as_ref()
        .unwrap();
    let rows = ps["rows"].as_array().expect("ps rows");
    assert!(rows.len() > 10, "expected many processes");

    let sys = results
        .iter()
        .find(|(t, _, _)| *t == ParserType::sys)
        .unwrap()
        .1
        .as_ref()
        .unwrap();
    assert!(
        sys["plist"].is_object() || sys["plist"].is_null(),
        "sys plist"
    );

    let taskinfo = results
        .iter()
        .find(|(t, _, _)| *t == ParserType::taskinfo)
        .unwrap()
        .1
        .as_ref()
        .unwrap();
    let events = taskinfo["events"].as_array().expect("taskinfo events");
    assert!(
        events.len() > 200,
        "expected full taskinfo parse (summary + per-process events)"
    );
    assert!(
        taskinfo["acquisition_rfc3339"].as_str().is_some(),
        "acquisition parsed from bundle folder name"
    );
}
