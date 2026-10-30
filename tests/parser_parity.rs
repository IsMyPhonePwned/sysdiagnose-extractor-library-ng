// SPDX-License-Identifier: GPL-3.0-only

//! Fixture-based parity smoke tests for parsers touched in the Phase 0 / parity program.
//!
//! Full archive diffs against upstream Python live in `sysdiagnose_testdata` when
//! `SYSDIAGNOSE_TESTDATA` is configured; these tests always run on minimal in-memory archives.

use std::collections::HashMap;
use std::sync::Arc;

use serde_json::{json, Value};
use sysdiagnose_extractor_library::{
    parser_for, ParserType, SysdiagnoseArchive,
};

const IOREG_FIXTURE: &str = include_str!("../testdata/fixtures/ioreg_basic.txt");

fn arch_with(files: HashMap<String, Arc<[u8]>>) -> SysdiagnoseArchive {
    SysdiagnoseArchive::from_files_for_test(files)
}

#[test]
fn parity_ioreg_tree_has_class_keys() {
    let mut m = HashMap::new();
    m.insert(
        "ioreg/IOACPIPlane.txt".into(),
        Arc::from(IOREG_FIXTURE.as_bytes().to_vec().into_boxed_slice()),
    );
    let arch = arch_with(m);
    let v = parser_for(ParserType::ioacpiplane).parse(&arch).unwrap();
    assert_eq!(v["parser"], "ioacpiplane");
    assert_eq!(v["tree"]["class"], json!("test1"));
}

#[test]
fn parity_brctl_structured_data() {
    let mut m = HashMap::new();
    m.insert(
        "brctl/brctl-container-list.txt".into(),
        Arc::from(
            b"id: com.example.app localizedName: App documents: Mobile Documents clients: [x]"
                .to_vec()
                .into_boxed_slice(),
        ),
    );
    m.insert(
        "brctl/brctl-dump.txt".into(),
        Arc::from(
            b"dump header\n-----------------------------------------------------\n"
                .to_vec()
                .into_boxed_slice(),
        ),
    );
    let v = parser_for(ParserType::brctl).parse(&arch_with(m)).unwrap();
    assert_eq!(v["parser"], "brctl");
    let containers = v["data"]["containers"].as_array().unwrap();
    assert_eq!(containers[0]["id"], "com.example.app");
}

#[test]
fn parity_wifinetworks_basename_files_and_jsonl() {
    let mut m = HashMap::new();
    m.insert(
        "WiFi/com.apple.wifi.known-networks.plist".into(),
        Arc::from(
            br#"<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN" "http://www.apple.com/DTDs/PropertyList-1.0.dtd">
<plist version="1.0"><dict><key>n1</key><dict><key>SSID</key><string>Net</string></dict></dict></plist>"#
                .to_vec()
                .into_boxed_slice(),
        ),
    );
    let v = parser_for(ParserType::wifinetworks)
        .parse(&arch_with(m))
        .unwrap();
    assert_eq!(v["format"], "jsonl");
    assert!(v["files"]["com.apple.wifi.known-networks"].is_object());
    assert!(!v["events"].as_array().unwrap().is_empty());
}

#[test]
fn parity_wrap_jsonl_required_fields_on_wifinetworks() {
    const FIELDS: &[&str] = &["message", "datetime", "timestamp_desc", "module"];
    let mut m = HashMap::new();
    m.insert(
        "WiFi/foo.plist".into(),
        Arc::from(
            br#"<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN" "http://www.apple.com/DTDs/PropertyList-1.0.dtd">
<plist version="1.0"><dict><key>k</key><dict><key>SSID</key><string>X</string></dict></dict></plist>"#
                .to_vec()
                .into_boxed_slice(),
        ),
    );
    let v = parser_for(ParserType::wifinetworks)
        .parse(&arch_with(m))
        .unwrap();
    for ev in v["events"].as_array().unwrap() {
        let ev: &Value = ev;
        for f in FIELDS {
            assert!(ev.get(*f).and_then(|x| x.as_str()).is_some(), "missing {f}");
        }
    }
}

#[test]
fn parity_plists_meta_and_parse_failure() {
    let mut m = HashMap::new();
    m.insert(
        "ok.plist".into(),
        Arc::from(
            br#"<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN" "http://www.apple.com/DTDs/PropertyList-1.0.dtd">
<plist version="1.0"><dict><key>k</key><string>v</string></dict></plist>"#
                .to_vec()
                .into_boxed_slice(),
        ),
    );
    m.insert(
        "bad.plist".into(),
        Arc::from(b"not a plist".to_vec().into_boxed_slice()),
    );
    let v = parser_for(ParserType::plists)
        .parse(&arch_with(m))
        .unwrap();
    assert_eq!(v["parser"], "plists");
    assert_eq!(v["files"]["ok.plist"]["k"], "v");
    assert_eq!(v["files"]["bad.plist"], json!({}));
    assert!(!v["meta"]["parse_failures"].as_array().unwrap().is_empty());
}

#[test]
fn parity_itunesstore_data_shape() {
    let path = tempfile::NamedTempFile::new().unwrap();
    let conn = rusqlite::Connection::open(path.path()).unwrap();
    conn.execute_batch(
        "CREATE TABLE download (bundle_id TEXT);
         INSERT INTO download VALUES ('com.parity.app');",
    )
    .unwrap();
    let bytes = std::fs::read(path.path()).unwrap();
    let mut m = HashMap::new();
    m.insert(
        "logs/itunesstored/downloads.1.sqlitedb".into(),
        Arc::from(bytes.into_boxed_slice()),
    );
    let v = parser_for(ParserType::itunesstore)
        .parse(&arch_with(m))
        .unwrap();
    assert_eq!(v["data"]["download"][0]["bundle_id"], "com.parity.app");
}

#[test]
fn parity_remotectl_golden_fixture() {
    let mut m = HashMap::new();
    m.insert(
        "remotectl_dumpstate.txt".into(),
        Arc::from(
            include_bytes!("../testdata/fixtures/remotectl_dumpstate_golden.txt").to_vec()
                .into_boxed_slice(),
        ),
    );
    let v = parser_for(ParserType::remotectl_dumpstate)
        .parse(&arch_with(m))
        .unwrap();
    assert_eq!(
        v["data"]["Device"]["OSVersion"].as_str(),
        Some("17.2.1")
    );
}

#[test]
fn parity_logarchive_inventory_without_decode() {
    let mut m = HashMap::new();
    m.insert(
        "system_logs.logarchive/Info.plist".into(),
        Arc::from(b"plist".to_vec().into_boxed_slice()),
    );
    let v = parser_for(ParserType::logarchive)
        .parse(&arch_with(m))
        .unwrap();
    assert_eq!(v["inventory"]["paths"].as_array().unwrap().len(), 1);
    #[cfg(not(feature = "logarchive-decode"))]
    assert_eq!(v["decode"], "deferred");
}
