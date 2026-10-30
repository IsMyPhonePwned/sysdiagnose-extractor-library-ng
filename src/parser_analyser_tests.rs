// SPDX-License-Identifier: GPL-3.0-only

use crate::parser_for;
use crate::ParserType;
use crate::SysdiagnoseArchive;
use std::collections::HashMap;
use std::sync::Arc;
use strum::IntoEnumIterator;

fn minimal_archive() -> SysdiagnoseArchive {
    let mut m = HashMap::new();
    m.insert("dummy.txt".to_string(), Arc::from(&b"x"[..]));
    SysdiagnoseArchive::from_files_for_test(m)
}

#[test]
fn every_parser_runs_ok_on_minimal_archive() {
    let arch = minimal_archive();
    let mut failed = Vec::new();
    for pt in ParserType::iter() {
        if let Err(e) = parser_for(pt).parse(&arch) {
            failed.push(format!("{} ({:?}): {e}", pt.as_str(), pt));
        }
    }
    assert!(
        failed.is_empty(),
        "parsers failed on minimal archive:\n{}",
        failed.join("\n")
    );
}

#[test]
fn parser_type_enum_iter_matches_expected_count() {
    assert_eq!(ParserType::iter().count(), 67);
}

#[test]
fn parser_for_covers_every_parser_type() {
    for pt in ParserType::iter() {
        let _ = parser_for(pt);
    }
}

#[test]
fn every_parser_as_str_roundtrips_via_from_str() {
    for pt in ParserType::iter() {
        let s = pt.as_str();
        let parsed: ParserType = s.parse().unwrap_or_else(|e| panic!("{s}: {e}"));
        assert_eq!(parsed, pt, "FromStr mismatch for {s}");
        assert!(!pt.description().is_empty(), "{s} has empty description");
    }
}
