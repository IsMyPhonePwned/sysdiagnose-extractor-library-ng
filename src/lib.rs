// SPDX-License-Identifier: GPL-3.0-only

//! Low-memory, parallel parser for Apple sysdiagnose archives.
//!
//! The compat API returns `serde_json::Value` so existing callers and tests
//! keep working. Archive members are retained on demand (mmap slices, small
//! owned buffers, or spilled files) instead of a single map of every payload.

pub mod archive;
pub mod error;
pub mod glob_match;
pub mod parsers;
pub mod sink;
pub mod sqlite_dump;
pub mod tab_hierarchy;
pub mod util;

mod engine;
#[cfg(feature = "logarchive-decode")]
mod logarchive_decode;
mod parser_type;
mod plan;

#[cfg(test)]
mod parser_analyser_tests;

pub use archive::{
    is_xz_prefix, parse_bundle_acquisition, sysdiagnose_creation, ArchiveOptions, ArchiveStats,
    RetentionPlan, SysdiagnoseArchive,
};
pub use engine::{run_parsers_concurrently, ParseOptions};
pub use plan::retention_plan;
pub use error::{ArchiveError, BoxErr};
pub use parser_type::{all_parser_types, ParserType};
pub use parsers::{parser_for, parser_for_with_options, SysdiagnoseParser};
pub use sink::{parse_into_sink, EventSink, ValueSink};
pub use util::{
    enrich_mobile_installation_event, enrich_ps_process_row, exclude_known_goods,
    looks_like_app_version, looks_like_cpu_time, normalize_process_path, parse_mobile_install_versions,
    parse_process_identity, peel_leading_cpu_time, process_short_name, snake_case,
    split_process_command, strip_process_name_quotes, MobileInstallVersions,
};

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::Arc;

    #[test]
    fn run_core_parsers_on_minimal_archive() {
        use std::collections::HashMap;
        let mut m = HashMap::new();
        let ps_bytes: Vec<u8> = b"USER PID\n1 1\n".to_vec();
        m.insert("ps.txt".to_string(), Arc::from(ps_bytes.into_boxed_slice()));
        let arch = Arc::new(SysdiagnoseArchive::from_files_for_test(m));
        let parsers: Vec<_> = [ParserType::ps, ParserType::sys, ParserType::taskinfo]
            .into_iter()
            .map(|t| (t, parser_for(t)))
            .collect();
        let results = run_parsers_concurrently(arch, parsers);
        assert_eq!(results.len(), 3);
    }

    #[test]
    fn all_parser_types_count_is_67() {
        assert_eq!(all_parser_types().len(), 67);
    }

    #[test]
    fn logarchive_line_cap_zero_and_huge_clamp_to_forensic_max() {
        use crate::parsers::clamp_logarchive_decode_max_lines;
        assert_eq!(clamp_logarchive_decode_max_lines(0), 250_000);
        assert_eq!(clamp_logarchive_decode_max_lines(usize::MAX), 250_000);
        assert_eq!(clamp_logarchive_decode_max_lines(2500), 2500);
        assert_eq!(clamp_logarchive_decode_max_lines(250_000), 250_000);
    }

    #[test]
    fn logarchive_memory_threshold_defaults_off() {
        if std::env::var_os("SYSDIAGNOSE_LOGARCHIVE_MEMORY_THRESHOLD").is_some() {
            return;
        }
        assert_eq!(ParseOptions::default().logarchive_memory_threshold, 0);
    }
}
