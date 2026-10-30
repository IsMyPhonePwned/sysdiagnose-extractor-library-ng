// SPDX-License-Identifier: GPL-3.0-only

use std::sync::Arc;
use std::time::Duration;

use crate::error::BoxErr;
use crate::parsers::SysdiagnoseParser;
use crate::parser_type::ParserType;
use crate::archive::SysdiagnoseArchive;
use serde_json::Value;

/// Highest unified-log line count either CLI will decode. `0` means this value.
pub const LOGARCHIVE_FORENSIC_MAX_LINES: usize = 250_000;

/// Knobs that change parser output shape.
#[derive(Debug, Clone)]
pub struct ParseOptions {
    pub ioservice_full_tree: bool,
    pub logarchive_decode_max_lines: usize,
    /// Stop the unified-log decode once retained event bytes reach this size.
    /// `0` leaves the limit off.
    pub logarchive_memory_threshold: u64,
    pub logarchive_inventory_only: bool,
}

impl Default for ParseOptions {
    fn default() -> Self {
        Self {
            ioservice_full_tree: false,
            logarchive_decode_max_lines: crate::parsers::default_logarchive_max_lines(),
            logarchive_memory_threshold: logarchive_memory_threshold_from_env(),
            logarchive_inventory_only: false,
        }
    }
}

fn logarchive_memory_threshold_from_env() -> u64 {
    std::env::var("SYSDIAGNOSE_LOGARCHIVE_MEMORY_THRESHOLD")
        .ok()
        .and_then(|s| s.parse().ok())
        .unwrap_or(0)
}

fn elapsed_since(start: std::time::Instant) -> Duration {
    #[cfg(not(target_arch = "wasm32"))]
    {
        start.elapsed()
    }
    #[cfg(target_arch = "wasm32")]
    {
        let _ = start;
        Duration::ZERO
    }
}

pub fn run_parsers_concurrently(
    archive: Arc<SysdiagnoseArchive>,
    parsers: Vec<(ParserType, Box<dyn SysdiagnoseParser>)>,
) -> Vec<(ParserType, Result<Value, BoxErr>, Duration)> {
    #[cfg(not(target_arch = "wasm32"))]
    {
        use rayon::prelude::*;
        parsers
            .into_par_iter()
            .map(|(ty, parser)| run_one(archive.clone(), ty, parser))
            .collect()
    }
    #[cfg(target_arch = "wasm32")]
    {
        parsers
            .into_iter()
            .map(|(ty, parser)| run_one(archive.clone(), ty, parser))
            .collect()
    }
}

fn run_one(
    archive: Arc<SysdiagnoseArchive>,
    ty: ParserType,
    parser: Box<dyn SysdiagnoseParser>,
) -> (ParserType, Result<Value, BoxErr>, Duration) {
    #[cfg(not(target_arch = "wasm32"))]
    let start = std::time::Instant::now();
    #[cfg(target_arch = "wasm32")]
    let start = {
        // Instant::now panics on wasm32-unknown-unknown in some runtimes.
        std::time::Instant::now()
    };
    let result = parser.parse(&archive);
    let dur = elapsed_since(start);
    (ty, result, dur)
}
