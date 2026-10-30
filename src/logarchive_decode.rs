// SPDX-License-Identifier: GPL-3.0-only

//! In-process unified-log decode via `mul-unifiedlog`.
//!
//! Chunks are decoded one at a time and the walk stops at `max_lines`.
//! `memory_threshold_bytes == 0` leaves the byte limit off.

use std::path::Path;

use mul_unifiedlog::decode::{decode_unit, DecodeCtx};
use mul_unifiedlog::source::LogSource;
use mul_unifiedlog::strings_cache::StringsCache;
use mul_unifiedlog::{scan_file, DirLogSource, OwnedLogEvent, TimesyncTable};
use serde_json::{json, Value};

use crate::engine::LOGARCHIVE_FORENSIC_MAX_LINES;

#[derive(Debug, thiserror::Error)]
pub enum DecodeError {
    #[error("logarchive decode failed: {0}")]
    Failed(String),
}

#[derive(Debug, Clone, Copy)]
pub struct DecodeLimits {
    pub max_lines: usize,
    /// `0` disables the byte stop.
    pub memory_threshold_bytes: u64,
}

#[derive(Debug)]
pub struct DecodedLog {
    pub events: Vec<Value>,
    pub memory_threshold_hit: bool,
    pub bytes_retained: u64,
}

pub fn decode_logarchive_dir(dir: &Path, limits: DecodeLimits) -> Result<DecodedLog, DecodeError> {
    let max_lines = if limits.max_lines == 0 || limits.max_lines > LOGARCHIVE_FORENSIC_MAX_LINES {
        LOGARCHIVE_FORENSIC_MAX_LINES
    } else {
        limits.max_lines
    };
    let threshold = limits.memory_threshold_bytes;
    let src = DirLogSource::open(dir).map_err(|e| DecodeError::Failed(e.to_string()))?;
    let mut timesync = TimesyncTable::default();
    for file in src.timesync_files() {
        if let Ok(bytes) = src.open(&file) {
            if let Ok(table) = TimesyncTable::parse(bytes.as_slice()) {
                timesync.merge(table);
            }
        }
    }
    let strings = StringsCache::new();
    let ctx = DecodeCtx {
        source: &src,
        timesync: &timesync,
        strings: &strings,
        include_signposts: false,
    };

    let mut events = Vec::new();
    let mut bytes_retained = 0u64;
    let mut memory_threshold_hit = false;

    'files: for (file_id, file) in src.tracev3_files().into_iter().enumerate() {
        let Ok(bytes) = src.open(&file) else {
            continue;
        };
        let (_stats, units, _header) = scan_file(&file, file_id as u32, bytes.as_slice())
            .map_err(|e| DecodeError::Failed(e.to_string()))?;
        for unit in units {
            if events.len() >= max_lines {
                break 'files;
            }
            let batch = match decode_unit(&ctx, &unit, bytes.as_slice()) {
                Ok(batch) => batch,
                Err(_) => continue,
            };
            for event in batch {
                if events.len() >= max_lines {
                    break 'files;
                }
                let add = retained_bytes(&event);
                if stop_for_memory(threshold, bytes_retained, add, !events.is_empty()) {
                    memory_threshold_hit = true;
                    break 'files;
                }
                bytes_retained = bytes_retained.saturating_add(add);
                events.push(owned_to_saf(&event));
            }
        }
    }

    Ok(DecodedLog {
        events,
        memory_threshold_hit,
        bytes_retained,
    })
}

/// `threshold == 0` leaves the limit off. The first event is always kept.
fn stop_for_memory(threshold: u64, bytes_retained: u64, add: u64, have_events: bool) -> bool {
    threshold > 0 && have_events && bytes_retained.saturating_add(add) > threshold
}

fn retained_bytes(row: &OwnedLogEvent) -> u64 {
    fn n(s: &Option<String>) -> u64 {
        s.as_ref().map(|text| text.len() as u64).unwrap_or(0)
    }
    // `message` is copied into the event three times.
    192 + n(&row.event_message) * 3
        + n(&row.process_image_path)
        + n(&row.sender_image_path)
        + n(&row.subsystem)
        + n(&row.category)
        + n(&row.event_type)
        + n(&row.message_type)
        + n(&row.timestamp) * 2
}

fn owned_to_saf(row: &OwnedLogEvent) -> Value {
    let message = row.event_message.clone().unwrap_or_default();
    let process = row
        .process_image_path
        .as_deref()
        .and_then(|p| p.rsplit('/').next())
        .unwrap_or("")
        .to_string();
    let event_type = row.event_type.clone().unwrap_or_default();
    let log_type = row.message_type.clone().unwrap_or_default();
    json!({
        "datetime": row.timestamp.clone().unwrap_or_default(),
        "message": message,
        "timestamp_desc": "unified log",
        "module": "logarchive",
        "data": {
            "process": process,
            "pid": row.process_id,
            "subsystem": row.subsystem,
            "category": row.category,
            "library": row.sender_image_path,
            "event_type": event_type,
            "log_type": log_type,
            "eventType": row.event_type,
            "eventMessage": row.event_message,
            "message": row.event_message,
            "threadID": row.thread_id,
            "timestamp": row.timestamp,
            "evidence": Value::Null,
        }
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn memory_threshold_zero_never_stops() {
        assert!(!stop_for_memory(0, 0, 10_000, false));
        assert!(!stop_for_memory(0, 1_000, 10_000, true));
    }

    #[test]
    fn memory_threshold_keeps_the_first_event() {
        assert!(!stop_for_memory(32, 0, 1_000, false));
    }

    #[test]
    fn memory_threshold_stops_before_the_next_event_crosses_it() {
        assert!(!stop_for_memory(100, 40, 60, true));
        assert!(stop_for_memory(100, 40, 61, true));
        assert!(stop_for_memory(100, 100, 1, true));
    }

    #[test]
    fn empty_logarchive_decodes_without_tripping_the_threshold() {
        let dir = tempfile::tempdir().unwrap();
        let decoded = decode_logarchive_dir(
            dir.path(),
            DecodeLimits {
                max_lines: 0,
                memory_threshold_bytes: 1,
            },
        )
        .unwrap();
        assert!(decoded.events.is_empty());
        assert!(!decoded.memory_threshold_hit);
        assert_eq!(decoded.bytes_retained, 0);
    }
}
