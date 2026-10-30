// SPDX-License-Identifier: GPL-3.0-only
//! Structured extractors for parsers that previously returned raw `files` bundles.

use chrono::{DateTime, FixedOffset};
use regex::Regex;
use serde_json::{json, Map, Value};
use std::collections::BTreeSet;
use std::sync::OnceLock;

use crate::archive::SysdiagnoseArchive;
use crate::error::BoxErr;
use crate::parsers::parser_events::{event, wrap_jsonl};
use crate::parsers::{matched_paths, MAX_UTF8_FILE};

fn creation(archive: &SysdiagnoseArchive) -> DateTime<FixedOffset> {
    crate::archive::sysdiagnose_creation(archive)
}

fn text_files(archive: &SysdiagnoseArchive, globs: &[&str], cap: usize) -> (Map<String, Value>, usize) {
    let paths = matched_paths(archive, globs);
    let total = paths.len();
    let mut files = Map::new();
    for path in paths.into_iter().take(cap) {
        let Some(bytes) = archive.get(&path) else {
            continue;
        };
        if bytes.len() > MAX_UTF8_FILE {
            continue;
        }
        files.insert(path, Value::String(String::from_utf8_lossy(bytes).into_owned()));
    }
    (files, total)
}

/// Bluetooth / AWDL status text → summary + device rows.
pub fn parse_bluetooth(archive: &SysdiagnoseArchive) -> Result<Value, BoxErr> {
    let globs = [
        "WiFi/bluetooth_status.txt",
        "WiFi/awdl_status.txt",
        "logs/Bluetooth/**",
        "logs/NetworkRelay/companion_link_status*.txt",
    ];
    let ts = creation(archive);
    let (files, total) = text_files(archive, &globs, 128);
    let mut events = Vec::new();
    let mut devices = Vec::new();
    let mut summary = Map::new();

    for (path, val) in &files {
        let Some(text) = val.as_str() else {
            continue;
        };
        for line in text.lines() {
            let line = line.trim();
            if let Some((k, v)) = line.split_once(':') {
                let k = k.trim();
                let v = v.trim();
                if matches!(
                    k,
                    "Power" | "MAC Address" | "Discoverable" | "Connectable" | "Scanning" | "Devices"
                ) {
                    summary.insert(k.to_ascii_lowercase().replace(' ', "_"), json!(v));
                }
            }
            // Paired device blocks often look like: "Name : Foo" near an address line.
            if line.to_ascii_lowercase().starts_with("name") && line.contains(':') {
                if let Some((_, name)) = line.split_once(':') {
                    let name = name.trim();
                    if !name.is_empty() && name != "Not Available" {
                        devices.push(json!({ "name": name, "source": path }));
                    }
                }
            }
            static ADDR_LABEL: OnceLock<Regex> = OnceLock::new();
            static MAC_RE: OnceLock<Regex> = OnceLock::new();
            let addr_label = ADDR_LABEL.get_or_init(|| {
                Regex::new(r"(?i)(bd[_\s-]?addr|address|mac)\s*[:=]").unwrap()
            });
            let mac_re = MAC_RE
                .get_or_init(|| Regex::new(r"([0-9A-Fa-f]{2}(?::[0-9A-Fa-f]{2}){5})").unwrap());
            if line.contains(':') && addr_label.is_match(line) {
                if let Some(addr) = mac_re.find(line).map(|m| m.as_str().to_string()) {
                    devices.push(json!({ "address": addr, "source": path, "line": line }));
                }
            }
        }
        events.push(event(
            "bluetooth",
            ts,
            format!("bluetooth status {path}"),
            "bluetooth",
            json!({ "path": path, "char_count": text.len() }),
        ));
    }

    let mut doc = wrap_jsonl("bluetooth", events);
    if let Some(obj) = doc.as_object_mut() {
        obj.insert("format".into(), json!("structured"));
        obj.insert("summary".into(), Value::Object(summary));
        obj.insert("devices".into(), json!(devices));
        obj.insert("files".into(), Value::Object(files));
        obj.insert(
            "meta".into(),
            json!({ "total_matched": total, "returned": obj.get("files").and_then(|f| f.as_object()).map(|m| m.len()).unwrap_or(0) }),
        );
    }
    Ok(doc)
}

/// RunningBoard_state.log → domain / assertion / grant inventory.
pub fn parse_runningboard(archive: &SysdiagnoseArchive) -> Result<Value, BoxErr> {
    let globs = ["RunningBoard/RunningBoard_state.log"];
    let ts = creation(archive);
    let (files, total) = text_files(archive, &globs, 8);
    let mut domains: BTreeSet<String> = BTreeSet::new();
    let mut assertions: BTreeSet<String> = BTreeSet::new();
    let mut grants: BTreeSet<String> = BTreeSet::new();
    let mut prevent_idle = 0usize;

    static DOMAIN_RE: OnceLock<Regex> = OnceLock::new();
    static NAME_RE: OnceLock<Regex> = OnceLock::new();
    static GRANT_RE: OnceLock<Regex> = OnceLock::new();
    let domain_re = DOMAIN_RE.get_or_init(|| Regex::new(r"domain:([A-Za-z0-9._-]+)").unwrap());
    let name_re = NAME_RE.get_or_init(|| Regex::new(r"\bname:([A-Za-z0-9._-]+)").unwrap());
    let grant_re = GRANT_RE.get_or_init(|| Regex::new(r"\b(RBS[A-Za-z0-9]+Grant)\b").unwrap());

    for (_path, val) in &files {
        let Some(text) = val.as_str() else {
            continue;
        };
        for cap in domain_re.captures_iter(text) {
            domains.insert(cap[1].to_string());
        }
        for cap in name_re.captures_iter(text) {
            assertions.insert(cap[1].to_string());
        }
        for cap in grant_re.captures_iter(text) {
            let g = cap[1].to_string();
            if g.contains("PreventIdleSleep") {
                prevent_idle += 1;
            }
            grants.insert(g);
        }
    }

    let events = vec![event(
        "runningboard",
        ts,
        format!(
            "runningboard domains={} assertions={} grants={}",
            domains.len(),
            assertions.len(),
            grants.len()
        ),
        "runningboard",
        json!({
            "domain_count": domains.len(),
            "assertion_count": assertions.len(),
            "grant_count": grants.len(),
            "prevent_idle_sleep_mentions": prevent_idle,
        }),
    )];

    let mut doc = wrap_jsonl("runningboard", events);
    if let Some(obj) = doc.as_object_mut() {
        obj.insert("format".into(), json!("structured"));
        obj.insert("domains".into(), json!(domains.into_iter().collect::<Vec<_>>()));
        obj.insert(
            "assertions".into(),
            json!(assertions.into_iter().collect::<Vec<_>>()),
        );
        obj.insert("grants".into(), json!(grants.into_iter().collect::<Vec<_>>()));
        obj.insert("prevent_idle_sleep_mentions".into(), json!(prevent_idle));
        obj.insert("files".into(), Value::Object(files));
        obj.insert("meta".into(), json!({ "total_matched": total }));
    }
    Ok(doc)
}

/// OTA / restore logs → file inventory + restore/update line hits.
pub fn parse_ota_update(archive: &SysdiagnoseArchive) -> Result<Value, BoxErr> {
    let globs = ["logs/OTAUpdateLogs/**", "restore_perform.txt"];
    let ts = creation(archive);
    let (files, total) = text_files(archive, &globs, 64);
    let mut hits = Vec::new();
    let mut file_rows = Vec::new();
    for (path, val) in &files {
        let Some(text) = val.as_str() else {
            continue;
        };
        file_rows.push(json!({
            "path": path,
            "char_count": text.len(),
            "is_ips": path.ends_with(".ips"),
        }));
        for (i, line) in text.lines().enumerate().take(4000) {
            let lower = line.to_ascii_lowercase();
            if lower.contains("restore")
                || lower.contains("update")
                || lower.contains("seeding")
                || lower.contains("mobileasset")
            {
                hits.push(json!({
                    "path": path,
                    "line": i + 1,
                    "text": line.chars().take(240).collect::<String>(),
                }));
                if hits.len() >= 200 {
                    break;
                }
            }
        }
        if hits.len() >= 200 {
            break;
        }
    }
    let events = vec![event(
        "ota_update",
        ts,
        format!("ota_update files={} hits={}", file_rows.len(), hits.len()),
        "ota_update",
        json!({ "file_count": file_rows.len(), "hit_count": hits.len() }),
    )];
    let mut doc = wrap_jsonl("ota_update", events);
    if let Some(obj) = doc.as_object_mut() {
        obj.insert("format".into(), json!("structured"));
        obj.insert("files_index".into(), json!(file_rows));
        obj.insert("restore_hints".into(), json!(hits));
        obj.insert("files".into(), Value::Object(files));
        obj.insert("meta".into(), json!({ "total_matched": total }));
    }
    Ok(doc)
}
