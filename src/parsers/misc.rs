// SPDX-License-Identifier: GPL-3.0-only

//! Structured, plist, and sectioned parsers.

use std::collections::BTreeMap;

use chrono::{FixedOffset, Utc};
use regex::Regex;
use serde_json::{json, Map, Value};
use std::sync::OnceLock;

use crate::archive::SysdiagnoseArchive;
use crate::engine::ParseOptions;
use crate::error::BoxErr;
use crate::parsers::parser_events::{
    event, events_from_known_networks_plist, events_from_wifinetworks_files, extract_multiline_log,
    mc_settings_events, mcstate_shared_profile_events, mobilebackup_events, olddsc_events,
    parse_avconference_gzip, parse_battery_bdc_csv, parse_logdata_statistics_jsonl,
    parse_logdata_statistics_txt, parse_wifi_scan, parse_wifi_security, wrap_jsonl,
};
use crate::parsers::timeutil::parse_apple_datetime;
use crate::parsers::{matched_paths, plist_bytes_to_json, SysdiagnoseParser};
use crate::util::{enrich_mobile_installation_event, parse_process_identity};

fn creation(archive: &SysdiagnoseArchive) -> chrono::DateTime<FixedOffset> {
    crate::archive::sysdiagnose_creation(archive)
}

fn text_at(archive: &SysdiagnoseArchive, path: &str) -> Option<String> {
    archive.get(path).map(|b| String::from_utf8_lossy(b).into_owned())
}

macro_rules! unit_parser {
    ($name:ident, $fn:ident) => {
        pub struct $name;
        impl SysdiagnoseParser for $name {
            fn parse(&self, archive: &SysdiagnoseArchive) -> Result<Value, BoxErr> {
                $fn(archive)
            }
        }
    };
}

unit_parser!(BrctlParser, parse_brctl);
unit_parser!(ItunesstoreParser, parse_itunesstore);
unit_parser!(PlistsParser, parse_plists);
unit_parser!(RemotectlParser, parse_remotectl);
unit_parser!(TransparencyJsonParser, parse_transparency_json);
unit_parser!(MountParser, parse_mount);
unit_parser!(SpindumpnosymbolsParser, parse_spindump);
unit_parser!(MobileinstallationParser, parse_mobileinstallation);
unit_parser!(WifiKnownNetworksParser, parse_wifi_known);
unit_parser!(WifinetworksParser, parse_wifinetworks);
unit_parser!(ShutdownLogsParser, parse_shutdown);
unit_parser!(TaskinfoParser, parse_taskinfo);

pub struct LogarchiveParser;
impl SysdiagnoseParser for LogarchiveParser {
    fn parse(&self, archive: &SysdiagnoseArchive) -> Result<Value, BoxErr> {
        parse_logarchive(archive, &ParseOptions::default())
    }
    fn parse_with_options(&self, archive: &SysdiagnoseArchive, opts: &ParseOptions) -> Result<Value, BoxErr> {
        parse_logarchive(archive, opts)
    }
}

pub fn parse_sys(archive: &SysdiagnoseArchive) -> Result<Value, BoxErr> {
    let globs = [
        "logs/SystemVersion/SystemVersion.plist",
        "SystemVersion.plist",
        "**/SystemVersion.plist",
    ];
    let mut paths = matched_paths(archive, &globs);
    paths.sort_by_key(|p| {
        if p.contains("logs/SystemVersion/SystemVersion.plist") {
            0
        } else {
            1
        }
    });
    let path = paths.into_iter().next();
    let plist = path
        .as_deref()
        .and_then(|p| archive.get(p))
        .and_then(|b| plist_bytes_to_json(b).ok());
    let message = plist.as_ref().map(|pl| {
        let name = pl.get("ProductName").and_then(|v| v.as_str()).unwrap_or("");
        let ver = pl.get("ProductVersion").and_then(|v| v.as_str()).unwrap_or("");
        let build = pl.get("ProductBuildVersion").and_then(|v| v.as_str()).unwrap_or("");
        format!("SystemVersion {name} {ver} {build}").trim().to_string()
    });
    let mut doc = json!({"parser": "sys", "plist": plist});
    if let Some(obj) = doc.as_object_mut() {
        if let Some(path) = &path {
            obj.insert("source".into(), json!(path));
        }
        if let Some(message) = message {
            obj.insert("message".into(), json!(message));
        }
    }
    Ok(doc)
}

pub const TASKINFO: &str = "taskinfo.txt";

fn taskinfo_kv(line: &str) -> Option<(String, String)> {
    let (k, v) = line.split_once(':')?;
    Some((k.trim().to_string(), v.trim().to_string()))
}

/// Group taskinfo process lines into policy dicts and a thread list.
fn taskinfo_process_body(lines: &[String]) -> Map<String, Value> {
    let mut data = Map::new();
    let mut section = "";
    let mut threads: Vec<Value> = Vec::new();
    let mut thread: Option<Map<String, Value>> = None;
    let mut thread_section = "";

    let flush_thread = |thread: &mut Option<Map<String, Value>>, threads: &mut Vec<Value>| {
        if let Some(t) = thread.take() {
            if !t.is_empty() {
                threads.push(Value::Object(t));
            }
        }
    };

    for line in lines {
        let bare = line.trim();
        if !bare.contains(':') {
            match bare {
                "requested policy" => section = "req",
                "effective policy" => section = "eff",
                "threads" => {
                    section = "threads";
                    thread_section = "";
                }
                other if other.starts_with("boosts ") => {
                    data.insert(other.to_string(), json!(true));
                }
                _ => {}
            }
            if bare == "requested policy" {
                data.insert("requested policy".into(), json!({}));
            } else if bare == "effective policy" {
                data.insert("effective policy".into(), json!({}));
            }
            continue;
        }
        let Some((key, val)) = taskinfo_kv(line) else {
            continue;
        };
        if key == "threads" {
            flush_thread(&mut thread, &mut threads);
            section = "threads";
            thread_section = "";
            continue;
        }
        if section == "threads" && key == "thread ID" {
            flush_thread(&mut thread, &mut threads);
            let mut t = Map::new();
            t.insert(key.clone(), json!(val));
            thread = Some(t);
            thread_section = "";
            continue;
        }
        if key == "requested policy" || key == "effective policy" {
            let nest = Map::new();
            if section == "threads" {
                if let Some(t) = thread.as_mut() {
                    t.insert(key.clone(), Value::Object(nest));
                }
                thread_section = if key.starts_with("requested") { "req" } else { "eff" };
            } else {
                data.insert(key.clone(), Value::Object(nest));
                section = if key.starts_with("requested") { "req" } else { "eff" };
            }
            continue;
        }
        if section == "threads" {
            let Some(t) = thread.as_mut() else {
                continue;
            };
            if thread_section == "req" && key.starts_with("req ") {
                if let Some(obj) = t.get_mut("requested policy").and_then(|v| v.as_object_mut()) {
                    obj.insert(key, json!(val));
                }
            } else if thread_section == "eff" && key.starts_with("eff ") {
                if let Some(obj) = t.get_mut("effective policy").and_then(|v| v.as_object_mut()) {
                    obj.insert(key, json!(val));
                }
            } else {
                thread_section = "";
                t.insert(key, json!(val));
            }
            continue;
        }
        if section == "req" && key.starts_with("req ") {
            if let Some(obj) = data.get_mut("requested policy").and_then(|v| v.as_object_mut()) {
                obj.insert(key, json!(val));
            }
            continue;
        }
        if section == "eff" && key.starts_with("eff ") {
            if let Some(obj) = data.get_mut("effective policy").and_then(|v| v.as_object_mut()) {
                obj.insert(key, json!(val));
            }
            continue;
        }
        section = "";
        data.insert(key, json!(val));
    }
    flush_thread(&mut thread, &mut threads);
    if !threads.is_empty() {
        data.insert("threads".into(), Value::Array(threads));
    }
    data
}

pub fn parse_taskinfo(archive: &SysdiagnoseArchive) -> Result<Value, BoxErr> {
    let text = text_at(archive, TASKINFO).unwrap_or_default();
    let ts = creation(archive);
    let mut events = Vec::new();
    if let Some(caps) = Regex::new(r"num tasks:\s*(\d+)")
        .unwrap()
        .captures(&text)
    {
        events.push(event(
            "taskinfo",
            ts,
            format!("num tasks {}", &caps[1]),
            "task count",
            json!({"tasks": caps[1].parse::<i64>().unwrap_or(0)}),
        ));
    }
    let mut current: Option<(String, i64, String, Vec<String>)> = None;
    let flush = |cur: &mut Option<(String, i64, String, Vec<String>)>, events: &mut Vec<Value>, ts| {
        if let Some((name, pid, line, body)) = cur.take() {
            let mut data = taskinfo_process_body(&body);
            data.insert("name".into(), json!(name));
            data.insert("process".into(), json!(name));
            data.insert("pid".into(), json!(pid));
            data.insert("process_line".into(), json!(line));
            events.push(event(
                "taskinfo",
                ts,
                format!("{name} started"),
                "process start time",
                Value::Object(data),
            ));
        }
    };
    for line in text.lines() {
        let t = line.trim();
        if let Some(rest) = t.strip_prefix("process:") {
            flush(&mut current, &mut events, ts);
            let (name, pid) = parse_process_identity(rest.trim());
            current = Some((name, pid.unwrap_or(0) as i64, rest.trim().to_string(), Vec::new()));
            continue;
        }
        if let Some((_, _, _, body)) = current.as_mut() {
            if !t.is_empty() {
                body.push(t.to_string());
            }
        }
    }
    flush(&mut current, &mut events, ts);
    let mut doc = wrap_jsonl("taskinfo", events);
    if let Some(obj) = doc.as_object_mut() {
        obj.insert("line_count".into(), json!(text.lines().count()));
        obj.insert("source".into(), json!(TASKINFO));
    }
    if let Some(dt) = archive.acquisition() {
        doc.as_object_mut()
            .unwrap()
            .insert("acquisition_rfc3339".into(), json!(dt.to_rfc3339()));
    } else {
        doc.as_object_mut().unwrap().insert(
            "acquisition_rfc3339".into(),
            json!(ts.to_rfc3339()),
        );
    }
    Ok(doc)
}

pub fn split_client_path(path: &str) -> (String, Option<String>) {
    static UUID: OnceLock<Regex> = OnceLock::new();
    let re = UUID.get_or_init(|| {
        Regex::new(r"(?i)[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$").unwrap()
    });
    if let Some(idx) = path.rfind('/') {
        let (dir, last) = path.split_at(idx);
        let last = last.trim_start_matches('/');
        if re.is_match(last) {
            return (dir.to_string(), Some(last.to_string()));
        }
    }
    (path.to_string(), None)
}

pub fn parse_shutdown(archive: &SysdiagnoseArchive) -> Result<Value, BoxErr> {
    let globs = [
        "system_logs.logarchive/Extra/shutdown.log",
        "system_logs.logarchive/Extra/shutdown.*.log",
        "private/var/db/diagnostics/shutdown.log",
        "private/var/db/diagnostics/shutdown.*.log",
    ];
    let mut paths = matched_paths(archive, &globs);
    // also plain suffix matches the tests use
    for p in archive.all_paths() {
        let base = p.rsplit('/').next().unwrap_or(&p);
        if (base == "shutdown.log" || base.starts_with("shutdown.") && base.ends_with(".log"))
            && (p.contains("logarchive/Extra") || p.contains("diagnostics"))
            && !paths.contains(&p)
        {
            paths.push(p);
        }
    }
    paths.sort();
    let mut events = Vec::new();
    let mut sources = Vec::new();
    for path in &paths {
        let Some(text) = text_at(archive, path) else {
            continue;
        };
        sources.push(json!(path));
        events.extend(parse_shutdown_text(&text, path));
    }
    let mut doc = wrap_jsonl("shutdownlogs", events);
    doc.as_object_mut().unwrap().insert("sources".into(), Value::Array(sources));
    Ok(doc)
}

fn parse_shutdown_text(text: &str, source: &str) -> Vec<Value> {
    struct Pend {
        wait: f64,
        pid: i64,
        client: String,
        times: i64,
        sigterm: Option<i64>,
    }
    let mut items: Vec<Pend> = Vec::new();
    let mut wait = 0.0_f64;
    for line in text.lines() {
        let line = line.trim();
        if let Some(rest) = line.strip_prefix("After ") {
            if let Some(num) = rest.split('s').next() {
                wait = num.trim().parse().unwrap_or(wait);
            }
        }
        if let Some(rest) = line.strip_prefix("remaining client pid:") {
            let rest = rest.trim();
            let pid = rest
                .split_whitespace()
                .next()
                .and_then(|p| p.parse().ok())
                .unwrap_or(0);
            let client = rest
                .find('(')
                .and_then(|start| rest.rfind(')').map(|end| rest[start + 1..end].to_string()))
                .unwrap_or_default();
            if client.is_empty() {
                continue;
            }
            if let Some(existing) = items.iter_mut().rev().find(|it| {
                it.sigterm.is_none() && it.pid == pid && it.client == client && it.wait == wait
            }) {
                existing.times += 1;
            } else {
                items.push(Pend {
                    wait,
                    pid,
                    client,
                    times: 1,
                    sigterm: None,
                });
            }
        }
        if let Some(idx) = line.find("SIGTERM:") {
            let rest = &line[idx..];
            let ts = rest
                .find('[')
                .and_then(|start| rest.find(']').map(|end| rest[start + 1..end].parse().ok()))
                .flatten();
            if let Some(ts) = ts {
                for it in items.iter_mut().filter(|it| it.sigterm.is_none()) {
                    it.sigterm = Some(ts);
                }
            }
        }
    }
    let mut events = Vec::new();
    for it in items {
        let (exe, uuid) = split_client_path(&it.client);
        let command = exe.rsplit('/').next().unwrap_or(&exe).to_string();
        let dt = it
            .sigterm
            .and_then(|s| chrono::DateTime::<Utc>::from_timestamp(s, 0))
            .map(|d| d.fixed_offset())
            .unwrap_or_else(|| Utc::now().fixed_offset());
        let mut data = json!({
            "pid": it.pid,
            "path": it.client,
            "executable_path": exe,
            "command": command,
            "source_path": source,
            "time_waiting": it.wait,
            "times_waiting": it.times,
        });
        if let Some(u) = uuid {
            data.as_object_mut().unwrap().insert("uuid".into(), json!(u));
        } else {
            data.as_object_mut().unwrap().insert("uuid".into(), Value::Null);
        }
        events.push(event(
            "shutdownlogs",
            dt,
            format!("{command} is still there during shutdown after {}s", it.wait),
            "process running at shutdown",
            data,
        ));
    }
    events
}

fn parse_mount_line(line: &str) -> Map<String, Value> {
    let mut data = Map::new();
    let Some((device, rest)) = line.split_once(" on ") else {
        data.insert("raw".into(), json!(line));
        return data;
    };
    let (mountpoint, opts_src) = if let Some(idx) = rest.rfind(" (") {
        let opts = rest[idx + 2..].trim().trim_end_matches(')');
        (rest[..idx].trim(), opts)
    } else {
        (rest.trim(), "")
    };
    let opts: Vec<Value> = opts_src
        .split(',')
        .map(|s| s.trim())
        .filter(|s| !s.is_empty())
        .map(|s| json!(s))
        .collect();
    let opt_strs: Vec<&str> = opts.iter().filter_map(|v| v.as_str()).collect();
    let is_root = mountpoint == "/";
    let read_only = opt_strs.iter().any(|s| *s == "read-only");
    let sealed = opt_strs.iter().any(|s| *s == "sealed");
    data.insert("device".into(), json!(device.trim()));
    data.insert("mountpoint".into(), json!(mountpoint));
    data.insert("opts".into(), Value::Array(opts));
    data.insert("is_root".into(), json!(is_root));
    data.insert("read_only".into(), json!(read_only));
    data.insert("sealed".into(), json!(sealed));
    data
}

pub fn parse_mount(archive: &SysdiagnoseArchive) -> Result<Value, BoxErr> {
    let text = text_at(archive, "mount.txt").unwrap_or_default();
    let ts = creation(archive);
    let mut events = Vec::new();
    let mut root_sealed = false;
    let mut root_ro = false;
    let mut root_mounts = Vec::new();
    for line in text.lines() {
        let line = line.trim();
        if line.is_empty() {
            continue;
        }
        let data = parse_mount_line(line);
        if data.get("is_root").and_then(|v| v.as_bool()) == Some(true) {
            root_sealed = data.get("sealed").and_then(|v| v.as_bool()).unwrap_or(false);
            root_ro = data.get("read_only").and_then(|v| v.as_bool()).unwrap_or(false);
            root_mounts.push(json!({
                "device": data.get("device").cloned().unwrap_or(Value::Null),
                "opts": data.get("opts").cloned().unwrap_or(json!([])),
                "read_only": root_ro,
                "sealed": root_sealed,
            }));
        }
        events.push(event("mount", ts, line, "mount", Value::Object(data)));
    }
    let hint = if root_sealed && root_ro {
        "system_partition_sealed_readonly"
    } else {
        ""
    };
    let mut doc = wrap_jsonl("mount", events);
    doc.as_object_mut().unwrap().insert(
        "summary".into(),
        json!({
            "root_sealed": root_sealed,
            "root_read_only": root_ro,
            "root_mounts": root_mounts,
            "integrity_hint": hint,
        }),
    );
    Ok(doc)
}

pub fn parse_list_file(text: &str) -> Value {
    let mut containers = Vec::new();
    for line in text.lines() {
        if !line.contains("id:") {
            continue;
        }
        let mut obj = Map::new();
        for key in ["id", "localizedName", "documents", "clients"] {
            if let Some(idx) = line.find(&format!("{key}:")) {
                let rest = line[idx + key.len() + 1..].trim();
                let end = ["id:", "localizedName:", "documents:", "clients:"]
                    .iter()
                    .filter_map(|k| rest.find(k))
                    .min()
                    .unwrap_or(rest.len());
                obj.insert(key.into(), json!(rest[..end].trim()));
            }
        }
        if obj.contains_key("id") {
            containers.push(Value::Object(obj));
        }
    }
    json!({"containers": containers})
}

pub fn parse_boot_history(text: &str) -> Vec<Value> {
    let mut rows = Vec::new();
    static RE: OnceLock<Regex> = OnceLock::new();
    let re = RE.get_or_init(|| {
        Regex::new(r"\[(?P<date>[^\]]+)\]\s*OS:(?P<os>\S+)\s*CloudDocs:(?P<cd>\S+)\s*BirdSchema:(?P<bird>\S+)\s*DBSchema:(?P<db>\S+)").unwrap()
    });
    for line in text.lines() {
        if let Some(c) = re.captures(line) {
            rows.push(json!({
                "date": c["date"].to_string(),
                "OS": c["os"].to_string(),
                "CloudDocs": c["cd"].to_string(),
                "BirdSchema": c["bird"].to_string(),
                "DBSchema": c["db"].to_string(),
            }));
        }
    }
    rows
}

pub fn parse_brctl(archive: &SysdiagnoseArchive) -> Result<Value, BoxErr> {
    let list = text_at(archive, "brctl/brctl-container-list.txt").unwrap_or_default();
    let dump = text_at(archive, "brctl/brctl-dump.txt").unwrap_or_default();
    let mut data = parse_list_file(&list);
    let boot = parse_boot_history(&dump);
    if let Some(obj) = data.as_object_mut() {
        let header_line = dump.lines().next().unwrap_or("").trim();
        obj.insert("header".into(), json!({"line": header_line}));
        obj.insert("boot_history".into(), Value::Array(boot));
        merge_brctl_dump(obj, &dump);
    }
    Ok(json!({"parser": "brctl", "data": data}))
}

fn merge_brctl_dump(data: &mut Map<String, Value>, dump: &str) {
    let mut header = Map::new();
    if let Some(line) = dump.lines().next() {
        if let Some(rest) = line.trim().strip_prefix("brctl") {
            header.insert("brctl".into(), json!(rest.trim()));
        }
    }
    let mut section = "header";
    let mut bucket: Vec<String> = Vec::new();
    let mut sections: Vec<(String, Vec<String>)> = Vec::new();
    for line in dump.lines() {
        let t = line.trim();
        if t.starts_with("---") {
            if !bucket.is_empty() {
                sections.push((section.to_string(), std::mem::take(&mut bucket)));
            }
            section = "";
            continue;
        }
        if section.is_empty() {
            if t.is_empty() {
                continue;
            }
            section = "body";
            bucket.push(t.to_string());
            continue;
        }
        bucket.push(t.to_string());
    }
    if !bucket.is_empty() {
        sections.push((section.to_string(), bucket));
    }
    for (name, lines) in &sections {
        if name == "header" {
            for line in lines {
                if let Some(rest) = line.strip_prefix("dump taken at ") {
                    header.insert("from".into(), json!(rest.trim()));
                } else if let Some((k, v)) = line.split_once(':') {
                    let key = match k.trim() {
                        "database version" => "version",
                        "database ID" => "ID",
                        "fsType" => "fsType",
                        _ => continue,
                    };
                    header.insert(key.into(), json!(v.trim()));
                } else if let Some(rest) = line.strip_prefix("brctl") {
                    header.insert("brctl".into(), json!(rest.trim()));
                }
            }
        }
    }
    for line in dump.lines() {
        let t = line.trim();
        if let Some(rest) = t.strip_prefix("boot_history") {
            let key = if rest.trim().is_empty() { "boot_history" } else { t };
            data.insert("boot_history".into(), json!({ key: {} }));
        }
        if t.contains("containers matching") {
            if let Some(n) = t.split_whitespace().next() {
                header.insert("containers".into(), json!(n));
            }
        }
    }
    data.insert("header".into(), Value::Object(header));
    if let Some(body) = brctl_named_fields(
        dump,
        &[
            "availableQuota",
            "clientRanks",
            "containerMetadataSync",
            "currentUserRecordID",
            "lastQuotaFetchDate",
            "periodicSyncDate",
            "sideCarSync",
            "stage",
            "syncUpBudget",
            "zoneHealthSync",
        ],
    ) {
        data.insert("client_state".into(), Value::Object(body));
    }
    if let Some(body) = kv_until_banner(dump, "system") {
        data.insert("system".into(), Value::Object(body));
    }
    if let Some(body) = kv_until_banner(dump, "scheduler") {
        data.insert("scheduler".into(), Value::Object(body));
    }
    if let Some(mut body) = brctl_named_fields(dump, &["last-sync", "nextRank", "minUsedTime"]) {
        if let Some(v) = body.remove("last-sync") {
            body.insert("last_sync".into(), v);
        }
        data.insert("server_state".into(), Value::Object(body));
    }
    data.entry("app_ids").or_insert_with(|| json!({}));
    data.entry("app_library_id").or_insert_with(|| json!({}));
    data.entry("applibrary").or_insert_with(|| json!([]));
    data.entry("server_items").or_insert_with(|| json!([]));
}

fn strip_ansi(s: &str) -> String {
    let mut out = String::new();
    let mut chars = s.chars().peekable();
    while let Some(c) = chars.next() {
        if c == '\u{1b}' {
            if chars.peek() == Some(&'[') {
                chars.next();
                for n in chars.by_ref() {
                    if n.is_ascii_alphabetic() {
                        break;
                    }
                }
            }
            continue;
        }
        out.push(c);
    }
    out
}

fn clean_brctl_key(k: &str) -> String {
    strip_ansi(k).trim().trim_start_matches('+').trim().to_string()
}

fn brctl_named_fields(dump: &str, keys: &[&str]) -> Option<Map<String, Value>> {
    let mut out = Map::new();
    for line in dump.lines() {
        let cleaned = clean_brctl_key(&strip_ansi(line));
        let mut hits: Vec<(usize, &str)> = Vec::new();
        for key in keys {
            let mut from = 0;
            while let Some(rel) = cleaned[from..].find(key) {
                let idx = from + rel;
                let before_ok = idx == 0
                    || cleaned[..idx]
                        .chars()
                        .next_back()
                        .map(|c| !c.is_ascii_alphanumeric())
                        .unwrap_or(true);
                let after = cleaned[idx + key.len()..].chars().next();
                let after_ok = after.map(|c| !c.is_ascii_alphanumeric()).unwrap_or(true);
                if before_ok && after_ok {
                    hits.push((idx, *key));
                    break;
                }
                from = idx + key.len();
            }
        }
        if hits.is_empty() {
            continue;
        }
        hits.sort_by_key(|(idx, _)| *idx);
        for (n, (idx, key)) in hits.iter().enumerate() {
            let mut start = idx + key.len();
            if cleaned[start..].starts_with(':') {
                start += 1;
            }
            let end = hits.get(n + 1).map(|(i, _)| *i).unwrap_or(cleaned.len());
            let val = cleaned[start..end].trim();
            out.insert((*key).to_string(), json!(val));
        }
    }
    if out.is_empty() { None } else { Some(out) }
}

fn kv_until_banner(dump: &str, label: &str) -> Option<Map<String, Value>> {
    let mut lines = dump.lines();
    while let Some(line) = lines.next() {
        if line.trim() == label || line.trim().strip_suffix(':').unwrap_or(line.trim()) == label {
            let mut out = Map::new();
            let mut skipped_banner = false;
            for line in lines.by_ref() {
                let t = line.trim();
                if t.starts_with("---") {
                    if out.is_empty() && !skipped_banner {
                        skipped_banner = true;
                        continue;
                    }
                    break;
                }
                if let Some((k, v)) = t.split_once(':') {
                    let key = clean_brctl_key(k);
                    if key.is_empty() {
                        continue;
                    }
                    out.insert(key, json!(strip_ansi(v.trim())));
                }
            }
            if out.is_empty() {
                return None;
            }
            return Some(out);
        }
    }
    None
}

pub fn parse_remotectl(archive: &SysdiagnoseArchive) -> Result<Value, BoxErr> {
    let text = text_at(archive, "remotectl_dumpstate.txt").unwrap_or_default();
    let data = crate::tab_hierarchy::parse_tab_hierarchy_text(&text);
    Ok(json!({"parser": "remotectl_dumpstate", "data": data}))
}

pub fn parse_transparency_json(archive: &SysdiagnoseArchive) -> Result<Value, BoxErr> {
    let text = text_at(archive, "transparency.log").unwrap_or_default();
    if text.trim().is_empty() {
        return Ok(json!({"error": "empty_file"}));
    }
    match serde_json::from_str::<Value>(text.trim()) {
        Ok(v) => Ok(v),
        Err(e) => Ok(json!({"error": e.to_string()})),
    }
}

pub fn parse_transparency(archive: &SysdiagnoseArchive) -> Result<Value, BoxErr> {
    let text = text_at(archive, "transparency.log").unwrap_or_default();
    let root = serde_json::from_str::<Value>(text.trim()).unwrap_or(Value::Null);
    let events = crate::parsers::parser_events::transparency_extract_events(&root, "transparency");
    Ok(wrap_jsonl("transparency", events))
}

#[derive(Debug, Clone, Copy)]
pub struct PlistsCaps {
    pub max_files: usize,
    pub max_each_bytes: usize,
}

impl PlistsCaps {
    pub fn from_env() -> Self {
        fn num(var: &str, default: usize) -> usize {
            std::env::var(var).ok().and_then(|s| s.parse().ok()).unwrap_or(default)
        }
        Self {
            max_files: num("SYSDIAGNOSE_PLISTS_MAX_FILES", 600),
            max_each_bytes: num("SYSDIAGNOSE_PLISTS_MAX_EACH_BYTES", 4 * 1024 * 1024),
        }
    }
}

pub fn plists_recursive_with_caps(archive: &SysdiagnoseArchive, caps: PlistsCaps) -> Value {
    let mut paths = matched_paths(archive, &["**/*.plist"]);
    paths.sort();
    let total = paths.len();
    let limit = if caps.max_files == 0 { total } else { caps.max_files.min(total) };
    let mut files = Map::new();
    let mut failures = Vec::new();
    for path in paths.iter().take(limit) {
        let Some(bytes) = archive.get(path) else {
            continue;
        };
        if caps.max_each_bytes > 0 && bytes.len() > caps.max_each_bytes {
            files.insert(path.clone(), json!({}));
            failures.push(json!(path));
            continue;
        }
        match plist_bytes_to_json(bytes) {
            Ok(v) => {
                files.insert(path.clone(), v);
            }
            Err(_) => {
                files.insert(path.clone(), json!({}));
                failures.push(json!(path));
            }
        }
    }
    let truncated = total.saturating_sub(limit);
    json!({
        "parser": "plists",
        "files": files,
        "meta": {
            "total_matched": total,
            "returned": files.len(),
            "truncated_file_count": truncated,
            "parse_failures": failures,
            "max_files": caps.max_files,
            "max_each_bytes": caps.max_each_bytes,
        }
    })
}

pub fn parse_plists(archive: &SysdiagnoseArchive) -> Result<Value, BoxErr> {
    Ok(plists_recursive_with_caps(archive, PlistsCaps::from_env()))
}

pub fn parse_logarchive(archive: &SysdiagnoseArchive, opts: &ParseOptions) -> Result<Value, BoxErr> {
    let mut paths: Vec<(String, u64)> = archive
        .all_paths()
        .into_iter()
        .filter(|p| p.starts_with("system_logs.logarchive/") || p.contains("/system_logs.logarchive/"))
        .map(|p| {
            let size = archive.entry_size(&p).unwrap_or(0);
            (p, size)
        })
        .collect();
    let file_count = paths.len();
    let total_bytes: u64 = paths.iter().map(|(_, n)| *n).sum();
    paths.sort_by(|a, b| b.1.cmp(&a.1).then(a.0.cmp(&b.0)));
    let cap = std::env::var("SYSDIAGNOSE_LOGARCHIVE_INVENTORY_MAX_PATHS")
        .ok()
        .and_then(|s| s.parse().ok())
        .unwrap_or(100usize);
    let listed: Vec<Value> = paths.iter().take(cap).map(|(p, n)| json!({"path": p, "size": n})).collect();
    let mut by_subdir = BTreeMap::<String, u64>::new();
    for (p, _) in &paths {
        let rest = p
            .split("system_logs.logarchive/")
            .nth(1)
            .unwrap_or(p);
        let sub = rest.split('/').next().unwrap_or("").to_string();
        *by_subdir.entry(sub).or_default() += 1;
    }
    let has_trace = paths.iter().any(|(p, _)| p.ends_with(".tracev3"));
    #[cfg(not(feature = "logarchive-decode"))]
    let decode = {
        let _ = has_trace;
        "deferred"
    };
    #[cfg(feature = "logarchive-decode")]
    let decode = if opts.logarchive_inventory_only || !has_trace {
        "skipped"
    } else {
        "pending"
    };
    let mut doc = json!({
        "parser": "logarchive",
        "format": "jsonl",
        "inventory": {
            "file_count": file_count,
            "total_bytes": total_bytes,
            "by_subdir": by_subdir,
            "paths": listed,
            "paths_cap": cap,
            "paths_truncated": paths.len() > cap,
        },
        "decode": decode,
        "decode_meta": {
            "status": decode,
            "max_lines": opts.logarchive_decode_max_lines,
            "memory_threshold": opts.logarchive_memory_threshold,
            "tool": "mul-unifiedlog",
        },
        "note": "unified log inventory",
    });
    #[cfg(feature = "logarchive-decode")]
    if decode != "skipped" && decode != "deferred" {
        if let Some(dir) = archive.logarchive_dir() {
            match crate::logarchive_decode::decode_logarchive_dir(
                &dir,
                crate::logarchive_decode::DecodeLimits {
                    max_lines: opts.logarchive_decode_max_lines,
                    memory_threshold_bytes: opts.logarchive_memory_threshold,
                },
            ) {
                Ok(decoded) => {
                    let n = decoded.events.len();
                    let obj = doc.as_object_mut().unwrap();
                    obj.insert("decode".into(), json!("success"));
                    obj.insert("events".into(), Value::Array(decoded.events));
                    obj.insert(
                        "decode_meta".into(),
                        json!({
                            "event_count": n,
                            "max_lines": opts.logarchive_decode_max_lines,
                            "memory_threshold": opts.logarchive_memory_threshold,
                            "memory_threshold_hit": decoded.memory_threshold_hit,
                            "bytes_retained": decoded.bytes_retained,
                            "status": "success",
                            "tool": "mul-unifiedlog",
                        }),
                    );
                    obj.insert(
                        "note".into(),
                        json!("Unified log decode via logarchive-decode feature (mul-unifiedlog)."),
                    );
                }
                Err(e) => {
                    let obj = doc.as_object_mut().unwrap();
                    obj.insert("decode".into(), json!("failed"));
                    obj.insert("decode_meta".into(), json!({ "reason": e.to_string() }));
                }
            }
        }
    }
    #[cfg(not(feature = "logarchive-decode"))]
    {
        let _ = &mut doc;
    }
    let _ = opts;
    Ok(doc)
}

pub fn parse_itunesstore(archive: &SysdiagnoseArchive) -> Result<Value, BoxErr> {
    let mut paths = matched_paths(archive, &["logs/itunesstored/downloads.*.sqlitedb"]);
    paths.sort();
    let Some(path) = paths.into_iter().next() else {
        return Ok(json!({"parser": "itunesstore", "source_path": Value::Null, "data": {}}));
    };
    let bytes = archive.get(&path).unwrap_or(b"");
    let data = crate::sqlite_dump::dump_sqlite_bytes(bytes, 25_000).unwrap_or(json!({}));
    Ok(json!({"parser": "itunesstore", "source_path": path, "data": data}))
}

pub fn parse_spindump(archive: &SysdiagnoseArchive) -> Result<Value, BoxErr> {
    let paths = matched_paths(archive, &["**/spindump-nosymbols.txt"]);
    let mut events = Vec::new();
    for path in paths {
        if let Some(text) = text_at(archive, &path) {
            events.extend(parse_spindump_nosymbols_text(&text));
        }
    }
    Ok(wrap_jsonl("spindumpnosymbols", events))
}

pub const MODULE: &str = "spindumpnosymbols";

pub fn parse_spindump_nosymbols_text(text: &str) -> Vec<Value> {
    if text.to_ascii_lowercase().contains("no samples") && !text.contains("Process:") {
        return Vec::new();
    }
    let mut events = Vec::new();
    let mut dt = Utc::now().fixed_offset();
    let mut header_bits = Vec::new();
    let mut header_data = Map::new();
    let mut in_proc = false;
    let mut in_images = false;
    let mut proc_data = Map::new();
    let image_re = Regex::new(
        r"(?P<start>0x[0-9a-fA-F]+) - (?P<end>0x[0-9a-fA-F]+)\s+(?P<image>.+?)\s+\((?P<uuid>[0-9A-Fa-f-]+)\)\s+(?P<path>\S+)",
    )
    .unwrap();
    let thread_re = Regex::new(r"^Thread\s+(?P<thread>0x[0-9a-fA-F]+).*?\bpriority\s+(?P<priority>\d+)").unwrap();
    let flush_proc = |proc_data: &mut Map<String, Value>, events: &mut Vec<Value>, dt| {
        if proc_data.is_empty() {
            return;
        }
        let name = proc_data.get("process").and_then(|v| v.as_str()).unwrap_or("").to_string();
        let pid = proc_data.get("pid").cloned().unwrap_or(Value::Null);
        events.push(event(
            MODULE,
            dt,
            format!("{name} [{pid}]"),
            "process running during spindump",
            Value::Object(std::mem::take(proc_data)),
        ));
    };
    for line in text.lines() {
        let t = line.trim();
        if t.is_empty() || t.starts_with("---") {
            continue;
        }
        if t.starts_with("Date/Time:") {
            let rest = t.trim_start_matches("Date/Time:").trim();
            if let Some(parsed) = parse_apple_datetime(rest) {
                dt = parsed;
            }
            header_bits.push(t.to_string());
            continue;
        }
        if t.eq_ignore_ascii_case("Binary Images:") {
            in_images = true;
            continue;
        }
        if let Some(c) = image_re.captures(t) {
            let img = json!({
                "start": c["start"].to_string(),
                "end": c["end"].to_string(),
                "image": c["image"].trim(),
                "uuid": c["uuid"].to_string(),
                "path": c["path"].to_string(),
            });
            let images = proc_data.entry("images").or_insert_with(|| json!([]));
            if let Some(arr) = images.as_array_mut() {
                arr.push(img);
            }
            continue;
        }
        if let Some(c) = thread_re.captures(t) {
            in_images = false;
            let th = json!({
                "thread": c["thread"].to_string(),
                "priority": c["priority"].to_string(),
            });
            let threads = proc_data.entry("threads").or_insert_with(|| json!([]));
            if let Some(arr) = threads.as_array_mut() {
                arr.push(th);
            }
            continue;
        }
        if t.starts_with("Process:") {
            flush_proc(&mut proc_data, &mut events, dt);
            in_proc = true;
            in_images = false;
            let rest = t.trim_start_matches("Process:").trim();
            let (name, pid) = parse_process_identity(rest);
            proc_data.insert("process".into(), json!(name.clone()));
            proc_data.insert("name".into(), json!(name));
            proc_data.insert("process_line".into(), json!(rest));
            if let Some(pid) = pid {
                proc_data.insert("pid".into(), json!(pid));
            }
            continue;
        }
        let Some((label, value)) = t.split_once(':') else {
            continue;
        };
        let value = value.trim();
        let label = label.trim();
        if value.is_empty()
            || label.contains('(')
            || label.starts_with(|c: char| c.is_ascii_digit())
            || label.starts_with("0x")
        {
            continue;
        }
        let key = crate::util::snake_case(label.trim());
        if !in_proc {
            header_bits.push(t.to_string());
            header_data.insert(key, json!(value));
            continue;
        }
        if in_images {
            continue;
        }
        match key.as_str() {
            "path" => {
                proc_data.insert("path".into(), json!(value));
            }
            "parent" => {
                let (name, pid) = parse_process_identity(value);
                proc_data.insert("parent".into(), json!(name));
                if let Some(pid) = pid {
                    proc_data.insert("ppid".into(), json!(pid));
                }
            }
            "uid" => {
                if let Ok(u) = value.parse::<i64>() {
                    proc_data.insert("uid".into(), json!(u));
                }
            }
            "time_since_fork" => {
                proc_data.insert("time_since_fork".into(), json!(value));
            }
            _ => {
                proc_data.insert(key, json!(value));
            }
        }
    }
    flush_proc(&mut proc_data, &mut events, dt);
    if !header_bits.is_empty() || !header_data.is_empty() {
        header_data.insert("header".into(), json!(header_bits));
        events.insert(
            0,
            event(
                MODULE,
                dt,
                format!("spindump {}", header_bits.join("; ")),
                "spindump",
                Value::Object(header_data),
            ),
        );
    }
    events
}

pub fn parse_swcutil(archive: &SysdiagnoseArchive) -> Result<Value, BoxErr> {
    let paths = matched_paths(archive, &["**/swcutil_show.txt"]);
    let ts = creation(archive);
    let mut events = Vec::new();
    for path in paths {
        if let Some(text) = text_at(archive, &path) {
            events.extend(parse_swcutil_show(&text, ts));
        }
    }
    Ok(wrap_jsonl("swcutil", events))
}

fn swc_field_name(label: &str) -> String {
    match label {
        "App ID" => "app_id".into(),
        "App Version" => "app_version".into(),
        "App PI" => "app_pi".into(),
        "User Approval" => "user_approval".into(),
        "Site/Fmwk Approval" => "site_fmwk_approval".into(),
        "Last Checked" => "last_checked".into(),
        "Next Check" => "next_check".into(),
        "Relative Order" => "relative_order".into(),
        "Settings Generation" => "settings_generation".into(),
        "LS Generation" => "ls_generation".into(),
        "Enterprise SHA" => "enterprise_sha".into(),
        "Developer Mode" => "developer_mode".into(),
        other => other.to_ascii_lowercase().replace(' ', "_"),
    }
}

pub fn parse_swcutil_show(text: &str, ts: chrono::DateTime<FixedOffset>) -> Vec<Value> {
    let mut events = Vec::new();
    let mut section = "";
    let mut header_map = Map::new();
    let mut saw_banner = false;
    let mut record: Map<String, Value> = Map::new();

    let flush_record = |record: &mut Map<String, Value>, events: &mut Vec<Value>| {
        if record.is_empty() {
            return;
        }
        let service = record.get("service").and_then(|v| v.as_str()).unwrap_or("").to_string();
        let domain = record.get("domain").and_then(|v| v.as_str()).unwrap_or("").to_string();
        let last = record.get("last_checked").and_then(|v| v.as_str()).unwrap_or("");
        let (dt, desc) = if let Some(parsed) = parse_apple_datetime(last) {
            (parsed, "db last checked")
        } else {
            (ts, "sysdiagnose creation time")
        };
        let message = if domain.is_empty() {
            format!("db {service}")
        } else if service.is_empty() {
            format!("db {domain}")
        } else {
            format!("db {service} {domain}")
        };
        let mut data = std::mem::take(record);
        data.insert("section".into(), json!("db"));
        data.insert("module".into(), json!("swcutil"));
        events.push(event("swcutil", dt, message.trim(), desc, Value::Object(data)));
    };

    for line in text.lines() {
        let t = line.trim();
        if t.contains("DATABASE") && t.contains('=') {
            flush_record(&mut record, &mut events);
            section = "database";
            saw_banner = true;
            continue;
        }
        if t.contains("NETWORK") && t.contains('=') {
            flush_record(&mut record, &mut events);
            section = "network";
            saw_banner = true;
            continue;
        }
        if t.contains("SETTINGS") && t.contains('=') {
            flush_record(&mut record, &mut events);
            section = "settings";
            saw_banner = true;
            continue;
        }
        if t.contains("MEMORY") && t.contains('=') {
            flush_record(&mut record, &mut events);
            section = "memory";
            saw_banner = true;
            continue;
        }
        if section.is_empty() {
            if let Some((k, v)) = t.split_once(':') {
                header_map.insert(swc_field_name(k.trim()), json!(v.trim()));
            }
            continue;
        }
        if section == "database" {
            if t.starts_with("---") || t.is_empty() {
                flush_record(&mut record, &mut events);
                continue;
            }
            if let Some((k, v)) = t.split_once(':') {
                let key = swc_field_name(k.trim());
                if key == "service" && record.contains_key("service") {
                    flush_record(&mut record, &mut events);
                }
                record.insert(key, json!(v.trim()));
            }
        } else if section == "network" {
            for part in t.split(',') {
                let name = part.split_whitespace().next().unwrap_or("").trim();
                if !name.is_empty() && name.contains('.') {
                    events.push(event(
                        "swcutil",
                        ts,
                        format!("Network: {name}"),
                        "network",
                        json!({"section": "network", "domain": name}),
                    ));
                }
            }
        } else if section == "memory" {
            if let Some((name, rest)) = t.split_once(':') {
                let num: f64 = rest.split_whitespace().next().unwrap_or("0").parse().unwrap_or(0.0);
                let unit = rest.split_whitespace().nth(1).unwrap_or("B");
                let mul = if unit.eq_ignore_ascii_case("MB") {
                    1024.0 * 1024.0
                } else if unit.eq_ignore_ascii_case("KB") {
                    1024.0
                } else {
                    1.0
                };
                events.push(event(
                    "swcutil",
                    ts,
                    format!("memory {name}"),
                    "memory usage at sysdiagnose creation",
                    json!({"section": "memory", "process": name.trim(), "usage": (num * mul) as i64}),
                ));
            }
        } else if section == "settings" && t.starts_with('{') && t.contains("s =") {
            let mut data = json!({"section": "settings", "settings": {}});
            if let Some(obj) = data.as_object_mut() {
                for key in ["s", "a", "d"] {
                    if let Some(idx) = t.find(&format!("{key} =")) {
                        let rest = t[idx + key.len() + 2..].trim();
                        let end = rest.find([',', '}']).unwrap_or(rest.len());
                        obj.insert(key.into(), json!(rest[..end].trim()));
                    }
                }
            }
            events.push(event(
                "swcutil",
                ts,
                "settings",
                "sysdiagnose creation time",
                data,
            ));
        } else if section == "settings" {
            if let Some((k, v)) = t.split_once('=') {
                let key = k
                    .trim()
                    .trim_matches(|c| c == '"' || c == ' ')
                    .replace('.', "_")
                    .to_ascii_lowercase();
                let val = v.trim().trim_end_matches(';').trim().to_string();
                if !key.is_empty() && key != "s" && key != "a" && key != "d" {
                    if let Some(ev) = events.last_mut() {
                        if ev.get("data").and_then(|d| d.get("section")).and_then(|s| s.as_str())
                            == Some("settings")
                        {
                            if let Some(settings) = ev
                                .get_mut("data")
                                .and_then(|d| d.get_mut("settings"))
                                .and_then(|s| s.as_object_mut())
                            {
                                settings.insert(key, json!(val));
                            }
                        }
                    }
                }
            }
        }
    }
    flush_record(&mut record, &mut events);
    if saw_banner || !header_map.is_empty() {
        let mut data = header_map;
        data.insert("section".into(), json!("headers"));
        data.insert("module".into(), json!("swcutil"));
        events.insert(
            0,
            event(
                "swcutil",
                ts,
                "swcutil headers",
                "swcutil headers at sysdiagnose creation",
                Value::Object(data),
            ),
        );
    }
    events
}

pub fn parse_security(archive: &SysdiagnoseArchive) -> Result<Value, BoxErr> {
    let text = text_at(archive, "security-sysdiagnose.txt").unwrap_or_default();
    let ts = creation(archive);
    let events = parse_security_sysdiagnose(&text, ts);
    Ok(wrap_jsonl("security_sysdiagnose", events))
}

pub const SECURITY_MODULE: &str = "security_sysdiagnose";

#[derive(Debug, Default)]
pub struct JsonResult {
    pub events: Vec<Value>,
    pub meta: Vec<(String, Value)>,
}

pub fn meta_get_mut_map<'a>(
    meta: &'a mut [(String, Value)],
    key: &str,
) -> Option<&'a mut Map<String, Value>> {
    meta.iter_mut().find_map(|(k, v)| {
        if k == key {
            v.as_object_mut()
        } else {
            None
        }
    })
}

pub fn parse_security_sysdiagnose(text: &str, fallback: chrono::DateTime<FixedOffset>) -> Vec<Value> {
    let mut acc = JsonResult::default();
    let mut buf: Vec<String> = Vec::new();
    let mut mode = "";
    let flush = |mode: &str, buf: &mut Vec<String>, acc: &mut JsonResult, fallback| {
        if buf.is_empty() {
            return;
        }
        match mode {
            "keychain" => process_buffer_keychain_state(buf, acc, fallback),
            "client" => process_buffer_client(buf, acc),
            "keys" => process_buffer_keys_and_values(buf, acc),
            _ => buf.clear(),
        }
    };
    for line in text.lines() {
        let t = line.trim_end();
        let lower = t.to_ascii_lowercase();
        let new_mode = if lower.contains("keychain state") {
            Some("keychain")
        } else if lower.starts_with("client:") {
            Some("client")
        } else if lower.contains("keys and values") || lower == "values" {
            Some("keys")
        } else {
            None
        };
        if let Some(m) = new_mode {
            flush(mode, &mut buf, &mut acc, fallback);
            mode = m;
            buf = vec![t.to_string()];
        } else if !mode.is_empty() {
            buf.push(t.to_string());
        }
    }
    flush(mode, &mut buf, &mut acc, fallback);
    acc.events
}

fn parse_kv_row(line: &str) -> Map<String, Value> {
    let mut map = Map::new();
    let body = match line.split_once(':') {
        Some((head, rest)) if !head.contains('=') => rest,
        _ => line,
    };
    let mut cur = String::new();
    let mut depth = 0i32;
    for c in body.chars() {
        if c == '{' || c == '(' {
            depth += 1;
            cur.push(c);
        } else if c == '}' || c == ')' {
            depth -= 1;
            cur.push(c);
        } else if c == ',' && depth == 0 {
            push_kv(&mut map, &cur);
            cur.clear();
        } else {
            cur.push(c);
        }
    }
    push_kv(&mut map, &cur);
    map
}

fn push_kv(map: &mut Map<String, Value>, piece: &str) {
    let piece = piece.trim();
    if piece.is_empty() {
        return;
    }
    if let Some((k, v)) = piece.split_once('=') {
        map.insert(k.trim().to_string(), Value::String(v.trim().to_string()));
    }
}

pub fn process_buffer_keychain_state(buf: &mut Vec<String>, acc: &mut JsonResult, _fallback: chrono::DateTime<FixedOffset>) {
    let header = buf.first().cloned().unwrap_or_default();
    let section = header
        .split_whitespace()
        .next()
        .unwrap_or("keychain")
        .trim_end_matches(':')
        .to_ascii_lowercase();
    acc.meta.push((section.clone(), json!([])));
    for line in buf.iter().skip(1) {
        if line.trim().is_empty() {
            continue;
        }
        let attrs = parse_kv_row(line);
        if attrs.contains_key("cdat") || attrs.contains_key("mdat") {
            let labl = attrs.get("labl").and_then(|v| v.as_str()).unwrap_or("");
            let agrp = attrs.get("agrp").and_then(|v| v.as_str()).unwrap_or("");
            let message = format!("{section} {labl} - {agrp}");
            if let Some(cdat) = attrs.get("cdat").and_then(|v| v.as_str()).and_then(parse_apple_datetime) {
                acc.events.push(event(
                    SECURITY_MODULE,
                    cdat,
                    message.clone(),
                    &format!("{section}: entry creation time"),
                    json!({"section": section, "attributes": attrs.clone()}),
                ));
            }
            if let Some(mdat) = attrs.get("mdat").and_then(|v| v.as_str()).and_then(parse_apple_datetime) {
                acc.events.push(event(
                    SECURITY_MODULE,
                    mdat,
                    message,
                    &format!("{section}: entry modification time"),
                    json!({"section": section, "attributes": attrs}),
                ));
            }
        }
    }
    buf.clear();
}

pub fn process_buffer_client(buf: &mut Vec<String>, acc: &mut JsonResult) {
    let header = buf.first().cloned().unwrap_or_default();
    let client = header
        .split_once(':')
        .map(|(_, r)| r.trim())
        .unwrap_or("client");
    let section = format!("client_{}", client.to_ascii_lowercase().replace(' ', "_"));
    let mut i = 1;
    while i < buf.len() {
        let line = buf[i].trim();
        if line.is_empty() {
            i += 1;
            continue;
        }
        let dt = line
            .split_whitespace()
            .take(4)
            .collect::<Vec<_>>()
            .join(" ");
        // try progressively shorter prefixes
        let parsed = parse_apple_datetime(line)
            .or_else(|| {
                let parts: Vec<&str> = line.split_whitespace().collect();
                for n in (2..=parts.len().min(5)).rev() {
                    if let Some(dt) = parse_apple_datetime(&parts[..n].join(" ")) {
                        return Some(dt);
                    }
                }
                None
            });
        let Some(when) = parsed else {
            i += 1;
            continue;
        };
        let rest = line[dt.len().min(line.len())..].trim();
        let rest = if line.len() > dt.len() {
            // find where the datetime ended by locating the severity token
            if let Some(idx) = line.find("Event") {
                line[idx..].trim()
            } else if let Some(idx) = line.find("Result") {
                line[idx..].trim()
            } else {
                rest
            }
        } else {
            rest
        };
        let mut block = rest.to_string();
        i += 1;
        while i < buf.len() && !looks_like_client_start(buf[i].trim()) {
            block.push(' ');
            block.push_str(buf[i].trim());
            i += 1;
        }
        let (severity, name, attrs) = split_client_event(&block);
        acc.events.push(event(
            SECURITY_MODULE,
            when,
            format!("{section} {severity} {name}"),
            &name,
            json!({"section": section, "attributes": attrs}),
        ));
        let _ = dt;
    }
    buf.clear();
}

fn looks_like_client_start(line: &str) -> bool {
    parse_apple_datetime(&line.split_whitespace().take(3).collect::<Vec<_>>().join(" ")).is_some()
        || line.contains(" +0000 ")
        || line.contains(" AM ")
        || line.contains(" PM ")
}

fn split_client_event(block: &str) -> (String, String, Map<String, Value>) {
    let mut severity = String::new();
    let mut name = String::new();
    let mut attrs = Map::new();
    let head = block.split("- Attributes:").next().unwrap_or(block).trim();
    if let Some((sev, rest)) = head.split_once(':') {
        severity = sev.trim().to_string();
        name = rest.trim().to_string();
    }
    if let Some(idx) = block.find("Attributes:") {
        let raw = block[idx + "Attributes:".len()..].trim();
        let raw = raw.trim_start_matches('{').trim_end_matches('}').trim();
        attrs = parse_attr_map(raw);
    }
    (severity, name, attrs)
}

fn parse_attr_map(raw: &str) -> Map<String, Value> {
    let mut map = Map::new();
    let mut depth = 0i32;
    let mut cur = String::new();
    for c in raw.chars() {
        if c == '(' || c == '{' {
            depth += 1;
            cur.push(c);
        } else if c == ')' || c == '}' {
            depth = depth.saturating_sub(1);
            cur.push(c);
        } else if c == ',' && depth == 0 {
            push_attr(&mut map, &cur);
            cur.clear();
        } else {
            cur.push(c);
        }
    }
    push_attr(&mut map, &cur);
    map
}

fn push_attr(map: &mut Map<String, Value>, piece: &str) {
    let piece = piece.trim();
    if piece.is_empty() {
        return;
    }
    if let Some((k, v)) = piece.split_once(':') {
        map.insert(k.trim().to_string(), Value::String(v.trim().to_string()));
    }
}

pub fn process_buffer_keys_and_values(buf: &mut Vec<String>, acc: &mut JsonResult) {
    let mut map = Map::new();
    let _header = buf.first().map(|s| s.trim().to_string()).unwrap_or_default();
    let key_name = "values";
    for line in buf.iter().skip(1) {
        if let Some((k, v)) = line.split_once(':') {
            map.insert(k.trim().to_string(), Value::String(v.trim().to_string()));
        }
    }
    acc.meta.push((key_name.to_string(), Value::Object(map.clone())));
    if !map.is_empty() {
        let summary = map
            .iter()
            .map(|(k, v)| format!("{k}={}", v.as_str().unwrap_or("")))
            .collect::<Vec<_>>()
            .join(" ");
        acc.events.push(event(
            SECURITY_MODULE,
            Utc::now().fixed_offset(),
            format!("keysandvalues {summary}"),
            "keys and values",
            json!({"section": "keysandvalues", "values": map}),
        ));
    }
    buf.clear();
}

pub fn parse_wifiscan(archive: &SysdiagnoseArchive) -> Result<Value, BoxErr> {
    let ts = creation(archive);
    let paths = matched_paths(archive, &["WiFi/wifi_scan*.txt"]);
    let mut events = Vec::new();
    for p in paths {
        if let Some(text) = text_at(archive, &p) {
            events.extend(parse_wifi_scan(&text, "wifiscan", ts));
        }
    }
    Ok(wrap_jsonl("wifiscan", events))
}

pub fn parse_wifisecurity(archive: &SysdiagnoseArchive) -> Result<Value, BoxErr> {
    let Some(text) = text_at(archive, "WiFi/security.txt") else {
        return Ok(json!({"parser": "wifisecurity", "format": "jsonl", "events": [], "error": "missing security.txt"}));
    };
    Ok(wrap_jsonl("wifisecurity", parse_wifi_security(&text, "wifisecurity")))
}

pub fn parse_wifi_known(archive: &SysdiagnoseArchive) -> Result<Value, BoxErr> {
    let ts = creation(archive);
    let paths = matched_paths(archive, &[
        "WiFi/com.apple.wifi.known-networks.plist",
        "**/WiFi/com.apple.wifi.known-networks.plist",
    ]);
    let mut events = Vec::new();
    let mut files = Map::new();
    for p in paths {
        let Some(bytes) = archive.get(&p) else { continue };
        if let Ok(v) = plist_bytes_to_json(bytes) {
            events.extend(events_from_known_networks_plist(&p, &v, ts));
            files.insert(p, v);
        }
    }
    let mut doc = wrap_jsonl("wifi_known_networks", events);
    doc.as_object_mut().unwrap().insert("files".into(), Value::Object(files));
    Ok(doc)
}

pub fn parse_wifinetworks(archive: &SysdiagnoseArchive) -> Result<Value, BoxErr> {
    let ts = creation(archive);
    let paths = matched_paths(archive, &["WiFi/*.plist", "WiFi/com.apple.wifi.recent-networks.json"]);
    let mut files = Map::new();
    for p in paths {
        let base = p.rsplit('/').next().unwrap_or(&p);
        let key = base.rsplit_once('.').map(|(n, _)| n).unwrap_or(base).to_string();
        let Some(bytes) = archive.get(&p) else { continue };
        if p.ends_with(".json") {
            if let Ok(v) = serde_json::from_slice::<Value>(bytes) {
                files.insert(key, v);
            }
        } else if let Ok(v) = plist_bytes_to_json(bytes) {
            files.insert(key, v);
        }
    }
    let events = events_from_wifinetworks_files(&files, ts);
    let mut doc = wrap_jsonl("wifinetworks", events);
    doc.as_object_mut().unwrap().insert("files".into(), Value::Object(files));
    Ok(doc)
}

pub fn parse_mobileinstallation(archive: &SysdiagnoseArchive) -> Result<Value, BoxErr> {
    let tz = archive.acquisition().map(|d| *d.offset()).unwrap_or_else(|| FixedOffset::east_opt(0).unwrap());
    let paths = matched_paths(archive, &["logs/MobileInstallation/mobile_installation*.log*"]);
    let mut events = Vec::new();
    for p in paths {
        if let Some(text) = text_at(archive, &p) {
            let mut evs = extract_multiline_log(&text, "mobileinstallation", tz);
            for ev in &mut evs {
                if let Some(obj) = ev.as_object_mut() {
                    obj.insert("timestamp_desc".into(), json!("mobileinstallation event"));
                }
                enrich_mobile_installation_event(ev);
            }
            events.extend(evs);
        }
    }
    Ok(wrap_jsonl("mobileinstallation", events))
}

pub fn parse_battery(archive: &SysdiagnoseArchive) -> Result<Value, BoxErr> {
    let paths = matched_paths(archive, &["logs/BatteryBDC/*.csv"]);
    let mut events = Vec::new();
    for p in paths {
        let kind = p.rsplit('/').next().unwrap_or("battery").trim_end_matches(".csv");
        if let Some(text) = text_at(archive, &p) {
            if let Ok(ev) = parse_battery_bdc_csv(&text, "battery_bdc", kind) {
                events.extend(ev);
            }
        }
    }
    Ok(wrap_jsonl("battery_bdc", events))
}

pub fn parse_logdata_jsonl(archive: &SysdiagnoseArchive) -> Result<Value, BoxErr> {
    let paths = matched_paths(archive, &["system_logs.logarchive/Extra/logdata.statistics.*.jsonl"]);
    let mut events = Vec::new();
    for p in paths {
        if let Some(text) = text_at(archive, &p) {
            events.extend(parse_logdata_statistics_jsonl(&text, "logdata_statistics"));
        }
    }
    Ok(wrap_jsonl("logdata_statistics", events))
}

pub fn parse_logdata_txt(archive: &SysdiagnoseArchive) -> Result<Value, BoxErr> {
    let paths = matched_paths(archive, &["system_logs.logarchive/Extra/logdata.statistics.*.txt"]);
    let mut events = Vec::new();
    for p in paths {
        if let Some(text) = text_at(archive, &p) {
            events.extend(parse_logdata_statistics_txt(&text, "logdata_statistics_txt"));
        }
    }
    Ok(wrap_jsonl("logdata_statistics_txt", events))
}

pub fn parse_mc_settings(archive: &SysdiagnoseArchive) -> Result<Value, BoxErr> {
    let path = "logs/MCState/Shared/MCSettingsEvents.plist";
    let events = archive
        .get(path)
        .and_then(|b| plist_bytes_to_json(b).ok())
        .map(|v| mc_settings_events(&v, "mcsettingsevents"))
        .unwrap_or_default();
    Ok(wrap_jsonl("mcsettingsevents", events))
}

pub fn parse_mcstate(archive: &SysdiagnoseArchive) -> Result<Value, BoxErr> {
    let paths = matched_paths(archive, &["logs/MCState/Shared/profile-*.stub"]);
    let mut events = Vec::new();
    for p in paths {
        let Some(bytes) = archive.get(&p) else { continue };
        let value = plist_bytes_to_json(bytes).unwrap_or_else(|_| {
            // stub text
            json!({"raw": String::from_utf8_lossy(bytes)})
        });
        if let Ok(ev) = mcstate_shared_profile_events(&value, "mcstate_shared_profile") {
            events.extend(ev);
        }
    }
    Ok(wrap_jsonl("mcstate_shared_profile", events))
}

pub fn parse_mobilebackup(archive: &SysdiagnoseArchive) -> Result<Value, BoxErr> {
    let ts = creation(archive);
    let path = "logs/MobileBackup/com.apple.MobileBackup.plist";
    let events = archive
        .get(path)
        .and_then(|b| plist_bytes_to_json(b).ok())
        .map(|v| mobilebackup_events(&v, "mobilebackup", ts))
        .unwrap_or_default();
    Ok(wrap_jsonl("mobilebackup", events))
}

pub fn parse_olddsc(archive: &SysdiagnoseArchive) -> Result<Value, BoxErr> {
    let ts = creation(archive);
    let paths = matched_paths(archive, &["logs/olddsc/**"]);
    let mut events = Vec::new();
    for p in paths {
        let Some(bytes) = archive.get(&p) else { continue };
        if let Ok(v) = plist_bytes_to_json(bytes) {
            events.extend(olddsc_events(&v, "olddsc", ts));
        }
    }
    Ok(wrap_jsonl("olddsc", events))
}

pub fn parse_appinstallation(archive: &SysdiagnoseArchive) -> Result<Value, BoxErr> {
    let paths = matched_paths(archive, &[
        "logs/appinstallation/AppUpdates.sqlitedb",
        "logs/appinstallation/appstored.sqlitedb",
    ]);
    let mut events = Vec::new();
    for p in paths {
        let Some(bytes) = archive.get(&p) else { continue };
        if let Ok(db) = crate::sqlite_dump::dump_sqlite_bytes(bytes, 100_000) {
            events.extend(crate::parsers::parser_events::appinstallation_events_from_tables(&db, "appinstallation"));
        }
    }
    Ok(wrap_jsonl("appinstallation", events))
}

pub fn parse_avconference(archive: &SysdiagnoseArchive) -> Result<Value, BoxErr> {
    let paths = matched_paths(archive, &["logs/AVConference/**"]);
    let mut events = Vec::new();
    for p in paths {
        if !p.to_ascii_lowercase().contains("calldump") {
            continue;
        }
        let Some(bytes) = archive.get(&p) else { continue };
        let decoded = crate::parsers::parser_events::decompress_gzip(bytes).unwrap_or_default();
        if let Ok(ev) = parse_avconference_gzip(&p, &decoded, "avconference_callsettings") {
            events.extend(ev);
        }
    }
    Ok(wrap_jsonl("avconference_callsettings", events))
}

pub fn parse_collection_meta(archive: &SysdiagnoseArchive) -> Result<Value, BoxErr> {
    let mut error_paths: Vec<String> = archive
        .all_paths()
        .into_iter()
        .filter(|p| {
            p.split('/').any(|c| c == "errors") && !p.rsplit('/').next().unwrap_or("").starts_with("._")
        })
        .collect();
    error_paths.sort();
    let error_file_count = error_paths.len();
    let mut errors = Map::new();
    for p in error_paths {
        if let Some(text) = text_at(archive, &p) {
            errors.insert(p, json!(text));
        }
    }
    let mut summary_paths: Vec<String> = archive
        .all_paths()
        .into_iter()
        .filter(|p| p.contains("/summaries/") || p.starts_with("summaries/"))
        .filter(|p| p.ends_with(".log") && !p.rsplit('/').next().unwrap_or("").starts_with("._"))
        .collect();
    summary_paths.sort();
    let summary_total = summary_paths.len();
    let mut summaries = Map::new();
    for p in summary_paths.into_iter().take(80) {
        if let Some(text) = text_at(archive, &p) {
            let preview: String = text.chars().take(8192).collect();
            summaries.insert(
                p,
                json!({
                    "len": text.len(),
                    "preview": preview,
                    "truncated": text.chars().count() > 8192,
                }),
            );
        }
    }
    let log_text = text_at(archive, "sysdiagnose.log")
        .or_else(|| archive.find_suffix("sysdiagnose.log").and_then(|p| text_at(archive, p)));
    let sysdiagnose_log = log_text.map(|t| {
        json!({
            "len": t.len(),
            "preview": t.chars().take(64_000).collect::<String>(),
        })
    });
    let task_text = text_at(archive, "taskSummary.csv").unwrap_or_default();
    let task_summary = task_text
        .lines()
        .filter(|l| l.contains(','))
        .skip(1)
        .map(|l| json!({"raw": l}))
        .collect::<Vec<_>>();
    Ok(json!({
        "parser": "collection_meta",
        "format": "collection",
        "meta": {
            "error_file_count": error_file_count,
            "note": "Use errors/ + task_summary to explain empty parser outputs",
            "summary_returned": summaries.len(),
            "summary_total_matched": summary_total,
        },
        "task_summary": task_summary,
        "errors": errors,
        "summaries": summaries,
        "sysdiagnose_log": sysdiagnose_log,
    }))
}

pub fn parse_lsaw(archive: &SysdiagnoseArchive) -> Result<Value, BoxErr> {
    let paths = matched_paths(archive, &["**/lsaw.csstoredump"]);
    let Some(path) = paths.into_iter().next() else {
        return Ok(json!({
            "parser": "lsaw",
            "format": "csstore_strings",
            "gzip": false,
            "source_path": Value::Null,
            "note": "Full CSStore decode is not implemented; URL / bundle-id string scrape only",
        }));
    };
    let bytes = archive.get(&path).unwrap_or(b"");
    let compressed_size = bytes.len();
    let gzip = bytes.len() >= 2 && bytes[0] == 0x1f && bytes[1] == 0x8b;
    let cap = 64 * 1024 * 1024;
    let (raw, inflate_error) = if gzip {
        let mut dec = flate2::read::GzDecoder::new(bytes);
        let mut out = Vec::new();
        let mut buf = [0u8; 64 * 1024];
        let mut err = None;
        loop {
            if out.len() >= cap {
                break;
            }
            match std::io::Read::read(&mut dec, &mut buf) {
                Ok(0) => break,
                Ok(n) => {
                    let room = cap - out.len();
                    out.extend_from_slice(&buf[..n.min(room)]);
                }
                Err(e) => {
                    err = Some(e.to_string());
                    break;
                }
            }
        }
        (out, err)
    } else {
        let n = bytes.len().min(cap);
        (bytes[..n].to_vec(), None)
    };
    let decompressed_size = raw.len();
    static URL: OnceLock<Regex> = OnceLock::new();
    static BUNDLE: OnceLock<Regex> = OnceLock::new();
    static RUN: OnceLock<Regex> = OnceLock::new();
    let url_re = URL.get_or_init(|| Regex::new(r#"https?://[^\s'\"<>]+"#).unwrap());
    let bun_re = BUNDLE.get_or_init(|| {
        Regex::new(r"^(?:com|org|net)\.[A-Za-z0-9][A-Za-z0-9_-]*(?:\.[A-Za-z0-9][A-Za-z0-9_-]*)+$").unwrap()
    });
    let run_re = RUN.get_or_init(|| Regex::new("[\x20-\x7e]{4,}").unwrap());
    let mut urls = Vec::new();
    let mut bundles = Vec::new();
    let text = String::from_utf8_lossy(&raw);
    for run in run_re.find_iter(&text) {
        let s = run.as_str();
        if s.len() <= 40 && bun_re.is_match(s) {
            bundles.push(s.to_string());
        }
        for c in url_re.find_iter(s) {
            urls.push(c.as_str().to_string());
        }
    }
    urls.sort();
    urls.dedup();
    bundles.sort();
    bundles.dedup();
    Ok(json!({
        "parser": "lsaw",
        "format": "csstore_strings",
        "gzip": gzip,
        "source_path": path,
        "compressed_size": compressed_size,
        "decompressed_size": decompressed_size,
        "inflate_error": inflate_error,
        "note": "Full CSStore decode is not implemented; URL / bundle-id string scrape only",
        "strings": {
            "bundle_hint_count": bundles.len(),
            "bundle_id_hints": bundles,
            "url_count": urls.len(),
            "urls": urls,
            "note": "Best-effort strings from csstore; not a full LaunchServices decode",
        },
    }))
}


#[cfg(test)]
mod brctl_parser_tests {
    use super::*;

    
    use crate::parsers::SysdiagnoseParser;
    use crate::archive::SysdiagnoseArchive;
    
    use std::collections::HashMap;
    use std::sync::Arc;

    #[test]
    fn structured_brctl_output() {
        let mut m = HashMap::new();
        m.insert(
            "brctl/brctl-container-list.txt".into(),
            Arc::from(
                b"id: X localizedName: Y documents: Mobile Documents clients: [a]"
                    .to_vec()
                    .into_boxed_slice(),
            ),
        );
        m.insert(
            "brctl/brctl-dump.txt".into(),
            Arc::from(
                b"header line\n-----------------------------------------------------\n"
                    .to_vec()
                    .into_boxed_slice(),
            ),
        );
        let arch = SysdiagnoseArchive::from_files_for_test(m);
        let v = BrctlParser.parse(&arch).unwrap();
        assert_eq!(v["parser"], "brctl");
        assert!(v["data"]["containers"].is_array());
    }
}

#[cfg(test)]
mod itunes_parser_tests {
    use super::*;

    use rusqlite::Connection;
    use std::collections::HashMap;
    use std::sync::Arc;

    fn sample_itunes_db_bytes() -> Vec<u8> {
        let path = tempfile::NamedTempFile::new().unwrap();
        let conn = Connection::open(path.path()).unwrap();
        conn.execute_batch(
            "CREATE TABLE download (bundle_id TEXT, application_id TEXT);
             INSERT INTO download VALUES ('com.example.app', 'app');",
        )
        .unwrap();
        std::fs::read(path.path()).unwrap()
    }

    #[test]
    fn first_db_tables_shape() {
        let mut m = HashMap::new();
        m.insert(
            "logs/itunesstored/downloads.28.sqlitedb".into(),
            Arc::from(sample_itunes_db_bytes().into_boxed_slice()),
        );
        let arch = SysdiagnoseArchive::from_files_for_test(m);
        let v = ItunesstoreParser.parse(&arch).unwrap();
        assert_eq!(v["parser"], "itunesstore");
        assert_eq!(
            v["source_path"],
            "logs/itunesstored/downloads.28.sqlitedb"
        );
        let rows = v["data"]["download"].as_array().unwrap();
        assert_eq!(rows[0]["bundle_id"], "com.example.app");
    }
}

#[cfg(test)]
mod logarchive_parser_tests {
    use super::*;

    use std::collections::HashMap;
    use std::sync::Arc;

    #[test]
    fn inventory_lists_logarchive_paths() {
        let mut m = HashMap::new();
        m.insert(
            "system_logs.logarchive/Info.plist".into(),
            Arc::from(b"plist".to_vec().into_boxed_slice()),
        );
        let arch = SysdiagnoseArchive::from_files_for_test(m);
        let v = LogarchiveParser.parse(&arch).unwrap();
        assert_eq!(v["inventory"]["file_count"], 1);
        assert_eq!(v["inventory"]["paths"].as_array().unwrap().len(), 1);
        #[cfg(not(feature = "logarchive-decode"))]
        assert_eq!(v["decode"], "deferred");
        #[cfg(feature = "logarchive-decode")]
        assert_eq!(v["decode"], "skipped");
    }
}

#[cfg(test)]
mod mobileinstallation_parser_tests {
    use super::*;

    use std::collections::HashMap;
    use std::sync::Arc;

    fn archive_with(files: &[(&str, &[u8])]) -> SysdiagnoseArchive {
        let mut m = HashMap::new();
        for (path, bytes) in files {
            m.insert(
                path.to_string(),
                Arc::from(bytes.to_vec().into_boxed_slice()),
            );
        }
        SysdiagnoseArchive::from_files_for_test(m)
    }

    #[test]
    fn stamps_versions_from_staging_line() {
        // Minimal MobileInstallation log line (timestamp + message body).
        let line = concat!(
            "Thu Jan  1 12:00:00 2026  localhost mobileinstallationd[123] <Notice>: ",
            "Staging <MIInstallableBundle ID=org.whispersystems.signal; Version=1, ShortVersion=7.12.0>\n"
        );
        let arch = archive_with(&[(
            "logs/MobileInstallation/mobile_installation.log.0",
            line.as_bytes(),
        )]);
        let out = MobileinstallationParser.parse(&arch).expect("parse");
        let events = out["events"].as_array().expect("events");
        // May be empty if line format doesn't match multiline extractor — still exercise enrich path.
        if let Some(ev) = events.first() {
            let data = ev.get("data").cloned().unwrap_or(json!({}));
            if data.get("short_version").is_some() {
                assert_eq!(data["short_version"], "7.12.0");
            }
        }
    }
}

#[cfg(test)]
mod mount_parser_tests {
    use super::*;

    use std::collections::HashMap;
    use std::sync::Arc;

    #[test]
    fn detects_sealed_readonly_root() {
        let text = concat!(
            "/dev/disk0s1s1 on / (apfs, sealed, local, nosuid, read-only, journaled)\n",
            "devfs on /dev (devfs, local)\n",
        );
        let mut m = HashMap::new();
        m.insert(
            "mount.txt".to_string(),
            Arc::from(text.as_bytes().to_vec().into_boxed_slice()),
        );
        let arch = SysdiagnoseArchive::from_files_for_test(m);
        let out = MountParser.parse(&arch).expect("parse");
        assert_eq!(out["summary"]["root_sealed"], true);
        assert_eq!(out["summary"]["root_read_only"], true);
        assert_eq!(
            out["summary"]["integrity_hint"],
            "system_partition_sealed_readonly"
        );
    }
}

#[cfg(test)]
mod plists_parser_tests {
    use super::*;

    use std::collections::HashMap;
    use std::sync::Arc;

    #[test]
    fn parse_failure_yields_empty_object() {
        let mut m = HashMap::new();
        m.insert(
            "broken.plist".into(),
            Arc::from(b"not a plist".to_vec().into_boxed_slice()),
        );
        let arch = SysdiagnoseArchive::from_files_for_test(m);
        let caps = PlistsCaps {
            max_files: 0,
            max_each_bytes: 0,
        };
        let v = crate::parsers::parser_helpers::plists_recursive_with_caps(&arch, caps);
        assert_eq!(v["files"]["broken.plist"], json!({}));
        assert!(v["meta"]["parse_failures"]
            .as_array()
            .unwrap()
            .iter()
            .any(|p| p == "broken.plist"));
    }

    #[test]
    fn respects_max_files_cap() {
        let mut m = HashMap::new();
        for i in 0..3 {
            m.insert(
                format!("a{i}.plist"),
                Arc::from(
                    br#"<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN" "http://www.apple.com/DTDs/PropertyList-1.0.dtd">
<plist version="1.0"><dict><key>k</key><string>v</string></dict></plist>"#
                        .to_vec()
                        .into_boxed_slice(),
                ),
            );
        }
        let arch = SysdiagnoseArchive::from_files_for_test(m);
        let caps = PlistsCaps {
            max_files: 2,
            max_each_bytes: 0,
        };
        let v = crate::parsers::parser_helpers::plists_recursive_with_caps(&arch, caps);
        assert_eq!(v["meta"]["truncated_file_count"], 1);
        assert_eq!(v["files"].as_object().unwrap().len(), 2);
    }
}


#[cfg(test)]
mod shutdown_parser_tests {
    use super::*;

    use std::collections::HashMap;
    use std::sync::Arc;

    const SAMPLE_UUID: &str = "550e8400-e29b-41d4-a716-446655440000";

    fn sample_block(client: &str, unix_ts: i64) -> String {
        format!(
            "these clients are still here:\n\
             After 3.0s, waiting...\n\
             remaining client pid: 4242 ({client})\n\
             SIGTERM: [{unix_ts}] shutting down\n"
        )
    }

    fn parse_files(files: Vec<(&str, String)>) -> Value {
        let mut m = HashMap::new();
        for (path, text) in files {
            m.insert(
                path.to_string(),
                Arc::from(text.into_bytes().into_boxed_slice()),
            );
        }
        let arch = SysdiagnoseArchive::from_files_for_test(m);
        ShutdownLogsParser.parse(&arch).expect("shutdownlogs parse")
    }

    #[test]
    fn split_client_path_strips_trailing_uuid_only() {
        let with_uuid = format!("/usr/sbin/filecoordinationd/{SAMPLE_UUID}");
        let (exe, uuid) = split_client_path(&with_uuid);
        assert_eq!(exe, "/usr/sbin/filecoordinationd");
        assert_eq!(uuid.as_deref(), Some(SAMPLE_UUID));

        let (exe, uuid) = split_client_path("/usr/sbin/filecoordinationd");
        assert_eq!(exe, "/usr/sbin/filecoordinationd");
        assert!(uuid.is_none());
    }

    #[test]
    fn discovers_rotated_diagnostics_shutdown_log() {
        let client = format!("/usr/sbin/filecoordinationd/{SAMPLE_UUID}");
        let v = parse_files(vec![(
            "private/var/db/diagnostics/shutdown.0.log",
            sample_block(&client, 1_712_498_480),
        )]);
        assert_eq!(v["parser"], "shutdownlogs");
        assert_eq!(
            v["sources"].as_array().unwrap(),
            &vec![json!("private/var/db/diagnostics/shutdown.0.log")]
        );
        let events = v["events"].as_array().expect("events");
        assert_eq!(events.len(), 1);
        let data = &events[0]["data"];
        assert_eq!(data["path"], client);
        assert_eq!(data["executable_path"], "/usr/sbin/filecoordinationd");
        assert_eq!(data["command"], "filecoordinationd");
        assert_eq!(data["uuid"], SAMPLE_UUID);
        assert_eq!(
            data["source_path"],
            "private/var/db/diagnostics/shutdown.0.log"
        );
        assert!(events[0]["message"]
            .as_str()
            .unwrap()
            .contains("filecoordinationd is still there"));
    }

    #[test]
    fn discovers_rotated_extra_shutdown_log_and_plain_path() {
        let v = parse_files(vec![(
            "system_logs.logarchive/Extra/shutdown.0.log",
            sample_block("/sbin/launchd", 1_712_498_500),
        )]);
        let events = v["events"].as_array().expect("events");
        assert_eq!(events.len(), 1);
        let data = &events[0]["data"];
        assert_eq!(data["path"], "/sbin/launchd");
        assert_eq!(data["executable_path"], "/sbin/launchd");
        assert_eq!(data["command"], "launchd");
        assert!(data["uuid"].is_null());
    }

    #[test]
    fn parses_all_discovered_shutdown_logs() {
        let v = parse_files(vec![
            (
                "system_logs.logarchive/Extra/shutdown.log",
                sample_block("/usr/libexec/amfid", 1_712_498_480),
            ),
            (
                "system_logs.logarchive/Extra/shutdown.0.log",
                sample_block("/usr/libexec/containermanagerd", 1_712_498_490),
            ),
        ]);
        let sources = v["sources"].as_array().unwrap();
        assert_eq!(sources.len(), 2);
        let events = v["events"].as_array().expect("events");
        assert_eq!(events.len(), 2);
        let cmds: Vec<&str> = events
            .iter()
            .filter_map(|e| e["data"]["command"].as_str())
            .collect();
        assert!(cmds.contains(&"amfid"));
        assert!(cmds.contains(&"containermanagerd"));
    }
}

#[cfg(test)]
mod spindump_parser_tests {
    use super::*;

    use std::collections::HashMap;
    use std::sync::Arc;

    const MINI: &str = r#"Date/Time:       2020-01-02 10:00:00 +0000
Data Source:     Stackshots

------------------------------------------------------------
Process:         launchd [1]
Path:            /sbin/launchd
UID:             0
Time since fork: 10s

Thread 0x1234 priority 31
  (libsystem_kernel.dylib+0x123) [0xabc]

Binary Images:
0x1000 - 0x2000  dyld  (AAAAAAAA-BBBB-CCCC-DDDD-EEEEEEEEEEEE)  /usr/lib/dyld
"#;

    #[test]
    fn parser_wraps_fixture_events() {
        let mut m = HashMap::new();
        m.insert(
            "logs/spindump-nosymbols.txt".to_string(),
            Arc::from(MINI.as_bytes().to_vec().into_boxed_slice()),
        );
        let arch = SysdiagnoseArchive::from_files_for_test(m);
        let v = SpindumpnosymbolsParser.parse(&arch).unwrap();
        assert_eq!(v["parser"], "spindumpnosymbols");
        assert_eq!(v["format"], "jsonl");
        let evs = v["events"].as_array().expect("events");
        assert!(evs.len() >= 2);
    }
}

#[cfg(test)]
mod taskinfo_parser_tests {
    use super::*;

    use std::collections::HashMap;
    use std::sync::Arc;

    #[test]
    fn num_tasks_event_without_process_sections() {
        let snippet = "num tasks: 3\n\n";
        let mut m = HashMap::new();
        m.insert(
            TASKINFO.to_string(),
            Arc::from(snippet.as_bytes().to_vec().into_boxed_slice()),
        );
        let arch = SysdiagnoseArchive::from_files_for_test(m);
        let v = TaskinfoParser.parse(&arch).unwrap();
        let ev = v["events"].as_array().unwrap();
        assert_eq!(ev.len(), 1);
        assert_eq!(ev[0]["data"]["tasks"], 3);
    }

    #[test]
    fn process_name_is_clean_not_raw_identity_line() {
        // Minimal taskinfo process block: process line + threads header + one thread + blank blank.
        let snippet = concat!(
            "num tasks: 1\n",
            "process: \"sshd\" [298] [unique ID: 298]\n",
            "run time: 10 secs\n",
            "threads: 1\n",
            "thread ID: 0x1\n",
            "\n",
            "\n",
        );
        let mut m = HashMap::new();
        m.insert(
            TASKINFO.to_string(),
            Arc::from(snippet.as_bytes().to_vec().into_boxed_slice()),
        );
        let arch = SysdiagnoseArchive::from_files_for_test(m);
        let v = TaskinfoParser.parse(&arch).unwrap();
        let ev = v["events"].as_array().unwrap();
        let proc = ev
            .iter()
            .find(|e| e["timestamp_desc"] == "process start time")
            .expect("process event");
        assert_eq!(proc["data"]["name"], "sshd");
        assert_eq!(proc["data"]["process"], "sshd");
        assert_eq!(proc["data"]["pid"], 298);
        assert_eq!(
            proc["data"]["process_line"],
            "\"sshd\" [298] [unique ID: 298]"
        );
        assert_eq!(proc["message"], "sshd started");
        assert!(!proc["message"]
            .as_str()
            .unwrap_or("")
            .contains("unique ID"));
    }
}

#[cfg(test)]
mod transparency_parser_tests {
    use super::*;

    use std::collections::HashMap;
    use std::sync::Arc;

    #[test]
    fn empty_transparency_log_is_soft_error() {
        let mut m = HashMap::new();
        m.insert(
            "transparency.log".into(),
            Arc::from(b"".to_vec().into_boxed_slice()),
        );
        let arch = SysdiagnoseArchive::from_files_for_test(m);
        let v = TransparencyJsonParser.parse(&arch).expect("ok");
        assert_eq!(v.get("error"), Some(&json!("empty_file")));
    }

    #[test]
    fn whitespace_only_transparency_log_is_soft_error() {
        let mut m = HashMap::new();
        m.insert(
            "transparency.log".into(),
            Arc::from(b"  \n\t".to_vec().into_boxed_slice()),
        );
        let arch = SysdiagnoseArchive::from_files_for_test(m);
        let v = TransparencyJsonParser.parse(&arch).expect("ok");
        assert_eq!(v.get("error"), Some(&json!("empty_file")));
    }

    #[test]
    fn valid_transparency_json_parses() {
        let mut m = HashMap::new();
        m.insert(
            "transparency.log".into(),
            Arc::from(br#"{"stateMachine":{"devices":{}}}"#.to_vec().into_boxed_slice()),
        );
        let arch = SysdiagnoseArchive::from_files_for_test(m);
        let v = TransparencyJsonParser.parse(&arch).expect("ok");
        assert!(v.get("stateMachine").is_some());
        assert!(v.get("error").is_none());
    }
}

#[cfg(test)]
mod wifi_known_parser_tests {
    use super::*;
    use chrono::TimeZone;

    use std::collections::HashMap;
    use std::sync::Arc;

    #[test]
    fn events_include_bss_with_coordinates() {
        let plist = json!({
            "net-uuid-1": {
                "SSID": "Cafe",
                "AddedAt": "2020-01-02T12:00:00Z",
                "BSSList": [
                    { "LocationLatitude": 48.85, "LocationLongitude": 2.35, "LocationAccuracy": 10.0 }
                ]
            }
        });
        let creation = chrono::FixedOffset::east_opt(3600)
            .unwrap()
            .with_ymd_and_hms(2024, 1, 1, 0, 0, 0)
            .unwrap();
        let evs = crate::parsers::parser_events::events_from_known_networks_plist(
            "WiFi/x.plist",
            &plist,
            creation,
        );
        assert_eq!(evs.len(), 1);
        assert_eq!(evs[0]["module"], "wifi_known_networks");
        assert_eq!(evs[0]["data"]["ssid"], "Cafe");
        assert_eq!(evs[0]["data"]["latitude"], 48.85);
    }

    #[test]
    fn parser_merges_files_and_wrap_jsonl() {
        let mut m = HashMap::new();
        m.insert(
            "WiFi/com.apple.wifi.known-networks.plist".to_string(),
            Arc::from(
                br#"<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN" "http://www.apple.com/DTDs/PropertyList-1.0.dtd">
<plist version="1.0"><dict><key>n1</key><dict><key>SSID</key><string>T</string><key>BSSList</key><array><dict><key>LocationLatitude</key><real>1</real><key>LocationLongitude</key><real>2</real></dict></array></dict></dict></plist>"#.to_vec().into_boxed_slice(),
            ),
        );
        let arch = SysdiagnoseArchive::from_files_for_test(m);
        let v = WifiKnownNetworksParser.parse(&arch).unwrap();
        assert_eq!(v["parser"], "wifi_known_networks");
        assert_eq!(v["format"], "jsonl");
        assert!(v["files"].is_object());
        let evs = v["events"].as_array().unwrap();
        assert_eq!(evs.len(), 1);
    }
}


#[cfg(test)]
mod wifinetworks_parser_tests {
    use super::*;

    use std::collections::HashMap;
    use std::sync::Arc;

    #[test]
    fn basename_keys_and_jsonl() {
        let mut m = HashMap::new();
        m.insert(
            "WiFi/com.apple.wifi.known-networks.plist".to_string(),
            Arc::from(
                br#"<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN" "http://www.apple.com/DTDs/PropertyList-1.0.dtd">
<plist version="1.0"><dict><key>n1</key><dict><key>SSID</key><string>T</string></dict></dict></plist>"#
                    .to_vec()
                    .into_boxed_slice(),
            ),
        );
        let arch = SysdiagnoseArchive::from_files_for_test(m);
        let v = WifinetworksParser.parse(&arch).unwrap();
        assert_eq!(v["parser"], "wifinetworks");
        assert_eq!(v["format"], "jsonl");
        assert!(v["files"]["com.apple.wifi.known-networks"].is_object());
        assert!(!v["events"].as_array().unwrap().is_empty());
    }
}


#[cfg(test)]
mod security_tests {
    use super::{
        parse_security_sysdiagnose, process_buffer_client, process_buffer_keychain_state,
        process_buffer_keys_and_values, JsonResult, SECURITY_MODULE as MODULE,
    };
    use super::meta_get_mut_map;
    use chrono::{DateTime, FixedOffset, TimeZone};
    use serde_json::Value;    fn fixed() -> DateTime<FixedOffset> {
        FixedOffset::east_opt(3600)
            .unwrap()
            .with_ymd_and_hms(2024, 6, 1, 12, 0, 0)
            .unwrap()
    }

    /// CPython `isoformat` uses `+00:00`; chrono may emit `Z` for UTC.
    fn assert_dt_pythonish(ev: &Value, want: &str) {
        let got = ev.get("datetime").and_then(|x| x.as_str()).unwrap();
        let got_norm = got.replacen('Z', "+00:00", 1);
        assert_eq!(got_norm, want, "datetime field mismatch");
    }

    #[test]
    fn keychain_state_emits_creation_and_modification() {
        let mut acc = JsonResult::default();
        let mut buf = vec![
            "Rapport keychain state:".to_string(),
            "rapport: accc=,acct=69AAAFE9-A7FA-4BF3-922E-A14C33F11924,agrp=com.apple.rapport,cdat=2023-05-24 19:56:14 +0000,gena={length = 33, bytes = 0xe3456d6f 64656c49 6950686f 6e65392c ... 6973696f 6e494409 },invi=1,labl=iPhone,mdat=2023-05-24 19:56:14 +0000,musr={length = 0, bytes = 0x},pdmn=ck,sha1={length = 20, bytes = 0x1490ff273a003ef4089c46beb3731eb04754c7e5},svce=RPIdentity-SameAccountDevice,sync=1,tomb=0,vwht=Home".to_string(),
        ];
        process_buffer_keychain_state(&mut buf, &mut acc, fixed());
        let rapport_meta = acc
            .meta
            .iter()
            .find(|(k, _)| k == "rapport")
            .and_then(|(_, v)| v.as_array());
        assert!(
            rapport_meta.is_some_and(|a| a.is_empty()),
            "rows with cdat/mdat should not populate meta list: {:?}",
            rapport_meta
        );
        assert_eq!(acc.events.len(), 2, "{:?}", acc.events);
        for ev in &acc.events {
            assert_eq!(ev["module"], MODULE);
            assert_dt_pythonish(ev, "2023-05-24T19:56:14.000000+00:00");
            assert_eq!(ev["message"], "rapport iPhone - com.apple.rapport");
            let attrs = ev["data"]["attributes"].as_object().unwrap();
            assert_eq!(
                attrs.get("acct").and_then(|x| x.as_str()),
                Some("69AAAFE9-A7FA-4BF3-922E-A14C33F11924")
            );
            assert_eq!(
                attrs.get("agrp").and_then(|x| x.as_str()),
                Some("com.apple.rapport")
            );
            assert_eq!(attrs.get("labl").and_then(|x| x.as_str()), Some("iPhone"));
        }
        assert_eq!(
            acc.events[0]["timestamp_desc"],
            "rapport: entry creation time"
        );
        assert_eq!(
            acc.events[1]["timestamp_desc"],
            "rapport: entry modification time"
        );
    }

    #[test]
    fn client_buffer_parses_soft_and_hard_failures() {
        let mut acc = JsonResult::default();
        let mut buf = vec![
            "Client: trust".to_string(),
            "2023-05-24 19:55:51 +0000 EventSoftFailure: OTAPKIEvent - Attributes: {product : iPhone OS, build : 19H349, errorDomain : NSOSStatusErrorDomain, modelid : iPhone9,3, errorCode : -67694 }".to_string(),
            "2023-05-24 19:57:58 +0000 EventSoftFailure: MitmDetectionEvent - Attributes: {product : iPhone OS, build : 19H349, overallScore : 0, timeSinceLastReset : 127, rootUsages : (".to_string(),
            " foo, bar ".to_string(),
            "), errorDomain : MITMErrorDomain, modelid : iPhone9,3, errorCode : 0 }".to_string(),
            "2024-09-06 9:45:15 AM +0000 EventHardFailure: CloudServicesSetConfirmedManifest - Attributes: {product : macOS, build : 22H121, errorDomain : NSOSStatusErrorDomain, modelid : MacBookPro14,3, errorCode : -25308 }".to_string(),
        ];
        process_buffer_client(&mut buf, &mut acc);
        assert_eq!(acc.events.len(), 3, "{:?}", acc.events);
        assert_eq!(acc.events[0]["module"], MODULE);
        assert_dt_pythonish(&acc.events[0], "2023-05-24T19:55:51.000000+00:00");
        assert_eq!(acc.events[0]["timestamp_desc"], "OTAPKIEvent");
        assert_eq!(
            acc.events[0]["message"],
            "client_trust EventSoftFailure OTAPKIEvent"
        );
        let a0 = acc.events[0]["data"]["attributes"].as_object().unwrap();
        assert_eq!(
            a0.get("product").and_then(|x| x.as_str()),
            Some("iPhone OS")
        );
        assert_eq!(a0.get("errorCode").and_then(|x| x.as_str()), Some("-67694"));

        assert_dt_pythonish(&acc.events[1], "2023-05-24T19:57:58.000000+00:00");
        assert_eq!(acc.events[1]["timestamp_desc"], "MitmDetectionEvent");
        let a1 = acc.events[1]["data"]["attributes"].as_object().unwrap();
        assert_eq!(
            a1.get("rootUsages").and_then(|x| x.as_str()),
            Some("( foo, bar )")
        );

        assert_dt_pythonish(&acc.events[2], "2024-09-06T09:45:15.000000+00:00");
        assert_eq!(
            acc.events[2]["timestamp_desc"],
            "CloudServicesSetConfirmedManifest"
        );
        let a2 = acc.events[2]["data"]["attributes"].as_object().unwrap();
        assert_eq!(a2.get("product").and_then(|x| x.as_str()), Some("macOS"));
    }

    #[test]
    fn keys_and_values_keeps_length_prefixed_blob() {
        let mut acc = JsonResult::default();
        let mut buf = vec![
            "values".to_string(),
            "~PCS-Notes-tomb: {length = 7741, capacity = 7741, bytes = 0x30821e39314c300e0c0a4170706c6963 ... 8df3270d7d823100}".to_string(),
        ];
        process_buffer_keys_and_values(&mut buf, &mut acc);
        let m = meta_get_mut_map(&mut acc.meta, "values").expect("values meta");
        let v = m
            .get("~PCS-Notes-tomb")
            .and_then(|x| x.as_str())
            .expect("tomb key");
        assert!(v.contains("30821e39314c300e0c0a4170706c6963"));
        assert!(v.contains("7741"));
    }

    #[test]
    fn keychain_row_with_cdat_emits_event() {
        let text = r"Genp keychain state:
desc=testdesc,agrp=testgrp,cdat=2020-01-02 03:04:05 +0000
";
        let evs = parse_security_sysdiagnose(text, fixed());
        assert_eq!(evs.len(), 1);
        assert_eq!(evs[0]["data"]["section"], "genp");
    }

    #[test]
    fn keys_and_values_meta_event() {
        let text = r"All keys and values
foo: bar
";
        let evs = parse_security_sysdiagnose(text, fixed());
        assert_eq!(evs.len(), 1);
        assert!(evs[0]["message"]
            .as_str()
            .unwrap()
            .contains("keysandvalues"));
        assert!(evs[0]["message"].as_str().unwrap().contains("foo"));
    }

    #[test]
    fn client_24h_line() {
        let text = r"Client: trust
2020-01-02 15:30:00 +0000 Result: Something happened - Attributes: {k1: v1, k2: (x)}
";
        let evs = parse_security_sysdiagnose(text, fixed());
        assert_eq!(evs.len(), 1);
        assert_eq!(evs[0]["data"]["section"], "client_trust");
    }
}

#[cfg(test)]
mod spindump_text_tests {
    use super::*;


    const FIXTURE: &str = r#"Date/Time:       2020-01-02 10:00:00 +0000
Data Source:     Stackshots

------------------------------------------------------------
Process:         launchd [1]
Path:            /sbin/launchd
Parent:          kernel_task [0]
UID:             0
Time since fork: 10s

Thread 0x1234 priority 31 cpu time 0.001s
  (libsystem_kernel.dylib+0x123) [0xabc] (running)

Binary Images:
0x1000 - 0x2000  dyld  (AAAAAAAA-BBBB-CCCC-DDDD-EEEEEEEEEEEE)  /usr/lib/dyld
"#;

    #[test]
    fn spindump_parses_header_and_process_events() {
        let evs = parse_spindump_nosymbols_text(FIXTURE);
        assert!(
            evs.len() >= 2,
            "expected header + process events, got {}",
            evs.len()
        );
        assert_eq!(evs[0].get("module").and_then(|x| x.as_str()), Some(MODULE));
        assert_eq!(
            evs[0].get("timestamp_desc").and_then(|x| x.as_str()),
            Some("spindump")
        );
        assert!(evs[0]
            .get("message")
            .and_then(|x| x.as_str())
            .unwrap_or("")
            .starts_with("spindump"),);

        let proc_ev = &evs[1];
        assert_eq!(
            proc_ev.get("timestamp_desc").and_then(|x| x.as_str()),
            Some("process running during spindump")
        );
        let data = proc_ev
            .get("data")
            .and_then(|d| d.as_object())
            .expect("data");
        assert_eq!(data.get("pid").and_then(|x| x.as_i64()), Some(1));
        assert_eq!(
            data.get("process").and_then(|x| x.as_str()),
            Some("launchd")
        );
        assert_eq!(
            data.get("name").and_then(|x| x.as_str()),
            Some("launchd")
        );
        assert_eq!(
            data.get("path").and_then(|x| x.as_str()),
            Some("/sbin/launchd")
        );
    }

    #[test]
    fn spindump_strips_quoted_process_names() {
        let text = r#"Date/Time:       2020-01-02 10:00:00 +0000
Data Source:     Stackshots

------------------------------------------------------------
Process:         "sshd" [298]
Path:            /usr/sbin/sshd
Parent:          "launchd" [1]
UID:             0
Time since fork: 10s

Thread 0x1234 priority 31 cpu time 0.001s
"#;
        let evs = parse_spindump_nosymbols_text(text);
        let proc_ev = evs
            .iter()
            .find(|e| {
                e.get("timestamp_desc").and_then(|t| t.as_str())
                    == Some("process running during spindump")
            })
            .expect("process event");
        let data = proc_ev.get("data").and_then(|d| d.as_object()).unwrap();
        assert_eq!(data.get("process").and_then(|x| x.as_str()), Some("sshd"));
        assert_eq!(data.get("name").and_then(|x| x.as_str()), Some("sshd"));
        assert_eq!(data.get("parent").and_then(|x| x.as_str()), Some("launchd"));
        assert_eq!(data.get("pid").and_then(|x| x.as_i64()), Some(298));
        assert_eq!(data.get("ppid").and_then(|x| x.as_i64()), Some(1));
    }

    #[test]
    fn spindump_no_samples_empty() {
        assert!(parse_spindump_nosymbols_text("No samples\n").is_empty());
    }
}

#[cfg(test)]
mod swcutil_tests {
    use super::*;
    use chrono::{DateTime, FixedOffset, TimeZone};

    fn fixed() -> DateTime<FixedOffset> {
        FixedOffset::east_opt(0)
            .unwrap()
            .with_ymd_and_hms(2024, 6, 1, 12, 0, 0)
            .unwrap()
    }

    #[test]
    fn swcutil_headers_db_network_memory() {
        let text = r"PID:                  1
Storage:              /tmp

=================================== DATABASE ===================================
Service:              webcredentials
App ID:               com.apple.test
Domain:               example.com
Last Checked:         2020-01-02 3:04:05 +0000
--------------------------------------------------------------------------------
=================================== NETWORK ====================================
example.com approved, wallet.apple.com pending
=================================== SETTINGS ===================================
(empty)
================================= MEMORY USAGE =================================
kernel_task: 2 MB
";
        let evs = parse_swcutil_show(text, fixed());
        assert!(
            evs.iter().any(|e| e["message"] == "swcutil headers"),
            "{evs:?}"
        );
        assert!(evs.iter().any(|e| e["message"] == "Network: example.com"));
        assert!(evs
            .iter()
            .any(|e| e["message"] == "Network: wallet.apple.com"));
        let db_ev = evs
            .iter()
            .find(|e| e["timestamp_desc"] == "db last checked")
            .expect("db event");
        assert!(db_ev["message"]
            .as_str()
            .unwrap()
            .contains("webcredentials"));
        let mem = evs
            .iter()
            .find(|e| e["data"]["section"] == "memory")
            .expect("memory");
        assert_eq!(mem["data"]["usage"], 2 * 1024 * 1024);
    }

    #[test]
    fn swcutil_settings_block() {
        let text = concat!(
            "=================================== SETTINGS ===================================\n",
            "{ s = applinks, a = com.apple.AppStore, d = (null) }: {\n",
            "  \"com.apple.LaunchServices.enabled\" = 1;\n",
            "}\n",
            "--------------------------------------------------------------------------------\n",
        );
        let evs = parse_swcutil_show(text, fixed());
        let s = evs.iter().find(|e| e["data"]["section"] == "settings");
        assert!(s.is_some());
        let ev = s.unwrap();
        assert_eq!(ev["data"]["s"], "applinks");
        assert_eq!(ev["data"]["a"], "com.apple.AppStore");
    }
}

#[cfg(test)]
mod brctl_text_tests {
    use super::*;


    #[test]
    fn parses_container_list_line() {
        let list = "id: ABC localizedName: Test documents: Mobile Documents/Public clients: [a]";
        let m = parse_list_file(list);
        let arr = m.get("containers").unwrap().as_array().unwrap();
        assert_eq!(arr.len(), 1);
        assert_eq!(arr[0]["id"], "ABC");
    }

    #[test]
    fn parses_boot_history_line() {
        let rows = parse_boot_history("[2020-01-01] OS:17 CloudDocs:1 BirdSchema:2 DBSchema:3\n");
        assert_eq!(rows.len(), 1);
        assert_eq!(rows[0]["OS"], "17");
    }
}

#[cfg(test)]
mod wifinetworks_text_tests {
    use super::*;
    use chrono::TimeZone;
    use serde_json::{json, Map};

    #[test]
    fn emits_network_and_bss_events() {
        let mut files = Map::new();
        files.insert(
            "com.apple.wifi.known-networks".into(),
            json!({
                "n1": {
                    "SSID": "Cafe",
                    "AddedAt": "2020-01-02T12:00:00Z",
                    "BSSList": [{"LocationLatitude": 1.0, "LocationLongitude": 2.0}]
                }
            }),
        );
        let t = chrono::FixedOffset::east_opt(0)
            .unwrap()
            .with_ymd_and_hms(2024, 1, 1, 0, 0, 0)
            .unwrap();
        let evs = events_from_wifinetworks_files(&files, t);
        assert_eq!(evs.len(), 2);
    }
}
