// SPDX-License-Identifier: GPL-3.0-only

use chrono::{NaiveDateTime, Utc};
use regex::Regex;
use serde_json::{json, Map, Value};
use std::sync::OnceLock;

use crate::archive::SysdiagnoseArchive;
use crate::error::BoxErr;
use crate::glob_match::glob_match;
use crate::parsers::parser_events::{event, wrap_jsonl};
use crate::parsers::timeutil::parse_apple_datetime;

pub struct CrashlogsParser;

impl crate::parsers::SysdiagnoseParser for CrashlogsParser {
    fn parse(&self, archive: &SysdiagnoseArchive) -> Result<Value, BoxErr> {
        parse_crashlogs(archive)
    }
}

pub fn parse_crashlogs(archive: &SysdiagnoseArchive) -> Result<Value, BoxErr> {
    let creation = crate::archive::sysdiagnose_creation(archive);
    let mut events = Vec::new();
    let mut paths: Vec<String> = archive
        .all_paths()
        .into_iter()
        .filter(|p| {
            (glob_match("**/crashes_and_spins/**/*.ips", p)
                || glob_match("**/CrashReporter/**/*.ips", p)
                || p.ends_with(".ips"))
                && !p.contains("WiFiLQMMetrics")
                && !p.contains("OTAUpdate")
                && (p.contains("crashes_and_spins") || p.contains("CrashReporter"))
        })
        .collect();
    paths.sort();
    for path in paths {
        let Some(bytes) = archive.get(&path) else {
            continue;
        };
        let text = String::from_utf8_lossy(bytes);
        let (header, body) = split_ips(&text);
        let mut data = enrich_ips_report(header, body);
        if let Some(app) = data.get("app_name").cloned() {
            data.as_object_mut().unwrap().insert("app_name".into(), app);
        }
        let (app, dt) = metadata_from_filename(&path, data.get("app_name").and_then(|v| v.as_str()));
        if data.get("app_name").is_none() {
            data.as_object_mut()
                .unwrap()
                .insert("app_name".into(), json!(app));
        }
        let filename = path.rsplit('/').next().unwrap_or(&path).to_string();
        if let Some(obj) = data.as_object_mut() {
            obj.insert("filename".into(), json!(filename));
            obj.insert("path".into(), json!(path));
        }
        let app_name = data
            .get("app_name")
            .and_then(|v| v.as_str())
            .unwrap_or(&app)
            .to_string();
        let dt = data
            .get("timestamp")
            .and_then(|v| v.as_str())
            .and_then(parse_apple_datetime)
            .unwrap_or(dt);
        let mut ev = event(
            "crashlogs",
            dt,
            format!("crash {app_name}"),
            "crashlog",
            data,
        );
        if let Some(obj) = ev.as_object_mut() {
            obj.insert("source".into(), json!(path));
        }
        events.push(ev);
    }
    for path in archive.all_paths() {
        if !glob_match("**/summaries/crashes_and_spins.log", &path) && path != "summaries/crashes_and_spins.log" {
            continue;
        }
        let Some(bytes) = archive.get(&path) else {
            continue;
        };
        let text = String::from_utf8_lossy(bytes);
        for line in text.lines() {
            let line = line.trim();
            if line.is_empty() {
                continue;
            }
            events.push(event(
                "crashlogs",
                creation,
                line,
                "crash summary",
                json!({ "format": "summary_text", "raw": line, "source": path }),
            ));
        }
    }
    Ok(wrap_jsonl("crashlogs", events))
}

fn split_ips(text: &str) -> (Value, &str) {
    let text = text.trim_start();
    if let Some(nl) = text.find('\n') {
        let first = text[..nl].trim();
        if first.starts_with('{') {
            if let Ok(header) = serde_json::from_str::<Value>(first) {
                let rest = text[nl + 1..].trim();
                if header.get("threads").is_some() || rest.is_empty() {
                    return (header, "");
                }
                return (header, rest);
            }
        }
    }
    if let Ok(v) = serde_json::from_str::<Value>(text) {
        return (v, "");
    }
    (json!({}), text)
}

pub fn enrich_ips_report(header: Value, body: &str) -> Value {
    let body_json = serde_json::from_str::<Value>(body.trim()).ok();
    let format = if body_json.is_some() && header.get("threads").is_none() {
        "two_part_json"
    } else if header.get("threads").is_some() {
        "single_json"
    } else if !body.trim().is_empty() {
        "legacy_text"
    } else {
        "unknown"
    };
    let report = body_json.clone().unwrap_or(Value::Null);
    let source = if format == "single_json" {
        header.clone()
    } else {
        body_json.clone().unwrap_or(Value::Null)
    };
    let mut data = Map::new();
    if let Some(obj) = header.as_object() {
        for (k, v) in obj {
            data.insert(k.clone(), v.clone());
        }
    }
    data.insert("ips_format".into(), json!(format));
    if format == "two_part_json" {
        data.insert("report".into(), report);
    }
    data.insert("report_raw".into(), Value::String(body.to_string()));

    let images = source
        .get("usedImages")
        .and_then(|v| v.as_array())
        .cloned()
        .unwrap_or_default();
    let mut used_images = Vec::new();
    for (i, img) in images.iter().take(256).enumerate() {
        let _ = i;
        used_images.push(json!({
            "name": img.get("name").cloned().unwrap_or(Value::Null),
            "uuid": img.get("uuid").cloned().unwrap_or(Value::Null),
            "base": img.get("base").cloned().unwrap_or(Value::Null),
            "arch": img.get("arch").cloned().unwrap_or(Value::Null),
        }));
    }
    if !used_images.is_empty() {
        data.insert("used_images".into(), Value::Array(used_images));
    }

    let (threads, faulting) = if format == "legacy_text" {
        parse_legacy_threads(body, &images)
    } else {
        normalize_threads(source.get("threads").and_then(|t| t.as_array()), &images)
    };
    let threads_truncated = threads.len() > 64;
    let mut threads: Vec<Value> = threads.into_iter().take(64).collect();
    let mut frames_truncated = false;
    for th in &mut threads {
        if let Some(frames) = th.get_mut("frames").and_then(|f| f.as_array_mut()) {
            if frames.len() > 128 {
                frames.truncate(128);
                frames_truncated = true;
            }
        }
    }
    if let Some(ft) = source.get("faultingThread").and_then(|v| v.as_i64()).or(faulting) {
        data.insert("faulting_thread".into(), json!(ft));
    }
    if let Some(ex) = source.get("exception") {
        data.insert("exception".into(), ex.clone());
    }
    if let Some(term) = source.get("termination") {
        data.insert("termination".into(), term.clone());
    }
    if let Some(bt) = source.get("lastExceptionBacktrace").or_else(|| source.get("last_exception_backtrace")) {
        data.insert("last_exception_backtrace".into(), bt.clone());
    }
    data.insert(
        "crash_structure".into(),
        json!({
            "threads_truncated": threads_truncated,
            "frames_truncated": frames_truncated,
        }),
    );
    data.insert("threads".into(), Value::Array(threads));
    Value::Object(data)
}

fn image_name(images: &[Value], idx: i64) -> String {
    images
        .get(idx as usize)
        .and_then(|i| i.get("name"))
        .and_then(|n| n.as_str())
        .unwrap_or("")
        .to_string()
}

fn image_base(images: &[Value], idx: i64) -> u64 {
    let Some(img) = images.get(idx as usize) else {
        return 0;
    };
    if let Some(n) = img.get("base").and_then(|b| b.as_u64()) {
        return n;
    }
    if let Some(s) = img.get("base").and_then(|b| b.as_str()) {
        return parse_hex_or_int(s);
    }
    0
}

fn parse_hex_or_int(s: &str) -> u64 {
    let s = s.trim();
    if let Some(hex) = s.strip_prefix("0x").or_else(|| s.strip_prefix("0X")) {
        u64::from_str_radix(hex, 16).unwrap_or(0)
    } else {
        s.parse().unwrap_or(0)
    }
}

fn normalize_threads(threads: Option<&Vec<Value>>, images: &[Value]) -> (Vec<Value>, Option<i64>) {
    let Some(threads) = threads else {
        return (Vec::new(), None);
    };
    let mut out = Vec::new();
    let mut faulting = None;
    for (i, th) in threads.iter().enumerate() {
        let triggered = th.get("triggered").and_then(|v| v.as_bool()).unwrap_or(false);
        if triggered {
            faulting = Some(i as i64);
        }
        let frames_in = th.get("frames").and_then(|f| f.as_array()).cloned().unwrap_or_default();
        let mut frames = Vec::new();
        for (fi, fr) in frames_in.iter().enumerate() {
            let image_index = fr.get("imageIndex").and_then(|v| v.as_i64()).unwrap_or(0);
            let offset = fr.get("imageOffset").and_then(|v| v.as_u64()).unwrap_or(0);
            let base = image_base(images, image_index);
            let addr = base.wrapping_add(offset);
            frames.push(json!({
                "index": fi,
                "symbol": fr.get("symbol").cloned().unwrap_or(Value::Null),
                "image": image_name(images, image_index),
                "image_index": image_index,
                "image_offset": offset,
                "address": format!("0x{addr:x}"),
            }));
        }
        out.push(json!({
            "id": th.get("id").cloned().unwrap_or(json!(i)),
            "triggered": triggered,
            "name": th.get("name").cloned().unwrap_or(Value::Null),
            "queue": th.get("queue").cloned().unwrap_or(Value::Null),
            "frame_count": frames.len(),
            "frames": frames,
        }));
    }
    (out, faulting)
}

fn parse_legacy_threads(body: &str, _images: &[Value]) -> (Vec<Value>, Option<i64>) {
    static THREAD: OnceLock<Regex> = OnceLock::new();
    let thread_re = THREAD.get_or_init(|| Regex::new(r"^Thread\s+(\d+)(.*)$").unwrap());
    static FRAME: OnceLock<Regex> = OnceLock::new();
    let frame_re = FRAME.get_or_init(|| {
        Regex::new(r"^\d+\s+(\S+)\s+(0x[0-9a-fA-F]+)\s+(0x[0-9a-fA-F]+)\s+\+\s+(\d+)").unwrap()
    });
    let mut threads = Vec::new();
    let mut current: Option<Value> = None;
    let mut faulting = None;
    let flush = |current: &mut Option<Value>, threads: &mut Vec<Value>| {
        if let Some(th) = current.take() {
            threads.push(th);
        }
    };
    for line in body.lines() {
        if let Some(caps) = thread_re.captures(line.trim()) {
            flush(&mut current, &mut threads);
            let id: i64 = caps[1].parse().unwrap_or(0);
            let rest = caps[2].trim();
            let crashed = rest.to_ascii_lowercase().contains("crashed");
            if crashed {
                faulting = Some(id);
            }
            let name = rest
                .strip_prefix("name:")
                .map(|s| s.trim().to_string())
                .filter(|s| !s.is_empty());
            current = Some(json!({
                "id": id,
                "triggered": crashed,
                "name": name,
                "queue": Value::Null,
                "frame_count": 0,
                "frames": [],
            }));
            continue;
        }
        if let Some(caps) = frame_re.captures(line.trim()) {
            if let Some(th) = current.as_mut().and_then(|v| v.as_object_mut()) {
                let n = {
                    let frames = th.entry("frames").or_insert(json!([])).as_array_mut().unwrap();
                    let idx = frames.len();
                    frames.push(json!({
                        "index": idx,
                        "symbol": Value::Null,
                        "image": caps[1].to_string(),
                        "image_index": Value::Null,
                        "image_offset": caps[4].parse::<u64>().unwrap_or(0),
                        "address": caps[2].to_string(),
                    }));
                    frames.len()
                };
                th.insert("frame_count".into(), json!(n));
            }
        }
    }
    flush(&mut current, &mut threads);
    (threads, faulting)
}

pub fn metadata_from_filename(path: &str, fallback: Option<&str>) -> (String, chrono::DateTime<chrono::FixedOffset>) {
    let base = path.rsplit('/').next().unwrap_or(path);
    let stem = base.trim_end_matches(".ips");
    static RE: OnceLock<Regex> = OnceLock::new();
    let re = RE.get_or_init(|| Regex::new(r"^(?P<name>.+)-(?P<y>\d{4})-(?P<m>\d{2})-(?P<d>\d{2})-(?P<h>\d{2})(?P<min>\d{2})(?P<s>\d{2})$").unwrap());
    if let Some(caps) = re.captures(stem) {
        let name = caps.name("name").unwrap().as_str().to_string();
        let stamp = format!(
            "{}-{}-{} {}:{}:{}",
            &caps["y"], &caps["m"], &caps["d"], &caps["h"], &caps["min"], &caps["s"]
        );
        let dt = NaiveDateTime::parse_from_str(&stamp, "%Y-%m-%d %H:%M:%S")
            .ok()
            .map(|n| n.and_utc().fixed_offset())
            .unwrap_or_else(|| Utc::now().fixed_offset());
        return (name, dt);
    }
    (
        fallback.unwrap_or("unknown").to_string(),
        Utc::now().fixed_offset(),
    )
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::parsers::SysdiagnoseParser;
    use serde_json::json;
    use std::collections::HashMap;
    use std::sync::Arc;

    #[test]
    fn two_part_json_extracts_threads_and_images() {
        let header = json!({
            "app_name": "TestApp",
            "captureTime": "2024-01-01T00:00:00Z"
        });
        let body = json!({
            "faultingThread": 0,
            "exception": { "type": "EXC_CRASH", "signal": "SIGABRT" },
            "usedImages": [{
                "name": "TestApp",
                "uuid": "UU1",
                "base": 4294967296_u64
            }],
            "threads": [{
                "id": 0,
                "triggered": true,
                "frames": [{
                    "imageIndex": 0,
                    "imageOffset": 4096,
                    "symbol": "main"
                }]
            }]
        })
        .to_string();

        let data = enrich_ips_report(header, &body);
        assert_eq!(data["ips_format"], "two_part_json");
        assert_eq!(data["faulting_thread"], 0);
        assert_eq!(data["exception"]["type"], "EXC_CRASH");
        let threads = data["threads"].as_array().unwrap();
        assert_eq!(threads.len(), 1);
        assert_eq!(threads[0]["triggered"], true);
        let frames = threads[0]["frames"].as_array().unwrap();
        assert_eq!(frames[0]["symbol"], "main");
        assert_eq!(frames[0]["image"], "TestApp");
        assert!(frames[0]["address"].as_str().unwrap().starts_with("0x"));
    }

    #[test]
    fn single_json_header_with_embedded_threads() {
        let header = json!({
            "captureTime": "2024-06-01",
            "faultingThread": 1,
            "usedImages": [{ "name": "libx", "base": "0x1000" }],
            "threads": [
                { "id": 0, "frames": [{ "imageIndex": 0, "imageOffset": 8, "symbol": "foo" }] },
                { "id": 1, "triggered": true, "frames": [{ "imageIndex": 0, "imageOffset": 16, "symbol": "bar" }] }
            ]
        });
        let data = enrich_ips_report(header, "");
        assert_eq!(data["ips_format"], "single_json");
        assert_eq!(data["threads"].as_array().unwrap().len(), 2);
        assert_eq!(data["faulting_thread"], 1);
    }

    #[test]
    fn legacy_text_parses_thread_stacks() {
        let header = json!({ "procName": "Foo", "captureTime": "2020-01-01" });
        let body = r#"Incident Identifier: ABC
Thread 0 Crashed:
0   FooApp   0x0000000100ab1000 0x100ab0000 + 4096
1   libdyld  0x00000001802a8000 0x1802a0000 + 32768
Thread 1 name: com.apple.NSURLConnectionLoader
0   libnetwork  0x00000001b2c3d000 0x1b2c00000 + 250000
"#;
        let data = enrich_ips_report(header, body);
        assert_eq!(data["ips_format"], "legacy_text");
        assert_eq!(data["faulting_thread"], 0);
        let threads = data["threads"].as_array().unwrap();
        assert_eq!(threads.len(), 2);
        assert_eq!(threads[0]["frames"].as_array().unwrap().len(), 2);
        assert_eq!(threads[0]["frames"][0]["image"], "FooApp");
        assert_eq!(threads[1]["name"], "com.apple.NSURLConnectionLoader");
    }

    #[test]
    fn parses_palera1n_style_two_part_ips_without_collapsing() {
        let mut files: HashMap<String, Arc<[u8]>> = HashMap::new();
        for (name, ts) in [
            ("palera1nHelper-2023-05-24-130825.ips", "2023-05-24 13:08:25.00 -0700"),
            ("palera1nHelper-2023-05-24-130843.ips", "2023-05-24 13:08:43.00 -0700"),
            ("palera1nHelper-2023-05-24-132608.ips", "2023-05-24 13:26:08.00 -0700"),
        ] {
            let body = format!(
                r#"{{"app_name":"palera1nHelper","timestamp":"{ts}","name":"palera1nHelper","bug_type":"309"}}
{{
  "procName" : "palera1nHelper",
  "exception" : {{ "type" : "EXC_CRASH", "signal" : "SIGABRT" }},
  "faultingThread" : 0,
  "usedImages" : [{{ "name" : "palera1nHelper", "uuid" : "U", "base" : 1 }}],
  "threads" : [{{ "id" : 0, "triggered" : true, "frames" : [{{ "imageIndex" : 0, "imageOffset" : 1, "symbol" : "main" }}] }}]
}}"#
            );
            files.insert(
                format!("crashes_and_spins/{name}"),
                Arc::from(body.into_bytes()),
            );
        }
        files.insert(
            "summaries/crashes_and_spins.log".into(),
            Arc::from(
                b"\n/private/var/mobile/Library/Logs/CrashReporter/palera1nHelper-2023-05-24-132608.ips, Added\n\
/private/var/mobile/Library/Logs/CrashReporter/palera1nHelper-2023-05-24-130825.ips, Added\n"
                    .as_slice(),
            ),
        );
        files.insert(
            "sysdiagnose.log".into(),
            Arc::from(
                b"IN_PROGRESS_sysdiagnose_2023.05.24_13-29-15-0700_iPhone-OS_iPhone_19H349/\n"
                    .as_slice(),
            ),
        );

        let arch = SysdiagnoseArchive::from_files_for_test(files);
        let out = CrashlogsParser.parse(&arch).unwrap();
        assert_eq!(out["format"], "jsonl");
        let events = out["events"].as_array().unwrap();
        assert_eq!(events.len(), 5);
        let pal = events
            .iter()
            .filter(|e| {
                e["data"]["app_name"].as_str().is_some_and(|s| s == "palera1nHelper")
                    && e["source"].as_str().is_some_and(|s| s.ends_with(".ips"))
            })
            .count();
        assert_eq!(pal, 3);
        let one = events
            .iter()
            .find(|e| e["source"].as_str().is_some_and(|s| s.contains("130825.ips")))
            .unwrap();
        assert_eq!(one["module"], "crashlogs");
        assert_eq!(one["timestamp_desc"], "crashlog");
        assert!(one["message"].as_str().unwrap().contains("palera1nHelper"));
        assert_eq!(one["data"]["report"]["procName"], "palera1nHelper");
        assert_eq!(one["data"]["report"]["exception"]["type"], "EXC_CRASH");
        assert!(!one["data"]["threads"].as_array().unwrap().is_empty());
    }

    #[test]
    fn parses_crashreporter_layout_ips() {
        let body = r#"{"app_name":"Signal","timestamp":"2025-04-07 07:41:58.00 -0700","name":"Signal","bug_type":"309"}
{
  "procName" : "Signal",
  "exception" : { "type" : "EXC_CRASH", "signal" : "SIGABRT" },
  "faultingThread" : 0,
  "usedImages" : [{ "name" : "Signal", "uuid" : "U", "base" : 1 }],
  "threads" : [{ "id" : 0, "triggered" : true, "frames" : [{ "imageIndex" : 0, "imageOffset" : 1, "symbol" : "main" }] }]
}"#;
        let mut files: HashMap<String, Arc<[u8]>> = HashMap::new();
        files.insert(
            "var/mobile/Library/Logs/CrashReporter/Signal.hooked-2025-04-07-074158.ips".into(),
            Arc::from(body.as_bytes()),
        );
        let arch = SysdiagnoseArchive::from_files_for_test(files);
        let out = CrashlogsParser.parse(&arch).unwrap();
        let events = out["events"].as_array().unwrap();
        assert_eq!(events.len(), 1);
        assert_eq!(events[0]["data"]["app_name"].as_str(), Some("Signal"));
    }

    #[test]
    fn metadata_from_relative_ips_path() {
        let (app, dt) = metadata_from_filename("crashes_and_spins/stacks-2023-05-24-132915.ips", None);
        assert_eq!(app, "stacks");
        assert_eq!(dt.format("%Y-%m-%d %H:%M:%S").to_string(), "2023-05-24 13:29:15");
    }
}
