// SPDX-License-Identifier: GPL-3.0-only

//! Timeline helpers shared by the log and plist-backed parsers.

mod auth;

pub use auth::classify_ios_auth_message;

use std::borrow::Cow;
use std::io::Read;

use base64::Engine;
use chrono::{DateTime, FixedOffset, NaiveDateTime, TimeZone, Utc};
use flate2::read::GzDecoder;
use regex::Regex;
use serde_json::{json, Map, Value};
use std::sync::OnceLock;

use crate::archive::SysdiagnoseArchive;
use crate::error::BoxErr;
use crate::glob_match::glob_match;
use crate::parsers::timeutil::{parse_apple_datetime, rfc3339_micros, unix_to_dt};

pub use crate::parsers::timeutil::{event, wrap_jsonl};

pub const MAX_UTF8_FILE: usize = 8 * 1024 * 1024;

#[cfg(test)]
pub fn sysdiagnose_creation(archive: &SysdiagnoseArchive) -> DateTime<FixedOffset> {
    crate::archive::sysdiagnose_creation(archive)
}

pub fn matching_utf8_files(
    archive: &SysdiagnoseArchive,
    globs: &[&str],
) -> Result<Vec<(String, String)>, BoxErr> {
    let mut out = Vec::new();
    for path in archive.paths() {
        if !globs.iter().any(|g| glob_match(g, path)) {
            continue;
        }
        let Some(bytes) = archive.get(path) else {
            continue;
        };
        if bytes.len() > MAX_UTF8_FILE {
            continue;
        }
        let text = match std::str::from_utf8(bytes) {
            Ok(s) => Cow::Borrowed(s),
            Err(_) => Cow::Owned(String::from_utf8_lossy(bytes).into_owned()),
        };
        out.push((path.to_string(), text.into_owned()));
    }
    out.sort_by(|a, b| a.0.cmp(&b.0));
    Ok(out)
}

pub fn parse_kbdebug_log(text: &str, module: &str) -> Vec<Value> {
    static RE: OnceLock<Regex> = OnceLock::new();
    let re = RE.get_or_init(|| {
        Regex::new(r"^(\d{4}-\d{2}-\d{2} \d{2}:\d{2}:\d{2} [+-]\d{4}):\s*([A-Za-z]+):\s*(.*)$")
            .unwrap()
    });
    let mut out = Vec::new();
    for line in text.lines() {
        let Some(caps) = re.captures(line.trim()) else {
            continue;
        };
        let dt = parse_apple_datetime(&caps[1]).unwrap_or_else(|| Utc::now().fixed_offset());
        out.push(event(
            module,
            dt,
            caps[3].trim(),
            "kbdebug event",
            json!({ "level": caps[2].trim() }),
        ));
    }
    out
}

pub fn extract_lockdownd(text: &str, module: &str, tz: FixedOffset) -> Vec<Value> {
    static RE: OnceLock<Regex> = OnceLock::new();
    let re = RE.get_or_init(|| Regex::new(r"^pid=(\d+)\s+(\S+):\s*(.*)$").unwrap());
    let mut out = Vec::new();
    for line in text.lines() {
        if line.len() < 24 {
            continue;
        }
        let stamp = &line[..24];
        let Ok(naive) = NaiveDateTime::parse_from_str(stamp, "%m/%d/%y %H:%M:%S%.f") else {
            continue;
        };
        let dt = tz
            .from_local_datetime(&naive)
            .single()
            .unwrap_or_else(|| naive.and_utc().fixed_offset());
        let rest = line[24..].trim();
        let Some(caps) = re.captures(rest) else {
            continue;
        };
        let pid: i64 = caps[1].parse().unwrap_or(0);
        out.push(event(
            module,
            dt,
            caps[3].trim(),
            "lockdownd",
            json!({ "pid": pid, "event_type": caps[2].trim() }),
        ));
    }
    out
}

fn human_bytes(token: &str) -> i64 {
    let token = token.trim();
    if token.is_empty() {
        return 0;
    }
    let (num, mul) = match token.as_bytes()[token.len() - 1] {
        b'G' | b'g' => (&token[..token.len() - 1], 1024_i64 * 1024 * 1024),
        b'M' | b'm' => (&token[..token.len() - 1], 1024_i64 * 1024),
        b'K' | b'k' => (&token[..token.len() - 1], 1024_i64),
        b'T' | b't' => (&token[..token.len() - 1], 1024_i64 * 1024 * 1024 * 1024),
        _ => (token, 1_i64),
    };
    (num.parse::<f64>().unwrap_or(0.0) * mul as f64) as i64
}

pub fn parse_disks_txt(text: &str, module: &str, ts: DateTime<FixedOffset>) -> Vec<Value> {
    let mut lines = text.lines();
    let header = lines.next().unwrap_or("");
    let has_inodes = header.split_whitespace().any(|h| h == "iused");
    let mut out = Vec::new();
    for line in lines {
        if line.trim().is_empty() {
            continue;
        }
        let parts: Vec<&str> = line.split_whitespace().collect();
        let (fs, size_s, used_s, avail_s, cap, mount, inodes) = if has_inodes && parts.len() >= 9 {
            (
                parts[0],
                parts[1],
                parts[2],
                parts[3],
                parts[4],
                parts[8..].join(" "),
                Some((parts[5], parts[6], parts[7])),
            )
        } else if parts.len() >= 6 {
            (parts[0], parts[1], parts[2], parts[3], parts[4], parts[5..].join(" "), None)
        } else {
            continue;
        };
        let mut data = json!({
            "filesystem": fs,
            "size": size_s,
            "used": used_s,
            "avail": avail_s,
            "capacity": cap,
            "mounted_on": mount,
            "size_bytes": human_bytes(size_s),
            "used_bytes": human_bytes(used_s),
            "avail_bytes": human_bytes(avail_s),
        });
        if let Some(obj) = data.as_object_mut() {
            if let Ok(pct) = cap.trim_end_matches('%').parse::<f64>() {
                obj.insert("capacity_percent".into(), json!(pct));
            }
            if let Some((iused, ifree, pct)) = inodes {
                obj.insert("iused".into(), json!(iused));
                obj.insert("ifree".into(), json!(ifree));
                obj.insert("%iused".into(), json!(pct));
            }
        }
        out.push(event(
            module,
            ts,
            format!("Disk usage on {mount} ({fs})"),
            "disk usage",
            data,
        ));
    }
    out
}

pub fn parse_battery_bdc_csv(csv_text: &str, module: &str, kind: &str) -> Result<Vec<Value>, BoxErr> {
    let mut reader = csv::ReaderBuilder::new()
        .flexible(true)
        .from_reader(csv_text.as_bytes());
    let headers = reader.headers()?.clone();
    let ts_idx = headers.iter().position(|h| {
        let n = h.replace(['_', ' '], "").to_ascii_lowercase();
        n == "timestamp" || n == "setsystemtime"
    });
    let mut out = Vec::new();
    for rec in reader.records() {
        let rec = rec?;
        let mut data = Map::new();
        let mut dt = None;
        for (i, field) in rec.iter().enumerate() {
            let name = headers.get(i).unwrap_or("");
            if Some(i) == ts_idx {
                dt = parse_apple_datetime(field).or_else(|| {
                    NaiveDateTime::parse_from_str(field.trim(), "%Y-%m-%d %H:%M:%S")
                        .ok()
                        .map(|n| n.and_utc().fixed_offset())
                });
                continue;
            }
            data.insert(name.to_string(), Value::String(field.to_string()));
        }
        data.insert("type".into(), Value::String(kind.to_string()));
        let dt = dt.unwrap_or_else(|| Utc::now().fixed_offset());
        out.push(event(module, dt, "power state report", "battery bdc", Value::Object(data)));
    }
    Ok(out)
}

pub fn parse_logdata_statistics_jsonl(text: &str, module: &str) -> Vec<Value> {
    let mut out = Vec::new();
    for line in text.lines() {
        let line = line.trim();
        if line.is_empty() {
            continue;
        }
        let Ok(v) = serde_json::from_str::<Value>(line) else {
            out.push(event(
                module,
                Utc::now().fixed_offset(),
                line,
                "parse_error",
                json!({ "parse_error": true, "line": line }),
            ));
            continue;
        };
        let unix = v.get("unixTime").and_then(|u| u.as_i64().or_else(|| u.as_f64().map(|f| f as i64)));
        let dt = unix.map(unix_to_dt).unwrap_or_else(|| Utc::now().fixed_offset());
        let file = v.get("file").cloned().unwrap_or(Value::Null);
        let typ = v.get("type").cloned().unwrap_or(Value::Null);
        if let Some(list) = v.get("processList").and_then(|p| p.as_array()) {
            for item in list {
                let proc = item
                    .get("process")
                    .and_then(|p| p.as_str())
                    .unwrap_or("")
                    .to_string();
                out.push(event(
                    module,
                    dt,
                    format!("process {proc}"),
                    "logdata statistics",
                    json!({ "file": file.clone(), "type": typ.clone(), "process": proc }),
                ));
            }
        }
    }
    out
}

pub fn parse_logdata_statistics_txt(text: &str, module: &str) -> Vec<Value> {
    let mut out = Vec::new();
    for block in text.split("--- ") {
        if !block.contains("logd statistics") && !block.contains("time") {
            continue;
        }
        let mut time_s = None;
        let mut file = String::new();
        let mut typ = String::new();
        let mut procs = Vec::new();
        for line in block.lines() {
            let line = line.trim();
            if let Some(rest) = line.strip_prefix("time") {
                time_s = rest.split(':').nth(1).map(|s| s.trim().to_string()).or_else(|| {
                    rest.trim().trim_start_matches(':').trim().to_string().into()
                });
                if let Some(idx) = line.find(':') {
                    time_s = Some(line[idx + 1..].trim().to_string());
                }
            } else if let Some(idx) = line.find(':') {
                let key = line[..idx].trim();
                let val = line[idx + 1..].trim();
                if key == "file" {
                    file = val.to_string();
                } else if key == "type" {
                    typ = val.to_string();
                }
            } else if line.starts_with("- [") || line.starts_with("-[") {
                if let Some(proc) = line.rsplit(',').next() {
                    let proc = proc.trim().trim_end_matches(']').trim();
                    if !proc.is_empty() {
                        procs.push(proc.to_string());
                    }
                }
            }
        }
        let dt = time_s
            .as_deref()
            .and_then(parse_apple_datetime)
            .unwrap_or_else(|| Utc::now().fixed_offset());
        for proc in procs {
            out.push(event(
                module,
                dt,
                format!("process {proc}"),
                "logdata statistics",
                json!({ "file": file, "type": typ, "process": proc }),
            ));
        }
    }
    out
}

pub fn extract_multiline_log(text: &str, module: &str, tz: FixedOffset) -> Vec<Value> {
    static RE: OnceLock<Regex> = OnceLock::new();
    let re = RE.get_or_init(|| {
        Regex::new(
            r"^(?P<ts>\w{3} \w{3}\s+\d{1,2} \d{2}:\d{2}:\d{2} \d{4}) \[(?P<pid>\d+)\] <(?P<lvl>[^>]+)> \((?P<hex>0x[0-9a-fA-F]+)\)\s*(?P<rest>.*)$",
        )
        .unwrap()
    });
    static SEL: OnceLock<Regex> = OnceLock::new();
    let sel = SEL.get_or_init(|| {
        Regex::new(r"-\[(?P<sub>[^\]]+)\]:\s*(?P<msg>.*)$").unwrap()
    });
    static RE2: OnceLock<Regex> = OnceLock::new();
    let re2 = RE2.get_or_init(|| {
        Regex::new(
            r"^(?P<ts>\w{3} \w{3}\s+\d{1,2} \d{2}:\d{2}:\d{2} \d{4}).*<(?P<lvl>[^>]+)>:\s*(?P<msg>.*)$",
        )
        .unwrap()
    });
    let lines: Vec<&str> = text.lines().collect();
    let mut out = Vec::new();
    let mut i = 0;
    while i < lines.len() {
        let line = lines[i];
        if let Some(caps) = re.captures(line) {
            let _ = tz;
            let dt = parse_apple_datetime(caps.name("ts").unwrap().as_str())
                .unwrap_or_else(|| Utc::now().fixed_offset());
            let rest = caps.name("rest").unwrap().as_str();
            let (event_type, msg) = if let Some(s) = sel.captures(rest) {
                (
                    Some(s.name("sub").unwrap().as_str().to_string()),
                    s.name("msg").unwrap().as_str().trim().to_string(),
                )
            } else {
                (None, rest.trim().to_string())
            };
            let mut data = Map::new();
            data.insert("loglevel".into(), json!(caps.name("lvl").unwrap().as_str()));
            data.insert("hexID".into(), json!(caps.name("hex").unwrap().as_str()));
            if let Some(et) = &event_type {
                data.insert("event_type".into(), json!(et));
            }
            if let Some(c) = classify_ios_auth_message(&msg) {
                data.insert("auth_success".into(), json!(c.success));
                data.insert("auth_type".into(), json!(c.auth_type));
            }
            i += 1;
            if i < lines.len() && lines[i].trim_start().starts_with("<?xml") {
                let start = i;
                while i < lines.len() && !lines[i].contains("</plist>") {
                    i += 1;
                }
                if i < lines.len() {
                    i += 1;
                }
                let xml = lines[start..i].join("\n");
                if let Some(plist) = plist_xml_to_json(&xml) {
                    data.insert("plist".into(), plist);
                }
            }
            out.push(event(module, dt, msg, "log line", Value::Object(data)));
            continue;
        } else if let Some(caps) = re2.captures(line) {
            let dt = parse_apple_datetime(caps.name("ts").unwrap().as_str())
                .unwrap_or_else(|| Utc::now().fixed_offset());
            let msg = caps.name("msg").unwrap().as_str().trim().to_string();
            let mut data = json!({
                "loglevel": caps.name("lvl").unwrap().as_str(),
                "event_type": msg.split_whitespace().next().unwrap_or(""),
            });
            if let Some(obj) = data.as_object_mut() {
                if let Some(c) = classify_ios_auth_message(&msg) {
                    obj.insert("auth_success".into(), json!(c.success));
                    obj.insert("auth_type".into(), json!(c.auth_type));
                }
            }
            out.push(event(module, dt, msg, "log line", data));
        }
        i += 1;
    }
    out
}

fn plist_xml_to_json(xml: &str) -> Option<Value> {
    let value = plist::Value::from_reader(std::io::Cursor::new(xml.as_bytes())).ok()?;
    Some(plist_to_json(&value))
}

fn plist_to_json(v: &plist::Value) -> Value {
    use plist::Value as P;
    match v {
        P::Array(a) => Value::Array(a.iter().map(plist_to_json).collect()),
        P::Dictionary(d) => {
            let mut m = Map::new();
            for (k, v) in d {
                m.insert(k.clone(), plist_to_json(v));
            }
            Value::Object(m)
        }
        P::Boolean(b) => json!(*b),
        P::Data(d) => Value::String(base64::engine::general_purpose::STANDARD.encode(d)),
        P::Date(date) => {
            let st: std::time::SystemTime = (*date).into();
            let dt: chrono::DateTime<Utc> = st.into();
            Value::String(dt.to_rfc3339_opts(chrono::SecondsFormat::Micros, true))
        }
        P::Real(f) => json!(*f),
        P::Integer(i) => {
            if let Some(s) = i.as_signed() {
                json!(s)
            } else if let Some(u) = i.as_unsigned() {
                json!(u)
            } else {
                Value::String(i.to_string())
            }
        }
        P::String(s) => Value::String(s.clone()),
        P::Uid(u) => json!(u.get()),
        _ => Value::Null,
    }
}

pub fn transparency_extract_events(root: &Value, module: &str) -> Vec<Value> {
    let mut out = Vec::new();
    if let Some(regs) = root.get("registration").and_then(|r| r.as_array()) {
        for item in regs {
            let msg = format!(
                "registration {}",
                item.get("app").and_then(|a| a.as_str()).unwrap_or("")
            );
            let dt = item
                .get("installedAt")
                .and_then(|s| s.as_str())
                .and_then(parse_apple_datetime)
                .unwrap_or_else(|| Utc::now().fixed_offset());
            out.push(event(module, dt, msg, "registration", item.clone()));
        }
    }
    let Some(sm) = root.get("stateMachine") else {
        return out;
    };
    if let Some(s) = sm.get("accountFirstSeen").and_then(|v| v.as_str()) {
        let dt = parse_apple_datetime(s).unwrap_or_else(|| Utc::now().fixed_offset());
        out.push(event(module, dt, "accountFirstSeen", "state machine", json!({"value": s})));
    }
    if let Some(s) = sm.pointer("/backgroundOp/lastDutyCycle").and_then(|v| v.as_str()) {
        let dt = parse_apple_datetime(s).unwrap_or_else(|| Utc::now().fixed_offset());
        out.push(event(module, dt, "lastDutyCycle", "state machine", json!({"value": s})));
    }
    if let Some(lasts) = sm.get("lasts").and_then(|v| v.as_object()) {
        for (k, v) in lasts {
            let s = v.as_str().unwrap_or("");
            let dt = parse_apple_datetime(s).unwrap_or_else(|| Utc::now().fixed_offset());
            out.push(event(
                module,
                dt,
                format!("stateMachine last {k}"),
                "state machine",
                json!({"key": k, "value": s}),
            ));
        }
    }
    if let Some(launch) = sm.get("launch").and_then(|v| v.as_array()) {
        for item in launch {
            let s = item.as_str().unwrap_or("");
            let head = s.split(" - ").next().unwrap_or(s);
            let dt = parse_apple_datetime(head.trim()).unwrap_or_else(|| Utc::now().fixed_offset());
            out.push(event(module, dt, format!("launch {s}"), "launch", json!({"raw": s})));
        }
    }
    if let Some(s) = sm.get("lockState").and_then(|v| v.as_str()) {
        let dt = s
            .split_whitespace()
            .rev()
            .collect::<Vec<_>>()
            .into_iter()
            .rev()
            .collect::<Vec<_>>()
            .windows(3)
            .find_map(|w| parse_apple_datetime(&format!("{} {} {}", w[0], w[1], w[2])))
            .or_else(|| {
                // "x 2024-08-19 09:00:28 +0200"
                let parts: Vec<&str> = s.split_whitespace().collect();
                if parts.len() >= 3 {
                    parse_apple_datetime(&parts[parts.len() - 3..].join(" "))
                } else {
                    None
                }
            })
            .unwrap_or_else(|| Utc::now().fixed_offset());
        out.push(event(module, dt, format!("lockState {s}"), "lockState", json!({"raw": s})));
    }
    if let Some(ops) = sm.get("ops").and_then(|v| v.as_object()) {
        for (k, v) in ops {
            let s = v.as_str().unwrap_or("");
            let dt = find_embedded_datetime(s).unwrap_or_else(|| Utc::now().fixed_offset());
            out.push(event(module, dt, format!("op {k} {s}"), "ops", json!({"key": k, "value": s})));
        }
    }
    out
}

fn find_embedded_datetime(s: &str) -> Option<DateTime<FixedOffset>> {
    static RE: OnceLock<Regex> = OnceLock::new();
    let re = RE.get_or_init(|| {
        Regex::new(r"\d{4}-\d{2}-\d{2}[ T]\d{2}:\d{2}:\d{2}(?:\.\d+)?(?: ?[+-]\d{4}|Z)?").unwrap()
    });
    re.find(s).and_then(|m| parse_apple_datetime(m.as_str()))
}

pub fn mc_settings_events(plist: &Value, module: &str) -> Vec<Value> {
    let mut out = Vec::new();
    fn walk(node: &Value, path: &str, module: &str, out: &mut Vec<Value>) {
        let Value::Object(map) = node else {
            if let Value::Array(arr) = node {
                for (i, item) in arr.iter().enumerate() {
                    walk(item, &format!("{path}[{i}]"), module, out);
                }
            }
            return;
        };
        if map.contains_key("timestamp") {
            let ts = map.get("timestamp").and_then(|v| v.as_str()).unwrap_or("");
            let dt = parse_apple_datetime(ts).unwrap_or_else(|| Utc::now().fixed_offset());
            let process = map.get("process").and_then(|v| v.as_str()).unwrap_or("");
            let evname = map.get("event").and_then(|v| v.as_str()).unwrap_or("");
            let mut data = map.clone();
            data.insert("setting".into(), Value::String(path.to_string()));
            out.push(event(
                module,
                dt,
                format!("{process} {evname} {path}"),
                "mc settings",
                Value::Object(data),
            ));
        }
        for (k, v) in map {
            if k == "timestamp" {
                continue;
            }
            let child = if path.is_empty() {
                k.clone()
            } else {
                format!("{path}.{k}")
            };
            if v.is_object() || v.is_array() {
                walk(v, &child, module, out);
            }
        }
    }
    walk(plist, "", module, &mut out);
    out
}

pub fn mcstate_shared_profile_events(plist: &Value, module: &str) -> Result<Vec<Value>, BoxErr> {
    let Some(obj) = plist.as_object() else {
        return Ok(Vec::new());
    };
    let mut out = Vec::new();
    let install = obj.get("InstallDate").and_then(|v| v.as_str());
    let dt = install
        .and_then(parse_apple_datetime)
        .unwrap_or_else(|| Utc::now().fixed_offset());
    let desc = obj.get("PayloadDescription").and_then(|v| v.as_str()).unwrap_or("");
    let typ = obj.get("PayloadType").and_then(|v| v.as_str()).unwrap_or("");
    let name = obj.get("PayloadDisplayName").and_then(|v| v.as_str()).unwrap_or("");
    let org = obj.get("PayloadOrganization").and_then(|v| v.as_str()).unwrap_or("");
    if install.is_some() || !typ.is_empty() || !name.is_empty() {
        out.push(event(
            module,
            dt,
            format!("profile {desc} {name}"),
            &format!("profile install {typ}"),
            json!({
                "PayloadType": typ,
                "PayloadDescription": desc,
                "PayloadDisplayName": name,
                "PayloadOrganization": org,
                "InstallDate": install.unwrap_or(""),
            }),
        ));
    }
    // Flatten nested PayloadContent entries (VPN, cert, wifi, restrictions, …).
    if let Some(content) = obj.get("PayloadContent").and_then(|v| v.as_array()) {
        for (i, item) in content.iter().enumerate() {
            let Some(p) = item.as_object() else {
                continue;
            };
            let ptype = p.get("PayloadType").and_then(|v| v.as_str()).unwrap_or("");
            let pname = p.get("PayloadDisplayName").and_then(|v| v.as_str()).unwrap_or("");
            let puuid = p.get("PayloadUUID").and_then(|v| v.as_str()).unwrap_or("");
            let mut data = json!({
                "PayloadType": ptype,
                "PayloadDisplayName": pname,
                "PayloadUUID": puuid,
                "index": i,
                "parent_PayloadType": typ,
                "parent_PayloadDisplayName": name,
            });
            if let Some(obj) = data.as_object_mut() {
                for key in [
                    "PayloadIdentifier",
                    "PayloadOrganization",
                    "PayloadDescription",
                    "UserDefinedName",
                    "VPNType",
                    "RemoteAddress",
                    "ServerURL",
                    "PayloadCertificateFileName",
                ] {
                    if let Some(v) = p.get(key) {
                        obj.insert(key.into(), v.clone());
                    }
                }
            }
            out.push(event(
                module,
                dt,
                format!("payload {ptype} {pname}"),
                "mdm payload",
                data,
            ));
        }
    }
    Ok(out)
}

pub fn olddsc_events(plist: &Value, module: &str, ts: DateTime<FixedOffset>) -> Vec<Value> {
    let mut out = Vec::new();
    let Some(bins) = plist.get("Binaries").and_then(|b| b.as_array()) else {
        return out;
    };
    for bin in bins {
        let path = bin.get("Path").and_then(|p| p.as_str()).unwrap_or("");
        let uuid = bin.get("UUID_String").and_then(|p| p.as_str()).unwrap_or("");
        let mut data = json!({
            "Path": path,
            "UUID_String": uuid,
            "timestamp_info": "sysdiagnose creation time",
        });
        if let Some(obj) = data.as_object_mut() {
            for key in ["Load_Address", "Text_Segment_Size", "Segments"] {
                if let Some(v) = bin.get(key) {
                    obj.insert(key.into(), v.clone());
                }
            }
        }
        out.push(event(
            module,
            ts,
            format!("binary {path}"),
            "olddsc",
            data,
        ));
    }
    out
}

pub fn mobilebackup_events(plist: &Value, module: &str, ts: DateTime<FixedOffset>) -> Vec<Value> {
    let mut out = Vec::new();
    if let Some(errors) = plist.pointer("/BackupStateInfo/errors").and_then(|e| e.as_array()) {
        for err in errors {
            let mut data = err.as_object().cloned().unwrap_or_default();
            let dt = data
                .get("date")
                .and_then(|d| d.as_str())
                .and_then(parse_apple_datetime)
                .unwrap_or(ts);
            data.remove("date");
            let desc = err
                .get("localizedDescription")
                .and_then(|s| s.as_str())
                .unwrap_or("");
            out.push(event(module, dt, format!("backup error {desc}"), "backup error", Value::Object(data)));
        }
    }
    if let Some(pre) = plist.get("PreflightSizing").and_then(|p| p.as_object()) {
        for (k, v) in pre {
            out.push(event(
                module,
                ts,
                format!("PreflightSizing {k}"),
                "preflight",
                json!({ "key": k, "bytes": v }),
            ));
        }
    }
    out
}

pub fn appinstallation_events_from_tables(db: &Value, module: &str) -> Vec<Value> {
    let Some(obj) = db.as_object() else {
        return Vec::new();
    };
    let mut out = Vec::new();
    for (table, rows) in obj {
        if table == "sqlite_sequence" {
            continue;
        }
        let Some(rows) = rows.as_array() else {
            continue;
        };
        for row in rows {
            let mut data = row.as_object().cloned().unwrap_or_default();
            data.insert("db_table".into(), Value::String(table.clone()));
            let dt = data
                .get("timestamp")
                .and_then(|t| t.as_i64().or_else(|| t.as_f64().map(|f| f as i64)))
                .map(unix_to_dt)
                .or_else(|| {
                    data.get("timestamp")
                        .and_then(|t| t.as_str())
                        .and_then(parse_apple_datetime)
                })
                .unwrap_or_else(|| Utc::now().fixed_offset());
            out.push(event(module, dt, format!("{table} row"), table, Value::Object(data)));
        }
    }
    out
}

pub fn decompress_gzip(bytes: &[u8]) -> Result<Vec<u8>, BoxErr> {
    let mut dec = GzDecoder::new(bytes);
    let mut out = Vec::new();
    dec.read_to_end(&mut out)?;
    Ok(out)
}

pub fn parse_avconference_gzip(path: &str, decoded: &[u8], module: &str) -> Result<Vec<Value>, BoxErr> {
    let base = path.rsplit('/').next().unwrap_or(path);
    static RE: OnceLock<Regex> = OnceLock::new();
    let re = RE.get_or_init(|| {
        Regex::new(r"(?i)^\d{8}-\d{6}.+\.calldump\.gz$|CallSettings\.calldump\.gz$").unwrap()
    });
    if !re.is_match(base) && !base.to_ascii_lowercase().contains("calldump") {
        return Err("bad avconference filename".into());
    }
    if !base.to_ascii_lowercase().contains("calldump") {
        return Err("bad avconference filename".into());
    }
    // Reject names that don't look like a dated calldump.
    let dated = Regex::new(r"\d{8}-\d{6}").unwrap();
    if !dated.is_match(base) && !base.to_ascii_lowercase().contains("callsettings") {
        return Err("bad avconference filename".into());
    }
    let text = String::from_utf8_lossy(decoded);
    let mut out = Vec::new();
    let base_dt = Utc::now().fixed_offset();
    for line in text.lines() {
        let line = line.trim();
        if line.is_empty() {
            continue;
        }
        let (msg, dt) = if let Some(rest) = strip_leading_offset(line) {
            rest
        } else {
            (line.to_string(), base_dt)
        };
        out.push(event(module, dt, msg, "avconference", json!({ "source": path })));
    }
    Ok(out)
}

fn strip_leading_offset(line: &str) -> Option<(String, DateTime<FixedOffset>)> {
    // "000000.000000 line-a" — a duration prefix, not a datetime. Message is the rest.
    let mut parts = line.splitn(2, char::is_whitespace);
    let first = parts.next()?;
    let rest = parts.next()?.trim();
    if first.chars().all(|c| c.is_ascii_digit() || c == '.') && first.contains('.') {
        return Some((rest.to_string(), Utc::now().fixed_offset()));
    }
    None
}

fn wifi_kv_line(line: &str) -> Map<String, Value> {
    let mut data = Map::new();
    for part in line.split(',') {
        if let Some((k, v)) = part.trim().split_once('=') {
            let key = k.trim().trim_start_matches(|c: char| c.is_whitespace());
            let key = key.split_whitespace().last().unwrap_or(key);
            if !key.is_empty() {
                data.insert(key.to_string(), Value::String(v.trim().to_string()));
            }
        }
    }
    data
}

pub fn parse_wifi_scan(text: &str, module: &str, ts: DateTime<FixedOffset>) -> Vec<Value> {
    let mut out = Vec::new();
    for line in text.lines() {
        let line = line.trim();
        if line.is_empty() {
            continue;
        }
        if line.contains("total=") {
            let data = wifi_kv_line(line);
            out.push(event(
                module,
                ts,
                format!("scan summary {line}"),
                "wifi scan summary",
                Value::Object(data),
            ));
            continue;
        }
        if let Some((name, rest)) = line.split_once(" - ") {
            let mut data = wifi_kv_line(rest);
            if let Some(hex) = data.remove("ssid") {
                data.insert("ssid_hex".into(), hex);
            }
            data.insert("ssid".into(), Value::String(name.trim().to_string()));
            let name = name.trim();
            out.push(event(module, ts, format!("scan {name}"), "wifi scan", Value::Object(data)));
            continue;
        }
        if line.contains('=') {
            let data = wifi_kv_line(line);
            if !data.is_empty() {
                out.push(event(module, ts, line.to_string(), "wifi scan", Value::Object(data)));
            }
        }
    }
    out
}

pub fn parse_wifi_security(text: &str, module: &str) -> Vec<Value> {
    let mut out = Vec::new();
    let mut block: Map<String, Value> = Map::new();
    let flush = |block: &mut Map<String, Value>, out: &mut Vec<Value>| {
        if block.is_empty() {
            return;
        }
        let acct = block.get("acct").and_then(|v| v.as_str()).unwrap_or("");
        let cdat = block.get("cdat").and_then(|v| v.as_str()).and_then(parse_apple_datetime);
        let dt = cdat.unwrap_or_else(|| Utc::now().fixed_offset());
        let desc = if block.contains_key("cdat") {
            "wifi AP config created"
        } else {
            "wifi security"
        };
        out.push(event(
            module,
            dt,
            format!("wifi security {acct}"),
            desc,
            Value::Object(std::mem::take(block)),
        ));
    };
    for line in text.lines() {
        if let Some((k, v)) = line.split_once(" : ") {
            block.insert(k.trim().to_string(), Value::String(v.trim().to_string()));
        } else if !block.is_empty() {
            let mut b = std::mem::take(&mut block);
            flush(&mut b, &mut out);
        }
    }
    if !block.is_empty() {
        flush(&mut block, &mut out);
    }
    out
}

pub fn events_from_known_networks_plist(
    path: &str,
    plist: &Value,
    creation: DateTime<FixedOffset>,
) -> Vec<Value> {
    let mut out = Vec::new();
    let Some(obj) = plist.as_object() else {
        return out;
    };
    for (_id, net) in obj {
        let ssid = net.get("SSID").and_then(|s| s.as_str()).unwrap_or("");
        let added = net
            .get("AddedAt")
            .and_then(|s| s.as_str())
            .and_then(parse_apple_datetime)
            .unwrap_or(creation);
        if let Some(bss) = net.get("BSSList").and_then(|b| b.as_array()) {
            for b in bss {
                let lat = b.get("LocationLatitude").and_then(|v| v.as_f64());
                let lon = b.get("LocationLongitude").and_then(|v| v.as_f64());
                if lat.is_none() || lon.is_none() {
                    continue;
                }
                out.push(event(
                    "wifi_known_networks",
                    added,
                    format!("known network {ssid}"),
                    "wifi known network",
                    json!({
                        "ssid": ssid,
                        "latitude": lat.unwrap(),
                        "longitude": lon.unwrap(),
                        "source": path,
                        "accuracy": b.get("LocationAccuracy").cloned().unwrap_or(Value::Null),
                    }),
                ));
            }
        }
    }
    let _ = rfc3339_micros(creation);
    out
}

pub fn events_from_wifinetworks_files(
    files: &Map<String, Value>,
    creation: DateTime<FixedOffset>,
) -> Vec<Value> {
    let mut out = Vec::new();
    for (name, plist) in files {
        let Some(obj) = plist.as_object() else {
            continue;
        };
        for (_id, net) in obj {
            let Some(ssid) = net.get("SSID").and_then(|s| s.as_str()) else {
                continue;
            };
            let added = net
                .get("AddedAt")
                .and_then(|s| s.as_str())
                .and_then(parse_apple_datetime)
                .unwrap_or(creation);
            out.push(event(
                "wifinetworks",
                added,
                format!("network {ssid}"),
                "wifi network",
                json!({ "ssid": ssid, "file": name }),
            ));
            if let Some(bss) = net.get("BSSList").and_then(|b| b.as_array()) {
                for b in bss {
                    let lat = b.get("LocationLatitude").and_then(|v| v.as_f64());
                    let lon = b.get("LocationLongitude").and_then(|v| v.as_f64());
                    if lat.is_none() || lon.is_none() {
                        continue;
                    }
                    out.push(event(
                        "wifinetworks",
                        added,
                        format!("bss {ssid}"),
                        "wifi bss",
                        json!({
                            "ssid": ssid,
                            "latitude": lat.unwrap(),
                            "longitude": lon.unwrap(),
                            "file": name,
                        }),
                    ));
                }
            }
        }
    }
    out
}

#[cfg(test)]
mod tests;
