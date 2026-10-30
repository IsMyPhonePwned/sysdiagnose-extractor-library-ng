// SPDX-License-Identifier: GPL-3.0-only

use serde_json::{json, Map, Value};

use crate::archive::SysdiagnoseArchive;
use crate::error::BoxErr;
use crate::util::{enrich_ps_process_row, snake_case};

pub const PS_TXT: &str = "ps.txt";
pub const PS_THREAD: &str = "ps_thread.txt";

pub use crate::util::exclude_known_goods;

pub struct PsParser;
pub struct PsThreadParser;

impl crate::parsers::SysdiagnoseParser for PsParser {
    fn parse(&self, archive: &SysdiagnoseArchive) -> Result<Value, BoxErr> {
        parse_ps(archive)
    }
}

impl crate::parsers::SysdiagnoseParser for PsThreadParser {
    fn parse(&self, archive: &SysdiagnoseArchive) -> Result<Value, BoxErr> {
        parse_psthread(archive)
    }
}

fn cell(header: &str, raw: &str) -> Value {
    let h = header.to_ascii_lowercase();
    if h == "%cpu" || h == "%mem" {
        return json!(raw.parse::<f64>().unwrap_or(0.0));
    }
    if matches!(
        h.as_str(),
        "uid" | "pid" | "ppid" | "pri" | "ni" | "vsz" | "rss" | "f"
    ) {
        if let Ok(i) = raw.parse::<i64>() {
            return json!(i);
        }
    }
    json!(raw)
}

fn split_row(headers: &[&str], line: &str) -> Option<Map<String, Value>> {
    if headers.is_empty() {
        return None;
    }
    let tokens: Vec<&str> = line.split_whitespace().collect();
    if tokens.len() < headers.len().saturating_sub(1) {
        return None;
    }
    let cmd_at = headers.len() - 1;
    let mut obj = Map::new();
    for (i, header) in headers.iter().take(cmd_at).enumerate() {
        if i >= tokens.len() {
            break;
        }
        obj.insert(snake_case(header), cell(header, tokens[i]));
    }
    let command = if tokens.len() > cmd_at {
        tokens[cmd_at..].join(" ")
    } else {
        String::new()
    };
    obj.insert("command".into(), json!(command));
    // Empty STARTED: a CPU-time token landed in STARTED and TIME holds the first command word.
    if let (Some(started), Some(time)) = (
        obj.get("started").and_then(|v| v.as_str()).map(str::to_string),
        obj.get("time").and_then(|v| v.as_str()).map(str::to_string),
    ) {
        if crate::util::looks_like_cpu_time(&started) && !crate::util::looks_like_cpu_time(&time) {
            let command = obj
                .get("command")
                .and_then(|v| v.as_str())
                .unwrap_or("")
                .to_string();
            let command = if command.is_empty() {
                time.clone()
            } else {
                format!("{time} {command}")
            };
            obj.insert("command".into(), json!(command));
            obj.insert("time".into(), json!(started));
            obj.insert("started".into(), json!(""));
        }
    }
    enrich_ps_process_row(&mut obj);
    Some(obj)
}

pub fn parse_ps(archive: &SysdiagnoseArchive) -> Result<Value, BoxErr> {
    let text = archive
        .get(PS_TXT)
        .map(|b| String::from_utf8_lossy(b).into_owned())
        .unwrap_or_default();
    let rows = parse_table(&text);
    Ok(json!({
        "parser": "ps",
        "source": PS_TXT,
        "rows": rows,
    }))
}

pub fn parse_psthread(archive: &SysdiagnoseArchive) -> Result<Value, BoxErr> {
    let text = archive
        .get(PS_THREAD)
        .map(|b| String::from_utf8_lossy(b).into_owned())
        .unwrap_or_default();
    let rows = parse_table(&text);
    let mut grouped: Vec<Value> = Vec::new();
    let mut index: std::collections::HashMap<i64, usize> = std::collections::HashMap::new();
    for row in rows {
        let pid = row.get("pid").and_then(|v| v.as_i64()).unwrap_or(-1);
        if let Some(slot) = index.get(&pid).copied() {
            let entry = grouped[slot].as_object_mut().unwrap();
            let n = entry.get("threads").and_then(|v| v.as_i64()).unwrap_or(1) + 1;
            entry.insert("threads".into(), json!(n));
        } else {
            let mut entry = row.as_object().cloned().unwrap_or_default();
            let command = entry
                .get("command")
                .and_then(|v| v.as_str())
                .unwrap_or("")
                .to_string();
            let user = entry.get("user").and_then(|v| v.as_str()).unwrap_or("").to_string();
            let pid_s = entry.get("pid").and_then(|v| v.as_i64()).unwrap_or(0);
            entry.insert("threads".into(), json!(1));
            entry.insert(
                "message".into(),
                json!(format!("{command} [{pid_s}] as {user}")),
            );
            index.insert(pid, grouped.len());
            grouped.push(Value::Object(entry));
        }
    }
    Ok(json!({
        "parser": "psthread",
        "source": PS_THREAD,
        "entries": grouped,
    }))
}

fn parse_table(text: &str) -> Vec<Value> {
    let mut lines = text.lines().filter(|l| !l.trim().is_empty());
    let Some(header) = lines.next() else {
        return Vec::new();
    };
    let headers: Vec<&str> = header.split_whitespace().collect();
    let mut rows = Vec::new();
    for line in lines {
        if let Some(row) = split_row(&headers, line) {
            rows.push(Value::Object(row));
        }
    }
    rows
}

#[allow(dead_code)]
fn _reexport_exclude(p: Vec<Value>, k: &[Value]) -> Vec<Value> {
    exclude_known_goods(p, k)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::parsers::SysdiagnoseParser;
    use serde_json::json;
    use std::collections::HashMap;
    use std::sync::Arc;

    fn parse_ps_txt(text: &str) -> Value {
        let mut m = HashMap::new();
        m.insert(
            PS_TXT.to_string(),
            Arc::from(text.as_bytes().to_vec().into_boxed_slice()),
        );
        let arch = SysdiagnoseArchive::from_files_for_test(m);
        PsParser.parse(&arch).expect("ps parse")
    }

    #[test]
    fn parses_sample_ps() {
        let sample = b"USER  PID COMMAND\nroot  1 /sbin/launchd\nmobile  45 /usr/bin/foo bar\n";
        let mut m = HashMap::new();
        m.insert(
            "ps.txt".to_string(),
            Arc::from(sample.to_vec().into_boxed_slice()),
        );
        let arch = SysdiagnoseArchive::from_files_for_test(m);
        let v = PsParser.parse(&arch).unwrap();
        assert_eq!(v["parser"], "ps");
        assert_eq!(v["rows"].as_array().unwrap().len(), 2);
        let row0 = &v["rows"][0];
        assert_eq!(row0["user"], "root");
        assert_eq!(row0["pid"], 1);
        let row1 = &v["rows"][1];
        assert_eq!(row1["command"], "/usr/bin/foo bar");
    }

    #[test]
    fn upstream_parse_ps_lower_than_v16_rows() {
        let text = concat!(
            "USER UID PID PPID %CPU %MEM PRI NI VSZ RSS WCHAN TT STAT STARTED TIME COMMAND\n",
            "root 0 1 0 0.0 0.4 37 0 4226848 8912 - ?? Ss 14Jan19 7:27.40 /sbin/launchd with space\n",
        );
        let v = parse_ps_txt(text);
        let row0 = &v["rows"].as_array().expect("rows")[0];
        let expected = json!({
            "user": "root",
            "uid": 0,
            "pid": 1,
            "ppid": 0,
            "%cpu": 0.0,
            "%mem": 0.4,
            "pri": 37,
            "ni": 0,
            "vsz": 4226848,
            "rss": 8912,
            "wchan": "-",
            "tt": "??",
            "stat": "Ss",
            "started": "14Jan19",
            "time": "7:27.40",
            "command": "/sbin/launchd with space",
            "command_line": "/sbin/launchd with space",
            "name": "launchd",
            "process": "launchd",
            "process_name": "launchd"
        });
        assert_eq!(row0, &expected);
    }

    #[test]
    fn upstream_parse_ps_newer_than_v16_rows() {
        let text = concat!(
            "USER UID PRSNA PID PPID F %CPU %MEM PRI NI VSZ RSS WCHAN TT STAT STARTED TIME COMMAND\n",
            "root 0 - 1 0 4004 0.0 0.0 0 0 0 0 - ?? ?s Tue09PM 0:00.00 /sbin/launchd\n",
        );
        let v = parse_ps_txt(text);
        let row0 = &v["rows"].as_array().expect("rows")[0];
        let expected = json!({
            "user": "root",
            "uid": 0,
            "prsna": "-",
            "pid": 1,
            "ppid": 0,
            "f": 4004,
            "%cpu": 0.0,
            "%mem": 0.0,
            "pri": 0,
            "ni": 0,
            "vsz": 0,
            "rss": 0,
            "wchan": "-",
            "tt": "??",
            "stat": "?s",
            "started": "Tue09PM",
            "time": "0:00.00",
            "command": "/sbin/launchd",
            "command_line": "/sbin/launchd",
            "name": "launchd",
            "process": "launchd",
            "process_name": "launchd"
        });
        assert_eq!(row0, &expected);
    }

    #[test]
    fn peels_glued_time_and_short_name_for_sshd_tty() {
        let text = concat!(
            "USER UID PID PPID %CPU %MEM PRI NI VSZ RSS WCHAN TT STAT STARTED COMMAND\n",
            "root 0 298 1 0.0 0.1 37 0 407922928 4880 ?? ttys000 Ss 24May25 0:00.10 sshd: root@ttys000\n",
        );
        let v = parse_ps_txt(text);
        let row0 = &v["rows"].as_array().expect("rows")[0];
        assert_eq!(row0["command"], "sshd: root@ttys000");
        assert_eq!(row0["time"], "0:00.10");
        assert_eq!(row0["name"], "sshd");
        assert_eq!(row0["process_name"], "sshd");
        assert_eq!(row0["pid"], 298);
    }

    #[test]
    fn repairs_empty_started_column_shift() {
        let text = concat!(
            "USER UID PID PPID %CPU %MEM PRI NI VSZ RSS WCHAN TT STAT STARTED TIME COMMAND\n",
            "root 0 298 1 0.0 0.1 37 0 407922928 4880 ?? ttys000 Ss 0:00.10 sshd: root@ttys000\n",
        );
        let v = parse_ps_txt(text);
        let row0 = &v["rows"].as_array().expect("rows")[0];
        assert_eq!(row0["command"], "sshd: root@ttys000");
        assert_eq!(row0["time"], "0:00.10");
        assert_eq!(row0["name"], "sshd");
    }

    #[test]
    fn upstream_exclude_known_goods() {
        let processes = vec![
            json!({"command": "good", "pid": 1}),
            json!({"command": "bad", "pid": 2}),
            json!({"command": "unknown", "pid": 3}),
        ];
        let known_good = vec![json!({"command": "good", "pid": 1})];
        let got = exclude_known_goods(processes, &known_good);
        assert_eq!(
            got,
            vec![
                json!({"command": "bad", "pid": 2}),
                json!({"command": "unknown", "pid": 3}),
            ]
        );
    }

    fn parse_psthread_txt(text: &str) -> Value {
        let mut m = HashMap::new();
        m.insert(
            PS_THREAD.to_string(),
            Arc::from(text.as_bytes().to_vec().into_boxed_slice()),
        );
        let arch = SysdiagnoseArchive::from_files_for_test(m);
        PsThreadParser.parse(&arch).expect("psthread parse")
    }

    #[test]
    fn short_name_and_message_for_sshd_tty() {
        let text = concat!(
            "USER UID PID PPID %CPU %MEM PRI NI VSZ RSS WCHAN TT STAT STARTED TIME COMMAND\n",
            "root 0 298 1 0.0 0.1 37 0 407922928 4880 ?? ttys000 Ss 24May25 0:00.10 sshd: root@ttys000\n",
            "root 0 298 1 0.0 0.1 37 0 407922928 4880 - ttys000 S 24May25 0:00.00 sshd: root@ttys000\n",
        );
        let v = parse_psthread_txt(text);
        let entries = v["entries"].as_array().expect("entries");
        assert_eq!(entries.len(), 1);
        let row = &entries[0];
        assert_eq!(row["pid"], 298);
        assert_eq!(row["threads"], 2);
        assert_eq!(row["command"], "sshd: root@ttys000");
        assert_eq!(row["name"], "sshd");
        assert_eq!(row["process_name"], "sshd");
        assert_eq!(
            row["message"].as_str(),
            Some("sshd: root@ttys000 [298] as root")
        );
    }

    #[test]
    fn peels_cpu_time_glued_into_command() {
        let text = concat!(
            "USER UID PID PPID %CPU %MEM PRI NI VSZ RSS WCHAN TT STAT STARTED COMMAND\n",
            "root 0 298 1 0.0 0.1 37 0 407922928 4880 ?? ttys000 Ss 24May25 0:00.10 sshd: root@ttys000\n",
        );
        let v = parse_psthread_txt(text);
        let row = &v["entries"].as_array().expect("entries")[0];
        assert_eq!(row["command"], "sshd: root@ttys000");
        assert_eq!(row["time"], "0:00.10");
        assert_eq!(row["name"], "sshd");
    }
}
