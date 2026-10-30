// SPDX-License-Identifier: GPL-3.0-only

use serde_json::{json, Map, Value};

pub fn snake_case(s: &str) -> String {
    s.to_lowercase().replace(' ', "_")
}

pub fn strip_process_name_quotes(s: &str) -> String {
    let t = s.trim();
    if t.len() >= 2 && t.starts_with('"') && t.ends_with('"') {
        t[1..t.len() - 1].to_string()
    } else {
        t.to_string()
    }
}

pub fn parse_process_identity(s: &str) -> (String, Option<u32>) {
    let t = s.trim();
    let name = if let Some(rest) = t.strip_prefix('"') {
        let end = rest.find('"').unwrap_or(rest.len());
        rest[..end].to_string()
    } else {
        let cut = t.find(" [").unwrap_or(t.len());
        t[..cut].trim().to_string()
    };
    let pid = t
        .split('[')
        .nth(1)
        .and_then(|x| x.split(']').next())
        .and_then(|n| n.trim().parse().ok());
    (name, pid)
}

pub fn looks_like_cpu_time(s: &str) -> bool {
    let s = s.trim();
    let mut parts = s.split(':');
    let Some(mins) = parts.next() else {
        return false;
    };
    let Some(secs) = parts.next() else {
        return false;
    };
    if parts.next().is_some() || mins.is_empty() || !mins.chars().all(|c| c.is_ascii_digit()) {
        return false;
    }
    let mut sp = secs.split('.');
    let sec = sp.next().unwrap_or("");
    if sec.is_empty() || !sec.chars().all(|c| c.is_ascii_digit()) {
        return false;
    }
    if let Some(frac) = sp.next() {
        if sp.next().is_some() || frac.is_empty() || !frac.chars().all(|c| c.is_ascii_digit()) {
            return false;
        }
    }
    true
}

pub fn peel_leading_cpu_time(s: &str) -> Option<(String, String)> {
    let s = s.trim();
    let mut it = s.splitn(2, char::is_whitespace);
    let first = it.next()?;
    let rest = it.next()?.trim();
    if rest.is_empty() || !looks_like_cpu_time(first) {
        return None;
    }
    Some((first.to_string(), rest.to_string()))
}

pub fn process_short_name(command: &str) -> String {
    let owned;
    let command = if let Some((_, rest)) = peel_leading_cpu_time(command) {
        owned = rest;
        owned.as_str()
    } else {
        command
    };
    let command = command.trim();
    let token = command.split_whitespace().next().unwrap_or(command);
    let token = token.trim_matches(|c| c == '(' || c == ')');
    let token = token.trim_end_matches(':');
    let base = token.rsplit('/').next().unwrap_or(token);
    strip_process_name_quotes(base)
}

/// Split a command into executable and a single argument token.
/// Remainder that itself contains whitespace stays part of the command.
pub fn split_process_command(command: &str) -> (String, String) {
    let command = command.trim();
    if let Some(idx) = command.find(char::is_whitespace) {
        let (exe, args) = command.split_at(idx);
        let args = args.trim();
        if exe.starts_with('/') && !args.is_empty() && !args.contains(char::is_whitespace) {
            return (exe.to_string(), args.to_string());
        }
    }
    (command.to_string(), String::new())
}

pub fn normalize_process_path(p: &str) -> String {
    let p = p.trim();
    p.strip_prefix("/private").unwrap_or(p).to_string()
}

#[derive(Debug, Clone, Default)]
pub struct MobileInstallVersions {
    pub version: Option<String>,
    pub short_version: Option<String>,
}

pub fn looks_like_app_version(s: &str) -> bool {
    let s = s.trim();
    if s.is_empty() || s.len() > 64 {
        return false;
    }
    if !s.chars().any(|c| c.is_ascii_digit()) {
        return false;
    }
    s.chars()
        .all(|c| c.is_ascii_digit() || c == '.' || c == '_')
}

pub fn parse_mobile_install_versions(msg: &str) -> MobileInstallVersions {
    if !msg.contains('=') {
        return MobileInstallVersions::default();
    }
    fn grab(msg: &str, key: &str) -> Option<String> {
        let pat = format!("{key}=");
        let i = msg.find(&pat)?;
        let rest = &msg[i + pat.len()..];
        let end = rest
            .find([',', ';', '>', ' ', '\n'])
            .unwrap_or(rest.len());
        let v = rest[..end].trim();
        if looks_like_app_version(v) {
            Some(v.to_string())
        } else {
            None
        }
    }
    MobileInstallVersions {
        version: grab(msg, "Version"),
        short_version: grab(msg, "ShortVersion"),
    }
}

pub fn enrich_mobile_installation_event(ev: &mut Value) {
    let msg = ev
        .get("message")
        .and_then(|m| m.as_str())
        .unwrap_or("")
        .to_string();
    let vers = parse_mobile_install_versions(&msg);
    let Some(data) = ev.get_mut("data").and_then(|d| d.as_object_mut()) else {
        return;
    };
    if data
        .get("short_version")
        .and_then(|v| v.as_str())
        .is_some_and(|s| !looks_like_app_version(s))
    {
        data.remove("short_version");
        data.remove("CFBundleShortVersionString");
    }
    if data
        .get("version")
        .and_then(|v| v.as_str())
        .is_some_and(|s| !looks_like_app_version(s))
    {
        data.remove("version");
        data.remove("CFBundleVersion");
    }
    if let Some(sv) = vers.short_version {
        data.insert("short_version".into(), json!(sv.clone()));
        data.insert("CFBundleShortVersionString".into(), json!(sv));
    }
    if let Some(v) = vers.version {
        data.insert("version".into(), json!(v.clone()));
        data.insert("CFBundleVersion".into(), json!(v));
    }
}

pub fn enrich_ps_process_row(obj: &mut Map<String, Value>) {
    let mut command = obj
        .get("command")
        .and_then(|v| v.as_str())
        .unwrap_or("")
        .to_string();
    if let Some(started) = obj.get("started").and_then(|v| v.as_str()).map(str::to_string) {
        let time = obj.get("time").and_then(|v| v.as_str()).unwrap_or("");
        if looks_like_cpu_time(&started) && !looks_like_cpu_time(time) {
            if !time.is_empty() {
                command = if command.is_empty() {
                    time.to_string()
                } else {
                    format!("{time} {command}")
                };
            }
            obj.insert("time".into(), json!(started));
            obj.insert("started".into(), json!(""));
        }
    }
    if let Some((cpu, rest)) = peel_leading_cpu_time(&command) {
        command = rest;
        obj.insert("time".into(), json!(cpu));
    }
    obj.insert("command".into(), json!(command.clone()));
    obj.insert("command_line".into(), json!(command.clone()));
    let (exe, args) = split_process_command(&command);
    let short = process_short_name(&command);
    obj.insert("name".into(), json!(short.clone()));
    obj.insert("process".into(), json!(short.clone()));
    obj.insert("process_name".into(), json!(short));
    if !args.is_empty() {
        obj.insert("args".into(), json!(args));
        obj.insert("path".into(), json!(normalize_process_path(&exe)));
    }
}

/// Drop rows whose `(command, pid)` pair is in `known_good`.
pub fn exclude_known_goods(processes: Vec<Value>, known_good: &[Value]) -> Vec<Value> {
    processes
        .into_iter()
        .filter(|row| {
            !known_good.iter().any(|g| {
                g.get("command") == row.get("command") && g.get("pid") == row.get("pid")
            })
        })
        .collect()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn snake_case_like_python() {
        assert_eq!(snake_case("%CPU"), "%cpu");
        assert_eq!(snake_case("USER"), "user");
        assert_eq!(snake_case("STARTED"), "started");
    }

    #[test]
    fn parse_process_identity_taskinfo_quoted() {
        let (name, pid) = parse_process_identity(r#""sshd" [298] [unique ID: 298]"#);
        assert_eq!(name, "sshd");
        assert_eq!(pid, Some(298));
    }

    #[test]
    fn parse_process_identity_spindump_unquoted() {
        let (name, pid) = parse_process_identity("launchd [1]");
        assert_eq!(name, "launchd");
        assert_eq!(pid, Some(1));
    }

    #[test]
    fn parse_process_identity_quoted_with_spaces() {
        let (name, pid) = parse_process_identity(r#""SpringBoard" [123]"#);
        assert_eq!(name, "SpringBoard");
        assert_eq!(pid, Some(123));
    }

    #[test]
    fn strip_process_name_quotes_basic() {
        assert_eq!(strip_process_name_quotes(r#""sshd""#), "sshd");
        assert_eq!(strip_process_name_quotes("sshd"), "sshd");
    }

    #[test]
    fn peel_leading_cpu_time_from_command() {
        assert_eq!(
            peel_leading_cpu_time("0:00.10 sshd: root@ttys000"),
            Some(("0:00.10".into(), "sshd: root@ttys000".into()))
        );
        assert_eq!(peel_leading_cpu_time("sshd: root@ttys000"), None);
        assert!(looks_like_cpu_time("7:27.40"));
        assert!(!looks_like_cpu_time("sshd:"));
    }

    #[test]
    fn process_short_name_from_ps_command() {
        assert_eq!(process_short_name("/sbin/launchd"), "launchd");
        assert_eq!(process_short_name("sshd: root@ttys000"), "sshd");
        assert_eq!(process_short_name("0:00.10 sshd: root@ttys000"), "sshd");
        assert_eq!(process_short_name("(kernel_task)"), "kernel_task");
    }

    #[test]
    fn split_process_command_extracts_args() {
        let (exe, args) = split_process_command(
            "/private/var/containers/Bundle/Application/UUID/Signal.app/mussel dGNwOi8vOTguNjYuMTU0LjIzNToyOTU1Mg==",
        );
        assert!(exe.ends_with("/Signal.app/mussel"));
        assert_eq!(args, "dGNwOi8vOTguNjYuMTU0LjIzNToyOTU1Mg==");
        assert_eq!(
            split_process_command("sshd: root@ttys000"),
            ("sshd: root@ttys000".into(), String::new())
        );
        assert_eq!(
            normalize_process_path("/private/var/containers/foo"),
            "/var/containers/foo"
        );
    }

    #[test]
    fn enrich_ps_process_row_repairs_glued_time() {
        let mut obj = Map::new();
        obj.insert("command".into(), json!("0:00.10 sshd: root@ttys000"));
        obj.insert("time".into(), json!("sshd:"));
        enrich_ps_process_row(&mut obj);
        assert_eq!(
            obj.get("command").and_then(|v| v.as_str()),
            Some("sshd: root@ttys000")
        );
        assert_eq!(obj.get("time").and_then(|v| v.as_str()), Some("0:00.10"));
        assert_eq!(obj.get("name").and_then(|v| v.as_str()), Some("sshd"));
        assert_eq!(
            obj.get("process_name").and_then(|v| v.as_str()),
            Some("sshd")
        );
        assert_eq!(obj.get("process").and_then(|v| v.as_str()), Some("sshd"));
    }

    #[test]
    fn enrich_ps_process_row_keeps_args() {
        let mut obj = Map::new();
        obj.insert(
            "command".into(),
            json!("/var/containers/Bundle/Application/X/Signal.app/mussel dGNwOi8vOTguNjYuMTU0LjIzNToyOTU1Mg=="),
        );
        enrich_ps_process_row(&mut obj);
        assert_eq!(
            obj.get("process_name").and_then(|v| v.as_str()),
            Some("mussel")
        );
        assert_eq!(
            obj.get("args").and_then(|v| v.as_str()),
            Some("dGNwOi8vOTguNjYuMTU0LjIzNToyOTU1Mg==")
        );
        assert_eq!(
            obj.get("path").and_then(|v| v.as_str()),
            Some("/var/containers/Bundle/Application/X/Signal.app/mussel")
        );
    }

    #[test]
    fn parse_mobile_install_versions_requires_equals() {
        let ok = parse_mobile_install_versions(
            "Staging <MIInstallableBundle ID=org.whispersystems.signal; Version=1, ShortVersion=7.12.0>",
        );
        assert_eq!(ok.short_version.as_deref(), Some("7.12.0"));
        assert_eq!(ok.version.as_deref(), Some("1"));

        let prose = parse_mobile_install_versions(
            "Install requested; version does not match existing container metadata",
        );
        assert_eq!(prose.short_version, None);
        assert_eq!(prose.version, None);
        assert!(!looks_like_app_version("does"));
    }

    #[test]
    fn enrich_mobile_installation_event_stamps_data() {
        let mut ev = json!({
            "message": "Staging <MIInstallableBundle ID=org.whispersystems.signal; Version=42, ShortVersion=7.12.0>",
            "data": { "event_type": "Staging" }
        });
        enrich_mobile_installation_event(&mut ev);
        assert_eq!(ev["data"]["short_version"], "7.12.0");
        assert_eq!(ev["data"]["CFBundleShortVersionString"], "7.12.0");
        assert_eq!(ev["data"]["version"], "42");
        assert_eq!(ev["data"]["CFBundleVersion"], "42");

        let mut bad = json!({
            "message": "version does not match",
            "data": { "short_version": "does", "version": "does" }
        });
        enrich_mobile_installation_event(&mut bad);
        assert!(bad["data"].get("short_version").is_none());
        assert!(bad["data"].get("version").is_none());
    }
}
