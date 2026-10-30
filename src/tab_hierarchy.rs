// SPDX-License-Identifier: GPL-3.0-only

use std::collections::BTreeMap;

use serde_json::{json, Map, Value};

/// Parse a remotectl-style tab hierarchy. Arrow lines `key=>value` are also accepted.
pub fn parse_tab_hierarchy_text(text: &str) -> Value {
    let lines: Vec<String> = text.lines().map(|l| l.trim_end().to_string()).collect();
    parse_block(&lines)
}

pub fn parse_block(lines: &[String]) -> Value {
    let mut obj = Map::new();
    let mut lists: BTreeMap<String, Vec<Value>> = BTreeMap::new();
    let mut i = 0;
    while i < lines.len() {
        let line = &lines[i];
        if line.trim().is_empty() {
            i += 1;
            continue;
        }
        let indent = line.chars().take_while(|c| *c == '\t').count();
        let body = line.trim();
        if body.ends_with(':') && !body.contains("=>") {
            let key = body.trim_end_matches(':').trim().to_string();
            let mut child = Vec::new();
            i += 1;
            while i < lines.len() {
                let next = &lines[i];
                if next.trim().is_empty() {
                    i += 1;
                    continue;
                }
                let ind = next.chars().take_while(|c| *c == '\t').count();
                if ind <= indent {
                    break;
                }
                child.push(unindent(next));
                i += 1;
            }
            let value = if child.iter().all(|l| !l.contains(':') && !l.contains("=>")) {
                Value::Array(
                    child
                        .iter()
                        .map(|l| Value::String(unquote(l.trim())))
                        .collect(),
                )
            } else {
                parse_block(&child)
            };
            obj.insert(key, value);
            continue;
        }
        if let Some((k, v)) = split_kv(body) {
            obj.insert(k, Value::String(v));
        } else if indent == 0 {
            lists
                .entry("items".into())
                .or_default()
                .push(Value::String(body.to_string()));
        }
        i += 1;
    }
    for (k, v) in lists {
        obj.entry(k).or_insert(Value::Array(v));
    }
    Value::Object(obj)
}

fn unindent(line: &str) -> String {
    line.trim_start_matches('\t').to_string()
}

fn unquote(s: &str) -> String {
    let t = s.trim();
    if t.len() >= 2 && t.starts_with('"') && t.ends_with('"') {
        t[1..t.len() - 1].to_string()
    } else {
        t.to_string()
    }
}

fn split_kv(body: &str) -> Option<(String, String)> {
    static RE: std::sync::OnceLock<regex::Regex> = std::sync::OnceLock::new();
    let re = RE.get_or_init(|| regex::Regex::new(r"^(.+?)=>*(.*)$").unwrap());
    if let Some(caps) = re.captures(body) {
        let key = caps.get(1).map(|m| m.as_str().trim()).unwrap_or("");
        let val = caps.get(2).map(|m| m.as_str().trim()).unwrap_or("");
        if key.is_empty() {
            return None;
        }
        if let Some((k, v)) = key.rsplit_once(':') {
            if !k.is_empty() && val.is_empty() {
                return Some((k.trim().to_string(), unquote(v)));
            }
        }
        if key.contains(':') && val.is_empty() {
            let (k, v) = key.split_once(':')?;
            return Some((k.trim().to_string(), unquote(v)));
        }
        if !val.is_empty() || body.contains(':') || body.contains("=>") {
            if val.is_empty() && key.ends_with(':') {
                return None;
            }
            let _ = val;
        }
    }
    if let Some((k, v)) = body.split_once(':') {
        let k = k.trim();
        if k.is_empty() {
            return None;
        }
        return Some((k.to_string(), unquote(v)));
    }
    None
}

#[allow(dead_code)]
fn _json_unused() -> Value {
    json!({})
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parse_nested_subsection() {
        let lines: Vec<String> = vec!["parent:".to_string(), "\tchild: x".to_string()];
        let v = parse_block(&lines);
        let m = v.as_object().unwrap();
        assert!(m.get("parent").is_some());
    }

    #[test]
    fn golden_remotectl_fixture() {
        const FIXTURE: &str = include_str!("../testdata/fixtures/remotectl_dumpstate_golden.txt");
        let v = parse_tab_hierarchy_text(FIXTURE);
        let device = v.get("Device").and_then(|d| d.as_object()).expect("Device");
        assert_eq!(
            device.get("OSVersion").and_then(|x| x.as_str()),
            Some("17.2.1")
        );
        assert_eq!(
            device.get("SerialNumber").and_then(|x| x.as_str()),
            Some("GOLDEN123")
        );
        let services = v
            .get("Services")
            .and_then(|s| s.as_array())
            .expect("Services");
        assert!(services
            .iter()
            .any(|x| x.as_str() == Some("com.apple.springboard")));
    }
}
