// SPDX-License-Identifier: GPL-3.0-only

use serde_json::{json, Map, Value};

use crate::archive::SysdiagnoseArchive;
use crate::error::BoxErr;
use crate::parsers::matched_paths;

pub struct IORegStructParser;

impl IORegStructParser {
    pub fn parse_bytes(bytes: &[u8]) -> Value {
        parse_ioreg_tree(&String::from_utf8_lossy(bytes))
    }
}

pub fn parse_ioreg_value(raw: &str) -> Value {
    let s = raw.trim();
    if s.starts_with('<') && s.ends_with('>') && s.contains("class ") {
        return Value::Object(parse_class_header(&s[1..s.len() - 1]));
    }
    parse_ioreg_literal(s)
}

fn parse_class_header(inner: &str) -> Map<String, Value> {
    let mut obj = Map::new();
    for part in split_commas(inner) {
        let part = part.trim();
        if part.is_empty() {
            continue;
        }
        if let Some(rest) = part.strip_prefix('!') {
            let key = rest.split_whitespace().next().unwrap_or(rest);
            obj.insert(key.to_string(), json!(false));
            continue;
        }
        if let Some((k, v)) = part.split_once(char::is_whitespace) {
            obj.insert(k.trim().to_string(), parse_ioreg_literal(v.trim()));
        } else {
            obj.insert(part.to_string(), json!(true));
        }
    }
    obj
}

fn parse_ioreg_literal(raw: &str) -> Value {
    let s = raw.trim();
    if s.is_empty() {
        return Value::String(String::new());
    }
    if s.starts_with('<') {
        return Value::String(s.to_string());
    }
    if (s.starts_with('{') && s.ends_with('}')) || (s.starts_with('(') && s.ends_with(')')) || (s.starts_with('"') && s.ends_with('"')) {
        let mut p = Lit { s: s.as_bytes(), i: 0 };
        if let Some(v) = p.parse_value() {
            p.skip_ws();
            if p.i == p.s.len() {
                return v;
            }
        }
    }
    if let Some(n) = parse_plain_int(s) {
        return json!(n);
    }
    Value::String(s.to_string())
}

fn parse_plain_int(s: &str) -> Option<i64> {
    if s.is_empty() || s.starts_with("0x") || s.starts_with("0X") {
        return None;
    }
    s.parse::<i64>().ok()
}

struct Lit<'a> {
    s: &'a [u8],
    i: usize,
}

impl<'a> Lit<'a> {
    fn peek(&self) -> Option<u8> {
        self.s.get(self.i).copied()
    }
    fn bump(&mut self) {
        self.i += 1;
    }
    fn skip_ws(&mut self) {
        while matches!(self.peek(), Some(b' ' | b'\t' | b'\n' | b'\r')) {
            self.bump();
        }
    }
    fn parse_value(&mut self) -> Option<Value> {
        self.skip_ws();
        match self.peek()? {
            b'"' => Some(Value::String(self.parse_string())),
            b'{' => Some(self.parse_dict()),
            b'(' => Some(self.parse_seq()),
            _ => Some(self.parse_atom()),
        }
    }
    fn parse_string(&mut self) -> String {
        self.bump();
        let start = self.i;
        while let Some(c) = self.peek() {
            if c == b'"' {
                break;
            }
            self.bump();
        }
        let out = String::from_utf8_lossy(&self.s[start..self.i]).into_owned();
        if self.peek() == Some(b'"') {
            self.bump();
        }
        out
    }
    fn parse_dict(&mut self) -> Value {
        self.bump();
        let mut map = Map::new();
        loop {
            self.skip_ws();
            match self.peek() {
                None | Some(b'}') => {
                    if self.peek() == Some(b'}') {
                        self.bump();
                    }
                    break;
                }
                Some(b',') => {
                    self.bump();
                    continue;
                }
                Some(b'=') => {
                    let start = self.i;
                    self.bump();
                    while self.peek().is_some_and(|c| c.is_ascii_digit()) {
                        self.bump();
                    }
                    let key = String::from_utf8_lossy(&self.s[start..self.i]).into_owned();
                    map.insert(key, json!(true));
                }
                _ => {
                    let key = if self.peek() == Some(b'"') {
                        self.parse_string()
                    } else {
                        self.parse_bare_key()
                    };
                    self.skip_ws();
                    if self.peek() == Some(b'=') {
                        self.bump();
                        let val = self.parse_value().unwrap_or(Value::Null);
                        map.insert(key, val);
                    } else if !key.is_empty() {
                        map.insert(key, json!(true));
                    }
                }
            }
        }
        Value::Object(map)
    }
    fn parse_bare_key(&mut self) -> String {
        let start = self.i;
        while let Some(c) = self.peek() {
            if c == b'=' || c == b',' || c == b'}' || c == b')' {
                break;
            }
            self.bump();
        }
        String::from_utf8_lossy(&self.s[start..self.i]).trim().to_string()
    }
    fn parse_seq(&mut self) -> Value {
        self.bump();
        let mut items = Vec::new();
        loop {
            self.skip_ws();
            match self.peek() {
                None | Some(b')') => {
                    if self.peek() == Some(b')') {
                        self.bump();
                    }
                    break;
                }
                Some(b',') => self.bump(),
                _ => {
                    if let Some(v) = self.parse_value() {
                        items.push(v);
                    } else {
                        break;
                    }
                }
            }
        }
        Value::Array(items)
    }
    fn parse_atom(&mut self) -> Value {
        let start = self.i;
        while let Some(c) = self.peek() {
            if c == b',' || c == b'}' || c == b')' {
                break;
            }
            self.bump();
        }
        let text = String::from_utf8_lossy(&self.s[start..self.i]).trim().to_string();
        if let Some(n) = parse_plain_int(&text) {
            json!(n)
        } else {
            Value::String(text)
        }
    }
}

fn insert_named(map: &mut Map<String, Value>, name: String, value: Value) {
    match map.remove(&name) {
        None => {
            map.insert(name, value);
        }
        Some(Value::Array(mut arr)) => {
            arr.push(value);
            map.insert(name, Value::Array(arr));
        }
        Some(prev) => {
            map.insert(name, Value::Array(vec![prev, value]));
        }
    }
}

fn split_commas(s: &str) -> Vec<&str> {
    let mut out = Vec::new();
    let mut start = 0;
    let mut in_quote = false;
    for (i, c) in s.char_indices() {
        if c == '"' {
            in_quote = !in_quote;
        } else if c == ',' && !in_quote {
            out.push(&s[start..i]);
            start = i + 1;
        }
    }
    out.push(&s[start..]);
    out
}

fn parse_ioreg_tree(text: &str) -> Value {
    if text.trim().is_empty() {
        return json!({});
    }
    let lines: Vec<&str> = text.lines().collect();
    let mut root = Map::new();
    // stack of (depth, object index path as keys from root). We mutate via a stack of maps... 
    // Use owned stack of (depth, name, object) and attach on pop.
    struct Frame {
        depth: usize,
        name: String,
        obj: Map<String, Value>,
        is_root: bool,
    }
    let mut stack: Vec<Frame> = Vec::new();

    let flush_closed = |stack: &mut Vec<Frame>, depth: usize, root: &mut Map<String, Value>| {
        while stack.len() > 1 && stack.last().map(|f| f.depth).unwrap_or(0) >= depth {
            let frame = stack.pop().unwrap();
            if let Some(parent) = stack.last_mut() {
                insert_named(&mut parent.obj, frame.name, Value::Object(frame.obj));
            }
        }
        if stack.len() == 1 && stack[0].depth >= depth && depth == 0 {
            // keep root
        }
        let _ = root;
    };

    let mut i = 0;
    while i < lines.len() {
        let line = lines[i];
        if let Some(col) = line.find("+-o ") {
            let depth = col;
            let rest = line[col + 4..].trim();
            let (name, title) = if let Some(start) = rest.find('<') {
                (rest[..start].trim().to_string(), rest[start..].trim().to_string())
            } else {
                (rest.to_string(), String::new())
            };
            while stack.last().map(|f| f.depth >= depth).unwrap_or(false) {
                let frame = stack.pop().unwrap();
                if let Some(parent) = stack.last_mut() {
                    insert_named(&mut parent.obj, frame.name, Value::Object(frame.obj));
                } else {
                    root = frame.obj;
                }
            }
            let mut obj = Map::new();
            if !title.is_empty() {
                if let Value::Object(dict) = parse_ioreg_value(&title) {
                    obj = dict;
                }
            }
            stack.push(Frame {
                depth,
                name,
                obj,
                is_root: stack.is_empty(),
            });
            i += 1;
            continue;
        }
        // property
        if let Some(eq) = line.find(" = ") {
            let mut key_part = line[..eq].trim().trim_start_matches('|').trim();
            key_part = key_part.trim();
            let key = key_part.trim_matches('"').to_string();
            let mut val_raw = line[eq + 3..].trim().to_string();
            if val_raw.starts_with('"') && !val_raw.ends_with('"') {
                // multiline string: consume until a line that ends the quote, drop newlines
                let mut acc = val_raw[1..].to_string();
                i += 1;
                while i < lines.len() {
                    let nxt = lines[i];
                    if let Some(end) = nxt.rfind('"') {
                        let before = nxt[..end].trim().trim_start_matches('|').trim();
                        acc.push_str(before);
                        break;
                    } else {
                        acc.push_str(nxt.trim().trim_start_matches('|').trim());
                    }
                    i += 1;
                }
                val_raw = format!("\"{acc}\"");
            }
            let value = parse_ioreg_literal(&val_raw);
            if let Some(frame) = stack.last_mut() {
                if !key.is_empty() {
                    frame.obj.insert(key, value);
                }
            }
        }
        i += 1;
    }
    while stack.len() > 1 {
        let frame = stack.pop().unwrap();
        if let Some(parent) = stack.last_mut() {
            insert_named(&mut parent.obj, frame.name, Value::Object(frame.obj));
        }
    }
    if let Some(frame) = stack.pop() {
        if frame.is_root {
            return Value::Object(frame.obj);
        }
        insert_named(&mut root, frame.name, Value::Object(frame.obj));
    }
    let _ = flush_closed;
    Value::Object(root)
}

pub struct CompactOpts {
    pub max_depth: usize,
    pub max_children: usize,
    pub max_value_chars: usize,
}

pub fn compact_tree(tree: &Value, opts: &CompactOpts) -> (Value, bool) {
    fn rec(node: &Value, depth: usize, opts: &CompactOpts) -> (Value, bool) {
        match node {
            Value::Object(map) => {
                if depth >= opts.max_depth {
                    return (json!({"_truncated": true}), true);
                }
                let mut out = Map::new();
                let mut trunc = false;
                for (children, (k, v)) in map.iter().enumerate() {
                    if children >= opts.max_children {
                        trunc = true;
                        out.insert("_truncated".into(), json!(true));
                        break;
                    }
                    let (cv, t) = rec(v, depth + 1, opts);
                    trunc |= t;
                    out.insert(k.clone(), cv);
                }
                (Value::Object(out), trunc)
            }
            Value::String(s) if s.chars().count() > opts.max_value_chars => {
                let t: String = s.chars().take(opts.max_value_chars).collect();
                (Value::String(t), true)
            }
            other => (other.clone(), false),
        }
    }
    rec(tree, 0, opts)
}

pub fn extract_interesting_properties(tree: &Value) -> Map<String, Value> {
    let mut out = Map::new();
    fn walk(node: &Value, path: &str, out: &mut Map<String, Value>) {
        let Value::Object(map) = node else {
            return;
        };
        for (k, v) in map {
            let child = if path.is_empty() {
                k.clone()
            } else {
                format!("{path}.{k}")
            };
            let interesting = k.to_ascii_lowercase().contains("serial")
                || k.contains("UniqueDeviceID")
                || k.contains("IOPlatform")
                || k.contains("model");
            if interesting && !v.is_object() {
                out.insert(child.clone(), v.clone());
            }
            walk(v, &child, out);
        }
    }
    walk(tree, "", &mut out);
    out
}

pub fn parse_plane(archive: &SysdiagnoseArchive, id: &str, globs: &[&str]) -> Result<Value, BoxErr> {
    let paths = matched_paths(archive, globs);
    let tree = paths
        .first()
        .and_then(|p| archive.get(p))
        .map(IORegStructParser::parse_bytes)
        .unwrap_or_else(|| json!({}));
    Ok(json!({"parser": id, "tree": tree}))
}

pub const PATH: &str = "ioreg/IOService.txt";
pub const PARSER_ID: &str = "ioservice";

pub struct IoserviceParser;

impl IoserviceParser {
    pub fn parse_with_options(
        &self,
        archive: &SysdiagnoseArchive,
        opts: &crate::engine::ParseOptions,
    ) -> Result<Value, BoxErr> {
        parse_ioservice(archive, opts)
    }
}

impl crate::parsers::SysdiagnoseParser for IoserviceParser {
    fn parse(&self, archive: &SysdiagnoseArchive) -> Result<Value, BoxErr> {
        self.parse_with_options(archive, &crate::engine::ParseOptions::default())
    }
    fn parse_with_options(
        &self,
        archive: &SysdiagnoseArchive,
        opts: &crate::engine::ParseOptions,
    ) -> Result<Value, BoxErr> {
        IoserviceParser::parse_with_options(self, archive, opts)
    }
}

pub fn parse_ioservice(archive: &SysdiagnoseArchive, opts: &crate::engine::ParseOptions) -> Result<Value, BoxErr> {
    let bytes = archive.get(PATH).unwrap_or(b"");
    let tree = IORegStructParser::parse_bytes(bytes);
    if opts.ioservice_full_tree {
        return Ok(json!({"parser": PARSER_ID, "tree": tree}));
    }
    let max_depth = std::env::var("SYSDIAGNOSE_IOSERVICE_MAX_DEPTH")
        .ok()
        .and_then(|s| s.parse().ok())
        .unwrap_or(3);
    let max_children = std::env::var("SYSDIAGNOSE_IOSERVICE_MAX_CHILDREN")
        .ok()
        .and_then(|s| s.parse().ok())
        .unwrap_or(48);
    let (compact, _trunc) = compact_tree(
        &tree,
        &CompactOpts {
            max_depth,
            max_children,
            max_value_chars: 256,
        },
    );
    let props = extract_interesting_properties(&tree);
    let node_count = count_nodes(&tree);
    Ok(json!({
        "parser": PARSER_ID,
        "format": "compact",
        "summary": { "node_count": node_count },
        "device_properties": props,
        "tree": compact,
    }))
}

fn count_nodes(v: &Value) -> u64 {
    match v {
        Value::Object(m) => 1 + m.values().map(count_nodes).sum::<u64>(),
        _ => 0,
    }
}

#[cfg(test)]
mod structure_tests {
    use super::*;
    use serde_json::json;
    use std::fs;

    const BASIC_FIXTURE: &str = include_str!("../../testdata/fixtures/ioreg_basic.txt");

    #[test]
    fn basic_structure_matches_upstream_fixture() {
        let tree = IORegStructParser::parse_bytes(BASIC_FIXTURE.as_bytes());
        let obj = tree.as_object().expect("tree object");
        assert_eq!(obj.get("class"), Some(&json!("test1")));
        assert_eq!(obj.get("key1"), Some(&json!("val1")));
        assert!(obj.contains_key("Node 2"));
        let node2 = obj.get("Node 2").unwrap().as_object().unwrap();
        assert_eq!(node2.get("#address-cells"), Some(&json!("<02000000>")));
    }

    #[test]
    fn parse_empty_returns_empty_object() {
        let tree = IORegStructParser::parse_bytes(b"");
        assert_eq!(tree, json!({}));
    }

    #[test]
    fn fixture_file_on_disk_matches_include() {
        let path = std::path::Path::new(env!("CARGO_MANIFEST_DIR")).join("testdata/fixtures/ioreg_basic.txt");
        let bytes = fs::read(path).expect("fixture");
        let tree = IORegStructParser::parse_bytes(&bytes);
        assert!(tree.get("Node 2").is_some());
    }

    #[test]
    fn overflow_anomaly_fixture() {
        const FIXTURE: &str = include_str!("../../testdata/fixtures/ioreg_overflow.txt");
        let tree = IORegStructParser::parse_bytes(FIXTURE.as_bytes());
        let leaf2 = tree
            .pointer("/Node 2/Node 3/Leaf 2")
            .and_then(|v| v.as_object())
            .expect("Leaf 2");
        assert_eq!(
            leaf2.get("data l4").and_then(|v| v.as_str()),
            Some("value aaaabbbbccccdddd")
        );
    }

    #[test]
    fn non_ascii_byte_in_value() {
        let mut fixture = String::from(include_str!("../../testdata/fixtures/ioreg_non_ascii.txt"));
        fixture = fixture.replace("value -->\\xbf<--", "value -->\u{bf}<--");
        let tree = IORegStructParser::parse_bytes(fixture.as_bytes());
        let leaf2 = tree
            .pointer("/Node 2/Node 3/Leaf 2")
            .and_then(|v| v.as_object())
            .expect("Leaf 2");
        assert_eq!(
            leaf2.get("data l4").and_then(|v| v.as_str()),
            Some("value -->\u{bf}<--")
        );
    }

    #[test]
    fn parses_xml_dict_title() {
        let v = parse_ioreg_value("<class test1, key1 val1>");
        let obj = v.as_object().expect("dict");
        assert_eq!(obj.get("class"), Some(&json!("test1")));
        assert_eq!(obj.get("key1"), Some(&json!("val1")));
    }

    #[test]
    fn parses_quoted_string_with_angle_brackets_and_non_ascii() {
        let v = parse_ioreg_value("\"value -->¿<--\"");
        assert_eq!(v, json!("value -->¿<--"));
    }

    #[test]
    fn parses_quoted_string_with_angle_brackets_and_literal_xbf() {
        let v = parse_ioreg_value("\"value -->\\xbf<--\"");
        assert_eq!(v, json!("value -->\\xbf<--"));
    }
}

#[cfg(test)]
mod compact_tests {
    use super::*;
    use serde_json::json;

    #[test]
    fn compact_tree_limits_depth_and_children() {
        let tree = json!({
            "A": {
                "p1": "v1",
                "B": { "p2": "v2", "C": { "deep": "hidden" } }
            },
            "sibling": "x"
        });
        let opts = CompactOpts {
            max_depth: 2,
            max_children: 10,
            max_value_chars: 64,
        };
        let (c, trunc) = compact_tree(&tree, &opts);
        assert!(trunc);
        assert!(c["A"]["B"].get("_truncated").is_some());
    }

    #[test]
    fn extracts_serial_like_properties() {
        let tree = json!({
            "IODeviceTree": {
                "arm-io": {
                    "IOPlatformSerialNumber": "SN123",
                    "other": "noise"
                }
            }
        });
        let props = extract_interesting_properties(&tree);
        assert!(props.keys().any(|k| k.contains("IOPlatformSerialNumber")));
    }
}

#[cfg(test)]
mod ioservice_tests {
    use super::*;
    use crate::parsers::SysdiagnoseParser;
    use crate::engine::ParseOptions;
    use std::collections::HashMap;
    use std::sync::Arc;

    fn fixture_archive() -> SysdiagnoseArchive {
        let fixture = include_bytes!(concat!(
            env!("CARGO_MANIFEST_DIR"),
            "/testdata/fixtures/ioreg_basic.txt"
        ));
        let mut m = HashMap::new();
        m.insert(
            PATH.to_string(),
            Arc::from(fixture.to_vec().into_boxed_slice()),
        );
        SysdiagnoseArchive::from_files_for_test(m)
    }

    #[test]
    fn compact_ioservice_from_fixture() {
        let arch = fixture_archive();
        let v = IoserviceParser.parse(&arch).unwrap();
        assert_eq!(v["format"], "compact");
        assert!(v["summary"]["node_count"].as_u64().unwrap() >= 1);
        assert!(v.get("tree").is_some());
    }

    #[test]
    fn full_tree_via_parse_options() {
        let arch = fixture_archive();
        let opts = ParseOptions {
            ioservice_full_tree: true,
            ..Default::default()
        };
        let v = IoserviceParser.parse_with_options(&arch, &opts).unwrap();
        assert_eq!(v["parser"], PARSER_ID);
        assert!(v.get("format").is_none());
        assert!(v.get("tree").is_some());
    }
}
