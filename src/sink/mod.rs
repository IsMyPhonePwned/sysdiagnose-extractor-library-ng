// SPDX-License-Identifier: GPL-3.0-only

//! Streaming sinks. The compat API materialises [`ValueSink`]; the CLI can
//! write parser objects straight to a file or a JSONL directory.
//!
//! SPEC §6 typed surface: [`EventSink::record`] accepts any `Serialize` value so
//! parsers can stream borrowed/typed rows without building a full `Value` tree.
//! [`mul-ingest`] prefers this path when available.

use std::fs::File;
use std::io::{BufWriter, Write};
use std::path::Path;

use serde::Serialize;
use serde_json::{Map, Value};

pub trait EventSink {
    fn begin(&mut self, parser: &str, header: &Map<String, Value>);
    fn record_value(&mut self, record: &Value);
    /// Stream a typed / borrowed record. Default serialises to [`Value`].
    fn record(&mut self, record: &dyn erased_serde::Serialize) {
        match serde_json::to_value(record) {
            Ok(v) => self.record_value(&v),
            Err(_) => {}
        }
    }
    fn end(&mut self, trailer: &Map<String, Value>);
}

pub struct ValueSink {
    pub parser: String,
    pub header: Map<String, Value>,
    pub records: Vec<Value>,
    pub trailer: Map<String, Value>,
}

impl ValueSink {
    pub fn new(parser: &str) -> Self {
        Self {
            parser: parser.to_string(),
            header: Map::new(),
            records: Vec::new(),
            trailer: Map::new(),
        }
    }

    pub fn into_jsonl(self) -> Value {
        let mut obj = self.header;
        obj.insert("parser".into(), Value::String(self.parser));
        obj.entry("format".to_string())
            .or_insert(Value::String("jsonl".into()));
        obj.insert("events".into(), Value::Array(self.records));
        for (k, v) in self.trailer {
            obj.insert(k, v);
        }
        Value::Object(obj)
    }
}

impl EventSink for ValueSink {
    fn begin(&mut self, parser: &str, header: &Map<String, Value>) {
        self.parser = parser.to_string();
        self.header = header.clone();
    }

    fn record_value(&mut self, record: &Value) {
        self.records.push(record.clone());
    }

    fn end(&mut self, trailer: &Map<String, Value>) {
        self.trailer = trailer.clone();
    }
}

impl ValueSink {
    pub fn push(&mut self, value: Value) {
        self.records.push(value);
    }
}

/// Writes one JSON object per line, one file per parser.
pub struct JsonlDirSink {
    dir: std::path::PathBuf,
}

impl JsonlDirSink {
    pub fn new(dir: impl AsRef<Path>) -> std::io::Result<Self> {
        std::fs::create_dir_all(dir.as_ref())?;
        Ok(Self {
            dir: dir.as_ref().to_path_buf(),
        })
    }

    pub fn write_value(&mut self, parser: &str, value: &Value) -> std::io::Result<()> {
        let path = self.dir.join(format!("{parser}.jsonl"));
        let file = File::create(path)?;
        let mut w = BufWriter::new(file);
        if let Some(events) = value.get("events").and_then(|e| e.as_array()) {
            for ev in events {
                serde_json::to_writer(&mut w, ev)?;
                w.write_all(b"\n")?;
            }
        } else {
            serde_json::to_writer(&mut w, value)?;
            w.write_all(b"\n")?;
        }
        w.flush()
    }
}

/// Serialize a JSON value with object keys sorted, matching serde_json's default map.
pub fn to_writer_sorted<W: Write>(writer: W, value: &Value) -> std::io::Result<()> {
    let mut ser = serde_json::Serializer::new(writer);
    value.serialize(&mut ser)?;
    Ok(())
}

pub struct CountingSink {
    pub records: u64,
}

impl CountingSink {
    pub fn new() -> Self {
        Self { records: 0 }
    }
}

impl Default for CountingSink {
    fn default() -> Self {
        Self::new()
    }
}

impl EventSink for CountingSink {
    fn begin(&mut self, _parser: &str, _header: &Map<String, Value>) {}
    fn record_value(&mut self, _record: &Value) {
        self.records += 1;
    }
    fn end(&mut self, _trailer: &Map<String, Value>) {}
}

/// Run a parser into an [`EventSink`], materialising via [`ValueSink`] when the
/// parser only implements the Value API (current default).
pub fn parse_into_sink(
    parser: &dyn crate::parsers::SysdiagnoseParser,
    archive: &crate::archive::SysdiagnoseArchive,
    sink: &mut dyn EventSink,
) -> Result<(), crate::error::BoxErr> {
    let value = parser.parse(archive)?;
    let name = value
        .get("parser")
        .and_then(|p| p.as_str())
        .unwrap_or("unknown");
    let mut header = Map::new();
    if let Some(obj) = value.as_object() {
        for (k, v) in obj {
            if k == "events" || k == "rows" || k == "entries" {
                continue;
            }
            header.insert(k.clone(), v.clone());
        }
    }
    sink.begin(name, &header);
    if let Some(events) = value.get("events").and_then(|e| e.as_array()) {
        for ev in events {
            sink.record_value(ev);
        }
    } else if let Some(rows) = value
        .get("rows")
        .or_else(|| value.get("entries"))
        .and_then(|e| e.as_array())
    {
        for row in rows {
            sink.record_value(row);
        }
    } else {
        sink.record_value(&value);
    }
    sink.end(&Map::new());
    Ok(())
}
