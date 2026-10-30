// SPDX-License-Identifier: GPL-3.0-only

use chrono::{DateTime, FixedOffset, Utc};
use serde_json::{json, Map, Value};

use crate::archive::SysdiagnoseArchive;
use crate::error::BoxErr;
use crate::glob_match::glob_match;
use crate::parsers::parser_events::{event, wrap_jsonl};
use crate::parsers::timeutil::parse_apple_datetime;

#[derive(Debug, Clone)]
#[cfg_attr(feature = "apollo-mul", allow(dead_code))]
pub struct ApolloQuery {
    pub file_name: String,
    pub query_name: String,
    pub database: String,
    pub activity: String,
    pub key_timestamp: String,
    pub sql: String,
}

pub fn archive_path_matches_db_type(path: &str, db_type: &str) -> bool {
    let file = path.rsplit('/').next().unwrap_or(path);
    if !file.eq_ignore_ascii_case(db_type) {
        return false;
    }
    if db_type.contains('.') || db_type.len() > 3 {
        return true;
    }
    path.split('/')
        .rev()
        .skip(1)
        .any(|c| c.to_ascii_lowercase().contains(&db_type.to_ascii_lowercase()))
}

fn norm_key(s: &str) -> String {
    s.chars()
        .filter(|c| !c.is_whitespace() && *c != '_')
        .flat_map(|c| c.to_lowercase())
        .collect()
}

pub fn timestamp_value_from_row(row: &Map<String, Value>, key_timestamp: &str) -> Option<Value> {
    let want = norm_key(key_timestamp);
    row.iter().find_map(|(k, v)| {
        if norm_key(k) == want {
            Some(v.clone())
        } else {
            None
        }
    })
}

pub fn parse_apollo_timestamp_str(s: &str) -> Option<DateTime<FixedOffset>> {
    let s = s.trim();
    if let Some(dt) = parse_apple_datetime(s) {
        return Some(dt);
    }
    if let Ok(n) = s.parse::<i64>() {
        return Some(unix_dt(n));
    }
    if let Ok(f) = s.parse::<f64>() {
        return Some(unix_dt(f as i64));
    }
    None
}

pub fn parse_apollo_timestamp_value(v: Value) -> Option<DateTime<FixedOffset>> {
    match v {
        Value::String(s) => parse_apollo_timestamp_str(&s),
        Value::Number(n) => {
            if let Some(i) = n.as_i64() {
                Some(unix_dt(i))
            } else {
                n.as_f64().map(|f| unix_dt(f as i64))
            }
        }
        _ => None,
    }
}

fn unix_dt(secs: i64) -> DateTime<FixedOffset> {
    DateTime::<Utc>::from_timestamp(secs, 0)
        .unwrap_or_else(|| DateTime::<Utc>::from_timestamp(0, 0).expect("epoch 0"))
        .fixed_offset()
}

/// Run APOLLO queries against one SQLite payload.
///
/// With feature `apollo-mul`, execution goes through `mul-apollo` (WAL-aware open,
/// schema probing, unknown timestamps stay unknown — never `Utc::now()`). The
/// `queries` argument is kept for API compatibility; the mul path selects modules
/// by `db_type` instead.
pub fn run_apollo_on_db_bytes(
    source_path: &str,
    bytes: &[u8],
    db_type: &str,
    module: &str,
    queries: Vec<&ApolloQuery>,
) -> Result<Vec<Value>, BoxErr> {
    #[cfg(feature = "apollo-mul")]
    {
        let _ = &queries;
        return run_apollo_mul(source_path, bytes, db_type, module);
    }
    #[cfg(not(feature = "apollo-mul"))]
    {
        run_apollo_legacy(source_path, bytes, db_type, module, queries)
    }
}

#[cfg(feature = "apollo-mul")]
fn module_matches_db(m: &mul_apollo::Module, db_type: &str) -> bool {
    match &m.source {
        mul_apollo::SourceSpec::Sqlite { db_names, .. } => db_names.iter().any(|n| {
            n.split(',')
                .any(|part| part.trim().eq_ignore_ascii_case(db_type))
        }),
        _ => false,
    }
}

#[cfg(feature = "apollo-mul")]
fn run_apollo_mul(
    source_path: &str,
    bytes: &[u8],
    db_type: &str,
    parser: &str,
) -> Result<Vec<Value>, BoxErr> {
    use mul_apollo::{ModuleSet, RunOptions, SqliteRuntime};
    use mul_core::event::TsQuality;

    let set = ModuleSet::default_set();
    let matched: Vec<_> = set
        .modules()
        .iter()
        .filter(|m| module_matches_db(m, db_type))
        .collect();
    if matched.is_empty() {
        return Ok(Vec::new());
    }
    let runtime = SqliteRuntime::new();
    // `all`: try every schema variant like classic sdx (yolo prepare), not just `best`.
    let opts = RunOptions {
        mode: "all".into(),
        ..RunOptions::default()
    };
    let batch = runtime
        .run_modules_on_bytes(&matched, source_path, bytes, &opts)
        .map_err(|e| -> BoxErr { e.to_string().into() })?;

    let mut events = Vec::new();
    for (module_id, _st, rows) in batch {
        let activity = matched
            .iter()
            .find(|m| m.id == module_id)
            .map(|m| m.activity.as_str())
            .unwrap_or("");
        for ev in rows {
            let mut data = Map::new();
            for (sym, val) in &ev.attrs {
                let key = runtime.interner().resolve(*sym);
                data.insert(key, val.to_json(runtime.interner()));
            }
            data.insert("apollo_module".into(), json!(module_id));
            data.insert("source_db".into(), json!(source_path));
            let mut bits = Vec::new();
            if !activity.is_empty() {
                bits.push(activity.to_string());
            }
            for (k, v) in &data {
                if let Some(s) = v.as_str() {
                    if !s.is_empty() && k != "apollo_module" && k != "source_db" {
                        bits.push(format!("{k}={s}"));
                    }
                }
            }
            let desc = if activity.is_empty() {
                "apollo"
            } else {
                activity
            };
            let message = bits.join(" ");
            if ev.ts == i64::MIN || matches!(ev.ts_quality, TsQuality::Unknown) {
                // Unknown time: never invent "now". Emit null datetime.
                events.push(json!({
                    "datetime": Value::Null,
                    "message": message,
                    "timestamp_desc": desc,
                    "module": parser,
                    "data": Value::Object(data),
                    "time_is_approximate": true,
                }));
            } else {
                let secs = ev.ts.div_euclid(1_000_000_000);
                let nsec = ev.ts.rem_euclid(1_000_000_000) as u32;
                let dt = DateTime::<Utc>::from_timestamp(secs, nsec)
                    .unwrap_or_else(|| DateTime::<Utc>::from_timestamp(0, 0).expect("epoch"))
                    .fixed_offset();
                events.push(event(parser, dt, message, desc, Value::Object(data)));
            }
        }
    }
    Ok(events)
}

#[cfg(not(feature = "apollo-mul"))]
fn run_apollo_legacy(
    source_path: &str,
    bytes: &[u8],
    db_type: &str,
    module: &str,
    queries: Vec<&ApolloQuery>,
) -> Result<Vec<Value>, BoxErr> {
    let _ = db_type;
    #[cfg(target_arch = "wasm32")]
    {
        let _ = (source_path, bytes, module, queries);
        return Ok(Vec::new());
    }
    #[cfg(not(target_arch = "wasm32"))]
    {
        use rusqlite::types::ValueRef;

        // Stream rows like classic sdx: one open, no intermediate Vec<Value> per query.
        let (conn, _tmp) = match crate::sqlite_dump::open_bytes(bytes) {
            Ok(v) => v,
            Err(_) => return Ok(Vec::new()),
        };
        let mut events = Vec::new();
        for q in queries {
            let mut stmt = match conn.prepare(&q.sql) {
                Ok(s) => s,
                Err(_) => continue, // schema mismatch is normal
            };
            let names: Vec<String> = stmt
                .column_names()
                .iter()
                .map(|s| s.to_ascii_lowercase())
                .collect();
            let mut rows = match stmt.query([]) {
                Ok(r) => r,
                Err(_) => continue,
            };
            let mut row_count = 0usize;
            while let Ok(Some(row)) = rows.next() {
                if row_count >= 100_000 {
                    break;
                }
                row_count += 1;
                let mut data = Map::new();
                for (i, name) in names.iter().enumerate() {
                    let val = match row.get_ref(i) {
                        Ok(ValueRef::Null) => Value::Null,
                        Ok(ValueRef::Integer(n)) => json!(n),
                        Ok(ValueRef::Real(f)) => json!(f),
                        Ok(ValueRef::Text(t)) => {
                            Value::String(String::from_utf8_lossy(t).into_owned())
                        }
                        Ok(ValueRef::Blob(b)) => Value::String(format!(
                            "b'{}'",
                            crate::sqlite_dump::blob_literal_pub(b)
                        )),
                        Err(_) => Value::Null,
                    };
                    data.insert(name.clone(), val);
                }
                let ts_val = timestamp_value_from_row(&data, &q.key_timestamp);
                let Some(dt) = ts_val.and_then(parse_apollo_timestamp_value) else {
                    continue;
                };
                data.insert("apollo_module".into(), json!(q.query_name));
                data.insert("source_db".into(), json!(source_path));
                let mut bits = Vec::with_capacity(8);
                if !q.activity.is_empty() {
                    bits.push(q.activity.clone());
                }
                for (k, v) in &data {
                    if let Some(s) = v.as_str() {
                        if !s.is_empty() && k != "apollo_module" && k != "source_db" {
                            bits.push(format!("{k}={s}"));
                        }
                    }
                }
                events.push(event(
                    module,
                    dt,
                    bits.join(" "),
                    if q.activity.is_empty() {
                        "apollo"
                    } else {
                        &q.activity
                    },
                    Value::Object(data),
                ));
            }
        }
        Ok(events)
    }
}

fn sqlite_db_names() -> Vec<String> {
    #[cfg(feature = "apollo-mul")]
    {
        use mul_apollo::{ModuleSet, SourceSpec};
        let mut names = Vec::new();
        for module in ModuleSet::default_set().modules() {
            let SourceSpec::Sqlite { db_names, .. } = &module.source else {
                continue;
            };
            for name in db_names {
                if names.iter().any(|have: &String| have.eq_ignore_ascii_case(name)) {
                    continue;
                }
                names.push(name.clone());
            }
        }
        names.sort();
        names
    }
    #[cfg(not(feature = "apollo-mul"))]
    {
        Vec::new()
    }
}

pub fn parse_db(
    archive: &SysdiagnoseArchive,
    parser: &str,
    db_types: &[&str],
    globs: &[&str],
) -> Result<Value, BoxErr> {
    #[cfg(target_arch = "wasm32")]
    {
        let _ = (archive, db_types, globs);
        return Ok(wrap_jsonl(parser, Vec::new()));
    }
    #[cfg(not(target_arch = "wasm32"))]
    {
        let mut events = Vec::new();
        let mut paths: Vec<String> = archive
            .all_paths()
            .into_iter()
            .filter(|p| globs.iter().any(|g| glob_match(g, p)) || db_types.iter().any(|d| archive_path_matches_db_type(p, d)))
            .collect();
        paths.sort();
        paths.dedup();
        for path in paths {
            let Some(bytes) = archive.get(&path) else {
                continue;
            };
            // Globs name the on-disk files (`powerlog_<id>.PLSQL`). Module DATABASE
            // values name the logical db (`CurrentPowerlog.PLSQL`). A glob hit still
            // runs that module's queries.
            let glob_hit = globs.iter().any(|g| glob_match(g, &path));
            for db in db_types {
                if !glob_hit && !archive_path_matches_db_type(&path, db) {
                    continue;
                }
                events.extend(run_apollo_on_db_bytes(&path, bytes, db, parser, Vec::new())?);
            }
        }
        Ok(wrap_jsonl(parser, events))
    }
}

pub fn parse_all(archive: &SysdiagnoseArchive) -> Result<Value, BoxErr> {
    #[cfg(target_arch = "wasm32")]
    {
        let _ = archive;
        return Ok(wrap_jsonl("apollo_all", Vec::new()));
    }
    #[cfg(not(target_arch = "wasm32"))]
    {
        let db_types = sqlite_db_names();
        let mut events = Vec::new();
        for path in archive.all_paths() {
            let Some(bytes) = archive.get(&path) else {
                continue;
            };
            for db in &db_types {
                if archive_path_matches_db_type(&path, db) {
                    events.extend(run_apollo_on_db_bytes(&path, bytes, db, "apollo_all", Vec::new())?);
                }
            }
        }
        Ok(wrap_jsonl("apollo_all", events))
    }
}

#[cfg(all(test, not(target_arch = "wasm32")))]
mod tests {
    use super::*;
    use rusqlite::Connection;

    #[test]
    fn apollo_timestamp_unix_integer_and_fuzzy_column() {
        let mut item = Map::new();
        item.insert("last_modified".into(), json!(1_700_000_000_i64));
        item.insert("service".into(), json!("kTCCServiceCamera"));
        let ts = timestamp_value_from_row(&item, "last modified")
            .and_then(parse_apollo_timestamp_value)
            .expect("unix int via fuzzy key");
        assert_eq!(ts.timestamp(), 1_700_000_000);
    }

    #[test]
    fn apollo_timestamp_iso_and_sqlite_datetime_strings() {
        let s = parse_apollo_timestamp_str("2023-11-14 22:13:20").unwrap();
        assert_eq!(s.format("%Y-%m-%d %H:%M:%S").to_string(), "2023-11-14 22:13:20");
        let t = parse_apollo_timestamp_str("2023-11-14T22:13:20").unwrap();
        assert_eq!(t.format("%Y-%m-%d %H:%M:%S").to_string(), "2023-11-14 22:13:20");
        let r = parse_apollo_timestamp_str("2023-11-14T22:13:20.123456+00:00").unwrap();
        assert_eq!(r.timestamp(), 1_700_000_000);
    }

    #[test]
    fn mul_apollo_knows_sysdiagnose_databases() {
        let names = sqlite_db_names();
        for db in [
            "TCC.db",
            "knowledgeC.db",
            "CurrentPowerlog.PLSQL",
            "History.db",
            "netusage.sqlite",
            "interactionC.db",
        ] {
            assert!(
                names.iter().any(|n| n.eq_ignore_ascii_case(db)),
                "mul-apollo is missing {db}"
            );
        }
    }

    #[test]
    fn archive_path_matches_db_type_heuristics() {
        assert!(archive_path_matches_db_type("logs/Accessibility/TCC.db", "TCC.db"));
        assert!(archive_path_matches_db_type(
            "logs/powerlogs/CurrentPowerlog.PLSQL",
            "CurrentPowerlog.PLSQL"
        ));
        assert!(!archive_path_matches_db_type("logs/foo/db", "db"));
        assert!(archive_path_matches_db_type("logs/UserNotifications/db2/db", "db"));
    }

    #[test]
    fn apollo_tcc_minimal_db_emits_event() {
        let tmp = tempfile::NamedTempFile::new().unwrap();
        {
            let conn = Connection::open(tmp.path()).unwrap();
            conn.execute_batch(
                r#"
                CREATE TABLE access (
                    last_modified INTEGER,
                    service TEXT,
                    client TEXT,
                    auth_value INTEGER,
                    auth_reason INTEGER,
                    client_type INTEGER,
                    indirect_object_identifier TEXT
                );
                INSERT INTO access VALUES (
                    1700000000,
                    'kTCCServiceCamera',
                    'com.example.tccapp',
                    2,
                    0,
                    0,
                    ''
                );
                CREATE TABLE service (client TEXT);
                INSERT INTO service VALUES ('probe');
            "#,
            )
            .unwrap();
        }
        let bytes = std::fs::read(tmp.path()).unwrap();
        let events = run_apollo_on_db_bytes(
            "logs/Accessibility/TCC.db",
            &bytes,
            "TCC.db",
            "accessibility_tcc",
            Vec::new(),
        )
        .unwrap();
        assert!(!events.is_empty(), "mul-apollo emitted no TCC rows");
        let data = events[0]["data"].as_object().unwrap();
        assert_eq!(data["client"], "com.example.tccapp");
        assert_eq!(data["service"], "kTCCServiceCamera");
    }
}
