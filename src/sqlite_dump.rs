// SPDX-License-Identifier: GPL-3.0-only

use serde_json::{json, Map, Value};

#[cfg(not(target_arch = "wasm32"))]
use rusqlite::{types::ValueRef, Connection, OpenFlags};

/// Dump every user table to the sqlite2struct shape: `{ table: [ {col: value} ] }`.
/// `row_cap == 0` means no cap.
#[cfg(not(target_arch = "wasm32"))]
pub fn dump_sqlite_bytes(bytes: &[u8], row_cap: usize) -> Result<Value, crate::error::BoxErr> {
    let (conn, _tmp) = open_bytes(bytes)?;
    let mut tables = Vec::new();
    {
        let mut stmt = conn.prepare(
            "SELECT name FROM sqlite_master WHERE type='table' AND name NOT LIKE 'sqlite_%' ORDER BY name",
        )?;
        let rows = stmt.query_map([], |r| r.get::<_, String>(0))?;
        for name in rows {
            tables.push(name?);
        }
    }
    let mut out = Map::new();
    for table in tables {
        let quoted = table.replace('"', "\"\"");
        let sql = format!("SELECT * FROM \"{quoted}\"");
        let rows = query_on(&conn, &sql, row_cap)?;
        out.insert(table, Value::Array(rows));
    }
    Ok(Value::Object(out))
}

#[cfg(not(target_arch = "wasm32"))]
pub fn query_sqlite_select(bytes: &[u8], sql: &str) -> Result<Vec<Value>, crate::error::BoxErr> {
    let (conn, _tmp) = open_bytes(bytes)?;
    query_on(&conn, sql, 0)
}

/// Run many statements against one opened copy of `bytes`.
/// A statement that fails to prepare is returned as `Err` and does not abort the rest.
#[cfg(not(target_arch = "wasm32"))]
pub fn query_sqlite_each(
    bytes: &[u8],
    sqls: &[String],
) -> Result<Vec<Result<Vec<Value>, crate::error::BoxErr>>, crate::error::BoxErr> {
    let (conn, _tmp) = open_bytes(bytes)?;
    let mut out = Vec::with_capacity(sqls.len());
    for sql in sqls {
        out.push(query_on(&conn, sql, 0));
    }
    Ok(out)
}

#[cfg(not(target_arch = "wasm32"))]
/// Open `bytes` as a private read-only SQLite DB (temp file kept alive with the conn).
pub(crate) fn open_bytes(
    bytes: &[u8],
) -> Result<(Connection, tempfile::NamedTempFile), crate::error::BoxErr> {
    let mut tmp = tempfile::NamedTempFile::new()?;
    std::io::Write::write_all(&mut tmp, bytes)?;
    // No sync_all: evidence is already a private temp copy; fsync only burns
    // wall time on large powerlog DBs and is not required for read-only open.
    let conn = Connection::open_with_flags(tmp.path(), OpenFlags::SQLITE_OPEN_READ_ONLY)?;
    let _ = conn.pragma_update(None, "query_only", true);
    let _ = conn.pragma_update(None, "temp_store", "memory");
    let _ = conn.pragma_update(None, "cache_size", -16384i32);
    Ok((conn, tmp))
}

#[cfg(not(target_arch = "wasm32"))]
fn query_on(conn: &Connection, sql: &str, row_cap: usize) -> Result<Vec<Value>, crate::error::BoxErr> {
    let mut stmt = conn.prepare(sql)?;
    // Lowercase once up front (SAF / APOLLO expect lowercased data keys).
    let names: Vec<String> = stmt
        .column_names()
        .iter()
        .map(|s| s.to_ascii_lowercase())
        .collect();
    let mut rows_out = Vec::new();
    let mut rows = stmt.query([])?;
    while let Some(row) = rows.next()? {
        if row_cap > 0 && rows_out.len() >= row_cap {
            break;
        }
        let mut obj = Map::new();
        for (i, name) in names.iter().enumerate() {
            obj.insert(name.clone(), value_ref_to_json(row.get_ref(i)?));
        }
        rows_out.push(Value::Object(obj));
    }
    Ok(rows_out)
}

#[cfg(not(target_arch = "wasm32"))]
fn value_ref_to_json(v: ValueRef<'_>) -> Value {
    match v {
        ValueRef::Null => Value::Null,
        ValueRef::Integer(i) => json!(i),
        ValueRef::Real(f) => json!(f),
        ValueRef::Text(t) => Value::String(String::from_utf8_lossy(t).into_owned()),
        ValueRef::Blob(b) => Value::String(format!("b'{}'", blob_literal(b))),
    }
}

#[cfg(not(target_arch = "wasm32"))]
fn blob_literal(bytes: &[u8]) -> String {
    blob_literal_pub(bytes)
}

#[cfg(not(target_arch = "wasm32"))]
pub(crate) fn blob_literal_pub(bytes: &[u8]) -> String {
    let mut s = String::new();
    for &b in bytes {
        match b {
            b'\\' => s.push_str("\\\\"),
            b'\'' => s.push_str("\\'"),
            0x20..=0x7e => s.push(b as char),
            _ => s.push_str(&format!("\\x{b:02x}")),
        }
    }
    s
}

#[cfg(target_arch = "wasm32")]
pub fn dump_sqlite_bytes(_bytes: &[u8], _row_cap: usize) -> Result<Value, crate::error::BoxErr> {
    Ok(Value::Object(Map::new()))
}

#[cfg(target_arch = "wasm32")]
pub fn query_sqlite_select(_bytes: &[u8], _sql: &str) -> Result<Vec<Value>, crate::error::BoxErr> {
    Ok(Vec::new())
}

#[cfg(target_arch = "wasm32")]
pub fn query_sqlite_each(
    _bytes: &[u8],
    sqls: &[String],
) -> Result<Vec<Result<Vec<Value>, crate::error::BoxErr>>, crate::error::BoxErr> {
    Ok(sqls.iter().map(|_| Ok(Vec::new())).collect())
}

#[cfg(all(test, not(target_arch = "wasm32")))]
mod tests {
    use super::*;
    use rusqlite::Connection;

    #[test]
    fn dump_matches_sqlite2struct_shape() {
        let path = tempfile::NamedTempFile::new().unwrap();
        let conn = Connection::open(path.path()).unwrap();
        conn.execute_batch(
            "CREATE TABLE items (id INTEGER PRIMARY KEY, name TEXT, flag INTEGER);
             INSERT INTO items (name, flag) VALUES ('hello', 1);",
        )
        .unwrap();
        let bytes = std::fs::read(path.path()).unwrap();
        let v = dump_sqlite_bytes(&bytes, 0).unwrap();
        let items = v.get("items").and_then(|a| a.as_array()).unwrap();
        assert_eq!(items[0]["name"], "hello");
        assert_eq!(items[0]["flag"], 1);
    }

    #[test]
    fn query_select_returns_rows() {
        let path = tempfile::NamedTempFile::new().unwrap();
        let conn = Connection::open(path.path()).unwrap();
        conn.execute_batch(
            "CREATE TABLE t (id INTEGER, label TEXT);
             INSERT INTO t VALUES (1, 'a');",
        )
        .unwrap();
        let bytes = std::fs::read(path.path()).unwrap();
        let rows = query_sqlite_select(&bytes, "SELECT id, label FROM t").unwrap();
        assert_eq!(rows.len(), 1);
        assert_eq!(rows[0]["label"], "a");
    }
}
