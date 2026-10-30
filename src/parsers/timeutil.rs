// SPDX-License-Identifier: GPL-3.0-only

use chrono::{DateTime, FixedOffset, NaiveDate, NaiveDateTime, NaiveTime, TimeZone, Utc};
use serde_json::{json, Value};

pub fn rfc3339_micros(dt: DateTime<FixedOffset>) -> String {
    dt.to_rfc3339_opts(chrono::SecondsFormat::Micros, true)
}

pub fn event(
    module: &str,
    dt: DateTime<FixedOffset>,
    message: impl Into<String>,
    timestamp_desc: &str,
    data: Value,
) -> Value {
    json!({
        "datetime": rfc3339_micros(dt),
        "message": message.into(),
        "timestamp_desc": timestamp_desc,
        "module": module,
        "data": data,
    })
}

pub fn wrap_jsonl(parser: &str, events: Vec<Value>) -> Value {
    json!({
        "parser": parser,
        "format": "jsonl",
        "events": events,
    })
}

pub fn parse_apple_datetime(text: &str) -> Option<DateTime<FixedOffset>> {
    let text = text.trim();
    let formats = [
        "%Y-%m-%d %H:%M:%S %z",
        "%Y-%m-%d %H:%M:%S%z",
        "%Y-%m-%dT%H:%M:%S%z",
        "%Y-%m-%dT%H:%M:%SZ",
        "%Y-%m-%dT%H:%M:%S%.f%z",
        "%Y-%m-%dT%H:%M:%S%.fZ",
        "%Y-%m-%d %H:%M:%S.%f %z",
        "%Y-%m-%dT%H:%M:%S%.f%:z",
        "%m/%d/%y %H:%M:%S.%f",
        "%Y-%m-%d %H:%M:%S",
        "%Y-%m-%dT%H:%M:%S",
        "%Y-%m-%dT%H:%M:%S%.f",
    ];
    for fmt in formats {
        if let Ok(dt) = DateTime::parse_from_str(text, fmt) {
            return Some(dt);
        }
        if let Ok(naive) = NaiveDateTime::parse_from_str(text, fmt) {
            return Some(naive.and_utc().fixed_offset());
        }
    }
    // "2024-09-06 9:45:15 AM +0000"
    if let Some(dt) = parse_ampm(text) {
        return Some(dt);
    }
    // "Wed Jan  3 04:05:06 2024"
    if let Ok(naive) = NaiveDateTime::parse_from_str(text, "%a %b %e %H:%M:%S %Y") {
        return Some(naive.and_utc().fixed_offset());
    }
    if let Ok(naive) = NaiveDateTime::parse_from_str(text, "%a %b %d %H:%M:%S %Y") {
        return Some(naive.and_utc().fixed_offset());
    }
    None
}

fn parse_ampm(text: &str) -> Option<DateTime<FixedOffset>> {
    let mut parts = text.split_whitespace();
    let date = parts.next()?;
    let time = parts.next()?;
    let ampm = parts.next()?;
    let tz = parts.next().unwrap_or("+0000");
    if !ampm.eq_ignore_ascii_case("am") && !ampm.eq_ignore_ascii_case("pm") {
        return None;
    }
    let d = NaiveDate::parse_from_str(date, "%Y-%m-%d").ok()?;
    let mut hm: Vec<&str> = time.split(':').collect();
    if hm.len() == 2 {
        hm.push("00");
    }
    if hm.len() != 3 {
        return None;
    }
    let hour_n: u32 = hm[0].parse().ok()?;
    let min_n: u32 = hm[1].parse().ok()?;
    let sec_n: u32 = hm[2].parse().ok()?;
    let mut hour = hour_n;
    if ampm.eq_ignore_ascii_case("pm") && hour < 12 {
        hour += 12;
    }
    if ampm.eq_ignore_ascii_case("am") && hour == 12 {
        hour = 0;
    }
    let t = NaiveTime::from_hms_opt(hour, min_n, sec_n)?;
    let naive = NaiveDateTime::new(d, t);
    let offset = parse_offset_token(tz)?;
    offset.from_local_datetime(&naive).single()
}

pub fn parse_offset_token(tz: &str) -> Option<FixedOffset> {
    let tz = tz.trim();
    if tz == "Z" || tz.eq_ignore_ascii_case("UTC") {
        return FixedOffset::east_opt(0);
    }
    let sign = if tz.starts_with('-') { -1 } else { 1 };
    let digits = tz.trim_start_matches(['+', '-']);
    if digits.len() == 4 && digits.chars().all(|c| c.is_ascii_digit()) {
        let h: i32 = digits[..2].parse().ok()?;
        let m: i32 = digits[2..].parse().ok()?;
        return FixedOffset::east_opt(sign * (h * 3600 + m * 60));
    }
    if let Ok(dt) = DateTime::parse_from_str(&format!("2020-01-01T00:00:00{tz}"), "%Y-%m-%dT%H:%M:%S%z") {
        return Some(*dt.offset());
    }
    None
}

pub fn unix_to_dt(secs: i64) -> DateTime<FixedOffset> {
    DateTime::<Utc>::from_timestamp(secs, 0)
        .unwrap_or_else(Utc::now)
        .fixed_offset()
}

