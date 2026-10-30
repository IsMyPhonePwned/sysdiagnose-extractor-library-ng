// SPDX-License-Identifier: GPL-3.0-only

//! Unit tests for SAF-style event helpers and timeline parsers in [`super`].

use std::collections::HashMap;
use std::io::Write;
use std::sync::Arc;

use chrono::{FixedOffset, TimeZone, Utc};
use flate2::write::GzEncoder;
use flate2::Compression;
use serde_json::json;

use crate::archive::SysdiagnoseArchive;
use crate::parsers::MAX_UTF8_FILE;

use super::{
    appinstallation_events_from_tables, decompress_gzip, extract_lockdownd, extract_multiline_log,
    matching_utf8_files, mc_settings_events, mcstate_shared_profile_events, mobilebackup_events,
    olddsc_events, parse_avconference_gzip, parse_battery_bdc_csv, parse_disks_txt,
    parse_kbdebug_log, parse_logdata_statistics_jsonl, parse_logdata_statistics_txt,
    parse_wifi_scan, parse_wifi_security, sysdiagnose_creation, transparency_extract_events,
    wrap_jsonl,
};

fn test_archive(files: &[(&str, &[u8])]) -> SysdiagnoseArchive {
    let mut m = HashMap::new();
    for (p, b) in files {
        m.insert((*p).to_string(), Arc::from(b.to_vec().into_boxed_slice()));
    }
    SysdiagnoseArchive::from_files_for_test(m)
}

#[test]
fn wrap_jsonl_shape() {
    let v = wrap_jsonl(
        "demo",
        vec![json!({"datetime": "2020-01-01T00:00:00+00:00", "message": "m"})],
    );
    assert_eq!(v["parser"], "demo");
    assert_eq!(v["format"], "jsonl");
    assert_eq!(v["events"].as_array().unwrap().len(), 1);
}

#[test]
fn sysdiagnose_creation_from_log_in_progress() {
    let log = b"foo IN_PROGRESS_sysdiagnose_2026.04.07_15-01-20+0200_bar more\n";
    let arch = test_archive(&[("sysdiagnose.log", log)]);
    let dt = sysdiagnose_creation(&arch);
    assert_eq!(dt.format("%Y-%m-%d %H:%M").to_string(), "2026-04-07 15:01");
    assert_eq!(dt.offset().local_minus_utc(), 2 * 3600);
}

#[test]
fn sysdiagnose_creation_from_bundle_acquisition() {
    let arch = SysdiagnoseArchive::from_files_for_test_with_bundle(
        HashMap::from([("dummy.txt".into(), Arc::from(&b"x"[..]))]),
        Some("sysdiagnose_2026.04.07_15-01-20+0200_iPhone-OS_iPhone_23D127".into()),
    );
    let dt = sysdiagnose_creation(&arch);
    assert_eq!(dt.format("%Y-%m-%d %H:%M").to_string(), "2026-04-07 15:01");
}

#[test]
fn matching_utf8_files_skips_oversized_members() {
    let big = vec![b'x'; MAX_UTF8_FILE + 1];
    let arch = test_archive(&[("huge.txt", big.as_slice()), ("ok.txt", b"hi")]);
    let v = matching_utf8_files(&arch, &["*.txt"]).expect("glob");
    assert_eq!(v.len(), 1);
    assert_eq!(v[0].0, "ok.txt");
    assert_eq!(v[0].1, "hi");
}

#[test]
fn matching_utf8_files_sorted_and_capped() {
    let arch = test_archive(&[
        ("z.txt", b"last"),
        ("a.txt", b"first"),
        ("b.txt", b"second"),
    ]);
    let v = matching_utf8_files(&arch, &["*.txt"]).expect("glob");
    assert_eq!(v.len(), 3);
    assert_eq!(v[0].0, "a.txt");
    assert_eq!(v[0].1, "first");
    assert_eq!(v[1].0, "b.txt");
    assert_eq!(v[2].0, "z.txt");
}

#[test]
fn parse_kbdebug_log_two_events() {
    let text =
        "2024-01-15 10:00:00 +0000: INFO: first line\n2024-01-15 10:00:01 +0000: WARN: second";
    let ev = parse_kbdebug_log(text, "kbdebug");
    assert_eq!(ev.len(), 2);
    assert_eq!(ev[0]["module"], "kbdebug");
    assert_eq!(ev[0]["timestamp_desc"], "kbdebug event");
    assert_eq!(ev[0]["message"], "first line");
    assert_eq!(ev[0]["data"]["level"], "INFO");
    assert_eq!(ev[1]["data"]["level"], "WARN");
    assert_eq!(ev[1]["message"], "second");
    assert!(ev[0]["datetime"].as_str().unwrap().contains("2024-01-15"));
}

#[test]
fn parse_kbdebug_log_empty() {
    assert!(parse_kbdebug_log("", "kbdebug").is_empty());
    assert!(parse_kbdebug_log("no timestamps here", "kbdebug").is_empty());
}

#[test]
fn extract_lockdownd_single_entry() {
    // First 24 chars must parse as %m/%d/%y %H:%M:%S.%f (see lockdownd.py).
    let line = "06/15/24 12:00:00.123456 pid=42 com.apple.foo: hello world\n";
    let tz = FixedOffset::east_opt(0).unwrap();
    let ev = extract_lockdownd(line, "lockdownd", tz);
    assert_eq!(ev.len(), 1);
    assert_eq!(ev[0]["module"], "lockdownd");
    assert_eq!(ev[0]["message"], "hello world");
    assert_eq!(ev[0]["data"]["pid"], 42);
    assert_eq!(ev[0]["data"]["event_type"], "com.apple.foo");
}

#[test]
fn parse_disks_txt_derives_bytes() {
    let text = "Filesystem Size Used Avail Capacity Mounted on\n/dev/disk1 1G 512M 512M 50% /";
    let ts = Utc
        .with_ymd_and_hms(2024, 6, 1, 12, 0, 0)
        .unwrap()
        .fixed_offset();
    let ev = parse_disks_txt(text, "disks", ts);
    assert_eq!(ev.len(), 1);
    assert_eq!(ev[0]["message"], "Disk usage on / (/dev/disk1)");
    let data = ev[0]["data"].as_object().unwrap();
    assert_eq!(
        data.get("size_bytes").and_then(|v| v.as_i64()),
        Some(1024 * 1024 * 1024)
    );
    assert_eq!(
        data.get("used_bytes").and_then(|v| v.as_i64()),
        Some(512 * 1024 * 1024)
    );
}

#[test]
fn parse_battery_bdc_csv_timestamp_and_set_system_time() {
    let csv = "TimeStamp,col\n2021-09-01 00:00:00,foo\n";
    let ev = parse_battery_bdc_csv(csv, "battery_bdc", "powerlog_1").expect("csv");
    assert_eq!(ev.len(), 1);
    assert_eq!(ev[0]["message"], "power state report");
    assert_eq!(ev[0]["data"]["col"], "foo");
    assert_eq!(ev[0]["data"]["type"], "powerlog_1");
    assert!(!ev[0]["data"].as_object().unwrap().contains_key("TimeStamp"));

    let csv2 = "set_system_time,col\n2022-03-04 05:06:07 +0000,bar\n";
    let ev2 = parse_battery_bdc_csv(csv2, "battery_bdc", "t").expect("csv2");
    assert_eq!(ev2.len(), 1);
    assert_eq!(ev2[0]["data"]["col"], "bar");
}

#[test]
fn parse_logdata_statistics_jsonl_process_list() {
    let line = r#"{"unixTime":1700000000,"type":"foo","file":"/x","processList":[{"process":"/bin/launchd"},{"process":"/sbin/foo"}]}"#;
    let ev = parse_logdata_statistics_jsonl(line, "logdata_statistics");
    assert_eq!(ev.len(), 2);
    assert!(ev[0]["message"].as_str().unwrap().contains("launchd"));
    assert!(ev[1]["message"].as_str().unwrap().contains("foo"));
    assert_eq!(ev[0]["data"]["file"], "/x");
}

#[test]
fn parse_logdata_statistics_jsonl_unix_time_as_integer() {
    let line = r#"{"unixTime":1700000000,"type":"t","file":"f","processList":[{"process":"p"}]}"#;
    let line2 = r#"{"unixTime":1700000001,"type":"t","file":"f","processList":[{"process":"q"}]}"#;
    let ev = parse_logdata_statistics_jsonl(&format!("{line}\n{line2}"), "m");
    assert_eq!(ev.len(), 2);
    assert_eq!(ev[1]["data"]["process"], "q");
}

#[test]
fn parse_logdata_statistics_txt_record() {
    let text = r"--- !logd statistics record
time  : 2024-01-02 03:04:05+0000
file  : /var/log/test.log
type  : foo
- [ 1, 0.0, /usr/bin/example ]
--- !other
";
    let ev = parse_logdata_statistics_txt(text, "logdata_statistics_txt");
    assert_eq!(ev.len(), 1);
    assert!(ev[0]["message"].as_str().unwrap().contains("example"));
    assert_eq!(ev[0]["data"]["process"], "/usr/bin/example");
}

#[test]
fn extract_multiline_log_apple_line() {
    let line = concat!(
        "Wed Jan  3 04:05:06 2024 [123] <Notice> (0xabc)-[subsystem event]: ",
        "hello\n",
    );
    let tz = FixedOffset::east_opt(0).unwrap();
    let ev = extract_multiline_log(line, "testmod", tz);
    assert_eq!(ev.len(), 1);
    assert_eq!(ev[0]["module"], "testmod");
    assert_eq!(ev[0]["message"], "hello");
    assert_eq!(ev[0]["data"]["loglevel"], "Notice");
    assert_eq!(ev[0]["data"]["hexID"], "0xabc");
}

#[test]
fn extract_multiline_log_spaced_selector() {
    let line = "Thu Apr  9 12:34:22 2026 [143] <notice> (0xabcdef1234) -[ExampleClass method:]: hello there\n";
    let tz = FixedOffset::east_opt(0).unwrap();
    let ev = extract_multiline_log(line, "mobileinstallation", tz);
    assert_eq!(ev.len(), 1);
    assert_eq!(ev[0]["message"], "hello there");
    assert_eq!(ev[0]["data"]["hexID"], "0xabcdef1234");
    assert_eq!(ev[0]["data"]["event_type"], "ExampleClass method:");
    assert_eq!(ev[0]["data"]["loglevel"], "notice");
}

#[test]
fn transparency_extract_events_registration_and_state_machine() {
    let root = json!({
        "registration": [{"app": "com.example", "installedAt": "2023-04-11 09:38:27 +0000"}],
        "stateMachine": {
            "accountFirstSeen": "2023-05-01 10:00:00 +0000",
            "backgroundOp": {"lastDutyCycle": "2023-06-01T12:00:00Z"},
            "lasts": {"k": "2023-07-01 11:00:00 +0000"},
            "launch": ["2024-08-19T09:00:28.946+0200 - boot"],
            "lockState": "x 2024-08-19 09:00:28 +0200",
            "ops": {"op1": "noise 2024-09-01 00:00:00 +0000 tail"}
        }
    });
    let ev = transparency_extract_events(&root, "transparency");
    assert!(ev.len() >= 6);
    let msgs: Vec<_> = ev.iter().filter_map(|e| e["message"].as_str()).collect();
    assert!(msgs.iter().any(|m| m.contains("registration")));
    assert!(msgs.iter().any(|m| m.contains("accountFirstSeen")));
    assert!(msgs.iter().any(|m| m.contains("lastDutyCycle")));
    assert!(msgs.iter().any(|m| m.contains("stateMachine last")));
    assert!(msgs.iter().any(|m| m.contains("launch")));
    assert!(msgs.iter().any(|m| m.contains("lockState")));
}

#[test]
fn mc_settings_events_finds_timestamp_nodes() {
    let plist = json!({
        "root": {
            "nested": {
                "timestamp": "2024-01-02T03:04:05.123456",
                "event": "changed",
                "process": "configd"
            }
        }
    });
    let ev = mc_settings_events(&plist, "mcsettingsevents");
    assert_eq!(ev.len(), 1);
    assert!(ev[0]["message"].as_str().unwrap().contains("configd"));
    assert_eq!(ev[0]["data"]["setting"], "root.nested");
}

#[test]
fn mcstate_shared_profile_events_install_date() {
    let plist = json!({
        "InstallDate": "2024-06-15T10:20:30.000000",
        "PayloadType": "Configuration",
        "PayloadDescription": "d",
        "PayloadDisplayName": "n",
        "PayloadOrganization": "o"
    });
    let ev = mcstate_shared_profile_events(&plist, "mcstate_shared_profile").expect("events");
    assert_eq!(ev.len(), 1);
    assert!(ev[0]["message"].as_str().unwrap().contains("d"));
    assert!(ev[0]["timestamp_desc"]
        .as_str()
        .unwrap()
        .contains("Configuration"));
}

#[test]
fn olddsc_events_from_binaries() {
    let plist = json!({
        "Binaries": [{"Path": "/usr/lib/foo", "UUID_String": "U1"}]
    });
    let ts = Utc
        .with_ymd_and_hms(2025, 1, 1, 0, 0, 0)
        .unwrap()
        .fixed_offset();
    let ev = olddsc_events(&plist, "olddsc", ts);
    assert_eq!(ev.len(), 1);
    assert!(ev[0]["message"].as_str().unwrap().contains("/usr/lib/foo"));
    assert_eq!(ev[0]["data"]["timestamp_info"], "sysdiagnose creation time");
}

#[test]
fn mobilebackup_events_errors_and_preflight() {
    let plist = json!({
        "BackupStateInfo": {"errors": [{
            "date": "2023-02-22T10:24:49.051000",
            "domain": "MBErrorDomain",
            "localizedDescription": "oops"
        }]},
        "PreflightSizing": {"MobileDeviceDomain-com.example.app": 12345}
    });
    let ts = Utc
        .with_ymd_and_hms(2024, 1, 1, 0, 0, 0)
        .unwrap()
        .fixed_offset();
    let ev = mobilebackup_events(&plist, "mobilebackup", ts);
    assert_eq!(ev.len(), 2);
    assert!(ev[0]["message"].as_str().unwrap().contains("oops"));
    assert!(!ev[0]["data"].as_object().unwrap().contains_key("date"));
    assert!(ev[1]["message"]
        .as_str()
        .unwrap()
        .contains("PreflightSizing"));
}

#[test]
fn appinstallation_events_from_tables_skips_sqlite_sequence() {
    let db = json!({
        "sqlite_sequence": [],
        "ZINSTALL": [{"timestamp": 1700000000, "name": "App"}]
    });
    let ev = appinstallation_events_from_tables(&db, "appinstallation");
    assert_eq!(ev.len(), 1);
    assert_eq!(ev[0]["timestamp_desc"], "ZINSTALL");
    assert_eq!(ev[0]["data"]["db_table"], "ZINSTALL");
    assert_eq!(ev[0]["data"]["name"], "App");
}

#[test]
fn decompress_gzip_roundtrip_and_parse_avconference() {
    let inner = "000000.000000 line-a\nline-b\n";
    let mut enc = GzEncoder::new(Vec::new(), Compression::default());
    enc.write_all(inner.as_bytes()).unwrap();
    let gz = enc.finish().unwrap();
    let dec = decompress_gzip(&gz).expect("gzip");
    assert_eq!(String::from_utf8_lossy(&dec), inner);

    let path = "logs/AVConference/20260101-120000-foo.calldump.gz";
    let ev = parse_avconference_gzip(path, &dec, "avconference_callsettings").expect("parse");
    assert_eq!(ev.len(), 2);
    assert_eq!(ev[0]["message"], "line-a");
    assert_eq!(ev[1]["message"], "line-b");
}

#[test]
fn parse_avconference_rejects_bad_filename() {
    let dec = b"x";
    assert!(parse_avconference_gzip("nope.gz", dec, "m").is_err());
}

#[test]
fn parse_wifi_scan_summary_and_kv_line() {
    let ts = Utc
        .with_ymd_and_hms(2024, 1, 1, 0, 0, 0)
        .unwrap()
        .fixed_offset();
    let text = "total=a=1,b=2\nFIRSTCONWIFI - ssid=414243, ch=6\n";
    let ev = parse_wifi_scan(text, "wifiscan", ts);
    assert_eq!(ev.len(), 2);
    assert!(ev[0]["message"].as_str().unwrap().contains("total"));
    assert_eq!(ev[1]["data"]["ssid"], "FIRSTCONWIFI");
}

#[test]
fn parse_wifi_security_keychain_block() {
    // A line without ` : ` ends the block and flushes (matches SAF wifisecurity.py).
    let text = "acct : MySSID\ncdat : 2023-02-09 21:10:38 +0000\ndesc : d\nlabl : l\nmdat : 2023-02-09 21:10:38 +0000\n--end--\n";
    let ev = parse_wifi_security(text, "wifisecurity");
    assert_eq!(ev.len(), 1);
    assert!(ev[0]["message"].as_str().unwrap().contains("MySSID"));
    assert_eq!(ev[0]["timestamp_desc"], "wifi AP config created");
}
