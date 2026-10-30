// SPDX-License-Identifier: GPL-3.0-only

//! Parser smoke test on a fixture archive owned by this crate.
//!
//! Every parser must return `Ok`. JSONL events must carry `message`, `datetime`,
//! `timestamp_desc`, and `module`.

use std::collections::HashMap;
use std::sync::Arc;

use sysdiagnose_extractor_library::{
    all_parser_types, parser_for, run_parsers_concurrently, ParserType, SysdiagnoseArchive,
};

const REQUIRED_JSONL_FIELDS: &[&str] = &["message", "datetime", "timestamp_desc", "module"];

fn fixture_archive() -> SysdiagnoseArchive {
    let mut files: HashMap<String, Arc<[u8]>> = HashMap::new();
    files.insert(
        "ps.txt".into(),
        Arc::from(
            &b"USER UID PID PPID %CPU %MEM PRI NI VSZ RSS WCHAN TT STAT STARTED TIME COMMAND\n\
root 0 1 0 0.0 0.1 31 0 1234 567 - ?? Ss 12:00AM 0:01.00 /sbin/launchd\n\
mobile 501 45 1 1.2 0.4 31 0 2345 890 - ?? S 12:01AM 0:02.00 /usr/libexec/mobileassetd\n"[..],
        ),
    );
    files.insert(
        "disks.txt".into(),
        Arc::from(
            &b"Filesystem Size Used Avail Capacity iused ifree %iused Mounted on\n\
/dev/disk1s1 1G 512M 512M 50% 1000 2000 33% /\n"[..],
        ),
    );
    files.insert(
        "logs/SystemVersion/SystemVersion.plist".into(),
        Arc::from(
            &br#"<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN" "http://www.apple.com/DTDs/PropertyList-1.0.dtd">
<plist version="1.0">
<dict>
  <key>ProductName</key><string>iPhone OS</string>
  <key>ProductVersion</key><string>17.0</string>
  <key>ProductBuildVersion</key><string>21A329</string>
</dict>
</plist>
"#[..],
        ),
    );
    files.insert(
        "sysdiagnose.log".into(),
        Arc::from(&b"IN_PROGRESS_sysdiagnose_2024.01.02_03-04-05+0000\n"[..]),
    );
    files.insert(
        "mount.txt".into(),
        Arc::from(&b"/dev/disk1s1 on / (apfs, sealed, read-only, local, journaled)\n"[..]),
    );
    SysdiagnoseArchive::from_files_for_test(files)
}

fn assert_jsonl_fields(parser: ParserType, v: &serde_json::Value) {
    if v.get("format").and_then(|x| x.as_str()) != Some("jsonl") {
        return;
    }
    let Some(events) = v.get("events").and_then(|e| e.as_array()) else {
        return;
    };
    for (i, ev) in events.iter().enumerate() {
        let obj = ev
            .as_object()
            .unwrap_or_else(|| panic!("{parser:?} events[{i}] is not an object"));
        for field in REQUIRED_JSONL_FIELDS {
            let val = obj
                .get(*field)
                .unwrap_or_else(|| panic!("{parser:?} events[{i}] missing `{field}`"));
            assert!(val.is_string(), "{parser:?} events[{i}].{field} must be a string");
        }
    }
}

#[test]
fn fixture_archive_all_parsers_ok() {
    let archive = Arc::new(fixture_archive());
    let jobs: Vec<_> = all_parser_types()
        .into_iter()
        .map(|t| (t, parser_for(t)))
        .collect();
    let results = run_parsers_concurrently(Arc::clone(&archive), jobs);
    assert_eq!(results.len(), 67);
    for (kind, res, _) in &results {
        let value = res
            .as_ref()
            .unwrap_or_else(|e| panic!("parser {} failed: {e}", kind.as_str()));
        assert_jsonl_fields(*kind, value);
    }

    let ps = results
        .iter()
        .find(|(t, _, _)| *t == ParserType::ps)
        .unwrap()
        .1
        .as_ref()
        .unwrap();
    assert_eq!(ps["rows"].as_array().unwrap().len(), 2);
    assert_eq!(ps["rows"][0]["command"], "/sbin/launchd");

    let sys = results
        .iter()
        .find(|(t, _, _)| *t == ParserType::sys)
        .unwrap()
        .1
        .as_ref()
        .unwrap();
    assert_eq!(sys["plist"]["ProductBuildVersion"], "21A329");
    assert_eq!(sys["message"], "SystemVersion iPhone OS 17.0 21A329");

    let disks = results
        .iter()
        .find(|(t, _, _)| *t == ParserType::disks)
        .unwrap()
        .1
        .as_ref()
        .unwrap();
    let disk_events = disks["events"].as_array().unwrap();
    assert_eq!(disk_events.len(), 1);
    assert_eq!(disk_events[0]["data"]["filesystem"], "/dev/disk1s1");
    assert_eq!(disk_events[0]["data"]["mounted_on"], "/");
    assert_eq!(disk_events[0]["data"]["iused"], "1000");
    assert_eq!(disk_events[0]["data"]["size_bytes"], 1024 * 1024 * 1024);
    assert_eq!(disk_events[0]["message"], "Disk usage on / (/dev/disk1s1)");

    let mount = results
        .iter()
        .find(|(t, _, _)| *t == ParserType::mount)
        .unwrap()
        .1
        .as_ref()
        .unwrap();
    assert_eq!(mount["summary"]["root_sealed"], true);
    assert_eq!(mount["summary"]["root_read_only"], true);
    assert_eq!(mount["summary"]["integrity_hint"], "system_partition_sealed_readonly");
    let root = &mount["events"][0]["data"];
    assert_eq!(root["device"], "/dev/disk1s1");
    assert_eq!(root["mountpoint"], "/");
    assert_eq!(root["is_root"], true);
}
