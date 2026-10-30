// SPDX-License-Identifier: GPL-3.0-only

//! End-to-end checks the GitHub workflow runs: list parsers, open a real
//! `.tar.gz`, and honor the logarchive line cap and memory threshold flags.

use std::fs;
use std::path::Path;
use std::process::Command;

use serde_json::Value;

fn bin() -> &'static str {
    env!("CARGO_BIN_EXE_sdx-cli")
}

fn write_archive(dir: &Path) -> std::path::PathBuf {
    let bundle = dir.join("sysdiagnose_2024.01.02_03-04-05+0000");
    fs::create_dir_all(bundle.join("logs/SystemVersion")).unwrap();
    fs::write(
        bundle.join("ps.txt"),
        "USER UID PID PPID %CPU %MEM PRI NI VSZ RSS WCHAN TT STAT STARTED TIME COMMAND\n\
root 0 1 0 0.0 0.1 31 0 1234 567 - ?? Ss 12:00AM 0:01.00 /sbin/launchd\n\
mobile 501 45 1 1.2 0.4 31 0 2345 890 - ?? S 12:01AM 0:02.00 /usr/libexec/mobileassetd\n",
    )
    .unwrap();
    fs::write(
        bundle.join("logs/SystemVersion/SystemVersion.plist"),
        r#"<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN" "http://www.apple.com/DTDs/PropertyList-1.0.dtd">
<plist version="1.0"><dict>
  <key>ProductName</key><string>iPhone OS</string>
  <key>ProductVersion</key><string>17.0</string>
  <key>ProductBuildVersion</key><string>21A329</string>
</dict></plist>
"#,
    )
    .unwrap();
    fs::write(
        bundle.join("sysdiagnose.log"),
        "IN_PROGRESS_sysdiagnose_2024.01.02_03-04-05+0000\n",
    )
    .unwrap();
    fs::write(
        bundle.join("mount.txt"),
        "/dev/disk1s1 on / (apfs, sealed, read-only, local, journaled)\n",
    )
    .unwrap();
    let archive = dir.join("fixture.tar.gz");
    let status = Command::new("tar")
        .args(["-C"])
        .arg(dir)
        .args(["-czf"])
        .arg(&archive)
        .arg("sysdiagnose_2024.01.02_03-04-05+0000")
        .status()
        .expect("tar");
    assert!(status.success());
    archive
}

fn run(args: &[&str]) -> (i32, String, String) {
    let out = Command::new(bin()).args(args).output().expect("sdx-cli");
    let code = out.status.code().unwrap_or(1);
    let stdout = String::from_utf8_lossy(&out.stdout).into_owned();
    let stderr = String::from_utf8_lossy(&out.stderr).into_owned();
    (code, stdout, stderr)
}

#[test]
fn list_parsers_prints_67_ids_and_descriptions() {
    let (code, stdout, stderr) = run(&["--list-parsers"]);
    assert_eq!(code, 0, "{stderr}");
    let lines: Vec<&str> = stdout.lines().filter(|l| !l.is_empty()).collect();
    assert_eq!(lines.len(), 67, "{stdout}");
    for line in lines {
        let (id, desc) = line.split_once('\t').unwrap_or_else(|| panic!("no tab: {line}"));
        assert!(!id.is_empty());
        assert!(!desc.is_empty(), "{id}");
    }
    assert!(stdout.lines().any(|l| l.starts_with("ps\t")));
    assert!(stdout.lines().any(|l| l.starts_with("logarchive\t")));
}

#[test]
fn missing_archive_exits_with_status_2() {
    let (code, _stdout, stderr) = run(&[]);
    assert_eq!(code, 2, "{stderr}");
    assert!(stderr.contains("missing archive"));
}

#[test]
fn tar_gz_parse_matches_ps_sys_and_mount() {
    let dir = tempfile::tempdir().unwrap();
    let archive = write_archive(dir.path());
    let (code, stdout, stderr) = run(&[
        archive.to_str().unwrap(),
        "--parsers",
        "ps,sys,mount",
        "--show-parser-results",
    ]);
    assert_eq!(code, 0, "{stderr}");
    let doc: Value = serde_json::from_str(&stdout).unwrap_or_else(|e| panic!("{e}\n{stdout}"));

    assert_eq!(doc["ps"]["ok"], true);
    assert_eq!(doc["ps"]["data"]["rows"][0]["pid"], 1);
    assert_eq!(doc["ps"]["data"]["rows"][0]["command"], "/sbin/launchd");
    assert_eq!(doc["ps"]["data"]["rows"][1]["pid"], 45);
    assert_eq!(doc["ps"]["data"]["rows"].as_array().unwrap().len(), 2);

    assert_eq!(doc["sys"]["data"]["plist"]["ProductBuildVersion"], "21A329");
    assert_eq!(doc["sys"]["data"]["message"], "SystemVersion iPhone OS 17.0 21A329");
    assert_eq!(
        doc["sys"]["data"]["source"],
        "logs/SystemVersion/SystemVersion.plist"
    );

    assert_eq!(doc["mount"]["data"]["summary"]["root_sealed"], true);
    assert_eq!(doc["mount"]["data"]["summary"]["root_read_only"], true);
    assert_eq!(doc["mount"]["data"]["events"][0]["data"]["device"], "/dev/disk1s1");
}

#[test]
fn summary_lines_report_ok_without_json() {
    let dir = tempfile::tempdir().unwrap();
    let archive = write_archive(dir.path());
    let (code, stdout, stderr) = run(&[archive.to_str().unwrap(), "--parsers", "ps,sys"]);
    assert_eq!(code, 0, "{stderr}");
    let mut saw_ps = false;
    let mut saw_sys = false;
    for line in stdout.lines() {
        let mut parts = line.split('\t');
        let id = parts.next().unwrap();
        let ok = parts.next().unwrap();
        let ms = parts.next().unwrap();
        assert_eq!(ok, "true", "{line}");
        assert!(ms.ends_with("ms"), "{line}");
        assert!(!line.contains("ProductBuildVersion"));
        match id {
            "ps" => saw_ps = true,
            "sys" => saw_sys = true,
            other => panic!("unexpected parser {other}"),
        }
    }
    assert!(saw_ps && saw_sys);
}

#[test]
fn unknown_parser_name_does_not_run_the_full_set() {
    let dir = tempfile::tempdir().unwrap();
    let archive = write_archive(dir.path());
    let (code, stdout, stderr) = run(&[
        archive.to_str().unwrap(),
        "--parsers",
        "not_a_parser",
    ]);
    assert_eq!(code, 0, "{stderr}");
    assert!(stdout.trim().is_empty(), "{stdout}");
}

#[test]
fn logarchive_flags_reach_decode_meta() {
    let dir = tempfile::tempdir().unwrap();
    let archive = write_archive(dir.path());
    let (code, stdout, stderr) = run(&[
        archive.to_str().unwrap(),
        "--parsers",
        "logarchive",
        "--logarchive-decode-max-lines",
        "0",
        "--logarchive-memory-threshold",
        "4096",
        "--show-parser-results",
    ]);
    assert_eq!(code, 0, "{stderr}");
    let doc: Value = serde_json::from_str(&stdout).unwrap();
    let meta = &doc["logarchive"]["data"]["decode_meta"];
    assert_eq!(meta["max_lines"], 250_000);
    assert_eq!(meta["memory_threshold"], 4096);
    assert_eq!(meta["status"], "skipped");
    assert_eq!(doc["logarchive"]["ok"], true);
}
