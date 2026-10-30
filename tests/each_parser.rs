// SPDX-License-Identifier: GPL-3.0-only

//! One fixture test per parser. Each test builds a small archive, runs that
//! parser through `parser_for`, and checks fields the parser is supposed to
//! extract. An empty archive must still return `Ok`.
//!
//! `each_parser_type_has_its_own_test` fails if a new `ParserType` is added
//! without a `fn parser_<id>` in this file. `cargo test` in CI runs this crate.

#![cfg(not(target_arch = "wasm32"))]

use std::collections::HashMap;
use std::io::Write;
use std::sync::Arc;

use flate2::write::GzEncoder;
use flate2::Compression;
use serde_json::Value;
use sysdiagnose_extractor_library::{
    all_parser_types, parser_for, ParserType, SysdiagnoseArchive,
};

const IOREG: &str = include_str!("../testdata/fixtures/ioreg_basic.txt");
const REMOTECTL: &[u8] = include_bytes!("../testdata/fixtures/remotectl_dumpstate_golden.txt");

const PLIST: &str = r#"<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN" "http://www.apple.com/DTDs/PropertyList-1.0.dtd">
<plist version="1.0"><dict>
  <key>ProductName</key><string>iPhone OS</string>
  <key>ProductVersion</key><string>17.0</string>
  <key>ProductBuildVersion</key><string>21A329</string>
</dict></plist>"#;

fn files(pairs: &[(&str, &[u8])]) -> SysdiagnoseArchive {
    let mut m = HashMap::new();
    for (path, bytes) in pairs {
        m.insert((*path).to_string(), Arc::<[u8]>::from(*bytes));
    }
    SysdiagnoseArchive::from_files_for_test(m)
}

fn parse(kind: ParserType, pairs: &[(&str, &[u8])]) -> Value {
    parser_for(kind)
        .parse(&files(pairs))
        .unwrap_or_else(|e| panic!("{kind:?} failed: {e}"))
}

fn empty_ok(kind: ParserType) {
    parser_for(kind)
        .parse(&files(&[]))
        .unwrap_or_else(|e| panic!("{kind:?} on an empty archive: {e}"));
}

fn sqlite(sql: &str) -> Vec<u8> {
    let tmp = tempfile::NamedTempFile::new().expect("sqlite temp");
    let conn = rusqlite::Connection::open(tmp.path()).expect("sqlite open");
    conn.execute_batch(sql).expect("sqlite schema");
    drop(conn);
    std::fs::read(tmp.path()).expect("sqlite bytes")
}

fn gzip(text: &str) -> Vec<u8> {
    let mut enc = GzEncoder::new(Vec::new(), Compression::default());
    enc.write_all(text.as_bytes()).unwrap();
    enc.finish().unwrap()
}

fn events(v: &Value) -> &[Value] {
    v["events"].as_array().expect("events array")
}

fn data_has(v: &Value, key_part: &str, value: &str) -> bool {
    let want = key_part.to_ascii_lowercase();
    events(v).iter().any(|ev| {
        ev["data"]
            .as_object()
            .map(|m| {
                m.iter().any(|(k, val)| {
                    k.to_ascii_lowercase().contains(&want) && val.as_str() == Some(value)
                })
            })
            .unwrap_or(false)
    })
}

fn plist_dict(body: &str) -> String {
    format!(
        r#"<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN" "http://www.apple.com/DTDs/PropertyList-1.0.dtd">
<plist version="1.0"><dict>{body}</dict></plist>"#
    )
}

#[test]
fn each_parser_type_has_its_own_test() {
    let src = include_str!("each_parser.rs");
    for kind in all_parser_types() {
        let needle = format!("fn parser_{}()", kind.as_str());
        assert!(
            src.contains(&needle),
            "missing dedicated test `{needle}` for parser {}",
            kind.as_str()
        );
    }
}

#[test]
fn parser_accessibility_tcc() {
    empty_ok(ParserType::accessibility_tcc);
    let db = sqlite(
        "CREATE TABLE access (
            last_modified INTEGER, service TEXT, client TEXT,
            auth_value INTEGER, auth_reason INTEGER, client_type INTEGER,
            indirect_object_identifier TEXT
        );
        INSERT INTO access VALUES (1700000000, 'kTCCServiceCamera', 'com.example.tccapp', 2, 0, 0, '');
        CREATE TABLE service (client TEXT);
        INSERT INTO service VALUES ('probe');",
    );
    let v = parse(ParserType::accessibility_tcc, &[("logs/Accessibility/TCC.db", &db)]);
    assert_eq!(v["parser"], "accessibility_tcc");
    assert_eq!(v["format"], "jsonl");
    assert!(data_has(&v, "client", "com.example.tccapp"));
    assert!(data_has(&v, "service", "kTCCServiceCamera"));
    assert_eq!(events(&v)[0]["module"], "accessibility_tcc");
}

#[test]
fn parser_apollo_all() {
    empty_ok(ParserType::apollo_all);
    let db = sqlite(
        "CREATE TABLE access (
            last_modified INTEGER, service TEXT, client TEXT,
            auth_value INTEGER, auth_reason INTEGER, client_type INTEGER,
            indirect_object_identifier TEXT
        );
        INSERT INTO access VALUES (1700000000, 'kTCCServiceCamera', 'com.example.tccapp', 2, 0, 0, '');
        CREATE TABLE service (client TEXT);",
    );
    let v = parse(ParserType::apollo_all, &[("logs/Accessibility/TCC.db", &db)]);
    assert_eq!(v["parser"], "apollo_all");
    assert!(data_has(&v, "client", "com.example.tccapp"));
}

#[test]
fn parser_appinstallation() {
    empty_ok(ParserType::appinstallation);
    let db = sqlite(
        "CREATE TABLE ZINSTALL (timestamp INTEGER, name TEXT);
         INSERT INTO ZINSTALL VALUES (1700000000, 'ExampleApp');",
    );
    let v = parse(
        ParserType::appinstallation,
        &[("logs/appinstallation/AppUpdates.sqlitedb", &db)],
    );
    assert_eq!(events(&v).len(), 1);
    assert_eq!(events(&v)[0]["data"]["db_table"], "ZINSTALL");
    assert_eq!(events(&v)[0]["data"]["name"], "ExampleApp");
    assert_eq!(events(&v)[0]["timestamp_desc"], "ZINSTALL");
}

#[test]
fn parser_avconference_callsettings() {
    empty_ok(ParserType::avconference_callsettings);
    let gz = gzip("000000.000000 call started\n");
    let v = parse(
        ParserType::avconference_callsettings,
        &[("logs/AVConference/20260101-120000-CallSettings.calldump.gz", &gz)],
    );
    assert_eq!(v["parser"], "avconference_callsettings");
    assert_eq!(events(&v).len(), 1);
    assert_eq!(events(&v)[0]["message"], "call started");
    assert_eq!(events(&v)[0]["module"], "avconference_callsettings");
}

#[test]
fn parser_awd_baseband() {
    empty_ok(ParserType::awd_baseband);
    let v = parse(ParserType::awd_baseband, &[("logs/AWD/radio.metriclog", b"\x1f\x8bmetric")]);
    assert_eq!(v["parser"], "awd_baseband");
    assert_eq!(v["format"], "inventory");
    assert_eq!(v["file_count"], 1);
    assert_eq!(v["files"][0]["path"], "logs/AWD/radio.metriclog");
    assert_eq!(v["files"][0]["magic"], "gzip");
    assert_eq!(v["files"][0]["size"], 8);
}

#[test]
fn parser_battery_bdc() {
    empty_ok(ParserType::battery_bdc);
    let csv = b"timestamp,level\n2024-01-02 03:04:05,80\n";
    let v = parse(ParserType::battery_bdc, &[("logs/BatteryBDC/power.csv", csv)]);
    assert_eq!(events(&v).len(), 1);
    assert_eq!(events(&v)[0]["message"], "power state report");
    assert_eq!(events(&v)[0]["data"]["level"], "80");
    assert_eq!(events(&v)[0]["data"]["type"], "power");
    assert_eq!(events(&v)[0]["timestamp_desc"], "battery bdc");
}

#[test]
fn parser_bluetooth() {
    empty_ok(ParserType::bluetooth);
    let text = b"Power: On\nMAC Address: aa:bb:cc:dd:ee:ff\nName: Keyboard\n";
    let v = parse(ParserType::bluetooth, &[("WiFi/bluetooth_status.txt", text)]);
    assert_eq!(v["parser"], "bluetooth");
    assert_eq!(v["summary"]["power"], "On");
    assert_eq!(v["summary"]["mac_address"], "aa:bb:cc:dd:ee:ff");
    let devices = v["devices"].as_array().unwrap();
    assert!(devices.iter().any(|d| d["name"] == "Keyboard"));
    assert!(devices.iter().any(|d| d["address"] == "aa:bb:cc:dd:ee:ff"));
    assert_eq!(events(&v)[0]["module"], "bluetooth");
}

#[test]
fn parser_brctl() {
    empty_ok(ParserType::brctl);
    let list = b"id: com.example.app localizedName: App documents: Mobile Documents clients: [x]\n";
    let dump = b"brctl dump\n[2024-01-02] OS:17.0 CloudDocs:1 BirdSchema:2 DBSchema:3\n";
    let v = parse(
        ParserType::brctl,
        &[
            ("brctl/brctl-container-list.txt", list),
            ("brctl/brctl-dump.txt", dump),
        ],
    );
    assert_eq!(v["data"]["containers"][0]["id"], "com.example.app");
    assert_eq!(v["data"]["containers"][0]["localizedName"], "App");
    assert_eq!(v["data"]["boot_history"][0]["OS"], "17.0");
    assert_eq!(v["data"]["boot_history"][0]["CloudDocs"], "1");
}

#[test]
fn parser_ckks_pcs() {
    empty_ok(ParserType::ckks_pcs);
    let v = parse(ParserType::ckks_pcs, &[("ckksctl_status.txt", b"pcs: ready\n")]);
    assert_eq!(v["parser"], "ckks_pcs");
    assert_eq!(v["format"], "files");
    assert_eq!(v["files"]["ckksctl_status.txt"], "pcs: ready\n");
    assert_eq!(v["meta"]["returned"], 1);
}

#[test]
fn parser_collection_meta() {
    empty_ok(ParserType::collection_meta);
    let v = parse(
        ParserType::collection_meta,
        &[
            ("errors/timeout.txt", b"task timed out\n"),
            ("summaries/crashes.log", b"one crash line that is long enough\n"),
            ("taskSummary.csv", b"name,status\nps,ok\n"),
            ("sysdiagnose.log", b"IN_PROGRESS_sysdiagnose_2024.01.02_03-04-05+0000\n"),
        ],
    );
    assert_eq!(v["parser"], "collection_meta");
    assert_eq!(v["errors"]["errors/timeout.txt"], "task timed out\n");
    assert_eq!(v["meta"]["error_file_count"], 1);
    assert_eq!(v["task_summary"][0]["raw"], "ps,ok");
    assert!(v["summaries"]["summaries/crashes.log"]["preview"]
        .as_str()
        .unwrap()
        .contains("one crash"));
    assert!(v["sysdiagnose_log"]["preview"]
        .as_str()
        .unwrap()
        .contains("2024.01.02"));
}

#[test]
fn parser_containermanager() {
    empty_ok(ParserType::containermanager);
    let line = b"Mon Jan  2 03:04:05 2024 [42] <Notice> (0xabc) -[ContainerManager setup]: container ready\n";
    let v = parse(
        ParserType::containermanager,
        &[("logs/MobileContainerManager/containermanagerd.log", line)],
    );
    assert_eq!(events(&v).len(), 1);
    assert_eq!(events(&v)[0]["message"], "container ready");
    assert_eq!(events(&v)[0]["data"]["loglevel"], "Notice");
    assert_eq!(events(&v)[0]["module"], "containermanager");
}

#[test]
fn parser_crashlogs() {
    empty_ok(ParserType::crashlogs);
    let ips = br#"{"app_name":"ExampleApp","timestamp":"2024-01-02 03:04:05.000000 +0000","threads":[{"id":0}]}
"#;
    let v = parse(
        ParserType::crashlogs,
        &[("crashes_and_spins/ExampleApp.ips", ips)],
    );
    assert_eq!(events(&v).len(), 1);
    assert_eq!(events(&v)[0]["message"], "crash ExampleApp");
    assert_eq!(events(&v)[0]["data"]["app_name"], "ExampleApp");
    assert_eq!(events(&v)[0]["data"]["filename"], "ExampleApp.ips");
    assert_eq!(events(&v)[0]["module"], "crashlogs");
}

#[test]
fn parser_disks() {
    empty_ok(ParserType::disks);
    let text = b"Filesystem Size Used Avail Capacity iused ifree %iused Mounted on\n\
/dev/disk1s1 1G 512M 512M 50% 1000 2000 33% /\n";
    let v = parse(ParserType::disks, &[("disks.txt", text)]);
    assert_eq!(events(&v).len(), 1);
    assert_eq!(events(&v)[0]["data"]["filesystem"], "/dev/disk1s1");
    assert_eq!(events(&v)[0]["data"]["mounted_on"], "/");
    assert_eq!(events(&v)[0]["data"]["size_bytes"], 1024 * 1024 * 1024);
    assert_eq!(events(&v)[0]["data"]["iused"], "1000");
    assert_eq!(events(&v)[0]["message"], "Disk usage on / (/dev/disk1s1)");
}

fn plane(kind: ParserType, path: &str, id: &str) {
    empty_ok(kind);
    let v = parse(kind, &[(path, IOREG.as_bytes())]);
    assert_eq!(v["parser"], id);
    assert_eq!(v["tree"]["class"], "test1");
    assert_eq!(v["tree"]["key1"], "val1");
    assert_eq!(v["tree"]["data 1"], "value 1");
    assert_eq!(v["tree"]["Node 2"]["class"], "test2");
    assert_eq!(v["tree"]["Node 2"]["#address-cells"], "<02000000>");
    assert_eq!(v["tree"]["Node 2"]["Node 3"]["class"], "test3");
    assert_eq!(v["tree"]["Node 2"]["Node 3"]["key3"], "val3");
}

#[test]
fn parser_ioacpiplane() {
    plane(ParserType::ioacpiplane, "ioreg/IOACPIPlane.txt", "ioacpiplane");
}

#[test]
fn parser_iodevicetree() {
    plane(ParserType::iodevicetree, "ioreg/IODeviceTree.txt", "iodevicetree");
}

#[test]
fn parser_iofirewire() {
    plane(ParserType::iofirewire, "ioreg/IOFireWire.txt", "iofirewire");
}

#[test]
fn parser_iopower() {
    plane(ParserType::iopower, "ioreg/IOPower.txt", "iopower");
}

#[test]
fn parser_ioservice() {
    empty_ok(ParserType::ioservice);
    let v = parse(ParserType::ioservice, &[("ioreg/IOService.txt", IOREG.as_bytes())]);
    assert_eq!(v["parser"], "ioservice");
    assert_eq!(v["format"], "compact");
    assert!(v["summary"]["node_count"].as_u64().unwrap() >= 3);
    assert_eq!(v["tree"]["class"], "test1");
}

#[test]
fn parser_iousb() {
    plane(ParserType::iousb, "ioreg/IOUSB.txt", "iousb");
}

#[test]
fn parser_interactionc() {
    empty_ok(ParserType::interactionc);
    let db = sqlite(
        "CREATE TABLE ZINTERACTIONS (
            ZSTARTDATE REAL, ZENDDATE REAL, ZBUNDLEID TEXT, ZACCOUNT TEXT,
            ZTARGETBUNDLEID TEXT, ZDIRECTION TEXT, ZRECIPIENTCOUNT INTEGER,
            ZDOMAINIDENTIFIER TEXT, ZISRESPONSE INTEGER, ZCREATIONDATE REAL,
            ZCONTENTURL TEXT, ZLOCATIONUUID TEXT, ZGROUPNAME TEXT,
            ZDERIVEDINTENTIDENTIFIER TEXT, Z_PK INTEGER, ZSENDER INTEGER
        );
        INSERT INTO ZINTERACTIONS VALUES (
            0, 1, 'com.example.chat', 'acct', 'com.example.target', '1', 1,
            'dom', 0, 0, 'https://example.test/c', 'loc', 'group', 'intent', 1, 1
        );
        CREATE TABLE ZCONTACTS (
            Z_PK INTEGER, ZDISPLAYNAME TEXT, ZIDENTIFIER TEXT, ZPERSONID TEXT,
            ZINCOMINGRECIPIENTCOUNT INTEGER, ZINCOMINGSENDERCOUNT INTEGER,
            ZOUTGOINGRECIPIENTCOUNT INTEGER, ZCREATIONDATE REAL,
            ZFIRSTINCOMINGRECIPIENTDATE REAL, ZFIRSTINCOMINGSENDERDATE REAL,
            ZFIRSTOUTGOINGRECIPIENTDATE REAL, ZLASTINCOMINGSENDERDATE REAL,
            ZLASTINCOMINGRECIPIENTDATE REAL, ZLASTOUTGOINGRECIPIENTDATE REAL,
            ZCUSTOMIDENTIFIER TEXT
        );
        INSERT INTO ZCONTACTS VALUES (
            1, 'Ada', 'ada-id', 'p1', 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 'custom'
        );
        CREATE TABLE Z_1INTERACTIONS (Z_3INTERACTIONS INTEGER, Z_1ATTACHMENTS INTEGER);
        CREATE TABLE ZATTACHMENT (
            Z_PK INTEGER, ZCONTENTTEXT TEXT, ZUTI TEXT, ZCONTENTURL TEXT,
            ZSIZEINBYTES INTEGER, ZPHOTOLOCALIDENTIFIER TEXT, ZIDENTIFIER BLOB,
            ZCLOUDIDENTIFIER TEXT
        );
        CREATE TABLE Z_2INTERACTIONRECIPIENT (
            Z_3INTERACTIONRECIPIENT INTEGER, Z_2RECIPIENTS INTEGER
        );",
    );
    let v = parse(ParserType::interactionc, &[("logs/interactionC.db", &db)]);
    assert_eq!(v["parser"], "interactionc");
    assert!(
        data_has(&v, "bundle", "com.example.chat"),
        "interaction row missing bundle id: {v}"
    );
}

#[test]
fn parser_ioport() {
    plane(ParserType::ioport, "ioreg/IOPort.txt", "ioport");
}

#[test]
fn parser_itunesstore() {
    empty_ok(ParserType::itunesstore);
    let missing = parse(ParserType::itunesstore, &[]);
    assert!(missing["source_path"].is_null());
    let db = sqlite(
        "CREATE TABLE download (bundle_id TEXT);
         INSERT INTO download VALUES ('com.example.store');",
    );
    let v = parse(
        ParserType::itunesstore,
        &[("logs/itunesstored/downloads.1.sqlitedb", &db)],
    );
    assert_eq!(v["parser"], "itunesstore");
    assert_eq!(v["source_path"], "logs/itunesstored/downloads.1.sqlitedb");
    assert_eq!(v["data"]["download"][0]["bundle_id"], "com.example.store");
}

#[test]
fn parser_kbdebug() {
    empty_ok(ParserType::kbdebug);
    let text = b"2024-01-02 03:04:05 +0000: Error: keyboard failed\n";
    let v = parse(ParserType::kbdebug, &[("kbdebug.txt", text)]);
    assert_eq!(events(&v).len(), 1);
    assert_eq!(events(&v)[0]["message"], "keyboard failed");
    assert_eq!(events(&v)[0]["data"]["level"], "Error");
    assert_eq!(events(&v)[0]["timestamp_desc"], "kbdebug event");
}

#[test]
fn parser_knowledgec() {
    empty_ok(ParserType::knowledgec);
    let db = sqlite(
        "CREATE TABLE ZOBJECT (
            Z_PK INTEGER, ZSTARTDATE REAL, ZENDDATE REAL, ZVALUESTRING TEXT,
            ZSTARTDAYOFWEEK TEXT, ZSECONDSFROMGMT INTEGER, ZCREATIONDATE REAL,
            ZUUID TEXT, ZSTRUCTUREDMETADATA INTEGER, ZSOURCE INTEGER, ZSTREAMNAME TEXT
        );
        INSERT INTO ZOBJECT VALUES (
            1, 0, 10, 'com.example.knowledge', '2', 0, 0, 'uuid-1', 1, 1, '/app/activity'
        );
        CREATE TABLE ZSTRUCTUREDMETADATA (
            Z_PK INTEGER,
            Z_DKAPPLICATIONACTIVITYMETADATAKEY__ACTIVITYTYPE TEXT,
            Z_DKAPPLICATIONACTIVITYMETADATAKEY__CONTENTDESCRIPTION TEXT,
            Z_DKAPPLICATIONACTIVITYMETADATAKEY__USERACTIVITYREQUIREDSTRING TEXT,
            Z_DKAPPLICATIONACTIVITYMETADATAKEY__ITEMRELATEDCONTENTURL TEXT,
            Z_DKAPPLICATIONACTIVITYMETADATAKEY__SUGGESTEDINVOCATIONPHRASE TEXT,
            Z_DKAPPLICATIONACTIVITYMETADATAKEY__ITEMRELATEDUNIQUEIDENTIFIER TEXT,
            Z_DKAPPLICATIONACTIVITYMETADATAKEY__ITEMIDENTIFIER TEXT,
            Z_DKAPPLICATIONACTIVITYMETADATAKEY__USERACTIVITYUUID TEXT,
            Z_DKAPPLICATIONACTIVITYMETADATAKEY__ISELIGIBLEFORPREDICTION INTEGER,
            Z_DKAPPLICATIONACTIVITYMETADATAKEY__ISPUBLICLYINDEXABLE INTEGER,
            Z_DKAPPLICATIONACTIVITYMETADATAKEY__EXPIRATIONDATE REAL,
            ZMETADATAHASH TEXT
        );
        INSERT INTO ZSTRUCTUREDMETADATA VALUES (
            1, 'browse', 'desc', 'req', 'https://example.test/k', 'phrase', 'uniq',
            'item', 'act-uuid', 1, 0, 0, 'hash'
        );
        CREATE TABLE ZSOURCE (Z_PK INTEGER, ZGROUPID TEXT, ZSOURCEID TEXT);
        INSERT INTO ZSOURCE VALUES (1, 'group', 'source');",
    );
    let v = parse(
        ParserType::knowledgec,
        &[("logs/Knowledge/knowledgeC.db", &db)],
    );
    assert_eq!(v["parser"], "knowledgec");
    assert!(
        data_has(&v, "bundle", "com.example.knowledge"),
        "knowledge row missing bundle id: {v}"
    );
}

#[test]
fn parser_lockdownd() {
    empty_ok(ParserType::lockdownd);
    let text = b"01/02/24 03:04:05.000000 pid=42 Pair: device paired\n";
    let v = parse(
        ParserType::lockdownd,
        &[("logs/MobileLockdown/lockdownd.log", text)],
    );
    assert_eq!(events(&v).len(), 1);
    assert_eq!(events(&v)[0]["message"], "device paired");
    assert_eq!(events(&v)[0]["data"]["pid"], 42);
    assert_eq!(events(&v)[0]["data"]["event_type"], "Pair");
}

#[test]
fn parser_logarchive() {
    empty_ok(ParserType::logarchive);
    let v = parse(
        ParserType::logarchive,
        &[("system_logs.logarchive/Extra/shutdown.log", b"no tracev3 here\n")],
    );
    assert_eq!(v["parser"], "logarchive");
    assert_eq!(v["inventory"]["file_count"], 1);
    assert_eq!(v["inventory"]["total_bytes"], 16);
    assert_eq!(
        v["inventory"]["paths"][0]["path"],
        "system_logs.logarchive/Extra/shutdown.log"
    );
    assert_eq!(v["inventory"]["by_subdir"]["Extra"], 1);
    assert_eq!(v["decode"], "skipped");
    assert_eq!(v["decode_meta"]["status"], "skipped");
    assert_eq!(v["decode_meta"]["tool"], "mul-unifiedlog");
}

#[test]
fn parser_logdata_statistics() {
    empty_ok(ParserType::logdata_statistics);
    let line = br#"{"unixTime":1700000000,"file":"system.log","type":"log","processList":[{"process":"configd"}]}
"#;
    let v = parse(
        ParserType::logdata_statistics,
        &[("system_logs.logarchive/Extra/logdata.statistics.0.jsonl", line)],
    );
    assert_eq!(events(&v).len(), 1);
    assert_eq!(events(&v)[0]["message"], "process configd");
    assert_eq!(events(&v)[0]["data"]["file"], "system.log");
    assert_eq!(events(&v)[0]["data"]["process"], "configd");
    assert_eq!(events(&v)[0]["timestamp_desc"], "logdata statistics");
}

#[test]
fn parser_logdata_statistics_txt() {
    empty_ok(ParserType::logdata_statistics_txt);
    let text = b"--- logd statistics\ntime: 2024-01-02 03:04:05\nfile: system.log\ntype: log\n- [1, configd]\n";
    let v = parse(
        ParserType::logdata_statistics_txt,
        &[("system_logs.logarchive/Extra/logdata.statistics.0.txt", text)],
    );
    assert!(!events(&v).is_empty(), "{v}");
    assert!(events(&v).iter().any(|e| e["data"]["process"] == "configd"));
    assert!(events(&v).iter().any(|e| e["data"]["file"] == "system.log"));
}

#[test]
fn parser_lsaw() {
    empty_ok(ParserType::lsaw);
    let missing = parse(ParserType::lsaw, &[]);
    assert!(missing["source_path"].is_null());
    assert_eq!(missing["format"], "csstore_strings");
    let blob = b"\x00https://example.test/launch\x00com.example.bundle\x00";
    let v = parse(ParserType::lsaw, &[("logs/lsaw.csstoredump", blob)]);
    assert_eq!(v["parser"], "lsaw");
    assert_eq!(v["gzip"], false);
    assert_eq!(v["source_path"], "logs/lsaw.csstoredump");
    assert_eq!(v["strings"]["urls"][0], "https://example.test/launch");
    assert_eq!(v["strings"]["bundle_id_hints"][0], "com.example.bundle");
    assert_eq!(v["strings"]["url_count"], 1);
}

#[test]
fn parser_mcsettingsevents() {
    empty_ok(ParserType::mcsettingsevents);
    let body = r#"<key>root</key><dict><key>nested</key><dict>
        <key>timestamp</key><string>2024-01-02T03:04:05.123456</string>
        <key>event</key><string>changed</string>
        <key>process</key><string>configd</string>
    </dict></dict>"#;
    let xml = plist_dict(body);
    let v = parse(
        ParserType::mcsettingsevents,
        &[("logs/MCState/Shared/MCSettingsEvents.plist", xml.as_bytes())],
    );
    assert_eq!(events(&v).len(), 1);
    assert!(events(&v)[0]["message"].as_str().unwrap().contains("configd"));
    assert_eq!(events(&v)[0]["data"]["setting"], "root.nested");
}

#[test]
fn parser_mcstate_shared_profile() {
    empty_ok(ParserType::mcstate_shared_profile);
    let body = r#"<key>InstallDate</key><string>2024-06-15T10:20:30.000000</string>
        <key>PayloadType</key><string>Configuration</string>
        <key>PayloadDescription</key><string>desk profile</string>
        <key>PayloadDisplayName</key><string>Desk</string>
        <key>PayloadOrganization</key><string>Example</string>"#;
    let xml = plist_dict(body);
    let v = parse(
        ParserType::mcstate_shared_profile,
        &[("logs/MCState/Shared/profile-desk.stub", xml.as_bytes())],
    );
    assert_eq!(events(&v).len(), 1);
    assert!(events(&v)[0]["message"].as_str().unwrap().contains("desk profile"));
    assert!(events(&v)[0]["timestamp_desc"]
        .as_str()
        .unwrap()
        .contains("Configuration"));
}

#[test]
fn parser_microstackshots() {
    empty_ok(ParserType::microstackshots);
    let v = parse(
        ParserType::microstackshots,
        &[("logs/stacks/microstackshots", b"bplist00stack")],
    );
    assert_eq!(v["parser"], "microstackshots");
    assert_eq!(v["format"], "inventory");
    assert_eq!(v["files"][0]["magic"], "bplist");
    assert_eq!(v["files"][0]["path"], "logs/stacks/microstackshots");
    assert_eq!(v["total_bytes"], b"bplist00stack".len() as u64);
}

#[test]
fn parser_mobileactivation() {
    empty_ok(ParserType::mobileactivation);
    let line = b"Mon Jan  2 03:04:05 2024 [7] <Info> (0x1) -[Activation start]: device activated\n";
    let v = parse(
        ParserType::mobileactivation,
        &[("logs/MobileActivation/mobileactivationd.log", line)],
    );
    assert_eq!(events(&v)[0]["message"], "device activated");
    assert_eq!(events(&v)[0]["data"]["hexID"], "0x1");
    assert_eq!(events(&v)[0]["module"], "mobileactivation");
}

#[test]
fn parser_mobilebackup() {
    empty_ok(ParserType::mobilebackup);
    let body = r#"<key>BackupStateInfo</key><dict><key>errors</key><array><dict>
        <key>date</key><string>2023-02-22T10:24:49.051000</string>
        <key>domain</key><string>MBErrorDomain</string>
        <key>localizedDescription</key><string>backup failed</string>
    </dict></array></dict>
    <key>PreflightSizing</key><dict>
        <key>MobileDeviceDomain-com.example.app</key><integer>12345</integer>
    </dict>"#;
    let xml = plist_dict(body);
    let v = parse(
        ParserType::mobilebackup,
        &[("logs/MobileBackup/com.apple.MobileBackup.plist", xml.as_bytes())],
    );
    assert_eq!(events(&v).len(), 2);
    assert!(events(&v).iter().any(|e| e["message"].as_str().unwrap().contains("backup failed")));
    assert!(events(&v).iter().any(|e| e["message"].as_str().unwrap().contains("PreflightSizing")));
}

#[test]
fn parser_mobileinstallation() {
    empty_ok(ParserType::mobileinstallation);
    let line = b"Mon Jan  2 03:04:05 2024 [9] <Notice> (0x2) -[MIInstallable install]: installed com.example.app\n";
    let v = parse(
        ParserType::mobileinstallation,
        &[("logs/MobileInstallation/mobile_installation.log", line)],
    );
    assert_eq!(events(&v)[0]["message"], "installed com.example.app");
    assert_eq!(events(&v)[0]["timestamp_desc"], "mobileinstallation event");
    assert_eq!(events(&v)[0]["module"], "mobileinstallation");
}

#[test]
fn parser_mount() {
    empty_ok(ParserType::mount);
    let text = b"/dev/disk1s1 on / (apfs, sealed, read-only, local, journaled)\n";
    let v = parse(ParserType::mount, &[("mount.txt", text)]);
    assert_eq!(v["summary"]["root_sealed"], true);
    assert_eq!(v["summary"]["root_read_only"], true);
    assert_eq!(v["summary"]["integrity_hint"], "system_partition_sealed_readonly");
    assert_eq!(events(&v)[0]["data"]["device"], "/dev/disk1s1");
    assert_eq!(events(&v)[0]["data"]["is_root"], true);
}

#[test]
fn parser_networkextension() {
    empty_ok(ParserType::networkextension);
    let xml = plist_dict(r#"<key>VPN</key><string>ExampleVPN</string>"#);
    let v = parse(
        ParserType::networkextension,
        &[("logs/Networking/com.apple.networkextension.plist", xml.as_bytes())],
    );
    assert_eq!(
        v["logs/Networking/com.apple.networkextension.plist"]["VPN"],
        "ExampleVPN"
    );
}

#[test]
fn parser_networkextensioncache() {
    empty_ok(ParserType::networkextensioncache);
    let xml = plist_dict(r#"<key>Cache</key><string>warm</string>"#);
    let v = parse(
        ParserType::networkextensioncache,
        &[(
            "logs/Networking/com.apple.networkextension.cache.plist",
            xml.as_bytes(),
        )],
    );
    assert_eq!(
        v["logs/Networking/com.apple.networkextension.cache.plist"]["Cache"],
        "warm"
    );
}

#[test]
fn parser_netusage() {
    empty_ok(ParserType::netusage);
    let db = sqlite(
        "CREATE TABLE ZPROCESS (
            ZTIMESTAMP REAL, ZFIRSTTIMESTAMP REAL, ZPROCNAME TEXT, ZBUNDLENAME TEXT, Z_PK INTEGER
        );
        INSERT INTO ZPROCESS VALUES (0, 0, 'netd', 'com.example.net', 7);",
    );
    let v = parse(ParserType::netusage, &[("logs/Networking/netusage.sqlite", &db)]);
    assert_eq!(v["parser"], "netusage");
    assert!(data_has(&v, "process", "netd") || data_has(&v, "bundle", "com.example.net"), "{v}");
}

#[test]
fn parser_olddsc() {
    empty_ok(ParserType::olddsc);
    let body = r#"<key>Binaries</key><array><dict>
        <key>Path</key><string>/usr/lib/foo</string>
        <key>UUID_String</key><string>U1</string>
    </dict></array>"#;
    let xml = plist_dict(body);
    let v = parse(ParserType::olddsc, &[("logs/olddsc/shared.plist", xml.as_bytes())]);
    assert_eq!(events(&v).len(), 1);
    assert!(events(&v)[0]["message"].as_str().unwrap().contains("/usr/lib/foo"));
    assert_eq!(events(&v)[0]["data"]["timestamp_info"], "sysdiagnose creation time");
}

#[test]
fn parser_ota_update() {
    empty_ok(ParserType::ota_update);
    let text = b"seeding mobile asset\nrestore finished\n";
    let v = parse(ParserType::ota_update, &[("restore_perform.txt", text)]);
    assert_eq!(v["parser"], "ota_update");
    assert_eq!(v["files_index"][0]["path"], "restore_perform.txt");
    let hints = v["restore_hints"].as_array().unwrap();
    assert!(hints.iter().any(|h| h["text"].as_str().unwrap().contains("restore finished")));
    assert!(hints.iter().any(|h| h["text"].as_str().unwrap().contains("seeding")));
    assert_eq!(events(&v)[0]["data"]["hit_count"], 2);
}

#[test]
fn parser_plists() {
    empty_ok(ParserType::plists);
    let v = parse(
        ParserType::plists,
        &[
            ("ok.plist", PLIST.as_bytes()),
            ("bad.plist", b"not a plist"),
        ],
    );
    assert_eq!(v["parser"], "plists");
    assert_eq!(v["files"]["ok.plist"]["ProductBuildVersion"], "21A329");
    assert_eq!(v["files"]["bad.plist"], serde_json::json!({}));
    assert!(!v["meta"]["parse_failures"].as_array().unwrap().is_empty());
}

#[test]
fn parser_powerlogs() {
    empty_ok(ParserType::powerlogs);
    let db = sqlite(
        "CREATE TABLE timestamp (BundleID TEXT);
        CREATE TABLE PLAppTimeService_Aggregate_AppRunTime (
            timestamp REAL, BundleID TEXT, ScreenOnTime REAL, BackgroundTime REAL
        );
        INSERT INTO PLAppTimeService_Aggregate_AppRunTime VALUES (0, 'com.example.power', 3, 4);",
    );
    let v = parse(
        ParserType::powerlogs,
        &[("logs/powerlogs/CurrentPowerlog.PLSQL", &db)],
    );
    assert_eq!(v["parser"], "powerlogs");
    assert!(
        data_has(&v, "bundle", "com.example.power"),
        "powerlog row missing bundle: {v}"
    );
}

#[test]
fn parser_preferences() {
    empty_ok(ParserType::preferences);
    let v = parse(ParserType::preferences, &[("Preferences/notes.txt", b"locale=en\n")]);
    assert_eq!(v["files"]["Preferences/notes.txt"], "locale=en\n");
    assert_eq!(v["meta"]["total_matched"], 1);
    assert_eq!(v["parser"], "preferences");
}

#[test]
fn parser_ps() {
    empty_ok(ParserType::ps);
    let text = b"USER  PID COMMAND\nroot  1 /sbin/launchd\nmobile  45 /usr/bin/foo bar\n";
    let v = parse(ParserType::ps, &[("ps.txt", text)]);
    assert_eq!(v["rows"].as_array().unwrap().len(), 2);
    assert_eq!(v["rows"][0]["user"], "root");
    assert_eq!(v["rows"][0]["pid"], 1);
    assert_eq!(v["rows"][0]["command"], "/sbin/launchd");
    assert_eq!(v["rows"][1]["command"], "/usr/bin/foo bar");
}

#[test]
fn parser_psthread() {
    empty_ok(ParserType::psthread);
    let text = b"USER PID COMMAND\nroot 1 /sbin/launchd\nroot 1 /sbin/launchd\nmobile 45 /usr/bin/foo\n";
    let v = parse(ParserType::psthread, &[("ps_thread.txt", text)]);
    let entries = v["entries"].as_array().unwrap();
    let launchd = entries.iter().find(|e| e["pid"] == 1).unwrap();
    assert_eq!(launchd["threads"], 2);
    assert_eq!(launchd["command"], "/sbin/launchd");
    assert!(launchd["message"].as_str().unwrap().contains("launchd"));
    let foo = entries.iter().find(|e| e["pid"] == 45).unwrap();
    assert_eq!(foo["threads"], 1);
}

#[test]
fn parser_quarantine_events() {
    empty_ok(ParserType::quarantine_events);
    let db = sqlite(
        "CREATE TABLE LSQUARANTINEEVENT (
            LSQUARANTINETIMESTAMP REAL,
            LSQUARANTINEEVENTIDENTIFIER TEXT,
            LSQUARANTINEAGENTBUNDLEIDENTIFIER TEXT,
            LSQUARANTINEAGENTNAME TEXT,
            LSQUARANTINETYPENUMBER INTEGER,
            LSQUARANTINESENDERNAME TEXT,
            LSQUARANTINESENDERADDRESS TEXT,
            LSQUARANTINEORIGINTITLE TEXT,
            LSQUARANTINEORIGINURLSTRING TEXT,
            LSQUARANTINEORIGINALIAS TEXT,
            LSQUARANTINEDATAURLSTRING TEXT
        );
        INSERT INTO LSQUARANTINEEVENT VALUES (
            0, 'evt-1', 'com.example.agent', 'Safari', 1, 'Ada', 'ada@example.test',
            'Download', 'https://example.test/file', 'alias', 'https://example.test/data'
        );",
    );
    let v = parse(
        ParserType::quarantine_events,
        &[("logs/com.apple.LaunchServices.QuarantineEventsV2", &db)],
    );
    assert!(
        data_has(&v, "agent", "com.example.agent") || data_has(&v, "bundle", "com.example.agent"),
        "{v}"
    );
}

#[test]
fn parser_remotectl_dumpstate() {
    empty_ok(ParserType::remotectl_dumpstate);
    let v = parse(ParserType::remotectl_dumpstate, &[("remotectl_dumpstate.txt", REMOTECTL)]);
    assert_eq!(v["parser"], "remotectl_dumpstate");
    assert_eq!(v["data"]["Device"]["OSVersion"], "17.2.1");
}

#[test]
fn parser_runningboard() {
    empty_ok(ParserType::runningboard);
    let text = b"domain:com.apple.board name:com.example.assertion RBSPreventIdleSleepGrant\n";
    let v = parse(
        ParserType::runningboard,
        &[("RunningBoard/RunningBoard_state.log", text)],
    );
    assert_eq!(v["domains"][0], "com.apple.board");
    assert_eq!(v["assertions"][0], "com.example.assertion");
    assert_eq!(v["grants"][0], "RBSPreventIdleSleepGrant");
    assert_eq!(v["prevent_idle_sleep_mentions"], 1);
    assert_eq!(events(&v)[0]["data"]["domain_count"], 1);
}

#[test]
fn parser_safari_history() {
    empty_ok(ParserType::safari_history);
    let db = sqlite(
        "CREATE TABLE THIS (x TEXT);
        CREATE TABLE HISTORY_ITEMS (ID INTEGER, URL TEXT, VISIT_COUNT INTEGER);
        CREATE TABLE HISTORY_VISITS (
            ID INTEGER, VISIT_TIME REAL, TITLE TEXT, ORIGIN INTEGER,
            LOAD_SUCCESSFUL INTEGER, REDIRECT_SOURCE INTEGER, REDIRECT_DESTINATION INTEGER,
            HISTORY_ITEM INTEGER
        );
        INSERT INTO HISTORY_ITEMS VALUES (1, 'https://example.test/page', 2);
        INSERT INTO HISTORY_VISITS VALUES (1, 0, 'Example', 0, 1, NULL, NULL, 1);",
    );
    let v = parse(ParserType::safari_history, &[("logs/Safari/History.db", &db)]);
    assert_eq!(v["parser"], "safari_history");
    assert!(
        data_has(&v, "url", "https://example.test/page"),
        "safari history missing url: {v}"
    );
}

#[test]
fn parser_security_sysdiagnose() {
    empty_ok(ParserType::security_sysdiagnose);
    let text = b"Genp keychain state:\ndesc=testdesc,agrp=testgrp,cdat=2020-01-02 03:04:05 +0000\n";
    let v = parse(ParserType::security_sysdiagnose, &[("security-sysdiagnose.txt", text)]);
    assert_eq!(events(&v).len(), 1);
    assert_eq!(events(&v)[0]["data"]["section"], "genp");
    assert_eq!(events(&v)[0]["data"]["attributes"]["agrp"], "testgrp");
    assert_eq!(events(&v)[0]["module"], "security_sysdiagnose");
}

#[test]
fn parser_screentime() {
    empty_ok(ParserType::screentime);
    let db = sqlite(
        "CREATE TABLE ZUSAGETIMEDITEM (Z_PK INTEGER, ZCATEGORY INTEGER);
        INSERT INTO ZUSAGETIMEDITEM VALUES (1, 1);
        CREATE TABLE ZUSAGECATEGORY (Z_PK INTEGER, ZBLOCK INTEGER);
        INSERT INTO ZUSAGECATEGORY VALUES (1, 1);
        CREATE TABLE ZUSAGEBLOCK (
            Z_PK INTEGER, ZUSAGE INTEGER, ZSTARTDATE REAL, ZSCREENTIMEINSECONDS REAL,
            ZLONGESTSESSIONSTARTDATE REAL, ZLONGESTSESSIONENDDATE REAL, ZLASTEVENTDATE REAL,
            ZPLATFORM INTEGER
        );
        INSERT INTO ZUSAGEBLOCK VALUES (1, 1, 0, 120, 0, 60, 60, 2);
        CREATE TABLE ZUSAGE (Z_PK INTEGER, ZUSER INTEGER, ZDEVICE INTEGER);
        INSERT INTO ZUSAGE VALUES (1, 1, 1);
        CREATE TABLE ZCOREUSER (
            Z_PK INTEGER, ZGIVENNAME TEXT, ZFAMILYNAME TEXT, ZFAMILYMEMBERTYPE INTEGER,
            ZAPPLEID TEXT, ZDSID TEXT, ZALTDSID TEXT
        );
        INSERT INTO ZCOREUSER VALUES (1, 'Ada', 'Lovelace', 1, 'ada@example.test', 'ds', 'alt');
        CREATE TABLE ZCOREDEVICE (
            Z_PK INTEGER, ZNAME TEXT, ZPLATFORM INTEGER, ZIDENTIFIER TEXT, ZLOCALUSERDEVICESTATE TEXT
        );
        INSERT INTO ZCOREDEVICE VALUES (1, 'phone', 2, 'dev-1', 'local');",
    );
    let v = parse(
        ParserType::screentime,
        &[("logs/ScreenTime/RMAdminStore-Local.sqlite", &db)],
    );
    assert_eq!(v["parser"], "screentime");
    assert!(
        data_has(&v, "given", "Ada") || data_has(&v, "name", "Ada"),
        "screentime row missing given name: {v}"
    );
}

#[test]
fn parser_shutdownlogs() {
    empty_ok(ParserType::shutdownlogs);
    let text = b"After 1.5s\nremaining client pid: 99 (/sbin/launchd)\nSIGTERM: [1700000000]\n";
    let v = parse(
        ParserType::shutdownlogs,
        &[("system_logs.logarchive/Extra/shutdown.log", text)],
    );
    assert_eq!(events(&v).len(), 1);
    assert_eq!(events(&v)[0]["data"]["pid"], 99);
    assert_eq!(events(&v)[0]["data"]["command"], "launchd");
    assert_eq!(events(&v)[0]["data"]["time_waiting"], 1.5);
    assert!(events(&v)[0]["message"].as_str().unwrap().contains("launchd"));
    assert_eq!(v["sources"][0], "system_logs.logarchive/Extra/shutdown.log");
}

#[test]
fn parser_spindumpnosymbols() {
    empty_ok(ParserType::spindumpnosymbols);
    let text = b"Date/Time:       2020-01-02 10:00:00 +0000\n\
Process:         launchd [1]\n\
Path:            /sbin/launchd\n\
Thread 0x1234 priority 31\n\
Binary Images:\n\
0x1000 - 0x2000  dyld  (AAAAAAAA-BBBB-CCCC-DDDD-EEEEEEEEEEEE)  /usr/lib/dyld\n";
    let v = parse(ParserType::spindumpnosymbols, &[("logs/spindump-nosymbols.txt", text)]);
    assert!(!events(&v).is_empty());
    let proc = events(&v).iter().find(|e| e["message"].as_str().unwrap().contains("launchd")).unwrap();
    assert_eq!(proc["data"]["pid"], 1);
    assert_eq!(proc["data"]["process"], "launchd");
    assert_eq!(proc["data"]["threads"][0]["thread"], "0x1234");
    assert_eq!(proc["data"]["images"][0]["path"], "/usr/lib/dyld");
}

#[test]
fn parser_swcutil() {
    empty_ok(ParserType::swcutil);
    let text = b"Version: 1\n\
======== DATABASE ========\n\
Service: applinks\n\
Domain: example.test\n\
Last Checked: 2020-01-02 03:04:05 +0000\n\
---\n\
======== NETWORK ========\n\
example.test extra\n\
======== MEMORY ========\n\
swcd: 2 MB\n";
    let v = parse(ParserType::swcutil, &[("swcutil_show.txt", text)]);
    assert!(events(&v).iter().any(|e| {
        e["message"].as_str().unwrap().contains("applinks")
            && e["message"].as_str().unwrap().contains("example.test")
    }));
    assert!(events(&v).iter().any(|e| e["data"]["section"] == "network" && e["data"]["domain"] == "example.test"));
    assert!(events(&v).iter().any(|e| e["data"]["usage"] == 2 * 1024 * 1024));
}

#[test]
fn parser_sys() {
    empty_ok(ParserType::sys);
    let v = parse(
        ParserType::sys,
        &[("logs/SystemVersion/SystemVersion.plist", PLIST.as_bytes())],
    );
    assert_eq!(v["parser"], "sys");
    assert_eq!(v["plist"]["ProductVersion"], "17.0");
    assert_eq!(v["plist"]["ProductBuildVersion"], "21A329");
    assert_eq!(v["message"], "SystemVersion iPhone OS 17.0 21A329");
    assert_eq!(v["source"], "logs/SystemVersion/SystemVersion.plist");
}

#[test]
fn parser_system_stats() {
    empty_ok(ParserType::system_stats);
    let v = parse(ParserType::system_stats, &[("vm_stat.txt", b"Pages free: 100\n")]);
    assert_eq!(v["files"]["vm_stat.txt"], "Pages free: 100\n");
    assert_eq!(v["parser"], "system_stats");
    assert_eq!(v["meta"]["returned"], 1);
}

#[test]
fn parser_taskinfo() {
    empty_ok(ParserType::taskinfo);
    let text = b"num tasks: 1\n\nprocess: launchd [1]\nthreads: 1\n\n";
    let v = parse(ParserType::taskinfo, &[("taskinfo.txt", text)]);
    assert_eq!(v["source"], "taskinfo.txt");
    assert!(events(&v).iter().any(|e| e["data"]["tasks"] == 1));
    assert!(events(&v).iter().any(|e| e["data"]["process"] == "launchd" && e["data"]["pid"] == 1));
}

#[test]
fn parser_transparency() {
    empty_ok(ParserType::transparency);
    let text = br#"{"registration":[{"app":"com.example","installedAt":"2023-04-11 09:38:27 +0000"}]}"#;
    let v = parse(ParserType::transparency, &[("transparency.log", text)]);
    assert_eq!(v["parser"], "transparency");
    assert!(!events(&v).is_empty());
    assert!(events(&v)[0]["message"].as_str().unwrap().contains("registration"));
    assert_eq!(events(&v)[0]["module"], "transparency");
}

#[test]
fn parser_transparency_json() {
    empty_ok(ParserType::transparency_json);
    let empty = parse(ParserType::transparency_json, &[("transparency.log", b"  \n")]);
    assert_eq!(empty["error"], "empty_file");
    let text = br#"{"registration":[{"app":"com.example"}]}"#;
    let v = parse(ParserType::transparency_json, &[("transparency.log", text)]);
    assert_eq!(v["registration"][0]["app"], "com.example");
}

#[test]
fn parser_usermanagement() {
    empty_ok(ParserType::usermanagement);
    let v = parse(
        ParserType::usermanagement,
        &[("logs/UserManagement/umtool.txt", b"user: mobile\n")],
    );
    assert_eq!(v["files"]["logs/UserManagement/umtool.txt"], "user: mobile\n");
    assert_eq!(v["parser"], "usermanagement");
}

#[test]
fn parser_uuid2path() {
    empty_ok(ParserType::uuid2path);
    let xml = plist_dict(
        r#"<key>AAAAAAAA-BBBB-CCCC-DDDD-EEEEEEEEEEEE</key><string>/usr/lib/dyld</string>"#,
    );
    let v = parse(
        ParserType::uuid2path,
        &[("logs/tailspindb/UUIDToBinaryLocations.plist", xml.as_bytes())],
    );
    assert_eq!(
        v["logs/tailspindb/UUIDToBinaryLocations.plist"]["AAAAAAAA-BBBB-CCCC-DDDD-EEEEEEEEEEEE"],
        "/usr/lib/dyld"
    );
}

#[test]
fn parser_wifi_diagnostics() {
    empty_ok(ParserType::wifi_diagnostics);
    let v = parse(ParserType::wifi_diagnostics, &[("WiFi/arp.txt", b"host.example (1.2.3.4)\n")]);
    assert_eq!(v["files"]["WiFi/arp.txt"], "host.example (1.2.3.4)\n");
    assert_eq!(v["parser"], "wifi_diagnostics");
    assert_eq!(v["meta"]["total_matched"], 1);
}

#[test]
fn parser_wifi_known_networks() {
    empty_ok(ParserType::wifi_known_networks);
    let xml = plist_dict(
        r#"<key>n1</key><dict><key>SSID</key><string>Cafe</string>
        <key>BSSList</key><array><dict>
          <key>LocationLatitude</key><real>48.85</real>
          <key>LocationLongitude</key><real>2.35</real>
        </dict></array></dict>"#,
    );
    let v = parse(
        ParserType::wifi_known_networks,
        &[("WiFi/com.apple.wifi.known-networks.plist", xml.as_bytes())],
    );
    assert_eq!(v["parser"], "wifi_known_networks");
    assert!(!events(&v).is_empty());
    assert_eq!(events(&v)[0]["data"]["latitude"], 48.85);
    assert_eq!(events(&v)[0]["data"]["longitude"], 2.35);
}

#[test]
fn parser_wifinetworks() {
    empty_ok(ParserType::wifinetworks);
    let xml = plist_dict(r#"<key>n1</key><dict><key>SSID</key><string>Cafe</string></dict>"#);
    let v = parse(
        ParserType::wifinetworks,
        &[("WiFi/com.apple.wifi.known-networks.plist", xml.as_bytes())],
    );
    assert_eq!(v["files"]["com.apple.wifi.known-networks"]["n1"]["SSID"], "Cafe");
    assert!(!events(&v).is_empty());
    for ev in events(&v) {
        assert!(ev["message"].is_string());
        assert!(ev["datetime"].is_string());
        assert!(ev["module"].is_string());
    }
}

#[test]
fn parser_wifiscan() {
    empty_ok(ParserType::wifiscan);
    let text = b"Cafe - ssid=43616665, rssi=-40, channel=6\nscan total=1\n";
    let v = parse(ParserType::wifiscan, &[("WiFi/wifi_scan.txt", text)]);
    assert!(events(&v).iter().any(|e| e["data"]["ssid"] == "Cafe" && e["timestamp_desc"] == "wifi scan"));
    assert!(events(&v).iter().any(|e| e["timestamp_desc"] == "wifi scan summary"));
}

#[test]
fn parser_wifisecurity() {
    empty_ok(ParserType::wifisecurity);
    let missing = parse(ParserType::wifisecurity, &[]);
    assert_eq!(missing["error"], "missing security.txt");
    let text = b"acct : Cafe\ncdat : 2020-01-02 03:04:05 +0000\n";
    let v = parse(ParserType::wifisecurity, &[("WiFi/security.txt", text)]);
    assert_eq!(events(&v).len(), 1);
    assert_eq!(events(&v)[0]["data"]["acct"], "Cafe");
    assert_eq!(events(&v)[0]["message"], "wifi security Cafe");
    assert_eq!(events(&v)[0]["timestamp_desc"], "wifi AP config created");
}
