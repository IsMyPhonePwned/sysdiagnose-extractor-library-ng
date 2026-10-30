// SPDX-License-Identifier: GPL-3.0-only

//! Parser implementations. Each parser returns `Ok` when its inputs are missing.

mod parser_events;
mod ps;
mod timeutil;

pub mod apollo;
pub mod crash;
pub mod ioreg;
pub mod misc;
mod structured_text;

pub mod parser_helpers {
    pub use super::misc::{plists_recursive_with_caps, PlistsCaps};
}

pub mod security_sysdiagnose {
    pub use super::misc::{
        meta_get_mut_map, parse_security_sysdiagnose, process_buffer_client,
        process_buffer_keychain_state, process_buffer_keys_and_values, JsonResult,
        SECURITY_MODULE as MODULE,
    };
}

pub mod spindump_nosymbols {
    pub use super::misc::{parse_spindump_nosymbols_text, MODULE};
}

pub mod swcutil {
    pub use super::misc::parse_swcutil_show;
}

pub mod brctl {
    pub use super::misc::{parse_boot_history, parse_list_file};
}

use std::io::Cursor;

use base64::Engine;
use chrono::{DateTime, Utc};
use serde_json::{json, Map, Value};

use crate::archive::SysdiagnoseArchive;
use crate::engine::ParseOptions;
use crate::error::BoxErr;
use crate::glob_match::any_glob;
use crate::parser_type::ParserType;

pub use parser_events::MAX_UTF8_FILE;
pub use ps::{PsParser, PsThreadParser, PS_THREAD, PS_TXT};

pub trait SysdiagnoseParser: Send + Sync {
    fn parse(&self, archive: &SysdiagnoseArchive) -> Result<Value, BoxErr>;
    fn parse_with_options(
        &self,
        archive: &SysdiagnoseArchive,
        opts: &ParseOptions,
    ) -> Result<Value, BoxErr> {
        let _ = opts;
        self.parse(archive)
    }
}

pub fn clamp_logarchive_decode_max_lines(max_lines: usize) -> usize {
    if max_lines == 0 || max_lines > crate::engine::LOGARCHIVE_FORENSIC_MAX_LINES {
        crate::engine::LOGARCHIVE_FORENSIC_MAX_LINES
    } else {
        max_lines
    }
}

pub fn default_logarchive_max_lines() -> usize {
    let raw = std::env::var("SYSDIAGNOSE_LOGARCHIVE_DECODE_MAX_LINES").unwrap_or_default();
    let n: usize = raw.parse().unwrap_or(2500);
    clamp_logarchive_decode_max_lines(n)
}

pub fn parser_inputs(parser: ParserType) -> &'static [&'static str] {
    match parser {
        ParserType::accessibility_tcc => &["logs/Accessibility/TCC.db"],
        ParserType::apollo_all => &["**/*"],
        ParserType::appinstallation => &[
            "logs/appinstallation/AppUpdates.sqlitedb",
            "logs/appinstallation/appstored.sqlitedb",
        ],
        ParserType::avconference_callsettings => &["logs/AVConference/*-CallSettings.calldump.gz", "logs/AVConference/*calldump.gz"],
        ParserType::awd_baseband => &["logs/AWD/**", "logs/Baseband/**", "**/*.metriclog", "**/*.istp"],
        ParserType::battery_bdc => &["logs/BatteryBDC/*.csv"],
        ParserType::bluetooth => &[
            "WiFi/bluetooth_status.txt",
            "WiFi/awdl_status.txt",
            "logs/Bluetooth/**",
            "logs/NetworkRelay/companion_link_status*.txt",
        ],
        ParserType::brctl => &["brctl/brctl-container-list.txt", "brctl/brctl-dump.txt"],
        ParserType::ckks_pcs => &["ckksctl_status.txt", "pcsstatus.txt", "**/ckksctl_status.txt", "**/pcsstatus.txt"],
        ParserType::collection_meta => &["taskSummary.csv", "errors/*.txt", "summaries/*.log", "sysdiagnose.log"],
        ParserType::containermanager => &["logs/MobileContainerManager/containermanagerd.log*"],
        ParserType::crashlogs => &[
            "**/crashes_and_spins/**/*.ips",
            "**/summaries/crashes_and_spins.log",
            "**/CrashReporter/**/*.ips",
        ],
        ParserType::disks => &["disks.txt"],
        ParserType::ioacpiplane => &["ioreg/IOACPIPlane.txt"],
        ParserType::iodevicetree => &["ioreg/IODeviceTree.txt"],
        ParserType::iofirewire => &["ioreg/IOFireWire.txt"],
        ParserType::iopower => &["ioreg/IOPower.txt"],
        ParserType::ioservice => &["ioreg/IOService.txt"],
        ParserType::iousb => &["ioreg/IOUSB.txt"],
        ParserType::interactionc => &["**/interactionC.db"],
        ParserType::ioport => &["ioreg/IOPort.txt"],
        ParserType::itunesstore => &["logs/itunesstored/downloads.*.sqlitedb"],
        ParserType::kbdebug => &["kbdebug.txt"],
        ParserType::knowledgec => &["**/Knowledge/knowledgeC.db", "**/CoreDuet/Knowledge/knowledgeC.db"],
        ParserType::lockdownd => &["logs/MobileLockdown/lockdownd.log*"],
        ParserType::logarchive => &["system_logs.logarchive/**"],
        ParserType::logdata_statistics => &["system_logs.logarchive/Extra/logdata.statistics.*.jsonl"],
        ParserType::logdata_statistics_txt => &["system_logs.logarchive/Extra/logdata.statistics.*.txt"],
        ParserType::lsaw => &["**/lsaw.csstoredump"],
        ParserType::mcsettingsevents => &["logs/MCState/Shared/MCSettingsEvents.plist"],
        ParserType::mcstate_shared_profile => &["logs/MCState/Shared/profile-*.stub"],
        ParserType::microstackshots => &["**/microstackshots"],
        ParserType::mobileactivation => &["logs/MobileActivation/mobileactivationd.log*"],
        ParserType::mobilebackup => &["logs/MobileBackup/com.apple.MobileBackup.plist"],
        ParserType::mobileinstallation => &["logs/MobileInstallation/mobile_installation*.log*"],
        ParserType::mount => &["mount.txt"],
        ParserType::networkextension => &["logs/Networking/com.apple.networkextension.plist"],
        ParserType::networkextensioncache => &["logs/Networking/com.apple.networkextension.cache.plist"],
        ParserType::netusage => &["logs/Networking/netusage.sqlite", "**/netusage.sqlite"],
        ParserType::olddsc => &["logs/olddsc/**"],
        ParserType::ota_update => &["logs/OTAUpdateLogs/**", "restore_perform.txt"],
        ParserType::plists => &["**/*.plist"],
        ParserType::powerlogs => &["logs/powerlogs/powerlog_*", "logs/powerlogs/log_*", "**/CurrentPowerlog.PLSQL"],
        ParserType::preferences => &["Preferences/*.txt", "**/Preferences/*.txt"],
        ParserType::ps => &["ps.txt"],
        ParserType::psthread => &["ps_thread.txt"],
        ParserType::quarantine_events => &["**/com.apple.LaunchServices.QuarantineEventsV2"],
        ParserType::remotectl_dumpstate => &["remotectl_dumpstate.txt"],
        ParserType::runningboard => &["RunningBoard/RunningBoard_state.log"],
        ParserType::safari_history => &["**/Safari/History.db", "**/History.db"],
        ParserType::security_sysdiagnose => &["security-sysdiagnose.txt"],
        ParserType::screentime => &["**/RMAdminStore-Local.sqlite", "**/RMAdminStore-Cloud.sqlite"],
        ParserType::shutdownlogs => &[
            "system_logs.logarchive/Extra/shutdown.log",
            "system_logs.logarchive/Extra/shutdown.*.log",
            "private/var/db/diagnostics/shutdown.log",
            "private/var/db/diagnostics/shutdown.*.log",
        ],
        ParserType::spindumpnosymbols => &["**/spindump-nosymbols.txt"],
        ParserType::swcutil => &["**/swcutil_show.txt"],
        ParserType::sys => &[
            "logs/SystemVersion/SystemVersion.plist",
            "SystemVersion.plist",
            "**/SystemVersion.plist",
        ],
        ParserType::system_stats => &[
            "apfs_stats.txt",
            "vm_stat.txt",
            "zprint.txt",
            "smcDiagnose.txt",
            "codecctl.txt",
            "night-shift.log",
            "ASPSnapshots/**",
            "TimezoneDB/**",
            "logs/Trial/trial.log",
            "logs/suggest_tool/**",
        ],
        ParserType::taskinfo => &["taskinfo.txt"],
        ParserType::transparency | ParserType::transparency_json => &["transparency.log"],
        ParserType::usermanagement => &[
            "logs/UserManagement/umtool.txt",
            "logs/UserManagement/usermanagerd.log*",
            "logs/umtool/**",
            "**/usermanagerd.log*",
        ],
        ParserType::uuid2path => &["logs/tailspindb/UUIDToBinaryLocations*"],
        ParserType::wifi_diagnostics => &[
            "WiFi/ifconfig.txt",
            "WiFi/arp.txt",
            "WiFi/netstat-PRE.txt",
            "WiFi/netstat-POST.txt",
            "WiFi/network_status.txt",
            "WiFi/wifi_status.txt",
            "WiFi/leaky_ap_stats.txt",
            "WiFi/diagnostics-*.txt",
        ],
        ParserType::wifi_known_networks => &[
            "WiFi/com.apple.wifi.known-networks.plist",
            "**/WiFi/com.apple.wifi.known-networks.plist",
        ],
        ParserType::wifinetworks => &["WiFi/*.plist", "WiFi/com.apple.wifi.recent-networks.json"],
        ParserType::wifiscan => &["WiFi/wifi_scan*.txt"],
        ParserType::wifisecurity => &["WiFi/security.txt"],
    }
}

struct ConfiguredParser {
    kind: ParserType,
    opts: ParseOptions,
}

impl SysdiagnoseParser for ConfiguredParser {
    fn parse(&self, archive: &SysdiagnoseArchive) -> Result<Value, BoxErr> {
        dispatch(self.kind, archive, &self.opts)
    }
}

pub fn parser_for(t: ParserType) -> Box<dyn SysdiagnoseParser> {
    parser_for_with_options(t, ParseOptions::default())
}

pub fn parser_for_with_options(t: ParserType, opts: ParseOptions) -> Box<dyn SysdiagnoseParser> {
    Box::new(ConfiguredParser { kind: t, opts })
}

pub fn dispatch(t: ParserType, archive: &SysdiagnoseArchive, opts: &ParseOptions) -> Result<Value, BoxErr> {
    match t {
        ParserType::ps => ps::parse_ps(archive),
        ParserType::psthread => ps::parse_psthread(archive),
        ParserType::kbdebug => text_one(archive, &["kbdebug.txt"], "kbdebug", |t, _| {
            parser_events::parse_kbdebug_log(t, "kbdebug")
        }),
        ParserType::lockdownd => {
            let tz = archive
                .acquisition()
                .map(|d| *d.offset())
                .unwrap_or_else(|| chrono::FixedOffset::east_opt(0).unwrap());
            text_many(archive, parser_inputs(t), "lockdownd", |text| {
                parser_events::extract_lockdownd(text, "lockdownd", tz)
            })
        }
        ParserType::disks => text_one(archive, &["disks.txt"], "disks", |t, ts| parser_events::parse_disks_txt(t, "disks", ts)),
        ParserType::sys => misc::parse_sys(archive),
        ParserType::taskinfo => misc::parse_taskinfo(archive),
        ParserType::shutdownlogs => misc::parse_shutdown(archive),
        ParserType::crashlogs => crash::parse_crashlogs(archive),
        ParserType::mount => misc::parse_mount(archive),
        ParserType::brctl => misc::parse_brctl(archive),
        ParserType::remotectl_dumpstate => misc::parse_remotectl(archive),
        ParserType::transparency_json => misc::parse_transparency_json(archive),
        ParserType::transparency => misc::parse_transparency(archive),
        ParserType::plists => misc::parse_plists(archive),
        ParserType::logarchive => misc::parse_logarchive(archive, opts),
        ParserType::itunesstore => misc::parse_itunesstore(archive),
        ParserType::ioservice => ioreg::parse_ioservice(archive, opts),
        ParserType::ioacpiplane => ioreg::parse_plane(archive, "ioacpiplane", &["ioreg/IOACPIPlane.txt"]),
        ParserType::iodevicetree => ioreg::parse_plane(archive, "iodevicetree", &["ioreg/IODeviceTree.txt"]),
        ParserType::iofirewire => ioreg::parse_plane(archive, "iofirewire", &["ioreg/IOFireWire.txt"]),
        ParserType::iopower => ioreg::parse_plane(archive, "iopower", &["ioreg/IOPower.txt"]),
        ParserType::iousb => ioreg::parse_plane(archive, "iousb", &["ioreg/IOUSB.txt"]),
        ParserType::ioport => ioreg::parse_plane(archive, "ioport", &["ioreg/IOPort.txt"]),
        ParserType::spindumpnosymbols => misc::parse_spindump(archive),
        ParserType::swcutil => misc::parse_swcutil(archive),
        ParserType::security_sysdiagnose => misc::parse_security(archive),
        ParserType::wifiscan => misc::parse_wifiscan(archive),
        ParserType::wifisecurity => misc::parse_wifisecurity(archive),
        ParserType::wifi_known_networks => misc::parse_wifi_known(archive),
        ParserType::wifinetworks => misc::parse_wifinetworks(archive),
        ParserType::mobileinstallation => misc::parse_mobileinstallation(archive),
        ParserType::containermanager => multiline_logs(archive, parser_inputs(t), "containermanager"),
        ParserType::mobileactivation => multiline_logs(archive, parser_inputs(t), "mobileactivation"),
        ParserType::battery_bdc => misc::parse_battery(archive),
        ParserType::logdata_statistics => misc::parse_logdata_jsonl(archive),
        ParserType::logdata_statistics_txt => misc::parse_logdata_txt(archive),
        ParserType::mcsettingsevents => misc::parse_mc_settings(archive),
        ParserType::mcstate_shared_profile => misc::parse_mcstate(archive),
        ParserType::mobilebackup => misc::parse_mobilebackup(archive),
        ParserType::olddsc => misc::parse_olddsc(archive),
        ParserType::appinstallation => misc::parse_appinstallation(archive),
        ParserType::avconference_callsettings => misc::parse_avconference(archive),
        ParserType::accessibility_tcc => apollo::parse_db(archive, "accessibility_tcc", &["TCC.db"], parser_inputs(t)),
        ParserType::powerlogs => apollo::parse_db(archive, "powerlogs", &["CurrentPowerlog.PLSQL"], parser_inputs(t)),
        ParserType::safari_history => apollo::parse_db(archive, "safari_history", &["History.db"], parser_inputs(t)),
        ParserType::knowledgec => apollo::parse_db(archive, "knowledgec", &["knowledgeC.db"], parser_inputs(t)),
        ParserType::netusage => apollo::parse_db(archive, "netusage", &["netusage.sqlite"], parser_inputs(t)),
        ParserType::interactionc => apollo::parse_db(archive, "interactionc", &["interactionC.db"], parser_inputs(t)),
        ParserType::quarantine_events => apollo::parse_db(
            archive,
            "quarantine_events",
            &["com.apple.LaunchServices.QuarantineEventsV2"],
            parser_inputs(t),
        ),
        ParserType::screentime => apollo::parse_db(
            archive,
            "screentime",
            &["RMAdminStore-Local.sqlite", "RMAdminStore-Cloud.sqlite"],
            parser_inputs(t),
        ),
        ParserType::apollo_all => apollo::parse_all(archive),
        ParserType::networkextension => plist_map(archive, parser_inputs(t)),
        ParserType::networkextensioncache => plist_map(archive, parser_inputs(t)),
        ParserType::uuid2path => plist_map(archive, parser_inputs(t)),
        ParserType::awd_baseband => binary_inventory(archive, "awd_baseband", parser_inputs(t), 200),
        ParserType::microstackshots => binary_inventory(archive, "microstackshots", parser_inputs(t), 200),
        ParserType::bluetooth => structured_text::parse_bluetooth(archive),
        ParserType::ota_update => structured_text::parse_ota_update(archive),
        ParserType::system_stats => files_bundle(archive, "system_stats", parser_inputs(t), 128),
        ParserType::usermanagement => files_bundle(archive, "usermanagement", parser_inputs(t), 32),
        ParserType::wifi_diagnostics => files_bundle(archive, "wifi_diagnostics", parser_inputs(t), 64),
        ParserType::preferences => files_bundle(archive, "preferences", parser_inputs(t), 200),
        ParserType::runningboard => structured_text::parse_runningboard(archive),
        ParserType::ckks_pcs => files_bundle(archive, "ckks_pcs", parser_inputs(t), 32),
        ParserType::collection_meta => misc::parse_collection_meta(archive),
        ParserType::lsaw => misc::parse_lsaw(archive),
    }
}

fn text_one(
    archive: &SysdiagnoseArchive,
    globs: &[&str],
    id: &str,
    f: impl Fn(&str, DateTime<chrono::FixedOffset>) -> Vec<Value>,
) -> Result<Value, BoxErr> {
    let ts = crate::archive::sysdiagnose_creation(archive);
    let mut events = Vec::new();
    for (path, text) in parser_events::matching_utf8_files(archive, globs)? {
        let _ = path;
        events.extend(f(&text, ts));
    }
    let _ = id;
    Ok(parser_events::wrap_jsonl(id, events))
}

fn text_many(
    archive: &SysdiagnoseArchive,
    globs: &[&str],
    id: &str,
    f: impl Fn(&str) -> Vec<Value>,
) -> Result<Value, BoxErr> {
    let mut events = Vec::new();
    for (_path, text) in parser_events::matching_utf8_files(archive, globs)? {
        events.extend(f(&text));
    }
    Ok(parser_events::wrap_jsonl(id, events))
}

fn multiline_logs(archive: &SysdiagnoseArchive, globs: &[&str], id: &str) -> Result<Value, BoxErr> {
    let tz = archive
        .acquisition()
        .map(|d| *d.offset())
        .unwrap_or_else(|| chrono::FixedOffset::east_opt(0).unwrap());
    let mut doc = text_many(archive, globs, id, |t| parser_events::extract_multiline_log(t, id, tz))?;
    if id == "mobileactivation" {
        if let Some(events) = doc.get_mut("events").and_then(|v| v.as_array_mut()) {
            *events = fold_mobileactivation_events(std::mem::take(events));
        }
    }
    Ok(doc)
}

fn fold_mobileactivation_events(events: Vec<Value>) -> Vec<Value> {
    let kv = regex::Regex::new(r"^[A-Za-z]+: [A-Za-z_]+: ([a-z0-9_]+): (.*)$").unwrap();
    let mut kept: Vec<Value> = Vec::new();
    for mut ev in events {
        let Some(obj) = ev.as_object_mut() else {
            continue;
        };
        obj.insert("timestamp_desc".into(), json!("mobileactivation event"));
        let msg = obj.get("message").and_then(|m| m.as_str()).unwrap_or("").to_string();
        if let Some(caps) = kv.captures(&msg) {
            if let Some(prev) = kept.last_mut().and_then(|v| v.get_mut("data")).and_then(|d| d.as_object_mut()) {
                let key = caps.get(1).unwrap().as_str().to_string();
                let val = caps.get(2).unwrap().as_str().trim().to_string();
                prev.insert(key, json!(val));
            }
            continue;
        }
        let body = msg
            .trim()
            .trim_start_matches("MA:")
            .trim()
            .trim_start_matches("main:")
            .trim();
        if !body.chars().any(|c| c.is_ascii_alphabetic()) {
            continue;
        }
        kept.push(ev);
    }
    kept
}

pub fn plist_bytes_to_json(bytes: &[u8]) -> Result<Value, String> {
    let value = plist::Value::from_reader(Cursor::new(bytes)).map_err(|e| e.to_string())?;
    Ok(plist_value_to_json(&value))
}

fn plist_value_to_json(v: &plist::Value) -> Value {
    use plist::Value as P;
    match v {
        P::Array(a) => Value::Array(a.iter().map(plist_value_to_json).collect()),
        P::Dictionary(d) => {
            let mut m = Map::new();
            for (k, v) in d {
                m.insert(k.clone(), plist_value_to_json(v));
            }
            Value::Object(m)
        }
        P::Boolean(b) => json!(*b),
        P::Data(d) => Value::String(base64::engine::general_purpose::STANDARD.encode(d)),
        P::Date(date) => {
            let st: std::time::SystemTime = (*date).into();
            let dt: chrono::DateTime<Utc> = st.into();
            Value::String(dt.to_rfc3339_opts(chrono::SecondsFormat::Micros, true))
        }
        P::Real(f) => json!(*f),
        P::Integer(i) => {
            if let Some(s) = i.as_signed() {
                json!(s)
            } else if let Some(u) = i.as_unsigned() {
                json!(u)
            } else {
                Value::String(i.to_string())
            }
        }
        P::String(s) => Value::String(s.clone()),
        P::Uid(u) => json!(u.get()),
        _ => Value::Null,
    }
}

pub fn matched_paths(archive: &SysdiagnoseArchive, globs: &[&str]) -> Vec<String> {
    let mut v: Vec<String> = archive
        .all_paths()
        .into_iter()
        .filter(|p| any_glob(globs, p))
        .collect();
    v.sort();
    v
}

fn plist_map(archive: &SysdiagnoseArchive, globs: &[&str]) -> Result<Value, BoxErr> {
    let mut files = Map::new();
    for path in matched_paths(archive, globs) {
        let Some(bytes) = archive.get(&path) else {
            continue;
        };
        match plist_bytes_to_json(bytes) {
            Ok(v) => {
                files.insert(path, v);
            }
            Err(_) => {
                files.insert(path, json!({}));
            }
        }
    }
    Ok(Value::Object(files))
}

fn files_bundle(archive: &SysdiagnoseArchive, id: &str, globs: &[&str], cap: usize) -> Result<Value, BoxErr> {
    let paths = matched_paths(archive, globs);
    let total = paths.len();
    let mut files = Map::new();
    let mut skipped = Vec::new();
    let mut returned = 0usize;
    for path in paths {
        if returned >= cap {
            break;
        }
        let Some(bytes) = archive.get(&path) else {
            continue;
        };
        if bytes.len() > MAX_UTF8_FILE {
            skipped.push(Value::String(path));
            continue;
        }
        files.insert(path, Value::String(String::from_utf8_lossy(bytes).into_owned()));
        returned += 1;
    }
    let truncated = total.saturating_sub(returned + skipped.len());
    Ok(json!({
        "parser": id,
        "format": "files",
        "files": files,
        "meta": {
            "total_matched": total,
            "returned": returned,
            "truncated_file_count": truncated,
            "skipped_oversized": skipped,
        }
    }))
}

fn binary_inventory(archive: &SysdiagnoseArchive, id: &str, globs: &[&str], cap: usize) -> Result<Value, BoxErr> {
    let paths = matched_paths(archive, globs);
    let total = paths.len();
    let mut files = Vec::new();
    let mut total_bytes = 0u64;
    for path in paths.iter().take(cap) {
        let size = archive.entry_size(path).unwrap_or(0);
        total_bytes += size;
        let magic = archive
            .get(path)
            .map(magic_of)
            .unwrap_or("binary");
        files.push(json!({"path": path, "size": size, "magic": magic}));
    }
    Ok(json!({
        "parser": id,
        "format": "inventory",
        "file_count": total,
        "returned": files.len(),
        "total_bytes": total_bytes,
        "files": files,
        "note": "Proprietary / undecoded binary; inventory only",
    }))
}

fn magic_of(bytes: &[u8]) -> &'static str {
    if bytes.len() >= 2 && bytes[0] == 0x1f && bytes[1] == 0x8b {
        "gzip"
    } else if bytes.len() >= 6 && &bytes[..6] == b"bplist" {
        "bplist"
    } else {
        "binary"
    }
}

// DateTime timezone helper used above — keep a type path stable.
trait _Off {
    fn timezone(self) -> Self;
}
impl _Off for chrono::FixedOffset {
    fn timezone(self) -> Self {
        self
    }
}
