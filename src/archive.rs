// SPDX-License-Identifier: GPL-3.0-only

use std::collections::BTreeMap;
use std::io::{self, Cursor, Read};
use std::path::{Path, PathBuf};
use std::sync::Arc;

use chrono::{DateTime, FixedOffset, NaiveDateTime};
use flate2::read::GzDecoder;
use regex::Regex;
use std::sync::OnceLock;

use crate::error::ArchiveError;

const DEFAULT_MAX_ENTRY: u64 = 64 * 1024 * 1024;
const DEFAULT_MAX_NESTED: u64 = 512 * 1024 * 1024;
const DEFAULT_INLINE: u64 = 256 * 1024;
const DEFAULT_MEM_BUDGET: u64 = 256 * 1024 * 1024;

/// Options for opening a sysdiagnose archive.
#[derive(Debug, Clone)]
pub struct ArchiveOptions {
    pub max_entry_bytes: u64,
    pub max_nested_sysdiagnose_bytes: u64,
    pub expand_nested_sysdiagnose: bool,
    pub spill_logarchive_heavy: bool,
    pub inline_threshold: u64,
    pub mem_budget: u64,
    pub spill_dir: Option<PathBuf>,
}

impl Default for ArchiveOptions {
    fn default() -> Self {
        Self {
            max_entry_bytes: DEFAULT_MAX_ENTRY,
            max_nested_sysdiagnose_bytes: DEFAULT_MAX_NESTED,
            expand_nested_sysdiagnose: true,
            spill_logarchive_heavy: cfg!(not(target_arch = "wasm32")),
            inline_threshold: DEFAULT_INLINE,
            mem_budget: DEFAULT_MEM_BUDGET,
            spill_dir: None,
        }
    }
}

/// Globs / fixed paths the reader should retain. Empty plan retains every eligible member.
#[derive(Debug, Clone, Default)]
pub struct RetentionPlan {
    pub globs: Vec<String>,
    /// When true, every regular file is retained (plists, apollo_all, file_stats paths).
    pub everything: bool,
    /// When true and `everything` is set, record paths and sizes only (no payloads).
    pub paths_only: bool,
}

impl RetentionPlan {
    fn wants(&self, rel: &str) -> bool {
        if self.globs.is_empty() && !self.everything {
            return true;
        }
        if self.everything {
            return true;
        }
        if rel == "sysdiagnose.log" || rel.ends_with("/sysdiagnose.log") {
            return true;
        }
        self.globs
            .iter()
            .any(|g| crate::glob_match::glob_match(g, rel))
    }
}

#[derive(Debug, Clone, Default)]
pub struct ArchiveStats {
    pub bytes_read: u64,
    pub bytes_decompressed: u64,
    pub bytes_retained: u64,
    pub bytes_spilled: u64,
    pub bytes_skipped: u64,
    pub members_seen: u64,
}

enum Blob {
    Owned(Arc<[u8]>),
    #[cfg(not(target_arch = "wasm32"))]
    Mapped {
        mmap: Arc<memmap2::Mmap>,
        range: std::ops::Range<usize>,
    },
    #[cfg(not(target_arch = "wasm32"))]
    Spilled {
        mmap: Arc<memmap2::Mmap>,
        len: usize,
    },
}

impl Blob {
    fn bytes(&self) -> &[u8] {
        match self {
            Blob::Owned(b) => b,
            #[cfg(not(target_arch = "wasm32"))]
            Blob::Mapped { mmap, range } => &mmap[range.clone()],
            #[cfg(not(target_arch = "wasm32"))]
            Blob::Spilled { mmap, len } => &mmap[..*len],
        }
    }
}

struct Member {
    size: u64,
    blob: Option<Blob>,
    spill_path: Option<PathBuf>,
}

/// In-memory view of a sysdiagnose bundle.
///
/// Retained payloads are reference-counted blobs (mmap slices for plain tar input,
/// owned bytes or spilled mmaps for compressed input). Heavy logarchive members are
/// spilled and omitted from [`Self::get`].
pub struct SysdiagnoseArchive {
    files: BTreeMap<String, Member>,
    spilled: Vec<(String, u64, PathBuf)>,
    bundle_dir_name: Option<String>,
    stats: ArchiveStats,
    #[cfg(not(target_arch = "wasm32"))]
    _spill_temp: Option<tempfile::TempDir>,
    #[cfg(not(target_arch = "wasm32"))]
    spill_root: Option<PathBuf>,
}

impl SysdiagnoseArchive {
    pub fn open_path(path: impl AsRef<Path>) -> Result<Self, ArchiveError> {
        Self::open_path_with_options(path, ArchiveOptions::default())
    }

    pub fn open_path_with_options(
        path: impl AsRef<Path>,
        opts: ArchiveOptions,
    ) -> Result<Self, ArchiveError> {
        Self::open_path_with_plan(path, opts, &RetentionPlan::default())
    }

    pub fn open_path_with_plan(
        path: impl AsRef<Path>,
        opts: ArchiveOptions,
        plan: &RetentionPlan,
    ) -> Result<Self, ArchiveError> {
        let path = path.as_ref();
        if !path.is_file() {
            return Err(ArchiveError::NotAFile(path.display().to_string()));
        }
        let mut magic = [0u8; 6];
        let n = {
            let mut f = std::fs::File::open(path)?;
            f.read(&mut magic)?
        };
        if n >= 2 && magic[0] == 0x1f && magic[1] == 0x8b {
            let f = std::fs::File::open(path)?;
            let dec = GzDecoder::new(f);
            return load_from_reader(dec, opts, plan, false, None);
        }
        #[cfg(not(target_arch = "wasm32"))]
        if is_xz_prefix(&magic[..n]) {
            let f = std::fs::File::open(path)?;
            let dec = xz2::read::XzDecoder::new(f);
            return load_from_reader(dec, opts, plan, false, None);
        }
        #[cfg(not(target_arch = "wasm32"))]
        {
            let file = std::fs::File::open(path)?;
            let mmap = unsafe { memmap2::Mmap::map(&file) }.map_err(ArchiveError::Io)?;
            let mapped = Arc::new(mmap);
            let cursor_src = Arc::clone(&mapped);
            load_from_reader(Cursor::new(&cursor_src[..]), opts, plan, true, Some(mapped))
        }
        #[cfg(target_arch = "wasm32")]
        {
            let bytes = std::fs::read(path)?;
            Self::from_bytes_with_options(&bytes, opts)
        }
    }

    pub fn from_bytes(bytes: &[u8]) -> Result<Self, ArchiveError> {
        Self::from_bytes_with_options(bytes, ArchiveOptions::default())
    }

    pub fn from_bytes_with_options(bytes: &[u8], opts: ArchiveOptions) -> Result<Self, ArchiveError> {
        Self::from_bytes_with_plan(bytes, opts, &RetentionPlan::default())
    }

    pub fn from_bytes_with_plan(
        bytes: &[u8],
        opts: ArchiveOptions,
        plan: &RetentionPlan,
    ) -> Result<Self, ArchiveError> {
        if bytes.len() >= 2 && bytes[0] == 0x1f && bytes[1] == 0x8b {
            let dec = GzDecoder::new(Cursor::new(bytes));
            return load_from_reader(dec, opts, plan, false, None);
        }
        #[cfg(not(target_arch = "wasm32"))]
        if is_xz_prefix(bytes) {
            let dec = xz2::read::XzDecoder::new(Cursor::new(bytes));
            return load_from_reader(dec, opts, plan, false, None);
        }
        load_from_reader(Cursor::new(bytes), opts, plan, false, None)
    }

    pub fn from_reader(reader: impl Read) -> Result<Self, ArchiveError> {
        load_from_reader(
            reader,
            ArchiveOptions::default(),
            &RetentionPlan::default(),
            false,
            None,
        )
    }

    pub fn from_files_for_test(files: std::collections::HashMap<String, Arc<[u8]>>) -> Self {
        Self::from_files_for_test_with_bundle(files, None)
    }

    pub fn from_files_for_test_with_bundle(
        files: std::collections::HashMap<String, Arc<[u8]>>,
        bundle: Option<String>,
    ) -> Self {
        let mut map = BTreeMap::new();
        for (path, bytes) in files {
            let size = bytes.len() as u64;
            map.insert(
                path,
                Member {
                    size,
                    blob: Some(Blob::Owned(bytes)),
                    spill_path: None,
                },
            );
        }
        Self {
            files: map,
            spilled: Vec::new(),
            bundle_dir_name: bundle,
            stats: ArchiveStats::default(),
            #[cfg(not(target_arch = "wasm32"))]
            _spill_temp: None,
            #[cfg(not(target_arch = "wasm32"))]
            spill_root: None,
        }
    }

    pub fn get(&self, path: &str) -> Option<&[u8]> {
        self.files.get(path).and_then(|m| m.blob.as_ref().map(Blob::bytes))
    }

    pub fn find_suffix<'a>(&'a self, suffix: &str) -> Option<&'a str> {
        self.files
            .keys()
            .map(String::as_str)
            .find(|p| p.ends_with(suffix))
    }

    pub fn paths(&self) -> impl Iterator<Item = &str> {
        self.files.keys().map(String::as_str)
    }

    pub fn iter_files(&self) -> Vec<(&str, &[u8])> {
        self.files
            .iter()
            .filter_map(|(p, m)| m.blob.as_ref().map(|b| (p.as_str(), b.bytes())))
            .collect()
    }

    pub fn len(&self) -> usize {
        self.files.len() + self.spilled.len()
    }

    pub fn is_empty(&self) -> bool {
        self.len() == 0
    }

    pub fn bundle_dir_name(&self) -> Option<&str> {
        self.bundle_dir_name.as_deref()
    }

    pub fn acquisition(&self) -> Option<DateTime<FixedOffset>> {
        self.bundle_dir_name
            .as_deref()
            .and_then(parse_bundle_acquisition)
    }

    pub fn logarchive_spilled_entries(&self) -> Vec<(String, u64)> {
        self.spilled
            .iter()
            .map(|(p, n, _)| (p.clone(), *n))
            .collect()
    }

    pub fn spilled_logarchive_abs(&self, rel: &str) -> Option<PathBuf> {
        self.spilled
            .iter()
            .find(|(p, _, _)| p == rel)
            .map(|(_, _, path)| path.clone())
    }

    pub fn spill_path(&self, rel: &str) -> Option<&Path> {
        self.files
            .get(rel)
            .and_then(|m| m.spill_path.as_deref())
            .or_else(|| {
                self.spilled
                    .iter()
                    .find(|(p, _, _)| p == rel)
                    .map(|(_, _, path)| path.as_path())
            })
    }

    pub fn entry_size(&self, rel: &str) -> Option<u64> {
        self.files
            .get(rel)
            .map(|m| m.size)
            .or_else(|| self.spilled.iter().find(|(p, _, _)| p == rel).map(|(_, n, _)| *n))
    }

    /// Every relative path, including spilled logarchive members. Sorted.
    pub fn all_paths(&self) -> Vec<String> {
        let mut v: Vec<String> = self.files.keys().cloned().collect();
        for (p, _, _) in &self.spilled {
            if !self.files.contains_key(p) {
                v.push(p.clone());
            }
        }
        v.sort();
        v
    }

    pub fn stats(&self) -> &ArchiveStats {
        &self.stats
    }

    #[cfg(not(target_arch = "wasm32"))]
    pub fn logarchive_dir(&self) -> Option<PathBuf> {
        self.spill_root
            .as_ref()
            .map(|r| r.join("system_logs.logarchive"))
            .filter(|p| p.is_dir())
    }
}

pub fn is_xz_prefix(bytes: &[u8]) -> bool {
    bytes.len() >= 6 && bytes[..6] == [0xfd, 0x37, 0x7a, 0x58, 0x5a, 0x00]
}

pub fn parse_bundle_acquisition(name: &str) -> Option<DateTime<FixedOffset>> {
    static RE: OnceLock<Regex> = OnceLock::new();
    let re = RE.get_or_init(|| {
        Regex::new(r"^sysdiagnose_(\d{4}\.\d{2}\.\d{2}_\d{2}-\d{2}-\d{2})([+-]\d{4})").unwrap()
    });
    let caps = re.captures(name)?;
    let stamp = format!("{}{}", &caps[1], &caps[2]);
    let naive_fmt = "%Y.%m.%d_%H-%M-%S%z";
    DateTime::parse_from_str(&stamp, naive_fmt).ok()
}

fn acquisition_re_stamp(text: &str) -> Option<DateTime<FixedOffset>> {
    static RE: OnceLock<Regex> = OnceLock::new();
    let re = RE.get_or_init(|| {
        Regex::new(
            r"(?:IN_PROGRESS_sysdiagnose_|spindump_sysdiagnose_)(\d{4}\.\d{2}\.\d{2}_\d{2}-\d{2}-\d{2}[+-]\d{4})",
        )
        .unwrap()
    });
    let caps = re.captures(text)?;
    DateTime::parse_from_str(&caps[1], "%Y.%m.%d_%H-%M-%S%z").ok()
}

pub fn sysdiagnose_creation(archive: &SysdiagnoseArchive) -> DateTime<FixedOffset> {
    if let Some(path) = archive.find_suffix("sysdiagnose.log") {
        if let Some(bytes) = archive.get(path) {
            let text = String::from_utf8_lossy(bytes);
            if let Some(dt) = acquisition_re_stamp(&text) {
                return dt;
            }
        }
    }
    if let Some(dt) = archive.acquisition() {
        return dt;
    }
    chrono::Utc::now().fixed_offset()
}

fn normalize_tar_path(raw: &str) -> Option<(String, String)> {
    let raw = raw.replace('\\', "/");
    let parts: Vec<&str> = raw
        .split('/')
        .filter(|p| !p.is_empty() && *p != "." && *p != "..")
        .collect();
    if parts.len() < 2 {
        return None;
    }
    if parts.iter().any(|p| p.starts_with("._")) {
        return None;
    }
    let bundle = parts[0].to_string();
    let rel = parts[1..].join("/");
    if rel.is_empty() {
        return None;
    }
    Some((bundle, rel))
}

fn is_nested_sysdiagnose(rel: &str) -> bool {
    let base = rel.rsplit('/').next().unwrap_or(rel).to_ascii_lowercase();
    base.starts_with("sysdiagnose_")
        && (base.ends_with(".tar.gz") || base.ends_with(".tgz") || base.ends_with(".tar.xz"))
}

fn is_heavy_logarchive(rel: &str, size: u64) -> bool {
    let in_la = rel.starts_with("system_logs.logarchive/")
        || rel.contains("/system_logs.logarchive/");
    if !in_la {
        return false;
    }
    rel.ends_with(".tracev3") || size >= 1024 * 1024
}

fn looks_like_sqlite(rel: &str) -> bool {
    let base = rel.rsplit('/').next().unwrap_or(rel).to_ascii_lowercase();
    base.ends_with(".sqlite")
        || base.ends_with(".sqlitedb")
        || base.ends_with(".db")
        || base.ends_with(".plsql")
        || base.ends_with(".sqlite-wal")
        || base.ends_with(".sqlite-shm")
}

struct Loader {
    opts: ArchiveOptions,
    plan: RetentionPlan,
    files: BTreeMap<String, Member>,
    spilled: Vec<(String, u64, PathBuf)>,
    bundle: Option<String>,
    stats: ArchiveStats,
    owned_bytes: u64,
    #[cfg(not(target_arch = "wasm32"))]
    spill_temp: Option<tempfile::TempDir>,
    #[cfg(not(target_arch = "wasm32"))]
    spill_root: Option<PathBuf>,
    #[cfg(not(target_arch = "wasm32"))]
    mmap: Option<Arc<memmap2::Mmap>>,
    nested: Vec<(String, Vec<u8>)>,
}

impl Loader {
    fn new(opts: ArchiveOptions, plan: &RetentionPlan) -> Self {
        Self {
            opts,
            plan: plan.clone(),
            files: BTreeMap::new(),
            spilled: Vec::new(),
            bundle: None,
            stats: ArchiveStats::default(),
            owned_bytes: 0,
            #[cfg(not(target_arch = "wasm32"))]
            spill_temp: None,
            #[cfg(not(target_arch = "wasm32"))]
            spill_root: None,
            #[cfg(not(target_arch = "wasm32"))]
            mmap: None,
            nested: Vec::new(),
        }
    }

    #[cfg(not(target_arch = "wasm32"))]
    fn spill_root_dir(&mut self) -> io::Result<PathBuf> {
        if let Some(root) = &self.spill_root {
            return Ok(root.clone());
        }
        if let Some(dir) = &self.opts.spill_dir {
            std::fs::create_dir_all(dir)?;
            self.spill_root = Some(dir.clone());
            return Ok(dir.clone());
        }
        let tmp = tempfile::TempDir::new()?;
        let path = tmp.path().to_path_buf();
        self.spill_temp = Some(tmp);
        self.spill_root = Some(path.clone());
        Ok(path)
    }

    fn consider_bundle(&mut self, bundle: &str) {
        if self.bundle.is_none() {
            self.bundle = Some(bundle.to_string());
        }
    }

    fn insert_blob(&mut self, rel: String, size: u64, blob: Blob, spill: Option<PathBuf>) {
        self.stats.bytes_retained += size;
        self.files.insert(
            rel,
            Member {
                size,
                blob: Some(blob),
                spill_path: spill,
            },
        );
    }

    fn store_payload(&mut self, rel: String, data: Vec<u8>, force_spill: bool) -> io::Result<()> {
        let size = data.len() as u64;
        let heavy = self.opts.spill_logarchive_heavy && is_heavy_logarchive(&rel, size);
        #[cfg(not(target_arch = "wasm32"))]
        {
            let should_spill = heavy
                || force_spill
                || looks_like_sqlite(&rel)
                || rel.ends_with(".tracev3")
                || size >= self.opts.inline_threshold
                || self.owned_bytes.saturating_add(size) > self.opts.mem_budget;
            if should_spill {
                let root = self.spill_root_dir()?;
                let path = root.join(&rel);
                if let Some(parent) = path.parent() {
                    std::fs::create_dir_all(parent)?;
                }
                std::fs::write(&path, &data)?;
                self.stats.bytes_spilled += size;
                if heavy || (rel.contains("system_logs.logarchive/") && rel.ends_with(".tracev3"))
                {
                    self.spilled.push((rel, size, path));
                    return Ok(());
                }
                let file = std::fs::File::open(&path)?;
                let mmap = unsafe { memmap2::Mmap::map(&file) }?;
                let len = mmap.len();
                self.insert_blob(rel, size, Blob::Spilled { mmap: Arc::new(mmap), len }, Some(path));
                return Ok(());
            }
        }
        let _ = force_spill;
        self.owned_bytes += size;
        self.insert_blob(rel, size, Blob::Owned(Arc::from(data.into_boxed_slice())), None);
        Ok(())
    }

    fn finish(mut self) -> Result<SysdiagnoseArchive, ArchiveError> {
        let nested = std::mem::take(&mut self.nested);
        for (_name, bytes) in nested {
            if let Ok(inner) = SysdiagnoseArchive::from_bytes_with_plan(
                &bytes,
                ArchiveOptions {
                    expand_nested_sysdiagnose: false,
                    ..self.opts.clone()
                },
                &self.plan,
            ) {
                if self.bundle.as_deref().and_then(parse_bundle_acquisition).is_none() {
                    if let Some(name) = inner.bundle_dir_name() {
                        if parse_bundle_acquisition(name).is_some() {
                            self.bundle = Some(name.to_string());
                        }
                    }
                }
                for (path, member) in inner.files {
                    self.files.entry(path).or_insert(member);
                }
                for spilled in inner.spilled {
                    if !self.spilled.iter().any(|(p, _, _)| p == &spilled.0)
                        && !self.files.contains_key(&spilled.0)
                    {
                        self.spilled.push(spilled);
                    }
                }
            } else {
                tracing::warn!("failed to expand nested sysdiagnose; skipping");
            }
        }
        if self.files.is_empty() && self.spilled.is_empty() {
            return Err(ArchiveError::EmptyArchive);
        }
        Ok(SysdiagnoseArchive {
            files: self.files,
            spilled: self.spilled,
            bundle_dir_name: self.bundle,
            stats: self.stats,
            #[cfg(not(target_arch = "wasm32"))]
            _spill_temp: self.spill_temp,
            #[cfg(not(target_arch = "wasm32"))]
            spill_root: self.spill_root,
        })
    }
}

#[cfg(not(target_arch = "wasm32"))]
type MaybeMmap = Option<Arc<memmap2::Mmap>>;
#[cfg(target_arch = "wasm32")]
type MaybeMmap = Option<()>;

fn load_from_reader<R: Read>(
    reader: R,
    opts: ArchiveOptions,
    plan: &RetentionPlan,
    #[allow(unused_variables)] mapped_input: bool,
    #[allow(unused_variables)] mmap: MaybeMmap,
) -> Result<SysdiagnoseArchive, ArchiveError> {
    let mut loader = Loader::new(opts, plan);
    #[cfg(not(target_arch = "wasm32"))]
    {
        loader.mmap = mmap;
    }
    let mut archive = tar::Archive::new(reader);
    let entries = archive
        .entries()
        .map_err(|e| ArchiveError::Format(e.to_string()))?;
    for entry in entries {
        let mut entry = entry.map_err(|e| ArchiveError::Format(e.to_string()))?;
        loader.stats.members_seen += 1;
        let path = entry
            .path()
            .map_err(|e| ArchiveError::Format(e.to_string()))?;
        let raw = path.to_string_lossy();
        let Some((bundle, rel)) = normalize_tar_path(&raw) else {
            io::copy(&mut entry, &mut io::sink())?;
            continue;
        };
        loader.consider_bundle(&bundle);
        let size = entry.size();
        let nested = loader.opts.expand_nested_sysdiagnose && is_nested_sysdiagnose(&rel);
        if nested {
            if size > loader.opts.max_nested_sysdiagnose_bytes {
                tracing::warn!(path = %rel, size, "nested sysdiagnose exceeds cap; skipping");
                io::copy(&mut entry, &mut io::sink())?;
                loader.stats.bytes_skipped += size;
                continue;
            }
            let mut buf = Vec::new();
            entry.read_to_end(&mut buf)?;
            loader.stats.bytes_decompressed += buf.len() as u64;
            loader.nested.push((rel, buf));
            continue;
        }
        if size > loader.opts.max_entry_bytes {
            tracing::warn!(path = %rel, size, "entry exceeds max_entry_bytes; skipping");
            io::copy(&mut entry, &mut io::sink())?;
            loader.stats.bytes_skipped += size;
            continue;
        }
        if !loader.plan.wants(&rel) || loader.plan.paths_only {
            io::copy(&mut entry, &mut io::sink())?;
            loader.stats.bytes_skipped += size;
            if loader.plan.paths_only && loader.plan.wants(&rel) {
                loader.files.insert(
                    rel,
                    Member {
                        size,
                        blob: None,
                        spill_path: None,
                    },
                );
            }
            continue;
        }
        // Plain-tar mmap: the payload sits at a known offset inside the mapping.
        #[cfg(not(target_arch = "wasm32"))]
        if mapped_input {
            if let Some(mm) = loader.mmap.clone() {
                let pos = entry.raw_file_position() as usize;
                let end = pos.saturating_add(size as usize);
                if end <= mm.len()
                    && size < loader.opts.inline_threshold
                    && !is_heavy_logarchive(&rel, size)
                    && !looks_like_sqlite(&rel)
                    && !rel.ends_with(".tracev3")
                {
                    let mut taken = io::sink();
                    io::copy(&mut entry, &mut taken)?;
                    loader.insert_blob(
                        rel,
                        size,
                        Blob::Mapped {
                            mmap: mm,
                            range: pos..end,
                        },
                        None,
                    );
                    continue;
                }
            }
        }
        let mut buf = Vec::new();
        entry.read_to_end(&mut buf)?;
        loader.stats.bytes_decompressed += buf.len() as u64;
        loader.stats.bytes_read += buf.len() as u64;
        loader
            .store_payload(rel, buf, false)
            .map_err(ArchiveError::Io)?;
    }
    loader.finish()
}

/// Silence unused import on wasm where NaiveDateTime is unused.
#[allow(dead_code)]
fn _chrono_stamp(s: &str) -> Option<NaiveDateTime> {
    NaiveDateTime::parse_from_str(s, "%Y-%m-%d %H:%M:%S").ok()
}

#[cfg(test)]
mod tests {
    use super::*;
    use flate2::write::GzEncoder;
    use flate2::Compression;
    use std::io::Write;
    use tar::Builder;

    fn make_sample_tar_gz() -> Vec<u8> {
        let mut tar_buf = Vec::new();
        {
            let mut tar = Builder::new(&mut tar_buf);
            let root = "sysdiagnose_test_iPhone/";
            let mut header = tar::Header::new_gnu();
            let data = b"hello";
            header.set_path(format!("{root}ps.txt")).unwrap();
            header.set_size(data.len() as u64);
            header.set_cksum();
            tar.append(&header, &data[..]).unwrap();
            tar.finish().unwrap();
        }
        let mut gz = GzEncoder::new(Vec::new(), Compression::default());
        gz.write_all(&tar_buf).unwrap();
        gz.finish().unwrap()
    }

    #[test]
    fn loads_gzipped_tar() {
        let gz = make_sample_tar_gz();
        let arch = SysdiagnoseArchive::from_bytes(&gz).unwrap();
        assert_eq!(arch.get("ps.txt").unwrap(), b"hello");
    }

    #[cfg(not(target_arch = "wasm32"))]
    fn make_sample_tar_xz() -> Vec<u8> {
        use xz2::write::XzEncoder;
        let mut tar_buf = Vec::new();
        {
            let mut tar = Builder::new(&mut tar_buf);
            let root = "private/";
            let mut header = tar::Header::new_gnu();
            let data = b"{\"app_name\":\"Test\"}\n{}";
            header
                .set_path(format!(
                    "{root}var/mobile/Library/Logs/CrashReporter/TestApp-2025-04-07-080618.ips"
                ))
                .unwrap();
            header.set_size(data.len() as u64);
            header.set_cksum();
            tar.append(&header, &data[..]).unwrap();
            tar.finish().unwrap();
        }
        let mut xz = XzEncoder::new(Vec::new(), 1);
        xz.write_all(&tar_buf).unwrap();
        xz.finish().unwrap()
    }

    #[cfg(not(target_arch = "wasm32"))]
    #[test]
    fn loads_xz_tar_with_crashreporter_layout() {
        let xz = make_sample_tar_xz();
        assert!(is_xz_prefix(&xz));
        let arch = SysdiagnoseArchive::from_bytes(&xz).unwrap();
        assert!(arch
            .get("var/mobile/Library/Logs/CrashReporter/TestApp-2025-04-07-080618.ips")
            .is_some());
        assert_eq!(arch.bundle_dir_name(), Some("private"));
    }

    #[test]
    fn expands_nested_sysdiagnose_tar_gz() {
        let nested = make_sample_tar_gz();
        let mut outer_tar = Vec::new();
        {
            let mut tar = Builder::new(&mut outer_tar);
            let root = "private/";
            let ips = b"{\"app_name\":\"Outer\"}\n{}";
            let mut h1 = tar::Header::new_gnu();
            h1.set_path(format!(
                "{root}var/mobile/Library/Logs/CrashReporter/Outer-1.ips"
            ))
            .unwrap();
            h1.set_size(ips.len() as u64);
            h1.set_cksum();
            tar.append(&h1, &ips[..]).unwrap();

            let nested_name = format!("{root}DiagnosticLogs/sysdiagnose_nested.tar.gz");
            let mut h2 = tar::Header::new_gnu();
            h2.set_path(&nested_name).unwrap();
            h2.set_size(nested.len() as u64);
            h2.set_cksum();
            tar.append(&h2, &nested[..]).unwrap();
            tar.finish().unwrap();
        }

        let arch = SysdiagnoseArchive::from_bytes(&outer_tar).unwrap();
        assert!(arch
            .get("var/mobile/Library/Logs/CrashReporter/Outer-1.ips")
            .is_some());
        assert_eq!(arch.get("ps.txt").unwrap(), b"hello");
        assert!(arch.paths().all(|p| !p.ends_with(".tar.gz")));
    }

    #[test]
    fn parses_acquisition_from_bundle_name() {
        let s = "sysdiagnose_2026.04.07_15-01-20+0200_iPhone-OS_iPhone_23D127";
        let dt = parse_bundle_acquisition(s).unwrap();
        assert_eq!(dt.format("%Y-%m-%d %H:%M").to_string(), "2026-04-07 15:01");
    }

    #[cfg(not(target_arch = "wasm32"))]
    #[test]
    fn spills_heavy_tracev3_out_of_ram() {
        let mut tar_buf = Vec::new();
        {
            let mut tar = Builder::new(&mut tar_buf);
            let root = "sysdiagnose_test_iPhone/";
            let small = b"plist";
            let mut h1 = tar::Header::new_gnu();
            h1.set_path(format!("{root}system_logs.logarchive/Info.plist"))
                .unwrap();
            h1.set_size(small.len() as u64);
            h1.set_cksum();
            tar.append(&h1, &small[..]).unwrap();

            let heavy = vec![0u8; 64 * 1024];
            let mut h2 = tar::Header::new_gnu();
            h2.set_path(format!(
                "{root}system_logs.logarchive/Persist/0000000000000001.tracev3"
            ))
            .unwrap();
            h2.set_size(heavy.len() as u64);
            h2.set_cksum();
            tar.append(&h2, &heavy[..]).unwrap();
            tar.finish().unwrap();
        }
        let mut gz = GzEncoder::new(Vec::new(), Compression::default());
        gz.write_all(&tar_buf).unwrap();
        let bytes = gz.finish().unwrap();

        let arch = SysdiagnoseArchive::from_bytes_with_options(
            &bytes,
            ArchiveOptions {
                spill_logarchive_heavy: true,
                max_entry_bytes: 128 * 1024 * 1024,
                ..ArchiveOptions::default()
            },
        )
        .unwrap();
        assert_eq!(
            arch.get("system_logs.logarchive/Info.plist").unwrap(),
            b"plist"
        );
        assert!(arch
            .get("system_logs.logarchive/Persist/0000000000000001.tracev3")
            .is_none());
        assert_eq!(arch.logarchive_spilled_entries().len(), 1);
        assert!(arch
            .spilled_logarchive_abs("system_logs.logarchive/Persist/0000000000000001.tracev3")
            .is_some());
    }
}
