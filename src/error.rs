// SPDX-License-Identifier: GPL-3.0-only

use std::io;

/// Failures while opening or reading a sysdiagnose archive.
#[derive(Debug, thiserror::Error)]
pub enum ArchiveError {
    #[error("archive is empty")]
    EmptyArchive,
    #[error("not a file: {0}")]
    NotAFile(String),
    #[error("unsupported or corrupt archive: {0}")]
    Format(String),
    #[error(transparent)]
    Io(#[from] io::Error),
}

pub type BoxErr = Box<dyn std::error::Error + Send + Sync>;

pub fn box_err(err: impl std::error::Error + Send + Sync + 'static) -> BoxErr {
    Box::new(err)
}
