use anyhow::{Context, Result};
use sha2::{Digest, Sha256};
use std::fs::File;
use std::io::{BufReader, Read};
use std::path::{Path, PathBuf};
use std::time::{Duration, Instant};
use walkdir::WalkDir;

use crate::db::SignatureDb;

pub struct Match {
    pub path: PathBuf,
    pub sha256: String,
    pub label: String,
}

pub struct ScanReport {
    pub files_scanned: usize,
    pub files_errored: usize,
    pub matches: Vec<Match>,
    pub elapsed: Duration,
}

/// Stream a file through SHA-256 without loading it into memory.
pub fn hash_file(path: &Path) -> Result<String> {
    let file = File::open(path).with_context(|| format!("failed to open {}", path.display()))?;
    let mut reader = BufReader::new(file);
    let mut hasher = Sha256::new();
    let mut buf = [0u8; 64 * 1024];
    loop {
        let n = reader.read(&mut buf)?;
        if n == 0 {
            break;
        }
        hasher.update(&buf[..n]);
    }
    Ok(format!("{:x}", hasher.finalize()))
}

/// Walk `root` (file or directory), hash every regular file, and check each
/// hash against `db`. `on_file` is called for every file as it's visited,
/// before hashing, so callers can print progress.
pub fn scan_path(root: &Path, db: &SignatureDb, mut on_file: impl FnMut(&Path)) -> Result<ScanReport> {
    let start = Instant::now();
    let mut files_scanned = 0usize;
    let mut files_errored = 0usize;
    let mut matches = Vec::new();

    for entry in WalkDir::new(root).follow_links(false) {
        let entry = match entry {
            Ok(e) => e,
            Err(_) => {
                files_errored += 1;
                continue;
            }
        };
        if !entry.file_type().is_file() {
            continue;
        }
        let path = entry.path();
        on_file(path);

        match hash_file(path) {
            Ok(hash) => {
                files_scanned += 1;
                if let Some(label) = db.lookup(&hash) {
                    matches.push(Match {
                        path: path.to_path_buf(),
                        sha256: hash,
                        label: label.to_string(),
                    });
                }
            }
            Err(_) => files_errored += 1,
        }
    }

    Ok(ScanReport {
        files_scanned,
        files_errored,
        matches,
        elapsed: start.elapsed(),
    })
}
