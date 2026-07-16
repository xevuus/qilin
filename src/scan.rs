use anyhow::{bail, Context, Result};
use rayon::iter::{ParallelBridge, ParallelIterator};
use sha2::{Digest, Sha256};
use std::fs::File;
use std::io::{BufReader, Read};
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::Mutex;
use std::time::{Duration, Instant};
use walkdir::WalkDir;

use crate::db::SignatureDb;

// How often (in files hashed) to emit a "still working" progress line on
// stderr during long scans. Stdout stays reserved for detections + the
// final summary so scan output remains clean and script-friendly.
const PROGRESS_INTERVAL: usize = 5000;

// Virtual/pseudo filesystems that are pointless (and sometimes hazardous:
// some /proc entries report misleading sizes or block on read) to hash.
// These are only skipped when encountered as an exact top-level path, so an
// explicit `scan /proc` still works.
#[cfg(unix)]
const DEFAULT_EXCLUDES: &[&str] = &["/proc", "/sys", "/dev", "/run"];
#[cfg(not(unix))]
const DEFAULT_EXCLUDES: &[&str] = &[];

#[derive(Debug)]
pub struct Match {
    pub path: PathBuf,
    pub sha256: String,
    pub label: String,
}

#[derive(Debug)]
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

fn is_excluded(path: &Path, scan_root: &Path, extra_excludes: &[PathBuf]) -> bool {
    if path == scan_root {
        return false;
    }
    if DEFAULT_EXCLUDES.iter().any(|p| path == Path::new(p)) {
        return true;
    }
    extra_excludes.iter().any(|ex| path.starts_with(ex))
}

/// Walk `root` (file or directory), hash every regular file, and check each
/// hash against `db`. Hashing is parallelized across available cores so
/// whole-filesystem scans stay practical.
///
/// `extra_excludes` are additional path prefixes to prune entirely (e.g. a
/// slow network mount); pseudo-filesystems (`/proc`, `/sys`, `/dev`, `/run`
/// on Unix) are always pruned unless `root` points directly at one of them.
///
/// `on_file` is called (from worker threads, possibly concurrently) for
/// every file as it's visited, before hashing, so callers can print progress.
pub fn scan_path(
    root: &Path,
    db: &SignatureDb,
    extra_excludes: &[PathBuf],
    on_file: impl Fn(&Path) + Sync,
) -> Result<ScanReport> {
    if !root.exists() {
        bail!("path does not exist: {}", root.display());
    }

    let start = Instant::now();
    let files_scanned = AtomicUsize::new(0);
    let files_errored = AtomicUsize::new(0);
    let matches = Mutex::new(Vec::new());

    WalkDir::new(root)
        .follow_links(false)
        .into_iter()
        .filter_entry(|e| !is_excluded(e.path(), root, extra_excludes))
        .par_bridge()
        .for_each(|entry| {
            let entry = match entry {
                Ok(e) => e,
                Err(_) => {
                    files_errored.fetch_add(1, Ordering::Relaxed);
                    return;
                }
            };
            if !entry.file_type().is_file() {
                return;
            }
            let path = entry.path();
            on_file(path);

            match hash_file(path) {
                Ok(hash) => {
                    let n = files_scanned.fetch_add(1, Ordering::Relaxed) + 1;
                    if n % PROGRESS_INTERVAL == 0 {
                        eprintln!(
                            "  ... {n} files scanned so far ({:.0}s elapsed)",
                            start.elapsed().as_secs_f64()
                        );
                    }
                    if let Some(label) = db.lookup(&hash) {
                        matches.lock().unwrap().push(Match {
                            path: path.to_path_buf(),
                            sha256: hash,
                            label: label.to_string(),
                        });
                    }
                }
                Err(_) => {
                    files_errored.fetch_add(1, Ordering::Relaxed);
                }
            }
        });

    Ok(ScanReport {
        files_scanned: files_scanned.load(Ordering::Relaxed),
        files_errored: files_errored.load(Ordering::Relaxed),
        matches: matches.into_inner().unwrap(),
        elapsed: start.elapsed(),
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::fs;

    fn test_dir(name: &str) -> PathBuf {
        let dir = std::env::temp_dir().join(format!("qilin-scan-test-{name}-{}", std::process::id()));
        let _ = fs::remove_dir_all(&dir);
        fs::create_dir_all(dir.join("subdir")).unwrap();
        dir
    }

    #[test]
    fn detects_matching_file_and_skips_clean_ones() {
        let dir = test_dir("detect");
        fs::write(dir.join("clean.txt"), b"nothing to see here").unwrap();
        fs::write(dir.join("subdir").join("evil.bin"), b"totally malicious payload").unwrap();

        let evil_hash = hash_file(&dir.join("subdir").join("evil.bin")).unwrap();
        let cache_path = dir.join("db.cache");
        fs::write(&cache_path, format!("{evil_hash}\tTest.Signature\n")).unwrap();
        let db = SignatureDb::load(&cache_path).unwrap();

        let report = scan_path(&dir, &db, &[], |_| {}).unwrap();

        // clean.txt + evil.bin (db.cache isn't a match but is still hashed)
        assert_eq!(report.files_scanned, 3);
        assert_eq!(report.matches.len(), 1);
        assert_eq!(report.matches[0].sha256, evil_hash);
        assert_eq!(report.matches[0].label, "Test.Signature");

        fs::remove_dir_all(&dir).ok();
    }

    #[test]
    fn errors_on_missing_path() {
        let dir = test_dir("missing");
        fs::remove_dir_all(&dir).ok();
        let db = SignatureDb::empty();
        let err = scan_path(&dir, &db, &[], |_| {}).unwrap_err();
        assert!(err.to_string().contains("does not exist"));
    }

    #[test]
    fn respects_extra_excludes() {
        let dir = test_dir("exclude");
        fs::write(dir.join("keep.txt"), b"keep me").unwrap();
        fs::write(dir.join("subdir").join("skip.txt"), b"skip me").unwrap();

        let db = SignatureDb::empty();
        let report = scan_path(&dir, &db, &[dir.join("subdir")], |_| {}).unwrap();
        assert_eq!(report.files_scanned, 1);

        fs::remove_dir_all(&dir).ok();
    }
}
