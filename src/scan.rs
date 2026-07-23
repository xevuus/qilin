use anyhow::{bail, Context, Result};
use rayon::iter::{ParallelBridge, ParallelIterator};
use sha2::{Digest, Sha256};
use std::fs::File;
use std::io::{BufReader, BufWriter, Read, Write};
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::Mutex;
use std::time::{Duration, Instant};
use walkdir::WalkDir;
use yara_x::Rules;

use crate::db::SignatureDb;
use crate::heuristics;

// Files larger than this are still hashed and checked against the hash
// database in full, but YARA pattern matching, and entropy/PE heuristics,
// are limited to their first chunk. Community/custom rules and PE headers
// live near the start of a file, not scattered through multi-gigabyte
// payloads, so this keeps a whole-filesystem scan from stalling on VM
// disks, ISOs, etc.
const YARA_MAX_SCAN_SIZE: usize = 64 * 1024 * 1024;
const HEURISTIC_MAX_READ_SIZE: usize = 64 * 1024 * 1024;

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
    /// Signature-name label from the hash database, if this file's hash was
    /// a known-bad match. Empty when the file was only flagged by YARA.
    pub label: String,
    /// Identifiers of every YARA rule that matched this file's contents.
    pub yara_rules: Vec<String>,
    /// Entropy/PE-structure findings; see [`crate::heuristics::inspect`].
    pub heuristics: Vec<String>,
    /// Where the file was moved to, if `--quarantine` was given and the
    /// move succeeded. `None` also covers "quarantine wasn't requested".
    pub quarantined_to: Option<PathBuf>,
}

/// Knobs for [`scan_path`], bundled into one struct because the list of
/// per-scan options (YARA, heuristics, exclusions, quarantine) keeps
/// growing and a wall of positional bool/Option params gets error-prone to
/// call correctly.
pub struct ScanOptions<'a> {
    pub yara_rules: Option<&'a Rules>,
    pub extra_excludes: &'a [PathBuf],
    pub heuristics_enabled: bool,
    pub entropy_threshold: f64,
    /// Directory to move detected files into. `None` means detections are
    /// only reported, never touched on disk.
    pub quarantine_dir: Option<&'a Path>,
}

impl Default for ScanOptions<'_> {
    fn default() -> Self {
        Self {
            yara_rules: None,
            extra_excludes: &[],
            heuristics_enabled: true,
            entropy_threshold: heuristics::DEFAULT_ENTROPY_THRESHOLD,
            quarantine_dir: None,
        }
    }
}

/// Moves detected files into `dir`, deduplicated by hash, and appends a
/// tab-separated line to `dir/quarantine.log` for each move. Never deletes:
/// a failed or unwanted quarantine can always be undone by moving the file
/// back from the logged destination.
struct Quarantine<'a> {
    dir: &'a Path,
    log: Mutex<BufWriter<File>>,
}

impl<'a> Quarantine<'a> {
    fn open(dir: &'a Path) -> Result<Self> {
        std::fs::create_dir_all(dir)
            .with_context(|| format!("failed to create quarantine dir {}", dir.display()))?;
        let log_path = dir.join("quarantine.log");
        let file = std::fs::OpenOptions::new()
            .create(true)
            .append(true)
            .open(&log_path)
            .with_context(|| format!("failed to open {}", log_path.display()))?;
        Ok(Self {
            dir,
            log: Mutex::new(BufWriter::new(file)),
        })
    }

    /// Move `path` into `<quarantine_dir>/<sha256>/<original file name>`.
    /// Keying by hash means identical content quarantined from multiple
    /// paths collapses onto one copy instead of erroring or duplicating.
    fn take(&self, path: &Path, sha256: &str, reasons: &str) -> Result<PathBuf> {
        let file_name = path.file_name().unwrap_or_default();
        let dest_dir = self.dir.join(sha256);
        std::fs::create_dir_all(&dest_dir)
            .with_context(|| format!("failed to create {}", dest_dir.display()))?;
        let dest = dest_dir.join(file_name);

        move_file(path, &dest)
            .with_context(|| format!("failed to quarantine {}", path.display()))?;

        let timestamp = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap_or_default()
            .as_secs();
        let line = format!(
            "{timestamp}\t{}\t{sha256}\t{reasons}\t{}\n",
            path.display(),
            dest.display()
        );
        let mut log = self.log.lock().unwrap();
        log.write_all(line.as_bytes())?;
        // Flushed per entry (not just at scan end) so a whole-filesystem
        // scan interrupted partway through doesn't lose the record of what
        // it already moved.
        log.flush()?;

        Ok(dest)
    }
}

/// Rename `src` to `dest`, falling back to copy+remove when they're on
/// different filesystems (the common case: a quarantine directory living
/// on a different mount than whatever a whole-system scan turns up, which
/// makes `rename()` fail with EXDEV).
fn move_file(src: &Path, dest: &Path) -> Result<()> {
    if std::fs::rename(src, dest).is_ok() {
        return Ok(());
    }
    std::fs::copy(src, dest)
        .with_context(|| format!("failed to copy {} to {}", src.display(), dest.display()))?;
    std::fs::remove_file(src).with_context(|| {
        format!(
            "copied {} to {} but failed to remove the original",
            src.display(),
            dest.display()
        )
    })?;
    Ok(())
}

/// Join whatever fired for a match into one human/log-readable string, e.g.
/// `"hash=Trojan.Test, yara=Qilin_Mimikatz_Artifacts, heuristic=high_entropy=7.83"`.
fn describe_reasons(label: &str, yara_hits: &[String], heuristic_hits: &[String]) -> String {
    let mut parts = Vec::new();
    if !label.is_empty() {
        parts.push(format!("hash={label}"));
    }
    parts.extend(yara_hits.iter().map(|r| format!("yara={r}")));
    parts.extend(heuristic_hits.iter().map(|h| format!("heuristic={h}")));
    parts.join(", ")
}

/// Read up to `cap` bytes from `path`. Used for heuristics, which (unlike
/// hashing) need the bytes in memory at once rather than streamed.
fn read_prefix(path: &Path, cap: usize) -> Result<Vec<u8>> {
    let file = File::open(path).with_context(|| format!("failed to open {}", path.display()))?;
    let mut reader = BufReader::new(file);
    let mut buf = vec![0u8; cap];
    let mut total = 0;
    while total < buf.len() {
        let n = reader.read(&mut buf[total..])?;
        if n == 0 {
            break;
        }
        total += n;
    }
    buf.truncate(total);
    Ok(buf)
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
/// `opts.extra_excludes` are additional path prefixes to prune entirely
/// (e.g. a slow network mount); pseudo-filesystems (`/proc`, `/sys`, `/dev`,
/// `/run` on Unix) are always pruned unless `root` points directly at one
/// of them.
///
/// `on_file` is called (from worker threads, possibly concurrently) for
/// every file as it's visited, before hashing, so callers can print progress.
///
/// `opts.yara_rules`, when given, is additionally matched against every
/// file's contents so family/pattern-based detections surface alongside
/// exact hash matches. A fresh [`yara_x::Scanner`] is created per rayon
/// worker (via `for_each_init`) rather than per file, since `Scanner` isn't
/// `Sync` but is cheap to reuse across many scans on the same thread.
///
/// When `opts.heuristics_enabled`, every file is also checked for high
/// byte-entropy and (if it parses as one) suspicious PE structure; see
/// [`crate::heuristics`].
///
/// When `opts.quarantine_dir` is set, any file with at least one detection
/// (hash, YARA, or heuristic) is moved there; see [`Quarantine`].
pub fn scan_path(
    root: &Path,
    db: &SignatureDb,
    opts: &ScanOptions,
    on_file: impl Fn(&Path) + Sync,
) -> Result<ScanReport> {
    if !root.exists() {
        bail!("path does not exist: {}", root.display());
    }

    let quarantine = opts.quarantine_dir.map(Quarantine::open).transpose()?;

    let start = Instant::now();
    let files_scanned = AtomicUsize::new(0);
    let files_errored = AtomicUsize::new(0);
    let matches = Mutex::new(Vec::new());

    WalkDir::new(root)
        .follow_links(false)
        .into_iter()
        .filter_entry(|e| !is_excluded(e.path(), root, opts.extra_excludes))
        .par_bridge()
        .for_each_init(
            || {
                let mut scanner = opts.yara_rules.map(yara_x::Scanner::new);
                if let Some(s) = scanner.as_mut() {
                    s.max_scan_size(YARA_MAX_SCAN_SIZE);
                }
                scanner
            },
            |scanner, entry| {
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

                let hash = match hash_file(path) {
                    Ok(hash) => hash,
                    Err(_) => {
                        files_errored.fetch_add(1, Ordering::Relaxed);
                        return;
                    }
                };
                let n = files_scanned.fetch_add(1, Ordering::Relaxed) + 1;
                if n % PROGRESS_INTERVAL == 0 {
                    eprintln!(
                        "  ... {n} files scanned so far ({:.0}s elapsed)",
                        start.elapsed().as_secs_f64()
                    );
                }

                let label = db.lookup(&hash).unwrap_or("");
                let yara_hits: Vec<String> = match scanner {
                    Some(scanner) => match scanner.scan_file(path) {
                        Ok(results) => results
                            .matching_rules()
                            .map(|r| {
                                if r.namespace() == "default" {
                                    r.identifier().to_string()
                                } else {
                                    format!("{}::{}", r.namespace(), r.identifier())
                                }
                            })
                            .collect(),
                        Err(_) => Vec::new(),
                    },
                    None => Vec::new(),
                };

                let heuristic_hits: Vec<String> = if opts.heuristics_enabled {
                    match read_prefix(path, HEURISTIC_MAX_READ_SIZE) {
                        Ok(data) => heuristics::inspect(path, &data, opts.entropy_threshold),
                        Err(_) => Vec::new(),
                    }
                } else {
                    Vec::new()
                };

                if !label.is_empty() || !yara_hits.is_empty() || !heuristic_hits.is_empty() {
                    let quarantined_to = quarantine.as_ref().and_then(|q| {
                        let reasons = describe_reasons(label, &yara_hits, &heuristic_hits);
                        match q.take(path, &hash, &reasons) {
                            Ok(dest) => Some(dest),
                            Err(e) => {
                                eprintln!("warning: failed to quarantine {}: {e}", path.display());
                                None
                            }
                        }
                    });

                    matches.lock().unwrap().push(Match {
                        path: path.to_path_buf(),
                        sha256: hash,
                        label: label.to_string(),
                        yara_rules: yara_hits,
                        heuristics: heuristic_hits,
                        quarantined_to,
                    });
                }
            },
        );

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

        let report = scan_path(&dir, &db, &ScanOptions::default(), |_| {}).unwrap();

        // clean.txt + evil.bin (db.cache isn't a match but is still hashed)
        assert_eq!(report.files_scanned, 3);
        assert_eq!(report.matches.len(), 1);
        assert_eq!(report.matches[0].sha256, evil_hash);
        assert_eq!(report.matches[0].label, "Test.Signature");
        assert!(report.matches[0].quarantined_to.is_none());

        fs::remove_dir_all(&dir).ok();
    }

    #[test]
    fn errors_on_missing_path() {
        let dir = test_dir("missing");
        fs::remove_dir_all(&dir).ok();
        let db = SignatureDb::empty();
        let err = scan_path(&dir, &db, &ScanOptions::default(), |_| {}).unwrap_err();
        assert!(err.to_string().contains("does not exist"));
    }

    #[test]
    fn respects_extra_excludes() {
        let dir = test_dir("exclude");
        fs::write(dir.join("keep.txt"), b"keep me").unwrap();
        fs::write(dir.join("subdir").join("skip.txt"), b"skip me").unwrap();

        let db = SignatureDb::empty();
        let excludes = [dir.join("subdir")];
        let opts = ScanOptions {
            extra_excludes: &excludes,
            ..Default::default()
        };
        let report = scan_path(&dir, &db, &opts, |_| {}).unwrap();
        assert_eq!(report.files_scanned, 1);

        fs::remove_dir_all(&dir).ok();
    }

    #[test]
    fn yara_match_surfaces_without_a_hash_hit() {
        let dir = test_dir("yara");
        fs::write(
            dir.join("dropper.ps1"),
            b"powershell -windowstyle hidden -EncodedCommand aGVsbG8=",
        )
        .unwrap();

        let db = SignatureDb::empty();
        let rule_set = crate::yara_rules::compile(&[]).unwrap();
        let opts = ScanOptions {
            yara_rules: Some(&rule_set.rules),
            ..Default::default()
        };
        let report = scan_path(&dir, &db, &opts, |_| {}).unwrap();

        assert_eq!(report.matches.len(), 1);
        assert!(report.matches[0].label.is_empty());
        assert!(report.matches[0]
            .yara_rules
            .contains(&"Qilin_Suspicious_PowerShell_EncodedCommand".to_string()));

        fs::remove_dir_all(&dir).ok();
    }

    #[test]
    fn high_entropy_file_surfaces_as_a_heuristic_hit_without_a_hash_or_yara_match() {
        let dir = test_dir("entropy");
        // A uniform byte-value cycle is not compressible and reads as
        // near-maximum entropy, the same signal a packed/encrypted binary
        // would produce.
        let mut packed = Vec::with_capacity(256 * 8);
        for _ in 0..8 {
            packed.extend(0u8..=255);
        }
        fs::write(dir.join("packed.bin"), &packed).unwrap();

        let db = SignatureDb::empty();
        let report = scan_path(&dir, &db, &ScanOptions::default(), |_| {}).unwrap();

        assert_eq!(report.matches.len(), 1);
        assert!(report.matches[0].label.is_empty());
        assert!(report.matches[0].yara_rules.is_empty());
        assert!(report.matches[0]
            .heuristics
            .iter()
            .any(|h| h.starts_with("high_entropy=")));

        fs::remove_dir_all(&dir).ok();
    }

    #[test]
    fn heuristics_can_be_disabled() {
        let dir = test_dir("entropy-disabled");
        let mut packed = Vec::with_capacity(256 * 8);
        for _ in 0..8 {
            packed.extend(0u8..=255);
        }
        fs::write(dir.join("packed.bin"), &packed).unwrap();

        let db = SignatureDb::empty();
        let opts = ScanOptions {
            heuristics_enabled: false,
            ..Default::default()
        };
        let report = scan_path(&dir, &db, &opts, |_| {}).unwrap();

        assert!(report.matches.is_empty());

        fs::remove_dir_all(&dir).ok();
    }

    #[test]
    fn quarantine_moves_detected_files_and_logs_them() {
        let dir = test_dir("quarantine");
        let evil_path = dir.join("subdir").join("evil.bin");
        fs::write(&evil_path, b"totally malicious payload").unwrap();

        let evil_hash = hash_file(&evil_path).unwrap();
        let cache_path = dir.join("db.cache");
        fs::write(&cache_path, format!("{evil_hash}\tTest.Signature\n")).unwrap();
        let db = SignatureDb::load(&cache_path).unwrap();

        // Kept outside `dir`: nesting the quarantine dir inside the tree
        // being scanned would let the walk pick up files after they land
        // in quarantine, which is a real footgun for callers to avoid but
        // not what this test is about.
        let quarantine_dir = test_dir("quarantine-dest");
        let opts = ScanOptions {
            quarantine_dir: Some(&quarantine_dir),
            ..Default::default()
        };
        let report = scan_path(&dir, &db, &opts, |_| {}).unwrap();

        assert_eq!(report.matches.len(), 1);
        assert!(!evil_path.exists(), "original file should have been moved");

        let quarantined_to = report.matches[0].quarantined_to.as_ref().unwrap();
        assert!(quarantined_to.exists());
        assert_eq!(fs::read(quarantined_to).unwrap(), b"totally malicious payload");
        assert!(quarantined_to.starts_with(&quarantine_dir));

        let log = fs::read_to_string(quarantine_dir.join("quarantine.log")).unwrap();
        assert!(log.contains(&evil_hash));
        assert!(log.contains("hash=Test.Signature"));

        fs::remove_dir_all(&dir).ok();
        fs::remove_dir_all(&quarantine_dir).ok();
    }
}
