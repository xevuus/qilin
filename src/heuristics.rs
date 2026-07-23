//! Signal-based detection that doesn't depend on already knowing a file is
//! bad: byte-distribution entropy (packed/encrypted payloads look like
//! noise) and PE structural oddities (packer section names, the API-call
//! combination behind process injection). Both are heuristics in the literal
//! sense -- individually they produce false positives -- so every finding is
//! surfaced as a labeled tag rather than a bare pass/fail, leaving the
//! decision to whoever reads the scan output.

use goblin::pe::PE;
use std::path::Path;

/// Above this (out of a possible 8.0 bits/byte), a file's byte distribution
/// is close to indistinguishable from random data: the signature of
/// compression or encryption, and by extension of most packers. Chosen to
/// sit just above where prose/code/typical binaries land and just below
/// where compressed/encrypted data lands, matching the threshold used by
/// PEiD-style packer heuristics.
pub const DEFAULT_ENTROPY_THRESHOLD: f64 = 7.2;

// Entropy readings on tiny files are noisy (a 10-byte file can trivially hit
// 8.0 bits/byte) and meaningless as a packing signal, so they're skipped
// outright rather than flagged.
const MIN_ENTROPY_FILE_SIZE: usize = 256;

// Extensions that are routinely high-entropy for entirely innocent reasons
// (already-compressed archives, encoded media, office formats that are zips
// under the hood). Skipping them by default keeps entropy flagging focused
// on the executables/scripts where high entropy is actually surprising.
const SKIP_ENTROPY_EXTENSIONS: &[&str] = &[
    "zip", "gz", "tgz", "xz", "bz2", "7z", "rar", "zst", "lz4", "jpg", "jpeg", "png", "gif",
    "webp", "mp3", "mp4", "mkv", "mov", "avi", "flac", "ogg", "pdf", "docx", "xlsx", "pptx",
    "apk", "jar", "deb", "rpm", "dmg", "iso", "cab", "whl",
];

/// Well-known, unremarkable PE section names. Anything outside this list is
/// surfaced -- not because it's necessarily bad (custom linkers and
/// languages invent their own section names all the time), but because it's
/// uncommon enough to be worth a human glance.
const KNOWN_GOOD_SECTIONS: &[&str] = &[
    ".text", ".data", ".rdata", ".rsrc", ".reloc", ".idata", ".edata", ".pdata", ".tls", ".bss",
    ".didat", ".textbss", ".gfids", ".00cfg", ".xdata", ".sxdata", ".debug", ".drectve",
];

// Section-name substrings left behind by specific, well-known packers. A
// match here is a much stronger signal than merely "not in the known-good
// list" -- these are near-certain packing indicators, called out separately
// in the finding text.
const PACKER_SECTION_MARKERS: &[&str] = &[
    "upx0", "upx1", "upx2", "upx!", ".aspack", ".adata", ".packed", ".nsp0", ".nsp1", ".nsp2",
    ".petite", ".mpress1", ".mpress2", ".vmp0", ".vmp1", ".themida",
];

// Imports that are individually mundane (installers, games, and DRM all
// call VirtualAlloc) but, seen together in the same binary, are the
// textbook fingerprint of process injection: allocate memory in a
// (possibly remote) process, write shellcode into it, then start executing
// it -- optionally after checking whether a debugger is watching.
const SUSPICIOUS_IMPORTS: &[&str] = &[
    "VirtualAlloc",
    "VirtualAllocEx",
    "VirtualProtect",
    "VirtualProtectEx",
    "WriteProcessMemory",
    "CreateRemoteThread",
    "CreateRemoteThreadEx",
    "NtUnmapViewOfSection",
    "NtWriteVirtualMemory",
    "NtCreateThreadEx",
    "SetWindowsHookExA",
    "SetWindowsHookExW",
    "QueueUserAPC",
    "URLDownloadToFileA",
    "URLDownloadToFileW",
    "WinExec",
    "ShellExecuteA",
    "IsDebuggerPresent",
    "CheckRemoteDebuggerPresent",
];

// A single suspicious import is noise (nearly every installer calls
// VirtualAlloc); this many together is the pattern.
const SUSPICIOUS_IMPORT_THRESHOLD: usize = 3;

/// Shannon entropy of `data`, in bits per byte (0.0 for empty or
/// single-valued input, up to 8.0 for a perfectly uniform byte distribution).
pub fn shannon_entropy(data: &[u8]) -> f64 {
    if data.is_empty() {
        return 0.0;
    }
    let mut counts = [0u32; 256];
    for &b in data {
        counts[b as usize] += 1;
    }
    let len = data.len() as f64;
    counts
        .iter()
        .filter(|&&c| c > 0)
        .map(|&c| {
            let p = c as f64 / len;
            -p * p.log2()
        })
        .sum()
}

fn worth_entropy_check(path: &Path, data_len: usize) -> bool {
    if data_len < MIN_ENTROPY_FILE_SIZE {
        return false;
    }
    match path.extension().and_then(|e| e.to_str()) {
        Some(ext) => {
            let lower = ext.to_ascii_lowercase();
            !SKIP_ENTROPY_EXTENSIONS.contains(&lower.as_str())
        }
        None => true,
    }
}

fn classify_section(name: &str) -> Option<String> {
    let lower = name.to_ascii_lowercase();
    if let Some(marker) = PACKER_SECTION_MARKERS.iter().find(|m| lower.contains(**m)) {
        Some(format!("{name} (matches known packer section {marker})"))
    } else if !KNOWN_GOOD_SECTIONS.contains(&lower.as_str()) {
        Some(name.to_string())
    } else {
        None
    }
}

fn classify_imports<'a>(names: impl Iterator<Item = &'a str>) -> Vec<String> {
    let mut hits: Vec<String> = names
        .filter(|n| SUSPICIOUS_IMPORTS.contains(n))
        .map(|n| n.to_string())
        .collect();
    hits.sort();
    hits.dedup();
    hits
}

#[derive(Debug, Default)]
pub struct PeFindings {
    pub suspicious_sections: Vec<String>,
    pub suspicious_imports: Vec<String>,
}

impl PeFindings {
    fn is_notable(&self) -> bool {
        !self.suspicious_sections.is_empty()
            || self.suspicious_imports.len() >= SUSPICIOUS_IMPORT_THRESHOLD
    }
}

/// Parse `data` as a PE (Windows executable/DLL) and flag structural
/// oddities associated with packing or process injection. Returns `None`
/// both for anything that isn't a well-formed PE and for a PE with nothing
/// worth flagging -- callers don't need to distinguish "not a PE" from
/// "clean PE".
pub fn inspect_pe(data: &[u8]) -> Option<PeFindings> {
    let pe = PE::parse(data).ok()?;

    let suspicious_sections: Vec<String> = pe
        .sections
        .iter()
        .filter_map(|s| s.name().ok())
        .filter_map(classify_section)
        .collect();
    let suspicious_imports = classify_imports(pe.imports.iter().map(|i| i.name.as_ref()));

    let findings = PeFindings {
        suspicious_sections,
        suspicious_imports,
    };
    findings.is_notable().then_some(findings)
}

/// Run every heuristic against `data` (the file's content, possibly
/// truncated to a read cap for large files) and return human-readable
/// finding tags, e.g. `"high_entropy=7.83"` or
/// `"pe_suspicious_imports=CreateRemoteThread,VirtualAllocEx,WriteProcessMemory"`.
/// An empty vec means nothing fired, not that the file wasn't checked.
pub fn inspect(path: &Path, data: &[u8], entropy_threshold: f64) -> Vec<String> {
    let mut tags = Vec::new();

    if worth_entropy_check(path, data.len()) {
        let entropy = shannon_entropy(data);
        if entropy >= entropy_threshold {
            tags.push(format!("high_entropy={entropy:.2}"));
        }
    }

    if let Some(pe) = inspect_pe(data) {
        for section in pe.suspicious_sections {
            tags.push(format!("pe_suspicious_section={section}"));
        }
        if !pe.suspicious_imports.is_empty() {
            tags.push(format!(
                "pe_suspicious_imports={}",
                pe.suspicious_imports.join(",")
            ));
        }
    }

    tags
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn entropy_of_constant_bytes_is_zero() {
        let data = vec![0x41u8; 1024];
        assert_eq!(shannon_entropy(&data), 0.0);
    }

    #[test]
    fn entropy_of_uniform_byte_distribution_is_near_maximum() {
        let mut data = Vec::with_capacity(256 * 64);
        for _ in 0..64 {
            data.extend(0u8..=255);
        }
        assert!(shannon_entropy(&data) > 7.99);
    }

    #[test]
    fn small_files_are_never_entropy_checked() {
        assert!(!worth_entropy_check(Path::new("a.bin"), MIN_ENTROPY_FILE_SIZE - 1));
        assert!(worth_entropy_check(Path::new("a.bin"), MIN_ENTROPY_FILE_SIZE));
    }

    #[test]
    fn known_compressed_extensions_are_skipped() {
        assert!(!worth_entropy_check(Path::new("archive.zip"), 4096));
        assert!(!worth_entropy_check(Path::new("photo.JPG"), 4096));
        assert!(worth_entropy_check(Path::new("payload.exe"), 4096));
        assert!(worth_entropy_check(Path::new("no_extension"), 4096));
    }

    #[test]
    fn known_good_sections_are_not_flagged() {
        assert_eq!(classify_section(".text"), None);
        assert_eq!(classify_section(".rdata"), None);
    }

    #[test]
    fn packer_sections_are_flagged_with_the_matched_marker() {
        let finding = classify_section("UPX1").unwrap();
        assert!(finding.contains("upx1"));
    }

    #[test]
    fn unrecognized_sections_are_flagged_plain() {
        assert_eq!(classify_section(".weird"), Some(".weird".to_string()));
    }

    #[test]
    fn a_single_suspicious_import_is_not_enough_to_flag() {
        let hits = classify_imports(vec!["VirtualAlloc", "printf", "malloc"].into_iter());
        assert_eq!(hits, vec!["VirtualAlloc".to_string()]);
        assert!(hits.len() < SUSPICIOUS_IMPORT_THRESHOLD);
    }

    #[test]
    fn injection_pattern_import_combo_is_collected_and_deduped() {
        let hits = classify_imports(
            vec![
                "WriteProcessMemory",
                "CreateRemoteThread",
                "VirtualAllocEx",
                "VirtualAllocEx",
                "printf",
            ]
            .into_iter(),
        );
        assert_eq!(
            hits,
            vec![
                "CreateRemoteThread".to_string(),
                "VirtualAllocEx".to_string(),
                "WriteProcessMemory".to_string(),
            ]
        );
    }

    #[test]
    fn garbage_bytes_are_not_a_pe() {
        assert!(inspect_pe(b"not a pe file at all").is_none());
    }

    #[test]
    fn inspect_combines_entropy_and_pe_tags() {
        let mut data = Vec::with_capacity(256 * 64);
        for _ in 0..64 {
            data.extend(0u8..=255);
        }
        let tags = inspect(Path::new("payload.exe"), &data, DEFAULT_ENTROPY_THRESHOLD);
        assert_eq!(tags.len(), 1);
        assert!(tags[0].starts_with("high_entropy="));
    }
}
