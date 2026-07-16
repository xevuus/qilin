use anyhow::{bail, Context, Result};
use std::collections::HashMap;
use std::fs::File;
use std::io::{BufRead, BufReader, BufWriter, Write};
use std::path::{Path, PathBuf};

const CACHE_FILE_NAME: &str = "malwarebazaar.cache";

#[derive(Clone, Copy, Debug)]
pub enum Dataset {
    Full,
    Recent,
}

impl Dataset {
    pub fn as_str(&self) -> &'static str {
        match self {
            Dataset::Full => "full",
            Dataset::Recent => "recent",
        }
    }
}

#[derive(Clone, Copy, Debug)]
pub enum ExportFormat {
    Csv,
    Txt,
}

impl ExportFormat {
    pub fn as_str(&self) -> &'static str {
        match self {
            ExportFormat::Csv => "csv",
            ExportFormat::Txt => "txt",
        }
    }
}

/// A locally cached set of known-bad SHA-256 hashes, optionally labeled with
/// the malware family / signature name reported by the source feed.
pub struct SignatureDb {
    hashes: HashMap<String, String>,
}

impl SignatureDb {
    /// An empty database with no known hashes (useful for tests, or a scan
    /// run before any signatures have been fetched).
    #[allow(dead_code)]
    pub fn empty() -> Self {
        Self {
            hashes: HashMap::new(),
        }
    }

    pub fn len(&self) -> usize {
        self.hashes.len()
    }

    pub fn lookup(&self, sha256_hex: &str) -> Option<&str> {
        self.hashes.get(sha256_hex).map(|s| s.as_str())
    }

    /// Default on-disk location for the cached signature database.
    pub fn default_path() -> Result<PathBuf> {
        let dir = dirs::cache_dir()
            .map(|d| d.join("detection-cli"))
            .unwrap_or_else(|| PathBuf::from("."));
        Ok(dir.join(CACHE_FILE_NAME))
    }

    /// Load a previously cached signature database (our own `sha256\tlabel`
    /// format, written by [`SignatureDb::update`]).
    pub fn load(path: &Path) -> Result<Self> {
        let file = File::open(path)
            .with_context(|| format!("failed to open signature database at {}", path.display()))?;
        let reader = BufReader::new(file);
        let mut hashes = HashMap::new();
        for line in reader.lines() {
            let line = line?;
            if line.is_empty() {
                continue;
            }
            let mut parts = line.splitn(2, '\t');
            let hash = parts.next().unwrap_or("").trim().to_ascii_lowercase();
            let label = parts.next().unwrap_or("").trim().to_string();
            if is_sha256_hex(&hash) {
                hashes.insert(hash, label);
            }
        }
        Ok(Self { hashes })
    }

    /// Download the MalwareBazaar hash export, parse it, and cache it to
    /// `dest`. Returns the number of hashes cached.
    ///
    /// abuse.ch requires a free Auth-Key (register at https://auth.abuse.ch/)
    /// passed as a path segment: the exact CSV column layout is documented
    /// only behind that login, so parsing below is defensive: it locates the
    /// `sha256_hash` column by header name and falls back to a bare
    /// one-hash-per-line format if the response isn't CSV-shaped.
    pub fn update(dest: &Path, auth_key: &str, dataset: Dataset, fmt: ExportFormat) -> Result<usize> {
        let url = format!(
            "https://mb-api.abuse.ch/v2/files/exports/{}/{}.{}",
            auth_key,
            dataset.as_str(),
            fmt.as_str(),
        );

        let response = reqwest::blocking::Client::builder()
            .user_agent("detection-cli/0.1")
            .build()?
            .get(&url)
            .send()
            .context("request to MalwareBazaar export API failed")?;

        if !response.status().is_success() {
            let status = response.status();
            let body = response.text().unwrap_or_default();
            let body = body.trim();
            bail!(
                "MalwareBazaar export API returned HTTP {status}: check that your Auth-Key is valid{}",
                if body.is_empty() {
                    String::new()
                } else {
                    format!("\nresponse body: {body}")
                }
            );
        }

        let body = response.text().context("failed to read response body")?;
        parse_and_write(&body, dest)
    }
}

fn is_sha256_hex(s: &str) -> bool {
    s.len() == 64 && s.bytes().all(|b| b.is_ascii_hexdigit())
}

fn parse_and_write(body: &str, dest: &Path) -> Result<usize> {
    if let Some(parent) = dest.parent() {
        std::fs::create_dir_all(parent)?;
    }
    let tmp_path = dest.with_extension("tmp");
    let mut out = BufWriter::new(File::create(&tmp_path)?);
    let mut count = 0usize;

    // MalwareBazaar exports prefix the payload with `#`-commented metadata
    // lines above the data rows, and the column header row itself is also
    // `#`-prefixed (e.g. `#first_seen_utc,sha256_hash,...`) rather than being
    // a normal first row, so it has to be pulled out of the preamble instead
    // of being treated as data.
    let mut header_line: Option<String> = None;
    let mut data_lines: Vec<&str> = Vec::new();
    for line in body.lines() {
        let trimmed = line.trim_start();
        if trimmed.starts_with('#') {
            let stripped = trimmed.trim_start_matches('#').trim();
            if stripped.to_ascii_lowercase().contains("sha256") && stripped.contains(',') {
                header_line = Some(stripped.to_string());
            }
            continue;
        }
        if trimmed.is_empty() {
            continue;
        }
        data_lines.push(line);
    }

    if data_lines.is_empty() {
        bail!("MalwareBazaar export was empty");
    }

    if data_lines[0].contains(',') {
        count = parse_csv(header_line.as_deref(), &data_lines, &mut out)?;
    } else {
        for line in &data_lines {
            let hash = line.trim().to_ascii_lowercase();
            if is_sha256_hex(&hash) {
                writeln!(out, "{hash}\t")?;
                count += 1;
            }
        }
    }

    out.flush()?;
    drop(out);
    std::fs::rename(&tmp_path, dest)?;
    Ok(count)
}

// Confirmed live 2026-07 MalwareBazaar CSV column order, used as a fallback
// when the `#`-commented header row can't be found in the response at all.
const FALLBACK_COLUMNS: &[&str] = &[
    "first_seen_utc",
    "sha256_hash",
    "md5_hash",
    "sha1_hash",
    "reporter",
    "file_name",
    "file_type_guess",
    "mime_type",
    "signature",
    "clamav",
    "vtpercent",
    "imphash",
    "ssdeep",
    "tlsh",
];

fn parse_csv(header_line: Option<&str>, data_lines: &[&str], out: &mut impl Write) -> Result<usize> {
    let owned_columns: Vec<String>;
    let columns: Vec<&str> = match header_line {
        Some(h) => {
            owned_columns = h
                .split(',')
                .map(|c| c.trim().trim_matches('"').to_ascii_lowercase())
                .collect();
            owned_columns.iter().map(|s| s.as_str()).collect()
        }
        None => FALLBACK_COLUMNS.to_vec(),
    };

    // Try an exact match first, then fall back to "contains sha256" in case
    // abuse.ch's real column name differs from the historical "sha256_hash".
    let sha256_idx = columns
        .iter()
        .position(|h| *h == "sha256_hash")
        .or_else(|| columns.iter().position(|h| h.contains("sha256")))
        .with_context(|| {
            format!(
                "could not find a sha256 column in the MalwareBazaar CSV export; columns were: {columns:?}"
            )
        })?;
    let signature_idx = columns
        .iter()
        .position(|h| *h == "signature")
        .or_else(|| columns.iter().position(|h| h.contains("signature")));

    let joined = data_lines.join("\n");
    let mut rdr = csv::ReaderBuilder::new()
        .has_headers(false)
        .flexible(true)
        .from_reader(joined.as_bytes());

    let mut count = 0usize;
    for record in rdr.records() {
        let record = record?;
        let hash = record
            .get(sha256_idx)
            .unwrap_or("")
            .trim()
            .trim_matches('"')
            .to_ascii_lowercase();
        if !is_sha256_hex(&hash) {
            continue;
        }
        let label = signature_idx
            .and_then(|i| record.get(i))
            .unwrap_or("")
            .trim()
            .trim_matches('"');
        writeln!(out, "{hash}\t{label}")?;
        count += 1;
    }
    Ok(count)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parses_malwarebazaar_style_csv_with_commented_header() {
        // This mirrors the real live export: every preamble line, including
        // the column header row, is prefixed with `#`.
        let body = "\
# MalwareBazaar SHA256 export\n\
# generated 2026-07-15\n\
#first_seen_utc,sha256_hash,md5_hash,signature\n\
\"2026-07-01 00:00:00\",\"56aad4955d4a52b5bbe3080f2bc67a507c181ff023169587e0ad3ab4e1789408\",\"deadbeef\",\"Trojan.Test\"\n\
\"2026-07-02 00:00:00\",\"not-a-valid-hash\",\"beadfeed\",\"Ransom.Fake\"\n\
\"2026-07-03 00:00:00\",\"aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa\",\"cafebabe\",\"\"\n\
";
        let dir = std::env::temp_dir().join(format!("detection-cli-test-{}", std::process::id()));
        std::fs::create_dir_all(&dir).unwrap();
        let dest = dir.join("cache.tsv");

        let count = parse_and_write(body, &dest).unwrap();
        // the second row's hash is malformed and must be rejected
        assert_eq!(count, 2);

        let db = SignatureDb::load(&dest).unwrap();
        assert_eq!(db.len(), 2);
        assert_eq!(
            db.lookup("56aad4955d4a52b5bbe3080f2bc67a507c181ff023169587e0ad3ab4e1789408"),
            Some("Trojan.Test")
        );
        assert_eq!(
            db.lookup("aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"),
            Some("")
        );

        std::fs::remove_dir_all(&dir).ok();
    }

    #[test]
    fn falls_back_to_known_schema_when_no_header_line_present() {
        // No `#`-prefixed header row at all; must fall back to the
        // confirmed live column order (sha256_hash is column index 1,
        // signature is column index 8).
        let body = "\
\"2026-07-01 00:00:00\",\"56aad4955d4a52b5bbe3080f2bc67a507c181ff023169587e0ad3ab4e1789408\",\"md5\",\"sha1\",\"abuse_ch\",\"a.js\",\"js\",\"text/plain\",\"AsyncRAT\",\"n/a\",\"n/a\",\"n/a\",\"ssdeep\",\"tlsh\"\n\
";
        let dir = std::env::temp_dir().join(format!("detection-cli-test-fallback-{}", std::process::id()));
        std::fs::create_dir_all(&dir).unwrap();
        let dest = dir.join("cache.tsv");

        let count = parse_and_write(body, &dest).unwrap();
        assert_eq!(count, 1);

        let db = SignatureDb::load(&dest).unwrap();
        assert_eq!(
            db.lookup("56aad4955d4a52b5bbe3080f2bc67a507c181ff023169587e0ad3ab4e1789408"),
            Some("AsyncRAT")
        );

        std::fs::remove_dir_all(&dir).ok();
    }

    #[test]
    fn parses_plain_text_hash_list() {
        let body = "\
# plain hash list\n\
56aad4955d4a52b5bbe3080f2bc67a507c181ff023169587e0ad3ab4e1789408\n\
aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa\n\
not-a-hash\n\
";
        let dir = std::env::temp_dir().join(format!("detection-cli-test-txt-{}", std::process::id()));
        std::fs::create_dir_all(&dir).unwrap();
        let dest = dir.join("cache.tsv");

        let count = parse_and_write(body, &dest).unwrap();
        assert_eq!(count, 2);

        std::fs::remove_dir_all(&dir).ok();
    }
}
