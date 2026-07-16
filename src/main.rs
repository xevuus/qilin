mod db;
mod scan;

use anyhow::{bail, Result};
use clap::{Parser, Subcommand, ValueEnum};
use db::{Dataset, ExportFormat, SignatureDb};
use std::path::PathBuf;

#[derive(Parser)]
#[command(name = "detection-cli", version, about = "A minimal file-hash malware scanner")]
struct Cli {
    #[command(subcommand)]
    command: Command,
}

#[derive(Subcommand)]
enum Command {
    /// Scan a file or directory against the local signature database.
    /// Omit PATH to scan the entire filesystem.
    Scan {
        path: Option<PathBuf>,
        /// Signature database path (defaults to the OS cache dir)
        #[arg(long)]
        db: Option<PathBuf>,
        /// Print every file as it's scanned, not just detections
        #[arg(short, long)]
        verbose: bool,
        /// Skip a path entirely (repeatable). Always applied on top of the
        /// default /proc, /sys, /dev, /run exclusions on Unix.
        #[arg(long)]
        exclude: Vec<PathBuf>,
    },
    /// Download and cache the MalwareBazaar hash export
    Update {
        /// abuse.ch Auth-Key (register at https://auth.abuse.ch/)
        #[arg(long, env = "MB_AUTH_KEY")]
        auth_key: String,
        /// Signature database path (defaults to the OS cache dir)
        #[arg(long)]
        db: Option<PathBuf>,
        /// Pull the full hash dump instead of the last-48h "recent" export
        #[arg(long)]
        full: bool,
        #[arg(long, value_enum, default_value_t = FormatArg::Csv)]
        format: FormatArg,
    },
}

#[derive(ValueEnum, Clone, Copy)]
enum FormatArg {
    Csv,
    Txt,
}

fn main() -> Result<()> {
    let cli = Cli::parse();
    match cli.command {
        Command::Scan { path, db, verbose, exclude } => cmd_scan(path, db, verbose, exclude),
        Command::Update { auth_key, db, full, format } => cmd_update(auth_key, db, full, format),
    }
}

/// Where to scan when the user doesn't name a path: everywhere.
#[cfg(unix)]
fn whole_system_path() -> PathBuf {
    PathBuf::from("/")
}
#[cfg(not(unix))]
fn whole_system_path() -> PathBuf {
    PathBuf::from(std::env::var("SystemDrive").unwrap_or_else(|_| "C:".to_string()) + "\\")
}

fn resolve_db_path(db: Option<PathBuf>) -> Result<PathBuf> {
    match db {
        Some(p) => Ok(p),
        None => SignatureDb::default_path(),
    }
}

fn cmd_update(auth_key: String, db: Option<PathBuf>, full: bool, format: FormatArg) -> Result<()> {
    let dest = resolve_db_path(db)?;
    let dataset = if full { Dataset::Full } else { Dataset::Recent };
    let export_format = match format {
        FormatArg::Csv => ExportFormat::Csv,
        FormatArg::Txt => ExportFormat::Txt,
    };

    println!(
        "Fetching MalwareBazaar {} hash export ({})...",
        dataset.as_str(),
        export_format.as_str(),
    );

    let count = SignatureDb::update(&dest, &auth_key, dataset, export_format)?;
    println!("Cached {count} hashes to {}", dest.display());
    Ok(())
}

fn cmd_scan(path: Option<PathBuf>, db: Option<PathBuf>, verbose: bool, exclude: Vec<PathBuf>) -> Result<()> {
    let db_path = resolve_db_path(db)?;
    if !db_path.exists() {
        bail!(
            "no signature database found at {}\nrun `detection-cli update --auth-key <KEY>` first",
            db_path.display()
        );
    }
    let signatures = SignatureDb::load(&db_path)?;

    let path = match path {
        Some(p) => p,
        None => {
            let whole = whole_system_path();
            println!(
                "No path given — scanning the entire filesystem from {} (this may take a while)",
                whole.display()
            );
            whole
        }
    };

    println!(
        "Scanning {} ({} signatures loaded)",
        path.display(),
        signatures.len()
    );
    // Rust's stdout is block-buffered when not a TTY (e.g. piped/redirected),
    // so without an explicit flush this "scan started" line wouldn't show up
    // until the whole scan finished, making a long scan look hung.
    {
        use std::io::Write;
        std::io::stdout().flush().ok();
    }

    let report = scan::scan_path(&path, &signatures, &exclude, |p| {
        if verbose {
            println!("  scanning {}", p.display());
        }
    })?;

    for m in &report.matches {
        let label = if m.label.is_empty() { "unknown" } else { &m.label };
        println!(
            "[INFECTED] {}  sha256={}  signature={}",
            m.path.display(),
            m.sha256,
            label
        );
    }

    println!(
        "\nScan complete: {} file(s) scanned, {} error(s), {} threat(s) detected in {:.2}s",
        report.files_scanned,
        report.files_errored,
        report.matches.len(),
        report.elapsed.as_secs_f64()
    );
    if report.files_errored > 0 {
        eprintln!(
            "note: {} file(s) could not be read (permissions, etc.) — re-run with sudo for full coverage",
            report.files_errored
        );
    }

    // std::process::exit skips flushing Rust's buffered stdout (it's only
    // line-buffered on a TTY; a redirected/piped stdout is block-buffered),
    // so results could be silently truncated if we didn't flush explicitly.
    use std::io::Write;
    std::io::stdout().flush().ok();

    if !report.matches.is_empty() {
        std::process::exit(1);
    }

    Ok(())
}
