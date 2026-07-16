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
    /// Scan a file or directory against the local signature database
    Scan {
        path: PathBuf,
        /// Signature database path (defaults to the OS cache dir)
        #[arg(long)]
        db: Option<PathBuf>,
        /// Print every file as it's scanned, not just detections
        #[arg(short, long)]
        verbose: bool,
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
        Command::Scan { path, db, verbose } => cmd_scan(path, db, verbose),
        Command::Update { auth_key, db, full, format } => cmd_update(auth_key, db, full, format),
    }
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

fn cmd_scan(path: PathBuf, db: Option<PathBuf>, verbose: bool) -> Result<()> {
    let db_path = resolve_db_path(db)?;
    if !db_path.exists() {
        bail!(
            "no signature database found at {}\nrun `detection-cli update --auth-key <KEY>` first",
            db_path.display()
        );
    }
    let signatures = SignatureDb::load(&db_path)?;
    println!(
        "Scanning {} ({} signatures loaded)",
        path.display(),
        signatures.len()
    );

    let report = scan::scan_path(&path, &signatures, |p| {
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

    if !report.matches.is_empty() {
        std::process::exit(1);
    }

    Ok(())
}
