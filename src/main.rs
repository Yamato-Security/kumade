// Copyright (c) 2026 Shirofune Security Co., Ltd.
// SPDX-License-Identifier: RPL-1.5

use anyhow::{Context, Result, ensure};
use clap::{Args, Parser, Subcommand};
use kumade::{
    catalog::{DEFAULT_CATALOG, Rules},
    collect::{self, Options},
    discovery,
    model::Source,
    paths, platform, verify,
};
use std::{
    collections::HashSet,
    io::Write,
    path::{Path, PathBuf},
    process::ExitCode,
};

#[derive(Parser)]
#[command(
    name = "kumade",
    version,
    args_conflicts_with_subcommands = true,
    about = "Windows evidence collection by Yamato Security — development prototype"
)]
struct Cli {
    #[command(subcommand)]
    command: Option<Command>,
    #[command(flatten)]
    options: CollectionArgs,
}

#[derive(Subcommand)]
enum Command {
    /// Collect selected artifacts into a new, hash-verified run directory
    Collect(CollectionArgs),
    /// Inspect platform support and acquisition prerequisites
    Doctor,
    /// List the embedded or explicitly selected acquisition catalog
    List {
        #[arg(long)]
        catalog: Option<PathBuf>,
    },
    /// Discover files and write a plan without copying evidence
    Plan(CollectionArgs),
    /// Verify the seal and every stored payload; never reads original sources
    Verify { directory: PathBuf },
}

#[derive(Args, Clone)]
struct CollectionArgs {
    /// Mounted Windows volume directory; repeat for additional volumes
    #[arg(short = 'd', long = "source", value_name = "DIR")]
    sources: Vec<PathBuf>,
    /// Output parent directory; plan writes Plan.json here
    #[arg(short, long, value_name = "DIR")]
    output: Option<PathBuf>,
    /// Computer name for offline evidence
    #[arg(long)]
    computer: Option<String>,
    /// Explicit acquisition catalog; executable-directory configs are never auto-loaded
    #[arg(long)]
    catalog: Option<PathBuf>,
    /// Limit scope to an artifact ID; repeat to include several
    #[arg(long = "artifact", value_name = "ID")]
    artifacts: Vec<String>,
    /// Additional local profile root under a selected source
    #[arg(long = "profile-root", value_name = "DIR")]
    profile_roots: Vec<PathBuf>,
    /// Maximum acquisition workers
    #[arg(short = 'T', long, default_value_t = 4)]
    threads: usize,
    /// Keep this much destination space free (MiB)
    #[arg(long, default_value_t = 2048)]
    reserve_mib: u64,
    /// Request RAM; this prototype records an explicit unsupported/partial result
    #[arg(short = 'm', long)]
    memory: bool,
    /// Suppress progress and routine console messages
    #[arg(short, long)]
    quiet: bool,
}

fn rules(path: Option<&Path>) -> Result<Rules> {
    match path {
        Some(p) => Rules::load(
            &std::fs::read_to_string(p).context("Cannot read the explicitly selected catalog")?,
        ),
        None => Rules::load(DEFAULT_CATALOG),
    }
}

fn sources(options: &CollectionArgs) -> Result<Vec<Source>> {
    if options.sources.is_empty() {
        ensure!(
            options.computer.is_none(),
            "--computer applies to offline --source inputs"
        );
        return platform::live_sources();
    }
    let computer = options.computer.as_deref().unwrap_or("OfflineComputer");
    ensure!(
        !computer.is_empty() && !computer.chars().any(char::is_control),
        "Invalid computer label"
    );
    let mut sources = Vec::new();
    let mut roots = HashSet::new();
    for (i, input) in options.sources.iter().enumerate() {
        let canonical = input.canonicalize()?;
        ensure!(
            roots.insert(canonical.clone()),
            "Duplicate source directory"
        );
        let basename = input
            .file_name()
            .and_then(|s| s.to_str())
            .unwrap_or("Volume");
        let label = if basename.eq_ignore_ascii_case("C%3A") {
            "C".to_owned()
        } else {
            paths::encode_component(basename)
        };
        let mut id = label.clone();
        let mut suffix = i + 1;
        while sources.iter().any(|s: &Source| s.id == id) {
            id = format!("{label}-{suffix}");
            suffix += 1;
        }
        let mut source = discovery::directory_source(&canonical, &id, computer)?;
        for profile in &options.profile_roots {
            let profile = profile.canonicalize()?;
            if profile.starts_with(&source.root) {
                source.profile_roots.push(profile);
            }
        }
        source.profile_roots.sort();
        source.profile_roots.dedup();
        sources.push(source);
    }
    for profile in &options.profile_roots {
        let p = profile.canonicalize()?;
        ensure!(
            sources.iter().any(|s| p.starts_with(&s.root)),
            "Profile root is outside selected sources"
        );
    }
    for (i, source) in sources.iter().enumerate() {
        for other in &sources[i + 1..] {
            ensure!(
                !source.root.starts_with(&other.root) && !other.root.starts_with(&source.root),
                "Source directory trees overlap"
            );
        }
    }
    Ok(sources)
}

fn run() -> Result<u8> {
    let cli = Cli::parse();
    let (options, plan_only) = match cli.command {
        Some(Command::Doctor) => {
            println!(
                "KUMADE {}\nPlatform: {} / {}\nLive acquisition: {}\nRaw NTFS library: Available\nRAM acquisition: Not implemented\nVSS acquisition: Not implemented\nCloud transport: Not implemented",
                env!("CARGO_PKG_VERSION"),
                std::env::consts::OS,
                std::env::consts::ARCH,
                if cfg!(windows) {
                    "Windows APIs compiled; elevated operation required"
                } else {
                    "Use offline --source directories"
                }
            );
            return Ok(0);
        }
        Some(Command::List { catalog }) => {
            let rules = rules(catalog.as_deref())?;
            for artifact in rules.catalog.artifacts {
                println!(
                    "{:<30} {:<24} {}",
                    artifact.id, artifact.category, artifact.name
                );
            }
            return Ok(0);
        }
        Some(Command::Verify { directory }) => {
            let (files, complete) = verify::verify(&directory)?;
            println!(
                "Integrity verified: {files} payloads\nAcquisition completeness: {}",
                if complete {
                    "Complete within selected prototype scope"
                } else {
                    "Partial — consult Summary.json and Errors.csv"
                }
            );
            return Ok(if complete { 0 } else { 3 });
        }
        Some(Command::Plan(options)) => (options, true),
        Some(Command::Collect(options)) => (options, false),
        None => (cli.options, false),
    };
    ensure!(
        options.threads > 0 && options.threads <= 128,
        "--threads must be between 1 and 128"
    );
    let rules = rules(options.catalog.as_deref())?;
    let sources = sources(&options)?;
    let output = options.output.clone().unwrap_or_else(|| {
        std::env::current_exe()
            .ok()
            .and_then(|p| p.parent().map(|p| p.join("Kumade-Results")))
            .unwrap_or_else(|| PathBuf::from("Kumade-Results"))
    });
    let output = paths::resolve_future(&output)?;
    for source in &sources {
        ensure!(
            source.live || (!output.starts_with(&source.root) && !source.root.starts_with(&output)),
            "Source and output directory trees must not overlap"
        );
    }
    if !options.quiet {
        if sources
            .iter()
            .any(|s| s.live && output.starts_with(&s.root))
        {
            eprintln!(
                "Notice: the destination is on a live source volume. Output writes will change that volume; acquisition uses a frozen pre-write plan."
            );
        }
        println!(
            "KUMADE — Windows Evidence Collection\nYamato Security / {}\nTimezone: UTC\nDiscovering artifacts…",
            env!("CARGO_PKG_VERSION")
        );
    }
    let plan = discovery::build_plan(sources, &rules, &options.artifacts, options.memory)?;
    if !options.quiet {
        println!(
            "Sources: {}\nArtifacts: {}\nPlanned files/streams: {}\nKnown bytes: {}\nUnknown sizes: {}\nDiscovery issues: {}",
            plan.sources.len(),
            rules.catalog.artifacts.len(),
            plan.files.len(),
            collect::human_bytes(plan.known_bytes),
            plan.unknown_sizes,
            plan.issues.len()
        );
    }
    if plan_only {
        std::fs::create_dir_all(&output)?;
        collect::write_json_new(&output.join("Plan.json"), &plan)?;
        println!("Plan saved: {}", output.join("Plan.json").display());
        return Ok(
            if plan
                .issues
                .iter()
                .any(|i| i.status == "Failed" || i.status == "Unsupported")
            {
                3
            } else {
                0
            },
        );
    }
    let reserve_bytes = options
        .reserve_mib
        .checked_mul(1024 * 1024)
        .context("Reserve value overflow")?;
    let (_, summary) = collect::collect(
        &plan,
        &output,
        &Options {
            threads: options.threads,
            reserve_bytes,
            quiet: options.quiet,
        },
    )?;
    Ok(if summary.completeness == "Partial" {
        3
    } else {
        0
    })
}

fn main() -> ExitCode {
    match run() {
        Ok(code) => ExitCode::from(code),
        Err(error) => {
            let _ = writeln!(std::io::stderr(), "Error: {error:#}");
            ExitCode::from(2)
        }
    }
}
