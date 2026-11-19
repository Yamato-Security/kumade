// Copyright (C) 2026 Shirofune Security Co., Ltd.
// SPDX-License-Identifier: RPL-1.5
//
// Unless explicitly acquired and licensed from Licensor under another license, the contents of this
// file are subject to the Reciprocal Public License ("RPL") Version 1.5, or subsequent versions as
// allowed by the RPL, and You may not copy or use this file in either source code or executable
// form, except in compliance with the terms and conditions of the RPL.
//
// All software distributed under the RPL is provided strictly on an "AS IS" basis, WITHOUT WARRANTY
// OF ANY KIND, EITHER EXPRESS OR IMPLIED, AND LICENSOR HEREBY DISCLAIMS ALL SUCH WARRANTIES,
// INCLUDING WITHOUT LIMITATION, ANY WARRANTIES OF MERCHANTABILITY, FITNESS FOR A PARTICULAR
// PURPOSE, QUIET ENJOYMENT, OR NON-INFRINGEMENT. See the RPL for specific language governing rights
// and limitations under the RPL.

use anyhow::{Context, Result, ensure};
use clap::{Args, CommandFactory, Parser, Subcommand};
use kumade::{
    catalog::{DEFAULT_CATALOG, Rules},
    collect::{self, Options},
    discovery,
    model::{Source, SourceDiscovery},
    paths, platform, ui, verify, vhdx,
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
    /// Save evidence in a new NTFS VHDX container (Windows, administrator)
    #[arg(long, value_name = "FILE", conflicts_with = "output")]
    vhdx: Option<PathBuf>,
    /// Virtual capacity in GiB (default: automatic, dynamically allocated)
    #[arg(long, value_name = "GIB", requires = "vhdx", value_parser = clap::value_parser!(u64).range(1..=65536))]
    vhdx_size_gib: Option<u64>,
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
    /// Maximum acquisition workers (default: available logical CPUs, at most 128)
    #[arg(short = 'T', long, default_value_t = default_threads())]
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
    /// List each file being copied instead of displaying a progress bar
    #[arg(short = 'v', long, conflicts_with = "quiet")]
    verbose: bool,
}

/// One worker per logical CPU, capped: more workers than that only multiply
/// open raw-volume handles and I/O contention on an evidence disk.
pub const MAX_THREADS: usize = 128;

fn default_threads() -> usize {
    std::thread::available_parallelism()
        .map_or(1, usize::from)
        .min(MAX_THREADS)
}

fn rules(path: Option<&Path>) -> Result<Rules> {
    match path {
        Some(p) => Rules::load(
            &std::fs::read_to_string(p).context("Cannot read the explicitly selected catalog")?,
        ),
        None => Rules::load(DEFAULT_CATALOG),
    }
}

fn sources(options: &CollectionArgs) -> Result<SourceDiscovery> {
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
        let canonical = platform::canonicalize(input)?;
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
            let profile = platform::canonicalize(profile)?;
            if profile.starts_with(&source.root) {
                source.profile_roots.push(profile);
            }
        }
        source.profile_roots.sort();
        source.profile_roots.dedup();
        sources.push(source);
    }
    for profile in &options.profile_roots {
        let p = platform::canonicalize(profile)?;
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
    Ok(SourceDiscovery {
        sources,
        issues: Vec::new(),
    })
}

fn run() -> Result<u8> {
    if std::env::args_os().len() == 1 {
        ui::banner();
        Cli::command().print_help()?;
        println!();
        return Ok(0);
    }
    let cli = match Cli::try_parse() {
        Ok(cli) => cli,
        Err(error) if error.kind() == clap::error::ErrorKind::DisplayHelp => {
            ui::banner();
            error.print()?;
            return Ok(0);
        }
        Err(error) => error.exit(),
    };
    let (options, plan_only) = match cli.command {
        Some(Command::Doctor) => {
            ui::banner();
            ui::field(
                "Platform",
                format!("{} / {}", std::env::consts::OS, std::env::consts::ARCH),
            );
            ui::field(
                "Live acquisition",
                if cfg!(windows) {
                    "Available; elevated privileges required"
                } else {
                    "Use offline --source directories"
                },
            );
            ui::field("Raw NTFS acquisition", "Available");
            ui::field("RAM acquisition", "Not implemented");
            ui::field("VSS acquisition", "Not implemented");
            ui::field("Cloud transport", "Not implemented");
            ui::field(
                "VHDX output",
                if cfg!(windows) {
                    "Available; elevated Windows and Storage cmdlets required"
                } else {
                    "Requires Windows"
                },
            );
            return Ok(0);
        }
        Some(Command::List { catalog }) => {
            ui::banner();
            let rules = rules(catalog.as_deref())?;
            ui::heading(&format!(
                "{:<30} {:<24} {}",
                "Artifact", "Category", "Description"
            ));
            for artifact in rules.catalog.artifacts {
                ui::status(&format!(
                    "{:<30} {:<24} {}",
                    artifact.id, artifact.category, artifact.name
                ));
            }
            return Ok(0);
        }
        Some(Command::Verify { directory }) => {
            ui::banner();
            let (files, complete) = verify::verify(&directory)?;
            ui::field(
                "Integrity verified",
                format!("{} payloads", ui::count(files as u64)),
            );
            ui::field(
                "Acquisition completeness",
                if complete {
                    "Complete within selected prototype scope"
                } else {
                    "Partial — consult Summary.json and Errors.csv"
                },
            );
            return Ok(if complete { 0 } else { 3 });
        }
        Some(Command::Plan(options)) => (options, true),
        Some(Command::Collect(options)) => (options, false),
        None => (cli.options, false),
    };
    ensure!(
        !plan_only || options.vhdx.is_none(),
        "plan does not create containers; use -o DIR for a plan"
    );
    ensure!(
        options.vhdx.is_none() || cfg!(windows),
        "VHDX creation requires Windows"
    );
    if !options.quiet {
        ui::banner();
        ui::field("Start time", chrono::Utc::now().format("%Y-%m-%d %H:%M:%S"));
        ui::field("Timezone", "UTC");
        println!();
        ui::status("Discovering artifacts…");
    }
    ensure!(
        options.threads > 0 && options.threads <= MAX_THREADS,
        "--threads must be between 1 and {MAX_THREADS}"
    );
    let rules = rules(options.catalog.as_deref())?;
    let discovered = sources(&options)?;
    let sources = discovered.sources;
    let output = options
        .vhdx
        .clone()
        .or_else(|| options.output.clone())
        .unwrap_or_else(|| {
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
    if !options.quiet
        && sources
            .iter()
            .any(|s| s.live && output.starts_with(&s.root))
    {
        ui::field(
            "Notice",
            "The destination is on a live source volume. Output writes will change that volume; acquisition uses a frozen pre-write plan.",
        );
    }
    let mut plan = discovery::build_plan(sources, &rules, &options.artifacts, options.memory)?;
    if !options.quiet {
        for issue in &discovered.issues {
            eprintln!("Source unavailable: {} ({})", issue.path, issue.reason);
        }
    }
    plan.issues.extend(discovered.issues);
    #[cfg(windows)]
    if options.vhdx.is_some() {
        kumade::metadata::enable_privileges()?;
        kumade::metadata::augment_streams(&mut plan)?;
    }
    if !options.quiet {
        ui::field("Sources", ui::count(plan.sources.len() as u64));
        ui::field("Artifacts", ui::count(rules.catalog.artifacts.len() as u64));
        ui::field("Planned files/streams", ui::count(plan.files.len() as u64));
        ui::field("Known bytes", collect::human_bytes(plan.known_bytes));
        ui::field("Unknown sizes", ui::count(plan.unknown_sizes));
        ui::field("Discovery issues", ui::count(plan.issues.len() as u64));
        ui::field("Threads", ui::count(options.threads as u64));
    }
    if plan_only {
        std::fs::create_dir_all(&output)?;
        collect::write_json_new(&output.join("Plan.json"), &plan)?;
        ui::field("Plan saved", output.join("Plan.json").display());
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
    let collect_options = Options {
        threads: options.threads,
        reserve_bytes,
        quiet: options.quiet,
        verbose: options.verbose,
        ntfs_metadata: false,
        host_reserve: None,
    };
    let summary = if options.vhdx.is_some() {
        vhdx::collect(&plan, &output, options.vhdx_size_gib, &collect_options)?
    } else {
        collect::collect(&plan, &output, &collect_options)?.1
    };
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

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn default_workers_follow_available_cpus_and_explicit_workers_override_them() {
        let cli = Cli::try_parse_from(["kumade", "-o", "results"]).unwrap();
        assert_eq!(cli.options.threads, default_threads());
        assert!(cli.options.threads > 0 && cli.options.threads <= MAX_THREADS);
        let cli = Cli::try_parse_from(["kumade", "collect", "-T", "2"]).unwrap();
        let Some(Command::Collect(options)) = cli.command else {
            panic!("expected collect");
        };
        assert_eq!(options.threads, 2);
    }
}
