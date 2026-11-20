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
    discovery, e01,
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
    /// Capture live Windows response inventory without copying forensic artifacts
    LiveInfo(LiveInfoArgs),
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
    /// Save to an NTFS VHDX; a directory uses the hostname and UTC start time
    #[arg(long, value_name = "FILE_OR_DIR", num_args = 0..=1, default_missing_value = ".", conflicts_with = "output")]
    vhdx: Option<PathBuf>,
    /// Virtual capacity in GiB (default: automatic, dynamically allocated)
    #[arg(long, value_name = "GIB", requires = "vhdx", value_parser = clap::value_parser!(u64).range(1..=65536))]
    vhdx_size_gib: Option<u64>,
    /// Save to compressed E01 segments; a directory uses the hostname and UTC start time
    #[arg(long, value_name = "FILE_OR_DIR", num_args = 0..=1, default_missing_value = ".", conflicts_with_all = ["output", "vhdx"])]
    e01: Option<PathBuf>,
    /// NTFS capacity in GiB before E01 compression (default: automatic)
    #[arg(long, value_name = "GIB", requires = "e01", value_parser = clap::value_parser!(u64).range(1..=65536))]
    e01_size_gib: Option<u64>,
    /// Skip the automatic live-response inventory (offline sources always skip it)
    #[arg(long)]
    no_live_info: bool,
    /// Live-response inventory output format
    #[arg(long, value_enum, default_value = "csv")]
    live_info_format: kumade::live_info::Format,
    /// Per-provider live-response deadline in seconds
    #[arg(long,default_value_t=90,value_parser=clap::value_parser!(u64).range(1..=3600))]
    live_info_timeout: u64,
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

#[derive(Args)]
struct LiveInfoArgs {
    /// New output directory (existing directories are refused)
    #[arg(short, long, value_name = "DIR", required_unless_present = "list")]
    output: Option<PathBuf>,
    /// List the embedded inventory data sets without querying the system
    #[arg(long)]
    list: bool,
    /// Output format
    #[arg(short = 't', long = "format", value_enum, default_value = "csv")]
    format: kumade::live_info::Format,
    /// Select a named data set; repeat (default: all)
    #[arg(long = "dataset", value_name = "NAME")]
    datasets: Vec<String>,
    /// Concurrent PowerShell queries
    #[arg(short='T',long,default_value_t=2,value_parser=clap::value_parser!(u64).range(1..=8))]
    threads: u64,
    /// Deadline for each query in seconds
    #[arg(long,default_value_t=90,value_parser=clap::value_parser!(u64).range(1..=3600))]
    timeout: u64,
    /// Suppress progress
    #[arg(short, long)]
    quiet: bool,
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
        let label = if basename.len() == 4
            && basename.as_bytes()[0].is_ascii_alphabetic()
            && basename[1..].eq_ignore_ascii_case("%3A")
        {
            basename[..1].to_ascii_uppercase()
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
    let started_utc = kumade::model::utc_now();
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
        Some(Command::LiveInfo(args)) => {
            if args.list {
                ui::banner();
                for dataset in kumade::live_info::datasets() {
                    ui::status(&format!(
                        "{:<28} {} fields",
                        dataset.name,
                        dataset.fields.len()
                    ));
                }
                return Ok(0);
            }
            ensure!(cfg!(windows), "Live response inventory requires Windows");
            // Reject unknown names before the output directory exists.
            kumade::live_info::select(&args.datasets)?;
            let output =
                paths::resolve_future(args.output.as_deref().context("Missing output directory")?)?;
            if let Some(parent) = output.parent() {
                std::fs::create_dir_all(parent)?;
            }
            std::fs::create_dir(&output).context("Live-info output must be a new directory")?;
            platform::protect_output_root(&output)?;
            if !args.quiet {
                ui::banner();
                ui::field("Start time", kumade::model::utc_now());
            }
            let info = kumade::live_info::collect_into(
                &output,
                &kumade::live_info::Options {
                    format: args.format,
                    threads: args.threads as usize,
                    timeout_seconds: args.timeout,
                    quiet: args.quiet,
                    selected: args.datasets,
                    ..Default::default()
                },
            )?;
            if !args.quiet {
                ui::field("Datasets", info.entries.len());
                ui::field("Failed/partial providers", info.failures());
                ui::field("Results saved", output.display());
            }
            return Ok(if info.failures() > 0 { 3 } else { 0 });
        }
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
            ui::field(
                "E01 output",
                if cfg!(windows) {
                    "Available; NTFS staging, native compression and hash verification"
                } else {
                    "Collection requires Windows"
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
        !plan_only || (options.vhdx.is_none() && options.e01.is_none()),
        "plan does not create containers; use -o DIR for a plan"
    );
    ensure!(
        options.vhdx.is_none() || cfg!(windows),
        "VHDX creation requires Windows"
    );
    ensure!(
        options.e01.is_none() || cfg!(windows),
        "E01 collection requires Windows"
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
        .or_else(|| options.e01.clone())
        .or_else(|| options.output.clone())
        .unwrap_or_else(|| {
            std::env::current_exe()
                .ok()
                .and_then(|p| p.parent().map(|p| p.join("Kumade-Results")))
                .unwrap_or_else(|| PathBuf::from("Kumade-Results"))
        });
    let output = if options.vhdx.is_some() || options.e01.is_some() {
        let computer = sources
            .first()
            .map(|s| s.computer.as_str())
            .unwrap_or("UnknownComputer");
        paths::image_destination(
            &output,
            &paths::run_name(computer, &started_utc)?,
            if options.vhdx.is_some() {
                "vhdx"
            } else {
                "E01"
            },
        )?
    } else {
        output
    };
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
    plan.created_utc = started_utc;
    if !options.quiet {
        for issue in &discovered.issues {
            eprintln!("Source unavailable: {} ({})", issue.path, issue.reason);
        }
    }
    plan.issues.extend(discovered.issues);
    #[cfg(windows)]
    if options.vhdx.is_some() || options.e01.is_some() {
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
        live_info: if options.sources.is_empty() && !options.no_live_info {
            Some(kumade::live_info::Options {
                format: options.live_info_format,
                timeout_seconds: options.live_info_timeout,
                threads: options.threads.min(2),
                reserve_bytes,
                quiet: options.quiet,
                ..Default::default()
            })
        } else {
            None
        },
    };
    let summary = if options.e01.is_some() {
        e01::collect(&plan, &output, options.e01_size_gib, &collect_options)?
    } else if options.vhdx.is_some() {
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

    #[test]
    fn containers_accept_automatic_names_and_destination_directories() {
        let cli = Cli::try_parse_from(["kumade", "--vhdx"]).unwrap();
        assert_eq!(cli.options.vhdx.as_deref(), Some(Path::new(".")));
        let cli = Cli::try_parse_from(["kumade", "--e01", "output"]).unwrap();
        assert_eq!(cli.options.e01.as_deref(), Some(Path::new("output")));
        let cli = Cli::try_parse_from(["kumade", "--vhdx", "--vhdx-size-gib", "4"]).unwrap();
        assert_eq!(cli.options.vhdx_size_gib, Some(4));
    }
}
