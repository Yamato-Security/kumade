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
    io::{IsTerminal, Write},
    path::{Path, PathBuf},
    process::ExitCode,
};

#[derive(Parser)]
#[command(
    name = "kumade",
    version,
    args_conflicts_with_subcommands = true,
    help_template = "{about}\n\n{usage-heading} {usage}\n\nCommands:\n{subcommands}\n\nRun `kumade <COMMAND> -h` for its options.",
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
    Doctor {
        /// Check platform support and collection prerequisites
        #[arg(long)]
        check: bool,
    },
    /// Image a logical partition to a raw file on a different external drive
    ForensicCopy(ForensicCopyArgs),
    /// Capture live Windows response inventory without copying forensic artifacts
    LiveInfo(LiveInfoArgs),
    /// List the embedded or explicitly selected acquisition catalog
    List {
        /// Show the embedded acquisition catalog
        #[arg(long, conflicts_with = "catalog")]
        builtin: bool,
        #[arg(long)]
        catalog: Option<PathBuf>,
    },
    /// List existing local Volume Shadow Copies without creating or deleting them
    ListVss(kumade::vss_history::ListOptions),
    /// Download or update a compressed YARA Forge rule package
    UpdateRules(kumade::yara_rules::UpdateOptions),
    /// Discover files and write a plan without copying evidence
    Plan(CollectionArgs),
    /// Receive evidence through a temporary upload-only SFTP account
    Receive(kumade::sftp_receive::Options),
    /// Resume phased S3 uploads from a protected workspace without reading original sources
    ResumeS3(kumade::s3_phases::ResumeArgs),
    /// Verify an SFTP delivery locally and optionally reconstruct files
    VerifyDelivery(kumade::sftp_verify::Options),
    /// Verify an S3 collection against its delivery hash and optionally restore it
    VerifyS3(kumade::s3::VerifyArgs),
    /// Scan running Windows processes with YARA Forge or local YARA rules
    ScanProcesses(kumade::yara_scan::Options),
    /// Verify the seal and every stored payload; never reads original sources
    Verify { directory: PathBuf },
}

#[derive(Args, Clone)]
struct CollectionArgs {
    /// Accept collection defaults without interactive prompts (for scripts)
    #[arg(long, alias = "no-wizard", conflicts_with = "wizard")]
    yes: bool,
    /// Force the collection wizard, including when answers are piped
    #[arg(long, conflicts_with = "quiet")]
    wizard: bool,
    /// Include paging, swap, hibernation and existing memory dumps (default: off)
    #[arg(long)]
    paging: bool,
    /// Include hiberfil.sys without other paging/dump files (default: off)
    #[arg(long)]
    hibernation: bool,
    /// Scan live process memory after hot disk artifacts (default: off)
    #[arg(long, conflicts_with = "sources")]
    scan_processes: bool,
    /// YARA Forge package (bundled selection by default, otherwise core)
    #[arg(
        long,
        value_enum,
        requires = "scan_processes",
        conflicts_with = "yara_rules"
    )]
    yara_ruleset: Option<kumade::yara_scan::RuleSet>,
    /// Use a local Forge ZIP or YARA source for the process scan
    #[arg(long, requires = "scan_processes")]
    yara_rules: Option<PathBuf>,
    /// YARA Forge release for the process scan (default: latest)
    #[arg(long, requires = "scan_processes", conflicts_with = "yara_rules")]
    yara_release: Option<String>,
    /// Mounted Windows volume directory; repeat for additional volumes
    #[arg(short = 'd', long = "source", value_name = "DIR")]
    sources: Vec<PathBuf>,
    /// Select a live volume such as C:; repeat (default: all discovered fixed volumes)
    #[arg(long = "volume", value_name = "VOLUME", conflicts_with = "sources")]
    volumes: Vec<String>,
    /// Acquire live files from owned, crash-consistent VSS snapshots
    #[arg(long, conflicts_with = "sources")]
    vss: bool,
    /// Also collect existing snapshots: all, newest, newest N per volume, or a GUID
    #[arg(long, num_args = 0..=1, default_missing_value = "all", value_name = "SELECTION", conflicts_with = "sources")]
    vss_existing: Option<kumade::vss_history::Selection>,
    /// VSS snapshot creation deadline in seconds
    #[arg(long, value_name = "SECONDS", requires = "vss", value_parser = clap::value_parser!(u64).range(1..=3600))]
    vss_timeout: Option<u64>,
    /// Output parent directory; plan writes Plan.json here
    #[arg(short, long, value_name = "DIR")]
    output: Option<PathBuf>,
    /// Save to an NTFS VHDX; a directory (or no value: Kumade-Results beside the executable) names it by hostname and UTC start time
    #[arg(long, value_name = "FILE_OR_DIR", conflicts_with = "output")]
    vhdx: Option<Option<PathBuf>>,
    /// Virtual capacity in GiB (default: automatic, dynamically allocated)
    #[arg(long, value_name = "GIB", requires = "vhdx", value_parser = clap::value_parser!(u64).range(1..=65536))]
    vhdx_size_gib: Option<u64>,
    /// Save to compressed E01 segments; a directory (or no value: Kumade-Results beside the executable) names them by hostname and UTC start time
    #[arg(long, value_name = "FILE_OR_DIR", conflicts_with_all = ["output", "vhdx"])]
    e01: Option<Option<PathBuf>>,
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
    /// Maximum acquisition workers (default: available logical CPUs, at most 4)
    #[arg(short = 'T', long, default_value_t = default_threads())]
    threads: usize,
    /// Keep this much destination space free (MiB)
    #[arg(long, default_value_t = 2048)]
    reserve_mib: u64,
    /// Acquire physical RAM first with a separately supplied DumpIt toolkit
    #[arg(short = 'm', long)]
    memory: bool,
    #[command(flatten)]
    memory_options: kumade::memory::Args,
    /// Suppress progress and routine console messages
    #[arg(short, long)]
    quiet: bool,
    #[command(flatten)]
    entropy: kumade::entropy::EntropyArgs,
    #[command(flatten)]
    sftp: kumade::sftp::Args,
    #[command(flatten)]
    s3: kumade::s3::S3Args,
    /// List each file being copied instead of displaying a progress bar
    #[arg(short = 'v', long, conflicts_with = "quiet")]
    verbose: bool,
}

#[derive(Args)]
struct ForensicCopyArgs {
    /// Logical volume to read, for example C: or a volume GUID
    #[arg(short = 's', long, value_name = "VOLUME")]
    source: String,
    /// Destination directory on a different external physical drive
    #[arg(short, long, value_name = "DIR")]
    output: PathBuf,
    /// Read from an owned, crash-consistent VSS snapshot
    #[arg(long)]
    vss: bool,
    /// VSS snapshot creation deadline in seconds
    #[arg(long, requires = "vss", value_parser = clap::value_parser!(u64).range(1..=3600))]
    vss_timeout: Option<u64>,
    /// Keep this much destination space free (MiB)
    #[arg(long, default_value_t = 2048)]
    reserve_mib: u64,
    /// Suppress progress and routine console messages
    #[arg(short, long)]
    quiet: bool,
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

/// A conservative live-triage default; operators can explicitly request up to
/// MAX_THREADS for faster storage or CPU-heavy encoding.
pub const MAX_THREADS: usize = 128;

fn default_threads() -> usize {
    std::thread::available_parallelism()
        .map_or(1, usize::from)
        .min(4)
}

/// `-o` and a bare `--vhdx`/`--e01` share this default. The shell's current
/// directory is never used: an elevated prompt starts in C:\Windows\System32,
/// on the very volume being acquired.
fn default_results_dir() -> PathBuf {
    std::env::current_exe()
        .ok()
        .and_then(|p| p.parent().map(|p| p.join("Kumade-Results")))
        .unwrap_or_else(|| PathBuf::from("Kumade-Results"))
}

fn rules(path: Option<&Path>) -> Result<Rules> {
    match path {
        Some(p) => Rules::load(
            &std::fs::read_to_string(p).context("Cannot read the explicitly selected catalog")?,
        ),
        None => Rules::load(DEFAULT_CATALOG),
    }
}

impl CollectionArgs {
    fn remote(&self) -> bool {
        self.sftp.sftp.is_some() || self.s3.s3.is_some()
    }
}

fn sources(options: &CollectionArgs, destination: &Path) -> Result<SourceDiscovery> {
    if options.sources.is_empty() {
        ensure!(
            options.computer.is_none(),
            "--computer applies to offline --source inputs"
        );
        return platform::live_sources(if options.remote() && !options.s3.phased() {
            None
        } else {
            Some(destination)
        });
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
        // Collection metadata (Plan.json, LiveInfo, ...) sits beside the drive
        // directories, so a source directory may not take one of those names.
        while paths::is_run_root_name(&id) || sources.iter().any(|s: &Source| s.id == id) {
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
    let mut args: Vec<_> = std::env::args_os().collect();
    // Ignore a trailing option terminator when deciding whether a command is bare.
    let supplied = match args.as_slice() {
        [_, supplied @ .., end] if end == "--" => supplied,
        [_, supplied @ ..] => supplied,
        [] => &[],
    };
    let show_help = match supplied {
        [] => true,
        [command] => command
            .to_str()
            .is_some_and(|name| Cli::command().find_subcommand(name).is_some()),
        _ => false,
    };
    if show_help {
        args.truncate(1 + supplied.len());
        args.push("-h".into());
    }
    let cli = match Cli::try_parse_from(args) {
        Ok(cli) => cli,
        Err(error) if error.kind() == clap::error::ErrorKind::DisplayHelp => {
            ui::banner();
            error.print()?;
            return Ok(0);
        }
        Err(error) => error.exit(),
    };
    let (mut options, plan_only) = match cli.command {
        Some(Command::Receive(args)) => return kumade::sftp_receive::run(&args),
        Some(Command::ResumeS3(args)) => return kumade::s3_phases::resume(&args),
        Some(Command::VerifyS3(args)) => return kumade::s3::verify(&args),
        Some(Command::VerifyDelivery(args)) => return kumade::sftp_verify::run(&args),
        Some(Command::ScanProcesses(args)) => return kumade::yara_scan::run(&args),
        Some(Command::ForensicCopy(args)) => {
            kumade::forensic_copy::run(&kumade::forensic_copy::Options {
                source: args.source,
                output: args.output,
                reserve_mib: args.reserve_mib,
                quiet: args.quiet,
                vss: args.vss,
                vss_timeout: args.vss_timeout.unwrap_or(120),
            })?;
            return Ok(0);
        }
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
        Some(Command::Doctor { .. }) => {
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
            ui::field(
                "Bundled YARA Forge",
                kumade::yara_rules::bundle_description(),
            );
            ui::field(
                "Partition imaging",
                if cfg!(windows) {
                    "forensic-copy; external destination and elevation required"
                } else {
                    "Requires Windows"
                },
            );
            ui::field(
                "RAM acquisition",
                "External DumpIt (--memory; toolkit required)",
            );
            ui::field(
                "VSS acquisition",
                "--vss; native elevated Windows, crash-consistent snapshots without application writers",
            );
            ui::field(
                "Remote transport",
                "--sftp (pinned host key) or --s3 (temporary upload credentials)",
            );
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
        Some(Command::List { catalog, .. }) => {
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
        Some(Command::UpdateRules(options)) => return kumade::yara_rules::update(&options),
        Some(Command::ListVss(options)) => return kumade::vss_history::run(&options),
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
    options.sftp.validate()?;
    ensure!(
        !plan_only || !options.remote(),
        "Remote uploads are a collect destination; plan uses -o DIR"
    );
    ensure!(
        !plan_only || !options.vss,
        "plan does not create VSS snapshots; use collect --vss"
    );
    if options.vss || options.vss_existing.is_some() {
        kumade::vss::check_host()?;
    }
    ensure!(
        options.volumes.is_empty() || cfg!(windows),
        "--volume requires Windows live acquisition"
    );
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
    // The destination is resolved before discovery so that live discovery can
    // leave the volume holding it out of scope.
    let destination = if options.s3.s3.is_some() {
        options
            .s3
            .staging_parent(options.memory_options.memory_staging_dir.as_deref())?
    } else if options.sftp.sftp.is_some() {
        options
            .sftp
            .sftp_staging_dir
            .clone()
            .unwrap_or_else(std::env::temp_dir)
    } else {
        options
            .vhdx
            .clone()
            .or_else(|| options.e01.clone())
            .unwrap_or_else(|| options.output.clone())
            .unwrap_or_else(default_results_dir)
    };
    let destination = paths::resolve_future(&destination)?;
    let mut discovered = sources(&options, &destination)?;
    kumade::vss::select_sources(&mut discovered, &options.volumes)?;
    // Fix the historical selection before creating any new snapshot set. Existing
    // snapshots are read-only sources; no cleanup session ever takes their IDs.
    let mut history = if let Some(selection) = &options.vss_existing {
        let result = kumade::vss_history::prepare(&discovered.sources, selection)?;
        if !options.quiet {
            ui::field("Existing VSS snapshots", result.sources.len());
            ui::field(
                "Historical evidence",
                "Kept separately; identical versions are not omitted",
            );
        }
        result
    } else {
        SourceDiscovery::default()
    };
    discovered.issues.append(&mut history.issues);
    ensure!(
        !plan_only || !options.wizard,
        "The collection wizard is not used with plan"
    );
    ensure!(
        !options.scan_processes || cfg!(windows),
        "Process-memory YARA scanning requires Windows"
    );
    if options.scan_processes {
        kumade::yara_scan::check_host()?;
    }
    let interactive = !plan_only
        && !options.yes
        && !options.quiet
        && (options.wizard || (std::io::stdin().is_terminal() && std::io::stdout().is_terminal()));
    let mut defaults =
        kumade::wizard::default_artifacts(&rules, &options.artifacts, options.paging);
    if options.hibernation {
        ensure!(
            rules
                .catalog
                .artifacts
                .iter()
                .any(|d| d.id == "windows.hibernation"),
            "--hibernation requires the windows.hibernation family in the selected catalog"
        );
        if !defaults.iter().any(|id| id == "windows.hibernation") {
            defaults.push("windows.hibernation".into());
        }
    }
    let mut selected = defaults.clone();
    if interactive {
        if !options.quiet {
            ui::status("Estimating transfer sizes from file and NTFS metadata…");
        }
        // An open scope is sized over the whole catalog so every group has an
        // estimate; an explicit scope is sized after optional family flags have been applied.
        let preflight_ids: &[String] = if options.artifacts.is_empty() {
            &[]
        } else {
            &defaults
        };
        let preflight = discovery::build_plan(
            discovered
                .sources
                .iter()
                .chain(&history.sources)
                .cloned()
                .collect(),
            &rules,
            preflight_ids,
            options.memory,
        )?;
        let sizes = kumade::wizard::Sizes::discover(&preflight);
        let choices = kumade::wizard::Choices {
            memory: options.memory,
            memory_bytes: kumade::memory::physical_bytes().ok(),
            artifacts: defaults,
            restrict_artifacts: !options.artifacts.is_empty(),
            live_info: !options.no_live_info,
            vss: options.vss,
            entropy: options.entropy.high_entropy,
            yara: options.scan_processes,
            local_yara: options.yara_rules.is_some(),
            vss_available: options.sources.is_empty()
                && cfg!(windows)
                && kumade::vss::check_host().is_ok(),
            yara_available: options.sources.is_empty()
                && cfg!(windows)
                && kumade::yara_scan::check_host().is_ok(),
            yara_ruleset: options.yara_ruleset.unwrap_or_default(),
            output: if options.s3.s3.is_some() {
                kumade::wizard::Output::S3
            } else if options.sftp.sftp.is_some() {
                kumade::wizard::Output::Sftp
            } else if options.e01.is_some() {
                kumade::wizard::Output::E01
            } else if options.vhdx.is_some() {
                kumade::wizard::Output::Vhdx
            } else {
                kumade::wizard::Output::Directory
            },
            output_explicit: options.remote() || options.e01.is_some() || options.vhdx.is_some(),
            threads: options.threads,
            image_source: None,
        };
        let live = options.sources.is_empty();
        let choices = kumade::wizard::run(
            &mut kumade::wizard::Prompt::new(std::io::stdin().lock(), std::io::stdout().lock()),
            &preflight,
            &rules,
            &sizes,
            choices,
            cfg!(windows),
            live,
        )?;
        if let Some(index) = choices.image_source {
            let source = preflight
                .sources
                .get(index)
                .context("Selected partition source is unavailable")?;
            let volume = source
                .raw_device
                .as_ref()
                .map(|p| p.to_string_lossy().into_owned())
                .unwrap_or_else(|| {
                    if source.id.len() == 1 && source.id.as_bytes()[0].is_ascii_alphabetic() {
                        format!("{}:", source.id)
                    } else {
                        source.root.to_string_lossy().into_owned()
                    }
                });
            kumade::forensic_copy::run(&kumade::forensic_copy::Options {
                source: volume,
                output: destination.join("DiskImages"),
                reserve_mib: options.reserve_mib,
                quiet: options.quiet,
                vss: choices.vss,
                vss_timeout: options.vss_timeout.unwrap_or(120),
            })?;
            return Ok(0);
        }
        options.memory = choices.memory;
        selected = choices.artifacts;
        options.no_live_info = !choices.live_info;
        options.vss = choices.vss;
        options.entropy.high_entropy = choices.entropy;
        options.scan_processes = choices.yara;
        options.yara_ruleset = Some(choices.yara_ruleset);
        options.threads = choices.threads;
        if !options.remote() && options.e01.is_none() && options.vhdx.is_none() {
            match choices.output {
                kumade::wizard::Output::Directory
                | kumade::wizard::Output::Sftp
                | kumade::wizard::Output::S3 => {}
                kumade::wizard::Output::Vhdx => {
                    options.output = None;
                    options.vhdx = Some(Some(destination.clone()));
                }
                kumade::wizard::Output::E01 => {
                    options.output = None;
                    options.e01 = Some(Some(destination.clone()));
                }
            }
        }
    }
    ensure!(
        plan_only
            || !selected.is_empty()
            || options.entropy.high_entropy
            || options.scan_processes
            || options.memory
            || (options.sources.is_empty() && !options.no_live_info),
        "Nothing selected for collection; use --hibernation, --paging or --artifact to select evidence"
    );
    ensure!(
        !options.memory
            || !options.sources.is_empty()
            || !options.remote()
            || options.s3.phased()
            || options.memory_options.memory_staging_dir.is_some()
            || plan_only,
        "DumpIt needs a staged RAM file for remote delivery; specify --memory-staging-dir <external-directory>"
    );
    // Authenticate and verify the upload-only policy before collecting evidence.
    let mut phases = if options.s3.phased() {
        Some(kumade::s3_phases::Run::start(
            &options.s3,
            &destination,
            &discovered.sources,
            &started_utc,
        )?)
    } else {
        None
    };
    let mut s3_delivery = None;
    let remote = if phases.is_some() {
        None
    } else if options.s3.s3.is_some() {
        let computer = discovered
            .sources
            .first()
            .map(|s| s.computer.as_str())
            .unwrap_or("UnknownComputer");
        let (target, uri) = kumade::s3::connect(&options.s3, computer, &started_utc)?;
        ui::field("S3 delivery URI", &uri);
        s3_delivery = Some(uri);
        Some(target)
    } else if options.sftp.sftp.is_some() {
        let password = options.sftp.password()?;
        if !options.quiet {
            ui::status("Verifying the pinned SFTP server and upload-only protections…");
        }
        Some(kumade::sftp::Target::connect(&options.sftp, password)?)
    } else {
        None
    };
    let mut staging = if remote.is_some() {
        Some(kumade::sftp::Staging::new(&destination)?)
    } else {
        None
    };
    let destination = phases
        .as_ref()
        .map_or(destination, |p| p.workspace().to_owned());
    let destination = staging
        .as_ref()
        .map_or(destination, |s| s.path().to_owned());
    if remote.is_some() && !options.quiet {
        ui::field(
            "Delivery",
            if s3_delivery.is_some() {
                "S3 direct streaming; independent readback required"
            } else {
                "SFTP direct streaming; trusted server readback required"
            },
        );
        ui::field("Metadata staging", destination.display());
        ui::field(
            "Notice",
            "Local metadata writes and source reads affect a live system. Use external or RAM-backed metadata staging where practical.",
        );
    }
    let reserve_bytes = options
        .reserve_mib
        .checked_mul(1024 * 1024)
        .context("Reserve value overflow")?;
    let live_options = if options.sources.is_empty() && !options.no_live_info {
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
    };
    // Wizard sizing is metadata-only preflight. Actual acquisition begins here:
    // RAM request first, then volatile live state, before VSS and full file planning.
    let computer = discovered
        .sources
        .first()
        .map(|s| s.computer.as_str())
        .unwrap_or("UnknownComputer");
    let early_output = if options.vhdx.is_some() || options.e01.is_some() {
        paths::image_destination(
            &destination,
            &paths::run_name(computer, &started_utc)?,
            if options.vhdx.is_some() {
                "vhdx"
            } else {
                "E01"
            },
        )?
    } else {
        destination.clone()
    };
    // A sibling image may share the source's parent. Validate the actual output,
    // rather than rejecting its parent: fresh UUID staging remains a sibling.
    let early_parent = if phases.is_some() {
        early_output.clone()
    } else if let Some(parent) = &options.memory_options.memory_staging_dir {
        paths::resolve_future(parent)?
    } else if options.vhdx.is_some() || options.e01.is_some() {
        early_output
            .parent()
            .context("Image output has no parent")?
            .to_owned()
    } else {
        early_output.clone()
    };
    for source in &discovered.sources {
        ensure!(
            source.live || !early_parent.starts_with(&source.root),
            "Volatile staging must not be inside an offline evidence source"
        );
        ensure!(
            source.live
                || (!early_output.starts_with(&source.root)
                    && !source.root.starts_with(&early_output)),
            "Source and output directory trees must not overlap"
        );
    }
    let early = if plan_only {
        None
    } else {
        kumade::early::prepare_configured(
            &early_parent,
            computer,
            options.memory,
            live_options.as_ref(),
            Some(kumade::early::MemoryConfig {
                live: options.sources.is_empty(),
                args: &options.memory_options,
                reserve_bytes,
                quiet: options.quiet,
            }),
        )?
    };
    if let (Some(phases), Some(capture)) = (&phases, &early) {
        phases.volatile(capture)?;
    }
    if let (Some(target), Some(capture)) = (&remote, &early) {
        target.upload_early(capture)?;
    }
    // Revalidate choices before creating a snapshot or output container.
    if options.vss {
        kumade::vss::check_host()?;
    }
    let mut snapshots = if options.vss {
        if !options.quiet {
            ui::status("Creating crash-consistent VSS snapshots…");
        }
        Some(kumade::vss::prepare_sources(
            &mut discovered,
            options.vss_timeout.unwrap_or(120),
        )?)
    } else {
        None
    };
    discovered.sources.extend(history.sources);
    let sources = discovered.sources;
    let output = if options.vhdx.is_some() || options.e01.is_some() {
        let computer = sources
            .first()
            .map(|s| s.computer.as_str())
            .unwrap_or("UnknownComputer");
        paths::image_destination(
            &destination,
            &paths::run_name(computer, &started_utc)?,
            if options.vhdx.is_some() {
                "vhdx"
            } else {
                "E01"
            },
        )?
    } else {
        destination
    };
    for source in &sources {
        ensure!(
            source.live || (!output.starts_with(&source.root) && !source.root.starts_with(&output)),
            "Source and output directory trees must not overlap"
        );
    }
    if !options.quiet
        && sources
            .iter()
            .any(|s| s.live && output.starts_with(s.live_root()))
    {
        ui::field(
            "Notice",
            "The destination is on a live source volume. Output writes will change that volume; acquisition uses a frozen pre-write plan.",
        );
    }
    let mut plan = kumade::wizard::build_plan(sources, &rules, &selected, options.memory)?;
    if let Some(capture) = &early {
        kumade::pagefile::deduplicate_plan(&mut plan, &capture.pagefiles()?);
    }
    plan.created_utc = started_utc;
    if !options.quiet {
        for issue in &discovered.issues {
            let kind = if issue.status == "Excluded" {
                "Source excluded"
            } else {
                "Source unavailable"
            };
            eprintln!("{kind}: {} ({})", issue.path, issue.reason);
        }
    }
    plan.issues.extend(discovered.issues);
    if plan_only && options.entropy.high_entropy {
        kumade::entropy::augment_plan(
            &mut plan,
            &options.entropy.settings(),
            &output,
            options.threads,
            options.quiet,
        )?;
    }
    #[cfg(windows)]
    if options.remote() || options.vhdx.is_some() || options.e01.is_some() {
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
        if let Some(report) = &plan.entropy_scan {
            // Plan.json carries the settings and counters only; the per-file inventory goes
            // beside it in the same report files a collection seals.
            kumade::entropy::write_report(&output, report, &[])?;
            ui::field("Entropy reports saved", output.display());
        }
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
    let collect_options = Options {
        remote: remote.clone(),
        threads: options.threads,
        reserve_bytes,
        quiet: options.quiet,
        verbose: options.verbose,
        ntfs_metadata: false,
        host_reserve: None,
        process_scan: if options.scan_processes {
            Some(kumade::yara_scan::Options {
                output: PathBuf::new(),
                ruleset: options.yara_ruleset.unwrap_or_default(),
                rules_release: options
                    .yara_release
                    .clone()
                    .unwrap_or_else(|| "latest".into()),
                rules: options.yara_rules.clone(),
                format: kumade::yara_scan::Format::Csv,
                pids: vec![],
                threads: 2,
                timeout: 60,
                chunk_mib: 16,
                quiet: options.quiet,
            })
        } else {
            None
        },
        live_info: live_options,
        early: early.clone(),
        entropy: options
            .entropy
            .high_entropy
            .then(|| options.entropy.settings()),
    };
    let mut remote_root = None;
    let result = if options.e01.is_some() {
        e01::collect(&plan, &output, options.e01_size_gib, &collect_options)
    } else if options.vhdx.is_some() {
        vhdx::collect(&plan, &output, options.vhdx_size_gib, &collect_options)
    } else if let Some(phases) = &phases {
        collect::collect_phased(&plan, &output, &collect_options, phases).map(|(root, summary)| {
            remote_root = Some(root);
            summary
        })
    } else {
        collect::collect(&plan, &output, &collect_options).map(|(root, summary)| {
            remote_root = Some(root);
            summary
        })
    };
    let cleanup = snapshots.as_mut().map(|s| s.close()).transpose();
    let summary = match (result, cleanup) {
        (Ok(summary), Ok(_)) => summary,
        (Err(error), Ok(_)) => return Err(error),
        (Ok(_), Err(error)) => {
            return Err(error).context(
                "Evidence was saved, but VSS cleanup failed; consult snapshot IDs in Plan.json",
            );
        }
        (Err(error), Err(cleanup)) => {
            anyhow::bail!("Acquisition failed: {error:#}; VSS cleanup also failed: {cleanup:#}")
        }
    };
    if options.vss && !options.quiet {
        ui::field("VSS cleanup", "Owned snapshot set released");
    }
    if let Some(phases) = phases.take() {
        phases.complete(
            remote_root
                .as_deref()
                .context("Missing staged collection")?,
            &summary,
        )?;
        // Volatile capture and disk evidence remain available until trusted readback.
        return Ok(if summary.completeness == "Partial" {
            3
        } else {
            0
        });
    }
    if let Some(target) = &remote {
        let (name, digest) = target.publish(
            remote_root.as_deref().context("Missing metadata root")?,
            &summary,
        )?;
        // Print the receipt even in quiet mode: it is the operator's trust anchor.
        ui::field("Remote delivery", s3_delivery.as_deref().unwrap_or(&name));
        ui::field("Delivery SHA256", digest);
        ui::field(
            "Integrity",
            if s3_delivery.is_some() {
                "PENDING — run verify-s3 with separate read credentials and the printed SHA-256"
            } else {
                "PENDING — revoke the account, then run the trusted server verifier"
            },
        );
    }
    // A remote publication failure retains the original RAM stage, not just metadata.
    if let Some(capture) = early {
        capture.cleanup()?;
    }
    if let Some(staging) = staging.as_mut() {
        staging.cleanup()?;
    }
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
    fn hybrid_requires_s3_and_a_single_staging_destination() {
        assert!(Cli::try_parse_from(["kumade", "collect", "--s3-hybrid-dir", "stage"]).is_err());
        for other in [
            "--s3-recovery-dir",
            "--s3-staging-dir",
            "--memory-staging-dir",
            "-o",
        ] {
            assert!(
                Cli::try_parse_from([
                    "kumade",
                    "collect",
                    "--s3",
                    "s3://evidence-test/case/",
                    "--s3-hybrid-dir",
                    "stage",
                    other,
                    "second"
                ])
                .is_err()
            );
        }
    }
    #[test]
    fn s3_defaults_to_hybrid_and_direct_requires_explicit_selection() {
        let parse = |extra: &[&str]| {
            let cli = Cli::try_parse_from(
                ["kumade", "--s3", "s3://test/case"]
                    .into_iter()
                    .chain(extra.iter().copied()),
            )
            .unwrap();
            cli.options
        };
        let default = parse(&[]);
        assert!(default.s3.phased());
        assert!(default.s3.s3_recovery_dir.is_none());
        assert_eq!(
            default.s3.staging_parent(None).unwrap(),
            std::env::current_exe().unwrap().parent().unwrap()
        );
        let dir = Path::new("stage");
        assert_eq!(default.s3.staging_parent(Some(dir)).unwrap(), dir);
        let staged = parse(&["--s3-staging-dir", "stage"]);
        assert!(staged.s3.phased());
        assert_eq!(staged.s3.staging_parent(None).unwrap(), dir);
        assert!(staged.s3.staging_parent(Some(dir)).is_err());
        let direct = parse(&["--s3-direct", "--s3-staging-dir", "stage"]);
        assert!(!direct.s3.phased());
        assert_eq!(
            direct.s3.staging_parent(Some(Path::new("ram"))).unwrap(),
            dir
        );
        assert!(Cli::try_parse_from(["kumade", "--s3-direct"]).is_err());
        for flag in ["--s3-hybrid-dir", "--s3-recovery-dir"] {
            assert!(
                Cli::try_parse_from([
                    "kumade",
                    "--s3",
                    "s3://test/case",
                    "--s3-direct",
                    flag,
                    "stage"
                ])
                .is_err()
            );
        }
    }
    #[test]
    fn sftp_options_require_explicit_pin_and_refuse_ambiguous_outputs() {
        for args in [
            vec!["kumade", "collect", "--sftp", "host", "-o", "results"],
            vec!["kumade", "collect", "--sftp", "host", "--vhdx"],
            vec!["kumade", "collect", "--sftp", "host", "--e01"],
            vec!["kumade", "collect", "--sftp-password-stdin"],
            vec![
                "kumade",
                "collect",
                "--sftp",
                "host",
                "--sftp-password-stdin",
                "--wizard",
            ],
        ] {
            assert!(Cli::try_parse_from(args).is_err());
        }
        let cli = Cli::try_parse_from(["kumade", "collect", "--sftp", "host"]).unwrap();
        let Some(Command::Collect(options)) = cli.command else {
            panic!("collect")
        };
        assert!(options.sftp.validate().is_err());
    }

    #[test]
    fn default_workers_follow_available_cpus_and_explicit_workers_override_them() {
        let cli = Cli::try_parse_from(["kumade", "-o", "results"]).unwrap();
        assert_eq!(cli.options.threads, default_threads());
        assert!(cli.options.threads > 0 && cli.options.threads <= 4);
        let cli = Cli::try_parse_from(["kumade", "collect", "-T", "2"]).unwrap();
        let Some(Command::Collect(options)) = cli.command else {
            panic!("expected collect");
        };
        assert_eq!(options.threads, 2);
    }

    #[test]
    fn entropy_flags_are_opt_in_and_validate_thresholds_and_limits() {
        let cli = Cli::try_parse_from(["kumade", "collect"]).unwrap();
        let Some(Command::Collect(options)) = cli.command else {
            panic!("collect");
        };
        assert!(!options.entropy.high_entropy);
        assert!(options.entropy.settings().max_file_mib.is_none());
        for args in [
            vec!["kumade", "--entropy-threshold", "7.2"],
            vec!["kumade", "--high-entropy", "--entropy-threshold", "NaN"],
            vec!["kumade", "--high-entropy", "--entropy-threshold", "8.1"],
            vec!["kumade", "--high-entropy", "--entropy-threshold", "0"],
            vec!["kumade", "--high-entropy", "--entropy-min-bytes", "0"],
            vec!["kumade", "--high-entropy", "--entropy-max-candidates", "0"],
            vec![
                "kumade",
                "--high-entropy",
                "--entropy-max-file-mib",
                "18446744073709551615",
            ],
            vec!["kumade", "--entropy-exclude", "Windows/**"],
            vec!["kumade", "--entropy-extension", "toc"],
            vec!["kumade", "--entropy-all-files"],
            vec!["kumade", "--entropy-coverage", "broad"],
            vec![
                "kumade",
                "--high-entropy",
                "--entropy-coverage",
                "everything",
            ],
        ] {
            assert!(Cli::try_parse_from(args).is_err());
        }
        let cli = Cli::try_parse_from([
            "kumade",
            "--high-entropy",
            "--entropy-extension",
            ".Toc",
            "--entropy-extension",
            "mibc",
        ])
        .unwrap();
        let settings = cli.options.entropy.settings();
        assert_eq!(settings.extensions, ["toc", "mibc"]);
        assert!(!settings.all_files);
        assert_eq!(settings.coverage, kumade::entropy::ExtensionSet::Standard);
        for (flag, level) in [
            ("broad", kumade::entropy::ExtensionSet::Broad),
            (
                "comprehensive",
                kumade::entropy::ExtensionSet::Comprehensive,
            ),
        ] {
            let cli = Cli::try_parse_from(["kumade", "--high-entropy", "--entropy-coverage", flag])
                .unwrap();
            assert_eq!(cli.options.entropy.settings().coverage, level);
        }
        assert!(
            Cli::try_parse_from(["kumade", "--high-entropy", "--entropy-all-files"])
                .unwrap()
                .options
                .entropy
                .settings()
                .all_files
        );
        for args in [
            vec!["kumade", "--high-entropy", "--entropy-threshold", "8"],
            vec![
                "kumade",
                "plan",
                "--high-entropy",
                "--entropy-scope",
                "either",
            ],
            vec!["kumade", "collect", "--high-entropy", "--vhdx"],
            vec![
                "kumade",
                "--e01",
                "--high-entropy",
                "--entropy-max-collect-mib",
                "100",
            ],
        ] {
            assert!(Cli::try_parse_from(args).is_ok());
        }
    }

    #[test]
    fn memory_pagefiles_are_default_on_but_ram_stays_opt_in() {
        let cli = Cli::try_parse_from(["kumade", "collect"]).unwrap();
        let Some(Command::Collect(options)) = cli.command else {
            panic!("collect")
        };
        assert!(!options.memory);
        assert!(!options.memory_options.no_memory_pagefile);
        let cli = Cli::try_parse_from(["kumade", "--memory", "--no-memory-pagefile"]).unwrap();
        assert!(cli.options.memory && cli.options.memory_options.no_memory_pagefile);
        assert!(Cli::try_parse_from(["kumade", "--no-memory-pagefile"]).is_err());
    }
    #[test]
    fn containers_accept_automatic_names_and_destination_directories() {
        // A bare flag carries no path; run() substitutes the exe-relative default.
        let cli = Cli::try_parse_from(["kumade", "--vhdx"]).unwrap();
        assert_eq!(cli.options.vhdx, Some(None));
        assert!(default_results_dir().ends_with("Kumade-Results"));
        assert!(default_results_dir().is_absolute() || std::env::current_exe().is_err());
        let cli = Cli::try_parse_from(["kumade", "--vhdx", "-v"]).unwrap();
        assert_eq!(cli.options.vhdx, Some(None));
        assert!(cli.options.verbose);
        let cli = Cli::try_parse_from(["kumade", "--e01", "output"]).unwrap();
        assert_eq!(cli.options.e01, Some(Some(PathBuf::from("output"))));
        let cli = Cli::try_parse_from(["kumade", "--vhdx", "--vhdx-size-gib", "4"]).unwrap();
        assert_eq!(cli.options.vhdx_size_gib, Some(4));
    }
}
