// Copyright (C) 2026 Shirofune Security Co., Ltd.
// SPDX-License-Identifier: RPL-1.5
//! Opt-in, read-only process-memory hunting. A rule match is an analyst lead.
#![cfg_attr(not(windows), allow(dead_code))]
use anyhow::{Context, Result, ensure};
use boreal::{
    MetadataValue, Scanner,
    compiler::{CompilerBuilder, CompilerParams},
    scanner::ScanParams,
};
use clap::{Args, ValueEnum};
use rayon::prelude::*;
use serde::Serialize;
use std::{
    collections::BTreeMap,
    fs::{self, File, OpenOptions},
    io::{BufWriter, Write},
    path::{Path, PathBuf},
    time::{Duration, Instant},
};

#[cfg(windows)]
mod windows;

pub use crate::yara_rules::RuleSet;
use crate::yara_rules::rule_url;
#[cfg(test)]
use crate::yara_rules::{archive_source, read_bounded};
const MAX_SAMPLES: usize = 16;

#[derive(Clone, Copy, Debug, Default, ValueEnum)]
pub enum Format {
    #[default]
    Csv,
    Jsonl,
}

#[derive(Args, Debug, Clone)]
pub struct Options {
    /// New result directory (existing directories are refused)
    #[arg(short, long, value_name = "DIR")]
    pub output: PathBuf,
    /// YARA Forge package (bundled selection by default, otherwise core)
    #[arg(long, value_enum, default_value_t, conflicts_with = "rules")]
    pub ruleset: RuleSet,
    /// Forge release tag YYYYMMDD, or latest
    #[arg(long, default_value = "latest", conflicts_with = "rules")]
    pub rules_release: String,
    /// Local Forge ZIP or UTF-8 YARA source (offline; includes disabled)
    #[arg(long, value_name = "FILE")]
    pub rules: Option<PathBuf>,
    /// Result table format
    #[arg(short = 't', long, value_enum, default_value = "csv")]
    pub format: Format,
    /// Limit scanning to a PID; repeat (default: all except this collector)
    #[arg(long = "pid", value_name = "PID")]
    pub pids: Vec<u32>,
    /// Concurrent processes (default: 2 to limit live-system pressure)
    #[arg(short = 'T', long, default_value_t = 2, value_parser = clap::value_parser!(u64).range(1..=16))]
    pub threads: u64,
    /// Deadline per process in seconds; expired scans retain partial matches
    #[arg(long, default_value_t = 60, value_parser = clap::value_parser!(u64).range(1..=3600))]
    pub timeout: u64,
    /// Memory read chunk size in MiB; patterns crossing chunks may be missed
    #[arg(long, default_value_t = 16, value_parser = clap::value_parser!(u64).range(1..=256))]
    pub chunk_mib: u64,
    /// Suppress progress and routine console messages
    #[arg(short, long)]
    pub quiet: bool,
}

#[derive(Debug, Clone, Serialize)]
#[serde(rename_all = "PascalCase")]
pub struct ProcessResult {
    pub computer: String,
    #[serde(rename = "PID")]
    pub pid: u32,
    pub process_name: String,
    pub image_path: String,
    pub process_created_utc: String,
    pub started_utc: String,
    pub elapsed_seconds: f64,
    pub status: String,
    pub matches: usize,
    pub bytes_read: u64,
    pub read_calls: u64,
    pub read_failures: u64,
    pub guard_regions_skipped: u64,
    pub message: String,
}
impl ProcessResult {
    pub fn new(pid: u32, name: String) -> Self {
        Self {
            computer: std::env::var("COMPUTERNAME").unwrap_or_default(),
            pid,
            process_name: name,
            image_path: String::new(),
            process_created_utc: String::new(),
            started_utc: crate::model::utc_now(),
            elapsed_seconds: 0.0,
            status: "Failed".into(),
            matches: 0,
            bytes_read: 0,
            read_calls: 0,
            read_failures: 0,
            guard_regions_skipped: 0,
            message: String::new(),
        }
    }
}
#[derive(Debug, Serialize)]
#[serde(rename_all = "PascalCase")]
pub struct Detection {
    pub computer: String,
    #[serde(rename = "PID")]
    pub pid: u32,
    pub process_name: String,
    pub image_path: String,
    pub process_created_utc: String,
    pub collected_utc: String,
    pub scan_status: String,
    pub rule: String,
    pub namespace: String,
    pub tags: String,
    /// JSON object encoded as a string so CSV and JSONL share the same schema.
    pub metadata: String,
    /// Bounded JSON array of pattern/address/length, never raw process bytes.
    pub match_locations: String,
}

pub fn compile(source: &str, timeout: u64, chunk_mib: u64) -> Result<Scanner> {
    compile_with_warnings(source, timeout, chunk_mib).map(|v| v.0)
}
fn compile_with_warnings(
    source: &str,
    timeout: u64,
    chunk_mib: u64,
) -> Result<(Scanner, Vec<String>)> {
    let mut compiler = CompilerBuilder::new()
        .add_module(boreal::module::Console::with_callback(|_| {}))
        .build();
    compiler.set_params(CompilerParams::default().disable_includes(true));
    let status = compiler
        .add_rules_str(source.strip_prefix('\u{feff}').unwrap_or(source))
        .map_err(|e| {
            anyhow::anyhow!("YARA compilation failed; no rules were silently discarded: {e}")
        })?;
    let warnings = status.warnings().map(ToString::to_string).collect();
    let mut scanner = compiler.finalize();
    ensure!(
        scanner.rules().any(|r| !r.is_private),
        "No public YARA rules to scan"
    );
    scanner.set_scan_params(
        ScanParams::default()
            .process_memory(true)
            .compute_full_matches(true)
            .match_max_length(0)
            .memory_chunk_size(Some(chunk_mib as usize * 1024 * 1024))
            .timeout_duration(Some(Duration::from_secs(timeout))),
    );
    Ok((scanner, warnings))
}

pub fn detections(
    scanner: &Scanner,
    result: boreal::scanner::ScanResult<'_>,
    process: &ProcessResult,
) -> Vec<Detection> {
    result.rules.into_iter().filter(|r| r.matched).map(|r| {
        let metadata: BTreeMap<_, _> = r.metadatas.iter().map(|m| {
            let v = match m.value {
                MetadataValue::Bytes(s) => serde_json::Value::String(String::from_utf8_lossy(scanner.get_bytes_symbol(s)).into_owned()),
                MetadataValue::Integer(i) => i.into(),
                MetadataValue::Boolean(b) => b.into(),
            };
            (scanner.get_string_symbol(m.name), v)
        }).collect();
        let samples: Vec<_> = r.matches.iter().flat_map(|s| s.matches.iter().take(1).map(move |m| serde_json::json!({
            "Pattern": format!("${}", s.name), "Address": format!("0x{:X}", m.base.saturating_add(m.offset)), "Length": m.length, "XorKey": m.xor_key
        }))).take(MAX_SAMPLES).collect();
        Detection {
            computer: process.computer.clone(), pid: process.pid, process_name: process.process_name.clone(),
            image_path: process.image_path.clone(), process_created_utc: process.process_created_utc.clone(),
            collected_utc: crate::model::utc_now(), scan_status: process.status.clone(),
            rule: r.name.into(), namespace: r.namespace.into(),
            tags: r.tags.iter().map(|s| scanner.get_string_symbol(*s)).collect::<Vec<_>>().join(" "),
            metadata: serde_json::to_string(&metadata).expect("metadata serialization"),
            match_locations: serde_json::to_string(&samples).expect("location serialization"),
        }
    }).collect()
}

fn load_rules(options: &Options) -> Result<crate::yara_rules::Loaded> {
    crate::yara_rules::load(
        options.rules.as_deref(),
        options.ruleset,
        &options.rules_release,
    )
}

fn write_new(path: &Path, bytes: &[u8]) -> Result<()> {
    let mut f = OpenOptions::new().write(true).create_new(true).open(path)?;
    f.write_all(bytes)?;
    f.sync_all()?;
    Ok(())
}
fn table<T: Serialize>(
    output: &Path,
    name: &str,
    rows: &[T],
    format: Format,
    headers: &[&str],
) -> Result<()> {
    match format {
        Format::Csv => {
            let mut writer = csv::WriterBuilder::new()
                .has_headers(false)
                .from_writer(File::create(output.join(format!("{name}.csv")))?);
            writer.write_record(headers)?;
            for row in rows {
                writer.serialize(row)?;
            }
            writer.flush()?;
        }
        Format::Jsonl => {
            let mut writer = BufWriter::new(File::create(output.join(format!("{name}.jsonl")))?);
            for row in rows {
                serde_json::to_writer(&mut writer, row)?;
                writer.write_all(b"\n")?;
            }
            writer.flush()?;
        }
    }
    Ok(())
}

/// Whether this binary can inspect the host's complete native address spaces.
pub fn check_host() -> Result<()> {
    #[cfg(windows)]
    return windows::require_native();
    #[cfg(not(windows))]
    anyhow::bail!("Process scanning requires native Windows");
}

pub fn run(options: &Options) -> Result<u8> {
    #[cfg(not(windows))]
    let _ = options;
    #[cfg(not(windows))]
    anyhow::bail!(
        "Process scanning requires native Windows; rule compilation tests remain portable"
    );
    #[cfg(windows)]
    {
        windows::require_native()?;
        run_with(
            options,
            windows::list_processes,
            windows::scan,
            windows::metrics,
        )
    }
}

#[derive(Default, Serialize)]
#[serde(rename_all = "PascalCase")]
pub struct Metrics {
    pub cpu_seconds: f64,
    pub peak_working_set_bytes: u64,
}

fn run_with(
    options: &Options,
    enumerate: impl FnOnce() -> Result<Vec<(u32, String)>>,
    scan: impl Fn(&Scanner, u32, String, &Options) -> (ProcessResult, Vec<Detection>) + Sync,
    metrics: impl Fn() -> Metrics,
) -> Result<u8> {
    ensure!(
        (1..=16).contains(&options.threads)
            && (1..=256).contains(&options.chunk_mib)
            && (1..=3600).contains(&options.timeout),
        "Invalid scan resource limits"
    );
    if options.rules.is_none() {
        rule_url(options.ruleset, &options.rules_release)?;
    }
    #[cfg(windows)]
    let privilege = windows::enable_debug_privilege()
        .map_or_else(|e| format!("Unavailable: {e:#}"), |()| "Enabled".into());
    #[cfg(not(windows))]
    let privilege = "Synthetic test";
    let start = Instant::now();
    let cpu_start = metrics().cpu_seconds;
    let mut processes = enumerate()?;
    let explicit = !options.pids.is_empty();
    if explicit {
        let mut pids = options.pids.clone();
        pids.sort_unstable();
        pids.dedup();
        processes = pids
            .into_iter()
            .map(|pid| {
                let name = processes
                    .iter()
                    .find(|p| p.0 == pid)
                    .map(|p| p.1.clone())
                    .unwrap_or_default();
                (pid, name)
            })
            .collect();
    }
    processes.sort_by_key(|p| p.0);
    ensure!(
        !processes.is_empty(),
        "No processes enumerated; refusing to report an empty scan as successful"
    );
    fs::create_dir(&options.output).context("Cannot create new output directory (parent must exist; existing results are never overwritten)")?;
    if !options.quiet {
        crate::ui::banner();
        crate::ui::field("Start time", crate::model::utc_now());
        crate::ui::field("Processes", processes.len());
        crate::ui::status("Loading and compiling YARA rules…");
    }
    // A failure before Summary.json remains an incomplete run, never a clean result.
    write_new(
        &options.output.join("RunStarted.json"),
        b"{\"Status\":\"Started\",\"CompletionMarker\":\"Summary.json\"}\n",
    )?;
    let loaded = load_rules(options)?;
    let source = loaded.source;
    let provenance = loaded.provenance;
    // Rule source is compiled in memory; do not write expanded signatures on a target.
    write_new(
        &options.output.join("RuleSource.json"),
        &serde_json::to_vec_pretty(&provenance)?,
    )?;
    let source_hash = crate::model::sha256(source.as_bytes());
    let compile_start = Instant::now();
    let (scanner, warnings) =
        match compile_with_warnings(&source, options.timeout, options.chunk_mib) {
            Ok(s) => s,
            Err(e) => {
                write_new(
                    &options.output.join("CompilationError.txt"),
                    format!("{e:#}\n").as_bytes(),
                )?;
                return Err(e);
            }
        };
    write_new(
        &options.output.join("CompilationWarnings.txt"),
        warnings.join("\n").as_bytes(),
    )?;
    let compile_seconds = compile_start.elapsed().as_secs_f64();
    let rules = scanner.rules().count();
    let public_rules = scanner.rules().filter(|r| !r.is_private).count();
    if !options.quiet {
        crate::ui::field("Rules", rules);
        crate::ui::field("Threads", options.threads);
    }
    let bar = crate::ui::progress_bar(processes.len() as u64, options.quiet);
    let pool = rayon::ThreadPoolBuilder::new()
        .num_threads(options.threads as usize)
        .build()?;
    let scan_start = Instant::now();
    let results: Vec<_> = pool.install(|| {
        processes
            .into_par_iter()
            .map(|(pid, name)| {
                bar.set_message(format!("PID {pid} / {name}"));
                let pair = if pid == std::process::id() && !explicit {
                    let mut p = ProcessResult::new(pid, name);
                    p.status = "Skipped".into();
                    p.message =
                        "Collector excluded: its memory contains rules and copied target bytes"
                            .into();
                    (p, vec![])
                } else {
                    scan(&scanner, pid, name, options)
                };
                bar.inc(1);
                pair
            })
            .collect()
    });
    bar.finish_and_clear();
    let scan_seconds = scan_start.elapsed().as_secs_f64();
    let (process_rows, detection_rows): (Vec<_>, Vec<_>) = results.into_iter().unzip();
    let detection_rows: Vec<_> = detection_rows.into_iter().flatten().collect();
    table(
        &options.output,
        "YaraProcesses",
        &process_rows,
        options.format,
        &[
            "Computer",
            "PID",
            "ProcessName",
            "ImagePath",
            "ProcessCreatedUtc",
            "StartedUtc",
            "ElapsedSeconds",
            "Status",
            "Matches",
            "BytesRead",
            "ReadCalls",
            "ReadFailures",
            "GuardRegionsSkipped",
            "Message",
        ],
    )?;
    table(
        &options.output,
        "YaraDetections",
        &detection_rows,
        options.format,
        &[
            "Computer",
            "PID",
            "ProcessName",
            "ImagePath",
            "ProcessCreatedUtc",
            "CollectedUtc",
            "ScanStatus",
            "Rule",
            "Namespace",
            "Tags",
            "Metadata",
            "MatchLocations",
        ],
    )?;
    let incomplete = process_rows
        .iter()
        .filter(|p| !matches!(p.status.as_str(), "Scanned" | "Skipped"))
        .count();
    let succeeded = process_rows
        .iter()
        .filter(|p| p.status == "Scanned")
        .count();
    let metric = metrics();
    let summary = serde_json::json!({
        "Status": if incomplete == 0 {"Finished"} else {"Partial"},
        "SeDebugPrivilege":privilege,"CompilationWarnings":warnings.len(),"Engine":"boreal", "EngineVersion":"1.4.0", "KumadeVersion":env!("CARGO_PKG_VERSION"),
        "RuleSet":provenance.ruleset, "RulesRelease":provenance.release,
        "RuleSource":provenance,"RulesSHA256":source_hash,"Rules":rules,"PublicRules":public_rules,"MaxMatchesPerPattern":1000,
        "Processes":process_rows.len(),"Scanned":succeeded,"Incomplete":incomplete,
        "Skipped":process_rows.iter().filter(|p| p.status=="Skipped").count(),
        "MatchedProcesses":process_rows.iter().filter(|p|p.matches>0).count(),"Detections":detection_rows.len(),
        "UniqueMatchedRules":detection_rows.iter().map(|d| &d.rule).collect::<std::collections::BTreeSet<_>>().len(),
        "CompileSeconds":compile_seconds,"ScanSeconds":scan_seconds,"ElapsedSeconds":start.elapsed().as_secs_f64(),
        "CpuSeconds":metric.cpu_seconds-cpu_start,"PeakWorkingSetBytes":metric.peak_working_set_bytes,
        "Threads":options.threads,"TimeoutSeconds":options.timeout,"ChunkMiB":options.chunk_mib,
        "Semantics":"Live process memory; filesize undefined; PE virtual layout; guard/unreadable pages excluded; cross-chunk patterns may be missed; no-match is not a clean bill of health"
    });
    write_new(
        &options.output.join("Summary.json"),
        &serde_json::to_vec_pretty(&summary)?,
    )?;
    // Summary.json is the completion marker; retain the start journal for interrupted-run diagnosis.
    if !options.quiet {
        crate::ui::heading("Results Summary:");
        crate::ui::field("Scanned", succeeded);
        crate::ui::field("Incomplete", incomplete);
        crate::ui::field("Rule/process matches", detection_rows.len());
        crate::ui::field("Results saved", options.output.display());
        crate::ui::field(
            "Elapsed seconds",
            format!("{:.3}", start.elapsed().as_secs_f64()),
        );
    }
    Ok(if incomplete > 0 { 3 } else { 0 })
}

#[cfg(test)]
mod tests;
