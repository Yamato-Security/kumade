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

//! Opt-in PE entropy discovery; candidates use the normal sealed acquisition pipeline.
use crate::{
    discovery,
    model::*,
    paths, platform,
    raw::{RawVolume, ReadSeek},
    ui,
};
use anyhow::{Context, Result, ensure};
use clap::{Args, ValueEnum};
use rayon::prelude::*;
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use std::{
    collections::{BTreeMap, HashMap},
    fs::{File, OpenOptions},
    io::{BufWriter, SeekFrom, Write},
    path::{Path, PathBuf},
    sync::Mutex,
};

pub const ARTIFACT: &str = "windows.binaries.high_entropy";
pub const FILES: &[&str] = &[
    "HighEntropyBinaries.csv",
    "HighEntropyBinaries.jsonl",
    "EntropySummary.json",
];

#[derive(Clone, Debug, Default, ValueEnum, Serialize, Deserialize, PartialEq)]
pub enum Scope {
    File,
    #[default]
    ExecutableSections,
    Either,
}
#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(rename_all = "PascalCase")]
pub struct Settings {
    pub threshold: f64,
    pub scope: Scope,
    pub min_bytes: u64,
    pub max_file_mib: Option<u64>,
    pub max_candidates: Option<u64>,
    pub max_collect_mib: Option<u64>,
    pub excludes: Vec<String>,
}
impl Default for Settings {
    fn default() -> Self {
        Self {
            threshold: 7.2,
            scope: Scope::ExecutableSections,
            min_bytes: 4096,
            max_file_mib: None,
            max_candidates: None,
            max_collect_mib: None,
            excludes: vec![],
        }
    }
}
#[derive(Args, Clone, Debug, Default)]
pub struct EntropyArgs {
    /// Scan selected source drives for high-entropy PE candidates and collect them
    #[arg(long)]
    pub high_entropy: bool,
    /// Entropy threshold in bits/byte (default: 7.2; range >0 through 8)
    #[arg(long, requires="high_entropy", value_parser=threshold)]
    pub entropy_threshold: Option<f64>,
    /// Candidate criterion (default: executable-sections)
    #[arg(long, value_enum, requires = "high_entropy")]
    pub entropy_scope: Option<Scope>,
    /// Minimum measured region size in bytes (default: 4096)
    #[arg(long,requires="high_entropy",value_parser=clap::value_parser!(u64).range(1..))]
    pub entropy_min_bytes: Option<u64>,
    /// Optional size cap for entropy analysis; no default file-size limit
    #[arg(long,requires="high_entropy",value_parser=mib)]
    pub entropy_max_file_mib: Option<u64>,
    /// Optional limit on additional binary files selected for collection
    #[arg(long,requires="high_entropy",value_parser=clap::value_parser!(u64).range(1..))]
    pub entropy_max_candidates: Option<u64>,
    /// Optional total MiB cap on additional binary collection
    #[arg(long,requires="high_entropy",value_parser=mib)]
    pub entropy_max_collect_mib: Option<u64>,
    /// Exclude a source-relative glob from entropy discovery; repeat as needed
    #[arg(long, requires = "high_entropy", value_name = "GLOB")]
    pub entropy_exclude: Vec<String>,
}
fn threshold(s: &str) -> std::result::Result<f64, String> {
    s.parse::<f64>()
        .ok()
        .filter(|n| n.is_finite() && *n > 0.0 && *n <= 8.0)
        .ok_or_else(|| "Entropy must be finite, above 0 and at most 8 bits/byte".into())
}
fn mib(s: &str) -> std::result::Result<u64, String> {
    s.parse::<u64>()
        .ok()
        .filter(|v| *v > 0 && v.checked_mul(1024 * 1024).is_some())
        .ok_or_else(|| "Use a positive whole MiB value within the 64-bit byte range".into())
}
impl EntropyArgs {
    pub fn settings(&self) -> Settings {
        let d = Settings::default();
        Settings {
            threshold: self.entropy_threshold.unwrap_or(d.threshold),
            scope: self.entropy_scope.clone().unwrap_or(d.scope),
            min_bytes: self.entropy_min_bytes.unwrap_or(d.min_bytes),
            max_file_mib: self.entropy_max_file_mib,
            max_candidates: self.entropy_max_candidates,
            max_collect_mib: self.entropy_max_collect_mib,
            excludes: self.entropy_exclude.clone(),
        }
    }
}

#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(rename_all = "PascalCase")]
pub struct Section {
    pub name: String,
    pub raw_offset: u64,
    pub raw_size: u64,
    pub executable: bool,
    pub entropy: f64,
}
#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(rename_all = "PascalCase")]
pub struct Analysis {
    pub size: u64,
    #[serde(rename = "SHA256")]
    pub sha256: String,
    pub file_entropy: f64,
    pub max_executable_entropy: Option<f64>,
    pub machine: String,
    #[serde(rename = "IsDLL")]
    pub is_dll: bool,
    pub has_certificate_table: bool,
    pub candidate: bool,
    pub sections: Vec<Section>,
}
#[derive(Debug)]
struct SizeLimit;
impl std::fmt::Display for SizeLimit {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str("Configured entropy file-size limit reached")
    }
}
impl std::error::Error for SizeLimit {}

fn entropy(counts: &[u64; 256], size: u64) -> f64 {
    if size == 0 {
        return 0.0;
    }
    counts
        .iter()
        .filter(|n| **n > 0)
        .map(|n| {
            let p = *n as f64 / size as f64;
            -p * p.log2()
        })
        .sum()
}
fn le16(b: &[u8], i: usize) -> u16 {
    u16::from_le_bytes(b[i..i + 2].try_into().expect("bounded header"))
}
fn le32(b: &[u8], i: usize) -> u32 {
    u32::from_le_bytes(b[i..i + 4].try_into().expect("bounded header"))
}
fn read_at(reader: &mut dyn ReadSeek, size: u64, offset: u64, buffer: &mut [u8]) -> Result<()> {
    ensure!(
        offset
            .checked_add(buffer.len() as u64)
            .is_some_and(|end| end <= size),
        "PE range extends past EOF"
    );
    reader.seek(SeekFrom::Start(offset))?;
    reader.read_exact(buffer)?;
    Ok(())
}
/// Header checks use seeked bounded reads. Histograms and hash then read the complete
/// logical file once; sections are measured from on-disk bytes, never virtual zero padding.
pub fn analyze(
    reader: &mut dyn ReadSeek,
    size: u64,
    settings: &Settings,
) -> Result<Option<Analysis>> {
    if size < 2 {
        return Ok(None);
    }
    let mut magic = [0; 2];
    read_at(reader, size, 0, &mut magic)?;
    if magic != *b"MZ" {
        return Ok(None);
    }
    if size < 64 {
        return Ok(None);
    }
    let mut dos = [0; 64];
    read_at(reader, size, 0, &mut dos)?;
    let at = u64::from(le32(&dos, 60));
    if at < 64 || at.checked_add(24).is_none_or(|e| e > size) {
        return Ok(None);
    }
    let mut coff = [0; 24];
    read_at(reader, size, at, &mut coff)?;
    if &coff[..4] != b"PE\0\0" {
        return Ok(None);
    }
    let n = usize::from(le16(&coff, 6));
    ensure!(
        (1..=96).contains(&n),
        "Invalid PE section count (Windows supports up to 96)"
    );
    ensure!(le16(&coff, 22) & 2 != 0, "PE is not an executable image");
    let optional_len = usize::from(le16(&coff, 20));
    ensure!(optional_len >= 96, "PE optional header is truncated");
    let mut optional = vec![0; optional_len];
    read_at(reader, size, at + 24, &mut optional)?;
    let directory = match le16(&optional, 0) {
        0x10b => 96,
        0x20b => {
            ensure!(optional_len >= 112, "PE32+ optional header is truncated");
            112
        }
        _ => anyhow::bail!("Unsupported PE optional-header format"),
    };
    let cert = if optional_len >= directory + 40 && le32(&optional, directory - 4) > 4 {
        let offset = u64::from(le32(&optional, directory + 32));
        let length = u64::from(le32(&optional, directory + 36));
        length > 0 && offset > 0 && offset.checked_add(length).is_some_and(|e| e <= size)
    } else {
        false
    };
    let mut sections = Vec::with_capacity(n);
    for index in 0..n {
        let mut s = [0; 40];
        read_at(
            reader,
            size,
            at + 24 + optional_len as u64 + index as u64 * 40,
            &mut s,
        )?;
        let offset = u64::from(le32(&s, 20));
        let length = u64::from(le32(&s, 16));
        ensure!(
            length == 0
                || offset
                    .checked_add(length)
                    .is_some_and(|e| offset > 0 && e <= size),
            "PE section raw bytes are truncated or out of bounds"
        );
        sections.push(Section {
            name: String::from_utf8_lossy(&s[..s[..8].iter().position(|b| *b == 0).unwrap_or(8)])
                .into_owned(),
            raw_offset: offset,
            raw_size: length,
            executable: le32(&s, 36) & 0x2000_0000 != 0,
            entropy: 0.0,
        });
    }
    if settings
        .max_file_mib
        .is_some_and(|n| size > n.saturating_mul(1024 * 1024))
    {
        return Err(SizeLimit.into());
    }
    let mut full = [0u64; 256];
    let mut per = vec![[0u64; 256]; n];
    let mut buffer = vec![0u8; 1024 * 1024];
    let mut position = 0u64;
    let mut digest = Sha256::new();
    reader.seek(SeekFrom::Start(0))?;
    loop {
        let read = reader.read(&mut buffer)?;
        if read == 0 {
            break;
        }
        let data = &buffer[..read];
        for b in data {
            full[*b as usize] += 1;
        }
        digest.update(data);
        let end = position
            .checked_add(read as u64)
            .context("File position overflow")?;
        ensure!(end <= size, "File grew during entropy analysis");
        for (section, counts) in sections.iter().zip(per.iter_mut()) {
            let start = position.max(section.raw_offset);
            let stop = end.min(section.raw_offset + section.raw_size);
            if start < stop {
                for b in &data[(start - position) as usize..(stop - position) as usize] {
                    counts[*b as usize] += 1;
                }
            }
        }
        position = end;
    }
    ensure!(position == size, "File shortened during entropy analysis");
    for (s, counts) in sections.iter_mut().zip(&per) {
        s.entropy = entropy(counts, s.raw_size);
    }
    let maximum = sections
        .iter()
        .filter(|s| s.executable && s.raw_size >= settings.min_bytes)
        .map(|s| s.entropy)
        .reduce(f64::max);
    let file_entropy = entropy(&full, size);
    let by_file = size >= settings.min_bytes && file_entropy >= settings.threshold;
    let by_section = maximum.is_some_and(|h| h >= settings.threshold);
    let candidate = match settings.scope {
        Scope::File => by_file,
        Scope::ExecutableSections => by_section,
        Scope::Either => by_file || by_section,
    };
    Ok(Some(Analysis {
        size,
        sha256: hex(&digest.finalize()),
        file_entropy,
        max_executable_entropy: maximum,
        machine: format!("0x{:04X}", le16(&coff, 4)),
        is_dll: le16(&coff, 22) & 0x2000 != 0,
        has_certificate_table: cert,
        candidate,
        sections,
    }))
}

#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(rename_all = "PascalCase")]
pub struct Observation {
    pub computer: String,
    pub source_id: String,
    pub relative_path: String,
    pub method: String,
    pub status: String,
    pub reason: String,
    pub analysis: Option<Analysis>,
    pub observation_id: Option<String>,
    pub fingerprint: Option<Fingerprint>,
}
#[derive(Default, Clone, Debug, Serialize, Deserialize)]
#[serde(rename_all = "PascalCase")]
pub struct Counts {
    pub files_seen: u64,
    pub non_pe: u64,
    pub pe_analyzed: u64,
    pub candidates: u64,
    pub selected_new: u64,
    pub selected_bytes: u64,
    pub skipped: u64,
    pub errors: u64,
}
#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(rename_all = "PascalCase")]
pub struct Report {
    pub settings: Settings,
    pub started_utc: String,
    pub finished_utc: String,
    pub counts: Counts,
    pub observations: Vec<Observation>,
}
fn issue(source: &Source, path: &str, status: &str, reason: &str) -> Observation {
    Observation {
        computer: source.computer.clone(),
        source_id: source.id.clone(),
        relative_path: path.into(),
        method: String::new(),
        status: status.into(),
        reason: reason.into(),
        analysis: None,
        observation_id: None,
        fingerprint: None,
    }
}
fn inspect(
    source: &Source,
    path: &Path,
    relative: &Path,
    settings: &Settings,
    cache: &mut HashMap<PathBuf, RawVolume>,
) -> Result<(Option<Analysis>, Fingerprint, String)> {
    let normal = (|| -> Result<_> {
        let mut file = platform::open_source(path)?;
        platform::validate_open_file(&file, &source.root)?;
        let before = discovery::fingerprint(&file.metadata()?);
        let result = analyze(&mut file, before.size, settings)?;
        let after = discovery::fingerprint(&file.metadata()?);
        ensure!(
            discovery::same_version(&before, &after),
            "Source changed during entropy analysis"
        );
        Ok((result, before, "FileAPI".into()))
    })();
    match normal {
        Ok(v) => Ok(v),
        Err(error) => {
            // Do not mask malformed-PE or changed-content failures by reading another version.
            let is_io = error
                .chain()
                .any(|e| e.downcast_ref::<std::io::Error>().is_some());
            let Some(device) = source.raw_device.as_ref().filter(|_| is_io) else {
                return Err(error);
            };
            if !cache.contains_key(device) {
                cache.insert(device.clone(), RawVolume::open(device)?);
            }
            let (result, before, after) = cache
                .get_mut(device)
                .expect("cached volume")
                .inspect_file(relative, |r, size| analyze(r, size, settings))
                .with_context(|| {
                    format!("File API failed ({error:#}); raw NTFS inspection failed")
                })?;
            ensure!(
                discovery::same_version(&before, &after),
                "Raw source changed during entropy analysis"
            );
            Ok((result, before, "RawNTFS".into()))
        }
    }
}

/// Runs before any output directory/container is created, so the scan cannot ingest its own
/// writes. It shares frozen VSS roots and never falls back to the live origin of a snapshot.
pub fn augment_plan(
    plan: &mut Plan,
    settings: &Settings,
    destination: &Path,
    threads: usize,
    quiet: bool,
) -> Result<()> {
    ensure!(
        settings.threshold.is_finite() && settings.threshold > 0.0 && settings.threshold <= 8.0,
        "Invalid entropy threshold"
    );
    ensure!(
        settings.min_bytes > 0 && threads > 0 && threads <= 128,
        "Invalid entropy minimum/worker count"
    );
    for cap in [settings.max_file_mib, settings.max_collect_mib]
        .into_iter()
        .flatten()
    {
        ensure!(
            cap > 0 && cap.checked_mul(1024 * 1024).is_some(),
            "Invalid entropy MiB cap"
        );
    }
    ensure!(
        settings.max_candidates != Some(0),
        "Invalid entropy candidate limit"
    );
    let mut builder = globset::GlobSetBuilder::new();
    for pattern in &settings.excludes {
        builder.add(
            globset::GlobBuilder::new(pattern)
                .case_insensitive(true)
                .literal_separator(false)
                .build()?,
        );
    }
    let excludes = builder.build()?;
    let pool = rayon::ThreadPoolBuilder::new()
        .num_threads(threads)
        .build()?;
    let started = utc_now();
    let state = Mutex::new((Counts::default(), Vec::<Observation>::new()));
    if !quiet {
        ui::status("Scanning source drives for high-entropy PE candidates…");
        ui::field(
            "Entropy threshold",
            format!("{} bits/byte", settings.threshold),
        );
    }
    let progress = ui::scan_spinner(quiet);
    for source in &plan.sources {
        let output = paths::resolve_future(destination)?;
        let root = platform::canonicalize(&source.root)?;
        let live = platform::canonicalize(source.live_root())?;
        let mapped = output.strip_prefix(&live).ok().map(|r| root.join(r));
        if source.metadata_only {
            let mut s = state.lock().expect("entropy state");
            s.0.skipped += 1;
            s.1.push(issue(
                source,
                ".",
                "Excluded",
                "Source explicitly restricted to NTFS metadata",
            ));
            continue;
        }
        let walker = walkdir::WalkDir::new(&source.root)
            .follow_links(false)
            .sort_by_file_name()
            .into_iter()
            .filter_entry(|e| {
                let relative = e.path().strip_prefix(&source.root).unwrap_or(Path::new(""));
                let excluded = e.depth() > 0
                    && (e.path().starts_with(&output)
                        || mapped.as_ref().is_some_and(|p| e.path().starts_with(p))
                        || excludes.is_match(relative));
                let reparse = e.depth() > 0
                    && (e.file_type().is_symlink() || platform::is_reparse_directory(e.path()));
                if excluded || reparse {
                    let mut s = state.lock().expect("entropy state");
                    s.0.skipped += 1;
                    s.1.push(issue(
                        source,
                        &relative.to_string_lossy(),
                        "Excluded",
                        if reparse {
                            "Reparse/symlink traversal disabled"
                        } else {
                            "Destination or configured entropy exclusion"
                        },
                    ));
                    return false;
                }
                true
            });
        pool.install(|| {
            walker
                .par_bridge()
                .map_init(HashMap::new, |cache, entry| {
                    let entry = match entry {
                        Ok(e) => e,
                        Err(e) => {
                            return Some(Err(issue(
                                source,
                                &e.path()
                                    .map(|p| p.display().to_string())
                                    .unwrap_or_default(),
                                "EnumerationError",
                                &format!("Enumeration failed: {e}"),
                            )));
                        }
                    };
                    if !entry.file_type().is_file() {
                        return None;
                    }
                    let relative = match entry.path().strip_prefix(&source.root) {
                        Ok(r) => r,
                        Err(e) => return Some(Err(issue(source, "", "Error", &e.to_string()))),
                    };
                    let text = match paths::relative_text(relative) {
                        Ok(t) => t,
                        Err(e) => {
                            return Some(Err(issue(
                                source,
                                &relative.to_string_lossy(),
                                "Error",
                                &e.to_string(),
                            )));
                        }
                    };
                    progress.set_message(ui::progress_message(
                        &text,
                        entry.metadata().ok().map(|m| m.len()),
                    ));
                    progress.inc(1);
                    Some(
                        match inspect(source, entry.path(), relative, settings, cache) {
                            Ok((analysis, before, method)) => Ok((text, analysis, before, method)),
                            Err(e) => Err(issue(
                                source,
                                &text,
                                if e.downcast_ref::<SizeLimit>().is_some() {
                                    "SizeLimit"
                                } else {
                                    "Error"
                                },
                                &format!("{e:#}"),
                            )),
                        },
                    )
                })
                .for_each(|result| {
                    let Some(result) = result else {
                        return;
                    };
                    let mut s = state.lock().expect("entropy state");
                    if !matches!(&result, Err(r) if r.status == "EnumerationError") {
                        s.0.files_seen += 1;
                    }
                    match result {
                        Ok((text, Some(analysis), before, method)) => {
                            s.0.pe_analyzed += 1;
                            if analysis.candidate {
                                s.0.candidates += 1;
                            }
                            let status = if analysis.candidate {
                                "Candidate"
                            } else {
                                "BelowThreshold"
                            };
                            s.1.push(Observation {
                                computer: source.computer.clone(),
                                source_id: source.id.clone(),
                                relative_path: text,
                                method,
                                status: status.into(),
                                reason: String::new(),
                                analysis: Some(analysis),
                                fingerprint: Some(before),
                                observation_id: None,
                            });
                        }
                        Ok((_, None, _, _)) => s.0.non_pe += 1,
                        Err(row) => {
                            if row.status == "SizeLimit" {
                                s.0.skipped += 1;
                            } else {
                                s.0.errors += 1;
                            }
                            s.1.push(row);
                        }
                    }
                })
        });
    }
    progress.finish_and_clear();
    let (mut counts, mut observations) = state.into_inner().expect("entropy state");
    observations
        .sort_by(|a, b| (&a.source_id, &a.relative_path).cmp(&(&b.source_id, &b.relative_path)));
    let mut existing: BTreeMap<_, _> = plan
        .files
        .iter()
        .enumerate()
        .map(|(i, p)| {
            (
                (
                    p.source_id.clone(),
                    p.relative_path.clone(),
                    p.stream.clone(),
                ),
                i,
            )
        })
        .collect();
    for row in &mut observations {
        if matches!(
            row.status.as_str(),
            "Error" | "EnumerationError" | "SizeLimit"
        ) {
            plan.issues.push(Issue {
                source_id: row.source_id.clone(),
                path: row.relative_path.clone(),
                status: if row.status == "SizeLimit" {
                    "Unsupported"
                } else {
                    "Failed"
                }
                .into(),
                reason: format!("Entropy scan: {}", row.reason),
            });
            continue;
        }
        if row.status != "Candidate" {
            continue;
        }
        let analysis = row.analysis.as_ref().expect("candidate analysis");
        let relative = PathBuf::from(
            row.relative_path
                .replace('/', std::path::MAIN_SEPARATOR_STR),
        );
        let key = (row.source_id.clone(), relative.clone(), None);
        if let Some(&index) = existing.get(&key) {
            let file = &mut plan.files[index];
            if !file.artifacts.iter().any(|a| a == ARTIFACT) {
                file.artifacts.push(ARTIFACT.into());
            }
            file.expected_sha256 = Some(analysis.sha256.clone());
            row.observation_id = Some(file.id.clone());
            row.status = "AlreadyPlanned".into();
            continue;
        }
        let next = counts
            .selected_bytes
            .checked_add(analysis.size)
            .context("Entropy selection size overflow")?;
        if settings
            .max_candidates
            .is_some_and(|n| counts.selected_new >= n)
            || settings
                .max_collect_mib
                .is_some_and(|n| next > n * 1024 * 1024)
        {
            row.status = "SelectionLimit".into();
            row.reason = "Configured entropy collection limit reached; candidate not added".into();
            plan.issues.push(Issue {
                source_id: row.source_id.clone(),
                path: row.relative_path.clone(),
                status: "Unsupported".into(),
                reason: row.reason.clone(),
            });
            continue;
        }
        let source = plan
            .sources
            .iter()
            .find(|s| s.id == row.source_id)
            .expect("known source");
        let id = uuid::Uuid::new_v4().to_string();
        existing.insert(key, plan.files.len());
        plan.files.push(PlannedFile {
            id: id.clone(),
            source_id: row.source_id.clone(),
            source_path: source.root.join(&relative),
            relative_path: relative,
            stream: None,
            artifacts: vec![ARTIFACT.into()],
            before: row.fingerprint.clone(),
            expected_sha256: Some(analysis.sha256.clone()),
        });
        row.observation_id = Some(id);
        row.status = "Selected".into();
        counts.selected_new += 1;
        counts.selected_bytes = next;
    }
    for source in &plan.sources {
        let rows: Vec<_> = observations
            .iter()
            .filter(|r| r.source_id == source.id)
            .collect();
        let incomplete = rows.iter().any(|r| {
            matches!(
                r.status.as_str(),
                "Error" | "EnumerationError" | "SizeLimit" | "SelectionLimit"
            )
        });
        plan.coverage.push(Coverage{source_id:source.id.clone(),artifact_id:ARTIFACT.into(),discovered:rows.iter().filter(|r|r.observation_id.is_some()).count() as u64,status:if incomplete{"Partial"}else if source.metadata_only{"NotSelected"}else{"Discovered"}.into(),reason:"Entropy is a packing heuristic, not a malware verdict; scope and exclusions are recorded in the entropy report".into()});
    }
    plan.known_bytes = 0;
    plan.unknown_sizes = 0;
    for file in &plan.files {
        if let Some(before) = &file.before {
            plan.known_bytes = plan
                .known_bytes
                .checked_add(before.size)
                .context("Planned size overflow")?;
        } else {
            plan.unknown_sizes += 1;
        }
    }
    if !quiet {
        ui::field("PE files analyzed", counts.pe_analyzed);
        ui::field("High-entropy candidates", counts.candidates);
        ui::field("Additional binary files", counts.selected_new);
        ui::field("Entropy scan failures", counts.errors);
    }
    plan.entropy_scan = Some(Report {
        settings: settings.clone(),
        started_utc: started,
        finished_utc: utc_now(),
        counts,
        observations,
    });
    Ok(())
}

#[derive(Serialize)]
#[serde(rename_all = "PascalCase")]
struct Export<'a> {
    computer: &'a str,
    source_id: &'a str,
    relative_path: &'a str,
    method: &'a str,
    analysis_status: &'a str,
    reason: &'a str,
    size: Option<u64>,
    #[serde(rename = "SHA256")]
    sha256: Option<&'a str>,
    file_entropy: Option<f64>,
    max_executable_entropy: Option<f64>,
    machine: Option<&'a str>,
    #[serde(rename = "IsDLL")]
    is_dll: Option<bool>,
    has_certificate_table: Option<bool>,
    sections: String,
    observation_id: Option<&'a str>,
    acquisition_status: Option<&'a str>,
    #[serde(rename = "CollectedSHA256")]
    collected_sha256: Option<&'a str>,
    relative_output_path: Option<&'a str>,
    hash_matches_analysis: Option<bool>,
}
pub fn write_report(root: &Path, report: &Report, records: &[Record]) -> Result<()> {
    let new = |name: &str| -> Result<File> {
        Ok(OpenOptions::new()
            .write(true)
            .create_new(true)
            .open(root.join(name))?)
    };
    let mut csv = csv::WriterBuilder::new()
        .has_headers(false)
        .from_writer(new(FILES[0])?);
    let mut jsonl = BufWriter::new(new(FILES[1])?);
    let by_id: HashMap<_, _> = records.iter().map(|r| (&r.observation_id, r)).collect();
    // Explicit headers also preserve a usable report when there are no PE images/errors.
    csv.write_record([
        "Computer",
        "SourceId",
        "RelativePath",
        "Method",
        "AnalysisStatus",
        "Reason",
        "Size",
        "SHA256",
        "FileEntropy",
        "MaxExecutableEntropy",
        "Machine",
        "IsDLL",
        "HasCertificateTable",
        "Sections",
        "ObservationId",
        "AcquisitionStatus",
        "CollectedSHA256",
        "RelativeOutputPath",
        "HashMatchesAnalysis",
    ])?;
    for row in &report.observations {
        let a = row.analysis.as_ref();
        let record = row
            .observation_id
            .as_ref()
            .and_then(|id| by_id.get(id))
            .copied();
        let exported = Export {
            computer: &row.computer,
            source_id: &row.source_id,
            relative_path: &row.relative_path,
            method: &row.method,
            analysis_status: &row.status,
            reason: &row.reason,
            size: a.map(|a| a.size),
            sha256: a.map(|a| a.sha256.as_str()),
            file_entropy: a.map(|a| a.file_entropy),
            max_executable_entropy: a.and_then(|a| a.max_executable_entropy),
            machine: a.map(|a| a.machine.as_str()),
            is_dll: a.map(|a| a.is_dll),
            has_certificate_table: a.map(|a| a.has_certificate_table),
            sections: serde_json::to_string(&a.map(|a| &a.sections))?,
            observation_id: row.observation_id.as_deref(),
            acquisition_status: record.map(|r| r.status.as_str()),
            collected_sha256: record.and_then(|r| r.sha256.as_deref()),
            relative_output_path: record.and_then(|r| r.relative_output_path.as_deref()),
            hash_matches_analysis: record
                .and_then(|r| r.sha256.as_ref())
                .zip(a)
                .map(|(hash, a)| hash == &a.sha256),
        };
        csv.serialize(&exported)?;
        serde_json::to_writer(&mut jsonl, &exported)?;
        jsonl.write_all(b"\n")?;
    }
    csv.flush()?;
    jsonl.flush()?;
    crate::collect::write_json_new(
        &root.join(FILES[2]),
        &serde_json::json!({"Settings":report.settings,"StartedUTC":report.started_utc,"FinishedUTC":report.finished_utc,"Counts":report.counts,"Interpretation":"High entropy is not proof of packing or malware. Certificate-table presence is not signature validation. Only enumerated, readable unnamed PE streams are analyzed."}),
    )?;
    Ok(())
}

/// Conservative headroom for Plan.json plus CSV/JSONL/summary reports in an evidence container.
/// Counting serialization avoids allocating another copy of a drive-wide inventory.
pub fn metadata_reserve(plan: &Plan) -> Result<u64> {
    struct Counter(u64);
    impl Write for Counter {
        fn write(&mut self, bytes: &[u8]) -> std::io::Result<usize> {
            self.0 = self
                .0
                .checked_add(bytes.len() as u64)
                .ok_or_else(|| std::io::Error::other("Entropy metadata size overflow"))?;
            Ok(bytes.len())
        }
        fn flush(&mut self) -> std::io::Result<()> {
            Ok(())
        }
    }
    let Some(report) = &plan.entropy_scan else {
        return Ok(0);
    };
    let mut counter = Counter(0);
    serde_json::to_writer(&mut counter, report)?;
    counter
        .0
        .checked_mul(12)
        .and_then(|n| n.checked_add(1024 * 1024))
        .context("Entropy metadata reserve overflow")
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn raw_inspection_fallback_reads_without_temporary_extraction() {
        let t = tempfile::tempdir().unwrap();
        let mut source = discovery::directory_source(t.path(), "C", "HOST").unwrap();
        source.raw_device =
            Some(Path::new(env!("CARGO_MANIFEST_DIR")).join("tests/fixtures/ntfs-testfs1.img"));
        let relative = Path::new("file-with-12345");
        let (a, before, method) = inspect(
            &source,
            &source.root.join(relative),
            relative,
            &Settings::default(),
            &mut HashMap::new(),
        )
        .unwrap();
        assert!(a.is_none());
        assert_eq!(method, "RawNTFS");
        assert_eq!(before.size, 5);
        assert_eq!(std::fs::read_dir(t.path()).unwrap().count(), 0);
    }

    #[cfg(windows)]
    fn high_pe() -> Vec<u8> {
        let mut b = vec![0u8; 4608];
        b[..2].copy_from_slice(b"MZ");
        b[60..64].copy_from_slice(&128u32.to_le_bytes());
        b[128..132].copy_from_slice(b"PE\0\0");
        b[132..134].copy_from_slice(&0x14cu16.to_le_bytes());
        b[134..136].copy_from_slice(&1u16.to_le_bytes());
        b[148..150].copy_from_slice(&224u16.to_le_bytes());
        b[150..152].copy_from_slice(&2u16.to_le_bytes());
        b[152..154].copy_from_slice(&0x10bu16.to_le_bytes());
        b[376..381].copy_from_slice(b".text");
        b[392..396].copy_from_slice(&4096u32.to_le_bytes());
        b[396..400].copy_from_slice(&512u32.to_le_bytes());
        b[412..416].copy_from_slice(&0x60000020u32.to_le_bytes());
        for (i, v) in b[512..].iter_mut().enumerate() {
            *v = (i % 256) as u8;
        }
        b
    }
    #[cfg(windows)]
    #[test]
    fn locked_windows_pe_uses_raw_ntfs_and_agrees_with_file_api() {
        use std::os::windows::fs::OpenOptionsExt;
        crate::metadata::enable_privileges().unwrap();
        let t = tempfile::tempdir().unwrap();
        let path = t.path().join("entropy-fixture.dat");
        let mut file = OpenOptions::new()
            .write(true)
            .create_new(true)
            .open(&path)
            .unwrap();
        file.write_all(&high_pe()).unwrap();
        file.sync_all().unwrap();
        drop(file);
        let path = platform::canonicalize(&path).unwrap();
        let text = path
            .to_str()
            .unwrap()
            .strip_prefix(r"\\?\")
            .unwrap_or(path.to_str().unwrap());
        let drive = &text[..2];
        let mut source =
            discovery::directory_source(Path::new(&format!("{drive}\\")), "C", "HOST").unwrap();
        source.raw_device = Some(PathBuf::from(format!(r"\\.\{drive}")));
        let relative = path.strip_prefix(&source.root).unwrap();
        let (native, _, method) = inspect(
            &source,
            &path,
            relative,
            &Settings::default(),
            &mut HashMap::new(),
        )
        .unwrap();
        assert_eq!(method, "FileAPI");
        let lock = OpenOptions::new()
            .read(true)
            .share_mode(0)
            .open(&path)
            .unwrap();
        let (raw, _, method) = inspect(
            &source,
            &path,
            relative,
            &Settings::default(),
            &mut HashMap::new(),
        )
        .unwrap();
        assert_eq!(method, "RawNTFS");
        assert_eq!(
            raw.as_ref().unwrap().sha256,
            native.as_ref().unwrap().sha256
        );
        assert!(raw.unwrap().candidate);
        drop(lock);
    }
    #[cfg(windows)]
    #[test]
    fn native_ads_do_not_inherit_the_unnamed_stream_analysis_hash() {
        crate::metadata::enable_privileges().unwrap();
        let t = tempfile::tempdir().unwrap();
        let root = t.path().join("source");
        std::fs::create_dir(&root).unwrap();
        let path = root.join("test.dat");
        std::fs::write(&path, high_pe()).unwrap();
        std::fs::write(
            format!("{}:Zone.Identifier", path.display()),
            b"[ZoneTransfer]\r\nZoneId=3",
        )
        .unwrap();
        let source = discovery::directory_source(&root, "C", "HOST").unwrap();
        let rules=crate::catalog::Rules::load("SchemaVersion: 1\nArtifacts:\n - {Id: test, Name: Test, Category: Test, Patterns: ['absent']}").unwrap();
        let mut plan = discovery::build_plan(vec![source], &rules, &[], false).unwrap();
        augment_plan(
            &mut plan,
            &Settings::default(),
            &t.path().join("output"),
            2,
            true,
        )
        .unwrap();
        crate::metadata::augment_streams(&mut plan).unwrap();
        assert_eq!(plan.files.len(), 2);
        assert!(
            plan.files
                .iter()
                .filter(|f| f.stream.is_some())
                .all(|f| f.expected_sha256.is_none())
        );
        assert!(
            plan.files
                .iter()
                .filter(|f| f.stream.is_none())
                .all(|f| f.expected_sha256.is_some())
        );
    }
}
