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

//! Acquisition planning, bounded copying and evidence verification.

//! Interactive planning; no snapshots, scans or evidence output are created until confirmation.
use crate::{catalog::Rules, discovery, model::*, raw::RawVolume};
use anyhow::{Context, Result, ensure};
use std::{
    collections::{BTreeMap, HashMap, HashSet},
    io::{BufRead, Write},
    path::PathBuf,
};

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Output {
    Directory,
    Sftp,
    S3,
    Vhdx,
    E01,
}
#[derive(Clone, Debug)]
pub struct Choices {
    pub memory: bool,
    pub memory_bytes: Option<u64>,
    pub artifacts: Vec<String>,
    pub restrict_artifacts: bool,
    pub local_yara: bool,
    pub vss_available: bool,
    pub yara_available: bool,
    pub live_info: bool,
    pub vss: bool,
    pub entropy: bool,
    pub yara: bool,
    pub yara_ruleset: crate::yara_scan::RuleSet,
    pub output: Output,
    pub output_explicit: bool,
    pub threads: usize,
    pub image_source: Option<usize>,
}
#[derive(Clone, Copy, Default, Debug, PartialEq, Eq)]
pub struct Estimate {
    pub bytes: u64,
    pub unknown: u64,
    pub files: u64,
}
impl Estimate {
    pub fn label(self) -> String {
        let size = crate::collect::human_bytes(self.bytes).replace(' ', "");
        if self.unknown > 0 {
            format!("{size} known + {} unknown-size items", self.unknown)
        } else {
            size
        }
    }
}
/// File identities, not artifact totals, are counted once in the combined estimate.
pub struct Sizes(HashMap<String, Option<u64>>);
impl Sizes {
    pub fn discover(plan: &Plan) -> Self {
        let mut devices = HashMap::<PathBuf, Option<RawVolume>>::new();
        let mut sizes = HashMap::new();
        for file in &plan.files {
            let mut size = file.before.as_ref().map(|v| v.size);
            if size.is_none()
                && let Some(device) = plan
                    .sources
                    .iter()
                    .find(|s| s.id == file.source_id)
                    .and_then(|s| s.raw_device.as_ref())
            {
                let raw = devices
                    .entry(device.clone())
                    .or_insert_with(|| RawVolume::open(device).ok());
                if let Some(raw) = raw {
                    match raw.stat(&file.relative_path, file.stream.as_deref()) {
                        Ok(stat) => size = Some(stat.size),
                        Err(e) if crate::raw::is_missing(&e) => size = Some(0),
                        Err(_) => {}
                    }
                }
            }
            sizes.insert(file.id.clone(), size);
        }
        Self(sizes)
    }
    pub fn selected(&self, plan: &Plan, ids: &HashSet<String>) -> Result<Estimate> {
        let mut out = Estimate::default();
        for file in plan
            .files
            .iter()
            .filter(|f| f.artifacts.iter().any(|id| ids.contains(id)))
        {
            out.files += 1;
            match self.0.get(&file.id).copied().flatten() {
                Some(n) => {
                    out.bytes = out
                        .bytes
                        .checked_add(n)
                        .context("Transfer size estimate overflow")?
                }
                None => out.unknown += 1,
            }
        }
        Ok(out)
    }
}

pub fn default_artifacts(rules: &Rules, explicit: &[String], paging: bool) -> Vec<String> {
    if !explicit.is_empty() {
        let mut ids = explicit.to_vec();
        if paging
            && rules
                .catalog
                .artifacts
                .iter()
                .any(|d| d.id == "windows.paging")
            && !ids.iter().any(|id| id == "windows.paging")
        {
            ids.push("windows.paging".into());
        }
        return ids;
    }
    rules
        .catalog
        .artifacts
        .iter()
        // The broad paging family already includes hiberfil.sys. Keep the dedicated
        // hibernation family opt-in; --hibernation or an explicit ID selects it.
        .filter(|d| d.id != "windows.hibernation" && (paging || d.id != "windows.paging"))
        .map(|d| d.id.clone())
        .collect()
}
/// An empty explicit selection means no artifacts, whereas discovery's [] means all.
pub fn build_plan(
    sources: Vec<Source>,
    rules: &Rules,
    ids: &[String],
    memory: bool,
) -> Result<Plan> {
    if !ids.is_empty() {
        return discovery::build_plan(sources, rules, ids, memory);
    }
    let coverage = sources
        .iter()
        .flat_map(|source| {
            rules.catalog.artifacts.iter().map(move |d| Coverage {
                source_id: source.id.clone(),
                artifact_id: d.id.clone(),
                discovered: 0,
                status: "Excluded".into(),
                reason: "Not selected for collection".into(),
            })
        })
        .collect();
    Ok(Plan {
        schema_version: SCHEMA_VERSION,
        created_utc: utc_now(),
        catalog_sha256: rules.sha256.clone(),
        sources,
        files: vec![],
        coverage,
        issues: vec![],
        known_bytes: 0,
        unknown_sizes: 0,
        memory_requested: memory,
        entropy_scan: None,
    })
}

pub struct Prompt<R, W> {
    input: R,
    output: W,
}
impl<R: BufRead, W: Write> Prompt<R, W> {
    pub fn new(input: R, output: W) -> Self {
        Self { input, output }
    }
    fn line(&mut self, label: &str) -> Result<String> {
        // Catalog descriptions and volume labels are data, never terminal controls.
        let label: String = label
            .chars()
            .map(|c| if c.is_control() { '?' } else { c })
            .collect();
        write!(self.output, "{label}")?;
        self.output.flush()?;
        let mut line = String::new();
        ensure!(
            std::io::Read::take(&mut self.input, 4097).read_line(&mut line)? > 0,
            "Wizard input ended; collection was not started. Use --no-wizard for unattended collection"
        );
        ensure!(line.len() <= 4096, "Wizard answer is too long");
        let value = line.trim();
        ensure!(
            !matches!(value.to_ascii_lowercase().as_str(), "q" | "quit"),
            "Wizard cancelled; collection was not started"
        );
        Ok(value.to_owned())
    }
    pub fn yes(&mut self, label: &str, default: bool) -> Result<bool> {
        loop {
            let value = self.line(&format!(
                "{label} ({}): ",
                if default { "Y/n" } else { "y/N" }
            ))?;
            match value.to_ascii_lowercase().as_str() {
                "" => return Ok(default),
                "y" | "yes" => return Ok(true),
                "n" | "no" => return Ok(false),
                _ => writeln!(self.output, "Enter y, n, or q to cancel.")?,
            }
        }
    }
    fn number(&mut self, label: &str, default: usize, max: usize) -> Result<usize> {
        loop {
            let value = self.line(&format!("{label} [{default}]: "))?;
            if value.is_empty() {
                return Ok(default);
            }
            if let Ok(n) = value.parse::<usize>()
                && (1..=max).contains(&n)
            {
                return Ok(n);
            }
            writeln!(self.output, "Enter a number from 1 through {max}.")?;
        }
    }
}
fn display_category(s: &str) -> &str {
    match s {
        "EventLogs" => "Windows event logs",
        "Registry" => "Registry hives",
        "FileExistence" => "File existence artifacts",
        "FileSystem" => "NTFS and file system artifacts",
        "ProcessExecution" => "Process execution artifacts",
        "FileAndFolderOpening" => "File and folder opening artifacts",
        "SecurityProducts" => "Security product artifacts",
        "BrowserActivity" => "Browser artifacts",
        "ServerRoles" => "Server role artifacts",
        "OperatingSystem" => "Operating system logs",
        "Paging" => "Paging, swap, hibernation and existing memory dumps",
        "Hibernation" => "Hibernation file only (hiberfil.sys)",
        "Memory" => "Other memory artifacts",
        _ => s,
    }
}

pub fn run<R: BufRead, W: Write>(
    prompt: &mut Prompt<R, W>,
    plan: &Plan,
    rules: &Rules,
    sizes: &Sizes,
    mut choices: Choices,
    windows: bool,
    live: bool,
) -> Result<Choices> {
    writeln!(
        prompt.output,
        "\nCollection wizard (Enter accepts the default; q cancels)"
    )?;
    writeln!(
        prompt.output,
        "Sizes are estimated logical input bytes, not allocated/compressed output. Groups can overlap; the final total counts each file once."
    )?;
    writeln!(
        prompt.output,
        "{}",
        if choices.output == Output::S3 {
            "Raw locked-file fallback and SHA-256: enabled. Verify the S3 collection with verify-s3."
        } else if choices.output == Output::Sftp {
            "Raw locked-file fallback and SHA-256: enabled. SFTP delivery requires separate trusted server readback verification."
        } else {
            "Raw locked-file fallback, SHA-256 and copied-file verification: enabled (required)."
        }
    )?;
    writeln!(
        prompt.output,
        "Physical RAM: opt-in with DumpIt; active pagefiles are copied concurrently by default (--no-memory-pagefile to skip). Hibernation can be selected separately; the broad Paging group also includes it."
    )?;
    if windows
        && live
        && !choices.output_explicit
        && prompt.yes(
            "Full partition imaging instead of artifact collection",
            false,
        )?
    {
        // Historical copies contribute artifact sizes, but are not live partition
        // choices. Keep the original plan index separate from the menu number.
        let image_sources: Vec<_> = plan
            .sources
            .iter()
            .enumerate()
            .filter(|(_, source)| source.snapshot.is_none())
            .collect();
        for (i, (_, source)) in image_sources.iter().enumerate() {
            let label = fs2::total_space(&source.root)
                .map(|b| crate::collect::human_bytes(b).replace(' ', ""))
                .unwrap_or_else(|_| "unknown size".into());
            writeln!(
                prompt.output,
                "  {}. {} ({} estimated)",
                i + 1,
                source.id,
                label
            )?;
        }
        ensure!(
            !image_sources.is_empty(),
            "No source volumes available for imaging"
        );
        let menu_index = prompt.number("Source volume", 1, image_sources.len())? - 1;
        let index = image_sources[menu_index].0;
        choices.vss = if choices.vss_available {
            prompt.yes(
                "VSS for partition imaging (snapshot growth unknown)",
                choices.vss,
            )?
        } else {
            false
        };
        choices.image_source = Some(index);
        let size = fs2::total_space(&plan.sources[index].root)
            .map(crate::collect::human_bytes)
            .unwrap_or_else(|_| "unknown size".into());
        writeln!(
            prompt.output,
            "Estimated partition transfer: {size}; normal artifact collection will not run."
        )?;
        ensure!(prompt.yes("Start full partition imaging to the selected destination (requires a different external disk)",true)?,"Wizard cancelled; collection was not started");
        return Ok(choices);
    }
    let selected: HashSet<_> = choices.artifacts.iter().cloned().collect();
    let mut categories = BTreeMap::<String, Vec<String>>::new();
    for d in &rules.catalog.artifacts {
        if choices.restrict_artifacts && !selected.contains(&d.id) {
            continue;
        }
        categories
            .entry(match d.id.as_str() {
                "windows.paging" => "Paging".into(),
                "windows.hibernation" => "Hibernation".into(),
                _ => d.category.clone(),
            })
            .or_default()
            .push(d.id.clone());
    }
    choices.artifacts.clear();
    for (category, ids) in categories {
        let set = ids.iter().cloned().collect();
        let estimate = sizes.selected(plan, &set)?;
        let label = format!(
            "{} ({}; {} files/streams)",
            display_category(&category),
            estimate.label(),
            estimate.files
        );
        if prompt.yes(&label, ids.iter().any(|id| selected.contains(id)))? {
            choices.artifacts.extend(ids);
        }
    }
    let total = sizes.selected(plan, &choices.artifacts.iter().cloned().collect())?;
    if windows && live {
        choices.memory = prompt.yes(
            &format!(
                "Physical RAM ({} plus active pagefiles by default; requires DumpIt, captured first)",
                choices
                    .memory_bytes
                    .map(crate::collect::human_bytes)
                    .unwrap_or_else(|| "size unknown".into())
            ),
            choices.memory,
        )?;
        choices.live_info = prompt.yes(
            "Live system inventory (output size unknown; two query workers)",
            choices.live_info,
        )?;
        choices.vss = if choices.vss_available {
            prompt.yes(
                &format!(
                    "VSS ({} selected evidence; snapshot growth unknown)",
                    total.label()
                ),
                choices.vss,
            )?
        } else {
            writeln!(
                prompt.output,
                "VSS: unavailable with this binary/host architecture"
            )?;
            false
        };
        choices.yara = if choices.yara_available {
            prompt.yes(
                "Process-memory YARA scan (output size unknown; two scan workers)",
                choices.yara,
            )?
        } else {
            writeln!(
                prompt.output,
                "Process-memory YARA: unavailable with this binary/host architecture"
            )?;
            false
        };
        if choices.yara && !choices.local_yara {
            writeln!(
                prompt.output,
                "YARA Forge: 1. Core  2. Extended  3. Full (matching bundled pack uses no network)"
            )?;
            let default = match choices.yara_ruleset {
                crate::yara_scan::RuleSet::Core => 1,
                crate::yara_scan::RuleSet::Extended => 2,
                crate::yara_scan::RuleSet::Full => 3,
            };
            choices.yara_ruleset = match prompt.number("Rule package", default, 3)? {
                1 => crate::yara_scan::RuleSet::Core,
                2 => crate::yara_scan::RuleSet::Extended,
                _ => crate::yara_scan::RuleSet::Full,
            };
        }
    } else {
        choices.live_info = false;
        choices.vss = false;
        choices.yara = false;
        writeln!(
            prompt.output,
            "Live inventory, VSS and process-memory YARA: unavailable for offline sources."
        )?;
    }
    choices.entropy = prompt.yes(
        "High-entropy PE scan (additional transfer size unknown until analysis)",
        choices.entropy,
    )?;
    if windows && !choices.output_explicit {
        choices.output = if prompt.yes(
            &format!(
                "VHDX output ({} input; native NTFS metadata)",
                total.label()
            ),
            false,
        )? {
            Output::Vhdx
        } else if prompt.yes(
            &format!(
                "E01 output ({} input; compressed size unknown)",
                total.label()
            ),
            false,
        )? {
            Output::E01
        } else {
            Output::Directory
        };
    }
    choices.threads = prompt.number("Acquisition workers", choices.threads, 128)?;
    writeln!(
        prompt.output,
        "Estimated transfer: {} / {} files/streams, plus inventory, reports, additional ADS and any entropy candidates.",
        total.label(),
        total.files
    )?;
    writeln!(
        prompt.output,
        "Output: {:?}. VSS is crash-consistent, not application-consistent.",
        choices.output
    )?;
    ensure!(
        !choices.artifacts.is_empty()
            || choices.entropy
            || choices.live_info
            || choices.yara
            || choices.memory,
        "Nothing selected for collection"
    );
    ensure!(
        prompt.yes("Start collection", true)?,
        "Wizard cancelled; collection was not started"
    );
    Ok(choices)
}
