// Copyright (C) 2026 Shirofune Security Co., Ltd.
// SPDX-License-Identifier: RPL-1.5
//! Read-only discovery and selection of existing local VSS snapshots.
use crate::{
    model::{Issue, Source, SourceDiscovery},
    vss::Snapshot,
};
use anyhow::{Context, Result, ensure};
use serde::Serialize;
use std::{
    collections::{BTreeMap, HashSet},
    fmt,
    fs::{self, OpenOptions},
    io::{BufWriter, Write},
    path::{Path, PathBuf},
    str::FromStr,
};

#[derive(Clone, Debug, PartialEq, Eq)]
pub enum Selection {
    All,
    Newest(usize),
    Id(uuid::Uuid),
}
impl FromStr for Selection {
    type Err = String;
    fn from_str(value: &str) -> std::result::Result<Self, Self::Err> {
        match value.to_ascii_lowercase().as_str() {
            "all" => return Ok(Self::All),
            "newest" => return Ok(Self::Newest(1)),
            _ => {}
        }
        if let Ok(n) = value.parse::<usize>()
            && n > 0
        {
            return Ok(Self::Newest(n));
        }
        if let Ok(id) = uuid::Uuid::parse_str(value)
            && !id.is_nil()
        {
            return Ok(Self::Id(id));
        }
        Err("Use all, newest, a positive count per volume, or a snapshot GUID (example: --vss-existing newest)".into())
    }
}
impl fmt::Display for Selection {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::All => write!(f, "all"),
            Self::Newest(1) => write!(f, "newest"),
            Self::Newest(n) => write!(f, "{n}"),
            Self::Id(id) => write!(f, "{id}"),
        }
    }
}
fn volume_key(value: &str) -> String {
    value.trim_end_matches('\\').to_ascii_lowercase()
}

#[cfg(windows)]
fn local_volume_identity(path: &Path) -> Result<Option<String>> {
    crate::platform::volume_identity(path)
}
#[cfg(not(windows))]
fn local_volume_identity(_path: &Path) -> Result<Option<String>> {
    anyhow::bail!("Existing VSS access requires native elevated Windows")
}

/// Newest N applies independently to each source volume. Ties are stable by GUID.
pub fn select(snapshots: &[Snapshot], selection: &Selection) -> Result<Vec<Snapshot>> {
    let mut ids = HashSet::new();
    let mut groups =
        BTreeMap::<String, Vec<(chrono::DateTime<chrono::FixedOffset>, &Snapshot)>>::new();
    for snapshot in snapshots {
        let id = uuid::Uuid::parse_str(&snapshot.snapshot_id).context("Invalid VSS snapshot ID")?;
        ensure!(
            !id.is_nil() && ids.insert(id),
            "Duplicate or nil VSS snapshot ID"
        );
        let created = chrono::DateTime::parse_from_rfc3339(&snapshot.created_utc)
            .context("Invalid VSS creation timestamp")?;
        groups
            .entry(volume_key(&snapshot.original_volume))
            .or_default()
            .push((created, snapshot));
    }
    let mut result = Vec::new();
    for mut group in groups.into_values() {
        group.sort_by(|a, b| {
            b.0.cmp(&a.0)
                .then_with(|| a.1.snapshot_id.cmp(&b.1.snapshot_id))
        });
        for (_, snapshot) in group
            .into_iter()
            .filter(|(_, s)| match selection {
                Selection::Id(id) => {
                    uuid::Uuid::parse_str(&s.snapshot_id).ok().as_ref() == Some(id)
                }
                _ => true,
            })
            .take(match selection {
                Selection::Newest(n) => *n,
                _ => usize::MAX,
            })
        {
            result.push(snapshot.clone());
        }
    }
    if matches!(selection, Selection::Id(_)) {
        ensure!(
            !result.is_empty(),
            "Requested VSS snapshot does not exist in the selected source volumes"
        );
    }
    Ok(result)
}

/// Output components contain a complete UUID, so snapshots at the same time cannot collide.
pub fn source_id(original: &str, snapshot: &Snapshot) -> Result<String> {
    let id = uuid::Uuid::parse_str(&snapshot.snapshot_id)?;
    ensure!(!id.is_nil(), "Nil snapshot ID");
    let time =
        chrono::DateTime::parse_from_rfc3339(&snapshot.created_utc)?.with_timezone(&chrono::Utc);
    let id = format!("{original}-VSS-{}-{id}", time.format("%Y%m%dT%H%M%SZ"));
    crate::paths::output_relative(&id, Path::new("probe"), None)?;
    Ok(id)
}

/// Matching is against original volume GUIDs, never device numbers or drive-letter guesses.
pub fn prepare(current: &[Source], selection: &Selection) -> Result<SourceDiscovery> {
    let snapshots = crate::vss::list_existing()?;
    let mapping = current
        .iter()
        .map(|source| {
            Ok((
                local_volume_identity(&source.root)?.context("Live source has no local volume")?,
                source,
            ))
        })
        .collect::<Result<Vec<_>>>()?;
    let matching: Vec<_> = snapshots
        .into_iter()
        .filter(|s| {
            mapping
                .iter()
                .any(|(volume, _)| volume_key(volume) == volume_key(&s.original_volume))
        })
        .collect();
    let selected = select(&matching, selection)?;
    let mut result = SourceDiscovery::default();
    for snapshot in selected {
        let source = mapping
            .iter()
            .find(|(volume, _)| volume_key(volume) == volume_key(&snapshot.original_volume))
            .context("Historical snapshot has no selected source volume")?
            .1;
        let id = source_id(&source.id, &snapshot)?;
        let root = match crate::vss::snapshot_device_root(&snapshot.device_object) {
            Ok(root) => root,
            Err(error) => {
                result.issues.push(Issue {
                    source_id: id,
                    path: snapshot.device_object.display().to_string(),
                    status: "Error".into(),
                    reason: format!(
                        "Historical snapshot {} ({}) has no supported local read device: {error:#}",
                        snapshot.snapshot_id, snapshot.created_utc
                    ),
                });
                continue;
            }
        };
        // Preserve provenance even when a snapshot disappears or its root cannot be opened.
        let mut historical = match crate::discovery::scoped_directory_source(
            &root,
            &id,
            &source.computer,
            source.metadata_only,
        ) {
            Ok(source) => source,
            Err(error) => {
                result.issues.push(Issue {
                    source_id: id.clone(),
                    path: root.display().to_string(),
                    status: "Error".into(),
                    reason: format!("Cannot inspect historical VSS snapshot: {error:#}"),
                });
                Source {
                    id,
                    root: root.clone(),
                    computer: source.computer.clone(),
                    live: false,
                    raw_device: None,
                    profile_roots: vec![],
                    excluded_profiles: vec![],
                    metadata_only: source.metadata_only,
                    snapshot: None,
                }
            }
        };
        historical.raw_device = source
            .raw_device
            .as_ref()
            .map(|_| snapshot.device_object.clone());
        let mut snapshot = snapshot;
        snapshot.original_root = source.root.clone();
        historical.snapshot = Some(snapshot);
        result.sources.push(historical);
    }
    Ok(result)
}

#[derive(clap::Args, Clone, Debug)]
pub struct ListOptions {
    /// Filter by local source volume; repeat for multiple volumes
    #[arg(long = "volume", value_name = "VOLUME")]
    pub volumes: Vec<String>,
    /// Write a fresh CSV/JSON/JSONL file (otherwise display a table)
    #[arg(short, long, value_name = "FILE")]
    pub output: Option<PathBuf>,
    /// Structured output format; without -o write structured rows to stdout
    #[arg(short = 't', long, value_enum)]
    pub format: Option<crate::live_info::Format>,
    /// Hide the banner and summary
    #[arg(short, long)]
    pub quiet: bool,
}

#[derive(Clone, Debug, Serialize)]
#[serde(rename_all = "PascalCase")]
pub struct Listing {
    pub snapshot_id: String,
    pub snapshot_set_id: String,
    pub original_volume: String,
    pub volume_paths: String,
    pub created_utc: String,
    pub device_object: String,
    pub provider_id: String,
    pub attributes: i32,
    pub root_readable: bool,
}
pub fn listings(snapshots: &[Snapshot]) -> Result<Vec<Listing>> {
    let selected = select(snapshots, &Selection::All)?;
    selected
        .into_iter()
        .map(|s| {
            let root = crate::vss::snapshot_device_root(&s.device_object).ok();
            Ok(Listing {
                snapshot_id: s.snapshot_id,
                snapshot_set_id: s.snapshot_set_id,
                volume_paths: volume_paths(&s.original_volume).join(";"),
                original_volume: s.original_volume,
                created_utc: s.created_utc,
                device_object: s.device_object.display().to_string(),
                provider_id: s.provider_id,
                attributes: s.attributes,
                root_readable: root.is_some_and(|root| fs::read_dir(root).is_ok()),
            })
        })
        .collect()
}
#[cfg(not(windows))]
fn volume_paths(_volume: &str) -> Vec<String> {
    vec![]
}
#[cfg(windows)]
fn volume_paths(volume: &str) -> Vec<String> {
    use std::os::windows::ffi::OsStrExt;
    use windows_sys::Win32::Storage::FileSystem::GetVolumePathNamesForVolumeNameW;
    let volume: Vec<u16> = std::ffi::OsStr::new(volume)
        .encode_wide()
        .chain(Some(0))
        .collect();
    let mut needed = 0;
    // SAFETY: live terminated input and output length; null buffer requests its size.
    unsafe {
        GetVolumePathNamesForVolumeNameW(volume.as_ptr(), std::ptr::null_mut(), 0, &mut needed)
    };
    if needed == 0 || needed > 65536 {
        return vec![];
    }
    let mut buffer = vec![0u16; needed as usize];
    // SAFETY: the owned buffer covers its declared size and outputs stay live.
    if unsafe {
        GetVolumePathNamesForVolumeNameW(volume.as_ptr(), buffer.as_mut_ptr(), needed, &mut needed)
    } == 0
    {
        return vec![];
    }
    buffer
        .split(|c| *c == 0)
        .filter(|s| !s.is_empty())
        .filter_map(|s| String::from_utf16(s).ok())
        .collect()
}

pub fn write_listing(
    writer: impl Write,
    rows: &[Listing],
    format: crate::live_info::Format,
) -> Result<()> {
    use crate::live_info::Format;
    match format {
        Format::Csv => {
            let mut writer = csv::WriterBuilder::new()
                .has_headers(false)
                .from_writer(writer);
            writer.write_record([
                "SnapshotId",
                "SnapshotSetId",
                "OriginalVolume",
                "VolumePaths",
                "CreatedUtc",
                "DeviceObject",
                "ProviderId",
                "Attributes",
                "RootReadable",
            ])?;
            for row in rows {
                writer.serialize(row)?;
            }
            writer.flush()?;
        }
        Format::Json => {
            let mut writer = writer;
            serde_json::to_writer_pretty(&mut writer, rows)?;
            writeln!(writer)?;
            writer.flush()?;
        }
        Format::Jsonl => {
            let mut writer = writer;
            for row in rows {
                serde_json::to_writer(&mut writer, row)?;
                writeln!(writer)?;
            }
            writer.flush()?;
        }
    }
    Ok(())
}
pub fn run(options: &ListOptions) -> Result<u8> {
    let mut snapshots = crate::vss::list_existing()?;
    if !options.volumes.is_empty() {
        let selected = options
            .volumes
            .iter()
            .map(|volume| {
                local_volume_identity(&crate::vss::volume_identifier(volume)?)?
                    .context("Selected volume is unavailable")
            })
            .collect::<Result<Vec<_>>>()?;
        snapshots.retain(|s| {
            selected
                .iter()
                .any(|v| volume_key(v) == volume_key(&s.original_volume))
        });
    }
    let rows = listings(&snapshots)?;
    if let Some(path) = &options.output {
        let format = options
            .format
            .unwrap_or(match path.extension().and_then(|e| e.to_str()) {
                Some("json") => crate::live_info::Format::Json,
                Some("jsonl") => crate::live_info::Format::Jsonl,
                _ => crate::live_info::Format::Csv,
            });
        let file = OpenOptions::new()
            .write(true)
            .create_new(true)
            .open(path)
            .context("Cannot create fresh snapshot listing")?;
        write_listing(BufWriter::new(file), &rows, format)?;
        if !options.quiet {
            crate::ui::banner();
            crate::ui::field("Snapshots", rows.len());
            crate::ui::field("Results saved", path.display());
        }
    } else if let Some(format) = options.format {
        write_listing(std::io::stdout().lock(), &rows, format)?;
    } else {
        if !options.quiet {
            crate::ui::banner();
        }
        crate::ui::heading("Volume / CreatedUtc / SnapshotId / Readable / Device");
        for row in &rows {
            crate::ui::status(&format!(
                "{} / {} / {} / {} / {}",
                if row.volume_paths.is_empty() {
                    &row.original_volume
                } else {
                    &row.volume_paths
                },
                row.created_utc,
                row.snapshot_id,
                row.root_readable,
                row.device_object
            ));
        }
        if !options.quiet {
            crate::ui::field("Snapshots", rows.len());
        }
    }
    Ok(0)
}
