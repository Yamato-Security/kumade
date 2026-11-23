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

//! Lossless source metadata inventory and native restoration for VHDX output.
use crate::{model::*, paths, raw::RawVolume};
use anyhow::{Context, Result, ensure};
use serde::{Deserialize, Serialize};
use std::{
    collections::{BTreeMap, BTreeSet, HashMap},
    io::{BufWriter, Write},
    path::{Path, PathBuf},
};

#[cfg(windows)]
#[path = "metadata_windows.rs"]
mod windows;
#[cfg(windows)]
pub use windows::{augment_streams, enable_privileges, file_identity, usn_journal_live_bytes};

pub const FILES: [&str; 2] = ["NTFS-Metadata.jsonl", "NTFS-Metadata.csv"];

/// Recorded for objects whose metadata can only come from the raw NTFS reader.
pub const RAW_BASIC_NOTE: &str = "NTFS system file: Windows does not expose it to file APIs; \
    basic times, attributes and the file reference were read from the raw $STANDARD_INFORMATION, \
    and no security descriptor or extended attributes are captured";
/// A file Windows refuses to open even for its metadata (an in-use `pagefile.sys`
/// or `hiberfil.sys`): the raw reader is the only source of its basic information.
pub const RAW_OPEN_REFUSED_NOTE: &str = "Windows refused to open the file for metadata; \
    basic times, attributes and the file reference were read from the raw $STANDARD_INFORMATION, \
    and no security descriptor or extended attributes are captured";

#[derive(Clone, Debug, Default, Serialize, Deserialize)]
#[serde(rename_all = "PascalCase")]
pub struct Snapshot {
    pub source_id: String,
    pub source_path: String,
    pub relative_output_path: String,
    pub directory: bool,
    pub captured_utc: String,
    pub creation_filetime: Option<i64>,
    pub access_filetime: Option<i64>,
    pub write_filetime: Option<i64>,
    pub change_filetime: Option<i64>,
    pub attributes: Option<u32>,
    pub source_file_id: Option<String>,
    pub security_descriptor_hex: Option<String>,
    pub sddl: Option<String>,
    pub extended_attributes_hex: Option<String>,
    pub capture_status: String,
    pub restore_status: String,
    pub problems: String,
    /// Known Windows normalizations and capture limits that are not errors.
    #[serde(default)]
    pub notes: String,
}

pub fn output_relative(source: &str, relative: &Path, stream: Option<&str>) -> Result<PathBuf> {
    let mut path = PathBuf::from(paths::encode_component(source));
    if !relative.as_os_str().is_empty() {
        for part in paths::relative_text(relative)?.split('/') {
            let encoded = paths::encode_component(part);
            ensure!(
                encoded.encode_utf16().count() <= 255,
                "Encoded NTFS filename exceeds 255 characters"
            );
            path.push(encoded);
        }
    }
    if let Some(stream) = stream {
        ensure!(!stream.is_empty(), "Empty data stream name");
        let leaf = path
            .file_name()
            .context("Stream has no base filename")?
            .to_str()
            .context("Invalid output filename")?;
        let name = paths::encode_component(stream);
        path.set_file_name(format!("{leaf}:{name}"));
    }
    Ok(path)
}

/// Typed ADS paths are accepted only when the sealed record declares that stream.
/// Metadata filenames and ordinary payload paths continue to use strict safe_join.
pub fn payload_path(root: &Path, relative: &str, stream: Option<&str>) -> Result<PathBuf> {
    let Some((base, name)) = relative.rsplit_once(':') else {
        return paths::safe_join(root, relative);
    };
    ensure!(
        cfg!(windows),
        "Native NTFS stream verification requires Windows"
    );
    let stream = stream.context("Undeclared alternate data stream")?;
    ensure!(
        name == paths::encode_component(stream) && !name.is_empty(),
        "Stream path/name mismatch"
    );
    let base = paths::safe_join(root, base)?;
    ensure!(
        crate::platform::open_source(&base)?.metadata()?.is_file(),
        "Stream base is not a regular file"
    );
    Ok(PathBuf::from(format!("{}:{name}", base.display())))
}

struct Target {
    source: PathBuf,
    output: PathBuf,
    directory: bool,
    /// Every planned item under this path is a raw-only candidate (no
    /// planning-time metadata), e.g. an NTFS system file or `$Extend`.
    raw_only: bool,
    device: Option<PathBuf>,
}

type RawVolumes = HashMap<PathBuf, Option<RawVolume>>;

pub(crate) fn prepare(plan: &Plan, files: &[&PlannedFile]) -> Vec<Snapshot> {
    // Include each collected file's containing directories exactly once. Capture
    // these before payload writes and restore deepest first after all children.
    let mut targets = BTreeMap::<(String, PathBuf), Target>::new();
    for item in files {
        let Some(source) = plan.sources.iter().find(|s| s.id == item.source_id) else {
            continue;
        };
        let output = match output_relative(&source.id, &item.relative_path, None) {
            Ok(v) => v,
            Err(_) => continue, // The acquisition reports this invalid planned path.
        };
        let raw = item.before.is_none();
        targets
            .entry((source.id.clone(), item.relative_path.clone()))
            .and_modify(|t| t.raw_only &= raw)
            .or_insert(Target {
                source: item.source_path.clone(),
                output,
                directory: false,
                raw_only: raw,
                device: source.raw_device.clone(),
            });
        let mut relative = item.relative_path.parent();
        while let Some(parent) = relative {
            // Long-path exports have no corresponding source directory tree.
            if let Ok(output) = output_relative(&source.id, parent, None) {
                targets
                    .entry((source.id.clone(), parent.to_owned()))
                    .and_modify(|t| t.raw_only &= raw)
                    .or_insert(Target {
                        source: source.root.join(parent),
                        output,
                        directory: true,
                        raw_only: raw,
                        device: source.raw_device.clone(),
                    });
            }
            relative = parent.parent();
        }
    }
    let mut volumes = RawVolumes::new();
    targets
        .into_iter()
        .map(|((source_id, relative), target)| {
            let mut record = Snapshot {
                source_id,
                source_path: target.source.display().to_string(),
                relative_output_path: paths::relative_text(&target.output).unwrap_or_default(),
                directory: target.directory,
                captured_utc: utc_now(),
                capture_status: "Failed".into(),
                restore_status: "Pending".into(),
                ..Default::default()
            };
            #[cfg(windows)]
            match windows::capture(&target.source, &mut record) {
                Ok(()) => record.capture_status = "Captured".into(),
                Err(error) => capture_failed(&mut record, target.raw_only, &error, |record| {
                    target
                        .device
                        .as_deref()
                        .is_some_and(|device| raw_capture(&mut volumes, device, &relative, record))
                }),
            }
            #[cfg(not(windows))]
            {
                let _ = (&relative, &mut volumes, target.raw_only, &target.device);
                record.problems = "Native NTFS metadata capture requires Windows".into();
            }
            record
        })
        .collect()
}

/// Marks failures at the metadata-open stage, rather than failures while reading
/// identity, ACLs or extended attributes from an already open file.
#[cfg(any(windows, test))]
#[derive(Debug)]
struct MetadataOpenFailed;

#[cfg(any(windows, test))]
impl std::fmt::Display for MetadataOpenFailed {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str("Windows metadata open failed")
    }
}

#[cfg(any(windows, test))]
fn capture_failed(
    record: &mut Snapshot,
    raw_only: bool,
    error: &anyhow::Error,
    raw: impl FnOnce(&mut Snapshot) -> bool,
) {
    // Only an open failure permits this downgrade. Later failures must retain
    // metadata already captured and stay visible in the metadata-error count.
    if error.is::<MetadataOpenFailed>() && raw(record) {
        record.capture_status = "RawBasic".into();
        record.notes = if raw_only {
            RAW_BASIC_NOTE.into()
        } else {
            format!("{RAW_OPEN_REFUSED_NOTE}: {error:#}")
        };
    } else {
        if record.attributes.is_some() {
            record.capture_status = "Partial".into();
        }
        record.problems = format!("Capture: {error:#}");
    }
}

#[cfg(windows)]
fn raw_capture(
    volumes: &mut RawVolumes,
    device: &Path,
    relative: &Path,
    record: &mut Snapshot,
) -> bool {
    let Some(volume) = volumes
        .entry(device.to_owned())
        .or_insert_with(|| RawVolume::open(device).ok())
        .as_mut()
    else {
        return false;
    };
    let Ok(stat) = volume.stat(relative, None) else {
        return false;
    };
    record.creation_filetime = Some(stat.created as i64);
    record.access_filetime = Some(stat.accessed as i64);
    record.write_filetime = Some(stat.modified as i64);
    record.change_filetime = Some(stat.changed as i64);
    record.attributes = Some(stat.attributes);
    record.source_file_id = Some(stat.identity);
    record.security_descriptor_hex = None;
    record.sddl = None;
    record.extended_attributes_hex = None;
    true
}

/// The USN journal's `$J` stream: NTFS keeps it allocated well beyond the
/// written records, so its allocated size overstates what a sparse-aware copy
/// stores.
pub fn is_usn_journal(relative: &Path, stream: Option<&str>) -> bool {
    relative
        .to_string_lossy()
        .replace('\\', "/")
        .eq_ignore_ascii_case("$Extend/$UsnJrnl")
        && stream.is_some_and(|s| s.eq_ignore_ascii_case("$J"))
}

/// What the raw NTFS provider knows about the raw-only plan items before the
/// container exists.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub struct RawSizes {
    /// Bytes now known: the allocated size of sparse streams, which are copied
    /// sparsely, bounded by the live journal range for `$UsnJrnl:$J`; zero for
    /// legitimately absent objects.
    pub known: u64,
    /// Items whose size stays unknown.
    pub unknown: u64,
    /// The largest logical stream size. A sparse copy keeps that size, and an
    /// NTFS reader such as The Sleuth Kit rejects a run longer than the volume,
    /// so the container must be at least this large to stay readable.
    pub largest_stream: u64,
}

/// Sizes of raw-only plan items, read from the raw NTFS provider so that a
/// container can be sized before it is created.
pub fn raw_candidate_sizes(plan: &Plan) -> RawSizes {
    let mut volumes = RawVolumes::new();
    let mut journals = HashMap::<PathBuf, Option<u64>>::new();
    let mut sizes = RawSizes::default();
    for item in plan.files.iter().filter(|f| f.before.is_none()) {
        let size = plan
            .sources
            .iter()
            .find(|s| s.id == item.source_id)
            .and_then(|s| s.raw_device.as_deref())
            .and_then(|device| {
                let volume = volumes
                    .entry(device.to_owned())
                    .or_insert_with(|| RawVolume::open(device).ok())
                    .as_mut()?;
                match volume.stat(&item.relative_path, item.stream.as_deref()) {
                    Ok(stat) if stat.attributes & 0x200 != 0 => {
                        sizes.largest_stream = sizes.largest_stream.max(stat.size);
                        let mut bytes = stat.allocated;
                        if is_usn_journal(&item.relative_path, item.stream.as_deref()) {
                            let live = journals.entry(device.to_owned()).or_insert_with(|| {
                                #[cfg(windows)]
                                {
                                    usn_journal_live_bytes(device)
                                }
                                #[cfg(not(windows))]
                                {
                                    None
                                }
                            });
                            if let Some(live) = *live {
                                bytes = bytes.min(live);
                            }
                        }
                        Some(bytes)
                    }
                    Ok(stat) => {
                        sizes.largest_stream = sizes.largest_stream.max(stat.size);
                        Some(stat.size.max(stat.allocated))
                    }
                    Err(error) if crate::raw::is_missing(&error) => Some(0),
                    Err(_) => None,
                }
            });
        match size {
            Some(bytes) => sizes.known = sizes.known.saturating_add(bytes),
            None => sizes.unknown += 1,
        }
    }
    sizes
}

fn same_identity(captured: Option<&str>, acquired: Option<&str>) -> bool {
    let (Some(captured), Some(acquired)) = (captured, acquired) else {
        return false;
    };
    if captured == acquired {
        return true;
    }
    if acquired.starts_with("ntfs:")
        && let Some(index) = captured
            .strip_prefix("win:")
            .and_then(|s| s.split_once(':'))
            .and_then(|(_, i)| u64::from_str_radix(i, 16).ok())
    {
        return acquired == format!("ntfs:{}:{}", index & 0x0000_ffff_ffff_ffff, index >> 48);
    }
    false
}

/// Keep remote metadata as an inventory, and bind file generations without
/// pretending to have restored permissions or independently verified payloads.
pub(crate) fn remote_inventory(snapshots: &mut [Snapshot], records: &[Record]) -> usize {
    let mut files = HashMap::<(&str, &str), Vec<&Record>>::new();
    let mut directories = BTreeSet::new();
    // As in local restoration, only a streamed payload (acknowledged or
    // partial) binds a metadata row; failed and absent candidates have no
    // payload to bind, so their rows are inventory without a payload.
    for record in records.iter().filter(|r| {
        r.relative_output_path.is_some() && matches!(r.status.as_str(), "Transferred" | "Partial")
    }) {
        files
            .entry((&record.source_id, &record.source_path))
            .or_default()
            .push(record);
        for parent in Path::new(&record.source_path).ancestors().skip(1) {
            directories.insert((record.source_id.as_str(), parent.to_owned()));
        }
    }
    let mut errors = 0;
    for snapshot in snapshots {
        let matching = files.get(&(snapshot.source_id.as_str(), snapshot.source_path.as_str()));
        let relevant = if snapshot.directory {
            directories.contains(&(
                snapshot.source_id.as_str(),
                PathBuf::from(&snapshot.source_path),
            ))
        } else {
            matching.is_some()
        };
        if !relevant {
            snapshot.restore_status = "PayloadUnavailable".into();
            continue;
        }
        if matches!(snapshot.capture_status.as_str(), "Failed" | "Partial") {
            snapshot.restore_status = "CaptureFailed".into();
            errors += 1;
            continue;
        }
        if !snapshot.directory
            && matching.is_some_and(|rows| {
                rows.iter().any(|r| {
                    !same_identity(
                        snapshot.source_file_id.as_deref(),
                        r.source_file_id.as_deref(),
                    )
                })
            })
        {
            snapshot.restore_status = "SourceChanged".into();
            snapshot
                .problems
                .push_str(" Metadata identity does not match the streamed file generation");
            errors += 1;
        } else {
            snapshot.restore_status = "InventoryOnly".into();
        }
    }
    errors
}

pub(crate) fn restore(root: &Path, snapshots: &mut [Snapshot], records: &[Record]) -> usize {
    let available: BTreeSet<_> = records
        .iter()
        .filter(|r| r.verified)
        .filter_map(|r| r.relative_output_path.as_deref())
        .map(|p| p.split_once(':').map_or(p, |(p, _)| p).to_owned())
        .collect();
    // Restore directory properties top-down, then file properties. This keeps
    // parent inheritance changes ahead of each child's final security state.
    snapshots.sort_by_key(|s| {
        (
            !s.directory,
            Path::new(&s.relative_output_path).components().count(),
        )
    });
    for snapshot in snapshots.iter_mut() {
        if !snapshot.directory && !available.contains(&snapshot.relative_output_path) {
            snapshot.restore_status = "PayloadUnavailable".into();
            continue;
        }
        if snapshot.capture_status == "Failed" {
            snapshot.restore_status = "CaptureFailed".into();
            continue;
        }
        if !snapshot.directory {
            let matching: Vec<_> = records
                .iter()
                .filter(|r| r.verified)
                .filter(|r| {
                    r.relative_output_path.as_deref().is_some_and(|p| {
                        p.split_once(':').map_or(p, |(base, _)| base)
                            == snapshot.relative_output_path
                    })
                })
                .collect();
            if matching.iter().any(|r| {
                !same_identity(
                    snapshot.source_file_id.as_deref(),
                    r.source_file_id.as_deref(),
                )
            }) {
                snapshot.restore_status = "SourceChanged".into();
                snapshot
                    .problems
                    .push_str("Captured metadata does not identify the acquired file generation");
                continue;
            }
        }
        let result = paths::safe_join(root, &snapshot.relative_output_path).and_then(|path| {
            #[cfg(windows)]
            {
                windows::restore(&path, snapshot)
            }
            #[cfg(not(windows))]
            {
                let _ = path;
                anyhow::bail!("Native NTFS restoration requires Windows")
            }
        });
        match result {
            Ok(()) => snapshot.restore_status = "Restored".into(),
            Err(error) => {
                snapshot.restore_status = "Partial".into();
                snapshot.problems.push_str(&format!("Restore: {error:#}"));
            }
        }
    }
    // After every property/security operation, restore basic timestamps deepest
    // first. Parent security propagation can no longer rewrite a child's times.
    snapshots.sort_by_key(|s| {
        std::cmp::Reverse(Path::new(&s.relative_output_path).components().count())
    });
    for snapshot in snapshots
        .iter_mut()
        .filter(|s| matches!(s.restore_status.as_str(), "Restored" | "Partial"))
    {
        #[cfg(windows)]
        let result = paths::safe_join(root, &snapshot.relative_output_path)
            .and_then(|path| windows::restore_times(&path, snapshot));
        #[cfg(not(windows))]
        let result: Result<()> = Err(anyhow::anyhow!("Native NTFS restoration requires Windows"));
        if let Err(error) = result {
            snapshot.restore_status = "Partial".into();
            snapshot
                .problems
                .push_str(&format!(" Basic metadata: {error:#}"));
        }
    }
    snapshots
        .iter()
        .filter(|s| {
            matches!(
                s.restore_status.as_str(),
                "Partial" | "CaptureFailed" | "SourceChanged"
            )
        })
        .count()
}

pub(crate) fn write_inventory(root: &Path, snapshots: &[Snapshot]) -> Result<()> {
    let create = |name| {
        std::fs::OpenOptions::new()
            .write(true)
            .create_new(true)
            .open(root.join(name))
    };
    let mut json = BufWriter::new(create(FILES[0])?);
    let mut csv = csv::Writer::from_writer(create(FILES[1])?);
    for snapshot in snapshots {
        serde_json::to_writer(&mut json, snapshot)?;
        json.write_all(b"\n")?;
        csv.serialize(snapshot)?;
    }
    json.flush()?;
    csv.flush()?;
    json.get_ref().sync_all()?;
    csv.get_ref().sync_all()?;
    Ok(())
}

pub fn unhex(text: &str) -> Result<Vec<u8>> {
    ensure!(text.len().is_multiple_of(2), "Invalid hexadecimal metadata");
    text.as_bytes()
        .as_chunks::<2>()
        .0
        .iter()
        .map(|pair| {
            let pair = std::str::from_utf8(pair)?;
            u8::from_str_radix(pair, 16).context("Invalid hexadecimal metadata")
        })
        .collect()
}

/// Extended attributes as sorted (name, flags, value) entries.
pub type EaEntries = Vec<(Vec<u8>, u8, Vec<u8>)>;

/// Parses and validates a FILE_FULL_EA_INFORMATION chain.
pub fn normalize_ea(bytes: &[u8]) -> Result<EaEntries> {
    let mut result = Vec::new();
    let mut at = 0;
    while at < bytes.len() {
        ensure!(bytes.len() - at >= 8, "Truncated extended attribute");
        let next = u32::from_le_bytes(bytes[at..at + 4].try_into()?) as usize;
        let flags = bytes[at + 4];
        let name_len = bytes[at + 5] as usize;
        let value_len = u16::from_le_bytes(bytes[at + 6..at + 8].try_into()?) as usize;
        let end = at + 8 + name_len + 1 + value_len;
        ensure!(
            end <= bytes.len() && bytes[at + 8 + name_len] == 0,
            "Invalid extended attribute lengths"
        );
        result.push((
            bytes[at + 8..at + 8 + name_len].to_vec(),
            flags,
            bytes[at + 8 + name_len + 1..end].to_vec(),
        ));
        if next == 0 {
            break;
        }
        ensure!(
            next >= end - at && next.is_multiple_of(4) && next <= bytes.len() - at,
            "Invalid extended attribute chain"
        );
        at += next;
    }
    result.sort();
    Ok(result)
}

/// Windows reserves the `$Kernel.` extended-attribute namespace for kernel-mode
/// callers. `NtSetEaFile` from user mode reports success for such names without
/// storing them, so they can only be retained in the inventory.
pub fn is_kernel_ea(name: &[u8]) -> bool {
    name.len() >= 8 && name[..8].eq_ignore_ascii_case(b"$KERNEL.")
}

/// Splits entries into the user-settable ones and the kernel-namespace names.
pub fn split_kernel_ea(entries: EaEntries) -> (EaEntries, Vec<String>) {
    let (kernel, user): (Vec<_>, Vec<_>) = entries
        .into_iter()
        .partition(|(name, _, _)| is_kernel_ea(name));
    (
        user,
        kernel
            .into_iter()
            .map(|(name, _, _)| String::from_utf8_lossy(&name).into_owned())
            .collect(),
    )
}

/// Builds a FILE_FULL_EA_INFORMATION chain; every entry but the last is padded
/// to a 4-byte boundary and the last entry's offset is zero.
pub fn encode_ea(entries: &EaEntries) -> Vec<u8> {
    let mut out = Vec::new();
    for (i, (name, flags, value)) in entries.iter().enumerate() {
        let start = out.len();
        let body = 8 + name.len() + 1 + value.len();
        let next = if i + 1 == entries.len() {
            0
        } else {
            body.div_ceil(4) * 4
        };
        out.extend_from_slice(&(next as u32).to_le_bytes());
        out.push(*flags);
        out.push(name.len() as u8);
        out.extend_from_slice(&(value.len() as u16).to_le_bytes());
        out.extend_from_slice(name);
        out.push(0);
        out.extend_from_slice(value);
        out.resize(start + if next == 0 { body } else { next }, 0);
    }
    out
}

/// Splits an SDDL string into its owner, group, DACL and SACL texts. Component
/// markers are recognized only outside parentheses, so conditional ACEs and
/// SIDs never start a component.
fn sddl_parts(text: &str) -> Option<[Option<String>; 4]> {
    let bytes = text.as_bytes();
    let mut parts: [Option<String>; 4] = Default::default();
    let mut current = None;
    let mut start = 0;
    let mut depth = 0usize;
    let mut i = 0;
    while i < bytes.len() {
        match bytes[i] {
            b'(' => depth += 1,
            b')' => depth = depth.checked_sub(1)?,
            _ => {}
        }
        let marker = match bytes[i] {
            b'O' => Some(0),
            b'G' => Some(1),
            b'D' => Some(2),
            b'S' => Some(3),
            _ => None,
        };
        if depth == 0
            && let Some(index) = marker
            && bytes.get(i + 1) == Some(&b':')
        {
            if let Some(previous) = current {
                parts[previous] = Some(text[start..i].to_owned());
            }
            if parts[index].is_some() {
                return None;
            }
            current = Some(index);
            start = i + 2;
            i += 2;
            continue;
        }
        i += 1;
    }
    if let Some(previous) = current {
        parts[previous] = Some(text[start..].to_owned());
    }
    Some(parts)
}

/// ACL text into its control-flag letters and ACE strings in their original order.
fn acl_parts(text: &str) -> (String, Vec<String>) {
    let flags = text[..text.find('(').unwrap_or(text.len())].to_owned();
    let mut aces = Vec::new();
    let mut depth = 0usize;
    let mut start = 0;
    for (i, c) in text.char_indices() {
        match c {
            '(' => {
                if depth == 0 {
                    start = i;
                }
                depth += 1;
            }
            ')' => {
                depth = depth.saturating_sub(1);
                if depth == 0 {
                    aces.push(text[start..=i].to_owned());
                }
            }
            _ => {}
        }
    }
    (flags, aces)
}

fn equivalent_dacl_aces(captured: &[String], actual: &[String]) -> bool {
    if captured == actual {
        return true;
    }
    // Windows checks a DACL in order. Arbitrarily sorting ACEs would silently
    // accept allow/deny inversions that change effective access. Restrict the
    // observed Windows normalization to ordinary allow-only ACLs; preserve the
    // order of mixed, object-specific and conditional ACEs conservatively.
    if !captured.iter().all(|ace| ace.starts_with("(A;"))
        || !actual.iter().all(|ace| ace.starts_with("(A;"))
    {
        return false;
    }
    let mut captured = captured.to_vec();
    let mut actual = actual.to_vec();
    captured.sort();
    actual.sort();
    captured == actual
}

fn acl_flags(text: &str) -> Option<BTreeSet<&'static str>> {
    let mut rest = text;
    let mut set = BTreeSet::new();
    while !rest.is_empty() {
        let token = ["NO_ACCESS_CONTROL", "AI", "AR", "P"]
            .into_iter()
            .find(|t| rest.starts_with(t))?;
        set.insert(token);
        rest = &rest[token.len()..];
    }
    Some(set)
}

/// Readback equivalence of a restored security descriptor. Windows stores a
/// DACL that lacks SE_DACL_AUTO_INHERITED as protected and in canonical ACE
/// order when it is written inside an auto-inheriting tree; owner, group, SACL
/// and every ACE must still match. Returns the note to record (empty when the
/// strings are identical), or None when the descriptors differ in substance.
pub fn sddl_equivalent(captured: &str, actual: &str) -> Option<String> {
    if captured == actual {
        return Some(String::new());
    }
    // Quoted conditional expressions have their own escaping grammar. For a
    // changed descriptor, require exact readback rather than guessing at it.
    if captured.contains('"') || actual.contains('"') {
        return None;
    }
    let [c_owner, c_group, c_dacl, c_sacl] = sddl_parts(captured)?;
    let [a_owner, a_group, a_dacl, a_sacl] = sddl_parts(actual)?;
    let (c_flags, c_aces) = acl_parts(c_dacl.as_deref()?);
    let (a_flags, a_aces) = acl_parts(a_dacl.as_deref()?);
    if c_owner != a_owner
        || c_group != a_group
        || !equivalent_dacl_aces(&c_aces, &a_aces)
        || c_sacl != a_sacl
    {
        return None;
    }
    let c_flags = acl_flags(&c_flags)?;
    let a_flags = acl_flags(&a_flags)?;
    if c_flags == a_flags {
        return Some(
            "Windows stored the DACL in canonical ACE order; every ACE matches the source".into(),
        );
    }
    let mut protected = c_flags.clone();
    protected.insert("P");
    if !c_flags.contains("AI") && a_flags == protected {
        return Some(
            "Windows stored the DACL as protected (SE_DACL_PROTECTED added to a DACL without \
             SE_DACL_AUTO_INHERITED) in canonical ACE order; owner, group, SACL and every ACE \
             match the source"
                .into(),
        );
    }
    None
}

#[cfg(test)]
mod tests {
    #[test]
    fn remote_inventory_binds_generations_and_does_not_turn_absence_into_damage() {
        use super::*;
        let mut record: Record = serde_json::from_value(serde_json::json!({
            "SchemaVersion":1,"ObservationId":"id","Computer":"HOST","SourceId":"C",
            "SourcePath":"C/file","StreamName":null,"ArtifactIds":"test",
            "RelativeOutputPath":"C/file","Method":"RawNTFS","Status":"Transferred",
            "Reason":"pending","StartedUtc":"","FinishedUtc":"","LogicalSize":1,
            "BytesRead":1,"SHA-256":null,"Verified":false,"ChangedDuringRead":false,
            "CreatedUtc":null,"ModifiedUtc":null,"AccessedUtc":null,"SourceFileId":"ntfs:2:3"
        }))
        .unwrap();
        let snapshot = Snapshot {
            source_id: "C".into(),
            source_path: "C/file".into(),
            capture_status: "Captured".into(),
            source_file_id: Some("win:1234:0003000000000002".into()),
            ..Default::default()
        };
        let mut rows = vec![snapshot.clone()];
        assert_eq!(
            remote_inventory(&mut rows, std::slice::from_ref(&record)),
            0
        );
        assert_eq!(rows[0].restore_status, "InventoryOnly");
        record.source_file_id = Some("ntfs:2:4".into());
        assert_eq!(
            remote_inventory(&mut rows, std::slice::from_ref(&record)),
            1
        );
        assert_eq!(rows[0].restore_status, "SourceChanged");
        rows[0].capture_status = "Failed".into();
        record.status = "NotPresent".into();
        assert_eq!(
            remote_inventory(&mut rows, std::slice::from_ref(&record)),
            0
        );
        assert_eq!(rows[0].restore_status, "PayloadUnavailable");
        // A failed read keeps a `.partial` object but, as in a local collection,
        // its metadata row is not a metadata error.
        record.status = "Failed".into();
        record.relative_output_path = Some("C/file.id.partial".into());
        assert_eq!(
            remote_inventory(&mut rows, std::slice::from_ref(&record)),
            0
        );
        assert_eq!(rows[0].restore_status, "PayloadUnavailable");
        record.status = "Transferred".into();
        record.relative_output_path = Some("C/file".into());
        assert_eq!(remote_inventory(&mut rows, &[record]), 1);
        assert_eq!(rows[0].restore_status, "CaptureFailed");
    }

    use super::*;
    #[cfg(windows)]
    #[test]
    fn windows_capture_tags_metadata_open_failures() {
        let temp = tempfile::tempdir().unwrap();
        let mut snapshot = Snapshot::default();
        let error = windows::capture(&temp.path().join("not-present"), &mut snapshot).unwrap_err();
        assert!(error.is::<MetadataOpenFailed>());
        assert!(snapshot.attributes.is_none());
    }

    #[test]
    fn post_open_errors_preserve_captured_metadata_and_remain_errors() {
        for message in [
            "security descriptor unreadable",
            "extended attributes unreadable",
            "file identity unreadable",
        ] {
            let mut snapshot = Snapshot {
                attributes: Some(0x20),
                capture_status: "Failed".into(),
                security_descriptor_hex: Some("01000000".into()),
                extended_attributes_hex: Some("00000000".into()),
                ..Default::default()
            };
            let called = std::cell::Cell::new(false);
            let error = anyhow::anyhow!(message).context("capturing source metadata");
            capture_failed(&mut snapshot, false, &error, |record| {
                called.set(true);
                // raw_capture would discard metadata already obtained through Windows.
                record.security_descriptor_hex = None;
                record.extended_attributes_hex = None;
                true
            });
            assert!(
                !called.get(),
                "post-open failure must not call the raw fallback"
            );
            assert_eq!(snapshot.capture_status, "Partial");
            assert_eq!(
                snapshot.security_descriptor_hex.as_deref(),
                Some("01000000")
            );
            assert_eq!(
                snapshot.extended_attributes_hex.as_deref(),
                Some("00000000")
            );
            assert!(snapshot.problems.contains(message));
            assert!(snapshot.notes.is_empty());
        }
    }

    #[test]
    fn open_refusals_can_use_raw_metadata_but_failed_recovery_stays_failed() {
        for recovered in [true, false] {
            let mut snapshot = Snapshot {
                capture_status: "Failed".into(),
                ..Default::default()
            };
            let error =
                anyhow::Error::new(std::io::Error::from(std::io::ErrorKind::PermissionDenied))
                    .context(MetadataOpenFailed)
                    .context("capturing source metadata");
            capture_failed(&mut snapshot, false, &error, |record| {
                if recovered {
                    record.attributes = Some(0x20);
                }
                recovered
            });
            if recovered {
                assert_eq!(snapshot.capture_status, "RawBasic");
                assert!(snapshot.notes.starts_with(RAW_OPEN_REFUSED_NOTE));
                assert!(snapshot.problems.is_empty());
            } else {
                assert_eq!(snapshot.capture_status, "Failed");
                assert!(snapshot.problems.starts_with("Capture:"));
                assert!(snapshot.notes.is_empty());
            }
        }
    }

    #[test]
    fn stream_names_cannot_create_paths_or_collide_with_default_data() {
        let plain = output_relative("C", Path::new("Windows/file.bin"), None).unwrap();
        let stream =
            output_relative("C", Path::new("Windows/file.bin"), Some("Zone.Identifier")).unwrap();
        assert_eq!(
            stream.to_string_lossy().replace('\\', "/"),
            format!(
                "{}:Zone.Identifier",
                plain.to_string_lossy().replace('\\', "/")
            )
        );
        let hostile = output_relative("C", Path::new("file"), Some("../other:name")).unwrap();
        assert!(hostile.to_string_lossy().ends_with(":..%2Fother%3Aname"));
        assert!(output_relative("C", Path::new("file"), Some("")).is_err());
    }
    #[test]
    fn source_directory_and_long_paths_keep_their_corresponding_container_paths() {
        assert_eq!(
            output_relative("C", Path::new(""), None).unwrap(),
            Path::new("C")
        );
        let relative = format!("Windows/{}/file", "long/".repeat(60));
        let path = output_relative("C", Path::new(&relative), None).unwrap();
        assert!(path.starts_with("C/Windows"));
        assert!(!path.to_string_lossy().contains("LongPaths"));
        assert!(output_relative("C", Path::new(&"x".repeat(256)), None).is_err());
    }

    #[test]
    fn the_usn_journal_data_stream_is_recognized_case_insensitively() {
        assert!(is_usn_journal(Path::new("$Extend/$UsnJrnl"), Some("$J")));
        assert!(is_usn_journal(Path::new("$extend\\$usnjrnl"), Some("$j")));
        assert!(!is_usn_journal(Path::new("$Extend/$UsnJrnl"), Some("$Max")));
        assert!(!is_usn_journal(Path::new("$Extend/$UsnJrnl"), None));
        assert!(!is_usn_journal(Path::new("$MFT"), Some("$J")));
    }

    #[test]
    fn metadata_cannot_be_assigned_to_another_file_generation() {
        assert!(same_identity(
            Some("win:12345678:000a000000001234"),
            Some("ntfs:4660:10")
        ));
        assert!(!same_identity(
            Some("win:12345678:000a000000001234"),
            Some("ntfs:4660:11")
        ));
        assert!(!same_identity(
            Some("win:12345678:000a000000001234"),
            Some("win:87654321:000a000000001234")
        ));
        assert!(!same_identity(None, Some("ntfs:4660:10")));
    }

    #[test]
    fn inventory_round_trips_large_filetimes_and_security_bytes() {
        let tmp = tempfile::tempdir().unwrap();
        let snapshot = Snapshot {
            creation_filetime: Some(134_370_987_123_456_789),
            security_descriptor_hex: Some("0100ff".into()),
            capture_status: "Captured".into(),
            notes: "kept".into(),
            ..Default::default()
        };
        write_inventory(tmp.path(), std::slice::from_ref(&snapshot)).unwrap();
        let from_json: Snapshot =
            serde_json::from_str(&std::fs::read_to_string(tmp.path().join(FILES[0])).unwrap())
                .unwrap();
        let from_csv: Snapshot = csv::Reader::from_path(tmp.path().join(FILES[1]))
            .unwrap()
            .deserialize()
            .next()
            .unwrap()
            .unwrap();
        assert_eq!(from_json.creation_filetime, snapshot.creation_filetime);
        assert_eq!(from_csv.creation_filetime, snapshot.creation_filetime);
        assert_eq!(from_csv.notes, "kept");
        assert_eq!(
            unhex(from_json.security_descriptor_hex.as_ref().unwrap()).unwrap(),
            [1, 0, 255]
        );
        assert!(unhex("0").is_err());
        assert!(unhex("zz").is_err());
        // Inventories written before the Notes column still load.
        let older: Snapshot = serde_json::from_str(r#"{"SourceId":"C","SourcePath":"","RelativeOutputPath":"","Directory":false,"CapturedUtc":"","CaptureStatus":"Captured","RestoreStatus":"Restored","Problems":""}"#).unwrap();
        assert!(older.notes.is_empty());
    }

    #[test]
    fn extended_attribute_chain_validates_lengths_offsets_and_values() {
        let ea = [0, 0, 0, 0, 0, 1, 2, 0, b'A', 0, b'x', b'y'];
        assert_eq!(
            normalize_ea(&ea).unwrap(),
            vec![(vec![b'A'], 0, vec![b'x', b'y'])]
        );
        for bad in [
            &ea[..7],
            &ea[..11],
            &[4, 0, 0, 0, 0, 1, 2, 0, b'A', 0, b'x', b'y'][..],
        ] {
            assert!(normalize_ea(bad).is_err());
        }
    }

    #[test]
    fn kernel_namespace_extended_attributes_are_kept_apart_and_chains_round_trip() {
        let entries: EaEntries = vec![
            (b"$KERNEL.CFDONOTCONVERT".to_vec(), 0, b"CM\0".to_vec()),
            (b"KUMADE".to_vec(), 0x80, b"evidence".to_vec()),
            (b"ZZ".to_vec(), 0, Vec::new()),
        ];
        let chain = encode_ea(&entries);
        // 34 and 23 byte entries padded to 4; the last entry (11 bytes) is not padded.
        assert_eq!(chain.len(), 36 + 24 + 11);
        assert_eq!(normalize_ea(&chain).unwrap(), entries);
        let (user, kernel) = split_kernel_ea(normalize_ea(&chain).unwrap());
        assert_eq!(kernel, vec!["$KERNEL.CFDONOTCONVERT"]);
        assert_eq!(user.len(), 2);
        assert_eq!(normalize_ea(&encode_ea(&user)).unwrap(), user);
        assert!(encode_ea(&Vec::new()).is_empty());
        assert!(is_kernel_ea(b"$kernel.purge.esbcache"));
        assert!(!is_kernel_ea(b"$KERNEL"));
        assert!(!is_kernel_ea(b"KERNEL.X"));
    }

    #[test]
    fn protected_dacl_normalization_is_equivalent_but_other_changes_are_not() {
        let captured = "O:NSG:NSD:(A;OICI;FA;;;BA)(A;OICI;FA;;;SY)(A;OICIIO;GA;;;CO)(A;OICI;0x1200a9;;;BU)(A;CI;LC;;;BU)(A;CIIO;DC;;;BU)(A;;0x1200a9;;;WD)";
        let actual = "O:NSG:NSD:P(A;;0x1200a9;;;WD)(A;OICIIO;GA;;;CO)(A;OICI;FA;;;SY)(A;OICI;FA;;;BA)(A;CI;LC;;;BU)(A;CIIO;DC;;;BU)(A;OICI;0x1200a9;;;BU)";
        assert_eq!(sddl_equivalent(captured, captured), Some(String::new()));
        assert!(
            sddl_equivalent(captured, actual)
                .unwrap()
                .contains("protected")
        );
        assert!(sddl_equivalent(captured, &actual.replace("(A;CI;LC;;;BU)", "")).is_none());
        assert!(sddl_equivalent(captured, &actual.replace("O:NS", "O:BA")).is_none());
        assert!(sddl_equivalent(captured, &actual.replace("D:P", "D:PAI")).is_none());
        // An already auto-inherited DACL becoming protected is a real change.
        let inherited = "O:SYG:SYD:AI(A;ID;FA;;;SY)(A;ID;FA;;;BA)S:AINO_ACCESS_CONTROL";
        assert!(sddl_equivalent(inherited, &inherited.replace("D:AI", "D:PAI")).is_none());
        assert!(
            sddl_equivalent(
                inherited,
                "O:SYG:SYD:AI(A;ID;FA;;;BA)(A;ID;FA;;;SY)S:AINO_ACCESS_CONTROL"
            )
            .unwrap()
            .contains("canonical")
        );
        // A SACL change or a conditional ACE difference is never equivalent.
        assert!(sddl_equivalent(inherited, &inherited.replace("S:AI", "S:PAI")).is_none());
        let conditional = "O:BAG:BAD:(XA;;FR;;;WD;(Member_of {SID(BA)}))";
        assert!(sddl_equivalent(conditional, &conditional.replace("SID(BA)", "SID(SY)")).is_none());
        assert_eq!(
            sddl_equivalent(conditional, &conditional.replace("D:(", "D:P("))
                .map(|n| n.contains("protected")),
            Some(true)
        );
    }

    #[test]
    fn permission_order_and_missing_acls_are_not_normalized_away() {
        let allow_first = "O:BAG:BAD:(A;;FR;;;WD)(D;;FR;;;WD)";
        let deny_first = "O:BAG:BAD:(D;;FR;;;WD)(A;;FR;;;WD)";
        assert!(sddl_equivalent(allow_first, deny_first).is_none());
        assert!(sddl_equivalent(allow_first, &deny_first.replace("D:(", "D:P(")).is_none());
        // A missing DACL grants access; a present empty DACL denies access.
        assert!(sddl_equivalent("O:BAG:BA", "O:BAG:BAD:").is_none());
        assert!(sddl_equivalent("O:BAG:BA", "O:BAG:BAD:P").is_none());
        assert!(sddl_equivalent("O:BAG:BAD:", "O:BAG:BAD:S:").is_none());
        let sacl = "O:BAG:BAD:(A;;FA;;;BA)S:(AU;SA;FR;;;WD)(AU;FA;FW;;;WD)";
        let reordered = "O:BAG:BAD:(A;;FA;;;BA)S:(AU;FA;FW;;;WD)(AU;SA;FR;;;WD)";
        assert!(sddl_equivalent(sacl, reordered).is_none());
    }
}
