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

use crate::{
    discovery::{fingerprint, same_version},
    metadata,
    model::*,
    paths, platform,
    raw::RawVolume,
    ui,
};
use anyhow::{Context, Result, bail, ensure};
use rayon::prelude::*;
use sha2::{Digest, Sha256};
use std::{
    collections::HashMap,
    fs::{self, File, OpenOptions},
    io::{self, BufReader, BufWriter, Read, Seek, Write},
    path::{Path, PathBuf},
    sync::{Arc, Mutex},
    time::Instant,
};

const BUFFER: usize = 1024 * 1024;
#[derive(Clone, Debug)]
pub struct HostReserve {
    pub path: PathBuf,
    pub bytes: u64,
}

#[derive(Clone)]
pub struct Options {
    pub remote: Option<Arc<crate::sftp::Target>>,
    pub threads: usize,
    pub reserve_bytes: u64,
    pub quiet: bool,
    pub verbose: bool,
    pub ntfs_metadata: bool,
    pub host_reserve: Option<HostReserve>,
    pub live_info: Option<crate::live_info::Options>,
    pub process_scan: Option<crate::yara_scan::Options>,
    pub early: Option<Arc<crate::early::Capture>>,
    pub entropy: Option<crate::entropy::Settings>,
}

pub fn hash_file(path: &Path) -> Result<(u64, String)> {
    let mut file = BufReader::with_capacity(BUFFER, platform::open_source(path)?);
    let mut hash = Sha256::new();
    let mut bytes = 0u64;
    let mut buffer = vec![0u8; BUFFER];
    loop {
        let n = file.read(&mut buffer)?;
        if n == 0 {
            break;
        }
        hash.update(&buffer[..n]);
        bytes = bytes
            .checked_add(n as u64)
            .context("Payload size overflow")?;
    }
    Ok((bytes, hex(&hash.finalize())))
}

pub fn write_json_new(path: &Path, value: &impl serde::Serialize) -> Result<()> {
    let file = OpenOptions::new().write(true).create_new(true).open(path)?;
    let mut writer = BufWriter::new(file);
    serde_json::to_writer_pretty(&mut writer, value)?;
    writer.write_all(b"\n")?;
    writer.flush()?;
    writer.get_ref().sync_all()?;
    Ok(())
}

struct Transfer<'a> {
    file: File,
    root: &'a Path,
    reserve: u64,
    hash: Sha256,
    bytes: u64,
    checked_at: u64,
    sparse: bool,
    host_reserve: Option<&'a HostReserve>,
}
impl Write for Transfer<'_> {
    fn write(&mut self, data: &[u8]) -> io::Result<usize> {
        if self.bytes == 0 || self.bytes - self.checked_at >= 16 * 1024 * 1024 {
            let available = fs2::available_space(self.root)?;
            if available < self.reserve.saturating_add(data.len() as u64) {
                return Err(io::Error::other("Destination free-space reserve reached"));
            }
            if let Some(host) = self.host_reserve {
                // Dynamic image allocation needs host space as well as NTFS space.
                // Leave extra headroom for in-flight workers and VHDX block metadata.
                let available = fs2::available_space(&host.path)?;
                if available
                    < host
                        .bytes
                        .saturating_add(64 * 1024 * 1024)
                        .saturating_add(data.len() as u64)
                {
                    return Err(io::Error::other("Physical host free-space reserve reached"));
                }
            }
            self.checked_at = self.bytes;
        }
        let n = if self.sparse && data.len() >= 4096 && data.iter().all(|&b| b == 0) {
            self.file.seek_relative(data.len() as i64)?;
            data.len()
        } else {
            self.file.write(data)?
        };
        self.hash.update(&data[..n]);
        self.bytes = self
            .bytes
            .checked_add(n as u64)
            .ok_or_else(|| io::Error::other("Byte count overflow"))?;
        Ok(n)
    }
    fn flush(&mut self) -> io::Result<()> {
        if self.sparse {
            self.file.set_len(self.bytes)?;
        }
        self.file.flush()
    }
}

fn source_fingerprint(file: &File, capture_identity: bool) -> Result<Fingerprint> {
    let value = fingerprint(&file.metadata()?);
    #[cfg(windows)]
    {
        let mut value = value;
        if capture_identity {
            value.identity = Some(metadata::file_identity(file)?);
        }
        Ok(value)
    }
    #[cfg(not(windows))]
    {
        let _ = capture_identity;
        Ok(value)
    }
}

pub fn acquire_one(
    root: &Path,
    source: &Source,
    item: &PlannedFile,
    reserve: u64,
    raw_cache: &mut HashMap<PathBuf, RawVolume>,
) -> Record {
    acquire_one_inner(
        root,
        source,
        item,
        reserve,
        raw_cache,
        DestinationPolicy::default(),
    )
}

#[derive(Default)]
struct DestinationPolicy<'a> {
    remote: Option<&'a Arc<crate::sftp::Target>>,
    native_ntfs: bool,
    phased_s3: bool,
    hybrid: Option<&'a crate::s3_phases::hybrid::Disk>,
    source_sparse: bool,
    host_reserve: Option<&'a HostReserve>,
}

fn acquire_one_inner(
    root: &Path,
    source: &Source,
    item: &PlannedFile,
    reserve: u64,
    raw_cache: &mut HashMap<PathBuf, RawVolume>,
    destination: DestinationPolicy<'_>,
) -> Record {
    let native_ntfs = destination.native_ntfs;
    let host_reserve = destination.host_reserve;
    let mut record = Record {
        schema_version: SCHEMA_VERSION,
        observation_id: item.id.clone(),
        computer: source.computer.clone(),
        source_id: source.id.clone(),
        source_path: item.source_path.display().to_string(),
        stream_name: item.stream.clone(),
        artifact_ids: item.artifacts.join(";"),
        relative_output_path: None,
        method: if source.snapshot.is_some() {
            "VssNativeRead"
        } else {
            "NativeRead"
        }
        .into(),
        status: "Failed".into(),
        reason: String::new(),
        started_utc: utc_now(),
        finished_utc: String::new(),
        logical_size: item.before.as_ref().map(|m| m.size),
        bytes_read: 0,
        sha256: None,
        verified: false,
        changed_during_read: false,
        created_utc: None,
        modified_utc: None,
        accessed_utc: None,
        source_file_id: None,
    };
    if source.snapshot.is_some() && crate::vss::omitted_paging_file(&item.relative_path) {
        // Summary, Coverage.csv, Errors.csv and `verify` know Acquired, Partial,
        // Failed and NotPresent. A paging file that exists in the snapshot is a
        // planned file that was not acquired, so the run is Partial; a raw
        // candidate that does not exist on this volume stays a legitimate absence.
        let missing_candidate = item.before.is_none()
            && source
                .root
                .join(&item.relative_path)
                .symlink_metadata()
                .is_err_and(|e| e.kind() == io::ErrorKind::NotFound);
        // A vanished/unreadable snapshot makes every child look missing. That
        // does not establish that this particular file was absent.
        if missing_candidate && !source.root.is_dir() {
            record.status = "Failed".into();
            record.reason =
                "Cannot establish paging-file absence: VSS snapshot root is unavailable or unreadable"
                    .into();
        } else if missing_candidate {
            record.status = "NotPresent".into();
            record.reason = "Not present in the VSS snapshot".into();
        } else {
            record.status = "Failed".into();
            record.reason =
                "VSS omits paging/hibernation contents; no live-file or raw-live fallback was used"
                    .into();
        }
        record.finished_utc = utc_now();
        return record;
    }
    if let Some(disk) = destination.hybrid {
        return disk.acquire(record, source, item, raw_cache);
    }
    if let Some(target) = destination.remote {
        return crate::sftp::acquire(record, source, item, raw_cache, target);
    }
    let outcome = (|| -> Result<()> {
        let relative = if destination.phased_s3 {
            PathBuf::from(crate::sftp::relative_payload(item)?)
        } else if native_ntfs {
            metadata::output_relative(&source.id, &item.relative_path, item.stream.as_deref())?
        } else {
            paths::output_relative(&source.id, &item.relative_path, item.stream.as_deref())?
        };
        let output = root.join(&relative);
        fs::create_dir_all(output.parent().context("Missing payload parent")?)?;
        let mut partial = output.clone();
        let original = output
            .file_name()
            .context("Missing payload name")?
            .to_str()
            .context("Unsupported output name")?;
        let direct_stream = native_ntfs && item.stream.is_some();
        if direct_stream {
            // Unnamed payloads finish in phase one. Stream-only NTFS objects
            // need an explicitly empty host file; no data is claimed for it.
            let base = root.join(metadata::output_relative(
                &source.id,
                &item.relative_path,
                None,
            )?);
            match OpenOptions::new().write(true).create_new(true).open(&base) {
                Ok(file) => file.sync_all()?,
                Err(error) if error.kind() == io::ErrorKind::AlreadyExists => {
                    ensure!(
                        base.symlink_metadata()?.is_file()
                            && !platform::is_reparse_directory(&base),
                        "Unsafe ADS host file"
                    );
                }
                Err(error) => return Err(error.into()),
            }
        } else {
            partial.set_file_name(format!("{original}.{}.partial", item.id));
        }
        let file = OpenOptions::new()
            .write(true)
            .create_new(true)
            .open(&partial)?;
        record.relative_output_path = Some(paths::relative_text(partial.strip_prefix(root)?)?);
        let sparse =
            (!native_ntfs || destination.source_sparse) && platform::enable_sparse_output(&file);
        let mut transfer = Transfer {
            file,
            root,
            reserve,
            hash: Sha256::new(),
            bytes: 0,
            checked_at: 0,
            sparse,
            host_reserve,
        };
        let copied = copy_source(
            source,
            item,
            raw_cache,
            native_ntfs || destination.phased_s3,
            &mut record.method,
            &mut transfer,
            |attributes, writer| {
                if native_ntfs && attributes & 0x200 != 0 && !writer.sparse {
                    writer.sparse = platform::enable_sparse_output(&writer.file);
                    ensure!(writer.sparse, "Cannot preserve sparse source stream");
                }
                Ok(())
            },
        );
        record.bytes_read = transfer.bytes;
        transfer.flush()?;
        transfer.file.sync_all()?;
        record.sha256 = Some(hex(&transfer.hash.finalize()));
        drop(transfer.file);
        match copied {
            Ok((before, after)) => {
                record.logical_size = Some(before.size);
                record.created_utc = before.created_ns.clone();
                record.modified_utc = before.modified_ns.clone();
                record.accessed_utc = before.accessed_ns.clone();
                record.source_file_id = before.identity.clone();
                record.changed_during_read = !same_version(&before, &after)
                    || item
                        .before
                        .as_ref()
                        .is_some_and(|p| !same_version(p, &before));
                if !direct_stream {
                    if output.exists() {
                        bail!("Payload destination collision: {}", output.display());
                    }
                    commit_payload(&partial, &output)?;
                }
                record.relative_output_path = Some(paths::relative_text(&relative)?);
                let (verified_bytes, verified_hash) = hash_file(&output)?;
                ensure!(
                    Some(&verified_hash) == record.sha256.as_ref()
                        && verified_bytes == record.bytes_read,
                    "Stored payload failed hash verification"
                );
                record.verified = true;
                if item
                    .expected_sha256
                    .as_ref()
                    .is_some_and(|expected| record.sha256.as_ref() != Some(expected))
                {
                    record.status = "Partial".into();
                    record.reason = "Acquired content differs from the entropy analysis SHA256; captured bytes are retained".into();
                } else if record.changed_during_read {
                    record.status = "Partial".into();
                    record.reason="Source metadata changed since planning or during read; captured bytes are retained".into();
                } else {
                    record.status = "Acquired".into();
                }
                if !native_ntfs
                    && let (Some(atime), Some(mtime)) = (before.accessed_ns, before.modified_ns)
                    && let (Ok(a), Ok(m)) = (
                        chrono::DateTime::parse_from_rfc3339(&atime),
                        chrono::DateTime::parse_from_rfc3339(&mtime),
                    )
                {
                    let times = fs::FileTimes::new()
                        .set_accessed(a.into())
                        .set_modified(m.into());
                    let restored = OpenOptions::new()
                        .write(true)
                        .open(&output)
                        .and_then(|f| f.set_times(times));
                    if let Err(e) = restored {
                        record.status = "Partial".into();
                        record.reason.push_str(&format!(
                            " Destination timestamps could not be restored: {e}"
                        ));
                    }
                }
                Ok(())
            }
            Err(error) => {
                record.relative_output_path =
                    Some(paths::relative_text(partial.strip_prefix(root)?)?);
                // Opening a missing raw device also returns NotFound. Only a
                // successfully opened provider can establish a missing NTFS
                // object/stream; never count provider failure as artifact absence.
                let raw_available = source
                    .raw_device
                    .as_ref()
                    .is_none_or(|device| raw_cache.contains_key(device));
                if item.before.is_none()
                    && crate::raw::is_missing(&error)
                    && record.bytes_read == 0
                    && raw_available
                    && source.root.is_dir()
                {
                    record.status = "NotPresent".into();
                    record.reason = format!("{error:#}");
                    Ok(())
                } else {
                    Err(error)
                }
            }
        }
    })();
    if let Err(error) = outcome {
        record.status = "Failed".into();
        record.reason = format!("{error:#}");
        if let Some(path) = &record.relative_output_path
            && let Ok((bytes, digest)) = hash_file(&root.join(path))
        {
            record.bytes_read = bytes;
            record.sha256 = Some(digest);
        }
    }
    record.finished_utc = utc_now();
    record
}

/// Common bounded native/raw read path for local and remote acquisition.
pub(crate) fn copy_source<W: Write>(
    source: &Source,
    item: &PlannedFile,
    raw_cache: &mut HashMap<PathBuf, RawVolume>,
    capture_identity: bool,
    method: &mut String,
    writer: &mut W,
    mut attributes: impl FnMut(u32, &mut W) -> Result<()>,
) -> Result<(Fingerprint, Fingerprint)> {
    let native_path = if let Some(stream) = &item.stream {
        PathBuf::from(format!("{}:{stream}", item.source_path.display()))
    } else {
        item.source_path.clone()
    };
    match platform::open_source(&native_path) {
        Ok(mut input) => {
            platform::validate_open_file(&input, &source.root)?;
            let before = source_fingerprint(&input, capture_identity)?;
            #[cfg(windows)]
            {
                use std::os::windows::fs::MetadataExt;
                attributes(input.metadata()?.file_attributes(), writer)?;
            }
            #[cfg(not(windows))]
            attributes(0, writer)?;
            let limit = before.size.checked_add(1).context("Source size overflow")?;
            let copied = io::copy(&mut Read::by_ref(&mut input).take(limit), &mut *writer)?;
            let after = source_fingerprint(&input, capture_identity)?;
            ensure!(
                copied == before.size,
                "Source changed size or ended early during acquisition"
            );
            Ok((before, after))
        }
        Err(native_error) => {
            let Some(device) = &source.raw_device else {
                return Err(native_error)
                    .context("Native read failed; source has no raw NTFS provider");
            };
            *method = if source.snapshot.is_some() {
                "VssRawNTFS"
            } else {
                "RawNTFS"
            }
            .into();
            if !raw_cache.contains_key(device) {
                raw_cache.insert(device.clone(), RawVolume::open(device)?);
            }
            let result = raw_cache
                .get_mut(device)
                .context("Raw provider missing")?
                .copy_file_with_attributes(
                    &item.relative_path,
                    item.stream.as_deref(),
                    writer,
                    &mut attributes,
                )?;

            Ok((result.before, result.after))
        }
    }
}

struct Journal {
    remote: Option<Arc<crate::sftp::Target>>,
    json: BufWriter<File>,
    csv: csv::Writer<File>,
    errors: csv::Writer<File>,
}
impl Journal {
    fn append(&mut self, r: &Record) -> Result<()> {
        serde_json::to_writer(&mut self.json, r)?;
        self.json.write_all(b"\n")?;
        self.json.flush()?;
        self.csv.serialize(r)?;
        self.csv.flush()?;
        if r.status == "Failed" || r.status == "Partial" {
            self.errors.serialize(r)?;
            self.errors.flush()?;
        }
        // Preserve the local observation even if its remote checkpoint fails.
        self.json.get_ref().sync_data()?;
        if let Some(target) = &self.remote {
            target.checkpoint(r)?;
        }
        Ok(())
    }
    fn finish(&mut self) -> Result<()> {
        self.json.flush()?;
        self.csv.flush()?;
        self.errors.flush()?;
        self.json.get_ref().sync_all()?;
        Ok(())
    }
}

pub fn collect(plan: &Plan, parent: &Path, options: &Options) -> Result<(PathBuf, Summary)> {
    collect_with_capacity(plan, parent, options, None)
}

pub struct CapacityUpdate {
    pub reserve: u64,
    pub host: Option<HostReserve>,
}
pub type CapacityHook<'a> = dyn FnMut(&Plan) -> Result<CapacityUpdate> + 'a;
pub fn collect_with_capacity(
    initial: &Plan,
    parent: &Path,
    options: &Options,
    capacity: Option<&mut CapacityHook<'_>>,
) -> Result<(PathBuf, Summary)> {
    collect_inner(initial, parent, options, capacity, None)
}
pub fn collect_phased(
    plan: &Plan,
    parent: &Path,
    options: &Options,
    phases: &crate::s3_phases::Run,
) -> Result<(PathBuf, Summary)> {
    collect_inner(plan, parent, options, None, Some(phases))
}
fn collect_inner(
    initial: &Plan,
    parent: &Path,
    options: &Options,
    mut capacity: Option<&mut CapacityHook<'_>>,
    phases: Option<&crate::s3_phases::Run>,
) -> Result<(PathBuf, Summary)> {
    ensure!(
        options.remote.is_none() || !options.ntfs_metadata,
        "Remote delivery exports streams and metadata separately; native container output is incompatible"
    );
    let mut owned_plan = initial.clone();
    let plan = &mut owned_plan;

    let mut source_ids = std::collections::HashSet::new();
    for s in &plan.sources {
        ensure!(
            !s.id.is_empty() && source_ids.insert(&s.id),
            "Duplicate or empty planned source ID"
        );
        ensure!(
            !paths::is_run_root_name(&s.id),
            "Source ID {} collides with a collection metadata name",
            s.id
        );
    }
    let mut file_ids = std::collections::HashSet::new();
    for f in &plan.files {
        ensure!(
            source_ids.contains(&f.source_id),
            "Planned task refers to an unknown source"
        );
        ensure!(file_ids.insert(&f.id), "Duplicate planned observation ID");
        paths::relative_text(&f.relative_path)?;
    }
    ensure!(
        options.threads > 0 && options.threads <= 128,
        "Threads must be in 1..=128"
    );
    let parent = paths::resolve_future(parent)?;
    for source in &plan.sources {
        // An ancestor destination is also rejected: later recursive tools could mix evidence.
        ensure!(
            source.live || (!parent.starts_with(&source.root) && !source.root.starts_with(&parent)),
            "Output and source trees must not overlap"
        );
    }
    ensure!(
        !options.ntfs_metadata || cfg!(windows),
        "Native NTFS metadata output requires Windows"
    );
    fs::create_dir_all(&parent)?;
    let hybrid = phases.and_then(|p| p.disk.as_ref());
    let streaming = options.remote.is_some() || hybrid.is_some();
    let required_payload = if streaming { 0 } else { plan.known_bytes };
    let available = fs2::available_space(&parent)?;
    ensure!(
        available
            >= required_payload
                .checked_add(options.reserve_bytes)
                .context("Space estimate overflow")?,
        "Insufficient destination space: {} required bytes plus {} reserved, {} available",
        required_payload,
        options.reserve_bytes,
        available
    );
    let computer = plan
        .sources
        .first()
        .map(|s| s.computer.as_str())
        .unwrap_or("UnknownComputer");
    let owned_early = options.early.is_none();
    let early = if let Some(v) = &options.early {
        Some(v.clone())
    } else {
        crate::early::prepare(
            &parent,
            computer,
            plan.memory_requested,
            options.live_info.as_ref(),
        )?
    };
    if let Some(early) = &early {
        early.validate(computer, plan.memory_requested)?;
        let expected: std::collections::HashSet<_> = options
            .live_info
            .as_ref()
            .map(|o| crate::live_info::select(&o.selected))
            .transpose()?
            .unwrap_or_default()
            .into_iter()
            .filter(|s| crate::ordering::live_priority(&s.name) <= 2)
            .map(|s| s.name)
            .collect();
        let actual: std::collections::HashSet<_> = early
            .live
            .as_ref()
            .map(|v| v.entries.iter().map(|e| e.provider.clone()).collect())
            .unwrap_or_default();
        ensure!(
            expected == actual,
            "Early volatile providers do not match the selected live scope"
        );
    }
    // RAM is already staged. Budget metadata here; import_memory first tries a
    // hard link, and requires the full extra dump size only if it must copy.
    // Keep the planned disk evidence and configured reserve available during import.
    let early_import_reserve = required_payload
        .checked_add(options.reserve_bytes)
        .and_then(|bytes| bytes.checked_add(early.as_ref().map_or(0, |e| e.metadata_bytes())))
        .context("Early import space estimate overflow")?;
    ensure!(
        fs2::available_space(&parent)? >= early_import_reserve,
        "Insufficient space to preserve the early volatile capture and selected artifacts"
    );
    let run_id = uuid::Uuid::new_v4().to_string();
    let root = parent.join(paths::run_name(computer, &plan.created_utc)?);
    fs::create_dir(&root).with_context(|| {
        format!(
            "Cannot create collection directory {}; each host/start-time name must be new",
            root.display()
        )
    })?;
    let destination_acl = platform::protect_output_root(&root)?;
    if destination_acl == "FilesystemHasNoPersistentACLs" && !options.quiet {
        ui::field(
            "Notice",
            "Destination filesystem cannot enforce per-file access controls; secure the storage separately.",
        );
    }
    write_json_new(
        &root.join(if options.entropy.is_some() {
            "InitialPlan.json"
        } else {
            "Plan.json"
        }),
        plan,
    )?;
    // A sealed collection boundary lets Juntei group sibling data volumes with
    // the Windows volume instead of discovering only C/Windows. `hostname` is
    // the interoperability field; this is collector metadata, not a source file.
    write_json_new(
        &root.join("client_info.json"),
        &serde_json::json!({
            "hostname": computer, "Collector": "Kumade", "CollectionStartedUtc": plan.created_utc
        }),
    )?;
    let mut run_metadata = serde_json::json!({"SchemaVersion":1,"RunId":run_id,"Version":env!("CARGO_PKG_VERSION"),"StartedUTC":plan.created_utc,"DirectoryTimestampTimezone":"UTC","FinalStateFile":"Summary.json","DestinationAccessControl":destination_acl,"DestinationOnLiveSource":plan.sources.iter().any(|s|s.live && (parent.starts_with(s.live_root()) || options.host_reserve.as_ref().is_some_and(|h| h.path.starts_with(s.live_root())))),"PhysicalHostDestination":options.host_reserve.as_ref().map(|h|h.path.display().to_string()),"EvidenceLayout":"DriveRoots","NativeNTFSStreams":options.ntfs_metadata,"LiveInfoEnabled":options.live_info.is_some(),"ProcessScanEnabled":options.process_scan.is_some(),"VolatilityOrdered":true,"CollectionOrder":["RAM request","Volatile process and network state","USN journal","NTFS transaction log","MFT","Event logs","Registry and active databases","Optional process YARA and remaining inventory","Other artifacts","Entropy analysis and extra binaries","Final metadata, seals and container encoding"],"RemoteDelivery":options.remote.as_ref().map(|r|r.id()),"EntropyDeferred":options.entropy.is_some(),"EntropyPreplanned":plan.entropy_scan.is_some() && options.entropy.is_none(),"VssEnabled":plan.sources.iter().any(|s|s.snapshot.is_some()),"ExistingVssEnabled":plan.sources.iter().any(|s|s.snapshot.as_ref().is_some_and(|v|v.owned_by_collector==Some(false))),"NTFSMetadataInventory":if options.ntfs_metadata || (cfg!(windows) && (options.remote.is_some() || phases.is_some())) {Some(metadata::FILES)}else{None},"Limitations":["New VSS snapshots are crash-consistent without application writers; historical writer consistency is unknown; live-response inventory is not snapshotted","Structural artifact validation is not implemented; Verified refers to stored-byte hashing","Acquisition is not an atomic machine snapshot"]});
    if hybrid.is_some() {
        run_metadata["HybridS3"] = true.into();
    }
    write_json_new(&root.join("Run.json"), &run_metadata)?;
    let mut prior_live = early
        .as_ref()
        .map(|e| e.import(&root))
        .transpose()?
        .flatten();
    let mut live_info = None;
    let mut process_scan_status = None;
    let new_file = |name: &str| -> Result<File> {
        Ok(OpenOptions::new()
            .write(true)
            .create_new(true)
            .open(root.join(name))?)
    };
    let journal = Arc::new(Mutex::new(Journal {
        remote: options.remote.clone(),
        json: BufWriter::new(new_file("Manifest.jsonl")?),
        csv: csv::Writer::from_writer(new_file("Manifest.csv")?),
        errors: csv::Writer::from_writer(new_file("Errors.csv")?),
    }));
    let records = Arc::new(Mutex::new(Vec::new()));
    let journal_errors = Arc::new(Mutex::new(Vec::new()));
    if !options.quiet {
        println!();
        ui::status("Collecting evidence…");
        println!();
    }
    let capture_metadata =
        options.ntfs_metadata || (cfg!(windows) && (options.remote.is_some() || phases.is_some()));
    let mut ntfs_metadata = capture_metadata.then(Vec::<metadata::Snapshot>::new);
    let mut snapshot_keys = std::collections::HashSet::new();
    let mut sparse_sources = std::collections::HashSet::new();
    let progress = ui::progress_bar(plan.files.len() as u64, options.quiet || options.verbose);
    let started = plan.created_utc.clone();
    let timer = Instant::now();
    let memory_record = early
        .as_ref()
        .map(|e| {
            e.import_memory(
                &root,
                options.remote.as_deref(),
                early_import_reserve,
                options.host_reserve.as_ref(),
            )
        })
        .transpose()?
        .flatten();
    if let Some(memory) = &memory_record {
        journal
            .lock()
            .map_err(|_| anyhow::anyhow!("Journal poisoned"))?
            .append(memory)?;
        records
            .lock()
            .map_err(|_| anyhow::anyhow!("Record state poisoned"))?
            .push(memory.clone());
    }
    let pagefile_records = early
        .as_ref()
        .map(|e| e.imported_pagefiles(options.remote.as_deref()))
        .transpose()?
        .unwrap_or_default();
    for row in &pagefile_records {
        journal
            .lock()
            .map_err(|_| anyhow::anyhow!("Journal poisoned"))?
            .append(row)?;
        records
            .lock()
            .map_err(|_| anyhow::anyhow!("Record state poisoned"))?
            .push(row.clone());
    }
    let mut reserve = options.reserve_bytes;
    let mut host_reserve = options.host_reserve.clone();
    let pool = rayon::ThreadPoolBuilder::new()
        .num_threads(options.threads)
        .build()?;
    // First pass: hot artifacts. Then expensive optional hunts/configuration,
    // followed by less volatile disk evidence. Every batch has a completion barrier.
    for section in 0..=2 {
        if section == 1 {
            process_scan_status = process_scan(&root, options)?;
            live_info = options
                .live_info
                .as_ref()
                .map(|config| {
                    crate::live_info::collect_remaining_into(&root, config, prior_live.take())
                })
                .transpose()?;
        }
        let previous_ids: std::collections::HashSet<_> =
            plan.files.iter().map(|f| f.id.clone()).collect();
        if section == 2 {
            let Some(settings) = &options.entropy else {
                continue;
            };
            if !options.quiet {
                ui::status("Selected artifacts acquired; starting deferred entropy analysis…");
            }
            let mut copies = HashMap::new();
            {
                let acquired = records
                    .lock()
                    .map_err(|_| anyhow::anyhow!("Record state poisoned"))?;
                let by_id: HashMap<_, _> =
                    acquired.iter().map(|r| (&r.observation_id, r)).collect();
                for f in &plan.files {
                    if f.stream.is_some() {
                        continue;
                    }
                    if let Some(r) = by_id.get(&f.id).filter(|r| r.status == "Acquired")
                        && let (Some(path), Some(hash)) = (&r.relative_output_path, &r.sha256)
                    {
                        copies.insert(
                            (f.source_id.clone(), f.relative_path.clone()),
                            crate::entropy::CopyInput {
                                root: root.clone(),
                                path: paths::safe_join(&root, path)?,
                                sha256: hash.clone(),
                                before: f.before.clone(),
                            },
                        );
                    }
                }
            }
            let mut settings = settings.clone();
            let mut outputs = vec![root.clone(), parent.clone()];
            if let Some(capture) = &early {
                outputs.push(capture.root.clone());
            }
            crate::entropy::exclude_output_paths(&mut settings, &plan.sources, &outputs)?;
            crate::entropy::augment_with_copies(
                plan,
                &settings,
                &root,
                options.threads,
                options.quiet,
                &copies,
            )?;
            #[cfg(windows)]
            if options.ntfs_metadata || options.remote.is_some() || phases.is_some() {
                metadata::augment_streams(plan)?;
            }
            if let Some(hook) = capacity.as_mut() {
                let update = hook(plan)?;
                reserve = update.reserve;
                host_reserve = update.host;
            }
            progress.set_length(plan.files.len() as u64);
        }
        let sources: HashMap<_, _> = plan.sources.iter().map(|s| (s.id.clone(), s)).collect();
        let files: Vec<_> = plan
            .files
            .iter()
            .filter(|f| section != 2 || !previous_ids.contains(&f.id))
            .cloned()
            .collect();
        for (priority, batch) in crate::ordering::batches(&files, options.ntfs_metadata) {
            if (section == 0 && priority > 5) || (section == 1 && priority <= 5) {
                continue;
            }
            if let Some(inventory) = ntfs_metadata.as_mut() {
                for snapshot in metadata::prepare(plan, &batch) {
                    if snapshot_keys.insert((
                        snapshot.source_id.clone(),
                        snapshot.relative_output_path.clone(),
                    )) {
                        if snapshot.attributes.is_some_and(|a| a & 0x200 != 0) {
                            sparse_sources
                                .insert((snapshot.source_id.clone(), snapshot.source_path.clone()));
                        }
                        inventory.push(snapshot);
                    }
                }
            }
            if !options.quiet {
                progress.suspend(|| {
                    ui::field(
                        "Acquisition stage",
                        if section == 2 {
                            "Additional entropy candidates"
                        } else {
                            crate::ordering::LABELS[priority]
                        },
                    )
                });
            }
            pool.install(|| {
                batch
                    .par_iter()
                    .for_each_init(HashMap::new, |raw_cache, item| {
                        let source = sources[&item.source_id];
                        if options.verbose && !options.quiet {
                            let mut path = item.source_path.display().to_string();
                            if let Some(stream) = &item.stream {
                                path.push(':');
                                path.push_str(stream);
                            }
                            ui::field("Copying", path);
                        } else if !options.quiet {
                            progress.set_message(ui::progress_message(
                                &format!("{}/{}", source.id, item.relative_path.display()),
                                item.before.as_ref().map(|m| m.size),
                            ));
                        }
                        let record = acquire_one_inner(
                            &root,
                            source,
                            item,
                            reserve,
                            raw_cache,
                            DestinationPolicy {
                                remote: options.remote.as_ref(),
                                native_ntfs: options.ntfs_metadata,
                                phased_s3: phases.is_some(),
                                hybrid,
                                source_sparse: sparse_sources.contains(&(
                                    source.id.clone(),
                                    item.source_path.display().to_string(),
                                )),
                                host_reserve: host_reserve.as_ref(),
                            },
                        );
                        match journal.lock() {
                            Ok(mut j) => {
                                if let Err(e) = j.append(&record)
                                    && let Ok(mut v) = journal_errors.lock()
                                {
                                    v.push(format!("{e:#}"));
                                }
                            }
                            Err(e) => {
                                if let Ok(mut v) = journal_errors.lock() {
                                    v.push(e.to_string());
                                }
                            }
                        }
                        if let Ok(mut v) = records.lock() {
                            v.push(record);
                        }
                        progress.inc(1);
                    })
            });
        }
        if section == 0
            && let Some(phases) = phases
        {
            let rows = records
                .lock()
                .map_err(|_| anyhow::anyhow!("Record state poisoned"))?;
            let discovery_failed = plan
                .issues
                .iter()
                .any(|issue| matches!(issue.status.as_str(), "Failed" | "Unsupported"));
            phases.hot_disk(&root, &rows, discovery_failed)?;
        }
    }
    progress.finish_and_clear();
    journal
        .lock()
        .map_err(|_| anyhow::anyhow!("Manifest journal mutex poisoned"))?
        .finish()?;
    let failures = journal_errors
        .lock()
        .map_err(|_| anyhow::anyhow!("Journal error state poisoned"))?;
    if !failures.is_empty() {
        // A lost remote connection fails every later record the same way.
        let mut distinct = std::collections::BTreeMap::<&str, usize>::new();
        for failure in failures.iter() {
            *distinct.entry(failure.as_str()).or_default() += 1;
        }
        let summary: Vec<String> = distinct
            .iter()
            .map(|(message, count)| {
                if *count > 1 {
                    format!("{message} ({count} records)")
                } else {
                    (*message).to_owned()
                }
            })
            .collect();
        bail!(
            "Cannot seal collection because manifest writing failed: {}",
            summary.join("; ")
        );
    }
    let records = records
        .lock()
        .map_err(|_| anyhow::anyhow!("Record state poisoned"))?;
    let mut summary = Summary {
        schema_version: 1,
        run_id,
        version: env!("CARGO_PKG_VERSION").into(),
        started_utc: started,
        finished_utc: utc_now(),
        completeness: "CompleteWithinSelectedPrototypeScope".into(),
        collected: 0,
        partial: 0,
        failed: 0,
        discovery_errors: plan
            .issues
            .iter()
            .filter(|i| i.status == "Failed" || i.status == "Unsupported")
            .count() as u64,
        bytes_acquired: 0,
        catalog_sha256: plan.catalog_sha256.clone(),
        metadata_errors: 0,
        live_info_failed_providers: live_info.as_ref().map_or(0, |r| r.failures()),
        process_scan_status,
    };
    for record in records.iter() {
        match record.status.as_str() {
            "Acquired" | "Transferred" => summary.collected += 1,
            "Partial" => summary.partial += 1,
            "Failed" => summary.failed += 1,
            _ => {}
        }
        summary.bytes_acquired = summary
            .bytes_acquired
            .checked_add(record.bytes_read)
            .context("Summary size overflow")?;
    }
    if options.remote.is_some() {
        summary.completeness = "PendingServerReadbackVerification".into();
    }
    let entropy_version_mismatches = if streaming {
        let expected: HashMap<_, _> = plan
            .files
            .iter()
            .filter_map(|f| f.expected_sha256.as_ref().map(|h| (&f.id, h)))
            .collect();
        records
            .iter()
            .filter(|r| {
                expected
                    .get(&r.observation_id)
                    .is_some_and(|h| r.sha256.as_ref() != Some(*h))
            })
            .count()
    } else {
        0
    };
    if entropy_version_mismatches > 0 {
        eprintln!(
            "{entropy_version_mismatches} streamed files differed from later entropy analysis; consult HashMatchesAnalysis in the entropy report"
        );
    }
    if entropy_version_mismatches > 0
        || summary.failed > 0
        || summary.partial > 0
        || summary.discovery_errors > 0
        || summary.live_info_failed_providers > 0
        || summary
            .process_scan_status
            .as_deref()
            .is_some_and(|s| s != "Success")
    {
        summary.completeness = "Partial".into();
    }
    ensure!(
        records.len()
            == plan.files.len() + usize::from(plan.memory_requested) + pagefile_records.len(),
        "Not every planned task produced a result"
    );
    let membership: HashMap<_, _> = plan.files.iter().map(|f| (&f.id, &f.artifacts)).collect();
    let mut coverage = csv::Writer::from_writer(new_file("Coverage.csv")?);
    for planned in &plan.coverage {
        let mut family = FamilyCoverage {
            source_id: planned.source_id.clone(),
            artifact_id: planned.artifact_id.clone(),
            planned: planned.discovered,
            acquired: 0,
            partial: 0,
            failed: 0,
            not_present: 0,
            status: planned.status.clone(),
            reason: planned.reason.clone(),
        };
        for record in records.iter().filter(|r| {
            r.source_id == planned.source_id
                && membership
                    .get(&r.observation_id)
                    .is_some_and(|ids| ids.contains(&planned.artifact_id))
        }) {
            match record.status.as_str() {
                "Acquired" | "Transferred" => family.acquired += 1,
                "Partial" => family.partial += 1,
                "Failed" => family.failed += 1,
                "NotPresent" => family.not_present += 1,
                _ => {}
            }
        }
        if family.status != "Excluded" {
            let discovery_failed = plan.issues.iter().any(|i| {
                i.source_id == planned.source_id
                    && (i.status == "Failed" || i.status == "Unsupported")
            });
            if family.failed > 0 || family.partial > 0 || discovery_failed {
                family.status = "Partial".into();
                family.reason="Acquisition or discovery was incomplete; consult the manifest and discovery issues".into();
            } else if family.acquired > 0 {
                family.status = if streaming { "Transferred" } else { "Acquired" }.into();
                family.reason = if streaming { "All discovered members streamed; server readback remains pending" } else { "All discovered members were copied and hash-verified; format/atomic consistency is not established" }.into();
            } else if family.not_present > 0 {
                family.status = "NotPresent".into();
                family.reason = "Raw candidates were not present".into();
            }
        }
        coverage.serialize(family)?;
    }
    if plan.memory_requested {
        coverage.serialize(FamilyCoverage {
            source_id: "Memory".into(),
            artifact_id: "windows.memory".into(),
            planned: 1,
            acquired: u64::from(
                memory_record
                    .as_ref()
                    .is_some_and(|r| matches!(r.status.as_str(), "Acquired" | "Transferred")),
            ),
            partial: u64::from(
                memory_record
                    .as_ref()
                    .is_some_and(|r| r.status == "Partial"),
            ),
            failed: u64::from(memory_record.as_ref().is_none_or(|r| r.status == "Failed")),
            not_present: 0,
            status: memory_record
                .as_ref()
                .map_or("Failed", |r| r.status.as_str())
                .into(),
            reason: memory_record
                .as_ref()
                .map_or("RAM capture missing", |r| r.reason.as_str())
                .into(),
        })?;
    }
    for row in &pagefile_records {
        coverage.serialize(FamilyCoverage {
            source_id: row.source_id.clone(),
            artifact_id: row.artifact_ids.clone(),
            planned: 1,
            acquired: u64::from(matches!(row.status.as_str(), "Acquired" | "Transferred")),
            partial: u64::from(row.status == "Partial"),
            failed: u64::from(row.status == "Failed"),
            not_present: 0,
            status: row.status.clone(),
            reason: row.reason.clone(),
        })?;
    }
    coverage.flush()?;
    journal
        .lock()
        .map_err(|_| anyhow::anyhow!("Journal poisoned"))?
        .finish()?;
    if let Some(snapshots) = ntfs_metadata.as_mut() {
        if !options.quiet {
            ui::status(if options.remote.is_some() || phases.is_some() {
                "Sealing NTFS metadata inventory (no server-side restoration)…"
            } else {
                "Restoring NTFS metadata and original permissions…"
            });
        }
        if options.remote.is_some() || phases.is_some() {
            summary.metadata_errors = metadata::remote_inventory(snapshots, &records) as u64;
        } else {
            summary.metadata_errors = metadata::restore(&root, snapshots, &records) as u64;
        }
        if summary.metadata_errors > 0 {
            summary.completeness = "Partial".into();
        }
        metadata::write_inventory(&root, snapshots)?;
    }
    if let Some(report) = &plan.entropy_scan {
        crate::entropy::write_report(&root, report, &records)?;
    }
    if options.entropy.is_some() {
        write_json_new(&root.join("Plan.json"), plan)?;
    }
    let mut discovery = csv::Writer::from_writer(new_file("DiscoveryIssues.csv")?);
    for issue in &plan.issues {
        discovery.serialize(issue)?;
    }
    discovery.flush()?;
    write_json_new(&root.join("Summary.json"), &summary)?;
    let (_, manifest_hash) = hash_file(&root.join("Manifest.jsonl"))?;
    let mut metadata = std::collections::BTreeMap::new();
    for name in [
        "Plan.json",
        "client_info.json",
        "Run.json",
        "Manifest.jsonl",
        "Manifest.csv",
        "Coverage.csv",
        "DiscoveryIssues.csv",
        "Errors.csv",
        "Summary.json",
    ] {
        metadata.insert(name.to_owned(), hash_file(&root.join(name))?.1);
    }
    if plan.memory_requested {
        for entry in fs::read_dir(root.join("Memory"))? {
            let entry = entry?;
            if entry.file_name() != "Memory.dmp"
                && !pagefile_records.iter().any(|r| {
                    r.relative_output_path.as_deref().is_some_and(|p| {
                        p.strip_prefix("Early/").unwrap_or(p)
                            == format!("Memory/{}", entry.file_name().to_string_lossy())
                    })
                })
            {
                metadata.insert(
                    format!("Memory/{}", entry.file_name().to_string_lossy()),
                    hash_file(&entry.path())?.1,
                );
            }
        }
    }
    if options.entropy.is_some() {
        metadata.insert(
            "InitialPlan.json".into(),
            hash_file(&root.join("InitialPlan.json"))?.1,
        );
    }
    if plan.entropy_scan.is_some() {
        for name in crate::entropy::FILES {
            metadata.insert((*name).into(), hash_file(&root.join(name))?.1);
        }
    }
    if options.process_scan.is_some() {
        for entry in walkdir::WalkDir::new(root.join("YaraScan")).follow_links(false) {
            let entry = entry?;
            if entry.file_type().is_dir() {
                continue;
            }
            ensure!(
                entry.file_type().is_file() && !platform::is_reparse_directory(entry.path()),
                "Unsafe process-scan report"
            );
            let relative = paths::relative_text(entry.path().strip_prefix(&root)?)?;
            metadata.insert(relative, hash_file(entry.path())?.1);
        }
    }
    if capture_metadata {
        for name in metadata::FILES {
            metadata.insert(name.to_owned(), hash_file(&root.join(name))?.1);
        }
    }
    if let Some(info) = &live_info {
        for name in &info.files {
            metadata.insert(name.clone(), hash_file(&root.join(name))?.1);
        }
    }
    write_json_new(
        &root.join("Seal.json"),
        &serde_json::json!({"SchemaVersion":1,"RunId":summary.run_id,"ManifestSHA256":manifest_hash,"MetadataSHA256":metadata,"SealedUTC":utc_now(),"Signature":"NotConfigured"}),
    )?;
    if !options.quiet {
        let mut file_count = 0u64;
        let mut output_bytes = 0u64;
        if !options.ntfs_metadata {
            for entry in walkdir::WalkDir::new(&root).follow_links(false) {
                let entry = entry?;
                if entry.file_type().is_file() {
                    file_count += 1;
                    output_bytes = output_bytes
                        .checked_add(entry.metadata()?.len())
                        .context("Output size overflow")?;
                }
            }
        }
        println!();
        ui::heading("Results Summary:");
        ui::field("Collected", ui::count(summary.collected));
        ui::field("Partial", ui::count(summary.partial));
        ui::field("Failed", ui::count(summary.failed));
        ui::field("Discovery errors", ui::count(summary.discovery_errors));
        if let Some(info) = &live_info {
            ui::field("Live-info datasets", ui::count(info.entries.len() as u64));
            ui::field(
                "Live-info failures",
                ui::count(summary.live_info_failed_providers),
            );
        }
        if capture_metadata {
            ui::field("Metadata errors", ui::count(summary.metadata_errors));
        }
        if !options.ntfs_metadata && options.remote.is_none() {
            ui::field(
                "Results saved",
                format!(
                    "{}/ ( {} files / {} )",
                    root.display(),
                    ui::count(file_count),
                    human_bytes(output_bytes)
                ),
            );
        }
        if let Some(status) = &summary.process_scan_status {
            ui::field("Process scan", format!("{status} (see YaraScan/)"));
        }
        ui::field("Completeness", &summary.completeness);
        ui::field("Elapsed", format!("{:.3}s", timer.elapsed().as_secs_f64()));
    }
    if owned_early
        && options.remote.is_none()
        && let Some(capture) = early
    {
        capture.cleanup()?;
    }
    Ok((root, summary))
}

pub fn human_bytes(bytes: u64) -> String {
    const UNITS: [&str; 5] = ["B", "KiB", "MiB", "GiB", "TiB"];
    let mut value = bytes as f64;
    let mut unit = 0;
    while value >= 1024.0 && unit < UNITS.len() - 1 {
        value /= 1024.0;
        unit += 1;
    }
    if unit == 0 {
        format!("{bytes} B")
    } else {
        format!("{value:.1} {}", UNITS[unit])
    }
}

pub fn clip_label(text: &str, width: usize) -> String {
    use unicode_width::{UnicodeWidthChar, UnicodeWidthStr};
    let clean: String = text
        .chars()
        .map(|c| if c.is_control() { '?' } else { c })
        .collect();
    let truncated = clean.width() > width;
    let limit = if truncated {
        width.saturating_sub(1)
    } else {
        width
    };
    let mut result = String::new();
    let mut used = 0;
    for c in clean.chars() {
        let cells = c.width().unwrap_or(0);
        if used + cells > limit {
            break;
        }
        result.push(c);
        used += cells;
    }
    if truncated && width > 0 {
        result.push('…');
    }
    result
}

pub(crate) fn commit_payload(from: &Path, to: &Path) -> Result<()> {
    #[cfg(target_os = "linux")]
    {
        use std::{ffi::CString, os::unix::ffi::OsStrExt};
        let from = CString::new(from.as_os_str().as_bytes())?;
        let to = CString::new(to.as_os_str().as_bytes())?;
        // Use the kernel entry point: musl does not export a renameat2 wrapper.
        // SAFETY: both paths are NUL-terminated; AT_FDCWD uses absolute owned paths.
        let code = unsafe {
            libc::syscall(
                libc::SYS_renameat2,
                libc::AT_FDCWD,
                from.as_ptr(),
                libc::AT_FDCWD,
                to.as_ptr(),
                libc::RENAME_NOREPLACE,
            )
        };
        if code != 0 {
            return Err(io::Error::last_os_error()).context("Cannot exclusively commit payload");
        }
        Ok(())
    }
    #[cfg(windows)]
    {
        use std::os::windows::ffi::OsStrExt;
        let a: Vec<u16> = from.as_os_str().encode_wide().chain(Some(0)).collect();
        let b: Vec<u16> = to.as_os_str().encode_wide().chain(Some(0)).collect();
        // SAFETY: both paths are valid NUL-terminated strings; MoveFileW does not overwrite.
        ensure!(
            // SAFETY: both buffers are owned NUL-terminated absolute paths.
            unsafe { windows_sys::Win32::Storage::FileSystem::MoveFileW(a.as_ptr(), b.as_ptr()) }
                != 0,
            "Cannot exclusively commit payload: {}",
            io::Error::last_os_error()
        );
        Ok(())
    }
    #[cfg(target_os = "macos")]
    {
        use std::{ffi::CString, os::unix::ffi::OsStrExt};
        let from = CString::new(from.as_os_str().as_bytes())?;
        let to = CString::new(to.as_os_str().as_bytes())?;
        // SAFETY: both paths are NUL-terminated; RENAME_EXCL refuses existing destinations.
        if unsafe { libc::renamex_np(from.as_ptr(), to.as_ptr(), libc::RENAME_EXCL) } != 0 {
            return Err(io::Error::last_os_error()).context("Cannot exclusively commit payload");
        }
        Ok(())
    }
    #[cfg(not(any(windows, target_os = "linux", target_os = "macos")))]
    {
        fs::hard_link(from, to)
            .context("Destination must support exclusive hard-link commits on this platform")?;
        fs::remove_file(from)?;
        Ok(())
    }
}

fn process_scan(root: &Path, options: &Options) -> Result<Option<String>> {
    let status = if let Some(config) = &options.process_scan {
        if !options.quiet {
            ui::status("Scanning live process memory with YARA…");
        }
        let mut config = config.clone();
        config.output = root.join("YaraScan");
        config.quiet = true;
        Some(match crate::yara_scan::run(&config) {
            Ok(0) => "Success".into(),
            Ok(_) => "Partial".into(),
            Err(error) => {
                fs::create_dir_all(&config.output)?;
                platform::protect_output_root(&config.output)?;
                write_json_new(
                    &config.output.join("Failure.json"),
                    &serde_json::json!({"Status":"Failed","Error":format!("{error:#}")}),
                )?;
                "Failed".into()
            }
        })
    } else {
        None
    };
    Ok(status)
}

#[cfg(test)]
mod commit_tests {
    use super::commit_payload;
    use std::fs;

    #[test]
    fn exclusive_commit_never_overwrites_an_existing_payload() {
        let t = tempfile::tempdir().unwrap();
        let from = t.path().join("pending");
        let to = t.path().join("existing");
        fs::write(&from, b"new bytes").unwrap();
        fs::write(&to, b"original evidence").unwrap();
        assert!(commit_payload(&from, &to).is_err());
        assert_eq!(fs::read(&from).unwrap(), b"new bytes");
        assert_eq!(fs::read(&to).unwrap(), b"original evidence");
    }

    #[test]
    fn exclusive_commit_preserves_bytes_and_removes_only_the_pending_name() {
        let t = tempfile::tempdir().unwrap();
        let from = t.path().join("pending");
        let to = t.path().join("payload");
        fs::write(&from, b"captured bytes").unwrap();
        commit_payload(&from, &to).unwrap();
        assert!(!from.exists());
        assert_eq!(fs::read(&to).unwrap(), b"captured bytes");
    }
}
