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

pub struct Options {
    pub threads: usize,
    pub reserve_bytes: u64,
    pub quiet: bool,
    pub verbose: bool,
    pub ntfs_metadata: bool,
    pub host_reserve: Option<HostReserve>,
    pub live_info: Option<crate::live_info::Options>,
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

fn source_fingerprint(file: &File, native_ntfs: bool) -> Result<Fingerprint> {
    let value = fingerprint(&file.metadata()?);
    #[cfg(windows)]
    {
        let mut value = value;
        if native_ntfs {
            value.identity = Some(metadata::file_identity(file)?);
        }
        Ok(value)
    }
    #[cfg(not(windows))]
    {
        let _ = native_ntfs;
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
    native_ntfs: bool,
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
        method: "NativeRead".into(),
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
    let outcome = (|| -> Result<()> {
        let relative = if native_ntfs {
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
        let native_path = if let Some(stream) = &item.stream {
            PathBuf::from(format!("{}:{stream}", item.source_path.display()))
        } else {
            item.source_path.clone()
        };
        let copied = (|| -> Result<(Fingerprint, Fingerprint)> {
            match platform::open_source(&native_path) {
                Ok(mut input) => {
                    platform::validate_open_file(&input, &source.root)?;
                    let before = source_fingerprint(&input, native_ntfs)?;
                    #[cfg(windows)]
                    if native_ntfs {
                        use std::os::windows::fs::MetadataExt;
                        if input.metadata()?.file_attributes() & 0x200 != 0 && !transfer.sparse {
                            transfer.sparse = platform::enable_sparse_output(&transfer.file);
                            ensure!(transfer.sparse, "Cannot preserve sparse source stream");
                        }
                    }
                    let limit = before.size.checked_add(1).context("Source size overflow")?;
                    io::copy(&mut Read::by_ref(&mut input).take(limit), &mut transfer)?;
                    let after = source_fingerprint(&input, native_ntfs)?;
                    ensure!(
                        transfer.bytes == before.size,
                        "Source changed size or ended early during acquisition"
                    );
                    Ok((before, after))
                }
                Err(native_error) => {
                    let Some(device) = &source.raw_device else {
                        return Err(native_error)
                            .context("Native read failed; source has no raw NTFS provider");
                    };
                    record.method = "RawNTFS".into();
                    if !raw_cache.contains_key(device) {
                        raw_cache.insert(device.clone(), RawVolume::open(device)?);
                    }
                    let result = raw_cache
                        .get_mut(device)
                        .context("Raw provider missing")?
                        .copy_file_with_attributes(
                            &item.relative_path,
                            item.stream.as_deref(),
                            &mut transfer,
                            |attributes, writer| {
                                if native_ntfs && attributes & 0x200 != 0 && !writer.sparse {
                                    writer.sparse = platform::enable_sparse_output(&writer.file);
                                    ensure!(writer.sparse, "Cannot preserve sparse source stream");
                                }
                                Ok(())
                            },
                        )?;
                    ensure!(
                        result.bytes == transfer.bytes,
                        "Raw reader/writer byte count mismatch"
                    );
                    Ok((result.before, result.after))
                }
            }
        })();
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
                if record.changed_during_read {
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
                if item.before.is_none() && crate::raw::is_missing(&error) && record.bytes_read == 0
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

struct Journal {
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
        // The append is durable before this task is considered journaled.
        self.json.get_ref().sync_data()?;
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
    let available = fs2::available_space(&parent)?;
    ensure!(
        available
            >= plan
                .known_bytes
                .checked_add(options.reserve_bytes)
                .context("Space estimate overflow")?,
        "Insufficient destination space: {} required bytes plus {} reserved, {} available",
        plan.known_bytes,
        options.reserve_bytes,
        available
    );
    let run_id = uuid::Uuid::new_v4().to_string();
    let computer = plan
        .sources
        .first()
        .map(|s| s.computer.as_str())
        .unwrap_or("UnknownComputer");
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
    write_json_new(&root.join("Plan.json"), plan)?;
    // A sealed collection boundary lets Juntei group sibling data volumes with
    // the Windows volume instead of discovering only C/Windows. `hostname` is
    // the interoperability field; this is collector metadata, not a source file.
    write_json_new(
        &root.join("client_info.json"),
        &serde_json::json!({
            "hostname": computer, "Collector": "Kumade", "CollectionStartedUtc": plan.created_utc
        }),
    )?;
    write_json_new(
        &root.join("Run.json"),
        &serde_json::json!({"SchemaVersion":1,"RunId":run_id,"Version":env!("CARGO_PKG_VERSION"),"StartedUTC":plan.created_utc,"DirectoryTimestampTimezone":"UTC","FinalStateFile":"Summary.json","DestinationAccessControl":destination_acl,"DestinationOnLiveSource":plan.sources.iter().any(|s|s.live && (parent.starts_with(&s.root) || options.host_reserve.as_ref().is_some_and(|h| h.path.starts_with(&s.root)))),"PhysicalHostDestination":options.host_reserve.as_ref().map(|h|h.path.display().to_string()),"EvidenceLayout":"DriveRoots","NativeNTFSStreams":options.ntfs_metadata,"LiveInfoEnabled":options.live_info.is_some(),"NTFSMetadataInventory":if options.ntfs_metadata {Some(metadata::FILES)}else{None},"Limitations":["VSS acquisition is not implemented in this prototype","Structural artifact validation is not implemented; Verified refers to stored-byte hashing","Acquisition is not an atomic machine snapshot"]}),
    )?;
    // Capture volatile state before potentially lengthy file copying. Explicit offline
    // collection never supplies this option; container backends carry it unchanged.
    let live_info = options
        .live_info
        .as_ref()
        .map(|config| crate::live_info::collect_into(&root, config))
        .transpose()?;
    let new_file = |name: &str| -> Result<File> {
        Ok(OpenOptions::new()
            .write(true)
            .create_new(true)
            .open(root.join(name))?)
    };
    let mut discovery = csv::Writer::from_writer(new_file("DiscoveryIssues.csv")?);
    for i in &plan.issues {
        discovery.serialize(i)?;
    }
    discovery.flush()?;
    let journal = Arc::new(Mutex::new(Journal {
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
    let mut ntfs_metadata = options.ntfs_metadata.then(|| metadata::prepare(plan));
    let sparse_sources: std::collections::HashSet<_> = ntfs_metadata
        .as_deref()
        .unwrap_or_default()
        .iter()
        .filter(|s| s.attributes.is_some_and(|a| a & 0x200 != 0))
        .map(|s| (s.source_id.clone(), s.source_path.clone()))
        .collect();
    let progress = ui::progress_bar(plan.files.len() as u64, options.quiet || options.verbose);
    let started = utc_now();
    let timer = Instant::now();
    let sources: HashMap<_, _> = plan.sources.iter().map(|s| (s.id.clone(), s)).collect();
    let pool = rayon::ThreadPoolBuilder::new()
        .num_threads(options.threads.min(plan.files.len().max(1)))
        .build()?;
    for phase in 0..if options.ntfs_metadata { 2 } else { 1 } {
        pool.install(|| {
            plan.files
                .par_iter()
                .filter(|item| !options.ntfs_metadata || item.stream.is_some() == (phase == 1))
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
                        options.reserve_bytes,
                        raw_cache,
                        DestinationPolicy {
                            native_ntfs: options.ntfs_metadata,
                            source_sparse: sparse_sources.contains(&(
                                source.id.clone(),
                                item.source_path.display().to_string(),
                            )),
                            host_reserve: options.host_reserve.as_ref(),
                        },
                    );
                    match journal.lock() {
                        Ok(mut j) => {
                            if let Err(e) = j.append(&record)
                                && let Ok(mut v) = journal_errors.lock()
                            {
                                v.push(e.to_string());
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
    progress.finish_and_clear();
    journal
        .lock()
        .map_err(|_| anyhow::anyhow!("Manifest journal mutex poisoned"))?
        .finish()?;
    let failures = journal_errors
        .lock()
        .map_err(|_| anyhow::anyhow!("Journal error state poisoned"))?;
    ensure!(
        failures.is_empty(),
        "Cannot seal collection because manifest writing failed: {}",
        failures.join("; ")
    );
    let mut records = records
        .lock()
        .map_err(|_| anyhow::anyhow!("Record state poisoned"))?;
    if plan.memory_requested {
        let record=Record{schema_version:1,observation_id:uuid::Uuid::new_v4().to_string(),computer:computer.into(),source_id:"Memory".into(),source_path:"Physical RAM".into(),stream_name:None,artifact_ids:"windows.memory".into(),relative_output_path:None,method:"MemoryProvider".into(),status:"Failed".into(),reason:"RAM acquisition is not implemented in this prototype; no memory image has been acquired".into(),started_utc:started.clone(),finished_utc:utc_now(),logical_size:None,bytes_read:0,sha256:None,verified:false,changed_during_read:false,created_utc:None,modified_utc:None,accessed_utc:None,source_file_id:None};
        journal
            .lock()
            .map_err(|_| anyhow::anyhow!("Journal poisoned"))?
            .append(&record)?;
        records.push(record);
    }
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
    };
    for record in records.iter() {
        match record.status.as_str() {
            "Acquired" => summary.collected += 1,
            "Partial" => summary.partial += 1,
            "Failed" => summary.failed += 1,
            _ => {}
        }
        summary.bytes_acquired = summary
            .bytes_acquired
            .checked_add(record.bytes_read)
            .context("Summary size overflow")?;
    }
    if summary.failed > 0
        || summary.partial > 0
        || summary.discovery_errors > 0
        || summary.live_info_failed_providers > 0
    {
        summary.completeness = "Partial".into();
    }
    ensure!(
        records.len() == plan.files.len() + usize::from(plan.memory_requested),
        "Not every planned task produced a result"
    );
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
                && r.artifact_ids
                    .split(';')
                    .any(|id| id == planned.artifact_id)
        }) {
            match record.status.as_str() {
                "Acquired" => family.acquired += 1,
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
                family.status = "Acquired".into();
                family.reason="All discovered members were copied and hash-verified; format/atomic consistency is not established".into();
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
            acquired: 0,
            partial: 0,
            failed: 1,
            not_present: 0,
            status: "Failed".into(),
            reason: "RAM acquisition is not implemented in this prototype".into(),
        })?;
    }
    coverage.flush()?;
    journal
        .lock()
        .map_err(|_| anyhow::anyhow!("Journal poisoned"))?
        .finish()?;
    if let Some(snapshots) = ntfs_metadata.as_mut() {
        if !options.quiet {
            ui::status("Restoring NTFS metadata and original permissions…");
        }
        summary.metadata_errors = metadata::restore(&root, snapshots, &records) as u64;
        if summary.metadata_errors > 0 {
            summary.completeness = "Partial".into();
        }
        metadata::write_inventory(&root, snapshots)?;
    }
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
    if options.ntfs_metadata {
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
        if options.ntfs_metadata {
            ui::field("Metadata errors", ui::count(summary.metadata_errors));
        }
        if !options.ntfs_metadata {
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
        ui::field("Completeness", &summary.completeness);
        ui::field("Elapsed", format!("{:.3}s", timer.elapsed().as_secs_f64()));
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
    #[cfg(not(any(windows, target_os = "linux")))]
    {
        fs::hard_link(from, to)
            .context("Destination must support exclusive hard-link commits on this platform")?;
        fs::remove_file(from)?;
        Ok(())
    }
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
