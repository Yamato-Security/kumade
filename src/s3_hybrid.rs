// Copyright (C) 2026 Shirofune Security Co., Ltd.
// SPDX-License-Identifier: RPL-1.5

//! Bulk evidence is read once from the source. Commit a small local receipt
//! after all its create-only S3 writes are acknowledged. Recovery reads receipts
//! and sealed volatile files and never needs access to the original host.
use super::{
    Bucket, Chunk, ConnectionArgs, Entry, Location, Member, Plan, Record, Session, Source, collect,
    digest_valid, json, paths, relative, save, sha256, store_chunk, utc_now, validate_chunks,
};
use crate::{
    model::{self, PlannedFile, hex},
    raw::{self, RawVolume},
    sftp,
};
use anyhow::{Context, Result, ensure};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use std::{
    collections::{BTreeMap, HashMap},
    fs,
    io::{self, Write},
    path::{Path, PathBuf},
};
use uuid::Uuid;

#[derive(Serialize, Deserialize)]
#[serde(rename_all = "PascalCase")]
struct AcknowledgedFile {
    observation: Record,
    member: Member,
}

fn receipt_name(path: &str) -> String {
    format!("{}.json", sha256(path.as_bytes()))
}

pub(super) fn acknowledged(root: &Path, id: Uuid, file: &Entry) -> Result<Option<Member>> {
    let name = format!("Streamed/{}", receipt_name(&file.path));
    if !root.join(&name).try_exists()? {
        return Ok(None);
    }
    let receipt: AcknowledgedFile = json(&paths::safe_join(root, &name)?)?;
    ensure!(
        receipt.member.file.path == file.path
            && receipt.member.file.bytes == file.bytes
            && receipt.member.file.sha256 == file.sha256,
        "Streamed evidence receipt differs: {}",
        file.path
    );
    validate_chunks(id, &receipt.member)?;
    Ok(Some(receipt.member))
}

pub(super) fn validate_seal(root: &Path, case: &Path, id: Uuid) -> Result<()> {
    crate::verify::verify_with(case, |row| {
        let Some(path) = &row.relative_output_path else {
            return Ok(None);
        };
        let file = Entry {
            path: path.clone(),
            bytes: row.bytes_read,
            sha256: row.sha256.clone().context("Missing observation digest")?,
        };
        Ok(acknowledged(root, id, &file)?.map(|m| (m.file.bytes, m.file.sha256)))
    })?;
    Ok(())
}

pub(crate) struct Disk {
    bucket: Bucket,
    location: Location,
    session: Uuid,
    part_size: usize,
    receipts: PathBuf,
}

impl Disk {
    pub(super) fn open(
        root: &Path,
        session: &Session,
        parent: &Location,
        connection: &ConnectionArgs,
    ) -> Result<Self> {
        let location = session.location(parent)?;
        let part_size = usize::from(session.part_mib) << 20;
        let mut connection = connection.clone();
        connection.s3_region = Some(session.region.clone());
        let bucket = Bucket::connect(location.clone(), &connection, part_size, true)?;
        let receipts = root.join("Streamed");
        fs::create_dir(&receipts)?;
        Ok(Self {
            bucket,
            location,
            session: session.id,
            part_size,
            receipts,
        })
    }

    pub(crate) fn acquire(
        &self,
        mut row: Record,
        source: &Source,
        item: &PlannedFile,
        raw_cache: &mut HashMap<PathBuf, RawVolume>,
    ) -> Record {
        let result = (|| -> Result<()> {
            let mut path = sftp::relative_payload(item)?;
            let mut upload = Stream {
                disk: self,
                buffer: Vec::new(),
                chunks: vec![],
                hash: Sha256::new(),
                bytes: 0,
                write_failed: false,
            };
            let copied = collect::copy_source(
                source,
                item,
                raw_cache,
                cfg!(windows),
                &mut row.method,
                &mut upload,
                |_, _| Ok(()),
            );
            let times = match copied {
                Ok(times) => Some(times),
                Err(e) if upload.write_failed => return Err(e),
                Err(e)
                    if item.before.is_none()
                        && raw::is_missing(&e)
                        && upload.bytes == 0
                        && source
                            .raw_device
                            .as_ref()
                            .is_none_or(|d| raw_cache.contains_key(d))
                        && source.root.is_dir() =>
                {
                    row.status = "NotPresent".into();
                    row.reason = format!("{e:#}");
                    return Ok(());
                }
                Err(e) if upload.bytes > 0 => {
                    // The reader stopped after supplying a prefix. Seal only those bytes
                    // and keep the original output path free for a complete observation.
                    path = format!(
                        "_KumadePartial/{}.partial",
                        paths::encode_component(&item.id)
                    );
                    row.status = "Partial".into();
                    row.reason = format!(
                        "Source read incomplete: {e:#}; {} bytes retained",
                        upload.bytes
                    );
                    None
                }
                Err(e) => {
                    row.status = "Failed".into();
                    row.reason = format!("Source read failed before returning any bytes: {e:#}");
                    return Ok(());
                }
            };
            if !upload.buffer.is_empty() || upload.chunks.is_empty() {
                upload.send()?;
            }
            let file = Entry {
                path,
                bytes: upload.bytes,
                sha256: hex(&upload.hash.finalize()),
            };
            if let Some((before, after)) = times {
                sftp::mark_transferred(&mut row, item, before, after, &file.sha256);
            }
            row.relative_output_path = Some(file.path.clone());
            row.bytes_read = file.bytes;
            row.sha256 = Some(file.sha256.clone());
            row.finished_utc = utc_now();
            let dest = self.receipts.join(receipt_name(&file.path));
            save(
                &dest,
                &AcknowledgedFile {
                    observation: row.clone(),
                    member: Member {
                        file,
                        chunks: upload.chunks,
                    },
                },
            )?;
            Ok(())
        })();
        if let Err(error) = result {
            row.status = "Failed".into();
            row.reason = format!("Disk transfer unconfirmed; reacquire this file: {error:#}");
            row.relative_output_path = None;
            row.sha256 = None;
            row.bytes_read = 0;
        }
        if row.status == "Failed" || row.status == "NotPresent" {
            row.finished_utc = utc_now();
        }
        row
    }
}

struct Stream<'a> {
    disk: &'a Disk,
    buffer: Vec<u8>,
    chunks: Vec<Chunk>,
    hash: Sha256,
    bytes: u64,
    write_failed: bool,
}
impl Stream<'_> {
    fn send(&mut self) -> Result<()> {
        let data = std::mem::take(&mut self.buffer);
        let digest = sha256(&data);
        self.chunks.push(store_chunk(
            &self.disk.bucket,
            &self.disk.location,
            self.disk.session,
            data,
            digest,
        )?);
        Ok(())
    }
}
impl Write for Stream<'_> {
    fn write(&mut self, data: &[u8]) -> io::Result<usize> {
        let n = data.len().min(self.disk.part_size - self.buffer.len());
        self.buffer.extend_from_slice(&data[..n]);
        if self.buffer.len() == self.disk.part_size
            && let Err(e) = self.send()
        {
            self.write_failed = true;
            return Err(io::Error::other(e));
        }
        self.hash.update(&data[..n]);
        self.bytes += n as u64;
        Ok(n)
    }
    fn flush(&mut self) -> io::Result<()> {
        Ok(())
    }
}

#[derive(Serialize)]
#[serde(rename_all = "PascalCase")]
struct PlannedStatus {
    observation_id: String,
    source_id: String,
    source_path: PathBuf,
    stream_name: Option<String>,
    status: String,
}

// The acquisition lock is exclusive here. A new process only publishes receipt-backed
// files, even if the collector stopped between saving a receipt and journaling the row.
pub(super) fn recover(workspace: &Path, case: &Path, id: Uuid) -> Result<()> {
    let plan_path = workspace.join("recovered-disk-plan.json");
    if plan_path.try_exists()? {
        return Ok(());
    }
    let mut pending = BTreeMap::new();
    let mut planned = false;
    for name in ["Plan.json", "InitialPlan.json"] {
        if case.join(name).try_exists()? {
            let input: model::Plan = match json(&paths::safe_join(case, name)?) {
                Ok(plan) => plan,
                Err(error) => {
                    eprintln!("Interrupted plan {name} is unreadable: {error:#}");
                    continue;
                }
            };
            for item in input.files {
                pending.insert(
                    item.id.clone(),
                    PlannedStatus {
                        observation_id: item.id,
                        source_id: item.source_id,
                        source_path: item.source_path,
                        stream_name: item.stream,
                        status: "NotConfirmed".into(),
                    },
                );
            }
            planned = true;
            break;
        }
    }
    let mut files = Vec::new();
    let mut observations = Vec::new();
    for entry in fs::read_dir(paths::safe_join(workspace, "Streamed")?)? {
        let entry = entry?;
        let filename = entry.file_name();
        let Some(digest) = filename
            .to_str()
            .and_then(|s| s.strip_suffix(".json"))
            .filter(|d| digest_valid(d))
        else {
            continue; // A crash may have left an uncommitted temporary receipt.
        };
        let ack: AcknowledgedFile = json(&entry.path())?;
        let file = ack.member.file;
        relative(&file.path)?;
        ensure!(
            digest == sha256(file.path.as_bytes())
                && digest_valid(&file.sha256)
                && ack.observation.relative_output_path.as_deref() == Some(file.path.as_str())
                && ack.observation.bytes_read == file.bytes
                && ack.observation.sha256.as_ref() == Some(&file.sha256)
                && matches!(ack.observation.status.as_str(), "Transferred" | "Partial"),
            "Invalid disk receipt"
        );
        let member = Member {
            file,
            chunks: ack.member.chunks,
        };
        validate_chunks(id, &member)?;
        let row = ack.observation;
        pending.insert(
            row.observation_id.clone(),
            PlannedStatus {
                observation_id: row.observation_id.clone(),
                source_id: row.source_id.clone(),
                source_path: row.source_path.clone().into(),
                stream_name: row.stream_name.clone(),
                status: row.status.clone(),
            },
        );
        observations.push(row);
        files.push(member.file);
    }
    if !planned && files.is_empty() {
        return Ok(());
    }
    let report_name = "DiskRecovery.json";
    let report = case.join(report_name);
    if !report.try_exists()? {
        save(
            &report,
            &serde_json::json!({"AcquisitionComplete":false,"PlanAvailable":planned,"Files":pending.values().collect::<Vec<_>>() }),
        )?;
    }
    let (bytes, sha256) = collect::hash_file(&paths::safe_join(case, report_name)?)?;
    let source = case
        .file_name()
        .and_then(|s| s.to_str())
        .context("Invalid recovery case")?;
    files.push(Entry {
        path: report_name.into(),
        bytes,
        sha256,
    });
    save(
        &plan_path,
        &Plan {
            directory: source.into(),
            partial: true,
            files,
            observations,
        },
    )
}
