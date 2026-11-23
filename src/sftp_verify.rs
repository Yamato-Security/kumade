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

//! Trusted local readback of an SFTP delivery. Network credentials never gain read access.
use crate::{
    collect,
    model::{Plan, Record, Summary, hex, utc_now},
    platform,
    sftp::Object,
};
use anyhow::{Context, Result, bail, ensure};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use std::{
    collections::{BTreeMap, HashMap, HashSet},
    fs::{self, File, OpenOptions},
    io::{BufRead, BufReader, Read, Seek, Write},
    path::{Path, PathBuf},
    time::{Duration, Instant},
};
pub const MAX_METADATA: u64 = 128 * 1024 * 1024;
#[derive(clap::Args)]
pub struct Options {
    /// Flat incoming object directory from an SFTP delivery
    #[arg(long)]
    pub incoming: PathBuf,
    /// Final UUID-delivery.json object name
    #[arg(long)]
    pub delivery: String,
    /// Delivery SHA256 printed by the collector (compare independently)
    #[arg(long)]
    pub sha256: String,
    /// New readback receipt path (will not overwrite an existing file)
    #[arg(long)]
    pub receipt: PathBuf,
    /// Optional new directory in which to reconstruct files (extra server disk space)
    #[arg(long)]
    pub restore: Option<PathBuf>,
    /// Maximum total decoded GiB, including sparse logical zero ranges
    #[arg(long,default_value_t=1024,value_parser=clap::value_parser!(u64).range(1..=1048576))]
    pub max_decoded_gib: u64,
    /// Confirm upload credentials have been revoked and existing sessions ended
    #[arg(long, required = true)]
    pub uploader_revoked: bool,
}
pub struct Inputs {
    pub incoming: PathBuf,
    pub delivery: String,
    pub sha256: String,
    pub max_decoded_bytes: u64,
    pub restore: Option<PathBuf>,
}
#[derive(Serialize, Deserialize)]
#[serde(rename_all = "PascalCase")]
pub struct Receipt {
    pub schema_version: u32,
    pub kind: String,
    pub version: String,
    pub verified_utc: String,
    pub delivery_id: String,
    #[serde(rename = "DeliverySHA256")]
    pub delivery_sha256: String,
    pub collection_name: String,
    pub objects_verified: usize,
    pub payload_records_verified: usize,
    pub stored_bytes: u64,
    pub logical_bytes: u64,
    pub payload_hashes_verified: bool,
    pub acquisition_state: String,
    pub collector_acquisition_state: String,
    pub limitations: Vec<String>,
}
#[derive(Deserialize)]
#[serde(rename_all = "PascalCase")]
struct Delivery {
    schema_version: u32,
    kind: String,
    delivery_id: String,
    collection_name: String,
    objects: Vec<Object>,
    summary: Summary,
}
fn digest_valid(value: &str) -> bool {
    value.len() == 64
        && value
            .bytes()
            .all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(&b))
}
fn open(root: &Path, name: &str) -> Result<File> {
    crate::sftp::validate_object_name(name)?;
    let path = root.join(name);
    ensure!(
        path.symlink_metadata()?.is_file() && !platform::is_reparse_directory(&path),
        "Object is not a regular file: {name}"
    );
    let file = platform::open_source(&path)?;
    platform::validate_open_file(&file, root)?;
    #[cfg(unix)]
    {
        use std::os::unix::fs::MetadataExt;
        ensure!(file.metadata()?.nlink() == 1, "Hard-linked upload object");
    }
    Ok(file)
}
fn read_metadata(root: &Path, object: &Object) -> Result<Vec<u8>> {
    ensure!(
        object.logical_bytes <= MAX_METADATA,
        "Metadata exceeds 128 MiB: {}",
        object.relative_path
    );
    let mut reader = decoded(open(root, &object.name)?, &object.encoding)?;
    let mut bytes = Vec::new();
    reader
        .by_ref()
        .take(MAX_METADATA + 1)
        .read_to_end(&mut bytes)?;
    ensure!(
        bytes.len() as u64 == object.logical_bytes
            && crate::model::sha256(&bytes) == object.logical_sha256,
        "Metadata changed during verification"
    );
    Ok(bytes)
}
fn decoded(file: File, encoding: &str) -> Result<Box<dyn Read>> {
    match encoding {
        "none" => Ok(Box::new(file)),
        "gzip" => Ok(Box::new(flate2::read::MultiGzDecoder::new(file))),
        _ => bail!("Unsupported encoding"),
    }
}
pub(crate) fn relative(value: &str) -> Result<Vec<&str>> {
    ensure!(
        !value.is_empty() && !value.contains('\\'),
        "Invalid relative output path"
    );
    let mut parts = Vec::new();
    for part in value.split('/') {
        let stem = part
            .split('.')
            .next()
            .unwrap_or_default()
            .to_ascii_uppercase();
        let numbered = stem.len() == 4
            && (stem.starts_with("COM") || stem.starts_with("LPT"))
            && matches!(stem.as_bytes()[3], b'1'..=b'9');
        ensure!(
            !part.is_empty()
                && !matches!(part, "." | "..")
                && !part.ends_with([' ', '.'])
                && !part
                    .chars()
                    .any(|c| c.is_control() || "<>:\"|?*".contains(c))
                && !matches!(
                    stem.as_str(),
                    "CON" | "PRN" | "AUX" | "NUL" | "CONIN$" | "CONOUT$" | "CLOCK$"
                )
                && !numbered,
            "Unsafe output path"
        );
        parts.push(part);
    }
    Ok(parts)
}
pub fn run(options: &Options) -> Result<u8> {
    ensure!(
        options.uploader_revoked,
        "Revoke the uploader before readback verification"
    );
    let receipt_path = crate::paths::resolve_future(&options.receipt)?;
    let incoming = platform::canonicalize(&options.incoming)?;
    ensure!(
        !receipt_path.starts_with(&incoming) && !receipt_path.exists(),
        "Receipt must be new and outside incoming"
    );
    if let Some(restore) = &options.restore {
        let path = crate::paths::resolve_future(restore)?;
        ensure!(
            !receipt_path.starts_with(&path) && !path.starts_with(&receipt_path),
            "Receipt and restore output must be separate"
        );
    }
    let receipt = verify(
        &Inputs {
            incoming,
            delivery: options.delivery.clone(),
            sha256: options.sha256.clone(),
            max_decoded_bytes: options
                .max_decoded_gib
                .checked_mul(1 << 30)
                .context("Decoded quota overflow")?,
            restore: options.restore.clone(),
        },
        None,
    )?;
    collect::write_json_new(&receipt_path, &receipt)?;
    crate::ui::field("Readback integrity", "Verified");
    crate::ui::field("Acquisition state", &receipt.acquisition_state);
    crate::ui::field("Receipt", receipt_path.display());
    Ok(if receipt.acquisition_state == "Partial" {
        3
    } else {
        0
    })
}
pub(crate) fn verify(
    inputs: &Inputs,
    closed: Option<&BTreeMap<String, crate::sftp_receive::Closed>>,
) -> Result<Receipt> {
    let root = platform::canonicalize(&inputs.incoming)?;
    let deadline = Instant::now() + Duration::from_secs(3600);
    ensure!(
        digest_valid(&inputs.sha256),
        "Expected a 64-character lowercase Delivery SHA256"
    );
    let mut data = Vec::new();
    open(&root, &inputs.delivery)?
        .take(MAX_METADATA + 1)
        .read_to_end(&mut data)?;
    ensure!(
        data.len() as u64 <= MAX_METADATA && crate::model::sha256(&data) == inputs.sha256,
        "Delivery SHA256 mismatch"
    );
    let delivery: Delivery = serde_json::from_slice(&data)?;
    ensure!(
        delivery.schema_version == 1 && delivery.kind == "KumadeSftpDelivery",
        "Unsupported delivery schema"
    );
    let id = uuid::Uuid::parse_str(&delivery.delivery_id)?;
    ensure!(
        id.to_string() == delivery.delivery_id && inputs.delivery == format!("{id}-delivery.json"),
        "Delivery ID/name mismatch"
    );
    ensure!(
        relative(&delivery.collection_name)?.len() == 1,
        "Invalid collection name"
    );
    let mut names = HashSet::new();
    let mut paths = HashSet::new();
    let mut parents = HashSet::new();
    let mut objects = HashMap::new();
    let (mut stored_bytes, mut logical_bytes) = (0u64, 0u64);
    for object in &delivery.objects {
        crate::sftp::validate_object_name(&object.name)?;
        ensure!(
            object.name.starts_with(&format!("{id}-"))
                && object.name != inputs.delivery
                && names.insert(object.name.clone()),
            "Foreign/duplicate object name"
        );
        ensure!(
            digest_valid(&object.logical_sha256) && digest_valid(&object.stored_sha256),
            "Invalid object hash"
        );
        let parts = relative(&object.relative_path)?;
        let path = object.relative_path.to_lowercase();
        ensure!(
            !parents.contains(&path) && paths.insert(path),
            "Duplicate or conflicting output path"
        );
        for end in 1..parts.len() {
            let parent = parts[..end].join("/").to_lowercase();
            ensure!(!paths.contains(&parent), "File/directory collision");
            parents.insert(parent);
        }
        stored_bytes = stored_bytes
            .checked_add(object.stored_bytes)
            .context("Stored size overflow")?;
        logical_bytes = logical_bytes
            .checked_add(object.logical_bytes)
            .context("Decoded size overflow")?;
        ensure!(
            logical_bytes <= inputs.max_decoded_bytes,
            "Decoded quota exceeded"
        );
        if let Some(closed) = closed {
            let info = closed
                .get(&object.name)
                .context("Object was not sealed by this receiver")?;
            let (bytes, hash) = crate::sftp_receive::closed_info(info);
            ensure!(
                bytes == object.stored_bytes && hash == object.stored_sha256,
                "Receiver/object inventory mismatch"
            );
        }
        objects.insert(object.relative_path.as_str(), object);
    }
    if let Some(closed) = closed {
        ensure!(
            closed
                .keys()
                .filter(|name| !name.starts_with("probe-") && *name != &inputs.delivery)
                .count()
                == names.len(),
            "Unlisted completed upload objects"
        );
    }
    let restore = if let Some(path) = &inputs.restore {
        let path = crate::paths::resolve_future(path)?;
        ensure!(
            !path.exists() && !path.starts_with(&root) && !root.starts_with(&path),
            "Restore directory must be new and outside incoming"
        );
        fs::create_dir(&path)?;
        ensure!(
            platform::protect_output_root(&path)? != "FilesystemHasNoPersistentACLs",
            "Restore requires access controls"
        );
        Some(platform::canonicalize(&path)?)
    } else {
        None
    };
    for object in &delivery.objects {
        ensure!(
            Instant::now() < deadline,
            "Readback verification exceeded one hour"
        );
        let mut file = open(&root, &object.name)?;
        let mut hash = Sha256::new();
        let mut buffer = vec![0u8; 1024 * 1024];
        let mut total = 0u64;
        loop {
            let n = file.read(&mut buffer)?;
            if n == 0 {
                break;
            }
            ensure!(Instant::now() < deadline, "Verification timeout");
            total = total.checked_add(n as u64).context("Size overflow")?;
            ensure!(total <= object.stored_bytes, "Stored object too large");
            hash.update(&buffer[..n]);
        }
        ensure!(
            total == object.stored_bytes && hex(&hash.finalize()) == object.stored_sha256,
            "Stored hash mismatch: {}",
            object.name
        );
        file.rewind()?;
        let mut reader = decoded(file, &object.encoding)?;
        let mut hash = Sha256::new();
        let mut total = 0u64;
        let mut output = if let Some(root) = &restore {
            let path =
                root.join(relative(&object.relative_path)?.join(std::path::MAIN_SEPARATOR_STR));
            let parent = path.parent().context("Missing output parent")?;
            fs::create_dir_all(parent)?;
            ensure!(
                platform::canonicalize(parent)?.starts_with(root),
                "Restore path escaped output root"
            );
            let file = OpenOptions::new().write(true).create_new(true).open(path)?;
            platform::validate_open_file(&file, root)?;
            let sparse = platform::enable_sparse_output(&file);
            Some((file, sparse))
        } else {
            None
        };
        loop {
            let limit = buffer.len().min(
                object
                    .logical_bytes
                    .saturating_sub(total)
                    .saturating_add(1)
                    .min(usize::MAX as u64) as usize,
            );
            let n = reader.read(&mut buffer[..limit])?;
            if n == 0 {
                break;
            }
            ensure!(Instant::now() < deadline, "Verification timeout");
            total = total
                .checked_add(n as u64)
                .context("Decoded size overflow")?;
            ensure!(
                total <= object.logical_bytes,
                "Decoded object exceeds declared length"
            );
            hash.update(&buffer[..n]);
            if let Some((file, sparse)) = &mut output {
                if *sparse && buffer[..n].iter().all(|b| *b == 0) {
                    file.seek_relative(n as i64)?;
                } else {
                    file.write_all(&buffer[..n])?;
                }
            }
        }
        ensure!(
            total == object.logical_bytes && hex(&hash.finalize()) == object.logical_sha256,
            "Logical hash mismatch: {}",
            object.relative_path
        );
        if let Some((file, _)) = output {
            file.set_len(total)?;
            file.sync_all()?;
        }
    }
    for name in [
        "Plan.json",
        "Run.json",
        "Manifest.jsonl",
        "Manifest.csv",
        "Coverage.csv",
        "Errors.csv",
        "Summary.json",
        "Seal.json",
        "DiscoveryIssues.csv",
        "client_info.json",
    ] {
        ensure!(
            objects.contains_key(name),
            "Missing required collection metadata: {name}"
        );
    }
    let metadata = |name: &str| -> Result<Vec<u8>> {
        read_metadata(&root, objects.get(name).context("Missing metadata")?)
    };
    let summary: Summary = serde_json::from_slice(&metadata("Summary.json")?)?;
    ensure!(
        serde_json::to_value(&summary)? == serde_json::to_value(&delivery.summary)?,
        "Summary differs from delivery"
    );
    ensure!(
        matches!(
            summary.completeness.as_str(),
            "PendingServerReadbackVerification" | "Partial"
        ),
        "Invalid collector acquisition state"
    );
    let seal: serde_json::Value = serde_json::from_slice(&metadata("Seal.json")?)?;
    for (name, expected) in seal["MetadataSHA256"]
        .as_object()
        .context("Missing seal inventory")?
    {
        ensure!(
            objects
                .get(name.as_str())
                .is_some_and(|o| Some(o.logical_sha256.as_str()) == expected.as_str()),
            "Sealed metadata hash mismatch: {name}"
        );
    }
    for name in [
        "Plan.json",
        "Run.json",
        "Manifest.jsonl",
        "Manifest.csv",
        "Coverage.csv",
        "Errors.csv",
        "Summary.json",
        "DiscoveryIssues.csv",
    ] {
        ensure!(
            seal["MetadataSHA256"].get(name).is_some(),
            "Required metadata not sealed: {name}"
        );
    }
    let plan: Plan = serde_json::from_slice(&metadata("Plan.json")?)?;
    let mut expected: HashSet<_> = plan.files.iter().map(|f| f.id.as_str()).collect();
    ensure!(
        expected.len() == plan.files.len(),
        "Duplicate planned observation IDs"
    );
    let mut memory = false;
    let mut seen = HashSet::new();
    let (mut count, mut acquired, mut partial, mut failed, mut bytes) =
        (0usize, 0u64, 0u64, 0u64, 0u64);
    let manifest = objects["Manifest.jsonl"];
    let mut reader = BufReader::new(decoded(open(&root, &manifest.name)?, &manifest.encoding)?);
    loop {
        let mut line = Vec::new();
        let n = (&mut reader)
            .take(1024 * 1024 + 1)
            .read_until(b'\n', &mut line)?;
        if n == 0 {
            break;
        }
        ensure!(n <= 1024 * 1024, "Manifest record exceeds 1 MiB");
        let record: Record = serde_json::from_slice(&line)?;
        ensure!(
            seen.insert(record.observation_id.clone()) && !record.verified,
            "Duplicate or prematurely verified record"
        );
        if !expected.remove(record.observation_id.as_str()) {
            ensure!(
                plan.memory_requested
                    && !memory
                    && record.source_id == "Memory"
                    && record.artifact_ids == "windows.memory"
                    && matches!(record.status.as_str(), "Transferred" | "Partial" | "Failed"),
                "Unexpected acquisition record"
            );
            memory = true;
        }
        if let Some(path) = record.relative_output_path.as_deref() {
            let object = objects.get(path).context("Missing record payload")?;
            ensure!(
                record.sha256.as_ref() == Some(&object.logical_sha256)
                    && record.bytes_read == object.logical_bytes,
                "Payload/record mismatch"
            );
            count += 1;
        } else {
            ensure!(
                record.status != "Transferred" && record.bytes_read == 0,
                "Missing transferred payload"
            );
        }
        match record.status.as_str() {
            "Transferred" => acquired += 1,
            "Partial" => partial += 1,
            "Failed" => failed += 1,
            "NotPresent" => ensure!(record.bytes_read == 0, "Absent record contains data"),
            _ => bail!("Unknown remote acquisition status"),
        }
        bytes = bytes
            .checked_add(record.bytes_read)
            .context("Record byte overflow")?;
    }
    ensure!(
        expected.is_empty() && memory == plan.memory_requested,
        "Incomplete acquisition manifest"
    );
    ensure!(
        summary.collected == acquired
            && summary.partial == partial
            && summary.failed == failed
            && summary.bytes_acquired == bytes,
        "Summary counters differ from records"
    );
    Ok(Receipt{schema_version:1,kind:"KumadeTrustedSftpReadback".into(),version:env!("CARGO_PKG_VERSION").into(),verified_utc:utc_now(),delivery_id:delivery.delivery_id,delivery_sha256:inputs.sha256.clone(),collection_name:delivery.collection_name,objects_verified:delivery.objects.len(),payload_records_verified:count,stored_bytes,logical_bytes,payload_hashes_verified:true,acquisition_state:if summary.completeness=="PendingServerReadbackVerification"{"CompleteWithinSelectedPrototypeScope".into()}else{"Partial".into()},collector_acquisition_state:summary.completeness,limitations:vec!["Readback integrity does not establish source authenticity or acquisition completeness. Compare DeliverySHA256 with the collector over a trusted channel.".into(),"Source timestamps/ACLs and named streams remain inventories/exports, not native metadata restoration.".into()]})
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn paths_and_device_names_cannot_escape_or_open_special_windows_files() {
        for path in [
            "../escape",
            "/absolute",
            "C:/absolute",
            "a\\b",
            "a//b",
            "a/./b",
            "a/CON.txt",
            "a/COM1",
            "a/CONIN$",
            "a/NUL",
            "a/trailing.",
            "a/trailing ",
        ] {
            assert!(relative(path).is_err(), "{path}");
        }
        assert_eq!(relative("C/Windows/Prefetch/APP.pf").unwrap().len(), 4);
    }
    #[test]
    fn correct_stored_hash_does_not_allow_a_gzip_length_bomb() {
        let root = tempfile::tempdir().unwrap();
        let id = uuid::Uuid::new_v4().to_string();
        let mut encoder = flate2::write::GzEncoder::new(Vec::new(), flate2::Compression::fast());
        encoder.write_all(&vec![0u8; 1024 * 1024]).unwrap();
        let stored = encoder.finish().unwrap();
        let name = format!("{id}-payload-test");
        fs::write(root.path().join(&name), &stored).unwrap();
        let object = Object {
            name,
            relative_path: "C/file".into(),
            encoding: "gzip".into(),
            logical_bytes: 1,
            logical_sha256: crate::model::sha256(&[0]),
            stored_bytes: stored.len() as u64,
            stored_sha256: crate::model::sha256(&stored),
        };
        let summary = serde_json::json!({"SchemaVersion":1,"RunId":"run","Version":"test","StartedUtc":"","FinishedUtc":"","Completeness":"PendingServerReadbackVerification","Collected":1,"Partial":0,"Failed":0,"DiscoveryErrors":0,"BytesAcquired":1,"CatalogSha256":""});
        let delivery=serde_json::to_vec(&serde_json::json!({"SchemaVersion":1,"Kind":"KumadeSftpDelivery","DeliveryId":id,"CollectionName":"HOST","Objects":[object],"Summary":summary})).unwrap();
        let name = format!("{id}-delivery.json");
        fs::write(root.path().join(&name), &delivery).unwrap();
        let error = verify(
            &Inputs {
                incoming: root.path().to_owned(),
                delivery: name,
                sha256: crate::model::sha256(&delivery),
                max_decoded_bytes: 1024,
                restore: None,
            },
            None,
        )
        .err()
        .unwrap();
        assert!(
            error
                .to_string()
                .contains("Decoded object exceeds declared length"),
            "{error:#}"
        );
    }
}
