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
    collect::hash_file,
    metadata,
    model::{Plan, Record, SCHEMA_VERSION, Summary},
    paths,
};
use anyhow::{Context, Result, ensure};
use std::{
    collections::HashSet,
    fs::File,
    io::{BufRead, BufReader},
    path::Path,
};

pub fn verify(root: &Path) -> Result<(usize, bool)> {
    let root = crate::platform::canonicalize(root)?;
    // Inventory-only output from `live-info` has no Run.json. A collection that
    // stopped before writing its outer seal must not pass on the inner seal alone.
    if !root.join("Run.json").exists()
        && !root.join("MemoryRequest.json").exists()
        && !root.join("Seal.json").exists()
        && root.join("LiveInfo/Seal.json").is_file()
    {
        let (datasets, failed) = crate::live_info::verify(&root)?;
        return Ok((datasets, failed == 0));
    }
    ensure!(
        root.join("Seal.json").is_file(),
        "Collection has no completed seal"
    );
    let seal: serde_json::Value =
        serde_json::from_reader(File::open(paths::safe_join(&root, "Seal.json")?)?)?;
    if seal["Kind"] == "KumadeEarlyVolatile" {
        return crate::early::verify(&root);
    }
    ensure!(
        seal["SchemaVersion"] == SCHEMA_VERSION,
        "Unsupported seal schema"
    );
    let digests = seal["MetadataSHA256"]
        .as_object()
        .context("Missing sealed metadata inventory")?;
    for file in [
        "Plan.json",
        "Run.json",
        "Manifest.jsonl",
        "Manifest.csv",
        "Coverage.csv",
        "DiscoveryIssues.csv",
        "Errors.csv",
        "Summary.json",
    ] {
        ensure!(
            digests.contains_key(file),
            "Missing required seal digest: {file}"
        );
    }
    for (file, expected) in digests {
        let expected = expected.as_str().context("Invalid sealed digest")?;
        ensure!(
            hash_file(&paths::safe_join(&root, file)?)?.1 == expected,
            "Sealed metadata differs: {file}"
        );
    }
    let run: serde_json::Value = serde_json::from_reader(File::open(root.join("Run.json"))?)?;
    ensure!(
        run["RemoteDelivery"].is_null(),
        "SFTP collections are verified on the trusted server with `kumade verify-delivery` or scripts/sftp_restore.py; uploader acknowledgements are not readback verification"
    );
    if run["EvidenceLayout"] == "DriveRoots" {
        ensure!(
            digests.contains_key("client_info.json"),
            "Missing sealed host boundary"
        );
    }
    if run["LiveInfoEnabled"] == true {
        for name in [
            "LiveInfo/Manifest.json",
            "LiveInfo/Manifest.csv",
            "LiveInfo/Seal.json",
        ] {
            ensure!(
                digests.contains_key(name),
                "Missing sealed live-info inventory"
            );
        }
        let (_, failed) = crate::live_info::verify(&root)?;
        let manifest: serde_json::Value =
            serde_json::from_reader(File::open(root.join("LiveInfo/Manifest.json"))?)?;
        for row in manifest["Entries"]
            .as_array()
            .context("Invalid live-info manifest")?
        {
            let name = row["OutputFile"]
                .as_str()
                .context("Missing live-info output filename")?;
            ensure!(
                digests.contains_key(name),
                "Live-info file omitted from the collection seal"
            );
        }
        let summary: Summary = serde_json::from_reader(File::open(root.join("Summary.json"))?)?;
        ensure!(
            failed == summary.live_info_failed_providers,
            "Live-info failure count differs"
        );
        ensure!(
            failed == 0 || summary.completeness == "Partial",
            "Failed live inventory must be partial"
        );
    }
    let native_streams = run["NativeNTFSStreams"].as_bool().unwrap_or(false);
    if native_streams {
        #[cfg(windows)]
        crate::platform::enable_backup_privilege()?;
        for name in metadata::FILES {
            ensure!(
                digests.contains_key(name),
                "Missing NTFS metadata inventory seal"
            );
        }
    }
    let summary: Summary = serde_json::from_reader(File::open(root.join("Summary.json"))?)?;
    ensure!(
        seal["RunId"].as_str() == Some(summary.run_id.as_str()),
        "Run identity mismatch"
    );
    let plan: Plan = serde_json::from_reader(File::open(root.join("Plan.json"))?)?;
    if run["EntropyDeferred"] == true {
        ensure!(
            digests.contains_key("InitialPlan.json"),
            "Missing initial acquisition plan"
        );
    }
    if plan.entropy_scan.is_some() {
        for name in crate::entropy::FILES {
            ensure!(
                digests.contains_key(*name),
                "Missing sealed entropy report: {name}"
            );
        }
    }
    if run["ProcessScanEnabled"] == true {
        let status = summary
            .process_scan_status
            .as_deref()
            .context("Missing process-scan status")?;
        ensure!(
            matches!(status, "Success" | "Partial" | "Failed"),
            "Invalid process-scan status"
        );
        let required = if status == "Failed" {
            "YaraScan/Failure.json"
        } else {
            "YaraScan/Summary.json"
        };
        ensure!(
            digests.contains_key(required),
            "Missing sealed process-scan completion report"
        );
        if status != "Failed" {
            let scan: serde_json::Value =
                serde_json::from_reader(File::open(paths::safe_join(&root, required)?)?)?;
            let incomplete = scan["Incomplete"]
                .as_u64()
                .context("Invalid process-scan incomplete count")?;
            ensure!(
                (status == "Success") == (incomplete == 0),
                "Process-scan status disagrees with its summary"
            );
        }
        ensure!(
            status == "Success" || summary.completeness == "Partial",
            "Incomplete process scan must make collection partial"
        );
    }
    let expected: HashSet<_> = plan.files.iter().map(|f| f.id.clone()).collect();
    let entropy_hashes: std::collections::HashMap<_, _> = plan
        .files
        .iter()
        .filter_map(|f| f.expected_sha256.as_ref().map(|h| (&f.id, h)))
        .collect();
    let reader = BufReader::new(File::open(root.join("Manifest.jsonl"))?);
    let mut observations = HashSet::new();
    let mut checked = 0;
    let mut acquired = 0;
    let mut failed = 0;
    let mut partial = 0;
    let mut memory = 0;
    let pagefiles = crate::pagefile::load(&root)?;
    ensure!(
        !root.join(crate::pagefile::INVENTORY).exists()
            || digests.contains_key(crate::pagefile::INVENTORY),
        "Unsealed paired-pagefile inventory"
    );
    let mut expected_pagefiles: std::collections::HashMap<_, _> =
        pagefiles.iter().map(|r| (&r.observation_id, r)).collect();
    for (index, line) in reader.lines().enumerate() {
        let record: Record = serde_json::from_str(&line?)
            .with_context(|| format!("Invalid manifest line {}", index + 1))?;
        ensure!(
            record.schema_version == SCHEMA_VERSION,
            "Unsupported manifest schema"
        );
        ensure!(
            observations.insert(record.observation_id.clone()),
            "Duplicate observation identity"
        );
        if record.artifact_ids == "windows.memory" && plan.memory_requested {
            memory += 1;
        } else if let Some(pagefile) = expected_pagefiles.remove(&record.observation_id) {
            ensure!(
                serde_json::to_value(pagefile)? == serde_json::to_value(&record)?,
                "Paired pagefile manifest differs from sealed inventory"
            );
        } else {
            ensure!(
                expected.contains(&record.observation_id),
                "Manifest observation is absent from the plan"
            );
        }
        if record.status == "Acquired"
            && let Some(expected_hash) = entropy_hashes.get(&record.observation_id)
        {
            ensure!(
                record.sha256.as_ref() == Some(*expected_hash),
                "Acquired binary differs from the entropy analysis hash"
            );
        }
        match record.status.as_str() {
            "Acquired" => acquired += 1,
            "Partial" => partial += 1,
            "Failed" => failed += 1,
            "NotPresent" => {}
            _ => anyhow::bail!("Unknown manifest result status"),
        }
        if let Some(path) = &record.relative_output_path {
            let payload = if native_streams {
                metadata::payload_path(&root, path, record.stream_name.as_deref())?
            } else {
                paths::safe_join(&root, path)?
            };
            let (bytes, digest) = hash_file(&payload)?;
            ensure!(
                bytes == record.bytes_read && record.sha256.as_ref() == Some(&digest),
                "Payload failed verification: {path}"
            );
            checked += 1;
        } else {
            ensure!(
                record.status != "Acquired",
                "Acquired record has no payload"
            );
        }
    }
    ensure!(
        memory == usize::from(plan.memory_requested)
            && expected_pagefiles.is_empty()
            && observations.len() == expected.len() + memory + pagefiles.len(),
        "Manifest does not account for all planned tasks"
    );
    ensure!(
        summary.collected == acquired && summary.failed == failed && summary.partial == partial,
        "Summary counters do not match the manifest"
    );
    if native_streams {
        let inventory = BufReader::new(File::open(root.join(metadata::FILES[0]))?);
        let mut errors = 0u64;
        for line in inventory.lines() {
            let row: metadata::Snapshot = serde_json::from_str(&line?)?;
            if matches!(
                row.restore_status.as_str(),
                "Partial" | "CaptureFailed" | "SourceChanged"
            ) {
                errors += 1;
            }
        }
        ensure!(
            errors == summary.metadata_errors,
            "NTFS metadata error count differs from the inventory"
        );
        ensure!(
            errors == 0 || summary.completeness == "Partial",
            "Metadata loss must be reported as partial"
        );
    }
    Ok((
        checked,
        summary.completeness == "CompleteWithinSelectedPrototypeScope",
    ))
}
