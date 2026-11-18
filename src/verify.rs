// Copyright (c) 2026 Shirofune Security Co., Ltd.
// SPDX-License-Identifier: RPL-1.5

use crate::{
    collect::hash_file,
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
    let root = root.canonicalize()?;
    let seal: serde_json::Value = serde_json::from_reader(
        File::open(paths::safe_join(&root, "Seal.json")?)
            .context("Collection has no completed seal")?,
    )?;
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
        let expected = digests
            .get(file)
            .and_then(|s| s.as_str())
            .context("Missing seal digest")?;
        ensure!(
            hash_file(&paths::safe_join(&root, file)?)?.1 == expected,
            "Sealed metadata differs: {file}"
        );
    }
    let summary: Summary = serde_json::from_reader(File::open(root.join("Summary.json"))?)?;
    ensure!(
        seal["RunId"].as_str() == Some(summary.run_id.as_str()),
        "Run identity mismatch"
    );
    let plan: Plan = serde_json::from_reader(File::open(root.join("Plan.json"))?)?;
    let expected: HashSet<_> = plan.files.iter().map(|f| f.id.clone()).collect();
    let reader = BufReader::new(File::open(root.join("Manifest.jsonl"))?);
    let mut observations = HashSet::new();
    let mut checked = 0;
    let mut acquired = 0;
    let mut failed = 0;
    let mut partial = 0;
    let mut memory = 0;
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
        } else {
            ensure!(
                expected.contains(&record.observation_id),
                "Manifest observation is absent from the plan"
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
            let payload = paths::safe_join(&root, path)?;
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
            && observations.len() == expected.len() + memory,
        "Manifest does not account for all planned tasks"
    );
    ensure!(
        summary.collected == acquired && summary.failed == failed && summary.partial == partial,
        "Summary counters do not match the manifest"
    );
    Ok((
        checked,
        summary.completeness == "CompleteWithinSelectedPrototypeScope",
    ))
}
