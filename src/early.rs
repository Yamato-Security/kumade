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

//! Protected early volatile capture. Retained on failure, imported with hash checks.
use crate::{collect, live_info, model::*, paths, platform};
use anyhow::{Context, Result, ensure};
use serde_json::json;
use std::{
    fs,
    io::{Read, Write},
    path::{Path, PathBuf},
    sync::{
        Arc,
        atomic::{AtomicBool, Ordering},
    },
};
#[derive(Debug)]
pub struct Capture {
    pub(crate) root: PathBuf,
    pub(crate) memory: Option<Record>,
    pub(crate) live: Option<live_info::Outcome>,
    pub(crate) bytes: u64,
    computer: String,
    seal_hash: String,
    cleaned: AtomicBool,
}
impl Drop for Capture {
    fn drop(&mut self) {
        if !self.cleaned.load(Ordering::Relaxed) && self.root.exists() {
            eprintln!("Early volatile evidence retained: {}", self.root.display());
        }
    }
}
/// This is the first acquisition hook. It must remain before all live providers.
/// No RAM provider exists yet: preserve an honest failed request, never a fake dump.
fn memory_request(computer: &str) -> Record {
    eprintln!(
        "RAM acquisition unavailable: no memory dump was created; the failed request is recorded first."
    );
    Record {
        schema_version: 1,
        observation_id: uuid::Uuid::new_v4().to_string(),
        computer: computer.into(),
        source_id: "Memory".into(),
        source_path: "Physical RAM".into(),
        stream_name: None,
        artifact_ids: "windows.memory".into(),
        relative_output_path: None,
        method: "MemoryProvider".into(),
        status: "Failed".into(),
        reason: "RAM acquisition is not implemented; no memory image was acquired".into(),
        started_utc: utc_now(),
        finished_utc: utc_now(),
        logical_size: None,
        bytes_read: 0,
        sha256: None,
        verified: false,
        changed_during_read: false,
        created_utc: None,
        modified_utc: None,
        accessed_utc: None,
        source_file_id: None,
    }
}
pub fn prepare(
    parent: &Path,
    computer: &str,
    memory: bool,
    live: Option<&live_info::Options>,
) -> Result<Option<Arc<Capture>>> {
    let fast = live
        .map(|o| live_info::select(&o.selected))
        .transpose()?
        .is_some_and(|v| {
            v.iter()
                .any(|s| crate::ordering::live_priority(&s.name) <= 2)
        });
    if !memory && !fast {
        return Ok(None);
    }
    let parent = paths::resolve_future(parent)?;
    fs::create_dir_all(&parent)?;
    let root = parent.join(format!(".kumade-volatile-{}", uuid::Uuid::new_v4()));
    fs::create_dir(&root)?;
    platform::protect_output_root(&root)?;
    let result = (|| -> Result<_> {
        let record = memory.then(|| memory_request(computer));
        collect::write_json_new(&root.join("MemoryRequest.json"), &record)?;
        // No disk scan, VSS creation, container setup or provider query precedes RAM handling.
        let outcome = live
            .map(|o| live_info::collect_fast_into(&root, o))
            .transpose()?
            .flatten();
        let mut hashes = std::collections::BTreeMap::new();
        hashes.insert(
            "MemoryRequest.json".to_string(),
            collect::hash_file(&root.join("MemoryRequest.json"))?.1,
        );
        if outcome.is_some() {
            hashes.insert(
                "LiveInfo/Seal.json".into(),
                collect::hash_file(&root.join("LiveInfo/Seal.json"))?.1,
            );
        }
        collect::write_json_new(
            &root.join("Seal.json"),
            &json!({"Computer":computer,"Hashes":hashes,"Kind":"KumadeEarlyVolatile","SchemaVersion":1}),
        )?;
        let seal_hash = collect::hash_file(&root.join("Seal.json"))?.1;
        let mut bytes = 0u64;
        for entry in walkdir::WalkDir::new(&root) {
            let e = entry?;
            if e.file_type().is_file() {
                bytes = bytes
                    .checked_add(e.metadata()?.len())
                    .context("Early capture size overflow")?;
            }
        }
        Ok(Arc::new(Capture {
            root: root.clone(),
            memory: record,
            live: outcome,
            bytes,
            computer: computer.into(),
            seal_hash,
            cleaned: AtomicBool::new(false),
        }))
    })();
    if result.is_err() {
        eprintln!(
            "Incomplete early volatile evidence retained: {}",
            root.display()
        );
    }
    result.map(Some)
}
impl Capture {
    pub fn path(&self) -> &Path {
        &self.root
    }

    pub fn validate(&self, computer: &str, memory: bool) -> Result<()> {
        ensure!(
            self.computer == computer && self.memory.is_some() == memory,
            "Early capture does not match the collection request"
        );
        ensure!(
            !self.root.symlink_metadata()?.file_type().is_symlink()
                && !platform::is_reparse_directory(&self.root),
            "Unsafe early evidence root"
        );
        ensure!(
            collect::hash_file(&self.root.join("Seal.json"))?.1 == self.seal_hash,
            "Early capture seal changed"
        );
        let seal: serde_json::Value =
            serde_json::from_reader(fs::File::open(self.root.join("Seal.json"))?)?;
        for (name, digest) in seal["Hashes"].as_object().context("Missing early hashes")? {
            ensure!(
                collect::hash_file(&paths::safe_join(&self.root, name)?)?.1
                    == digest.as_str().context("Invalid early digest")?,
                "Early volatile metadata changed"
            );
        }
        let memory: Option<Record> =
            serde_json::from_reader(fs::File::open(self.root.join("MemoryRequest.json"))?)?;
        ensure!(
            serde_json::to_value(memory)? == serde_json::to_value(&self.memory)?,
            "Early RAM request metadata differs"
        );
        if self.live.is_some() {
            live_info::verify(&self.root)?;
        }
        Ok(())
    }
    pub fn import(&self, root: &Path) -> Result<Option<live_info::Outcome>> {
        let Some(info) = &self.live else {
            return Ok(None);
        };
        fs::create_dir(root.join("LiveInfo"))?;
        for row in &info.entries {
            let source = paths::safe_join(&self.root, &row.output_file)?;
            let target = root.join(&row.output_file);
            let mut input = platform::open_source(&source)?;
            platform::validate_open_file(&input, &self.root)?;
            let mut output = fs::OpenOptions::new()
                .create_new(true)
                .write(true)
                .open(&target)?;
            let mut buffer = vec![0u8; 1024 * 1024];
            loop {
                let n = input.read(&mut buffer)?;
                if n == 0 {
                    break;
                }
                output.write_all(&buffer[..n])?;
            }
            output.sync_all()?;
            let (bytes, hash) = collect::hash_file(&target)?;
            ensure!(
                bytes == row.bytes && hash == row.sha256,
                "Imported volatile evidence hash mismatch"
            );
        }
        Ok(Some(info.clone()))
    }
    /// Only this run's owned staging tree is removed, after the final output has sealed.
    pub fn cleanup(&self) -> Result<()> {
        self.validate(&self.computer, self.memory.is_some())?;
        fs::remove_dir_all(&self.root)
            .context("Final evidence saved, but early staging cleanup failed")?;
        self.cleaned.store(true, Ordering::Relaxed);
        Ok(())
    }
}

/// Verify a retained volatile staging directory independently of a completed case.
pub fn verify(root: &Path) -> Result<(usize, bool)> {
    let seal: serde_json::Value =
        serde_json::from_reader(fs::File::open(paths::safe_join(root, "Seal.json")?)?)?;
    ensure!(
        seal["Kind"] == "KumadeEarlyVolatile" && seal["SchemaVersion"] == 1,
        "Unsupported early capture seal"
    );
    let hashes = seal["Hashes"]
        .as_object()
        .context("Missing early capture inventory")?;
    ensure!(
        hashes.contains_key("MemoryRequest.json"),
        "Missing RAM request state"
    );
    for (name, hash) in hashes {
        ensure!(
            collect::hash_file(&paths::safe_join(root, name)?)?.1
                == hash.as_str().context("Invalid early digest")?,
            "Early capture file differs: {name}"
        );
    }
    let memory: Option<Record> =
        serde_json::from_reader(fs::File::open(root.join("MemoryRequest.json"))?)?;
    let (count, failures) = if hashes.contains_key("LiveInfo/Seal.json") {
        live_info::verify(root)?
    } else {
        (0, 0)
    };
    Ok((count, failures == 0 && memory.is_none()))
}
