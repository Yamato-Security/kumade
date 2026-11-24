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
pub fn prepare(
    parent: &Path,
    computer: &str,
    memory: bool,
    live: Option<&live_info::Options>,
) -> Result<Option<Arc<Capture>>> {
    prepare_configured(parent, computer, memory, live, None)
}

pub struct MemoryConfig<'a> {
    pub live: bool,
    pub args: &'a crate::memory::Args,
    pub reserve_bytes: u64,
    pub quiet: bool,
}
pub fn prepare_configured(
    parent: &Path,
    computer: &str,
    memory: bool,
    live: Option<&live_info::Options>,
    config: Option<MemoryConfig<'_>>,
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
        let defaults = crate::memory::Args::default();
        let record = if memory && config.as_ref().is_none_or(|c| !c.live) {
            Some(crate::memory::unavailable(
                &root,
                computer,
                "RAM acquisition requires a configured provider on live Windows; offline sources never trigger a dump of the analyst computer",
            )?)
        } else if memory {
            Some(crate::memory::acquire(
                &root,
                computer,
                config.as_ref().map_or(&defaults, |c| c.args),
                config.as_ref().map_or(0, |c| c.reserve_bytes),
                config.as_ref().is_none_or(|c| c.quiet),
            )?)
        } else {
            None
        };
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
        if record.is_some() {
            for entry in walkdir::WalkDir::new(root.join("Memory")).follow_links(false) {
                let entry = entry?;
                if entry.file_type().is_file() {
                    hashes.insert(
                        paths::relative_text(entry.path().strip_prefix(&root)?)?,
                        collect::hash_file(entry.path())?.1,
                    );
                }
            }
        }
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
    /// RAM stays in protected staging until the complete collection is sealed/published.
    pub fn metadata_bytes(&self) -> u64 {
        self.bytes
            .saturating_sub(self.memory.as_ref().map_or(0, |m| m.bytes_read))
    }
    pub fn import_memory(
        &self,
        root: &Path,
        remote: Option<&crate::sftp::Target>,
        reserve: u64,
        host: Option<&collect::HostReserve>,
    ) -> Result<Option<Record>> {
        self.import_memory_with_link(root, remote, reserve, host, |source, target| {
            fs::hard_link(source, target)
        })
    }
    fn import_memory_with_link(
        &self,
        root: &Path,
        remote: Option<&crate::sftp::Target>,
        reserve: u64,
        host: Option<&collect::HostReserve>,
        mut link: impl FnMut(&Path, &Path) -> std::io::Result<()>,
    ) -> Result<Option<Record>> {
        let Some(mut row) = self.memory.clone() else {
            return Ok(None);
        };
        fs::create_dir(root.join("Memory"))?;
        for entry in fs::read_dir(self.root.join("Memory"))? {
            let entry = entry?;
            ensure!(
                entry.file_type()?.is_file() && !platform::is_reparse_directory(&entry.path()),
                "Unsafe memory evidence"
            );
            let name = entry.file_name();
            let payload = name == "Memory.dmp";
            if payload && remote.is_some() {
                continue;
            }
            let target = root.join("Memory").join(&name);
            let source = entry.path();
            let expected = collect::hash_file(&source)?;
            // Same-volume RAM import has no second multi-GiB allocation. If a container
            // or filesystem cannot link, bounded copying preserves the original stage.
            if !payload || link(&source, &target).is_err() {
                let required = reserve
                    .checked_add(expected.0)
                    .context("Early import copy size overflow")?;
                ensure!(
                    fs2::available_space(root)? >= required,
                    "Insufficient destination space for early memory import copy; original stage retained"
                );
                if let Some(host) = host {
                    let required = host
                        .bytes
                        .checked_add(expected.0)
                        .context("Early import physical-host size overflow")?;
                    ensure!(
                        fs2::available_space(&host.path)? >= required,
                        "Insufficient physical host space for early memory import copy; original stage retained"
                    );
                }
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
                    ensure!(
                        fs2::available_space(root)? >= reserve.saturating_add(n as u64),
                        "RAM import free-space reserve reached; original stage retained"
                    );
                    if let Some(host) = host {
                        ensure!(
                            fs2::available_space(&host.path)?
                                >= host.bytes.saturating_add(n as u64),
                            "RAM import physical-host reserve reached; original stage retained"
                        );
                    }
                    output.write_all(&buffer[..n])?;
                }
                output.sync_all()?;
            }
            ensure!(
                collect::hash_file(&target)? == expected,
                "Imported RAM evidence differs"
            );
        }
        if let Some(remote) = remote {
            remote.upload_early(self)?;
            row.verified = false; // Only trusted server readback can verify remote payloads.
            if let Some(path) = &row.relative_output_path {
                let logical = format!("Early/{path}");
                remote.require_object(
                    &logical,
                    row.bytes_read,
                    row.sha256.as_deref().context("Missing RAM hash")?,
                )?;
                row.relative_output_path = Some(logical);
                if row.status == "Acquired" {
                    row.status = "Transferred".into();
                }
            }
        }
        Ok(Some(row))
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
    if let Some(row) = &memory {
        ensure!(
            row.artifact_ids == "windows.memory" && row.source_id == "Memory",
            "Invalid early RAM record"
        );
        if let Some(path) = &row.relative_output_path {
            let path = paths::safe_join(root, path)?;
            let (bytes, digest) = collect::hash_file(&path)?;
            ensure!(
                bytes == row.bytes_read && row.sha256.as_deref() == Some(&digest),
                "Early RAM payload differs"
            );
        } else {
            ensure!(
                row.status != "Acquired" && row.bytes_read == 0,
                "Missing early RAM payload"
            );
        }
    }
    Ok((
        count
            + usize::from(
                memory
                    .as_ref()
                    .is_some_and(|r| r.relative_output_path.is_some()),
            ),
        failures == 0 && memory.as_ref().is_none_or(|r| r.status == "Acquired"),
    ))
}

#[cfg(test)]
mod memory_tests {
    use super::*;
    use crate::{
        collect::Options,
        sftp::{RemoteWrite, Store, Target},
    };
    use std::io;
    /// Integration fixture only: structural DMP validation is tested separately.
    fn fixture(parent: &Path) -> Arc<Capture> {
        fixture_size(parent, b"fixture captured RAM".len() as u64)
    }
    fn fixture_size(parent: &Path, size: u64) -> Arc<Capture> {
        let root = parent.join("stage");
        fs::create_dir(&root).unwrap();
        let root = platform::canonicalize(&root).unwrap();
        let mut row = crate::memory::unavailable(&root, "RAMHOST", "fixture").unwrap();
        let path = root.join("Memory/Memory.dmp");
        fs::write(&path, b"fixture captured RAM").unwrap();
        fs::OpenOptions::new()
            .write(true)
            .open(&path)
            .unwrap()
            .set_len(size)
            .unwrap();
        let (bytes, digest) = collect::hash_file(&path).unwrap();
        row.bytes_read = bytes;
        row.logical_size = Some(bytes);
        row.sha256 = Some(digest);
        row.relative_output_path = Some("Memory/Memory.dmp".into());
        row.status = "Acquired".into();
        row.verified = true;
        collect::write_json_new(&root.join("MemoryRequest.json"), &Some(&row)).unwrap();
        let mut hashes = std::collections::BTreeMap::new();
        for name in [
            "MemoryRequest.json",
            "Memory/Memory.dmp",
            "Memory/Acquisition.json",
        ] {
            hashes.insert(name, collect::hash_file(&root.join(name)).unwrap().1);
        }
        collect::write_json_new(&root.join("Seal.json"),&json!({"Kind":"KumadeEarlyVolatile","SchemaVersion":1,"Computer":"RAMHOST","Hashes":hashes})).unwrap();
        let seal_hash = collect::hash_file(&root.join("Seal.json")).unwrap().1;
        let bytes = walkdir::WalkDir::new(&root)
            .into_iter()
            .map(|e| e.unwrap())
            .filter(|e| e.file_type().is_file())
            .map(|e| e.metadata().unwrap().len())
            .sum();
        Arc::new(Capture {
            root,
            memory: Some(row),
            live: None,
            bytes,
            computer: "RAMHOST".into(),
            seal_hash,
            cleaned: AtomicBool::new(false),
        })
    }
    fn plan(parent: &Path) -> Plan {
        let source = parent.join("source");
        fs::create_dir(&source).unwrap();
        let source = crate::discovery::directory_source(&source, "C", "RAMHOST").unwrap();
        crate::wizard::build_plan(
            vec![source],
            &crate::catalog::Rules::load(crate::catalog::DEFAULT_CATALOG).unwrap(),
            &[],
            true,
        )
        .unwrap()
    }
    fn options(early: Arc<Capture>, remote: Option<Arc<Target>>) -> Options {
        Options {
            remote,
            threads: 1,
            reserve_bytes: 0,
            quiet: true,
            verbose: false,
            ntfs_metadata: false,
            host_reserve: None,
            live_info: None,
            process_scan: None,
            early: Some(early),
            entropy: None,
        }
    }
    #[test]
    fn successful_ram_is_first_verified_and_sealed_in_directory_output() {
        let t = tempfile::tempdir().unwrap();
        let capture = fixture(t.path());
        let p = plan(t.path());
        let (root, summary) = collect::collect(
            &p,
            &t.path().join("output"),
            &options(capture.clone(), None),
        )
        .unwrap();
        assert_eq!(summary.collected, 1);
        assert_eq!(summary.failed, 0);
        assert_eq!(crate::verify::verify(&root).unwrap(), (1, true));
        assert_eq!(verify(capture.path()).unwrap(), (1, true));
        let rows = fs::read_to_string(root.join("Manifest.jsonl")).unwrap();
        let row: Record = serde_json::from_str(rows.trim()).unwrap();
        assert_eq!(row.artifact_ids, "windows.memory");
        assert_eq!(row.status, "Acquired");
        let coverage = fs::read_to_string(root.join("Coverage.csv")).unwrap();
        assert!(coverage.contains("Memory,windows.memory,1,1,0,0,0,Acquired"));
        fs::write(root.join("Memory/Acquisition.json"), b"tampered").unwrap();
        assert!(crate::verify::verify(&root).is_err());
    }
    // The artificial reserve is based on current free space. Serialize these large
    // fixtures so their allocations/deletions cannot invalidate each other's budget.
    static CAPACITY_TEST_LOCK: std::sync::Mutex<()> = std::sync::Mutex::new(());
    const LARGE_DUMP: u64 = 256 * 1024 * 1024;
    const AVAILABLE_FOR_IMPORT: u64 = 128 * 1024 * 1024;

    #[test]
    fn same_volume_ram_import_does_not_require_a_second_dump_budget() {
        let _guard = CAPACITY_TEST_LOCK.lock().unwrap();
        let t = tempfile::tempdir().unwrap();
        let capture = fixture_size(t.path(), LARGE_DUMP);
        let initial = plan(t.path());
        let prefetch = initial.sources[0].root.join("Windows/Prefetch");
        fs::create_dir_all(&prefetch).unwrap();
        fs::write(prefetch.join("TEST.pf"), vec![42; 1024 * 1024]).unwrap();
        let p = crate::discovery::build_plan(
            initial.sources,
            &crate::catalog::Rules::load(crate::catalog::DEFAULT_CATALOG).unwrap(),
            &["windows.prefetch".into()],
            true,
        )
        .unwrap();
        assert_eq!(p.known_bytes, 1024 * 1024);
        let output = t.path().join("output");
        fs::create_dir(&output).unwrap();
        let mut config = options(capture.clone(), None);
        config.reserve_bytes = fs2::available_space(&output)
            .unwrap()
            .checked_sub(AVAILABLE_FOR_IMPORT)
            .unwrap();
        let (root, summary) = collect::collect(&p, &output, &config).unwrap();
        assert_eq!(summary.collected, 2);
        assert_eq!(summary.failed, 0);
        assert!(fs2::available_space(&root).unwrap() >= config.reserve_bytes);
        assert_eq!(crate::verify::verify(&root).unwrap(), (2, true));
        let expected = capture.memory.as_ref().unwrap().sha256.clone().unwrap();
        capture.cleanup().unwrap();
        assert_eq!(
            collect::hash_file(&root.join("Memory/Memory.dmp")).unwrap(),
            (LARGE_DUMP, expected)
        );
    }

    fn no_links(_: &Path, _: &Path) -> std::io::Result<()> {
        Err(std::io::Error::new(
            std::io::ErrorKind::Unsupported,
            "fixture filesystem has no hard links",
        ))
    }
    #[test]
    fn ram_copy_fallback_requires_its_full_budget_before_creating_a_dump() {
        let _guard = CAPACITY_TEST_LOCK.lock().unwrap();
        let t = tempfile::tempdir().unwrap();
        let capture = fixture_size(t.path(), LARGE_DUMP);
        let output = t.path().join("output");
        fs::create_dir(&output).unwrap();
        let reserve = fs2::available_space(&output)
            .unwrap()
            .checked_sub(AVAILABLE_FOR_IMPORT)
            .unwrap();
        let error = capture
            .import_memory_with_link(&output, None, reserve, None, no_links)
            .unwrap_err();
        assert!(
            error.to_string().contains("Insufficient destination space"),
            "{error:#}"
        );
        assert!(!output.join("Memory/Memory.dmp").exists());
        assert!(capture.path().join("Memory/Memory.dmp").exists());
        capture.validate("RAMHOST", true).unwrap();
    }
    #[test]
    fn ram_copy_fallback_preserves_the_physical_host_reserve() {
        let _guard = CAPACITY_TEST_LOCK.lock().unwrap();
        let t = tempfile::tempdir().unwrap();
        let capture = fixture_size(t.path(), LARGE_DUMP);
        let output = t.path().join("output");
        fs::create_dir(&output).unwrap();
        let host = collect::HostReserve {
            path: t.path().to_owned(),
            bytes: fs2::available_space(t.path())
                .unwrap()
                .checked_sub(AVAILABLE_FOR_IMPORT)
                .unwrap(),
        };
        let error = capture
            .import_memory_with_link(&output, None, 0, Some(&host), no_links)
            .unwrap_err();
        assert!(
            error
                .to_string()
                .contains("Insufficient physical host space"),
            "{error:#}"
        );
        assert!(!output.join("Memory/Memory.dmp").exists());
        capture.validate("RAMHOST", true).unwrap();
    }
    #[test]
    fn ram_copy_fallback_succeeds_and_retains_hashes_without_links() {
        let t = tempfile::tempdir().unwrap();
        let capture = fixture(t.path());
        let output = t.path().join("output");
        fs::create_dir(&output).unwrap();
        let host = collect::HostReserve {
            path: t.path().to_owned(),
            bytes: 1024,
        };
        let row = capture
            .import_memory_with_link(&output, None, 1024, Some(&host), no_links)
            .unwrap()
            .unwrap();
        assert_eq!(row.status, "Acquired");
        assert!(row.verified);
        assert_eq!(
            collect::hash_file(&output.join("Memory/Memory.dmp")).unwrap(),
            (row.bytes_read, row.sha256.unwrap())
        );
        capture.cleanup().unwrap();
        assert_eq!(
            fs::read(output.join("Memory/Memory.dmp")).unwrap(),
            b"fixture captured RAM"
        );
    }

    struct DiskStore(PathBuf);
    struct DiskFile(fs::File);
    impl Write for DiskFile {
        fn write(&mut self, b: &[u8]) -> io::Result<usize> {
            self.0.write(b)
        }
        fn flush(&mut self) -> io::Result<()> {
            self.0.flush()
        }
    }
    impl RemoteWrite for DiskFile {
        fn finish(self: Box<Self>) -> Result<()> {
            self.0.sync_all()?;
            Ok(())
        }
    }
    impl Store for DiskStore {
        fn create(&self, name: &str, _: u32) -> Result<Box<dyn RemoteWrite>> {
            Ok(Box::new(DiskFile(
                fs::OpenOptions::new()
                    .write(true)
                    .create_new(true)
                    .open(self.0.join(name))?,
            )))
        }
    }
    #[test]
    fn remote_ram_uploaded_once_and_native_readback_succeeds() {
        for gzip in [false, true] {
            let t = tempfile::tempdir().unwrap();
            let capture = fixture(t.path());
            let p = plan(t.path());
            let incoming = t.path().join("incoming");
            fs::create_dir(&incoming).unwrap();
            let target = Target::from_store(Arc::new(DiskStore(incoming.clone())), gzip).unwrap();
            target.upload_early(&capture).unwrap();
            let count = fs::read_dir(&incoming).unwrap().count();
            target.upload_early(&capture).unwrap();
            assert_eq!(fs::read_dir(&incoming).unwrap().count(), count);
            let (root, summary) = collect::collect(
                &p,
                &t.path().join("metadata"),
                &options(capture.clone(), Some(target.clone())),
            )
            .unwrap();
            assert!(!root.join("Memory/Memory.dmp").exists());
            assert!(capture.path().join("Memory/Memory.dmp").exists());
            let row: Record = serde_json::from_str(
                fs::read_to_string(root.join("Manifest.jsonl"))
                    .unwrap()
                    .trim(),
            )
            .unwrap();
            assert_eq!(row.status, "Transferred");
            assert!(!row.verified);
            assert_eq!(
                row.relative_output_path.as_deref(),
                Some("Early/Memory/Memory.dmp")
            );
            let (name, hash) = target.publish(&root, &summary).unwrap();
            let code = crate::sftp_verify::run(&crate::sftp_verify::Options {
                incoming,
                delivery: name,
                sha256: hash,
                receipt: t.path().join("receipt.json"),
                restore: None,
                max_decoded_gib: 1,
                uploader_revoked: true,
            })
            .unwrap();
            assert_eq!(code, 0);
            capture.cleanup().unwrap();
        }
    }
    #[test]
    fn changed_ram_stage_is_rejected_and_not_removed() {
        let t = tempfile::tempdir().unwrap();
        let capture = fixture(t.path());
        fs::write(capture.path().join("Memory/Memory.dmp"), b"changed").unwrap();
        assert!(capture.validate("RAMHOST", true).is_err());
        assert!(capture.cleanup().is_err());
        assert!(capture.path().exists());
        assert!(verify(capture.path()).is_err());
    }
}
