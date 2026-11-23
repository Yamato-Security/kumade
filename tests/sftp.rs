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

use kumade::{
    catalog::{DEFAULT_CATALOG, Rules},
    collect::{self, Options},
    discovery,
    model::*,
    sftp::{self, RemoteWrite, Store, Target},
};
use std::{
    collections::BTreeMap,
    fs,
    io::{self, Read, Write},
    sync::{Arc, Mutex},
};
#[derive(Default)]
struct MemoryStore {
    objects: Arc<Mutex<BTreeMap<String, Vec<u8>>>>,
    fail_after: Option<usize>,
}
struct MemoryFile {
    name: String,
    objects: Arc<Mutex<BTreeMap<String, Vec<u8>>>>,
    fail_after: Option<usize>,
}
impl Write for MemoryFile {
    fn write(&mut self, b: &[u8]) -> io::Result<usize> {
        let mut m = self.objects.lock().unwrap();
        let v = m.get_mut(&self.name).unwrap();
        if self.fail_after.is_some_and(|n| v.len() + b.len() > n) {
            return Err(io::Error::other("injected disconnect"));
        }
        v.extend_from_slice(b);
        Ok(b.len())
    }
    fn flush(&mut self) -> io::Result<()> {
        Ok(())
    }
}
impl RemoteWrite for MemoryFile {
    fn finish(self: Box<Self>) -> anyhow::Result<()> {
        Ok(())
    }
}
impl Store for MemoryStore {
    fn create(&self, name: &str, _: u32) -> anyhow::Result<Box<dyn RemoteWrite>> {
        let mut m = self.objects.lock().unwrap();
        anyhow::ensure!(!m.contains_key(name), "exclusive create collision");
        m.insert(name.into(), vec![]);
        Ok(Box::new(MemoryFile {
            name: name.into(),
            objects: self.objects.clone(),
            fail_after: self.fail_after,
        }))
    }
}
fn options(remote: Arc<Target>) -> Options {
    // Match the CLI's elevated Windows metadata-capture precondition. Without
    // SeSecurityPrivilege, ACCESS_SYSTEM_SECURITY is correctly a partial result.
    #[cfg(windows)]
    kumade::metadata::enable_privileges().unwrap();
    Options {
        remote: Some(remote),
        threads: 4,
        reserve_bytes: 0,
        quiet: true,
        verbose: false,
        ntfs_metadata: false,
        host_reserve: None,
        live_info: None,
        process_scan: None,
        early: None,
        entropy: None,
    }
}
#[test]
fn direct_streaming_roundtrip_seals_and_server_restorer() {
    let temp = tempfile::tempdir().unwrap();
    let source = temp.path().join("source");
    fs::create_dir_all(source.join("Windows/Prefetch")).unwrap();
    let bytes = vec![0u8; 2 * 1024 * 1024];
    fs::write(source.join("Windows/Prefetch/APP.EXE.pf"), &bytes).unwrap();
    let rules = Rules::load(DEFAULT_CATALOG).unwrap();
    let source = discovery::directory_source(&source, "C", "HOST").unwrap();
    let plan =
        discovery::build_plan(vec![source], &rules, &["windows.prefetch".into()], false).unwrap();
    assert_eq!(plan.files.len(), 1);
    let store = Arc::new(MemoryStore::default());
    let target = Target::from_store(store.clone(), true).unwrap();
    let (root, summary) = collect::collect(
        &plan,
        &temp.path().join("staging"),
        &options(target.clone()),
    )
    .unwrap();
    assert_eq!(
        summary.completeness,
        "PendingServerReadbackVerification",
        "{summary:?}\n{}\n{}",
        fs::read_to_string(root.join("Manifest.jsonl")).unwrap(),
        fs::read_to_string(root.join("NTFS-Metadata.jsonl")).unwrap_or_default()
    );
    assert!(!root.join("C").exists());
    let records: Vec<Record> = fs::read_to_string(root.join("Manifest.jsonl"))
        .unwrap()
        .lines()
        .map(|s| serde_json::from_str(s).unwrap())
        .collect();
    assert_eq!(records[0].status, "Transferred");
    assert!(!records[0].verified);
    assert_eq!(records[0].sha256, Some(sha256(&bytes)));
    assert!(kumade::verify::verify(&root).is_err());
    let (name, digest) = target.publish(&root, &summary).unwrap();
    let objects = store.objects.lock().unwrap();
    let delivery: serde_json::Value = serde_json::from_slice(&objects[&name]).unwrap();
    assert_eq!(sha256(&objects[&name]), digest);
    let payload = delivery["Objects"]
        .as_array()
        .unwrap()
        .iter()
        .find(|v| v["Name"].as_str().unwrap().contains("-payload-"))
        .unwrap();
    let compressed = &objects[payload["Name"].as_str().unwrap()];
    assert!(compressed.len() < 100000, "{}", compressed.len());
    let mut restored = vec![];
    flate2::read::GzDecoder::new(compressed.as_slice())
        .read_to_end(&mut restored)
        .unwrap();
    assert_eq!(restored, bytes);
    // The administrator verifies readback with only Python's standard library.
    let incoming = temp.path().join("incoming");
    fs::create_dir(&incoming).unwrap();
    for (n, b) in objects.iter() {
        fs::write(incoming.join(n), b).unwrap();
    }
    drop(objects);
    let python = if cfg!(windows) { "python" } else { "python3" };
    let result = std::process::Command::new(python)
        .arg(concat!(
            env!("CARGO_MANIFEST_DIR"),
            "/scripts/sftp_restore.py"
        ))
        .args([
            "--incoming",
            incoming.to_str().unwrap(),
            "--delivery",
            &name,
            "--sha256",
            &digest,
            "--output",
            temp.path().join("restore").to_str().unwrap(),
            "--receipt",
            temp.path().join("receipt.json").to_str().unwrap(),
            "--uploader-revoked",
        ])
        .output()
        .unwrap();
    assert!(
        result.status.success(),
        "{}",
        String::from_utf8_lossy(&result.stderr)
    );
    assert_eq!(
        fs::read(temp.path().join("restore/C/Windows/Prefetch/APP.EXE.pf")).unwrap(),
        bytes
    );
    assert!(target.publish(&root, &summary).is_err());
}
#[test]
fn failed_stream_never_creates_local_payload_or_completion_marker() {
    let t = tempfile::tempdir().unwrap();
    let s = t.path().join("source");
    fs::create_dir_all(s.join("Windows/Prefetch")).unwrap();
    fs::write(s.join("Windows/Prefetch/APP.pf"), vec![7; 40000]).unwrap();
    let rules = Rules::load(DEFAULT_CATALOG).unwrap();
    let plan = discovery::build_plan(
        vec![discovery::directory_source(&s, "C", "HOST").unwrap()],
        &rules,
        &["windows.prefetch".into()],
        false,
    )
    .unwrap();
    let store = Arc::new(MemoryStore {
        fail_after: Some(12000),
        ..Default::default()
    });
    let target = Target::from_store(store.clone(), false).unwrap();
    let (root, summary) =
        collect::collect(&plan, &t.path().join("staging"), &options(target)).unwrap();
    assert_eq!(summary.completeness, "Partial");
    assert_eq!(summary.failed, 1);
    assert!(!root.join("C").exists());
    assert!(
        store
            .objects
            .lock()
            .unwrap()
            .keys()
            .all(|k| !k.ends_with("-delivery.json"))
    );
}
#[test]
fn staging_retained_on_failure_and_removed_only_when_committed() {
    let t = tempfile::tempdir().unwrap();
    let path = {
        let s = sftp::Staging::new(t.path()).unwrap();
        s.path().to_owned()
    };
    assert!(path.is_dir());
    let mut s = sftp::Staging::new(t.path()).unwrap();
    let path = s.path().to_owned();
    s.cleanup().unwrap();
    assert!(!path.exists());
}
#[test]
fn validates_host_pin_path_and_exclusive_create() {
    let mut args = sftp::Args {
        sftp: Some("example.org".into()),
        sftp_user: Some("temp".into()),
        sftp_host_key: Some("SHA256:AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA".into()),
        ..Default::default()
    };
    assert!(args.validate().is_ok());
    for path in [
        "../incoming",
        "/incoming/../root",
        "/incoming\\root",
        "/incoming\nroot",
    ] {
        args.sftp_directory = Some(path.into());
        assert!(args.validate().is_err());
    }
    args.sftp_directory = None;
    args.sftp_host_key = Some("SHA256:short".into());
    assert!(args.validate().is_err());
    let store = MemoryStore::default();
    store
        .create("test", 0)
        .unwrap()
        .write_all(b"original")
        .unwrap();
    assert!(store.create("test", 0).is_err());
    assert_eq!(store.objects.lock().unwrap()["test"], b"original");
}

#[test]
fn raw_ntfs_and_absent_candidates_keep_their_status_without_local_payloads() {
    let temp = tempfile::tempdir().unwrap();
    let root = temp.path().join("source");
    fs::create_dir(&root).unwrap();
    let mut source = discovery::directory_source(&root, "C", "HOST").unwrap();
    source.raw_device = Some(
        std::path::Path::new(env!("CARGO_MANIFEST_DIR")).join("tests/fixtures/ntfs-testfs1.img"),
    );
    let rules = Rules::load(DEFAULT_CATALOG).unwrap();
    let plan = discovery::build_plan(
        vec![source],
        &rules,
        &["windows.ntfs.mft".into(), "windows.ntfs.usn".into()],
        false,
    )
    .unwrap();
    let store = Arc::new(MemoryStore::default());
    let target = Target::from_store(store.clone(), true).unwrap();
    let (root, summary) = collect::collect(
        &plan,
        &temp.path().join("staging"),
        &options(target.clone()),
    )
    .unwrap();
    assert_eq!(summary.collected, 1);
    assert_eq!(summary.failed, 0);
    assert!(!root.join("C").exists());
    let records: Vec<Record> = fs::read_to_string(root.join("Manifest.jsonl"))
        .unwrap()
        .lines()
        .map(|s| serde_json::from_str(s).unwrap())
        .collect();
    let mft = records.iter().find(|r| r.status == "Transferred").unwrap();
    assert_eq!(mft.method, "RawNTFS");
    assert!(records.iter().any(|r| r.status == "NotPresent"));
    let (name, _) = target.publish(&root, &summary).unwrap();
    let objects = store.objects.lock().unwrap();
    let delivery: serde_json::Value = serde_json::from_slice(&objects[&name]).unwrap();
    assert!(delivery["Objects"].as_array().unwrap().iter().any(|o| {
        o["RelativePath"]
            .as_str()
            .unwrap()
            .starts_with("_KumadeStreams/")
    }));
}

#[test]
fn source_change_is_partial_and_retains_the_actual_streamed_version() {
    let temp = tempfile::tempdir().unwrap();
    let source = temp.path().join("source");
    fs::create_dir_all(source.join("Windows/Prefetch")).unwrap();
    let file = source.join("Windows/Prefetch/APP.pf");
    fs::write(&file, b"before").unwrap();
    let rules = Rules::load(DEFAULT_CATALOG).unwrap();
    let plan = discovery::build_plan(
        vec![discovery::directory_source(&source, "C", "HOST").unwrap()],
        &rules,
        &["windows.prefetch".into()],
        false,
    )
    .unwrap();
    fs::write(file, b"different bytes after planning").unwrap();
    let target = Target::from_store(Arc::new(MemoryStore::default()), false).unwrap();
    let (root, summary) =
        collect::collect(&plan, &temp.path().join("staging"), &options(target)).unwrap();
    assert_eq!(summary.completeness, "Partial");
    assert_eq!(summary.partial, 1);
    let r: Record = serde_json::from_str(
        fs::read_to_string(root.join("Manifest.jsonl"))
            .unwrap()
            .lines()
            .next()
            .unwrap(),
    )
    .unwrap();
    assert!(r.changed_during_read);
    assert_eq!(r.sha256, Some(sha256(b"different bytes after planning")));
    assert!(!r.verified);
}

#[test]
fn named_streams_are_disjoint_from_the_base_file_namespace() {
    let temp = tempfile::tempdir().unwrap();
    let root = temp.path().join("source");
    fs::create_dir_all(root.join("Windows/Prefetch")).unwrap();
    let file = root.join("Windows/Prefetch/APP.pf");
    fs::write(&file, b"base").unwrap();
    fs::write(format!("{}:Extra", file.display()), b"named stream").unwrap();
    let rules = Rules::load(DEFAULT_CATALOG).unwrap();
    let mut plan = discovery::build_plan(
        vec![discovery::directory_source(&root, "C", "HOST").unwrap()],
        &rules,
        &["windows.prefetch".into()],
        false,
    )
    .unwrap();
    plan.files
        .retain(|f| f.relative_path.file_name().is_some_and(|n| n == "APP.pf"));
    let mut stream = plan.files[0].clone();
    stream.id = "named-stream".into();
    stream.stream = Some("Extra".into());
    stream.before = None;
    plan.files.push(stream);
    let store = Arc::new(MemoryStore::default());
    let target = Target::from_store(store.clone(), false).unwrap();
    let (root, summary) = collect::collect(
        &plan,
        &temp.path().join("staging"),
        &options(target.clone()),
    )
    .unwrap();
    assert_eq!(summary.collected, 2);
    let (name, _) = target.publish(&root, &summary).unwrap();
    let objects = store.objects.lock().unwrap();
    let delivery: serde_json::Value = serde_json::from_slice(&objects[&name]).unwrap();
    let list = delivery["Objects"].as_array().unwrap();
    assert!(
        list.iter()
            .any(|o| o["RelativePath"] == "C/Windows/Prefetch/APP.pf")
    );
    assert!(
        list.iter()
            .any(|o| o["RelativePath"] == "_KumadeStreams/C/Windows/Prefetch/APP.pf/Extra")
    );
}
