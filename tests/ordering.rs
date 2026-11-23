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

use kumade::{
    catalog::Rules,
    collect::{self, Options},
    discovery,
    model::*,
    ordering, paths,
};
use std::{
    fs,
    path::{Path, PathBuf},
};
fn fixture() -> (tempfile::TempDir, Plan) {
    let t = tempfile::tempdir().unwrap();
    let source = t.path().join("source");
    fs::create_dir(&source).unwrap();
    let artifacts = [
        ("windows.paging", "paging.bin"),
        ("windows.prefetch", "pf.bin"),
        ("windows.srum", "srum.bin"),
        ("windows.registry.system", "system.bin"),
        ("windows.eventlogs", "event.bin"),
        ("windows.ntfs.mft", "mft.bin"),
        ("windows.ntfs.logfile", "logfile.bin"),
        ("windows.ntfs.usn", "usn.bin"),
    ];
    let mut yaml = "SchemaVersion: 1\nArtifacts:\n".to_string();
    for (id, name) in artifacts {
        fs::write(source.join(name), name.as_bytes()).unwrap();
        yaml += &format!(" - {{Id: {id}, Name: Test, Category: Test, Patterns: ['{name}']}}\n");
    }
    let r = Rules::load(&yaml).unwrap();
    let source = discovery::directory_source(&source, "C", "ORDER").unwrap();
    let mut p = discovery::build_plan(vec![source], &r, &[], false).unwrap();
    p.files.reverse();
    (t, p)
}
fn options() -> Options {
    Options {
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
fn records(root: &Path) -> Vec<Record> {
    fs::read_to_string(root.join("Manifest.jsonl"))
        .unwrap()
        .lines()
        .map(|l| serde_json::from_str(l).unwrap())
        .collect()
}
#[test]
fn payloads_obey_volatility_barriers_and_ram_request_is_first() {
    let (t, mut p) = fixture();
    p.memory_requested = true;
    let (root, s) = collect::collect(&p, &t.path().join("output"), &options()).unwrap();
    let rows = records(&root);
    assert_eq!(rows[0].artifact_ids, "windows.memory");
    assert_eq!(
        rows.iter()
            .filter(|r| r.artifact_ids == "windows.memory")
            .count(),
        1
    );
    assert_eq!(rows[0].status, "Failed");
    let priorities: Vec<_> = rows[1..]
        .iter()
        .map(|r| {
            ordering::disk_priority(p.files.iter().find(|f| f.id == r.observation_id).unwrap())
        })
        .collect();
    assert!(
        priorities.windows(2).all(|p| p[0] <= p[1]),
        "{priorities:?}"
    );
    for pair in rows.windows(2) {
        assert!(pair[0].finished_utc <= pair[1].started_utc);
    }
    assert_eq!(s.completeness, "Partial");
    assert_eq!(kumade::verify::verify(&root).unwrap(), (8, false));
    assert!(fs::read_dir(t.path().join("output")).unwrap().all(|e| {
        !e.unwrap()
            .file_name()
            .to_string_lossy()
            .starts_with(".kumade-volatile-")
    }));
}
#[test]
fn native_base_and_ads_are_promoted_together_ahead_of_bulk_files() {
    let (_t, mut p) = fixture();
    let base = p
        .files
        .iter_mut()
        .find(|f| f.artifacts == ["windows.paging"])
        .unwrap();
    base.relative_path = PathBuf::from("journal");
    let mut stream = base.clone();
    stream.id = "stream".into();
    stream.stream = Some("$J".into());
    stream.artifacts = vec!["windows.ntfs.usn".into()];
    let base_id = base.id.clone();
    p.files.push(stream);
    let batches = ordering::batches(&p.files, true);
    let base_batch = batches
        .iter()
        .position(|(_, v)| v.iter().any(|f| f.id == base_id))
        .unwrap();
    let ads_batch = batches
        .iter()
        .position(|(_, v)| v.iter().any(|f| f.id == "stream"))
        .unwrap();
    assert_eq!(batches[base_batch].0, 0);
    assert_eq!(batches[ads_batch].0, 0);
    assert!(base_batch < ads_batch);
    assert!(
        batches
            .iter()
            .take(ads_batch + 1)
            .all(|(priority, _)| *priority == 0)
    );
}
#[test]
fn volatile_provider_classes_precede_slow_inventory() {
    assert!(ordering::live_priority("Processes") < ordering::live_priority("TcpConnections"));
    assert!(ordering::live_priority("DnsCache") < ordering::live_priority("HostInfo"));
    assert!(ordering::live_priority("SmbOpenFiles") < ordering::live_priority("WindowsPackages"));
    assert!(
        ordering::live_priority("IpConfiguration") < ordering::live_priority("InstalledSoftware")
    );
}
#[test]
fn retained_early_ram_request_has_independent_integrity_checks() {
    let t = tempfile::tempdir().unwrap();
    let early = kumade::early::prepare(t.path(), "HOST", true, None)
        .unwrap()
        .unwrap();
    assert_eq!(kumade::verify::verify(early.path()).unwrap(), (0, false));
    fs::write(early.path().join("MemoryRequest.json"), b"tampered").unwrap();
    assert!(early.validate("HOST", true).is_err());
    assert!(kumade::verify::verify(early.path()).is_err());
}
fn pe() -> Vec<u8> {
    let mut b = vec![0u8; 4608];
    b[..2].copy_from_slice(b"MZ");
    b[60..64].copy_from_slice(&128u32.to_le_bytes());
    b[128..132].copy_from_slice(b"PE\0\0");
    b[132..134].copy_from_slice(&0x14cu16.to_le_bytes());
    b[134..136].copy_from_slice(&1u16.to_le_bytes());
    b[148..150].copy_from_slice(&224u16.to_le_bytes());
    b[150..152].copy_from_slice(&2u16.to_le_bytes());
    b[152..154].copy_from_slice(&0x10bu16.to_le_bytes());
    b[376..381].copy_from_slice(b".text");
    b[392..396].copy_from_slice(&4096u32.to_le_bytes());
    b[396..400].copy_from_slice(&512u32.to_le_bytes());
    b[412..416].copy_from_slice(&0x60000020u32.to_le_bytes());
    for (i, v) in b[512..].iter_mut().enumerate() {
        *v = (i % 256) as u8;
    }
    b
}
#[test]
fn entropy_only_runs_after_core_payloads_and_uses_preserved_versions() {
    let (t, mut p) = fixture();
    let source = p.sources[0].root.clone();
    let hot = source.join("hot.exe");
    fs::write(&hot, pe()).unwrap();
    let r=Rules::load("SchemaVersion: 1\nArtifacts:\n - {Id: windows.eventlogs, Name: Event, Category: EventLogs, Patterns: ['hot.exe']}\n").unwrap();
    p = discovery::build_plan(p.sources, &r, &[], false).unwrap();
    fs::write(source.join("extra.exe"), pe()).unwrap();
    let parent = t.path().join("output");
    let root = parent.join(paths::run_name("ORDER", &p.created_utc).unwrap());
    let mut options = options();
    options.entropy = Some(kumade::entropy::Settings::default());
    let mut hook = |updated: &Plan| -> anyhow::Result<collect::CapacityUpdate> {
        assert!(root.join("C/hot.exe").is_file());
        assert!(!root.join("C/extra.exe").exists());
        assert_eq!(updated.files.len(), 2);
        fs::write(&hot, b"changed after acquisition").unwrap();
        Ok(collect::CapacityUpdate {
            reserve: 0,
            host: None,
        })
    };
    let (root, s) = collect::collect_with_capacity(&p, &parent, &options, Some(&mut hook)).unwrap();
    assert_eq!(s.collected, 2);
    assert_eq!(records(&root)[0].source_path, hot.display().to_string());
    let report: Vec<serde_json::Value> = fs::read_to_string(root.join("HighEntropyBinaries.jsonl"))
        .unwrap()
        .lines()
        .map(|l| serde_json::from_str(l).unwrap())
        .collect();
    assert!(report.iter().any(|r| r["RelativePath"] == "hot.exe"
        && r["Method"] == "CollectedCopy"
        && r["HashMatchesAnalysis"] == true));
    assert_eq!(kumade::verify::verify(&root).unwrap(), (2, true));
    let initial: Plan =
        serde_json::from_reader(fs::File::open(root.join("InitialPlan.json")).unwrap()).unwrap();
    assert_eq!(initial.files.len(), 1);
}
#[test]
fn deferred_entropy_can_analyze_a_preserved_binary_deleted_from_live_source() {
    let (t, mut p) = fixture();
    let source = p.sources[0].clone();
    let file = source.root.join("deleted.exe");
    fs::write(&file, pe()).unwrap();
    let r=Rules::load("SchemaVersion: 1\nArtifacts:\n - {Id: core, Name: Core, Category: Core, Patterns: ['deleted.exe']}").unwrap();
    p = discovery::build_plan(vec![source.clone()], &r, &[], false).unwrap();
    let captured = t.path().join("captured");
    fs::create_dir(&captured).unwrap();
    let copy = captured.join("deleted.exe");
    fs::copy(&file, &copy).unwrap();
    fs::remove_file(file).unwrap();
    let copies = [(
        (source.id, p.files[0].relative_path.clone()),
        kumade::entropy::CopyInput {
            root: captured,
            path: copy.clone(),
            sha256: collect::hash_file(&copy).unwrap().1,
            before: p.files[0].before.clone(),
        },
    )]
    .into_iter()
    .collect();
    kumade::entropy::augment_with_copies(
        &mut p,
        &Default::default(),
        &t.path().join("out"),
        2,
        true,
        &copies,
    )
    .unwrap();
    let report = p.entropy_scan.unwrap();
    assert_eq!(report.counts.candidates, 1);
    assert_eq!(report.observations[0].method, "CollectedCopy");
}
#[cfg(windows)]
#[test]
fn fast_live_state_is_preserved_before_disk_files_and_slow_inventory() {
    let (t, mut p) = fixture();
    p.files.retain(|f| f.artifacts == ["windows.ntfs.usn"]);
    let live = kumade::live_info::Options {
        selected: vec!["Processes".into(), "HostInfo".into()],
        reserve_bytes: 0,
        quiet: true,
        ..Default::default()
    };
    let early = kumade::early::prepare(&t.path().join("output"), "ORDER", false, Some(&live))
        .unwrap()
        .unwrap();
    let mut opts = options();
    opts.live_info = Some(live);
    opts.early = Some(early.clone());
    let (root, s) = collect::collect(&p, &t.path().join("output"), &opts).unwrap();
    assert_eq!(s.live_info_failed_providers, 0);
    let v: serde_json::Value =
        serde_json::from_reader(fs::File::open(root.join("LiveInfo/Manifest.json")).unwrap())
            .unwrap();
    let entries = v["Entries"].as_array().unwrap();
    let process = entries
        .iter()
        .find(|e| e["Provider"] == "Processes")
        .unwrap();
    let host = entries
        .iter()
        .find(|e| e["Provider"] == "HostInfo")
        .unwrap();
    let row = &records(&root)[0];
    assert!(process["FinishedUtc"].as_str().unwrap() <= row.started_utc.as_str());
    assert!(row.finished_utc.as_str() <= host["StartedUtc"].as_str().unwrap());
    assert_eq!(kumade::verify::verify(&root).unwrap(), (1, true));
    early.cleanup().unwrap();
}

#[test]
fn same_drive_output_parent_does_not_exclude_the_whole_drive_from_entropy() {
    let (t, mut p) = fixture();
    let root = p.sources[0].root.clone();
    p.sources[0].live = true;
    p.files.clear();
    for c in &mut p.coverage {
        c.discovered = 0;
        c.status = "Excluded".into();
    }
    p.known_bytes = 0;
    p.unknown_sizes = 0;
    fs::write(root.join("additional.exe"), pe()).unwrap();
    let mut opts = options();
    opts.entropy = Some(Default::default());
    let (output, s) = collect::collect(&p, &root, &opts).unwrap();
    assert_eq!(s.collected, 1);
    assert!(output.join("C/additional.exe").is_file());
    assert_eq!(kumade::verify::verify(&output).unwrap(), (1, true));
    drop(t);
}
