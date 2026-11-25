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
        remote: None,
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
    // Handle validation compares canonical Windows namespaces (including \\?\).
    let captured = kumade::platform::canonicalize(&captured).unwrap();
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
    assert_eq!(report.counts.candidates, 1, "{report:?}");
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

#[test]
fn output_exclusions_do_not_hide_matching_paths_on_another_volume() {
    let (t, p) = fixture();
    let mut c = p.sources[0].clone();
    c.live = true; // Synthetic live root permits the collector's own output on C.
    let d_root = t.path().join("drive-d");
    let output = c.root.join("Evidence");
    fs::create_dir_all(&output).unwrap();
    fs::write(output.join("previous-output.exe"), pe()).unwrap();
    fs::create_dir_all(d_root.join("Evidence")).unwrap();
    fs::write(d_root.join("Evidence/core.exe"), pe()).unwrap();
    fs::write(d_root.join("Evidence/additional.exe"), pe()).unwrap();
    let d = discovery::directory_source(&d_root, "D", "ORDER").unwrap();
    let r = Rules::load("SchemaVersion: 1\nArtifacts:\n - {Id: windows.prefetch, Name: Test, Category: Test, Patterns: ['pf.bin', 'Evidence/core.exe']}\n").unwrap();
    let plan = discovery::build_plan(vec![c, d], &r, &[], false).unwrap();
    let mut opts = options();
    opts.entropy = Some(Default::default());
    let (root, summary) = collect::collect(&plan, &output, &opts).unwrap();
    assert_eq!(
        summary.collected, 3,
        "D's additional candidate must be acquired"
    );
    assert_eq!(kumade::verify::verify(&root).unwrap(), (3, true));
    assert!(root.join("D/Evidence/additional.exe").is_file());
    let rows: Vec<serde_json::Value> = fs::read_to_string(root.join("HighEntropyBinaries.jsonl"))
        .unwrap()
        .lines()
        .map(|l| serde_json::from_str(l).unwrap())
        .collect();
    assert!(rows.iter().any(|r| r["SourceId"] == "C"
        && r["RelativePath"] == "Evidence"
        && r["AnalysisStatus"] == "Excluded"));
    for (path, status, method) in [
        ("Evidence/core.exe", "AlreadyPlanned", "CollectedCopy"),
        ("Evidence/additional.exe", "Selected", "FileAPI"),
    ] {
        let row = rows
            .iter()
            .find(|r| r["SourceId"] == "D" && r["RelativePath"] == path)
            .unwrap();
        assert_eq!(row["AnalysisStatus"], status);
        assert_eq!(row["Method"], method);
        assert_eq!(row["HashMatchesAnalysis"], true);
    }
    let final_plan: Plan =
        serde_json::from_reader(fs::File::open(root.join("Plan.json")).unwrap()).unwrap();
    let settings = final_plan.entropy_scan.unwrap().settings;
    assert!(
        settings.excludes.is_empty(),
        "Automatic paths must not become global user globs"
    );
    assert!(settings.output_excludes.contains_key("C"));
    assert!(!settings.output_excludes.contains_key("D"));
}

#[test]
fn scoped_output_paths_preserve_user_globs_and_snapshot_mapping() {
    for frozen in [false, true] {
        let t = tempfile::tempdir().unwrap();
        let c_root = t.path().join("drive-c");
        let d_root = t.path().join("drive-d");
        let snapshot = t.path().join("snapshot-c");
        for root in [&c_root, &d_root, &snapshot] {
            fs::create_dir_all(root.join("Evidence[1]")).unwrap();
            fs::create_dir_all(root.join("Private")).unwrap();
            fs::write(root.join("Evidence[1]/binary.exe"), pe()).unwrap();
            fs::write(root.join("Private/private.exe"), pe()).unwrap();
        }
        let mut c = discovery::directory_source(&c_root, "C", "ORDER").unwrap();
        if frozen {
            c.snapshot = Some(kumade::vss::Snapshot {
                snapshot_id: "synthetic".into(),
                snapshot_set_id: "synthetic".into(),
                provider_id: "synthetic".into(),
                original_volume: "synthetic".into(),
                original_root: c.root.clone(),
                device_object: snapshot.clone(),
                created_utc: utc_now(),
                attributes: 0,
                consistency: "Synthetic fixture".into(),
                writers_participated: Some(false),
                owned_by_collector: Some(true),
            });
            c.root = kumade::platform::canonicalize(&snapshot).unwrap();
        }
        let d = discovery::directory_source(&d_root, "D", "ORDER").unwrap();
        let r = Rules::load("SchemaVersion: 1\nArtifacts:\n - {Id: test, Name: Test, Category: Test, Patterns: ['missing']}\n").unwrap();
        let mut plan = discovery::build_plan(vec![c, d], &r, &[], false).unwrap();
        let mut settings = kumade::entropy::Settings {
            excludes: vec!["Private/**".into()],
            ..Default::default()
        };
        let output = c_root.join("Evidence[1]");
        kumade::entropy::exclude_output_paths(
            &mut settings,
            &plan.sources,
            std::slice::from_ref(&output),
        )
        .unwrap();
        assert_eq!(settings.excludes, ["Private/**"]);
        // Container output can be outside the source trees: only the scoped
        // physical-output rule should exclude C's frozen/live Evidence[1].
        kumade::entropy::augment_plan(&mut plan, &settings, &t.path().join("analysis"), 2, true)
            .unwrap();
        let report = plan.entropy_scan.unwrap();
        assert_eq!(report.counts.candidates, 1, "frozen={frozen}: {report:?}");
        assert!(report.observations.iter().any(|r| r.source_id == "D"
            && r.relative_path == "Evidence[1]/binary.exe"
            && r.status == "Selected"));
        assert!(
            !report
                .observations
                .iter()
                .any(|r| r.relative_path == "Private/private.exe" && r.analysis.is_some())
        );
    }
}

#[test]
fn entropy_settings_keep_scoped_exclusions_and_accept_older_settings() {
    let original = kumade::entropy::Settings::default();
    let old = serde_json::to_value(&original).unwrap();
    assert!(old.get("OutputExcludes").is_none());
    let restored: kumade::entropy::Settings = serde_json::from_value(old).unwrap();
    assert!(restored.output_excludes.is_empty());
    let mut settings = original;
    settings
        .output_excludes
        .insert("C".into(), vec!["Evidence/**".into()]);
    let value = serde_json::to_value(&settings).unwrap();
    assert_eq!(value["OutputExcludes"]["C"][0], "Evidence/**");
    let restored: kumade::entropy::Settings = serde_json::from_value(value).unwrap();
    assert_eq!(restored.output_excludes, settings.output_excludes);
}

#[test]
fn unfinished_early_stage_cannot_pass_as_standalone_live_info() {
    let t = tempfile::tempdir().unwrap();
    let root = t.path();
    let live = root.join("LiveInfo");
    fs::create_dir(&live).unwrap();
    collect::write_json_new(
        &live.join("Manifest.json"),
        &serde_json::json!({"SchemaVersion":1,"Entries":[]}),
    )
    .unwrap();
    fs::write(live.join("Manifest.csv"), b"").unwrap();
    let hashes: std::collections::BTreeMap<_, _> =
        ["LiveInfo/Manifest.json", "LiveInfo/Manifest.csv"]
            .into_iter()
            .map(|name| (name, collect::hash_file(&root.join(name)).unwrap().1))
            .collect();
    collect::write_json_new(
        &live.join("Seal.json"),
        &serde_json::json!({"SchemaVersion":1,"FileSHA256":hashes}),
    )
    .unwrap();
    // The same sealed inventory is valid as standalone live-info output.
    assert_eq!(kumade::verify::verify(root).unwrap(), (0, true));
    // Early capture writes this marker before providers. Without its outer seal,
    // an interrupted acquisition must not masquerade as a finished standalone run.
    collect::write_json_new(&root.join("MemoryRequest.json"), &serde_json::Value::Null).unwrap();
    assert!(kumade::verify::verify(root).is_err());
}
