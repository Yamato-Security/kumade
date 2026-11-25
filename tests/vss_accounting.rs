// Copyright (C) 2026 Shirofune Security Co., Ltd.
// SPDX-License-Identifier: RPL-1.5
//! Acquisition accounting with controlled snapshot views; no VSS service required.
use kumade::{
    catalog::{DEFAULT_CATALOG, Rules},
    collect::{self, Options},
    discovery,
    model::{Plan, Record, Source, Summary},
    verify,
    vss::Snapshot,
};
use std::{
    fs,
    path::{Path, PathBuf},
};

fn source(temp: &Path) -> Source {
    let root = temp.join("snapshot");
    fs::create_dir(&root).unwrap();
    let mut source = discovery::directory_source(&root, "C", "VSS-ACCOUNTING").unwrap();
    source.raw_device = Some(temp.join("unavailable-device"));
    source.snapshot = Some(Snapshot {
        snapshot_id: "snapshot-id".into(),
        snapshot_set_id: "set-id".into(),
        provider_id: "provider-id".into(),
        original_volume: "C:".into(),
        original_root: temp.join("live"),
        device_object: source.raw_device.clone().unwrap(),
        created_utc: kumade::model::utc_now(),
        attributes: 16,
        consistency: "CrashConsistent".into(),
        writers_participated: Some(false),
        owned_by_collector: Some(true),
    });
    source
}

fn plan(source: Source, artifact: &str) -> Plan {
    discovery::build_plan(
        vec![source],
        &Rules::load(DEFAULT_CATALOG).unwrap(),
        &[artifact.into()],
        false,
    )
    .unwrap()
}

fn collect(plan: &Plan, temp: &Path) -> (PathBuf, Summary, Vec<Record>) {
    let options = Options {
        remote: None,
        threads: 2,
        reserve_bytes: 0,
        quiet: true,
        verbose: false,
        ntfs_metadata: false,
        host_reserve: None,
        live_info: None,
        process_scan: None,
        early: None,
        entropy: None,
    };
    let (root, summary) = collect::collect(plan, &temp.join("results"), &options).unwrap();
    let records = fs::read_to_string(root.join("Manifest.jsonl"))
        .unwrap()
        .lines()
        .map(|line| serde_json::from_str(line).unwrap())
        .collect();
    (root, summary, records)
}

#[test]
fn omitted_paging_is_partial_sealed_and_accounted_for_everywhere() {
    let temp = tempfile::tempdir().unwrap();
    let source = source(temp.path());
    fs::write(source.root.join("pagefile.sys"), b"excluded paging content").unwrap();
    let (root, summary, records) = collect(&plan(source, "windows.paging"), temp.path());
    assert_eq!(summary.completeness, "Partial");
    assert_eq!(summary.failed, 1);
    assert_eq!(summary.collected, 0);
    assert_eq!(
        records.iter().filter(|r| r.status == "NotPresent").count(),
        2
    );
    assert_eq!(records.iter().filter(|r| r.status == "Failed").count(), 1);
    assert!(
        records
            .iter()
            .all(|r| r.bytes_read == 0 && r.relative_output_path.is_none())
    );
    let mut errors = csv::Reader::from_path(root.join("Errors.csv")).unwrap();
    assert_eq!(errors.records().count(), 1);
    let mut coverage = csv::Reader::from_path(root.join("Coverage.csv")).unwrap();
    let headers = coverage.headers().unwrap().clone();
    let artifact = headers
        .iter()
        .position(|name| name == "ArtifactId")
        .unwrap();
    let status = headers.iter().position(|name| name == "Status").unwrap();
    let paging = coverage
        .records()
        .map(|row| row.unwrap())
        .find(|row| &row[artifact] == "windows.paging")
        .unwrap();
    assert_eq!(&paging[status], "Partial");
    assert_eq!(verify::verify(&root).unwrap(), (0, false));
}

#[test]
fn absent_paging_on_a_readable_snapshot_is_complete_and_verifiable() {
    let temp = tempfile::tempdir().unwrap();
    let source = source(temp.path());
    let (root, summary, records) = collect(&plan(source, "windows.paging"), temp.path());
    assert_eq!(summary.completeness, "CompleteWithinSelectedPrototypeScope");
    assert_eq!(summary.failed, 0);
    assert_eq!(records.len(), 3);
    assert!(records.iter().all(|r| r.status == "NotPresent"));
    assert_eq!(verify::verify(&root).unwrap(), (0, true));
}

#[test]
fn a_lost_snapshot_is_failure_not_evidence_of_absent_paging() {
    let temp = tempfile::tempdir().unwrap();
    let source = source(temp.path());
    let snapshot_root = source.root.clone();
    let plan = plan(source, "windows.paging");
    fs::rename(&snapshot_root, temp.path().join("disconnected-snapshot")).unwrap();
    let (root, summary, records) = collect(&plan, temp.path());
    assert_eq!(summary.completeness, "Partial");
    assert_eq!(summary.failed, 3);
    assert!(records.iter().all(|r| r.status == "Failed"));
    assert_eq!(verify::verify(&root).unwrap(), (0, false));
}

#[test]
fn an_unavailable_raw_provider_is_failure_not_a_missing_mft() {
    for snapshot in [false, true] {
        let temp = tempfile::tempdir().unwrap();
        let mut source = source(temp.path());
        if !snapshot {
            source.snapshot = None;
        }
        let (root, summary, records) = collect(&plan(source, "windows.ntfs.mft"), temp.path());
        assert_eq!(summary.completeness, "Partial");
        assert_eq!(summary.failed, 1);
        assert_eq!(records[0].status, "Failed");
        assert!(!verify::verify(&root).unwrap().1);
    }
}

#[test]
fn a_readable_raw_snapshot_still_acquires_mft_bytes() {
    let temp = tempfile::tempdir().unwrap();
    let mut source = source(temp.path());
    source.raw_device =
        Some(Path::new(env!("CARGO_MANIFEST_DIR")).join("tests/fixtures/ntfs-testfs1.img"));
    let (root, summary, records) = collect(&plan(source, "windows.ntfs.mft"), temp.path());
    assert_eq!(summary.failed, 0);
    assert_eq!(summary.collected, 1);
    assert_eq!(records[0].method, "VssRawNTFS");
    let bytes = fs::read(root.join(records[0].relative_output_path.as_ref().unwrap())).unwrap();
    assert_eq!(&bytes[..4], b"FILE");
    assert_eq!(verify::verify(&root).unwrap(), (1, true));
}

#[test]
fn a_genuinely_absent_raw_file_is_still_not_present() {
    let temp = tempfile::tempdir().unwrap();
    let mut source = source(temp.path());
    source.raw_device =
        Some(Path::new(env!("CARGO_MANIFEST_DIR")).join("tests/fixtures/ntfs-testfs1.img"));
    let rules = Rules::load("SchemaVersion: 1\nArtifacts:\n  - Id: test.absent\n    Name: Missing file\n    Category: FileSystem\n    RawPaths: ['no-such-object']\n").unwrap();
    let plan = discovery::build_plan(vec![source], &rules, &[], false).unwrap();
    let (root, summary, records) = collect(&plan, temp.path());
    assert_eq!(summary.failed, 0);
    assert_eq!(records[0].status, "NotPresent");
    assert_eq!(records[0].method, "VssRawNTFS");
    assert!(verify::verify(&root).unwrap().1);
}
