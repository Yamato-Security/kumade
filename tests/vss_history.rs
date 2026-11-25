// Copyright (C) 2026 Shirofune Security Co., Ltd.
// SPDX-License-Identifier: RPL-1.5
use kumade::{
    catalog::Rules,
    discovery,
    model::{Record, Source},
    vss::Snapshot,
    vss_history::{self, Selection},
};
use std::{fs, path::Path, process::Command};

fn snapshot(id: u128, volume: &str, time: &str) -> Snapshot {
    Snapshot {
        snapshot_id: uuid::Uuid::from_u128(id).to_string(),
        snapshot_set_id: uuid::Uuid::from_u128(id + 100).to_string(),
        provider_id: uuid::Uuid::from_u128(900).to_string(),
        original_volume: volume.into(),
        original_root: "C:\\".into(),
        device_object: format!(r"\\?\GLOBALROOT\Device\HarddiskVolumeShadowCopy{id}").into(),
        created_utc: time.into(),
        attributes: 16,
        consistency: "UnknownHistorical".into(),
        writers_participated: None,
        owned_by_collector: Some(false),
    }
}
fn snapshots() -> Vec<Snapshot> {
    vec![
        snapshot(1, "C", "2026-10-20T09:00:00Z"),
        snapshot(2, "C", "2026-10-21T09:00:00Z"),
        snapshot(3, "D", "2026-10-20T09:00:00Z"),
        snapshot(4, "D", "2026-10-22T09:00:00Z"),
    ]
}
#[test]
fn selectors_validate_and_newest_counts_are_per_volume() {
    assert_eq!("ALL".parse::<Selection>().unwrap(), Selection::All);
    assert_eq!("newest".parse::<Selection>().unwrap(), Selection::Newest(1));
    assert_eq!("2".parse::<Selection>().unwrap(), Selection::Newest(2));
    for bad in [
        "0",
        "-1",
        "no",
        "1.5",
        "184467440737095516160",
        "00000000-0000-0000-0000-000000000000",
    ] {
        assert!(bad.parse::<Selection>().is_err(), "{bad}");
    }
    let selected = vss_history::select(&snapshots(), &Selection::Newest(1)).unwrap();
    assert_eq!(
        selected
            .iter()
            .map(|s| s.snapshot_id.clone())
            .collect::<Vec<_>>(),
        vec![
            uuid::Uuid::from_u128(2).to_string(),
            uuid::Uuid::from_u128(4).to_string()
        ]
    );
    assert_eq!(
        vss_history::select(&snapshots(), &Selection::Newest(2))
            .unwrap()
            .len(),
        4
    );
    assert_eq!(
        vss_history::select(&snapshots(), &Selection::All)
            .unwrap()
            .len(),
        4
    );
}
#[test]
fn snapshot_ids_and_sorting_do_not_confuse_clock_offsets_or_time_ties() {
    let mut all = vec![
        snapshot(2, "C", "2026-10-20T09:00:00+09:00"),
        snapshot(1, "c\\", "2026-10-20T01:00:00Z"),
    ];
    assert_eq!(
        vss_history::select(&all, &Selection::Newest(1)).unwrap()[0].snapshot_id,
        uuid::Uuid::from_u128(1).to_string()
    );
    all[0].created_utc = all[1].created_utc.clone();
    assert_eq!(
        vss_history::select(&all, &Selection::Newest(1)).unwrap()[0].snapshot_id,
        uuid::Uuid::from_u128(1).to_string()
    );
    assert_ne!(
        vss_history::source_id("C", &all[0]).unwrap(),
        vss_history::source_id("C", &all[1]).unwrap()
    );
    let selected = Selection::Id(uuid::Uuid::from_u128(2));
    assert_eq!(vss_history::select(&all, &selected).unwrap().len(), 1);
    assert!(vss_history::select(&all, &Selection::Id(uuid::Uuid::from_u128(99))).is_err());
    all[0].snapshot_id = all[1].snapshot_id.clone();
    assert!(vss_history::select(&all, &Selection::All).is_err());
}
#[test]
fn listing_formats_preserve_fields_and_empty_csv_still_has_headers() {
    use kumade::live_info::Format;
    let rows = vss_history::listings(&snapshots()).unwrap();
    let mut csv = vec![];
    vss_history::write_listing(&mut csv, &rows, Format::Csv).unwrap();
    let mut parsed = csv::Reader::from_reader(csv.as_slice());
    let headers = parsed.headers().unwrap().clone();
    assert_eq!(headers.len(), 9);
    assert_eq!(&headers[0], "SnapshotId");
    assert_eq!(parsed.records().count(), 4);
    let mut json = vec![];
    vss_history::write_listing(&mut json, &rows, Format::Json).unwrap();
    let parsed: serde_json::Value = serde_json::from_slice(&json).unwrap();
    assert_eq!(parsed.as_array().unwrap().len(), 4);
    assert!(parsed[0].get("CreatedUtc").is_some());
    let mut jsonl = vec![];
    vss_history::write_listing(&mut jsonl, &rows, Format::Jsonl).unwrap();
    assert_eq!(String::from_utf8(jsonl).unwrap().lines().count(), 4);
    let mut csv = vec![];
    vss_history::write_listing(&mut csv, &[], Format::Csv).unwrap();
    assert!(String::from_utf8(csv).unwrap().starts_with("SnapshotId,"));
    let mut unavailable = snapshots();
    unavailable[0].device_object = "".into();
    let rows = vss_history::listings(&unavailable).unwrap();
    assert!(
        !rows
            .iter()
            .find(|r| r.snapshot_id == unavailable[0].snapshot_id)
            .unwrap()
            .root_readable
    );
}
#[test]
fn historical_writer_participation_is_unknown_and_legacy_snapshot_metadata_still_reads() {
    let s = snapshot(1, "C", "2026-10-20T09:00:00Z");
    let mut value = serde_json::to_value(s).unwrap();
    assert!(value["WritersParticipated"].is_null());
    assert_eq!(value["OwnedByCollector"], false);
    value.as_object_mut().unwrap().remove("OwnedByCollector");
    value["WritersParticipated"] = serde_json::json!(false);
    let old: Snapshot = serde_json::from_value(value).unwrap();
    assert_eq!(old.writers_participated, Some(false));
    assert_eq!(old.owned_by_collector, None);
}
#[test]
fn live_and_historical_versions_are_separate_even_when_bytes_match() {
    let temp = tempfile::tempdir().unwrap();
    let r=Rules::load("SchemaVersion: 1\nArtifacts:\n - {Id: windows.prefetch, Name: Prefetch, Category: ProcessExecution, Patterns: ['Windows/Prefetch/*.pf']}\n").unwrap();
    let mut sources: Vec<Source> = vec![];
    for (n, bytes) in [
        (0, b"current".as_slice()),
        (1, b"current".as_slice()),
        (2, b"older".as_slice()),
    ] {
        let root = temp.path().join(format!("source{n}"));
        fs::create_dir_all(root.join("Windows/Prefetch")).unwrap();
        fs::write(root.join("Windows/Prefetch/EVIDENCE.pf"), bytes).unwrap();
        let s = snapshot(n, "C", "2026-10-20T09:00:00Z");
        let id = if n == 0 {
            "C".into()
        } else {
            vss_history::source_id("C", &s).unwrap()
        };
        let mut source = discovery::directory_source(&root, &id, "HISTORY-TEST").unwrap();
        if n != 0 {
            source.snapshot = Some(s);
        }
        sources.push(source);
    }
    let roots = sources.iter().map(|s| s.root.clone()).collect::<Vec<_>>();
    let plan = discovery::build_plan(sources, &r, &[], false).unwrap();
    assert_eq!(plan.files.len(), 3);
    let options = kumade::collect::Options {
        remote: None,
        threads: 3,
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
    let (output, summary) =
        kumade::collect::collect(&plan, &temp.path().join("output"), &options).unwrap();
    assert_eq!(summary.collected, 3);
    let rows = fs::read_to_string(output.join("Manifest.jsonl"))
        .unwrap()
        .lines()
        .map(|l| serde_json::from_str::<Record>(l).unwrap())
        .collect::<Vec<_>>();
    assert_eq!(
        rows.iter().filter(|r| r.method == "VssNativeRead").count(),
        2
    );
    assert_eq!(
        rows.iter()
            .filter(|r| r.sha256.as_deref() == Some(kumade::model::sha256(b"current").as_str()))
            .count(),
        2
    );
    let paths = rows
        .iter()
        .map(|r| r.relative_output_path.clone().unwrap())
        .collect::<std::collections::HashSet<_>>();
    assert_eq!(paths.len(), 3);
    for row in &rows {
        assert!(
            output
                .join(row.relative_output_path.as_ref().unwrap())
                .is_file()
        );
    }
    assert_eq!(kumade::verify::verify(&output).unwrap(), (3, true));
    for root in roots {
        assert!(root.join("Windows/Prefetch/EVIDENCE.pf").is_file());
    }
    let run: serde_json::Value =
        serde_json::from_slice(&fs::read(output.join("Run.json")).unwrap()).unwrap();
    assert_eq!(run["ExistingVssEnabled"], true);
}
#[test]
fn listing_help_and_invalid_selectors_do_not_touch_vss() {
    let help = Command::new(env!("CARGO_BIN_EXE_kumade"))
        .args(["list-vss", "--help"])
        .output()
        .unwrap();
    assert!(help.status.success());
    let text = String::from_utf8_lossy(&help.stdout);
    assert!(text.contains("--volume") && text.contains("--format"));
    for args in [
        vec!["collect", "--vss-existing", "0"],
        vec!["collect", "--vss-existing", "no"],
        vec!["collect", "--vss-existing", "--source", "offline"],
    ] {
        let out = Command::new(env!("CARGO_BIN_EXE_kumade"))
            .args(args)
            .output()
            .unwrap();
        assert_eq!(out.status.code(), Some(2));
    }
    assert!(Path::new(env!("CARGO_BIN_EXE_kumade")).is_file());
}
