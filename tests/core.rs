// Copyright (c) 2026 Shirofune Security Co., Ltd.
// SPDX-License-Identifier: RPL-1.5

use kumade::{
    catalog::{DEFAULT_CATALOG, Pattern, Rules},
    collect::{self, Options},
    discovery,
    model::*,
    paths,
    raw::{DeviceReader, RawVolume},
    verify,
};
use std::{
    collections::HashMap,
    fs::{self, File},
    io::{Read, Seek, SeekFrom, Write},
    path::{Path, PathBuf},
};
use tempfile::TempDir;

fn rules() -> Rules {
    Rules::load(DEFAULT_CATALOG).unwrap()
}
fn fixture() -> (TempDir, Source) {
    let temp = TempDir::new().unwrap();
    let root = temp.path().join("source");
    fs::create_dir_all(root.join("Windows/Prefetch")).unwrap();
    fs::create_dir_all(root.join("Users/test/AppData/Roaming/Microsoft/Windows/Recent")).unwrap();
    fs::write(
        root.join("Windows/Prefetch/PROGRAM.EXE.pf"),
        b"synthetic prefetch input",
    )
    .unwrap();
    fs::write(
        root.join("Users/test/AppData/Roaming/Microsoft/Windows/Recent/report.lnk"),
        b"synthetic shortcut input",
    )
    .unwrap();
    let source = discovery::directory_source(&root, "C", "HOST01").unwrap();
    (temp, source)
}
fn plan(source: Source) -> Plan {
    discovery::build_plan(vec![source], &rules(), &[], false).unwrap()
}
fn options() -> Options {
    Options {
        threads: 4,
        reserve_bytes: 0,
        quiet: true,
    }
}
fn read_records(root: &Path) -> Vec<Record> {
    fs::read_to_string(root.join("Manifest.jsonl"))
        .unwrap()
        .lines()
        .map(|l| serde_json::from_str(l).unwrap())
        .collect()
}
fn ntfs_image() -> PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR")).join("tests/fixtures/ntfs-testfs1.img")
}

#[test]
fn embedded_catalog_is_valid_and_has_broad_families() {
    let r = rules();
    assert!(r.catalog.artifacts.len() >= 40);
    for id in [
        "windows.srum",
        "windows.eventlogs",
        "windows.paging",
        "windows.defender",
        "windows.outlook",
        "windows.ntfs.usn",
    ] {
        assert!(r.catalog.artifacts.iter().any(|d| d.id == id));
    }
}
#[test]
fn malformed_catalog_is_rejected() {
    for text in [
        "SchemaVersion: 99\nArtifacts: []",
        "SchemaVersion: 1\nArtifacts: []",
        "Unknown: true",
    ] {
        assert!(Rules::load(text).is_err());
    }
}
#[test]
fn duplicate_artifact_ids_are_rejected() {
    assert!(Rules::load("SchemaVersion: 1\nArtifacts:\n - {Id: x, Name: X, Category: X, Patterns: ['x']}\n - {Id: x, Name: Y, Category: Y, Patterns: ['y']}").is_err());
}
#[test]
fn catalog_cannot_execute_commands() {
    assert!(Rules::load("SchemaVersion: 1\nArtifacts:\n - {Id: x, Name: X, Category: X, Patterns: ['x'], Command: 'evil'}").is_err());
}
#[test]
fn traversal_selectors_are_rejected() {
    for p in [
        "../x",
        "/absolute",
        "C:/Windows",
        "Windows/../x",
        "Windows\\x",
    ] {
        assert!(Pattern::new(p).is_err());
    }
}
#[test]
fn raw_selectors_cannot_escape_volume() {
    for p in ["C:/x", "../x", "x:y/z", "x:", "x:y:z"] {
        let text = format!(
            "SchemaVersion: 1\nArtifacts:\n - {{Id: x, Name: X, Category: X, RawPaths: ['{p}']}}"
        );
        assert!(Rules::load(&text).is_err(), "{p}");
    }
}
#[test]
fn windows_masks_are_case_insensitive() {
    let p = Pattern::new("Windows/System32/winevt/Logs/*.evtx").unwrap();
    assert!(p.matches("windows/SYSTEM32/winevt/Logs/Security.EVTX"));
    assert!(!p.matches("Windows/Elsewhere/Security.evtx"));
}
#[test]
fn percent4_event_names_remain_literal() {
    let p = Pattern::new("Windows/*%4Operational.evtx").unwrap();
    assert!(p.matches("Windows/Microsoft-Windows-Sysmon%4Operational.evtx"));
    assert!(!p.matches("Windows/Microsoft-Windows-SysmonOperational.evtx"));
}
#[test]
fn recursive_pattern_pruning_keeps_only_possible_paths() {
    let p = Pattern::new("Windows/**/Logs/*.evtx").unwrap();
    assert!(p.can_descend("Windows/System32/winevt/Logs"));
    assert!(p.can_descend("Windows"));
    assert!(!p.can_descend("Users/test"));
}
#[test]
fn repeated_recursive_segments_do_not_lose_matches() {
    let p = Pattern::new("Windows/**/**/Logs/**").unwrap();
    assert!(p.can_descend("Windows/Logs/deep/nested"));
    assert!(p.matches("Windows/a/b/Logs/file.bin"));
}
#[test]
fn destination_encoding_is_reversible_without_common_collisions() {
    let values = [
        "CON.txt",
        "%43ON.txt",
        "file:stream",
        "file%3Astream",
        "日本語.txt",
        "a.",
        "a%2E",
        "a ",
        "x\ny",
    ];
    let out: std::collections::HashSet<_> =
        values.iter().map(|v| paths::encode_component(v)).collect();
    assert_eq!(values.len(), out.len());
    assert_eq!(paths::encode_component("日本語.txt"), "日本語.txt");
}
#[test]
fn output_relative_paths_reject_parent_components() {
    assert!(paths::output_relative("C", Path::new("../escape"), None).is_err());
}
#[test]
fn fresh_relative_output_has_an_existing_ancestor() {
    let p = paths::resolve_future(Path::new("kumade-test-nonexistent/child")).unwrap();
    assert!(p.is_absolute());
    assert!(p.ends_with("kumade-test-nonexistent/child"));
}
#[test]
fn profile_artifacts_are_found_without_collecting_all_user_documents() {
    let (_temp, s) = fixture();
    let p = plan(s);
    assert_eq!(p.files.len(), 2);
    assert!(
        p.files
            .iter()
            .any(|f| f.artifacts.contains(&"windows.recent".to_owned()))
    );
}
#[test]
fn complete_database_directory_includes_recovery_companions() {
    let (_temp, s) = fixture();
    fs::create_dir_all(s.root.join("Windows/System32/sru")).unwrap();
    for name in ["SRUDB.dat", "SRU.log", "SRU.chk", "SRU00001.log"] {
        fs::write(
            s.root.join("Windows/System32/sru").join(name),
            b"recovery input",
        )
        .unwrap();
    }
    let p = plan(s);
    assert_eq!(
        p.files
            .iter()
            .filter(|f| f.artifacts.contains(&"windows.srum".to_owned()))
            .count(),
        4
    );
}
#[test]
fn artifact_selection_is_explicit_in_coverage() {
    let (_temp, s) = fixture();
    let p = discovery::build_plan(vec![s], &rules(), &["windows.prefetch".into()], false).unwrap();
    assert_eq!(p.files.len(), 1);
    assert!(
        p.coverage
            .iter()
            .any(|c| c.artifact_id == "windows.recent" && c.status == "Excluded")
    );
}
#[test]
fn unknown_artifact_does_not_silently_collect_nothing() {
    let (_temp, s) = fixture();
    assert!(discovery::build_plan(vec![s], &rules(), &["does-not-exist".into()], false).is_err());
}
#[test]
fn overlapping_definitions_copy_once_with_both_origins() {
    let (_temp, s) = fixture();
    let r=Rules::load("SchemaVersion: 1\nArtifacts:\n - {Id: a, Name: A, Category: X, Patterns: ['Windows/Prefetch/**']}\n - {Id: b, Name: B, Category: X, Patterns: ['Windows/Prefetch/*.pf']}").unwrap();
    let p = discovery::build_plan(vec![s], &r, &[], false).unwrap();
    assert_eq!(p.files.len(), 1);
    assert_eq!(p.files[0].artifacts, vec!["a", "b"]);
}
#[test]
fn collect_and_verify_round_trip_preserves_source_bytes() {
    let (temp, s) = fixture();
    let p = plan(s.clone());
    let original = fs::read(&p.files[0].source_path).unwrap();
    let (root, summary) = collect::collect(&p, &temp.path().join("results"), &options()).unwrap();
    assert_eq!(summary.failed, 0);
    assert_eq!(summary.collected, 2);
    assert_eq!(verify::verify(&root).unwrap(), (2, true));
    assert_eq!(fs::read(&p.files[0].source_path).unwrap(), original);
    for r in read_records(&root) {
        assert!(r.verified);
        assert_eq!(r.status, "Acquired");
        assert_eq!(r.sha256.as_ref().unwrap().len(), 64);
    }
}
#[test]
fn payload_tampering_is_detected() {
    let (temp, s) = fixture();
    let (root, _) = collect::collect(&plan(s), &temp.path().join("results"), &options()).unwrap();
    let record = read_records(&root).remove(0);
    fs::write(root.join(record.relative_output_path.unwrap()), b"tampered").unwrap();
    assert!(verify::verify(&root).is_err());
}
#[test]
fn coverage_tampering_is_detected() {
    let (temp, s) = fixture();
    let (root, _) = collect::collect(&plan(s), &temp.path().join("results"), &options()).unwrap();
    fs::write(root.join("Coverage.csv"), b"tampered").unwrap();
    assert!(verify::verify(&root).is_err());
}
#[test]
fn absent_planned_file_does_not_become_success() {
    let (temp, s) = fixture();
    let p = plan(s);
    fs::remove_file(&p.files[0].source_path).unwrap();
    let (root, summary) = collect::collect(&p, &temp.path().join("results"), &options()).unwrap();
    assert_eq!(summary.failed, 1);
    assert_eq!(summary.completeness, "Partial");
    assert!(!verify::verify(&root).unwrap().1);
    assert!(
        read_records(&root)
            .iter()
            .any(|r| r.status == "Failed" && r.relative_output_path.is_some())
    );
}
#[test]
fn changed_source_is_flagged_instead_of_silently_accepting_old_plan() {
    let (temp, s) = fixture();
    let p = plan(s);
    fs::write(&p.files[0].source_path, b"a different length and new bytes").unwrap();
    let (_, summary) = collect::collect(&p, &temp.path().join("results"), &options()).unwrap();
    assert_eq!(summary.partial, 1);
}
#[test]
fn unavailable_memory_never_creates_a_fake_successful_dump() {
    let (temp, s) = fixture();
    let mut p = plan(s);
    p.memory_requested = true;
    let (root, summary) = collect::collect(&p, &temp.path().join("results"), &options()).unwrap();
    assert_eq!(summary.failed, 1);
    assert!(!root.join("Memory.raw").exists());
    assert!(!verify::verify(&root).unwrap().1);
}
#[test]
fn output_inside_evidence_is_rejected() {
    let (_temp, s) = fixture();
    let output = s.root.join("results");
    assert!(collect::collect(&plan(s), &output, &options()).is_err());
    assert!(!output.exists());
}
#[test]
fn impossible_space_reservation_is_rejected() {
    let (temp, s) = fixture();
    let mut o = options();
    o.reserve_bytes = u64::MAX;
    assert!(collect::collect(&plan(s), &temp.path().join("results"), &o).is_err());
}
#[test]
fn zero_length_payload_is_legitimate() {
    let (temp, s) = fixture();
    fs::write(s.root.join("Windows/Prefetch/EMPTY.pf"), []).unwrap();
    let (root, summary) =
        collect::collect(&plan(s), &temp.path().join("results"), &options()).unwrap();
    assert_eq!(summary.collected, 3);
    assert_eq!(verify::verify(&root).unwrap().0, 3);
}
#[test]
fn hashes_match_known_sha256() {
    assert_eq!(
        sha256(b"abc"),
        "ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad"
    );
}
#[test]
fn compatible_timestamp_precision_does_not_create_false_change() {
    let a = Fingerprint {
        size: 1,
        modified_ns: Some("2026-10-20T08:00:00.1234567Z".into()),
        identity: None,
        ..Default::default()
    };
    let b = Fingerprint {
        modified_ns: Some("2026-10-20T08:00:00.123456700Z".into()),
        identity: Some("ntfs:45:1".into()),
        ..a.clone()
    };
    assert!(discovery::same_version(&a, &b));
}
#[test]
fn changed_file_identity_is_not_ignored() {
    let a = Fingerprint {
        identity: Some("ntfs:45:1".into()),
        ..Default::default()
    };
    let b = Fingerprint {
        identity: Some("ntfs:45:2".into()),
        ..Default::default()
    };
    assert!(!discovery::same_version(&a, &b));
}
#[test]
fn safe_join_rejects_traversal_and_windows_prefixes() {
    let t = TempDir::new().unwrap();
    for path in ["../outside", "/etc/passwd", "C:secret", "a\\b", ""] {
        assert!(paths::safe_join(t.path(), path).is_err());
    }
}
#[test]
fn raw_reader_handles_cross_block_reads_and_exact_eof() {
    let t = TempDir::new().unwrap();
    let p = t.path().join("device");
    let data: Vec<_> = (0..65536 + 512).map(|i| (i % 251) as u8).collect();
    fs::write(&p, &data).unwrap();
    let mut r = DeviceReader::new(File::open(p).unwrap(), data.len() as u64, 512).unwrap();
    r.seek(SeekFrom::Start(65530)).unwrap();
    let mut got = Vec::new();
    r.read_to_end(&mut got).unwrap();
    assert_eq!(got, data[65530..]);
    let mut end = [0; 1];
    assert_eq!(r.read(&mut end).unwrap(), 0);
}
#[test]
fn raw_seek_cannot_overflow_or_wrap() {
    let t = TempDir::new().unwrap();
    let p = t.path().join("device");
    fs::write(&p, vec![0; 512]).unwrap();
    let mut r = DeviceReader::new(File::open(p).unwrap(), 512, 512).unwrap();
    r.seek(SeekFrom::Start(u64::MAX)).unwrap();
    assert!(r.seek(SeekFrom::Current(1)).is_err());
    r.seek(SeekFrom::Start(0)).unwrap();
    assert!(r.seek(SeekFrom::Current(i64::MIN)).is_err());
}
#[test]
fn raw_ntfs_resident_nonresident_and_sparse_payloads() {
    let mut raw = RawVolume::open(&ntfs_image()).unwrap();
    for (name, expected) in [
        ("file-with-12345", b"12345".to_vec()),
        ("1000-bytes-file", b"12345".repeat(200)),
    ] {
        let mut out = Vec::new();
        let r = raw.copy_file(Path::new(name), None, &mut out).unwrap();
        assert_eq!(out, expected);
        assert_eq!(r.bytes, out.len() as u64);
    }
    let mut out = Vec::new();
    let r = raw
        .copy_file(Path::new("sparse-file"), None, &mut out)
        .unwrap();
    assert_eq!(r.bytes, 500005);
    assert_eq!(&out[..5], b"12345");
    assert!(out[5..500000].iter().all(|&b| b == 0));
    assert_eq!(&out[500000..], b"11111");
}
#[test]
fn raw_ntfs_hidden_metadata_and_missing_stream() {
    let mut raw = RawVolume::open(&ntfs_image()).unwrap();
    let mut data = Vec::new();
    raw.copy_file(Path::new("$MFT"), None, &mut data).unwrap();
    assert_eq!(&data[..4], b"FILE");
    let error = raw
        .copy_file(Path::new("no-such-object"), None, &mut Vec::new())
        .err()
        .unwrap();
    assert!(kumade::raw::is_missing(&error));
}

#[cfg(unix)]
#[test]
fn source_symlinks_are_not_followed() {
    use std::os::unix::fs::symlink;
    let (temp, s) = fixture();
    let secret = temp.path().join("outside");
    fs::write(&secret, b"outside").unwrap();
    symlink(&secret, s.root.join("Windows/Prefetch/SECRET.pf")).unwrap();
    let p = plan(s);
    assert_eq!(p.files.len(), 2);
    assert!(p.issues.iter().any(|i| i.status == "Excluded"));
}
#[cfg(unix)]
#[test]
fn opened_source_cannot_follow_a_swapped_parent_outside_scope() {
    use std::os::unix::fs::symlink;
    let (temp, s) = fixture();
    let p = plan(s.clone());
    let target = p
        .files
        .iter()
        .find(|f| {
            f.relative_path
                .to_string_lossy()
                .ends_with("PROGRAM.EXE.pf")
        })
        .unwrap();
    let original = s.root.join("Windows/Prefetch");
    fs::rename(&original, s.root.join("Windows/OldPrefetch")).unwrap();
    let outside = temp.path().join("outside");
    fs::create_dir(&outside).unwrap();
    fs::write(outside.join("PROGRAM.EXE.pf"), b"secret").unwrap();
    symlink(outside, &original).unwrap();
    let record = collect::acquire_one(temp.path(), &s, target, 0, &mut HashMap::new());
    assert_eq!(record.status, "Failed");
    assert!(record.reason.contains("escaped"));
}
#[cfg(unix)]
#[test]
fn verifier_rejects_symlinked_payloads_outside_collection() {
    use std::os::unix::fs::symlink;
    let (temp, s) = fixture();
    let (root, _) = collect::collect(&plan(s), &temp.path().join("results"), &options()).unwrap();
    let record = read_records(&root).remove(0);
    let payload = root.join(record.relative_output_path.unwrap());
    let outside = temp.path().join("outside");
    fs::rename(&payload, &outside).unwrap();
    symlink(outside, &payload).unwrap();
    assert!(verify::verify(&root).is_err());
}

#[test]
fn buffered_copy_does_not_drop_large_payload_tails() {
    let (temp, s) = fixture();
    let input = s.root.join("Windows/Prefetch/LARGE.pf");
    let mut f = File::create(&input).unwrap();
    for _ in 0..9 {
        f.write_all(&vec![0x5a; 1024 * 1024]).unwrap();
    }
    f.write_all(b"tail").unwrap();
    drop(f);
    let expected = collect::hash_file(&input).unwrap();
    let (root, summary) =
        collect::collect(&plan(s), &temp.path().join("results"), &options()).unwrap();
    assert_eq!(summary.collected, 3);
    let record = read_records(&root)
        .into_iter()
        .find(|r| r.source_path.ends_with("LARGE.pf"))
        .unwrap();
    assert_eq!(record.bytes_read, expected.0);
    assert_eq!(record.sha256.as_ref(), Some(&expected.1));
}

#[test]
fn selected_scope_does_not_crawl_unselected_browser_directories() {
    let (_t, s) = fixture();
    let r = rules();
    assert!(!r.can_descend_selected(
        "Users/test/AppData/Local/Google/Chrome",
        Some("AppData/Local/Google/Chrome"),
        &["windows.prefetch".into()]
    ));
    assert!(r.can_descend_selected("Windows/Prefetch", None, &["windows.prefetch".into()]));
    let _ = s;
}

#[test]
fn raw_acquisition_is_used_for_hidden_metadata_candidates() {
    let (temp, mut s) = fixture();
    s.raw_device = Some(ntfs_image());
    let p = discovery::build_plan(vec![s], &rules(), &["windows.ntfs.mft".into()], false).unwrap();
    let (root, summary) = collect::collect(&p, &temp.path().join("results"), &options()).unwrap();
    assert_eq!(summary.collected, 1);
    let records = read_records(&root);
    assert_eq!(records[0].method, "RawNTFS");
    assert_eq!(verify::verify(&root).unwrap(), (1, true));
}

#[test]
fn raw_named_stream_is_acquired_without_losing_its_identity() {
    let mut raw = RawVolume::open(&ntfs_image()).unwrap();
    let mut bytes = Vec::new();
    let r = raw
        .copy_file(Path::new("$Secure"), Some("$SDS"), &mut bytes)
        .unwrap();
    assert!(r.bytes > 0);
    assert_eq!(r.bytes, bytes.len() as u64);
}

#[test]
fn live_output_can_be_on_an_acquired_volume_without_discovering_itself() {
    let (_temp, mut s) = fixture();
    s.live = true;
    let root = s.root.clone();
    let p = plan(s);
    let (out, summary) = collect::collect(&p, &root.join("Kumade-Results"), &options()).unwrap();
    assert_eq!(summary.collected, 2);
    assert_eq!(verify::verify(&out).unwrap(), (2, true));
}

#[test]
fn duplicate_source_ids_are_rejected_before_copying() {
    let (_temp, s) = fixture();
    assert!(discovery::build_plan(vec![s.clone(), s], &rules(), &[], false).is_err());
}

#[test]
fn invalid_plan_cannot_panic_on_an_unknown_source() {
    let (temp, s) = fixture();
    let mut p = plan(s);
    p.files[0].source_id = "absent".into();
    assert!(collect::collect(&p, &temp.path().join("results"), &options()).is_err());
}

#[test]
fn progress_labels_respect_cjk_width_and_remove_terminal_control_chars() {
    use unicode_width::UnicodeWidthStr;
    for width in 0..12 {
        let s = collect::clip_label("日本語の長いファイル名\n\u{1b}[31m", width);
        assert!(s.width() <= width);
        assert!(!s.chars().any(char::is_control));
    }
}

#[test]
fn acquired_coverage_is_not_left_in_planned_state() {
    let (temp, s) = fixture();
    let (root, _) = collect::collect(&plan(s), &temp.path().join("results"), &options()).unwrap();
    let data = fs::read_to_string(root.join("Coverage.csv")).unwrap();
    assert!(data.contains("Acquired"));
    let mut csv = csv::Reader::from_reader(data.as_bytes());
    let status = csv
        .headers()
        .unwrap()
        .iter()
        .position(|v| v == "Status")
        .unwrap();
    for row in csv.records() {
        assert_ne!(&row.unwrap()[status], "Planned");
    }
}

#[test]
fn sparse_output_preserves_a_zero_tail_and_logical_hash() {
    let (temp, s) = fixture();
    let p = s.root.join("Windows/Prefetch/ZERO.pf");
    File::create(&p)
        .unwrap()
        .set_len(4 * 1024 * 1024 + 31)
        .unwrap();
    let expected = collect::hash_file(&p).unwrap();
    let (root, _) = collect::collect(&plan(s), &temp.path().join("results"), &options()).unwrap();
    let r = read_records(&root)
        .into_iter()
        .find(|r| r.source_path.ends_with("ZERO.pf"))
        .unwrap();
    assert_eq!(r.bytes_read, expected.0);
    assert_eq!(r.sha256, Some(expected.1));
    assert!(verify::verify(&root).unwrap().1);
}

#[test]
fn remote_profile_paths_are_identified_before_filesystem_access() {
    for path in [
        r"\\server\share\user",
        r"\\?\UNC\server\share",
        r"\??\UNC\server\share",
    ] {
        assert!(kumade::platform::is_remote_windows_path(path), "{path}");
    }
    for path in [
        r"C:\Users\example",
        r"\\?\C:\Users\example",
        r"\\?\Volume{123}\Users\example",
    ] {
        assert!(!kumade::platform::is_remote_windows_path(path));
    }
}
