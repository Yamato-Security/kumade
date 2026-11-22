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
    catalog::Rules,
    collect::{self, Options},
    discovery,
    entropy::{self, Scope, Settings},
    model::*,
    verify,
};
use std::{
    fs,
    io::Cursor,
    path::{Path, PathBuf},
};
use tempfile::TempDir;

// Generated PE32/PE32+ fixtures contain only headers and inert section bytes; never execute them.
fn pe(executable_high: bool, resource_high: bool, plus: bool) -> Vec<u8> {
    let mut b = vec![0u8; 0x200 + 8192];
    b[..2].copy_from_slice(b"MZ");
    b[60..64].copy_from_slice(&0x80u32.to_le_bytes());
    b[0x80..0x84].copy_from_slice(b"PE\0\0");
    b[0x84..0x86].copy_from_slice(&(if plus { 0x8664u16 } else { 0x14cu16 }).to_le_bytes());
    b[0x86..0x88].copy_from_slice(&2u16.to_le_bytes());
    let optional = if plus { 240u16 } else { 224u16 };
    b[0x94..0x96].copy_from_slice(&optional.to_le_bytes());
    b[0x96..0x98].copy_from_slice(&2u16.to_le_bytes());
    b[0x98..0x9a].copy_from_slice(&(if plus { 0x20bu16 } else { 0x10bu16 }).to_le_bytes());
    for (i, (name, offset, flags)) in [
        (b".text", 0x200u32, 0x60000020u32),
        (b".rsrc", 0x1200, 0x40000040),
    ]
    .iter()
    .enumerate()
    {
        let s = 0x98 + optional as usize + i * 40;
        b[s..s + 5].copy_from_slice(*name);
        b[s + 16..s + 20].copy_from_slice(&4096u32.to_le_bytes());
        b[s + 20..s + 24].copy_from_slice(&offset.to_le_bytes());
        b[s + 36..s + 40].copy_from_slice(&flags.to_le_bytes());
    }
    for (start, high) in [(0x200, executable_high), (0x1200, resource_high)] {
        for i in 0..4096 {
            b[start + i] = if high { (i % 256) as u8 } else { 0x90 };
        }
    }
    b
}
fn analyze(bytes: &[u8], s: &Settings) -> Option<entropy::Analysis> {
    entropy::analyze(&mut Cursor::new(bytes), bytes.len() as u64, s).unwrap()
}
fn fixture() -> (TempDir, kumade::model::Plan, PathBuf) {
    let temp = TempDir::new().unwrap();
    let root = temp.path().join("source");
    fs::create_dir_all(root.join("OddLocation")).unwrap();
    fs::write(root.join("OddLocation/payload.dat"), pe(true, false, true)).unwrap();
    fs::write(
        root.join("OddLocation/resources.exe"),
        pe(false, true, false),
    )
    .unwrap();
    fs::write(root.join("text.txt"), b"not a binary").unwrap();
    let source = discovery::directory_source(&root, "C", "HOST01").unwrap();
    let rules=Rules::load("SchemaVersion: 1\nArtifacts:\n - {Id: test, Name: Test, Category: Test, Patterns: ['absent']}\n").unwrap();
    let plan = discovery::build_plan(vec![source], &rules, &[], false).unwrap();
    let output = temp.path().join("results");
    (temp, plan, output)
}
fn options() -> Options {
    Options {
        threads: 2,
        reserve_bytes: 0,
        quiet: true,
        verbose: false,
        ntfs_metadata: false,
        host_reserve: None,
        live_info: None,
    }
}
fn scan(plan: &mut Plan, output: &Path, s: &Settings) {
    entropy::augment_plan(plan, s, output, 2, true).unwrap();
}

#[test]
fn section_entropy_and_hash_are_exact_for_pe32_and_pe32_plus() {
    for plus in [false, true] {
        let b = pe(true, false, plus);
        let a = analyze(&b, &Settings::default()).unwrap();
        assert!(a.candidate);
        assert_eq!(a.max_executable_entropy, Some(8.0));
        assert_eq!(a.sections[1].entropy, 0.0);
        assert_eq!(a.sha256, sha256(&b));
        assert_eq!(a.machine, if plus { "0x8664" } else { "0x014C" });
        assert!(!a.has_certificate_table);
        assert!(!a.is_managed);
        assert_eq!(a.sections[0].measured_size, 4096);
    }
}
#[test]
fn compressed_resources_alone_are_not_default_candidates() {
    let b = pe(false, true, true);
    let a = analyze(&b, &Settings::default()).unwrap();
    assert!(!a.candidate);
    assert_eq!(a.max_executable_entropy, Some(0.0));
    assert_eq!(a.sections[1].entropy, 8.0);
    let file = Settings {
        scope: Scope::File,
        threshold: 4.0,
        ..Default::default()
    };
    assert!(analyze(&b, &file).unwrap().candidate);
    assert!(
        analyze(
            &b,
            &Settings {
                scope: Scope::Either,
                ..file
            }
        )
        .unwrap()
        .candidate
    );
}
#[test]
fn minimum_region_size_and_no_executable_sections() {
    let mut b = pe(true, false, true);
    assert!(
        !analyze(
            &b,
            &Settings {
                min_bytes: 4097,
                ..Default::default()
            }
        )
        .unwrap()
        .candidate
    );
    b[0x98 + 240 + 36..0x98 + 240 + 40].copy_from_slice(&0x40000040u32.to_le_bytes());
    let a = analyze(&b, &Settings::default()).unwrap();
    assert_eq!(a.max_executable_entropy, None);
    assert!(!a.candidate);
}
#[test]
fn malformed_and_short_headers_never_panic_or_allocate_declared_sizes() {
    let good = pe(true, false, true);
    for end in 0..512 {
        let _ = entropy::analyze(
            &mut Cursor::new(&good[..end]),
            end as u64,
            &Settings::default(),
        );
    }
    for (offset, bytes) in [
        (0x86, 97u16.to_le_bytes().to_vec()),
        (0x94, 0u16.to_le_bytes().to_vec()),
        (0x98, 0xffffu16.to_le_bytes().to_vec()),
        (0x98 + 240 + 20, u32::MAX.to_le_bytes().to_vec()),
    ] {
        let mut b = good.clone();
        b[offset..offset + bytes.len()].copy_from_slice(&bytes);
        assert!(
            entropy::analyze(&mut Cursor::new(&b), b.len() as u64, &Settings::default()).is_err()
        );
    }
    for b in [b"".as_slice(), b"MZ", b"random", b"MZ nonsense DOS stub"] {
        assert!(analyze(b, &Settings::default()).is_none());
    }
}
#[test]
fn file_size_caps_are_optional_and_do_not_reject_non_pe_media() {
    let mut b = pe(true, false, true);
    b.resize(2 * 1024 * 1024, 0);
    assert!(analyze(&b, &Settings::default()).unwrap().candidate);
    let capped = Settings {
        max_file_mib: Some(1),
        ..Default::default()
    };
    assert!(entropy::analyze(&mut Cursor::new(&b), b.len() as u64, &capped).is_err());
    b[..2].copy_from_slice(b"XX");
    assert!(analyze(&b, &capped).is_none());
}
#[test]
fn certificate_table_is_metadata_not_a_skip_or_trust_verdict() {
    let mut b = pe(true, false, true);
    b[0x98 + 108..0x98 + 112].copy_from_slice(&16u32.to_le_bytes());
    b[0x98 + 112 + 32..0x98 + 112 + 36].copy_from_slice(&0x1200u32.to_le_bytes());
    b[0x98 + 112 + 36..0x98 + 112 + 40].copy_from_slice(&100u32.to_le_bytes());
    let a = analyze(&b, &Settings::default()).unwrap();
    assert!(a.has_certificate_table && a.candidate);
}
#[test]
fn discovery_collects_renamed_pe_once_and_seals_reports() {
    let (_temp, mut plan, out) = fixture();
    assert!(plan.entropy_scan.is_none());
    assert_eq!(entropy::metadata_reserve(&plan).unwrap(), 0);
    scan(&mut plan, &out, &Settings::default());
    assert_eq!(plan.files.len(), 1);
    assert_eq!(
        plan.files[0].relative_path,
        Path::new("OddLocation/payload.dat")
    );
    assert!(plan.files[0].expected_sha256.is_some());
    let r = plan.entropy_scan.as_ref().unwrap();
    assert_eq!(r.counts.files_seen, 3);
    assert_eq!(r.counts.pe_analyzed, 2);
    assert_eq!(r.counts.non_pe, 1);
    assert!(entropy::metadata_reserve(&plan).unwrap() > 1024 * 1024);
    let (root, summary) = collect::collect(&plan, &out, &options()).unwrap();
    assert_eq!(summary.collected, 1);
    assert_eq!(verify::verify(&root).unwrap(), (1, true));
    let rows: Vec<serde_json::Value> = fs::read_to_string(root.join("HighEntropyBinaries.jsonl"))
        .unwrap()
        .lines()
        .map(|l| serde_json::from_str(l).unwrap())
        .collect();
    let selected = rows
        .iter()
        .find(|r| r["AnalysisStatus"] == "Selected")
        .unwrap();
    assert_eq!(selected["HashMatchesAnalysis"], true);
    let mut csv = csv::Reader::from_path(root.join("HighEntropyBinaries.csv")).unwrap();
    assert_eq!(csv.records().count(), 2);
    fs::write(root.join("HighEntropyBinaries.jsonl"), b"tampered").unwrap();
    assert!(verify::verify(&root).is_err());
}
#[test]
fn existing_catalog_candidate_is_deduplicated_and_not_limited() {
    let (_temp, mut plan, out) = fixture();
    let source = plan.sources[0].clone();
    let rules=Rules::load("SchemaVersion: 1\nArtifacts:\n - {Id: test, Name: Test, Category: Test, Patterns: ['OddLocation/payload.dat']}\n").unwrap();
    plan = discovery::build_plan(vec![source], &rules, &[], false).unwrap();
    scan(
        &mut plan,
        &out,
        &Settings {
            max_collect_mib: Some(1),
            ..Default::default()
        },
    );
    assert_eq!(plan.files.len(), 1);
    assert_eq!(plan.files[0].artifacts, vec!["test", entropy::ARTIFACT]);
    assert_eq!(plan.entropy_scan.as_ref().unwrap().counts.selected_new, 0);
    assert!(
        plan.entropy_scan
            .as_ref()
            .unwrap()
            .observations
            .iter()
            .any(|r| r.status == "AlreadyPlanned")
    );
}
#[test]
fn changed_bytes_are_partial_even_without_a_size_change() {
    let (_temp, mut plan, out) = fixture();
    scan(&mut plan, &out, &Settings::default());
    let mut b = fs::read(&plan.files[0].source_path).unwrap();
    b[1024] ^= 0xff;
    fs::write(&plan.files[0].source_path, b).unwrap();
    // Mimic reset timestamps in the plan: expected hash must still catch the change.
    plan.files[0].before = Some(discovery::fingerprint(
        &fs::metadata(&plan.files[0].source_path).unwrap(),
    ));
    let (root, summary) = collect::collect(&plan, &out, &options()).unwrap();
    assert_eq!(summary.partial, 1);
    assert_eq!(verify::verify(&root).unwrap(), (1, false));
    let rows: Vec<serde_json::Value> = fs::read_to_string(root.join("HighEntropyBinaries.jsonl"))
        .unwrap()
        .lines()
        .map(|l| serde_json::from_str(l).unwrap())
        .collect();
    assert!(
        rows.iter()
            .any(|r| r["HashMatchesAnalysis"] == false && r["AcquisitionStatus"] == "Partial")
    );
}
#[test]
fn candidate_limits_are_deterministic_and_report_incomplete_coverage() {
    let (_temp, mut plan, out) = fixture();
    fs::write(
        plan.sources[0].root.join("OddLocation/z.dat"),
        pe(true, false, true),
    )
    .unwrap();
    scan(
        &mut plan,
        &out,
        &Settings {
            max_candidates: Some(1),
            ..Default::default()
        },
    );
    assert_eq!(plan.files.len(), 1);
    assert_eq!(
        plan.files[0].relative_path,
        Path::new("OddLocation/payload.dat")
    );
    assert!(
        plan.coverage
            .iter()
            .any(|c| c.artifact_id == entropy::ARTIFACT && c.status == "Partial")
    );
    let (root, summary) = collect::collect(&plan, &out, &options()).unwrap();
    assert_eq!(summary.completeness, "Partial");
    assert_eq!(verify::verify(&root).unwrap(), (1, false));
}
#[test]
fn excludes_destination_and_configured_globs_without_following_links() {
    let (_temp, mut plan, _) = fixture();
    let out = plan.sources[0].root.join("results");
    fs::create_dir_all(&out).unwrap();
    fs::write(out.join("old.exe"), pe(true, false, true)).unwrap();
    scan(
        &mut plan,
        &out,
        &Settings {
            excludes: vec!["oddlocation/**".into()],
            ..Default::default()
        },
    );
    assert!(plan.files.is_empty());
    assert!(plan.entropy_scan.as_ref().unwrap().counts.skipped >= 2);
}
#[cfg(unix)]
#[test]
fn symlink_targets_outside_the_source_are_not_read_or_copied() {
    let (temp, mut plan, out) = fixture();
    fs::write(temp.path().join("outside.exe"), pe(true, false, true)).unwrap();
    std::os::unix::fs::symlink(
        temp.path().join("outside.exe"),
        plan.sources[0].root.join("linked.exe"),
    )
    .unwrap();
    scan(&mut plan, &out, &Settings::default());
    assert_eq!(plan.files.len(), 1);
    assert!(
        plan.entropy_scan
            .as_ref()
            .unwrap()
            .observations
            .iter()
            .any(|r| r.relative_path == "linked.exe" && r.status == "Excluded")
    );
}
#[test]
fn invalid_settings_are_rejected_before_walking() {
    let (_temp, mut plan, out) = fixture();
    for s in [
        Settings {
            threshold: f64::NAN,
            ..Default::default()
        },
        Settings {
            min_bytes: 0,
            ..Default::default()
        },
        Settings {
            max_file_mib: Some(u64::MAX),
            ..Default::default()
        },
    ] {
        assert!(entropy::augment_plan(&mut plan, &s, &out, 2, true).is_err());
    }
}
#[test]
fn raw_ntfs_inspection_is_seekable_and_returns_identity() {
    let path = Path::new(env!("CARGO_MANIFEST_DIR")).join("tests/fixtures/ntfs-testfs1.img");
    let mut volume = kumade::raw::RawVolume::open(&path).unwrap();
    // SDK fixture has a resident UTF-8 test file and a non-resident 40-KiB file.
    for name in ["file-with-12345", "1000-bytes-file", "sparse-file"] {
        if let Ok((bytes, before, after)) = volume.inspect_file(Path::new(name), |r, size| {
            let mut b = Vec::new();
            r.read_to_end(&mut b)?;
            assert_eq!(b.len() as u64, size);
            Ok(b)
        }) {
            assert!(!bytes.is_empty());
            assert!(discovery::same_version(&before, &after));
        } else {
            panic!("Expected raw fixture file {name}");
        }
    }
}
#[test]
fn old_plans_deserialize_without_new_optional_fields() {
    let (_temp, plan, _) = fixture();
    let value = serde_json::to_value(&plan).unwrap();
    assert!(value.get("entropy_scan").is_none());
    let restored: Plan = serde_json::from_value(value).unwrap();
    assert!(restored.entropy_scan.is_none());
}

#[test]
fn size_limit_is_a_visible_skip_and_marks_scope_partial() {
    let (_temp, mut plan, out) = fixture();
    let mut large = pe(true, false, true);
    large.resize(2 * 1024 * 1024, 0);
    fs::write(plan.sources[0].root.join("large.exe"), large).unwrap();
    scan(
        &mut plan,
        &out,
        &Settings {
            max_file_mib: Some(1),
            ..Default::default()
        },
    );
    let r = plan.entropy_scan.as_ref().unwrap();
    assert_eq!(r.counts.skipped, 1);
    assert_eq!(r.counts.errors, 0);
    assert!(
        r.observations
            .iter()
            .any(|o| o.status == "SizeLimit" && o.relative_path == "large.exe")
    );
    assert!(
        plan.coverage
            .iter()
            .any(|c| c.artifact_id == entropy::ARTIFACT && c.status == "Partial")
    );
}
#[test]
fn total_collection_cap_does_not_silently_discard_candidates() {
    let (_temp, mut plan, out) = fixture();
    let mut large = pe(true, false, true);
    large.resize(2 * 1024 * 1024, 0);
    fs::write(plan.sources[0].root.join("large.exe"), large).unwrap();
    scan(
        &mut plan,
        &out,
        &Settings {
            max_collect_mib: Some(1),
            ..Default::default()
        },
    );
    assert_eq!(plan.files.len(), 1);
    let r = plan.entropy_scan.as_ref().unwrap();
    assert_eq!(r.counts.candidates, 2);
    assert!(
        r.observations
            .iter()
            .any(|o| o.status == "SelectionLimit" && o.relative_path == "large.exe")
    );
}

#[test]
fn only_listed_extensions_are_opened_unless_asked_otherwise() {
    let (_temp, plan, out) = fixture();
    let root = plan.sources[0].root.clone();
    // The same high-entropy PE under names outside the list is never opened by default,
    // while the comparison of listed names ignores case.
    fs::write(root.join("OddLocation/table.toc"), pe(true, false, true)).unwrap();
    fs::write(root.join("OddLocation/kernel"), pe(true, false, true)).unwrap();
    fs::write(root.join("OddLocation/UPPER.EXE"), pe(true, false, true)).unwrap();
    let rules=Rules::load("SchemaVersion: 1\nArtifacts:\n - {Id: test, Name: Test, Category: Test, Patterns: ['absent']}\n").unwrap();
    let fresh =
        || discovery::build_plan(vec![plan.sources[0].clone()], &rules, &[], false).unwrap();
    let mut p = fresh();
    scan(&mut p, &out, &Settings::default());
    let c = &p.entropy_scan.as_ref().unwrap().counts;
    assert_eq!(
        (c.files_seen, c.other_extension, c.pe_analyzed, c.non_pe),
        (6, 2, 3, 1)
    );
    assert_eq!(p.files.len(), 2);
    assert!(
        p.entropy_scan
            .as_ref()
            .unwrap()
            .observations
            .iter()
            .all(|o| !o.relative_path.ends_with(".toc") && o.relative_path != "OddLocation/kernel")
    );
    let mut p = fresh();
    scan(
        &mut p,
        &out,
        &Settings {
            extensions: vec!["toc".into()],
            ..Default::default()
        },
    );
    assert_eq!(p.entropy_scan.as_ref().unwrap().counts.pe_analyzed, 4);
    assert_eq!(p.files.len(), 3);
    let mut p = fresh();
    scan(
        &mut p,
        &out,
        &Settings {
            all_files: true,
            ..Default::default()
        },
    );
    let c = &p.entropy_scan.as_ref().unwrap().counts;
    assert_eq!((c.other_extension, c.pe_analyzed), (0, 5));
    assert_eq!(p.files.len(), 4);
    assert!(entropy::DEFAULT_EXTENSIONS.contains(&"appref-ms"));
    assert!(!entropy::DEFAULT_EXTENSIONS.contains(&"toc"));
    assert_eq!(entropy::DEFAULT_EXTENSIONS.len(), 228);
}

#[test]
fn non_image_pe_counts_as_non_pe_and_malformed_pe_is_not_a_failure() {
    // Without IMAGE_FILE_EXECUTABLE_IMAGE the file is a PE-format container, such as a .NET
    // Native TOC table, and the heuristic has nothing to score.
    let mut container = pe(true, false, true);
    container[0x96..0x98].copy_from_slice(&0u16.to_le_bytes());
    assert!(analyze(&container, &Settings::default()).is_none());
    // A section pointing past EOF is malformed: its own row and counter, no plan issue, and
    // the run stays complete.
    let (_temp, mut plan, out) = fixture();
    let mut truncated = pe(true, false, true);
    truncated[0x98 + 240 + 20..0x98 + 240 + 24].copy_from_slice(&u32::MAX.to_le_bytes());
    fs::write(
        plan.sources[0].root.join("OddLocation/broken.exe"),
        truncated,
    )
    .unwrap();
    fs::write(
        plan.sources[0].root.join("OddLocation/table.dat"),
        container,
    )
    .unwrap();
    scan(&mut plan, &out, &Settings::default());
    let r = plan.entropy_scan.as_ref().unwrap();
    assert_eq!(
        (
            r.counts.malformed,
            r.counts.errors,
            r.counts.non_pe,
            r.counts.pe_analyzed
        ),
        (1, 0, 2, 2)
    );
    let row = r
        .observations
        .iter()
        .find(|o| o.relative_path == "OddLocation/broken.exe")
        .unwrap();
    assert_eq!(row.status, "Malformed");
    assert!(row.reason.contains("out of bounds"));
    assert!(
        plan.issues
            .iter()
            .all(|i| !i.reason.starts_with("Entropy scan"))
    );
    assert!(
        plan.coverage
            .iter()
            .any(|c| c.artifact_id == entropy::ARTIFACT && c.status == "Discovered")
    );
    let (root, summary) = collect::collect(&plan, &out, &options()).unwrap();
    assert_eq!(summary.discovery_errors, 0);
    assert_eq!(summary.completeness, "CompleteWithinSelectedPrototypeScope");
    assert_eq!(verify::verify(&root).unwrap(), (1, true));
    let rows: Vec<serde_json::Value> = fs::read_to_string(root.join("HighEntropyBinaries.jsonl"))
        .unwrap()
        .lines()
        .map(|l| serde_json::from_str(l).unwrap())
        .collect();
    assert!(rows.iter().any(
        |r| r["AnalysisStatus"] == "Malformed" && r["RelativePath"] == "OddLocation/broken.exe"
    ));
}

#[test]
fn plan_json_omits_the_inventory_and_plan_mode_writes_the_reports() {
    let (temp, mut plan, out) = fixture();
    scan(&mut plan, &out, &Settings::default());
    let value = serde_json::to_value(&plan).unwrap();
    let report = &value["EntropyScan"];
    assert!(report.is_object(), "{value}");
    assert!(report.get("Observations").is_none(), "{report}");
    assert_eq!(report["Counts"]["PeAnalyzed"], 2);
    assert_eq!(report["Settings"]["AllFiles"], false);
    // Plan mode through the binary: Plan.json plus the three report files, no collection.
    let plan_dir = temp.path().join("plan-only");
    let status = std::process::Command::new(env!("CARGO_BIN_EXE_kumade"))
        .args(["plan", "-d"])
        .arg(&plan.sources[0].root)
        .args(["--computer", "HOST01", "--high-entropy", "-q", "-o"])
        .arg(&plan_dir)
        .status()
        .unwrap();
    assert!(status.success());
    for name in entropy::FILES {
        assert!(plan_dir.join(name).is_file(), "{name}");
    }
    assert!(plan_dir.join("Plan.json").is_file());
    assert!(!plan_dir.join("Manifest.jsonl").exists());
    let mut csv = csv::Reader::from_path(plan_dir.join("HighEntropyBinaries.csv")).unwrap();
    assert_eq!(csv.records().count(), 2);
    let saved: serde_json::Value =
        serde_json::from_reader(fs::File::open(plan_dir.join("Plan.json")).unwrap()).unwrap();
    assert!(saved["EntropyScan"].is_object() && saved["EntropyScan"].get("Observations").is_none());
    assert!(
        saved["Files"]
            .as_array()
            .unwrap()
            .iter()
            .any(|f| f["ExpectedSHA256"].is_string())
    );
}

/// A PE32 assembly: data directory 14 points at a CLR header at the start of `.text`
/// (RVA 0x1000, file 0x200) whose managed resources cover `resources_len` bytes from
/// RVA 0x1100. The rest of `.text` keeps the high-entropy pattern of `pe()`.
fn managed_pe(resources_len: u32) -> Vec<u8> {
    let mut b = pe(true, false, false);
    let optional = 0x98;
    b[optional + 92..optional + 96].copy_from_slice(&16u32.to_le_bytes());
    b[optional + 96 + 112..optional + 96 + 116].copy_from_slice(&0x1000u32.to_le_bytes());
    b[optional + 96 + 116..optional + 96 + 120].copy_from_slice(&72u32.to_le_bytes());
    for (i, va) in [0x1000u32, 0x2000].into_iter().enumerate() {
        let s = 0x98 + 224 + i * 40;
        b[s + 8..s + 12].copy_from_slice(&4096u32.to_le_bytes());
        b[s + 12..s + 16].copy_from_slice(&va.to_le_bytes());
    }
    b[0x200..0x204].copy_from_slice(&72u32.to_le_bytes());
    b[0x210..0x214].copy_from_slice(&1u32.to_le_bytes());
    b[0x218..0x21c].copy_from_slice(&0x1100u32.to_le_bytes());
    b[0x21c..0x220].copy_from_slice(&resources_len.to_le_bytes());
    b
}

#[test]
fn managed_resources_are_left_out_of_the_executable_section_measurement() {
    let settings = Settings {
        min_bytes: 1024,
        ..Default::default()
    };
    // Satellite assembly: everything after the CLR header is compressed resources. Only the
    // 256 header bytes remain, below the minimum, so the file is no longer a candidate.
    let satellite = analyze(&managed_pe(4096 - 0x100), &settings).unwrap();
    assert!(satellite.is_managed);
    assert_eq!(satellite.sections[0].raw_size, 4096);
    assert_eq!(satellite.sections[0].measured_size, 0x100);
    assert_eq!(satellite.max_executable_entropy, None);
    assert!(!satellite.candidate);
    // Whole-file entropy still counts the resources: with the uniform resource bytes, the
    // constant `.rsrc` section and the headers it lands well above the low-entropy sections.
    assert!(satellite.file_entropy > 4.0 && satellite.file_entropy < 7.0);
    // A crypted assembly: the IL region itself is high entropy and stays a candidate.
    let crypted = analyze(&managed_pe(512), &settings).unwrap();
    assert!(crypted.is_managed);
    assert_eq!(crypted.sections[0].measured_size, 4096 - 512);
    assert!(crypted.max_executable_entropy.unwrap() > 7.9);
    assert!(crypted.candidate);
    // No resources at all: measured like a native image.
    let plain = analyze(&managed_pe(0), &settings).unwrap();
    assert!(plain.is_managed && plain.candidate);
    assert_eq!(plain.sections[0].measured_size, 4096);
    // Exported through the scan: the column and the per-section measured size are visible.
    let (_temp, mut plan, out) = fixture();
    fs::write(
        plan.sources[0]
            .root
            .join("OddLocation/strings.resources.dll"),
        managed_pe(4096 - 0x100),
    )
    .unwrap();
    scan(&mut plan, &out, &settings);
    assert_eq!(
        plan.files.len(),
        1,
        "the satellite assembly is not selected"
    );
    let (root, _) = collect::collect(&plan, &out, &options()).unwrap();
    let rows: Vec<serde_json::Value> = fs::read_to_string(root.join("HighEntropyBinaries.jsonl"))
        .unwrap()
        .lines()
        .map(|l| serde_json::from_str(l).unwrap())
        .collect();
    let row = rows
        .iter()
        .find(|r| r["RelativePath"] == "OddLocation/strings.resources.dll")
        .unwrap();
    assert_eq!(row["AnalysisStatus"], "BelowThreshold");
    assert_eq!(row["IsManaged"], true);
    let sections: serde_json::Value =
        serde_json::from_str(row["Sections"].as_str().unwrap()).unwrap();
    assert_eq!(sections[0]["MeasuredSize"], 0x100);
    assert_eq!(rows.iter().filter(|r| r["IsManaged"] == false).count(), 2);
}
