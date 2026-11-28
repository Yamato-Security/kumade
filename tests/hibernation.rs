// Copyright (C) 2026 Shirofune Security Co., Ltd.
// SPDX-License-Identifier: RPL-1.5
//! Hibernation acquisition and selection regressions; payloads are synthetic bytes.
use kumade::{
    catalog::{DEFAULT_CATALOG, Rules},
    discovery,
    model::{Plan, Record},
    ordering,
    wizard::{self, Choices, Output, Prompt, Sizes},
};
use std::{
    fs,
    io::{Cursor, Write},
    path::{Path, PathBuf},
    process::{Command, Stdio},
};

fn fixture() -> (tempfile::TempDir, PathBuf) {
    let temp = tempfile::tempdir().unwrap();
    let source = temp.path().join("source");
    fs::create_dir_all(source.join("Windows/Prefetch")).unwrap();
    fs::write(source.join("Windows/Prefetch/ONE.pf"), b"prefetch").unwrap();
    fs::write(source.join("hiberfil.sys"), b"saved hibernation bytes").unwrap();
    fs::write(source.join("pagefile.sys"), b"pagefile").unwrap();
    fs::write(source.join("swapfile.sys"), b"swapfile").unwrap();
    fs::write(source.join("Windows/MEMORY.DMP"), b"existing crash dump").unwrap();
    (temp, source)
}

fn invoke(
    temp: &Path,
    source: &Path,
    action: &str,
    args: &[&str],
    answers: Option<&str>,
) -> std::process::Output {
    let mut command = Command::new(env!("CARGO_BIN_EXE_kumade"));
    command
        .current_dir(temp)
        .arg(action)
        .arg("-d")
        .arg(source)
        .arg("-o")
        .arg(temp.join("results"))
        .args(["--reserve-mib", "0", "--computer", "HIBERNATION-TEST"])
        .args(args)
        .stdout(Stdio::piped())
        .stderr(Stdio::piped());
    command.stdin(if answers.is_some() {
        Stdio::piped()
    } else {
        Stdio::null()
    });
    let mut child = command.spawn().unwrap();
    if let Some(answers) = answers {
        child
            .stdin
            .take()
            .unwrap()
            .write_all(answers.as_bytes())
            .unwrap();
    }
    child.wait_with_output().unwrap()
}

fn read_plan(temp: &Path) -> Plan {
    serde_json::from_slice(&fs::read(temp.join("results/Plan.json")).unwrap()).unwrap()
}

fn records(temp: &Path) -> (PathBuf, Vec<Record>) {
    let root = fs::read_dir(temp.join("results"))
        .unwrap()
        .next()
        .unwrap()
        .unwrap()
        .path();
    let rows = fs::read_to_string(root.join("Manifest.jsonl"))
        .unwrap()
        .lines()
        .map(|line| serde_json::from_str(line).unwrap())
        .collect();
    (root, rows)
}

#[test]
fn defaults_do_not_collect_hibernation_and_paging_keeps_its_existing_scope() {
    let rules = Rules::load(DEFAULT_CATALOG).unwrap();
    let defaults = wizard::default_artifacts(&rules, &[], false);
    assert!(
        !defaults
            .iter()
            .any(|id| matches!(id.as_str(), "windows.hibernation" | "windows.paging"))
    );
    let paging = wizard::default_artifacts(&rules, &[], true);
    assert!(paging.iter().any(|id| id == "windows.paging"));
    // --paging still matches hiberfil.sys through the original broad family.
    let (temp, source) = fixture();
    let out = invoke(temp.path(), &source, "collect-test", &["--paging"], None);
    assert!(
        out.status.success(),
        "{}",
        String::from_utf8_lossy(&out.stderr)
    );
    let plan = read_plan(temp.path());
    for path in ["hiberfil.sys", "pagefile.sys", "swapfile.sys"] {
        assert_eq!(
            plan.files
                .iter()
                .filter(|f| f.relative_path == Path::new(path))
                .count(),
            1,
            "{path}"
        );
    }
}

#[test]
fn hibernation_flag_adds_only_hiberfil_to_an_explicit_scope_and_sizes_it() {
    let (temp, source) = fixture();
    let out = invoke(
        temp.path(),
        &source,
        "collect-test",
        &["--artifact", "windows.prefetch", "--hibernation"],
        None,
    );
    assert!(
        out.status.success(),
        "{}",
        String::from_utf8_lossy(&out.stderr)
    );
    let plan = read_plan(temp.path());
    assert_eq!(plan.files.len(), 2);
    let hiber = plan
        .files
        .iter()
        .find(|f| f.relative_path == Path::new("hiberfil.sys"))
        .unwrap();
    assert_eq!(hiber.artifacts, ["windows.hibernation"]);
    assert_eq!(ordering::disk_priority(hiber), 9);
    let ids = ["windows.hibernation".to_owned()].into_iter().collect();
    let size = Sizes::discover(&plan).selected(&plan, &ids).unwrap();
    assert_eq!(size.bytes, b"saved hibernation bytes".len() as u64);
    assert_eq!(size.files, 1);
}

#[test]
fn hibernation_flag_also_augments_the_normal_default_scope() {
    let (temp, source) = fixture();
    let out = invoke(
        temp.path(),
        &source,
        "collect-test",
        &["--hibernation"],
        None,
    );
    assert!(
        out.status.success(),
        "{}",
        String::from_utf8_lossy(&out.stderr)
    );
    let plan = read_plan(temp.path());
    assert!(
        plan.files
            .iter()
            .any(|f| f.relative_path == Path::new("hiberfil.sys"))
    );
    assert!(
        plan.files
            .iter()
            .any(|f| f.relative_path.ends_with("ONE.pf"))
    );
    assert!(!plan.files.iter().any(|f| matches!(
        f.relative_path.to_str(),
        Some("pagefile.sys" | "swapfile.sys" | "Windows/MEMORY.DMP")
    )));
}

#[test]
fn broad_paging_and_hibernation_capture_one_verified_copy() {
    let (temp, source) = fixture();
    let bytes: Vec<u8> = (0..131_089).map(|i| (i % 251) as u8).collect();
    fs::write(source.join("hiberfil.sys"), &bytes).unwrap();
    let out = invoke(
        temp.path(),
        &source,
        "collect",
        &[
            "--no-wizard",
            "--artifact",
            "windows.hibernation",
            "--hibernation",
            "--paging",
        ],
        None,
    );
    assert!(
        out.status.success(),
        "{}",
        String::from_utf8_lossy(&out.stderr)
    );
    let (root, rows) = records(temp.path());
    let hiber: Vec<_> = rows
        .iter()
        .filter(|r| r.source_path.ends_with("hiberfil.sys"))
        .collect();
    assert_eq!(hiber.len(), 1);
    let record = hiber[0];
    assert_eq!(record.status, "Acquired");
    assert!(record.verified);
    assert_eq!(record.bytes_read, bytes.len() as u64);
    assert_eq!(
        record.sha256.as_deref(),
        Some(kumade::model::sha256(&bytes).as_str())
    );
    assert_eq!(
        fs::read(root.join(record.relative_output_path.as_ref().unwrap())).unwrap(),
        bytes
    );
    assert!(
        record
            .artifact_ids
            .split(';')
            .any(|id| id == "windows.hibernation")
    );
    assert!(
        record
            .artifact_ids
            .split(';')
            .any(|id| id == "windows.paging")
    );
    assert_eq!(kumade::verify::verify(&root).unwrap(), (4, true));
}

#[test]
fn case_insensitive_hiberfil_name_is_acquired_without_paging_files() {
    let (temp, source) = fixture();
    fs::rename(source.join("hiberfil.sys"), source.join("HIBERFIL.SYS")).unwrap();
    let out = invoke(
        temp.path(),
        &source,
        "collect",
        &["--no-wizard", "--artifact", "windows.hibernation"],
        None,
    );
    assert!(
        out.status.success(),
        "{}",
        String::from_utf8_lossy(&out.stderr)
    );
    let (root, rows) = records(temp.path());
    assert_eq!(rows.len(), 1);
    assert!(rows[0].source_path.ends_with("HIBERFIL.SYS"));
    assert_eq!(kumade::verify::verify(&root).unwrap(), (1, true));
}

#[test]
fn missing_hiberfil_is_not_fabricated_or_reported_as_acquired() {
    let (temp, source) = fixture();
    fs::remove_file(source.join("hiberfil.sys")).unwrap();
    let out = invoke(
        temp.path(),
        &source,
        "collect",
        &["--no-wizard", "--artifact", "windows.hibernation"],
        None,
    );
    assert!(
        out.status.success(),
        "{}",
        String::from_utf8_lossy(&out.stderr)
    );
    let (root, rows) = records(temp.path());
    assert!(rows.iter().all(|r| r.status != "Acquired"));
    let mut coverage = csv::Reader::from_path(root.join("Coverage.csv")).unwrap();
    let headers = coverage.headers().unwrap().clone();
    let status = headers.iter().position(|v| v == "Status").unwrap();
    let artifact = headers.iter().position(|v| v == "ArtifactId").unwrap();
    let row = coverage
        .records()
        .map(Result::unwrap)
        .find(|r| &r[artifact] == "windows.hibernation")
        .unwrap();
    assert_eq!(&row[status], "NotPresent");
}

#[test]
fn flag_rejects_a_custom_catalog_that_cannot_supply_the_requested_family() {
    let (temp, source) = fixture();
    fs::write(temp.path().join("custom.yaml"), "SchemaVersion: 1\nArtifacts:\n - {Id: custom.file, Name: Custom, Category: Test, Patterns: ['pagefile.sys']}\n").unwrap();
    let out = invoke(
        temp.path(),
        &source,
        "collect-test",
        &["--hibernation", "--catalog", "custom.yaml"],
        None,
    );
    assert!(!out.status.success());
    assert!(
        String::from_utf8_lossy(&out.stderr)
            .contains("--hibernation requires the windows.hibernation family")
    );
    assert!(!temp.path().join("results").exists());
}

#[test]
fn explicit_wizard_scope_has_a_separate_hibernation_prompt_and_accurate_estimate() {
    let (temp, source) = fixture();
    let out = invoke(
        temp.path(),
        &source,
        "collect",
        &["--artifact", "windows.prefetch", "--hibernation"],
        Some(&"\n".repeat(20)),
    );
    assert!(
        out.status.success(),
        "{}",
        String::from_utf8_lossy(&out.stderr)
    );
    let text = String::from_utf8_lossy(&out.stdout);
    assert!(
        text.contains("Hibernation file only (hiberfil.sys) (23B; 1 files/streams) (Y/n)"),
        "{text}"
    );
    assert!(
        text.contains("Estimated transfer: 31B / 2 files/streams"),
        "{text}"
    );
    assert!(
        !text.contains("Paging, swap, hibernation and existing memory dumps ("),
        "{text}"
    );
    assert_eq!(records(temp.path()).1.len(), 2);
}

#[test]
fn wizard_can_choose_hibernation_without_the_broad_paging_group() {
    let (temp, root) = fixture();
    let rules = Rules::load("SchemaVersion: 1\nArtifacts:\n - {Id: windows.hibernation, Name: Hibernation, Category: Memory, Patterns: ['hiberfil.sys']}\n - {Id: windows.paging, Name: Paging, Category: Memory, Patterns: ['pagefile.sys', 'hiberfil.sys']}\n").unwrap();
    let source = discovery::directory_source(&root, "C", "HIBERNATION-TEST").unwrap();
    let plan = discovery::build_plan(vec![source], &rules, &[], false).unwrap();
    let sizes = Sizes::discover(&plan);
    let choices = Choices {
        memory: false,
        memory_bytes: None,
        artifacts: vec![],
        restrict_artifacts: false,
        local_yara: false,
        vss_available: false,
        yara_available: false,
        live_info: false,
        vss: false,
        entropy: false,
        yara: false,
        yara_ruleset: kumade::yara_scan::RuleSet::Core,
        output: Output::Directory,
        output_explicit: true,
        threads: 2,
        image_source: None,
    };
    // Hibernation yes, broad paging no, entropy no, workers default, start yes.
    let mut io = Prompt::new(Cursor::new(b"y\nn\nn\n\n\n"), Vec::new());
    let selected = wizard::run(&mut io, &plan, &rules, &sizes, choices, false, false).unwrap();
    assert_eq!(selected.artifacts, ["windows.hibernation"]);
    drop(temp);
}

#[test]
fn raw_ntfs_hibernation_fallback_preserves_nonresident_bytes_without_native_access() {
    let temp = tempfile::tempdir().unwrap();
    let image = temp.path().join("source.img");
    let compressed = include_bytes!("fixtures/hibernation-ntfs.img.gz");
    let mut decoder = flate2::read::GzDecoder::new(&compressed[..]);
    let mut file = fs::File::create(&image).unwrap();
    std::io::copy(&mut decoder, &mut file).unwrap();
    drop(file);
    let root = temp.path().join("native-view-unavailable");
    fs::create_dir(&root).unwrap();
    let mut source = discovery::directory_source(&root, "C", "HIBERNATION-RAW").unwrap();
    source.raw_device = Some(image);
    let plan = discovery::build_plan(
        vec![source],
        &Rules::load(DEFAULT_CATALOG).unwrap(),
        &["windows.hibernation".into()],
        false,
    )
    .unwrap();
    assert_eq!(plan.files.len(), 1);
    assert!(!root.join("hiberfil.sys").exists());
    let options = kumade::collect::Options {
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
    let (output, summary) =
        kumade::collect::collect(&plan, &temp.path().join("results"), &options).unwrap();
    assert_eq!(summary.collected, 1);
    assert_eq!(summary.failed, 0);
    assert_eq!(summary.metadata_errors, 0);
    let record: Record = serde_json::from_str(
        fs::read_to_string(output.join("Manifest.jsonl"))
            .unwrap()
            .lines()
            .next()
            .unwrap(),
    )
    .unwrap();
    assert_eq!(record.method, "RawNTFS");
    assert!(record.verified);
    let bytes: Vec<u8> = (0..131_089).map(|i| (i % 251) as u8).collect();
    assert_eq!(
        record.sha256.as_deref(),
        Some(kumade::model::sha256(&bytes).as_str())
    );
    assert_eq!(
        fs::read(output.join(record.relative_output_path.as_ref().unwrap())).unwrap(),
        bytes
    );
    assert_eq!(kumade::verify::verify(&output).unwrap(), (1, true));
}
