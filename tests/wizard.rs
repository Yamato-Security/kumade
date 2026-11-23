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
    discovery,
    model::*,
    wizard::{self, Choices, Output, Prompt, Sizes},
};
use std::{
    fs,
    io::{Cursor, Write},
    path::{Path, PathBuf},
    process::{Command, Stdio},
};
fn rules() -> Rules {
    Rules::load("SchemaVersion: 1\nArtifacts:\n - {Id: windows.prefetch, Name: Prefetch, Category: Core, Patterns: ['Windows/Prefetch/*']}\n - {Id: windows.paging, Name: Paging, Category: Memory, Patterns: ['pagefile.sys']}\n").unwrap()
}
fn fixture() -> (tempfile::TempDir, Plan, Rules) {
    let t = tempfile::tempdir().unwrap();
    let root = t.path().join("source");
    fs::create_dir_all(root.join("Windows/Prefetch")).unwrap();
    fs::write(root.join("Windows/Prefetch/ONE.pf"), b"evidence").unwrap();
    fs::write(root.join("pagefile.sys"), b"paging").unwrap();
    let source = discovery::directory_source(&root, "C", "HOST").unwrap();
    let r = rules();
    let p = discovery::build_plan(vec![source], &r, &[], false).unwrap();
    (t, p, r)
}
fn choices() -> Choices {
    Choices {
        artifacts: vec!["windows.prefetch".into()],
        restrict_artifacts: false,
        local_yara: false,
        vss_available: true,
        yara_available: true,
        live_info: true,
        vss: false,
        entropy: false,
        yara: false,
        yara_ruleset: kumade::yara_scan::RuleSet::Core,
        output: Output::Directory,
        output_explicit: false,
        threads: 4,
        image_source: None,
    }
}
#[test]
fn yes_no_defaults_reprompt_and_eof_are_safe() {
    let mut p = Prompt::new(Cursor::new(b"maybe\nYES\n\nn\n"), Vec::new());
    assert!(p.yes("one", false).unwrap());
    assert!(p.yes("two", true).unwrap());
    assert!(!p.yes("three", true).unwrap());
    assert!(p.yes("EOF", true).is_err());
    let mut q = Prompt::new(Cursor::new(b"q\n"), Vec::new());
    assert!(q.yes("cancel", true).is_err());
}
#[test]
fn default_selection_excludes_paging_but_honors_explicit_selection() {
    let r = rules();
    assert_eq!(
        wizard::default_artifacts(&r, &[], false),
        vec!["windows.prefetch"]
    );
    assert_eq!(wizard::default_artifacts(&r, &[], true).len(), 2);
    assert_eq!(
        wizard::default_artifacts(&r, &["windows.paging".into()], false),
        vec!["windows.paging"]
    );
}
#[test]
fn estimates_count_shared_files_once_and_keep_unknown_sizes_visible() {
    let (_t, mut p, _r) = fixture();
    p.files[0].artifacts.push("also".into());
    let ids = ["windows.prefetch".into(), "also".into()]
        .into_iter()
        .collect();
    let sizes = Sizes::discover(&p);
    let e = sizes.selected(&p, &ids).unwrap();
    assert_eq!(e.bytes, 8);
    assert_eq!(e.files, 1);
    p.files[0].before = None;
    let e = Sizes::discover(&p).selected(&p, &ids).unwrap();
    assert_eq!(e.unknown, 1);
    assert!(e.label().contains("unknown-size"));
}
#[test]
fn accepting_defaults_keeps_heavy_work_off() {
    let (_t, p, r) = fixture();
    let sizes = Sizes::discover(&p);
    let mut io = Prompt::new(Cursor::new(b"\n\n\n\n\n"), Vec::new());
    let c = wizard::run(&mut io, &p, &r, &sizes, choices(), false, false).unwrap();
    assert_eq!(c.artifacts, vec!["windows.prefetch"]);
    assert!(!c.vss && !c.entropy && !c.yara && !c.live_info);
    assert_eq!(c.output, Output::Directory);
}
#[test]
fn selecting_nothing_never_means_collect_everything() {
    let (_t, p, r) = fixture();
    let sizes = Sizes::discover(&p);
    let mut io = Prompt::new(Cursor::new(b"n\nn\nn\n\n"), Vec::new());
    assert!(wizard::run(&mut io, &p, &r, &sizes, choices(), false, false).is_err());
    let p = wizard::build_plan(p.sources, &r, &[], false).unwrap();
    assert!(p.files.is_empty());
    assert!(p.coverage.iter().all(|r| r.status == "Excluded"));
}
#[test]
fn explicit_artifact_scope_is_not_expanded_to_other_category_members() {
    let (_t, p, r) = fixture();
    let sizes = Sizes::discover(&p);
    let mut c = choices();
    c.restrict_artifacts = true;
    let mut io = Prompt::new(Cursor::new(b"\n\n\n\n"), Vec::new());
    let c = wizard::run(&mut io, &p, &r, &sizes, c, false, false).unwrap();
    assert_eq!(c.artifacts, vec!["windows.prefetch"]);
}
#[test]
fn image_selection_stays_separate_from_artifact_collection() {
    let (_t, p, r) = fixture();
    let sizes = Sizes::discover(&p);
    let mut c = choices();
    c.artifacts = vec!["windows.prefetch".into()];
    let mut io = Prompt::new(Cursor::new(b"y\n\n\n\n"), Vec::new());
    let c = wizard::run(&mut io, &p, &r, &sizes, c, true, true).unwrap();
    assert_eq!(c.image_source, Some(0));
    assert!(!c.vss);
}
fn cli(t: &Path, args: &[&str], answers: &str) -> std::process::Output {
    let source = t.join("source");
    let output = t.join("results");
    let catalog = t.join("catalog.yaml");
    fs::write(&catalog,"SchemaVersion: 1\nArtifacts:\n - {Id: windows.prefetch, Name: Prefetch, Category: Core, Patterns: ['Windows/Prefetch/*']}\n - {Id: windows.paging, Name: Paging, Category: Memory, Patterns: ['pagefile.sys']}\n").unwrap();
    let mut cmd = Command::new(env!("CARGO_BIN_EXE_kumade"));
    cmd.arg("collect")
        .arg("-d")
        .arg(source)
        .arg("-o")
        .arg(output)
        .arg("--catalog")
        .arg(catalog)
        .args(["--reserve-mib", "0"])
        .args(args);
    cmd.stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped());
    let mut child = cmd.spawn().unwrap();
    child
        .stdin
        .take()
        .unwrap()
        .write_all(answers.as_bytes())
        .unwrap();
    child.wait_with_output().unwrap()
}
fn manifest(t: &Path) -> Vec<Record> {
    let root = fs::read_dir(t.join("results"))
        .unwrap()
        .next()
        .unwrap()
        .unwrap()
        .path();
    fs::read_to_string(root.join("Manifest.jsonl"))
        .unwrap()
        .lines()
        .map(|r| serde_json::from_str(r).unwrap())
        .collect()
}
#[test]
fn cli_wizard_defaults_and_transfers_match_actual_manifest() {
    let (t, _p, _r) = fixture();
    let o = cli(t.path(), &["--wizard"], &"\n".repeat(20));
    assert!(o.status.success(), "{}", String::from_utf8_lossy(&o.stderr));
    let text = String::from_utf8_lossy(&o.stdout);
    assert!(text.contains("Estimated transfer: 8B"));
    assert!(text.contains("Memory") || text.contains("Paging"));
    let rows = manifest(t.path());
    assert_eq!(rows.len(), 1);
    assert!(rows[0].source_path.ends_with("ONE.pf"));
    let root = fs::read_dir(t.path().join("results"))
        .unwrap()
        .next()
        .unwrap()
        .unwrap()
        .path();
    assert_eq!(kumade::verify::verify(&root).unwrap(), (1, true));
}
#[test]
fn cli_wizard_can_include_paging() {
    let (t, _p, _r) = fixture();
    let answers = format!("\ny\n\n{}2\n\n", if cfg!(windows) { "\n\n" } else { "" });
    let o = cli(t.path(), &["--wizard"], &answers);
    assert!(o.status.success(), "{}", String::from_utf8_lossy(&o.stderr));
    assert_eq!(manifest(t.path()).len(), 2);
}
#[test]
fn cli_eof_and_cancellation_create_no_collection() {
    for input in [
        "".to_string(),
        format!("\n\n\n{}\nn\n", if cfg!(windows) { "\n\n" } else { "" }),
    ] {
        let (t, _p, _r) = fixture();
        let o = cli(t.path(), &["--wizard"], &input);
        assert!(!o.status.success());
        assert!(!t.path().join("results").exists());
    }
}
#[test]
fn unattended_mode_uses_safe_defaults_and_can_explicitly_include_paging() {
    for paging in [false, true] {
        let (t, _p, _r) = fixture();
        let args = if paging {
            vec!["--yes", "--paging"]
        } else {
            vec!["--no-wizard"]
        };
        let o = cli(t.path(), &args, "");
        assert!(o.status.success(), "{}", String::from_utf8_lossy(&o.stderr));
        assert!(!String::from_utf8_lossy(&o.stdout).contains("(Y/n):"));
        assert_eq!(manifest(t.path()).len(), if paging { 2 } else { 1 });
    }
}
#[test]
fn failed_embedded_process_scan_remains_sealed_and_partial() {
    let (t, p, _r) = fixture();
    let output = t.path().join("collected");
    let local = t.path().join("bad.yar");
    fs::write(&local, b"invalid YARA source").unwrap();
    let options = kumade::collect::Options {
        threads: 1,
        reserve_bytes: 0,
        quiet: true,
        verbose: false,
        ntfs_metadata: false,
        host_reserve: None,
        live_info: None,
        early: None,
        entropy: None,
        process_scan: Some(kumade::yara_scan::Options {
            output: PathBuf::new(),
            ruleset: kumade::yara_scan::RuleSet::Core,
            rules_release: "latest".into(),
            rules: Some(local),
            format: kumade::yara_scan::Format::Csv,
            pids: vec![std::process::id()],
            threads: 1,
            timeout: 1,
            chunk_mib: 1,
            quiet: true,
        }),
    };
    let (root, s) = kumade::collect::collect(&p, &output, &options).unwrap();
    assert_eq!(s.process_scan_status.as_deref(), Some("Failed"));
    assert_eq!(s.completeness, "Partial");
    assert_eq!(kumade::verify::verify(&root).unwrap(), (2, false));
    fs::write(root.join("YaraScan/Failure.json"), b"tampered").unwrap();
    assert!(kumade::verify::verify(&root).is_err());
}

#[test]
fn overlong_input_is_rejected_before_collection() {
    let input = "y".repeat(10000);
    let mut p = Prompt::new(Cursor::new(input), Vec::new());
    assert!(p.yes("long", true).is_err());
}
#[cfg(all(windows, not(target_arch = "x86")))]
#[test]
fn successful_embedded_process_scan_is_sealed_and_verified() {
    let (t, p, _r) = fixture();
    let rules = t.path().join("local.yar");
    use std::io::{BufRead, BufReader};
    struct ChildGuard(std::process::Child);
    impl Drop for ChildGuard {
        fn drop(&mut self) {
            let _ = self.0.kill();
            let _ = self.0.wait();
        }
    }
    let marker = format!("KumadeWizardControl_{}", uuid::Uuid::new_v4().simple());
    let mut child = ChildGuard(
        Command::new(std::env::current_exe().unwrap())
            .args(["--exact", "embedded_yara_child", "--nocapture"])
            .env("KUMADE_WIZARD_CONTROL", &marker)
            .stdout(Stdio::piped())
            .spawn()
            .unwrap(),
    );
    let stdout = child.0.stdout.take().unwrap();
    let (tx, rx) = std::sync::mpsc::channel();
    std::thread::spawn(move || {
        for line in BufReader::new(stdout).lines().map_while(Result::ok) {
            if line.contains("CONTROL_READY") {
                let _ = tx.send(());
                break;
            }
        }
    });
    rx.recv_timeout(std::time::Duration::from_secs(15)).unwrap();
    fs::write(
        &rules,
        format!("rule harmless_control {{ strings: $x=\"{marker}\" condition: $x }}"),
    )
    .unwrap();
    let options = kumade::collect::Options {
        threads: 1,
        reserve_bytes: 0,
        quiet: true,
        verbose: false,
        ntfs_metadata: false,
        host_reserve: None,
        live_info: None,
        early: None,
        entropy: None,
        process_scan: Some(kumade::yara_scan::Options {
            output: PathBuf::new(),
            ruleset: kumade::yara_scan::RuleSet::Core,
            rules_release: "latest".into(),
            rules: Some(rules),
            format: kumade::yara_scan::Format::Csv,
            pids: vec![child.0.id()],
            threads: 1,
            timeout: 60,
            chunk_mib: 1,
            quiet: true,
        }),
    };
    let (root, s) = kumade::collect::collect(&p, &t.path().join("results"), &options).unwrap();
    assert_eq!(s.process_scan_status.as_deref(), Some("Success"));
    assert_eq!(kumade::verify::verify(&root).unwrap(), (2, true));
    fs::write(root.join("YaraScan/Summary.json"), b"tampered").unwrap();
    assert!(kumade::verify::verify(&root).is_err());
}

#[cfg(all(windows, not(target_arch = "x86")))]
#[test]
fn embedded_yara_child() {
    let Ok(marker) = std::env::var("KUMADE_WIZARD_CONTROL") else {
        return;
    };
    let bytes = marker.into_bytes();
    println!("CONTROL_READY");
    std::io::stdout().flush().unwrap();
    for _ in 0..120 {
        std::hint::black_box(&bytes);
        std::thread::sleep(std::time::Duration::from_secs(1));
    }
}

#[test]
fn custom_category_cannot_accidentally_enable_paging_by_default() {
    let (_t, mut p, _r) = fixture();
    let r=Rules::load("SchemaVersion: 1\nArtifacts:\n - {Id: windows.prefetch, Name: Prefetch, Category: Memory, Patterns: ['Windows/Prefetch/*']}\n - {Id: windows.paging, Name: Paging, Category: Memory, Patterns: ['pagefile.sys']}\n").unwrap();
    p = discovery::build_plan(p.sources, &r, &[], false).unwrap();
    let sizes = Sizes::discover(&p);
    let mut io = Prompt::new(Cursor::new(b"\n\n\n\n\n"), Vec::new());
    let c = wizard::run(&mut io, &p, &r, &sizes, choices(), false, false).unwrap();
    assert_eq!(c.artifacts, vec!["windows.prefetch"]);
}

#[test]
fn cli_wizard_sizes_the_paging_family_added_to_an_explicit_scope() {
    let (t, _p, _r) = fixture();
    let o = cli(
        t.path(),
        &["--wizard", "--artifact", "windows.prefetch", "--paging"],
        &"\n".repeat(20),
    );
    assert!(o.status.success(), "{}", String::from_utf8_lossy(&o.stderr));
    let text = String::from_utf8_lossy(&o.stdout);
    assert!(
        text.contains(
            "Paging, swap, hibernation and existing memory dumps (6B; 1 files/streams) (Y/n)"
        ),
        "{text}"
    );
    assert!(
        text.contains("Estimated transfer: 14B / 2 files/streams"),
        "{text}"
    );
    assert_eq!(manifest(t.path()).len(), 2);
}
