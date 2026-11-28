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

use std::{
    fs,
    path::Path,
    process::{Command, Output},
};

fn run(args: &[&str]) -> Output {
    Command::new(env!("CARGO_BIN_EXE_kumade"))
        .args(args)
        .output()
        .unwrap()
}
fn arg(path: &Path) -> &str {
    path.to_str().unwrap()
}

#[test]
fn root_lists_commands_and_bare_commands_with_options_print_help() {
    let root = run(&[]);
    assert!(root.status.success());
    assert!(root.stderr.is_empty());
    let menu = String::from_utf8(root.stdout).unwrap();
    assert!(menu.contains("Commands:"));
    assert!(
        menu.lines()
            .any(|line| line.trim_start().starts_with("check-support ")
                && line.ends_with("Check platform support and acquisition prerequisites"))
    );
    assert!(!menu.contains("doctor"));
    assert!(!menu.contains("Options:"));
    assert!(!menu.contains("--vhdx"));
    for args in [["-h"], ["--help"], ["help"], ["--"]] {
        let output = run(&args);
        assert!(output.status.success());
        assert_eq!(output.stdout, menu.as_bytes());
    }
    let temp = tempfile::tempdir().unwrap();
    let binary_name = Path::new(env!("CARGO_BIN_EXE_kumade"))
        .file_name()
        .unwrap()
        .to_str()
        .unwrap();
    for command in [
        "collect",
        "forensic-copy",
        "list-artifacts",
        "list-vss",
        "live-info",
        "collect-test",
        "receive-sftp",
        "resume-s3",
        "scan-processes",
        "update-rules",
        "verify",
        "verify-delivery",
        "verify-s3",
    ] {
        let shown = Command::new(env!("CARGO_BIN_EXE_kumade"))
            .arg(command)
            .current_dir(temp.path())
            .output()
            .unwrap();
        assert!(shown.status.success(), "{command}: {:?}", shown.stderr);
        assert!(shown.stderr.is_empty(), "{command}");
        let help = String::from_utf8(shown.stdout).unwrap();
        assert!(
            help.contains(&format!("Usage: {binary_name} {command}")),
            "{command}"
        );
        assert!(help.contains("--help"), "{command}");
        assert_eq!(
            help.contains("--vhdx "),
            matches!(command, "collect" | "collect-test")
        );
        for option in ["-h", "--"] {
            let explicit = run(&[command, option]);
            assert!(explicit.status.success());
            assert_eq!(help.as_bytes(), explicit.stdout, "{command} {option}");
        }
    }
    assert_eq!(fs::read_dir(temp.path()).unwrap().count(), 0);
}

#[test]
fn check_support_runs_directly_and_help_is_explicit() {
    let report = run(&["check-support"]);
    assert!(report.status.success());
    assert!(report.stderr.is_empty());
    assert!(String::from_utf8_lossy(&report.stdout).contains("Raw NTFS acquisition:"));
    let terminated = run(&["check-support", "--"]);
    assert!(terminated.status.success());
    assert_eq!(terminated.stdout, report.stdout);

    for args in [
        ["check-support", "-h"],
        ["check-support", "--help"],
        ["help", "check-support"],
    ] {
        let help = run(&args);
        assert!(help.status.success());
        let text = String::from_utf8(help.stdout).unwrap();
        assert!(text.contains("Usage:"));
        assert!(!text.contains("Raw NTFS acquisition:"));
        assert!(!text.contains("--check"));
    }
}

#[test]
fn explicit_flags_run_default_inspection_actions() {
    let catalog = run(&["list-artifacts", "--builtin"]);
    assert!(catalog.status.success());
    assert!(String::from_utf8_lossy(&catalog.stdout).contains("windows.prefetch"));
    assert_eq!(
        run(&["list-vss", "--all", "--volume", "C:"]).status.code(),
        Some(2)
    );
    for args in [
        &["unknown-command"][..],
        &["doctor"],
        &["check-support", "--check"],
        &["collect", "--unknown"],
        &["verify", "--unknown"],
    ] {
        let invalid = run(args);
        assert_eq!(invalid.status.code(), Some(2));
        assert!(!invalid.stderr.is_empty());
    }
}

#[test]
fn verbose_lists_every_file_with_parallel_workers_and_preserves_verification() {
    let temp = tempfile::tempdir().unwrap();
    let source = temp.path().join("source");
    fs::create_dir_all(source.join("Windows/Prefetch")).unwrap();
    // Several files exercise concurrent console writes without relying on order.
    for i in 0..24 {
        fs::write(source.join(format!("Windows/Prefetch/TEST-{i:02}.pf")), [i]).unwrap();
    }
    let parent = temp.path().join("results");
    for verbose in ["-v", "--verbose"] {
        let output = parent.join(verbose.trim_start_matches('-'));
        let out = run(&[
            "collect",
            "-d",
            arg(&source),
            "-o",
            arg(&output),
            "--artifact",
            "windows.prefetch",
            "--reserve-mib",
            "0",
            "-T",
            "4",
            "--no-wizard",
            verbose,
        ]);
        assert!(
            out.status.success(),
            "{}",
            String::from_utf8_lossy(&out.stderr)
        );
        let stdout = String::from_utf8(out.stdout).unwrap();
        let copies: Vec<_> = stdout
            .lines()
            .filter(|line| line.starts_with("Copying: "))
            .collect();
        assert_eq!(copies.len(), 24, "{stdout}");
        for i in 0..24 {
            assert_eq!(
                copies
                    .iter()
                    .filter(|line| line.ends_with(&format!("TEST-{i:02}.pf")))
                    .count(),
                1
            );
        }
        assert!(!stdout.contains(" / 24"));
        // Windows checkout can embed CRLF in the logo. Reject progress-bar
        // carriage returns, while allowing ordinary Windows line endings.
        assert!(!stdout.replace("\r\n", "\n").contains('\r'));
        assert!(!stdout.contains('\x1b'));
        for root in fs::read_dir(output).unwrap() {
            assert!(
                run(&["verify", arg(&root.unwrap().path())])
                    .status
                    .success()
            );
        }
    }
}

#[test]
fn verbose_and_quiet_conflict_and_zero_workers_are_rejected() {
    for args in [
        vec!["-v", "-q"],
        vec!["collect", "--verbose", "--quiet"],
        vec!["collect", "-T", "0"],
        vec!["collect", "-T", "129"],
    ] {
        assert_eq!(run(&args).status.code(), Some(2), "{args:?}");
    }
}
#[test]
fn root_and_subcommand_options_cannot_silently_conflict() {
    let o = run(&["--computer", "IGNORED", "collect-test"]);
    assert!(!o.status.success());
}
#[test]
fn cli_can_plan_collect_and_verify_offline() {
    let temp = tempfile::tempdir().unwrap();
    let source = temp.path().join("source");
    fs::create_dir_all(source.join("Windows/Prefetch")).unwrap();
    fs::write(source.join("Windows/Prefetch/EXAMPLE.pf"), b"fixture").unwrap();
    let planned = temp.path().join("planned");
    let out = run(&[
        "collect-test",
        "-d",
        arg(&source),
        "-o",
        arg(&planned),
        "--computer",
        "HOST01",
    ]);
    assert!(
        out.status.success(),
        "{}",
        String::from_utf8_lossy(&out.stderr)
    );
    assert!(planned.join("Plan.json").exists());
    let output = temp.path().join("results");
    let out = run(&[
        "-d",
        arg(&source),
        "-o",
        arg(&output),
        "--computer",
        "HOST01",
        "--reserve-mib",
        "0",
        "--no-wizard",
    ]);
    assert!(
        out.status.success(),
        "{}",
        String::from_utf8_lossy(&out.stderr)
    );
    let root = fs::read_dir(output)
        .unwrap()
        .next()
        .unwrap()
        .unwrap()
        .path();
    assert!(run(&["verify", arg(&root)]).status.success());
}
#[test]
fn memory_request_has_nonzero_partial_exit() {
    let temp = tempfile::tempdir().unwrap();
    let source = temp.path().join("source");
    fs::create_dir_all(source.join("Windows/Prefetch")).unwrap();
    fs::write(source.join("Windows/Prefetch/EXAMPLE.pf"), b"fixture").unwrap();
    let output = temp.path().join("results");
    let out = run(&[
        "collect",
        "-d",
        arg(&source),
        "-o",
        arg(&output),
        "--memory",
        "--reserve-mib",
        "0",
        "--no-wizard",
    ]);
    assert_eq!(out.status.code(), Some(3));
}

#[test]
fn requested_terminal_colors_do_not_change_redirected_or_no_color_output() {
    let output = Command::new(env!("CARGO_BIN_EXE_kumade"))
        .arg("check-support")
        .env("CLICOLOR_FORCE", "1")
        .env_remove("NO_COLOR")
        .output()
        .unwrap();
    assert!(output.status.success());
    let text = String::from_utf8(output.stdout).unwrap();
    assert!(text.contains("\x1b[38;2;0;255;0mVersion:\x1b[0m \x1b[38;2;255;255;255m"));
    let output = Command::new(env!("CARGO_BIN_EXE_kumade"))
        .arg("check-support")
        .env("CLICOLOR_FORCE", "1")
        .env("NO_COLOR", "1")
        .output()
        .unwrap();
    assert!(output.status.success());
    let text = String::from_utf8(output.stdout).unwrap();
    assert!(!text.contains('\x1b'));
    assert!(text.contains("by Yamato Security"));
    let output = Command::new(env!("CARGO_BIN_EXE_kumade"))
        .arg("check-support")
        .env_remove("CLICOLOR_FORCE")
        .env_remove("NO_COLOR")
        .output()
        .unwrap();
    assert!(output.status.success());
    assert!(!String::from_utf8(output.stdout).unwrap().contains('\x1b'));
}

#[test]
fn support_colors_every_unavailable_value_and_keeps_the_plain_text_readable() {
    let bin = env!("CARGO_BIN_EXE_kumade");
    let plain = Command::new(bin)
        .arg("check-support")
        .env("NO_COLOR", "1")
        .output()
        .unwrap();
    let colored = Command::new(bin)
        .arg("check-support")
        .env_remove("NO_COLOR")
        .env("CLICOLOR_FORCE", "1")
        .output()
        .unwrap();
    assert!(plain.status.success() && colored.status.success());
    let plain = String::from_utf8(plain.stdout).unwrap();
    let colored = String::from_utf8(colored.stdout).unwrap();
    assert!(!plain.contains('\x1b'));
    assert_eq!(console::strip_ansi_codes(&colored), plain);
    for line in plain.lines() {
        if let Some((label, value)) = line.split_once(": ") {
            let line = colored
                .lines()
                .find(|text| console::strip_ansi_codes(text).starts_with(&format!("{label}: ")))
                .unwrap();
            let unavailable =
                value.starts_with("Not available (") || value.starts_with("Unknown (");
            assert_eq!(line.contains("\x1b[38;2;255;0;0m"), unavailable, "{label}");
            if unavailable {
                assert!(
                    line.ends_with(&format!("\x1b[38;2;255;0;0m{value}\x1b[0m")),
                    "{label}"
                );
            }
        }
    }
}

#[test]
fn version_remains_a_single_machine_readable_line() {
    let output = run(&["--version"]);
    assert!(output.status.success());
    assert_eq!(
        String::from_utf8(output.stdout).unwrap().trim(),
        concat!("kumade ", env!("CARGO_PKG_VERSION"))
    );
}

#[test]
fn vhdx_options_reject_ambiguous_destinations_and_invalid_capacity() {
    for args in [
        vec!["--vhdx", "evidence.vhdx", "-o", "output"],
        vec!["--vhdx-size-gib", "1"],
        vec!["--vhdx", "evidence.vhdx", "--vhdx-size-gib", "0"],
        vec!["--vhdx", "evidence.vhdx", "--vhdx-size-gib", "65537"],
        vec!["collect-test", "--vhdx", "evidence.vhdx"],
    ] {
        let output = run(&args);
        assert_eq!(output.status.code(), Some(2), "{args:?}");
    }
}

#[test]
fn e01_options_reject_conflicts_and_invalid_capacity() {
    for args in [
        vec!["--e01", "case.E01", "-o", "out"],
        vec!["--e01", "case.E01", "--vhdx", "case.vhdx"],
        vec!["--e01-size-gib", "1"],
        vec!["--e01", "case.E01", "--e01-size-gib", "0"],
        vec!["--e01", "case.E01", "--e01-size-gib", "65537"],
        vec!["collect-test", "--e01", "case.E01"],
    ] {
        assert_eq!(run(&args).status.code(), Some(2), "{args:?}");
    }
}

#[cfg(not(windows))]
#[test]
fn e01_collection_requires_windows() {
    let result = run(&["--e01", "case.E01"]);
    assert_eq!(result.status.code(), Some(2));
    assert!(String::from_utf8_lossy(&result.stderr).contains("E01 collection requires Windows"));
}

#[cfg(not(windows))]
#[test]
fn vhdx_is_explicitly_unsupported_on_other_platforms() {
    for args in [vec!["--vhdx", "evidence.vhdx"], vec!["--vhdx"]] {
        let output = run(&args);
        assert_eq!(output.status.code(), Some(2), "{args:?}");
        assert!(String::from_utf8_lossy(&output.stderr).contains("VHDX creation requires Windows"));
    }
}

#[test]
fn offline_source_directories_cannot_shadow_collection_metadata() {
    let temp = tempfile::tempdir().unwrap();
    let source = temp.path().join("LiveInfo");
    fs::create_dir_all(source.join("Windows/Prefetch")).unwrap();
    fs::write(source.join("Windows/Prefetch/EXAMPLE.pf"), b"fixture").unwrap();
    let output = temp.path().join("results");
    let out = run(&[
        "-d",
        arg(&source),
        "-o",
        arg(&output),
        "--computer",
        "HOST01",
        "--reserve-mib",
        "0",
        "--no-wizard",
        "-q",
    ]);
    assert!(
        out.status.success(),
        "{}",
        String::from_utf8_lossy(&out.stderr)
    );
    let root = fs::read_dir(&output)
        .unwrap()
        .next()
        .unwrap()
        .unwrap()
        .path();
    assert!(
        root.join("LiveInfo-1/Windows/Prefetch/EXAMPLE.pf")
            .is_file()
    );
    assert!(!root.join("LiveInfo").exists());
    assert!(run(&["verify", arg(&root)]).status.success());
}

#[test]
fn forensic_copy_help_and_required_arguments() {
    let help = run(&["forensic-copy", "--help"]);
    assert!(help.status.success());
    let text = String::from_utf8(help.stdout).unwrap();
    assert!(text.contains("--source <VOLUME>"));
    assert!(text.contains("--output <DIR>"));
    assert!(text.contains("external physical drive"));
    for args in [
        vec!["forensic-copy", "-s", "C:"],
        vec!["forensic-copy", "-o", "E:\\Evidence"],
    ] {
        assert_eq!(run(&args).status.code(), Some(2));
    }
}

#[cfg(not(windows))]
#[test]
fn forensic_copy_rejects_unsupported_hosts_without_creating_output() {
    let temp = tempfile::tempdir().unwrap();
    let output = temp.path().join("not-created");
    let result = run(&["forensic-copy", "-s", "C:", "-o", arg(&output)]);
    assert_eq!(result.status.code(), Some(2));
    assert!(String::from_utf8_lossy(&result.stderr).contains("requires elevated Windows"));
    assert!(!output.exists());
}

#[test]
fn vss_flags_reject_offline_plans_and_invalid_timeouts_without_writing() {
    let temp = tempfile::tempdir().unwrap();
    let output = temp.path().join("no-output");
    for extra in [
        vec!["collect-test", "--vss"],
        vec!["collect", "--vss", "-d", "offline"],
        vec!["collect", "--vss-timeout", "30"],
        vec!["collect", "--vss", "--vss-timeout", "0"],
        vec!["collect", "--volume", "C:", "-d", "offline"],
    ] {
        let mut cmd = Command::new(env!("CARGO_BIN_EXE_kumade"));
        cmd.args(&extra).arg("-o").arg(&output);
        let result = cmd.output().unwrap();
        assert!(!result.status.success(), "{extra:?}");
        assert!(!output.exists());
    }
    let help = run(&["collect", "--help"]);
    let text = String::from_utf8(help.stdout).unwrap();
    assert!(text.contains("--vss"));
    assert!(text.contains("--volume"));
    let help = run(&["forensic-copy", "--help"]);
    assert!(String::from_utf8(help.stdout).unwrap().contains("--vss"));
}

#[test]
fn offline_memory_never_runs_a_provider_on_the_analyst_host() {
    let temp = tempfile::tempdir().unwrap();
    let source = temp.path().join("source");
    fs::create_dir_all(source.join("Windows/Prefetch")).unwrap();
    fs::write(source.join("Windows/Prefetch/EXAMPLE.pf"), b"fixture").unwrap();
    let output = temp.path().join("results");
    let out = run(&[
        "collect",
        "-d",
        arg(&source),
        "-o",
        arg(&output),
        "--memory",
        "--dumpit",
        "DO-NOT-RUN.exe",
        "--reserve-mib",
        "0",
        "--no-wizard",
    ]);
    assert_eq!(out.status.code(), Some(3));
    let root = fs::read_dir(&output)
        .unwrap()
        .next()
        .unwrap()
        .unwrap()
        .path();
    let data = fs::read_to_string(root.join("Manifest.jsonl")).unwrap();
    let first: serde_json::Value = serde_json::from_str(data.lines().next().unwrap()).unwrap();
    assert_eq!(first["Status"], "Failed");
    assert!(
        first["Reason"]
            .as_str()
            .unwrap()
            .contains("analyst computer")
    );
    assert!(!root.join("Memory/Memory.dmp").exists());
}

#[test]
fn explicit_volatile_staging_cannot_write_inside_offline_evidence() {
    let temp = tempfile::tempdir().unwrap();
    let source = temp.path().join("source");
    fs::create_dir_all(source.join("Windows/Prefetch")).unwrap();
    let output = temp.path().join("results");
    let out = run(&[
        "collect",
        "-d",
        arg(&source),
        "-o",
        arg(&output),
        "--memory",
        "--memory-staging-dir",
        arg(&source.join("forbidden")),
        "--no-wizard",
    ]);
    assert_eq!(out.status.code(), Some(2));
    assert!(!source.join("forbidden").exists());
}
