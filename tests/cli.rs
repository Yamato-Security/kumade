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
fn help_and_doctor_do_not_collect_evidence() {
    for cmd in ["--help", "doctor", "list"] {
        let o = run(&[cmd]);
        assert!(o.status.success(), "{}", String::from_utf8_lossy(&o.stderr));
    }
}
#[test]
fn root_and_subcommand_options_cannot_silently_conflict() {
    let o = run(&["--computer", "IGNORED", "plan"]);
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
        "plan",
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
    ]);
    assert_eq!(out.status.code(), Some(3));
}

#[test]
fn requested_terminal_colors_do_not_change_redirected_or_no_color_output() {
    let output = Command::new(env!("CARGO_BIN_EXE_kumade"))
        .arg("doctor")
        .env("CLICOLOR_FORCE", "1")
        .env_remove("NO_COLOR")
        .output()
        .unwrap();
    assert!(output.status.success());
    let text = String::from_utf8(output.stdout).unwrap();
    assert!(text.contains("\x1b[38;2;0;255;0mVersion:\x1b[0m \x1b[38;2;255;255;255m"));
    let output = Command::new(env!("CARGO_BIN_EXE_kumade"))
        .arg("doctor")
        .env("CLICOLOR_FORCE", "1")
        .env("NO_COLOR", "1")
        .output()
        .unwrap();
    assert!(output.status.success());
    let text = String::from_utf8(output.stdout).unwrap();
    assert!(!text.contains('\x1b'));
    assert!(text.contains("by Yamato Security"));
    let output = Command::new(env!("CARGO_BIN_EXE_kumade"))
        .arg("doctor")
        .env_remove("CLICOLOR_FORCE")
        .env_remove("NO_COLOR")
        .output()
        .unwrap();
    assert!(output.status.success());
    assert!(!String::from_utf8(output.stdout).unwrap().contains('\x1b'));
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
        vec!["plan", "--vhdx", "evidence.vhdx"],
    ] {
        let output = run(&args);
        assert_eq!(output.status.code(), Some(2), "{args:?}");
    }
}

#[cfg(not(windows))]
#[test]
fn vhdx_is_explicitly_unsupported_on_other_platforms() {
    let output = run(&["--vhdx", "evidence.vhdx"]);
    assert_eq!(output.status.code(), Some(2));
    assert!(String::from_utf8_lossy(&output.stderr).contains("VHDX creation requires Windows"));
}
