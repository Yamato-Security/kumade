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
