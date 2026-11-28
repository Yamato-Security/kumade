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

#![cfg(windows)]

use std::process::Command;

#[test]
fn support_report_matches_the_live_acquisition_privilege_gate() {
    let report = Command::new(env!("CARGO_BIN_EXE_kumade"))
        .arg("check-support")
        .env("NO_COLOR", "1")
        .output()
        .unwrap();
    assert!(report.status.success(), "{:?}", report.stderr);
    let stdout = String::from_utf8(report.stdout).unwrap();
    let row = |label: &str| {
        stdout
            .lines()
            .find_map(|line| line.strip_prefix(label))
            .unwrap()
    };
    let status = row("Live acquisition: ");

    // Exercise the collection gate in this isolated test process, after running
    // the CLI so its child sees the original state of SeBackupPrivilege.
    match kumade::platform::enable_backup_privilege() {
        Ok(()) => {
            assert_eq!(status, "Available");
            assert!(row("Partition imaging: ").contains("external destination"));
            let vss = row("VSS acquisition: ");
            if kumade::platform::require_native_build("VSS acquisition").is_ok() {
                assert!(vss.contains("--vss"), "{vss}");
            } else {
                assert!(
                    vss.starts_with("Not available (") || vss.starts_with("Unknown ("),
                    "{vss}"
                );
            }
        }
        Err(error) if error.to_string().contains("elevated local administrator") => {
            for label in [
                "Live acquisition: ",
                "Raw NTFS acquisition: ",
                "Partition imaging: ",
                "VSS acquisition: ",
                "RAM acquisition: ",
            ] {
                assert_eq!(
                    row(label),
                    "Not available (run as administrator)",
                    "{label}"
                );
            }
        }
        Err(error)
            if error
                .to_string()
                .contains("does not hold SeBackupPrivilege") =>
        {
            assert_eq!(status, "Not available (SeBackupPrivilege is missing)");
        }
        Err(error) => panic!("Could not test live acquisition privileges: {error:#}"),
    }
}
