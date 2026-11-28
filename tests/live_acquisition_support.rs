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
    let status = stdout
        .lines()
        .find_map(|line| line.strip_prefix("Live acquisition: "))
        .unwrap();

    // Exercise the collection gate in this isolated test process, after running
    // the CLI so its child sees the original state of SeBackupPrivilege.
    match kumade::platform::enable_backup_privilege() {
        Ok(()) => assert_eq!(status, "Available"),
        Err(error) if error.to_string().contains("elevated local administrator") => {
            assert_eq!(status, "Not available (run as administrator)");
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
