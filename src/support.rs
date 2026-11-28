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

//! Read-only prerequisites for the capabilities displayed by `check-support`.
use crate::ui;

#[derive(Clone)]
enum Check {
    Ready,
    Unavailable(String),
    #[cfg(windows)]
    Unknown(String),
}

impl Check {
    fn show(&self, label: &str, ready: &str) {
        match self {
            Self::Ready => ui::field(label, ready),
            Self::Unavailable(reason) => {
                ui::error_field(label, &format!("Not available ({reason})"))
            }
            #[cfg(windows)]
            Self::Unknown(reason) => ui::error_field(label, &format!("Unknown ({reason})")),
        }
    }

    #[cfg(windows)]
    fn then(&self, next: impl FnOnce() -> Self) -> Self {
        match self {
            Self::Ready => next(),
            other => other.clone(),
        }
    }

    #[cfg(windows)]
    fn privileges(names: &[&str], require_elevation: bool) -> Self {
        match crate::platform::check_privileges(names, require_elevation) {
            Ok(None) => Self::Ready,
            Ok(Some(reason)) => Self::Unavailable(reason),
            Err(e) => Self::Unknown(format!("{e:#}")),
        }
    }
}

struct Checks {
    live: Check,
    ram: Check,
    vss: Check,
    transport: Check,
    container: Check,
}

impl Checks {
    #[cfg(windows)]
    fn current() -> Self {
        use crate::{memory, platform, vhdx};
        let live = Check::privileges(&[platform::BACKUP_PRIVILEGE], true);
        let ram = live.then(|| match memory::check_default_tool() {
            Ok(()) => Check::Ready,
            Err(e) => Check::Unavailable(format!("default DumpIt provider: {e}")),
        });
        let vss = live.then(|| match platform::require_native_build("VSS acquisition") {
            Ok(()) => Check::Ready,
            Err(e) => Check::Unavailable(e.to_string()),
        });
        // Windows also preserves NTFS metadata when uploading an offline tree.
        // That path checks the four privileges but does not require an elevated token itself.
        let transport = Check::privileges(platform::METADATA_PRIVILEGES, false);
        let container = transport.then(|| match vhdx::powershell() {
            Err(e) => Check::Unavailable(e.to_string()),
            Ok(shell) => {
                let module = shell.with_file_name("Modules").join("Storage/Storage.psd1");
                match module.try_exists() {
                    Ok(true) => Check::Ready,
                    Ok(false) => Check::Unknown(
                        "check the Windows PowerShell Storage module installation".into(),
                    ),
                    Err(e) => Check::Unknown(format!(
                        "cannot inspect the Windows PowerShell Storage module: {e}"
                    )),
                }
            }
        });
        Self {
            live,
            ram,
            vss,
            transport,
            container,
        }
    }

    #[cfg(not(windows))]
    fn current() -> Self {
        let windows = Check::Unavailable("requires Windows".into());
        Self {
            live: windows.clone(),
            ram: windows.clone(),
            vss: windows.clone(),
            transport: Check::Ready,
            container: windows,
        }
    }
}

pub fn print() {
    ui::banner();
    ui::field(
        "Platform",
        format!("{} / {}", std::env::consts::OS, std::env::consts::ARCH),
    );
    let checks = Checks::current();
    checks.live.show("Live acquisition", "Available");
    checks.live.show(
        "Raw NTFS acquisition",
        "Available for readable live NTFS volumes",
    );
    let bundle = crate::yara_rules::bundle_description();
    if crate::yara_rules::has_bundle() {
        ui::field("Bundled YARA Forge", bundle);
    } else {
        ui::error_field("Bundled YARA Forge", &bundle);
    }
    checks.live.show(
        "Partition imaging",
        "forensic-copy (requires a separate external destination disk)",
    );
    checks.ram.show(
        "RAM acquisition",
        "--memory (default DumpIt provider verified; driver policy must allow capture)",
    );
    checks.vss.show(
        "VSS acquisition",
        "--vss (crash-consistent snapshots without application writers)",
    );
    checks.transport.show(
        "Remote transport",
        "--sftp (pinned host key) or --s3 (temporary upload credentials)",
    );
    checks.container.show(
        "VHDX output",
        "VHDX with NTFS (requires sufficient local space and working Storage cmdlets)",
    );
    checks.container.show("E01 output", "NTFS staging, compression and hash verification (requires sufficient local space and working Storage cmdlets)");
}
