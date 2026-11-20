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

//! Read-only NTFS access through the MIT/Apache-2.0 `ntfs` library.

//! Owned, auto-release VSS snapshots. No application writers and no live-read fallback.
#[cfg(windows)]
use crate::model::Issue;
use crate::model::SourceDiscovery;
use anyhow::{Context, Result, ensure};
use serde::{Deserialize, Serialize};
use std::path::{Path, PathBuf};

#[cfg(windows)]
#[path = "vss_windows.rs"]
mod windows;

#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(rename_all = "PascalCase")]
pub struct Snapshot {
    pub snapshot_id: String,
    pub snapshot_set_id: String,
    pub provider_id: String,
    pub original_volume: String,
    pub original_root: PathBuf,
    pub device_object: PathBuf,
    pub created_utc: String,
    pub attributes: i32,
    pub consistency: String,
    pub writers_participated: bool,
}

pub struct Session {
    #[cfg(windows)]
    inner: windows::Session,
}

impl Session {
    pub fn create(volumes: &[String], timeout_seconds: u64) -> Result<Self> {
        #[cfg(windows)]
        {
            Ok(Self {
                inner: windows::Session::create(volumes, timeout_seconds, false)?.0,
            })
        }
        #[cfg(not(windows))]
        {
            let _ = (volumes, timeout_seconds);
            anyhow::bail!("VSS acquisition requires native Windows and elevation")
        }
    }
    pub fn snapshots(&self) -> &[Snapshot] {
        #[cfg(windows)]
        {
            &self.inner.snapshots
        }
        #[cfg(not(windows))]
        {
            &[]
        }
    }
    /// Must run on the creating thread; COM ownership never enters acquisition workers.
    pub fn close(&mut self) -> Result<()> {
        #[cfg(windows)]
        {
            self.inner.close()
        }
        #[cfg(not(windows))]
        {
            Ok(())
        }
    }
}

/// Check this before discovering live files or creating output.
pub fn check_host() -> Result<()> {
    #[cfg(windows)]
    {
        windows::check_host()
    }
    #[cfg(not(windows))]
    {
        anyhow::bail!("VSS acquisition requires native Windows and elevation")
    }
}

/// Interpret only volume identifiers, never filenames, remote shares or devices.
pub fn volume_identifier(input: &str) -> Result<PathBuf> {
    let text = input
        .strip_prefix(r"\\.\")
        .unwrap_or(input)
        .trim_end_matches('\\');
    let bytes = text.as_bytes();
    if bytes.len() == 2 && bytes[0].is_ascii_alphabetic() && bytes[1] == b':' {
        return Ok(format!("{}:\\", char::from(bytes[0].to_ascii_uppercase())).into());
    }
    let prefix = r"\\?\Volume{";
    if text
        .get(..prefix.len())
        .is_some_and(|s| s.eq_ignore_ascii_case(prefix))
        && text.ends_with('}')
    {
        let id = uuid::Uuid::parse_str(&text[prefix.len()..text.len() - 1])
            .context("Invalid volume GUID")?;
        return Ok(format!(r"\\?\Volume{{{id}}}\").into());
    }
    anyhow::bail!(r"Use a local volume identifier such as C: or \\?\Volume{{GUID}}\")
}

pub fn select_sources(discovery: &mut SourceDiscovery, selected: &[String]) -> Result<()> {
    if selected.is_empty() {
        return Ok(());
    }
    #[cfg(windows)]
    {
        let ids = selected
            .iter()
            .map(|s| {
                crate::platform::volume_identity(&volume_identifier(s)?)?
                    .context("Selected volume is not local")
            })
            .collect::<Result<Vec<_>>>()?;
        let sources = std::mem::take(&mut discovery.sources);
        let mut found = vec![false; ids.len()];
        for source in sources {
            let volume = crate::platform::volume_identity(&source.root)?
                .context("Live source has no local volume")?;
            let mut keep = false;
            for (i, id) in ids.iter().enumerate() {
                if id.eq_ignore_ascii_case(&volume) {
                    found[i] = true;
                    keep = true;
                }
            }
            if keep {
                discovery.sources.push(source);
            } else {
                discovery.issues.push(Issue {
                    source_id: source.id,
                    path: source.root.display().to_string(),
                    status: "Excluded".into(),
                    reason: "Volume is outside the explicit --volume selection".into(),
                });
            }
        }
        for (i, yes) in found.iter().enumerate() {
            ensure!(
                *yes,
                "Selected volume {} is unavailable, excluded as the destination, or outside live fixed-volume discovery",
                selected[i]
            );
        }
        Ok(())
    }
    #[cfg(not(windows))]
    {
        let _ = discovery;
        anyhow::bail!("--volume requires Windows live acquisition")
    }
}

/// Replace every included source and raw provider with its snapshot. Unsupported
/// volumes remain explicit discovery issues and are never read from live storage.
pub fn prepare_sources(discovery: &mut SourceDiscovery, timeout_seconds: u64) -> Result<Session> {
    check_host()?;
    #[cfg(windows)]
    {
        ensure!(
            !discovery.sources.is_empty(),
            "No live volumes are available for VSS acquisition"
        );
        let volumes = discovery
            .sources
            .iter()
            .map(|s| {
                ensure!(
                    s.live && s.snapshot.is_none(),
                    "VSS is supported only for live, unsnapshotted volumes"
                );
                crate::platform::volume_identity(&s.root)?
                    .context("Live source has no local volume")
            })
            .collect::<Result<Vec<_>>>()?;
        let (inner, unsupported) = windows::Session::create(&volumes, timeout_seconds, true)?;
        let session = Session { inner };
        let originals = std::mem::take(&mut discovery.sources);
        for (mut source, volume) in originals.into_iter().zip(volumes) {
            if unsupported.iter().any(|v| v.eq_ignore_ascii_case(&volume)) {
                discovery.issues.push(Issue{source_id:source.id,path:source.root.display().to_string(),status:"Unsupported".into(),reason:"VSS provider does not support this volume; it was not acquired and no live fallback was used".into()});
                continue;
            }
            let mut snapshot = session
                .snapshots()
                .iter()
                .find(|s| s.original_volume.eq_ignore_ascii_case(&volume))
                .context("Snapshot volume mapping is missing")?
                .clone();
            snapshot.original_root = source.root.clone();
            let root = snapshot_device_root(&snapshot.device_object)?;
            ensure!(
                root.is_dir(),
                "VSS snapshot is not readable: {}",
                root.display()
            );
            source.profile_roots = source
                .profile_roots
                .iter()
                .map(|p| {
                    Ok(root.join(
                        p.strip_prefix(&source.root)
                            .context("Profile root escaped its source before VSS remapping")?,
                    ))
                })
                .collect::<Result<Vec<_>>>()?;
            source.root = root;
            if source.raw_device.is_some() {
                source.raw_device = Some(snapshot.device_object.clone());
            }
            source.snapshot = Some(snapshot);
            discovery.sources.push(source);
        }
        ensure!(
            !discovery.sources.is_empty(),
            "No supported VSS volumes remain"
        );
        Ok(session)
    }
    #[cfg(not(windows))]
    {
        let _ = (discovery, timeout_seconds);
        unreachable!("check_host rejects non-Windows")
    }
}

pub fn snapshot_device_root(device: &Path) -> Result<PathBuf> {
    let text = device.to_str().context("Unsupported VSS device name")?;
    let prefix = r"\\?\GLOBALROOT\Device\HarddiskVolumeShadowCopy";
    let suffix = text
        .get(prefix.len()..)
        .context("Invalid VSS snapshot device")?;
    ensure!(
        text.get(..prefix.len())
            .is_some_and(|s| s.eq_ignore_ascii_case(prefix))
            && !suffix.is_empty()
            && suffix.bytes().all(|b| b.is_ascii_digit()),
        "Invalid VSS snapshot device"
    );
    Ok(PathBuf::from(format!("{text}\\")))
}

pub fn omitted_paging_file(relative: &Path) -> bool {
    let Ok(path) = crate::paths::relative_text(relative) else {
        return false;
    };
    ["pagefile.sys", "swapfile.sys", "hiberfil.sys"]
        .iter()
        .any(|s| path.eq_ignore_ascii_case(s))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn snapshot_paging_is_not_claimed_as_live_evidence() {
        let temp = tempfile::tempdir().unwrap();
        let source_root = temp.path().join("source");
        std::fs::create_dir(&source_root).unwrap();
        std::fs::write(source_root.join("pagefile.sys"), b"not a snapshot of RAM").unwrap();
        let mut source = crate::discovery::directory_source(&source_root, "C", "TEST").unwrap();
        source.snapshot = Some(Snapshot {
            snapshot_id: "id".into(),
            snapshot_set_id: "set".into(),
            provider_id: "provider".into(),
            original_volume: "C:".into(),
            original_root: source_root.clone(),
            device_object: PathBuf::from(r"\\?\GLOBALROOT\Device\HarddiskVolumeShadowCopy1"),
            created_utc: crate::model::utc_now(),
            attributes: 16,
            consistency: "CrashConsistent".into(),
            writers_participated: false,
        });
        let rules = crate::catalog::Rules::load(crate::catalog::DEFAULT_CATALOG).unwrap();
        let plan = crate::discovery::build_plan(
            vec![source.clone()],
            &rules,
            &["windows.paging".into()],
            false,
        )
        .unwrap();
        let file = plan
            .files
            .iter()
            .find(|p| p.relative_path == Path::new("pagefile.sys"))
            .unwrap();
        let output = temp.path().join("output");
        std::fs::create_dir(&output).unwrap();
        let record = crate::collect::acquire_one(
            &output,
            &source,
            file,
            0,
            &mut std::collections::HashMap::new(),
        );
        assert_eq!(record.status, "Unsupported");
        assert!(record.reason.contains("no live-file"));
        assert_eq!(record.bytes_read, 0);
        assert!(!record.verified);
        assert_eq!(std::fs::read_dir(&output).unwrap().count(), 0);
    }
    #[test]
    fn identifiers_and_device_names_are_strict() {
        assert_eq!(volume_identifier("c:").unwrap(), PathBuf::from("C:\\"));
        for s in [
            r"\\host\share",
            r"\\.\PhysicalDrive0",
            "C:/file",
            "日本語",
            r"\\?\Volume{bad}\",
        ] {
            assert!(volume_identifier(s).is_err());
        }
        assert_eq!(
            snapshot_device_root(Path::new(
                r"\\?\GLOBALROOT\Device\HarddiskVolumeShadowCopy123"
            ))
            .unwrap(),
            PathBuf::from("\\\\?\\GLOBALROOT\\Device\\HarddiskVolumeShadowCopy123\\")
        );
        for s in [
            r"\\?\GLOBALROOT\Device\HarddiskVolumeShadowCopy",
            r"\\?\GLOBALROOT\Device\HarddiskVolumeShadowCopy2\..",
            r"\\?\GLOBALROOT\Device\HarddiskVolumeShadowCopy2\Windows",
            r"\\?\GLOBALROOT\Device\HarddiskVolumeShadowCopyX",
        ] {
            assert!(snapshot_device_root(Path::new(s)).is_err());
        }
        assert!(omitted_paging_file(Path::new("PAGEFILE.SYS")));
        assert!(!omitted_paging_file(Path::new("Users/pagefile.sys")));
        assert!(!omitted_paging_file(Path::new("Windows/MEMORY.DMP")));
    }
}
