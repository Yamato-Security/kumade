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

//! Lossless source metadata inventory and native restoration for VHDX output.
use crate::{model::*, paths};
use anyhow::{Context, Result, ensure};
use serde::{Deserialize, Serialize};
use std::{
    collections::{BTreeMap, BTreeSet},
    io::{BufWriter, Write},
    path::{Path, PathBuf},
};

#[cfg(windows)]
#[path = "metadata_windows.rs"]
mod windows;
#[cfg(windows)]
pub use windows::{augment_streams, enable_privileges};

pub const FILES: [&str; 2] = ["NTFS-Metadata.jsonl", "NTFS-Metadata.csv"];

#[derive(Clone, Debug, Default, Serialize, Deserialize)]
#[serde(rename_all = "PascalCase")]
pub struct Snapshot {
    pub source_id: String,
    pub source_path: String,
    pub relative_output_path: String,
    pub directory: bool,
    pub captured_utc: String,
    pub creation_filetime: Option<i64>,
    pub access_filetime: Option<i64>,
    pub write_filetime: Option<i64>,
    pub change_filetime: Option<i64>,
    pub attributes: Option<u32>,
    pub source_file_id: Option<String>,
    pub security_descriptor_hex: Option<String>,
    pub sddl: Option<String>,
    pub extended_attributes_hex: Option<String>,
    pub capture_status: String,
    pub restore_status: String,
    pub problems: String,
}

pub fn output_relative(source: &str, relative: &Path, stream: Option<&str>) -> Result<PathBuf> {
    let mut path = PathBuf::from("Evidence")
        .join("Live")
        .join(paths::encode_component(source));
    if !relative.as_os_str().is_empty() {
        for part in paths::relative_text(relative)?.split('/') {
            let encoded = paths::encode_component(part);
            ensure!(
                encoded.encode_utf16().count() <= 255,
                "Encoded NTFS filename exceeds 255 characters"
            );
            path.push(encoded);
        }
    }
    if let Some(stream) = stream {
        ensure!(!stream.is_empty(), "Empty data stream name");
        let leaf = path
            .file_name()
            .context("Stream has no base filename")?
            .to_str()
            .context("Invalid output filename")?;
        let name = paths::encode_component(stream);
        path.set_file_name(format!("{leaf}:{name}"));
    }
    Ok(path)
}

/// Typed ADS paths are accepted only when the sealed record declares that stream.
/// Metadata filenames and ordinary payload paths continue to use strict safe_join.
pub fn payload_path(root: &Path, relative: &str, stream: Option<&str>) -> Result<PathBuf> {
    let Some((base, name)) = relative.rsplit_once(':') else {
        return paths::safe_join(root, relative);
    };
    ensure!(
        cfg!(windows),
        "Native NTFS stream verification requires Windows"
    );
    let stream = stream.context("Undeclared alternate data stream")?;
    ensure!(
        name == paths::encode_component(stream) && !name.is_empty(),
        "Stream path/name mismatch"
    );
    let base = paths::safe_join(root, base)?;
    ensure!(
        crate::platform::open_source(&base)?.metadata()?.is_file(),
        "Stream base is not a regular file"
    );
    Ok(PathBuf::from(format!("{}:{name}", base.display())))
}

pub fn prepare(plan: &Plan) -> Vec<Snapshot> {
    // Include each collected file's containing directories exactly once. Capture
    // these before payload writes and restore deepest first after all children.
    let mut targets = BTreeMap::<(String, PathBuf), (PathBuf, PathBuf, bool)>::new();
    for item in &plan.files {
        let Some(source) = plan.sources.iter().find(|s| s.id == item.source_id) else {
            continue;
        };
        let output = match output_relative(&source.id, &item.relative_path, None) {
            Ok(v) => v,
            Err(_) => continue, // The acquisition reports this invalid planned path.
        };
        targets.insert(
            (source.id.clone(), item.relative_path.clone()),
            (item.source_path.clone(), output, false),
        );
        let mut relative = item.relative_path.parent();
        while let Some(parent) = relative {
            // Long-path exports have no corresponding source directory tree.
            if let Ok(output) = output_relative(&source.id, parent, None) {
                targets
                    .entry((source.id.clone(), parent.to_owned()))
                    .or_insert((source.root.join(parent), output, true));
            }
            relative = parent.parent();
        }
    }
    targets
        .into_iter()
        .map(|((source_id, _), (source, output, directory))| {
            let mut record = Snapshot {
                source_id,
                source_path: source.display().to_string(),
                relative_output_path: paths::relative_text(&output).unwrap_or_default(),
                directory,
                captured_utc: utc_now(),
                capture_status: "Failed".into(),
                restore_status: "Pending".into(),
                ..Default::default()
            };
            #[cfg(windows)]
            match windows::capture(&source, &mut record) {
                Ok(()) => record.capture_status = "Captured".into(),
                Err(error) => {
                    if record.attributes.is_some() {
                        record.capture_status = "Partial".into();
                    }
                    record.problems = format!("Capture: {error:#}");
                }
            }
            #[cfg(not(windows))]
            {
                let _ = source;
                record.problems = "Native NTFS metadata capture requires Windows".into();
            }
            record
        })
        .collect()
}

pub fn restore(root: &Path, snapshots: &mut [Snapshot], records: &[Record]) -> usize {
    let available: BTreeSet<_> = records
        .iter()
        .filter(|r| r.verified)
        .filter_map(|r| r.relative_output_path.as_deref())
        .map(|p| p.split_once(':').map_or(p, |(p, _)| p).to_owned())
        .collect();
    // File metadata first, then directories deepest first; no subsequent writes
    // take place under restored source directories.
    snapshots.sort_by_key(|s| {
        (
            s.directory,
            std::cmp::Reverse(Path::new(&s.relative_output_path).components().count()),
        )
    });
    let mut errors = 0;
    for snapshot in snapshots {
        if !snapshot.directory && !available.contains(&snapshot.relative_output_path) {
            snapshot.restore_status = "PayloadUnavailable".into();
            continue;
        }
        if snapshot.capture_status == "Failed" {
            snapshot.restore_status = "CaptureFailed".into();
            errors += 1;
            continue;
        }
        let result = paths::safe_join(root, &snapshot.relative_output_path).and_then(|path| {
            #[cfg(windows)]
            {
                windows::restore(&path, snapshot)
            }
            #[cfg(not(windows))]
            {
                let _ = path;
                anyhow::bail!("Native NTFS restoration requires Windows")
            }
        });
        match result {
            Ok(()) => snapshot.restore_status = "Restored".into(),
            Err(error) => {
                snapshot.restore_status = "Partial".into();
                snapshot.problems.push_str(&format!("Restore: {error:#}"));
                errors += 1;
            }
        }
    }
    errors
}

pub fn write_inventory(root: &Path, snapshots: &[Snapshot]) -> Result<()> {
    let create = |name| {
        std::fs::OpenOptions::new()
            .write(true)
            .create_new(true)
            .open(root.join(name))
    };
    let mut json = BufWriter::new(create(FILES[0])?);
    let mut csv = csv::Writer::from_writer(create(FILES[1])?);
    for snapshot in snapshots {
        serde_json::to_writer(&mut json, snapshot)?;
        json.write_all(b"\n")?;
        csv.serialize(snapshot)?;
    }
    json.flush()?;
    csv.flush()?;
    json.get_ref().sync_all()?;
    csv.get_ref().sync_all()?;
    Ok(())
}

pub fn unhex(text: &str) -> Result<Vec<u8>> {
    ensure!(text.len().is_multiple_of(2), "Invalid hexadecimal metadata");
    text.as_bytes()
        .as_chunks::<2>()
        .0
        .iter()
        .map(|pair| {
            let pair = std::str::from_utf8(pair)?;
            u8::from_str_radix(pair, 16).context("Invalid hexadecimal metadata")
        })
        .collect()
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn stream_names_cannot_create_paths_or_collide_with_default_data() {
        let plain = output_relative("C", Path::new("Windows/file.bin"), None).unwrap();
        let stream =
            output_relative("C", Path::new("Windows/file.bin"), Some("Zone.Identifier")).unwrap();
        assert_eq!(
            stream.to_string_lossy().replace('\\', "/"),
            format!(
                "{}:Zone.Identifier",
                plain.to_string_lossy().replace('\\', "/")
            )
        );
        let hostile = output_relative("C", Path::new("file"), Some("../other:name")).unwrap();
        assert!(hostile.to_string_lossy().ends_with(":..%2Fother%3Aname"));
        assert!(output_relative("C", Path::new("file"), Some("")).is_err());
    }
    #[test]
    fn source_directory_and_long_paths_keep_their_corresponding_container_paths() {
        assert_eq!(
            output_relative("C", Path::new(""), None).unwrap(),
            Path::new("Evidence/Live/C")
        );
        let relative = format!("Windows/{}/file", "long/".repeat(60));
        let path = output_relative("C", Path::new(&relative), None).unwrap();
        assert!(path.starts_with("Evidence/Live/C/Windows"));
        assert!(!path.to_string_lossy().contains("LongPaths"));
        assert!(output_relative("C", Path::new(&"x".repeat(256)), None).is_err());
    }

    #[test]
    fn inventory_round_trips_large_filetimes_and_security_bytes() {
        let tmp = tempfile::tempdir().unwrap();
        let snapshot = Snapshot {
            creation_filetime: Some(134_370_987_123_456_789),
            security_descriptor_hex: Some("0100ff".into()),
            capture_status: "Captured".into(),
            ..Default::default()
        };
        write_inventory(tmp.path(), std::slice::from_ref(&snapshot)).unwrap();
        let from_json: Snapshot =
            serde_json::from_str(&std::fs::read_to_string(tmp.path().join(FILES[0])).unwrap())
                .unwrap();
        let from_csv: Snapshot = csv::Reader::from_path(tmp.path().join(FILES[1]))
            .unwrap()
            .deserialize()
            .next()
            .unwrap()
            .unwrap();
        assert_eq!(from_json.creation_filetime, snapshot.creation_filetime);
        assert_eq!(from_csv.creation_filetime, snapshot.creation_filetime);
        assert_eq!(
            unhex(from_json.security_descriptor_hex.as_ref().unwrap()).unwrap(),
            [1, 0, 255]
        );
        assert!(unhex("0").is_err());
        assert!(unhex("zz").is_err());
    }
}
