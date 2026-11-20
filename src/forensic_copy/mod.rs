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

//! Raw logical-volume imaging. The destination is an ordinary file, never a disk device.
use anyhow::Result;
#[cfg(any(windows, test))]
use anyhow::{Context, ensure};
use serde::{Deserialize, Serialize};
#[cfg(any(windows, test))]
use sha2::{Digest, Sha256};
#[cfg(any(windows, test))]
use std::io::{Read, Write};

#[cfg(windows)]
mod windows;

#[derive(Debug)]
pub struct Options {
    pub source: String,
    pub output: std::path::PathBuf,
    pub reserve_mib: u64,
    pub quiet: bool,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(rename_all = "PascalCase")]
pub struct Extent {
    pub disk_number: u32,
    pub starting_offset: u64,
    pub length: u64,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(rename_all = "PascalCase")]
pub struct Disk {
    pub disk_number: u32,
    pub bus_type: i32,
    pub removable: bool,
    pub hotplug: bool,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(rename_all = "PascalCase")]
pub struct Volume {
    pub volume_name: String,
    pub extents: Vec<Extent>,
    pub disks: Vec<Disk>,
}

#[derive(Debug, Serialize, Deserialize)]
#[serde(rename_all = "PascalCase")]
pub struct Report {
    pub schema_version: u32,
    pub version: String,
    pub computer: String,
    pub started_utc: String,
    pub finished_utc: Option<String>,
    pub status: String,
    pub source: Volume,
    pub destination: Volume,
    pub expected_bytes: u64,
    pub bytes_copied: u64,
    pub logical_sector_size: u32,
    pub image: String,
    pub acquired_sha256: Option<String>,
    pub image_sha256: Option<String>,
    pub verified: bool,
    /// Raw reads do not provide VSS or a point-in-time snapshot of a writable volume.
    pub consistency: String,
    pub error: Option<String>,
}

pub fn run(options: &Options) -> Result<()> {
    #[cfg(windows)]
    return windows::run(options);
    #[cfg(not(windows))]
    {
        let _ = options;
        anyhow::bail!("forensic-copy requires elevated Windows and an external destination drive")
    }
}

/// Fail closed when storage topology is unknown. Distinct drive letters are not proof
/// of distinct disks. Reject virtual/pool-backed sources because their backing disk
/// identities cannot be established by this basic-volume implementation.
#[cfg(any(windows, test))]
fn validate_destination(source: &Volume, destination: &Volume) -> Result<()> {
    ensure!(
        !source
            .volume_name
            .eq_ignore_ascii_case(&destination.volume_name),
        "Source and destination are on the same volume"
    );
    for (label, volume) in [("Source", source), ("Destination", destination)] {
        ensure!(
            !volume.extents.is_empty(),
            "{label} has no physical disk extents"
        );
        for extent in &volume.extents {
            ensure!(
                extent.length > 0 && extent.starting_offset.checked_add(extent.length).is_some(),
                "Invalid {label} disk extent"
            );
            ensure!(
                volume
                    .disks
                    .iter()
                    .any(|d| d.disk_number == extent.disk_number),
                "{label} physical disk identity is incomplete"
            );
        }
    }
    ensure!(
        source.extents.len() == 1,
        "Only single-extent logical partitions are supported"
    );
    ensure!(
        !source.extents.iter().any(|s| destination
            .extents
            .iter()
            .any(|d| s.disk_number == d.disk_number)),
        "Destination is on the same physical disk as the source, even if the drive letters differ"
    );
    // Windows STORAGE_BUS_TYPE: virtual, file-backed virtual, Storage Spaces, unknown, RAID, iSCSI.
    for disk in source.disks.iter().chain(&destination.disks) {
        ensure!(
            (1..=19).contains(&disk.bus_type) && !matches!(disk.bus_type, 8 | 9 | 14 | 15 | 16),
            "Unsupported or unknown storage topology for disk {} (bus type {})",
            disk.disk_number,
            disk.bus_type
        );
    }
    ensure!(
        destination.disks.iter().all(external_disk),
        "Destination must be an external drive (USB, FireWire, SD/MMC, or removable/hotplug storage)"
    );
    Ok(())
}

#[cfg(any(windows, test))]
fn external_disk(disk: &Disk) -> bool {
    matches!(disk.bus_type, 4 | 7 | 12 | 13) || disk.removable || disk.hotplug
}

#[cfg(any(windows, test))]
fn validate_capacity(
    length: u64,
    available: u64,
    reserve_mib: u64,
    filesystem: &str,
) -> Result<()> {
    ensure!(length > 0, "Source partition is empty");
    let reserve = reserve_mib
        .checked_mul(1024 * 1024)
        .context("Reserve size overflows")?;
    let required = length
        .checked_add(reserve)
        .and_then(|n| n.checked_add(1024 * 1024))
        .context("Image capacity overflows")?;
    ensure!(
        available >= required,
        "Not enough destination space: need {} including reserve and report space; available {}",
        crate::collect::human_bytes(required),
        crate::collect::human_bytes(available)
    );
    ensure!(
        !filesystem.eq_ignore_ascii_case("FAT32") || length <= u32::MAX as u64,
        "FAT32 cannot store an image this large; use NTFS or exFAT"
    );
    Ok(())
}

/// Bound memory independently of partition size. Read errors, early EOF and write
/// errors are fatal; never silently pad damaged/unreadable sectors with zeros.
#[cfg(any(windows, test))]
fn copy_exact(
    input: &mut impl Read,
    output: &mut impl Write,
    length: u64,
    copied: &mut u64,
    mut progress: impl FnMut(u64),
) -> Result<String> {
    let mut hash = Sha256::new();
    let mut buffer = vec![0u8; 1024 * 1024];
    *copied = 0;
    while *copied < length {
        let wanted = (length - *copied).min(buffer.len() as u64) as usize;
        let n = match input.read(&mut buffer[..wanted]) {
            Err(e) if e.kind() == std::io::ErrorKind::Interrupted => continue,
            result => result.with_context(|| format!("Source read failed at byte {}", *copied))?,
        };
        ensure!(n > 0, "Source ended early at byte {} of {length}", *copied);
        // Count successful partial writes too, so an incomplete image receipt remains accurate.
        let mut written = 0;
        while written < n {
            match output.write(&buffer[written..n]) {
                Err(e) if e.kind() == std::io::ErrorKind::Interrupted => continue,
                Err(e) => {
                    return Err(e)
                        .with_context(|| format!("Image write failed at byte {}", *copied));
                }
                Ok(0) => anyhow::bail!("Image write returned zero at byte {}", *copied),
                Ok(w) => {
                    written += w;
                    *copied += w as u64;
                    progress(*copied);
                }
            }
        }
        hash.update(&buffer[..n]);
    }
    output.flush().context("Cannot flush partition image")?;
    Ok(crate::model::hex(&hash.finalize()))
}

#[cfg(any(windows, test))]
fn verify_image(
    input: &mut impl Read,
    length: u64,
    expected: &str,
    progress: impl FnMut(u64),
) -> Result<String> {
    let mut bytes = 0;
    let digest = copy_exact(input, &mut std::io::sink(), length, &mut bytes, progress)?;
    let mut extra = [0u8; 1];
    ensure!(
        input.read(&mut extra)? == 0,
        "Saved image is longer than the source partition"
    );
    ensure!(
        digest == expected,
        "Saved image SHA-256 does not match the bytes acquired from the source"
    );
    Ok(digest)
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::io::{self, Cursor};

    fn volume(name: &str, disk: u32, bus: i32) -> Volume {
        Volume {
            volume_name: name.into(),
            extents: vec![Extent {
                disk_number: disk,
                starting_offset: 1024,
                length: 4096,
            }],
            disks: vec![Disk {
                disk_number: disk,
                bus_type: bus,
                removable: false,
                hotplug: false,
            }],
        }
    }

    #[test]
    fn destination_requires_a_different_known_external_physical_disk() {
        let source = volume("source", 0, 17);
        assert!(validate_destination(&source, &volume("external", 1, 7)).is_ok());
        assert!(
            validate_destination(&source, &volume("SOURCE", 1, 7))
                .unwrap_err()
                .to_string()
                .contains("same volume")
        );
        assert!(
            validate_destination(&source, &volume("other partition", 0, 7))
                .unwrap_err()
                .to_string()
                .contains("same physical disk")
        );
        assert!(validate_destination(&source, &volume("internal", 1, 17)).is_err());
        for bus in [0, 8, 9, 14, 15, 16, 20, 127, -1] {
            let mut target = volume("unknown", 1, bus);
            target.disks[0].hotplug = true;
            assert!(validate_destination(&source, &target).is_err());
            assert!(
                validate_destination(&volume("virtual source", 0, bus), &volume("usb", 1, 7))
                    .is_err()
            );
        }
        let mut target = volume("external eSATA", 1, 11);
        target.disks[0].hotplug = true;
        assert!(validate_destination(&source, &target).is_ok());
        target.extents.push(Extent {
            disk_number: 0,
            starting_offset: 1024,
            length: 4096,
        });
        target.disks.push(source.disks[0].clone());
        assert!(validate_destination(&source, &target).is_err());
        target.extents[1].disk_number = 2;
        assert!(validate_destination(&source, &target).is_err()); // missing disk identity
        target.extents.clear();
        assert!(validate_destination(&source, &target).is_err());
    }

    #[test]
    fn capacity_checks_include_reserve_overflow_and_fat32_limit() {
        assert!(validate_capacity(4096, 2 * 1024 * 1024, 0, "NTFS").is_ok());
        assert!(validate_capacity(4096, 4096, 0, "NTFS").is_err());
        assert!(validate_capacity(4096, u64::MAX, u64::MAX, "NTFS").is_err());
        assert!(validate_capacity(u64::MAX, u64::MAX, 0, "NTFS").is_err());
        assert!(validate_capacity(1u64 << 32, u64::MAX, 0, "fat32").is_err());
        assert!(validate_capacity(1u64 << 32, u64::MAX, 0, "exFAT").is_ok());
    }

    #[test]
    fn byte_exact_copy_hash_verification_and_corruption_detection() {
        let bytes: Vec<u8> = (0..2_100_123).map(|n| (n % 251) as u8).collect();
        let mut input = Cursor::new(&bytes);
        let mut output = Vec::new();
        let mut copied = 0;
        let mut progress = Vec::new();
        let hash = copy_exact(
            &mut input,
            &mut output,
            bytes.len() as u64,
            &mut copied,
            |n| progress.push(n),
        )
        .unwrap();
        assert_eq!(bytes, output);
        assert_eq!(copied, bytes.len() as u64);
        assert_eq!(hash, crate::model::sha256(&bytes));
        assert_eq!(progress.last(), Some(&copied));
        assert!(progress.windows(2).all(|w| w[0] < w[1]));
        assert!(verify_image(&mut Cursor::new(&output), copied, &hash, |_| {}).is_ok());
        output[4096] ^= 1;
        assert!(verify_image(&mut Cursor::new(&output), copied, &hash, |_| {}).is_err());
        assert!(
            verify_image(
                &mut Cursor::new(&bytes),
                copied - 1,
                &crate::model::sha256(&bytes[..bytes.len() - 1]),
                |_| {}
            )
            .is_err()
        );
    }

    struct BrokenWriter {
        bytes: Vec<u8>,
        limit: usize,
    }
    impl Write for BrokenWriter {
        fn write(&mut self, bytes: &[u8]) -> io::Result<usize> {
            let n = bytes.len().min(self.limit - self.bytes.len());
            if n == 0 {
                return Err(io::Error::other("simulated full disk"));
            }
            self.bytes.extend_from_slice(&bytes[..n]);
            Ok(n)
        }
        fn flush(&mut self) -> io::Result<()> {
            Ok(())
        }
    }

    #[test]
    fn source_truncation_and_partial_writes_never_claim_success() {
        let mut copied = 0;
        let mut out = Vec::new();
        assert!(copy_exact(&mut Cursor::new(b"short"), &mut out, 9, &mut copied, |_| {}).is_err());
        assert_eq!(copied, 5);
        assert_eq!(&out, b"short");
        let mut out = BrokenWriter {
            bytes: Vec::new(),
            limit: 3,
        };
        assert!(
            copy_exact(
                &mut Cursor::new(b"abcdef"),
                &mut out,
                6,
                &mut copied,
                |_| {}
            )
            .is_err()
        );
        assert_eq!(copied, 3);
        assert_eq!(&out.bytes, b"abc");
    }
}
