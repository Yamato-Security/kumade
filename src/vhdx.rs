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

//! Optional Windows-native NTFS evidence container. No full host-side staging.
use crate::{
    collect::Options,
    model::{Plan, Summary},
};
use anyhow::{Context, Result, ensure};
use std::path::Path;

const GIB: u64 = 1024 * 1024 * 1024;
const MIB: u64 = 1024 * 1024;
const MAX: u64 = 64 * 1024 * GIB;
pub const INITIALIZE_SCRIPT: &str = include_str!("../scripts/initialize_vhdx.ps1");

/// Space kept free inside the container for the manifests, inventories and the
/// seal: a fixed floor, room for every planned file's rows, and the per-writer
/// slack of the throttled free-space check. A payload that would consume it is
/// stopped and recorded as failed instead of filling the volume.
pub fn metadata_reserve(files: usize, threads: usize) -> u64 {
    let workers = threads.max(1).min(files.max(1));
    64 * MIB + files as u64 * 8 * 1024 + workers as u64 * 16 * MIB
}

/// The virtual capacity: the explicit size, or the known evidence with headroom,
/// the container reserve and 1 GiB per unknown-size item. Either way it is at
/// least `largest_stream` plus headroom: a sparse stream keeps its logical size
/// (a USN journal's `$J` is often larger than the evidence), and The Sleuth Kit
/// rejects an NTFS run longer than the volume, so a smaller container would
/// hold a journal that Autopsy cannot read.
pub fn capacity(
    known: u64,
    unknown: u64,
    explicit_gib: Option<u64>,
    reserve: u64,
    largest_stream: u64,
) -> Result<u64> {
    let minimum = known
        .checked_add(known / 4)
        .and_then(|v| v.checked_add(512 * MIB))
        .and_then(|v| v.checked_add(reserve))
        .context("VHDX capacity estimate overflow")?
        .max(
            largest_stream
                .checked_add(512 * MIB)
                .context("VHDX capacity estimate overflow")?,
        )
        .max(GIB);
    let capacity = if let Some(gib) = explicit_gib {
        gib.checked_mul(GIB).context("VHDX capacity overflow")?
    } else {
        minimum
            .checked_add(
                unknown
                    .checked_mul(GIB)
                    .context("Unknown-size capacity overflow")?,
            )
            .and_then(|v| v.checked_add(GIB - 1))
            .context("VHDX capacity overflow")?
            / GIB
            * GIB
    };
    ensure!(
        (GIB..=MAX).contains(&capacity),
        "VHDX capacity must be between 1 and 65536 GiB"
    );
    ensure!(
        capacity >= minimum,
        "VHDX capacity {} is smaller than the {} needed for the known evidence, its largest sparse stream, NTFS/metadata headroom and the container reserve",
        crate::collect::human_bytes(capacity),
        crate::collect::human_bytes(minimum)
    );
    Ok(capacity)
}

pub fn physical_disk_number(path: &str) -> Result<u32> {
    let text = path
        .strip_prefix(r"\\.\PhysicalDrive")
        .context("Unexpected virtual disk device path")?;
    ensure!(
        !text.is_empty() && text.bytes().all(|b| b.is_ascii_digit()),
        "Invalid virtual disk device number"
    );
    Ok(text.parse()?)
}

pub fn validate_volume_path(path: &str) -> Result<()> {
    let guid = path
        .strip_prefix(r"\\?\Volume{")
        .and_then(|s| s.strip_suffix("}\\"))
        .context("Unexpected NTFS volume path")?;
    uuid::Uuid::parse_str(guid).context("Invalid volume GUID")?;
    Ok(())
}

pub fn validate_new_image_path(path: &Path) -> Result<()> {
    ensure!(
        path.extension()
            .is_some_and(|s| s.eq_ignore_ascii_case("vhdx")),
        "--vhdx requires a .vhdx filename"
    );
    ensure!(
        !path
            .file_name()
            .is_some_and(|s| s.to_string_lossy().contains(':')),
        "VHDX destination cannot be an alternate stream"
    );
    match std::fs::symlink_metadata(path) {
        Ok(_) => anyhow::bail!("Refusing to overwrite an existing VHDX path (including links)"),
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => Ok(()),
        Err(error) => Err(error).context("Cannot inspect VHDX destination"),
    }
}

pub fn collect(
    plan: &Plan,
    image: &Path,
    explicit_gib: Option<u64>,
    options: &Options,
) -> Result<Summary> {
    #[cfg(windows)]
    {
        windows::collect(plan, image, explicit_gib, options, None)
    }
    #[cfg(not(windows))]
    {
        let _ = (plan, image, explicit_gib, options);
        anyhow::bail!("VHDX creation requires Windows; use directory output on this platform")
    }
}

/// Create the temporary NTFS disk for E01 packaging, without reporting it as the final output.
#[cfg(windows)]
pub(crate) fn collect_staged(
    plan: &Plan,
    image: &Path,
    explicit_gib: Option<u64>,
    options: &Options,
    maximum_capacity: u64,
) -> Result<Summary> {
    windows::collect(plan, image, explicit_gib, options, Some(maximum_capacity))
}

/// Reopen only an owned, finalized staging VHDX as a read-only virtual disk.
#[cfg(windows)]
pub(crate) fn read_staged_disk<T>(
    path: &Path,
    consume: impl FnOnce(&mut dyn std::io::Read, u64) -> Result<T>,
) -> Result<T> {
    windows::read_staged_disk(path, consume)
}

#[cfg(windows)]
mod windows {
    use super::*;
    use crate::{
        collect::{self, HostReserve},
        metadata, paths, platform, ui,
    };
    use anyhow::bail;
    use std::{
        fs::{self, File, OpenOptions},
        os::windows::{ffi::OsStrExt, fs::OpenOptionsExt, io::AsRawHandle},
        path::PathBuf,
        process::{Command, Stdio},
        ptr,
        time::Duration,
    };
    use windows_sys::Win32::{
        Foundation::*,
        Security::Authorization::ConvertStringSecurityDescriptorToSecurityDescriptorW,
        Storage::{FileSystem::*, Vhd::*},
        System::{IO::DeviceIoControl, Ioctl::*},
    };

    struct Image {
        handle: HANDLE,
        attached: bool,
        volume: PathBuf,
        path: PathBuf,
    }
    impl Drop for Image {
        fn drop(&mut self) {
            // On an error path the volume is still mounted. Flush and dismount it
            // (best effort) so the retained partial image holds consistent NTFS
            // structures before the disk disappears; a plain detach would leave
            // cached writes behind.
            if self.attached
                && !self.volume.as_os_str().is_empty()
                && let Ok(volume) = self.volume_handle()
            {
                let mut returned = 0;
                // SAFETY: owned volume handle of the destination created by this
                // guard; flush and dismount take no buffers.
                unsafe {
                    FlushFileBuffers(volume.as_raw_handle());
                    DeviceIoControl(
                        volume.as_raw_handle(),
                        FSCTL_DISMOUNT_VOLUME,
                        ptr::null(),
                        0,
                        ptr::null_mut(),
                        0,
                        &mut returned,
                        ptr::null_mut(),
                    );
                }
            }
            // SAFETY: this RAII guard owns only the handle it created. Attachment
            // has no permanent lifetime, so closing also releases it on errors.
            unsafe {
                if self.attached {
                    let error = DetachVirtualDisk(self.handle, DETACH_VIRTUAL_DISK_FLAG_NONE, 0);
                    if error != 0 {
                        eprintln!(
                            "VHDX cleanup: could not detach {} (Windows error {error}); inspect the image before reuse",
                            self.path.display()
                        );
                    }
                }
                CloseHandle(self.handle);
            }
        }
    }
    fn wide(path: &Path) -> Vec<u16> {
        path.as_os_str().encode_wide().chain(Some(0)).collect()
    }
    fn win(code: u32, action: &str) -> Result<()> {
        ensure!(
            code == 0,
            "{action}: {}",
            std::io::Error::from_raw_os_error(code as i32)
        );
        Ok(())
    }

    pub(super) fn read_staged_disk<T>(
        path: &Path,
        consume: impl FnOnce(&mut dyn std::io::Read, u64) -> Result<T>,
    ) -> Result<T> {
        let storage = VIRTUAL_STORAGE_TYPE {
            DeviceId: VIRTUAL_STORAGE_TYPE_DEVICE_VHDX,
            VendorId: VIRTUAL_STORAGE_TYPE_VENDOR_MICROSOFT,
        };
        let parameters = OPEN_VIRTUAL_DISK_PARAMETERS {
            Version: OPEN_VIRTUAL_DISK_VERSION_1,
            Anonymous: OPEN_VIRTUAL_DISK_PARAMETERS_0 {
                Version1: OPEN_VIRTUAL_DISK_PARAMETERS_0_0 {
                    RWDepth: OPEN_VIRTUAL_DISK_RW_DEPTH_DEFAULT,
                },
            },
        };
        let mut handle = ptr::null_mut();
        // SAFETY: terminated owned staging path, matching versioned parameters and output.
        win(
            // SAFETY: terminated staging path, versioned parameters, valid handle output.
            unsafe {
                OpenVirtualDisk(
                    &storage,
                    wide(path).as_ptr(),
                    VIRTUAL_DISK_ACCESS_READ,
                    OPEN_VIRTUAL_DISK_FLAG_NONE,
                    &parameters,
                    &mut handle,
                )
            },
            "OpenVirtualDisk (read-only staging)",
        )?;
        // An empty volume path deliberately avoids writable-volume cleanup in Drop.
        let mut image = Image {
            handle,
            attached: false,
            volume: PathBuf::new(),
            path: path.to_owned(),
        };
        let attach = ATTACH_VIRTUAL_DISK_PARAMETERS {
            Version: ATTACH_VIRTUAL_DISK_VERSION_1,
            ..Default::default()
        };
        // SAFETY: read-only attachment of this owned staging image, without a drive letter.
        win(
            // SAFETY: owned staging handle; read-only attachment without a drive letter.
            unsafe {
                AttachVirtualDisk(
                    handle,
                    ptr::null_mut(),
                    ATTACH_VIRTUAL_DISK_FLAG_READ_ONLY | ATTACH_VIRTUAL_DISK_FLAG_NO_DRIVE_LETTER,
                    0,
                    &attach,
                    ptr::null(),
                )
            },
            "AttachVirtualDisk (read-only staging)",
        )?;
        image.attached = true;
        let mut buffer = vec![0u16; 512];
        let mut bytes = (buffer.len() * 2) as u32;
        // SAFETY: owned virtual-disk handle and a correctly sized UTF-16 output buffer.
        win(
            // SAFETY: live owned handle and correctly sized UTF-16 output buffer.
            unsafe { GetVirtualDiskPhysicalPath(handle, &mut bytes, buffer.as_mut_ptr()) },
            "GetVirtualDiskPhysicalPath (staging)",
        )?;
        let end = buffer
            .iter()
            .position(|&c| c == 0)
            .context("Unterminated staging device path")?;
        let physical = String::from_utf16(&buffer[..end])?;
        physical_disk_number(&physical)?;
        let file = platform::open_source(Path::new(&physical))?;
        let (length, sector) = crate::raw::device_geometry(&file)?;
        let mut reader = crate::raw::DeviceReader::new(file, length, sector)?;
        let result = consume(&mut reader, length)?;
        drop(reader);
        // SAFETY: only the staging attachment owned above is released.
        win(
            // SAFETY: only the read-only staging attachment owned by this guard is released.
            unsafe { DetachVirtualDisk(handle, DETACH_VIRTUAL_DISK_FLAG_NONE, 0) },
            "DetachVirtualDisk (staging)",
        )?;
        image.attached = false;
        Ok(result)
    }
    fn powershell() -> Result<PathBuf> {
        let windows = std::env::var_os("SystemRoot").context("SystemRoot is unavailable")?;
        // A 32-bit collector must launch native PowerShell for Storage cmdlets.
        for prefix in ["Sysnative", "System32"] {
            let executable = PathBuf::from(&windows)
                .join(prefix)
                .join("WindowsPowerShell/v1.0/powershell.exe");
            if executable.is_file() {
                return Ok(executable);
            }
        }
        bail!("Windows PowerShell with Storage cmdlets is required to format a new NTFS VHDX")
    }
    impl Image {
        fn create(path: &Path, bytes: u64) -> Result<Self> {
            validate_new_image_path(path)?;
            ensure!(
                !platform::is_remote_windows_path(&path.display().to_string()),
                "VHDX output must be on a local volume"
            );
            let shell = powershell()?;
            let storage = VIRTUAL_STORAGE_TYPE {
                DeviceId: VIRTUAL_STORAGE_TYPE_DEVICE_VHDX,
                VendorId: VIRTUAL_STORAGE_TYPE_VENDOR_MICROSOFT,
            };
            let parameters = CREATE_VIRTUAL_DISK_PARAMETERS {
                Version: CREATE_VIRTUAL_DISK_VERSION_2,
                Anonymous: CREATE_VIRTUAL_DISK_PARAMETERS_0 {
                    Version2: CREATE_VIRTUAL_DISK_PARAMETERS_0_1 {
                        UniqueId: windows_sys::core::GUID::from_u128(
                            uuid::Uuid::new_v4().as_u128(),
                        ),
                        MaximumSize: bytes,
                        BlockSizeInBytes: 2 * MIB as u32,
                        SectorSizeInBytes: 512,
                        PhysicalSectorSizeInBytes: 4096,
                        ..Default::default()
                    },
                },
            };
            let sddl: Vec<_> = "D:P(A;;FA;;;SY)(A;;FA;;;BA)(A;;FA;;;OW)"
                .encode_utf16()
                .chain(Some(0))
                .collect();
            let mut descriptor = ptr::null_mut();
            // SAFETY: terminated SDDL and writable LocalAlloc descriptor output.
            ensure!(
                // SAFETY: terminated SDDL and writable LocalAlloc descriptor output.
                unsafe {
                    ConvertStringSecurityDescriptorToSecurityDescriptorW(
                        sddl.as_ptr(),
                        1,
                        &mut descriptor,
                        ptr::null_mut(),
                    )
                } != 0,
                "Cannot build private VHDX permissions"
            );
            let mut handle = ptr::null_mut();
            // SAFETY: correctly versioned parameters, terminated absolute new file path, valid descriptor and handle output.
            let code = unsafe {
                CreateVirtualDisk(
                    &storage,
                    wide(path).as_ptr(),
                    VIRTUAL_DISK_ACCESS_NONE,
                    descriptor,
                    CREATE_VIRTUAL_DISK_FLAG_NONE,
                    0,
                    &parameters,
                    ptr::null(),
                    &mut handle,
                )
            };
            // SAFETY: CreateVirtualDisk has finished using this API-allocated descriptor.
            unsafe {
                LocalFree(descriptor);
            }
            win(code, "CreateVirtualDisk")?;
            let mut image = Self {
                handle,
                attached: false,
                volume: PathBuf::new(),
                path: path.to_owned(),
            };
            let attach = ATTACH_VIRTUAL_DISK_PARAMETERS {
                Version: ATTACH_VIRTUAL_DISK_VERSION_1,
                ..Default::default()
            };
            // SAFETY: only this newly created virtual disk is attached; no drive letter/permanent lifetime is requested.
            win(
                // SAFETY: only this newly created virtual disk is attached; no drive letter/permanent lifetime is requested.
                unsafe {
                    AttachVirtualDisk(
                        handle,
                        ptr::null_mut(),
                        ATTACH_VIRTUAL_DISK_FLAG_NO_DRIVE_LETTER,
                        0,
                        &attach,
                        ptr::null(),
                    )
                },
                "AttachVirtualDisk",
            )?;
            image.attached = true;
            let mut buffer = vec![0u16; 512];
            let mut length = (buffer.len() * 2) as u32;
            // SAFETY: owned handle and correctly byte-sized UTF-16 output.
            win(
                // SAFETY: owned handle and correctly byte-sized UTF-16 output.
                unsafe { GetVirtualDiskPhysicalPath(handle, &mut length, buffer.as_mut_ptr()) },
                "GetVirtualDiskPhysicalPath",
            )?;
            let end = buffer
                .iter()
                .position(|&x| x == 0)
                .context("Unterminated virtual disk path")?;
            let number = physical_disk_number(&String::from_utf16(&buffer[..end])?)?;
            let output = Command::new(shell)
                .args([
                    "-NoLogo",
                    "-NoProfile",
                    "-NonInteractive",
                    "-Command",
                    INITIALIZE_SCRIPT,
                ])
                .env("KUMADE_VHDX_PATH", path)
                .env("KUMADE_VHDX_DISK_NUMBER", number.to_string())
                .stdin(Stdio::null())
                .output()
                .context("Cannot run Windows Storage initialization")?;
            ensure!(
                output.status.success(),
                "New VHDX initialization failed; the image was retained: {}",
                String::from_utf8_lossy(&output.stderr)
            );
            let result: serde_json::Value =
                serde_json::from_slice(&output.stdout).context("Invalid Windows Storage result")?;
            ensure!(
                result["DiskNumber"].as_u64() == Some(u64::from(number))
                    && result["FileSystem"] == "NTFS",
                "Initialized disk identity/filesystem mismatch"
            );
            let volume = result["VolumePath"]
                .as_str()
                .context("Missing formatted volume path")?;
            validate_volume_path(volume)?;
            image.volume = PathBuf::from(volume);
            let handle = image.volume_handle()?;
            let mut extents = VOLUME_DISK_EXTENTS::default();
            let mut returned = 0;
            // SAFETY: raw volume handle and fixed buffer for exactly one extent; additional extents are rejected by the buffer/error check.
            ensure!(
                // SAFETY: raw volume handle and fixed buffer for exactly one extent; additional extents are rejected by the buffer/error check.
                unsafe {
                    DeviceIoControl(
                        handle.as_raw_handle(),
                        IOCTL_VOLUME_GET_VOLUME_DISK_EXTENTS,
                        ptr::null(),
                        0,
                        (&mut extents as *mut VOLUME_DISK_EXTENTS).cast(),
                        size_of::<VOLUME_DISK_EXTENTS>() as u32,
                        &mut returned,
                        ptr::null_mut(),
                    )
                } != 0,
                "Cannot validate the new volume's disk extent"
            );
            ensure!(
                extents.NumberOfDiskExtents == 1 && extents.Extents[0].DiskNumber == number,
                "Formatted volume is not on the created VHDX"
            );
            Ok(image)
        }
        fn volume_handle(&self) -> Result<File> {
            let path = self
                .volume
                .to_str()
                .context("Invalid volume path")?
                .trim_end_matches('\\');
            Ok(OpenOptions::new()
                .access_mode(GENERIC_READ | GENERIC_WRITE)
                .share_mode(FILE_SHARE_READ | FILE_SHARE_WRITE)
                .open(path)?)
        }
        fn finish(mut self) -> Result<()> {
            let volume = self.volume_handle()?;
            // SAFETY: owned writable volume handle; every payload/metadata file is closed.
            ensure!(
                // SAFETY: owned writable volume handle; every payload/metadata file is closed.
                unsafe { FlushFileBuffers(volume.as_raw_handle()) } != 0,
                "Cannot flush evidence volume: {}",
                std::io::Error::last_os_error()
            );
            let mut returned = 0;
            let mut locked = false;
            for _ in 0..10 {
                // SAFETY: volume-control operation on the newly created destination only; no buffers.
                if unsafe {
                    DeviceIoControl(
                        volume.as_raw_handle(),
                        FSCTL_LOCK_VOLUME,
                        ptr::null(),
                        0,
                        ptr::null_mut(),
                        0,
                        &mut returned,
                        ptr::null_mut(),
                    )
                } != 0
                {
                    locked = true;
                    break;
                }
                std::thread::sleep(Duration::from_millis(200));
            }
            if !locked {
                // Another process (typically an on-access scanner) still holds a
                // handle inside the new volume. Every evidence file is closed and
                // the volume is flushed, so a forced dismount loses nothing of
                // ours; failing the whole acquisition here would discard a
                // complete, sealed result.
                eprintln!(
                    "Notice: the evidence volume could not be locked ({}); dismounting it anyway because all evidence files are closed and flushed",
                    std::io::Error::last_os_error()
                );
            }
            // SAFETY: destination volume was flushed (and locked when possible); this dismount never targets a source.
            ensure!(
                // SAFETY: destination volume was flushed (and locked when possible); this dismount never targets a source.
                unsafe {
                    DeviceIoControl(
                        volume.as_raw_handle(),
                        FSCTL_DISMOUNT_VOLUME,
                        ptr::null(),
                        0,
                        ptr::null_mut(),
                        0,
                        &mut returned,
                        ptr::null_mut(),
                    )
                } != 0,
                "Cannot dismount evidence volume"
            );
            drop(volume);
            // SAFETY: the owned virtual disk is the destination created by this guard.
            win(
                // SAFETY: the owned virtual disk is the destination created by this guard.
                unsafe { DetachVirtualDisk(self.handle, DETACH_VIRTUAL_DISK_FLAG_NONE, 0) },
                "DetachVirtualDisk",
            )?;
            self.attached = false;
            Ok(())
        }
    }
    pub(super) fn collect(
        plan: &Plan,
        path: &Path,
        explicit_gib: Option<u64>,
        options: &Options,
        staging_limit: Option<u64>,
    ) -> Result<Summary> {
        metadata::enable_privileges()?;
        // Raw-only NTFS candidates have no planning-time size; read them from
        // the raw provider before the container is sized.
        let sizes = metadata::raw_candidate_sizes(plan);
        let raw_known = sizes.known;
        let known = plan
            .known_bytes
            .checked_add(raw_known)
            .context("Known evidence size overflow")?;
        let reserve = metadata_reserve(plan.files.len(), options.threads);
        let bytes = capacity(
            known,
            sizes.unknown,
            explicit_gib,
            reserve,
            sizes.largest_stream,
        )?;
        ensure!(
            staging_limit.is_none_or(|limit| bytes <= limit),
            "NTFS capacity exceeds the E01 segment-set limit; narrow the collection scope"
        );
        let path = paths::resolve_future(path)?;
        validate_new_image_path(&path)?;
        let parent = path.parent().context("VHDX output has no parent")?;
        fs::create_dir_all(parent)?;
        let required = known
            .checked_add(512 * MIB)
            .and_then(|v| v.checked_add(options.reserve_bytes))
            .context("Host free-space estimate overflow")?;
        ensure!(
            fs2::available_space(parent)? >= required,
            "Insufficient physical host space for known evidence, VHDX overhead and the free-space reserve"
        );
        if !options.quiet {
            ui::field("VHDX container", path.display());
            ui::field("Virtual capacity", collect::human_bytes(bytes));
            ui::field("Container reserve", collect::human_bytes(reserve));
            if raw_known > 0 {
                ui::field("Raw NTFS sizes", collect::human_bytes(raw_known));
            }
            ui::status("Creating and formatting the new NTFS evidence container…");
        }
        let image = Image::create(&path, bytes)?;
        let inner = Options {
            threads: options.threads,
            reserve_bytes: reserve,
            quiet: options.quiet,
            verbose: options.verbose,
            ntfs_metadata: true,
            live_info: options.live_info.clone().map(|mut config| {
                config.reserve_bytes = reserve;
                config.host_reserve = Some(HostReserve {
                    path: parent.to_owned(),
                    bytes: options.reserve_bytes,
                });
                config
            }),
            host_reserve: Some(HostReserve {
                path: parent.to_owned(),
                // Each active worker can write up to 16 MiB between checks.
                // Account for that slack on the physical host as well.
                bytes: options
                    .reserve_bytes
                    .saturating_add(options.threads.min(plan.files.len().max(1)) as u64 * 16 * MIB),
            }),
        };
        // The planned sources were frozen before this destination was attached.
        let result = collect::collect(plan, &image.volume, &inner);
        let (_, summary) = result.with_context(|| {
            format!(
                "Collection failed; partial VHDX retained at {}",
                path.display()
            )
        })?;
        if !options.quiet {
            ui::status("Flushing and detaching the evidence container…");
        }
        image
            .finish()
            .with_context(|| format!("VHDX finalization failed: {}", path.display()))?;
        if !options.quiet && staging_limit.is_none() {
            ui::field(
                "Results saved",
                format!(
                    "{} ( 1 file / {} )",
                    path.display(),
                    collect::human_bytes(fs::metadata(&path)?.len())
                ),
            );
        }
        Ok(summary)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn capacity_is_bounded_and_counts_unknown_stream_headroom() {
        assert_eq!(capacity(0, 0, None, 0, 0).unwrap(), GIB);
        assert_eq!(capacity(0, 2, None, 0, 0).unwrap(), 3 * GIB);
        assert!(capacity(0, 0, Some(0), 0, 0).is_err());
        assert!(capacity(0, 0, Some(65537), 0, 0).is_err());
        assert!(capacity(2 * GIB, 0, Some(1), 0, 0).is_err());
        assert!(capacity(u64::MAX, 0, None, 0, 0).is_err());
        assert!(capacity(0, u64::MAX, None, 0, 0).is_err());
        assert!(capacity(0, 0, Some(u64::MAX), 0, 0).is_err());
    }
    #[test]
    fn capacity_holds_the_largest_sparse_stream_at_its_logical_size() {
        // A 3.3 GiB sparse USN journal in a 1 GiB collection: the container must
        // hold its logical size, or The Sleuth Kit cannot read the journal.
        let journal = 3 * GIB + 300 * MIB;
        assert_eq!(capacity(0, 0, None, 0, journal).unwrap(), 4 * GIB);
        assert_eq!(capacity(0, 0, None, 0, 512 * MIB).unwrap(), GIB);
        assert!(capacity(0, 0, Some(3), 0, journal).is_err());
        assert_eq!(capacity(0, 0, Some(4), 0, journal).unwrap(), 4 * GIB);
        assert!(capacity(0, 0, None, 0, u64::MAX).is_err());
    }
    #[test]
    fn container_reserve_is_part_of_the_minimum_capacity() {
        assert_eq!(metadata_reserve(0, 1), 80 * MIB);
        assert_eq!(metadata_reserve(0, 0), 80 * MIB);
        assert_eq!(
            metadata_reserve(100_000, 8),
            64 * MIB + 100_000 * 8 * 1024 + 128 * MIB
        );
        // 512 MiB headroom + 3 GiB reserve rounds up to a 4 GiB container.
        assert_eq!(capacity(0, 0, None, 3 * GIB, 0).unwrap(), 4 * GIB);
        assert!(capacity(0, 0, Some(1), 600 * MIB, 0).is_err());
        assert_eq!(capacity(0, 0, Some(2), 600 * MIB, 0).unwrap(), 2 * GIB);
        assert!(capacity(0, 0, None, u64::MAX, 0).is_err());
        // High CPU counts must not reserve slack for workers with no tasks.
        assert_eq!(metadata_reserve(2, 256), 96 * MIB + 2 * 8 * 1024);
    }
    #[test]
    fn device_and_volume_identity_validation_rejects_unrelated_paths() {
        assert_eq!(physical_disk_number(r"\\.\PhysicalDrive12").unwrap(), 12);
        for path in [
            r"C:\",
            r"\\.\PhysicalDrive-1",
            r"\\.\PhysicalDrive1;format",
            r"\\.\PhysicalDrive",
        ] {
            assert!(physical_disk_number(path).is_err());
        }
        validate_volume_path(r"\\?\Volume{12345678-1234-4234-9234-123456789abc}\").unwrap();
        for path in [
            r"C:\",
            r"\\?\Volume{bad}\",
            r"\\?\Volume{12345678-1234-4234-9234-123456789abc}\evil",
        ] {
            assert!(validate_volume_path(path).is_err());
        }
    }
    #[test]
    fn image_destination_refuses_existing_files_and_dangling_links() {
        let tmp = tempfile::tempdir().unwrap();
        let image = tmp.path().join("evidence.vhdx");
        validate_new_image_path(&image).unwrap();
        std::fs::write(&image, b"existing evidence").unwrap();
        assert!(validate_new_image_path(&image).is_err());
        assert_eq!(std::fs::read(&image).unwrap(), b"existing evidence");
        assert!(validate_new_image_path(&tmp.path().join("file:stream.vhdx")).is_err());
        #[cfg(unix)]
        {
            let link = tmp.path().join("link.vhdx");
            std::os::unix::fs::symlink(tmp.path().join("absent"), &link).unwrap();
            assert!(validate_new_image_path(&link).is_err());
        }
    }

    #[test]
    fn formatter_uses_created_disk_identity_and_never_assigns_a_letter() {
        assert!(INITIALIZE_SCRIPT.contains("$disk.Number -ne $number"));
        assert!(INITIALIZE_SCRIPT.contains("$disk.PartitionStyle -ne 'RAW'"));
        assert!(INITIALIZE_SCRIPT.contains("$disk.IsBoot -or $disk.IsSystem"));
        assert!(INITIALIZE_SCRIPT.contains("-AssignDriveLetter:$false"));
        assert!(INITIALIZE_SCRIPT.contains("$env:KUMADE_VHDX_PATH"));
    }
}
