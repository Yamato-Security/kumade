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

use super::*;
use anyhow::{Context, bail};
use std::{
    fs::{self, File, OpenOptions},
    io::{Seek, SeekFrom},
    mem::{offset_of, size_of},
    os::windows::{ffi::OsStrExt, fs::OpenOptionsExt, io::AsRawHandle},
    path::Path,
    ptr,
};
use windows_sys::Win32::{
    Foundation::{ERROR_INSUFFICIENT_BUFFER, ERROR_MORE_DATA},
    Storage::FileSystem::*,
    System::{IO::DeviceIoControl, Ioctl::*},
};

fn wide(path: &Path) -> Vec<u16> {
    path.as_os_str().encode_wide().chain(Some(0)).collect()
}

/// Accept volume identifiers, never physical disks, remote shares or an ordinary source file.
fn source_root(text: &str) -> Result<String> {
    let t = text
        .strip_prefix(r"\\.\")
        .unwrap_or(text)
        .trim_end_matches('\\');
    let b = t.as_bytes();
    if b.len() == 2 && b[0].is_ascii_alphabetic() && b[1] == b':' {
        return Ok(format!("{}:\\", char::from(b[0].to_ascii_uppercase())));
    }
    let prefix = r"\\?\Volume{";
    if t.len() > prefix.len()
        && t.get(..prefix.len())
            .is_some_and(|p| p.eq_ignore_ascii_case(prefix))
        && t.ends_with('}')
    {
        let guid =
            uuid::Uuid::parse_str(&t[prefix.len()..t.len() - 1]).context("Invalid volume GUID")?;
        return Ok(format!(r"\\?\Volume{{{guid}}}\"));
    }
    bail!(
        r"Source must identify a logical volume, for example C:, \\.\C: or \\?\Volume{{GUID}}\; physical disks and source files are not accepted"
    )
}

/// Bounded, retryable metadata IOCTLs. Parse returned bytes rather than casting
/// untrusted variable-length responses to Rust structs (some have bool fields).
fn ioctl(file: &File, code: u32, input: &[u8], initial: usize) -> Result<Vec<u8>> {
    let mut capacity = initial;
    loop {
        ensure!(
            capacity <= 1024 * 1024,
            "Storage metadata exceeds safety limit"
        );
        let mut data = vec![0u8; capacity];
        let mut returned = 0u32;
        // SAFETY: owned synchronous handle, live input/output buffers with their actual lengths.
        let ok = unsafe {
            DeviceIoControl(
                file.as_raw_handle(),
                code,
                if input.is_empty() {
                    ptr::null()
                } else {
                    input.as_ptr().cast()
                },
                input.len() as u32,
                if data.is_empty() {
                    ptr::null_mut()
                } else {
                    data.as_mut_ptr().cast()
                },
                data.len() as u32,
                &mut returned,
                ptr::null_mut(),
            )
        };
        if ok != 0 {
            ensure!(
                returned as usize <= data.len(),
                "Invalid storage metadata length"
            );
            data.truncate(returned as usize);
            return Ok(data);
        }
        let error = std::io::Error::last_os_error();
        if initial > 0
            && matches!(error.raw_os_error(),Some(n) if n==ERROR_MORE_DATA as i32 || n==ERROR_INSUFFICIENT_BUFFER as i32)
        {
            capacity = capacity
                .checked_mul(2)
                .context("Storage metadata size overflows")?;
            continue;
        }
        return Err(error).with_context(|| format!("Storage query 0x{code:08x} failed"));
    }
}

fn u32_at(data: &[u8], offset: usize) -> Result<u32> {
    let bytes = data
        .get(offset..offset.checked_add(4).context("Offset overflow")?)
        .context("Truncated storage metadata")?;
    Ok(u32::from_le_bytes(bytes.try_into()?))
}
fn i64_at(data: &[u8], offset: usize) -> Result<i64> {
    let bytes = data
        .get(offset..offset.checked_add(8).context("Offset overflow")?)
        .context("Truncated storage metadata")?;
    Ok(i64::from_le_bytes(bytes.try_into()?))
}

fn parse_extents(data: &[u8]) -> Result<Vec<Extent>> {
    let count = u32_at(data, offset_of!(VOLUME_DISK_EXTENTS, NumberOfDiskExtents))? as usize;
    ensure!((1..=4096).contains(&count), "Invalid disk extent count");
    let first = offset_of!(VOLUME_DISK_EXTENTS, Extents);
    let required = first
        .checked_add(count * size_of::<DISK_EXTENT>())
        .context("Extent size overflow")?;
    ensure!(data.len() >= required, "Truncated volume disk extents");
    (0..count)
        .map(|i| {
            let start = first + i * size_of::<DISK_EXTENT>();
            let offset = i64_at(data, start + offset_of!(DISK_EXTENT, StartingOffset))?;
            let length = i64_at(data, start + offset_of!(DISK_EXTENT, ExtentLength))?;
            ensure!(offset >= 0 && length > 0, "Invalid physical disk extent");
            Ok(Extent {
                disk_number: u32_at(data, start + offset_of!(DISK_EXTENT, DiskNumber))?,
                starting_offset: offset as u64,
                length: length as u64,
            })
        })
        .collect()
}

fn disk_info(number: u32) -> Result<Disk> {
    let disk = OpenOptions::new()
        .access_mode(0)
        .share_mode(FILE_SHARE_READ | FILE_SHARE_WRITE)
        .open(format!(r"\\.\PhysicalDrive{number}"))?;
    let mut input = vec![0u8; size_of::<STORAGE_PROPERTY_QUERY>()];
    let property = offset_of!(STORAGE_PROPERTY_QUERY, PropertyId);
    let query_type = offset_of!(STORAGE_PROPERTY_QUERY, QueryType);
    input[property..property + 4].copy_from_slice(&StorageDeviceProperty.to_le_bytes());
    input[query_type..query_type + 4].copy_from_slice(&PropertyStandardQuery.to_le_bytes());
    let data = ioctl(&disk, IOCTL_STORAGE_QUERY_PROPERTY, &input, 4096)?;
    let bus_type = u32_at(&data, offset_of!(STORAGE_DEVICE_DESCRIPTOR, BusType))? as i32;
    let removable = *data
        .get(offset_of!(STORAGE_DEVICE_DESCRIPTOR, RemovableMedia))
        .context("Truncated device descriptor")?
        != 0;
    // Some USB drivers omit this optional IOCTL; bus/removable identity remains mandatory.
    let hotplug = ioctl(
        &disk,
        IOCTL_STORAGE_GET_HOTPLUG_INFO,
        &[],
        size_of::<STORAGE_HOTPLUG_INFO>(),
    )
    .ok()
    .and_then(|bytes| {
        bytes
            .get(offset_of!(STORAGE_HOTPLUG_INFO, DeviceHotplug))
            .copied()
    })
    .is_some_and(|b| b != 0);
    Ok(Disk {
        disk_number: number,
        bus_type,
        removable,
        hotplug,
    })
}

fn volume_info(name: &str, handle: &File) -> Result<Volume> {
    let extents = parse_extents(&ioctl(
        handle,
        IOCTL_VOLUME_GET_VOLUME_DISK_EXTENTS,
        &[],
        4096,
    )?)?;
    let mut numbers: Vec<_> = extents.iter().map(|e| e.disk_number).collect();
    numbers.sort_unstable();
    numbers.dedup();
    let disks = numbers
        .into_iter()
        .map(disk_info)
        .collect::<Result<Vec<_>>>()?;
    Ok(Volume {
        volume_name: name.into(),
        extents,
        disks,
    })
}

fn open_volume(name: &str, read: bool) -> Result<File> {
    let mut opts = OpenOptions::new();
    opts.share_mode(FILE_SHARE_READ | FILE_SHARE_WRITE);
    if read {
        opts.read(true).custom_flags(FILE_FLAG_NO_BUFFERING);
    } else {
        opts.access_mode(0);
    }
    opts.open(name.trim_end_matches('\\'))
        .with_context(|| format!("Cannot open {name}; run as Administrator"))
}

fn destination_info(path: &Path) -> Result<Volume> {
    let name = crate::platform::volume_identity(path)?
        .context("Destination must be a local external drive; network shares are not supported")?;
    volume_info(&name, &open_volume(&name, false)?)
}

fn filesystem(name: &str) -> Result<String> {
    let root = wide(Path::new(name));
    let mut fsname = [0u16; 64];
    // SAFETY: terminated volume name and a writable UTF-16 filesystem-name buffer.
    ensure!(
        // SAFETY: terminated volume name and writable UTF-16 filesystem-name buffer.
        unsafe {
            GetVolumeInformationW(
                root.as_ptr(),
                ptr::null_mut(),
                0,
                ptr::null_mut(),
                ptr::null_mut(),
                ptr::null_mut(),
                fsname.as_mut_ptr(),
                fsname.len() as u32,
            )
        } != 0,
        "Cannot identify destination filesystem: {}",
        std::io::Error::last_os_error()
    );
    Ok(String::from_utf16(
        &fsname[..fsname
            .iter()
            .position(|&c| c == 0)
            .context("Unterminated filesystem name")?],
    )?)
}

fn handle_volume(file: &File) -> Result<Volume> {
    let mut buffer = vec![0u16; 32768];
    // SAFETY: open file handle and a writable buffer with the advertised UTF-16 capacity.
    let n = unsafe {
        GetFinalPathNameByHandleW(
            file.as_raw_handle(),
            buffer.as_mut_ptr(),
            buffer.len() as u32,
            VOLUME_NAME_GUID,
        )
    } as usize;
    ensure!(
        n > 0 && n < buffer.len(),
        "Cannot resolve actual image volume: {}",
        std::io::Error::last_os_error()
    );
    let path = String::from_utf16(&buffer[..n])?;
    let end = path
        .find("}\\")
        .context("Image is not on a volume-GUID path")?
        + 2;
    destination_info(Path::new(&path[..end]))
}

fn write_report(file: &mut File, report: &Report) -> Result<()> {
    file.seek(SeekFrom::Start(0))?;
    file.set_len(0)?;
    serde_json::to_writer_pretty(&mut *file, report)?;
    file.write_all(b"\n")?;
    file.sync_all()?;
    Ok(())
}

fn new_output(path: &Path) -> Result<File> {
    // Refuse pre-existing files and do not allow another process to replace the open image.
    Ok(OpenOptions::new()
        .read(true)
        .write(true)
        .create_new(true)
        .share_mode(FILE_SHARE_READ)
        .custom_flags(FILE_FLAG_OPEN_REPARSE_POINT)
        .open(path)?)
}

fn promote_image(partial: &Path, image: &Path) -> Result<()> {
    // SAFETY: terminated paths; flags=0 forbids replacing an existing destination.
    ensure!(
        // SAFETY: terminated paths, flags=0 disallow replacement.
        unsafe { MoveFileExW(wide(partial).as_ptr(), wide(image).as_ptr(), 0) } != 0,
        "Cannot finalize image without overwriting an existing file: {}",
        std::io::Error::last_os_error()
    );
    Ok(())
}

pub(super) fn run(options: &Options) -> Result<()> {
    crate::platform::enable_backup_privilege()?;
    let root = source_root(&options.source)?;
    let name = crate::platform::volume_identity(Path::new(&root))?
        .context("Source must be a local logical volume")?;
    let source_file = open_volume(&name, true)?;
    let source = volume_info(&name, &source_file)?;
    let length_data = ioctl(&source_file, IOCTL_DISK_GET_LENGTH_INFO, &[], 8)?;
    let length =
        u64::try_from(i64_at(&length_data, 0)?).context("Invalid source partition length")?;
    let geometry = ioctl(
        &source_file,
        IOCTL_DISK_GET_DRIVE_GEOMETRY,
        &[],
        size_of::<DISK_GEOMETRY>(),
    )?;
    let sector = u32_at(&geometry, offset_of!(DISK_GEOMETRY, BytesPerSector))?;
    ensure!(
        (512..=4096).contains(&sector)
            && sector.is_power_of_two()
            && length > 0
            && length.is_multiple_of(u64::from(sector)),
        "Invalid source sector geometry"
    );
    // These checks precede any output-directory or file creation.
    let parent = crate::paths::resolve_future(&options.output)?;
    let destination = destination_info(&parent)?;
    validate_destination(&source, &destination)?;
    ensure!(
        source.extents[0].length == length,
        "Source extent and reported partition length disagree"
    );
    let fsname = filesystem(&destination.volume_name)?;
    validate_capacity(
        length,
        fs2::available_space(Path::new(&destination.volume_name))?,
        options.reserve_mib,
        &fsname,
    )?;
    // Required to include the final sectors beyond the filesystem's normal read boundary.
    ioctl(&source_file, FSCTL_ALLOW_EXTENDED_DASD_IO, &[], 0)
        .context("Cannot enable complete read-only partition access")?;
    let mut source_reader = crate::raw::DeviceReader::new(source_file, length, sector as usize)?;
    fs::create_dir_all(&parent)?;
    let computer = crate::platform::computer_name();
    let start = chrono::Utc::now();
    let output = parent.join(format!(
        "{}_{}",
        crate::paths::encode_component(&computer),
        start.format("%Y-%m-%d_%H-%M-%S")
    ));
    fs::create_dir(&output).context("Output run already exists; no files were overwritten")?;
    crate::platform::protect_output_root(&output)?;
    let label = if root.len() == 3 {
        root[..1].to_owned()
    } else {
        "Volume".into()
    };
    let image_name = format!("{label}.dd");
    let partial_name = format!("{image_name}.partial");
    let partial = output.join(&partial_name);
    let image = output.join(&image_name);
    let mut image_file = new_output(&partial)?;
    // Revalidate the volume of the file actually opened, guarding mount-point/path aliases.
    let actual_destination = handle_volume(&image_file)?;
    validate_destination(&source, &actual_destination)?;
    ensure!(
        actual_destination
            .volume_name
            .eq_ignore_ascii_case(&destination.volume_name),
        "Destination volume changed during setup"
    );
    let mut report_file = new_output(&output.join("ForensicCopy.json"))?;
    let mut report=Report {schema_version:1,version:env!("CARGO_PKG_VERSION").into(),computer,started_utc:start.to_rfc3339_opts(chrono::SecondsFormat::Nanos,true),finished_utc:None,status:"InProgress".into(),source,destination:actual_destination,expected_bytes:length,bytes_copied:0,logical_sector_size:sector,image:partial_name,acquired_sha256:None,image_sha256:None,verified:false,consistency:"Sequential raw read; no snapshot or source lock. A live writable source can change during acquisition.".into(),error:None};
    write_report(&mut report_file, &report)?;
    if !options.quiet {
        crate::ui::banner();
        crate::ui::field("Start time", &report.started_utc);
        crate::ui::field("Source", &report.source.volume_name);
        crate::ui::field("Partition size", crate::collect::human_bytes(length));
        crate::ui::field("Destination", output.display());
        crate::ui::status(&report.consistency);
        crate::ui::heading("Copying partition. Please wait.");
    }
    let progress = crate::ui::progress_bar(length, options.quiet);
    let result = (|| -> Result<()> {
        report.acquired_sha256 = Some(copy_exact(
            &mut source_reader,
            &mut image_file,
            length,
            &mut report.bytes_copied,
            |n| progress.set_position(n),
        )?);
        image_file
            .sync_all()
            .context("Cannot sync partition image")?;
        ensure!(
            image_file.metadata()?.len() == length,
            "Saved image length differs from source partition"
        );
        progress.finish_and_clear();
        if !options.quiet {
            crate::ui::heading("Verifying partition image. Please wait.");
        }
        let verify_progress = crate::ui::progress_bar(length, options.quiet);
        image_file.seek(SeekFrom::Start(0))?;
        let verified = verify_image(
            &mut image_file,
            length,
            report
                .acquired_sha256
                .as_deref()
                .context("Missing acquisition hash")?,
            |n| verify_progress.set_position(n),
        );
        verify_progress.finish_and_clear();
        report.image_sha256 = Some(verified?);
        Ok(())
    })();
    progress.finish_and_clear();
    // Close the output before its no-replace rename (Windows sharing rules).
    drop(image_file);
    let result = result.and_then(|()| promote_image(&partial, &image));
    report.finished_utc = Some(crate::model::utc_now());
    if let Err(error) = result {
        report.status = "Failed".into();
        report.error = Some(format!("{error:#}"));
        write_report(&mut report_file, &report)
            .context("Imaging failed and its failure receipt could not be saved")?;
        return Err(error).with_context(|| {
            format!(
                "Incomplete image retained: {}; report: {}",
                partial.display(),
                output.join("ForensicCopy.json").display()
            )
        });
    }
    report.image = image_name;
    report.verified = true;
    report.status = "Verified".into();
    write_report(&mut report_file, &report)?;
    if !options.quiet {
        crate::ui::field(
            "Bytes copied",
            crate::collect::human_bytes(report.bytes_copied),
        );
        crate::ui::field(
            "SHA-256",
            report.image_sha256.as_deref().unwrap_or_default(),
        );
        crate::ui::field("Verification", "Passed");
        crate::ui::field("Results saved", output.display());
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::path::PathBuf;
    #[test]
    fn source_parser_accepts_volumes_but_never_disk_devices_files_or_shares() {
        for text in ["C:", "c:\\", r"\\.\C:"] {
            assert_eq!(source_root(text).unwrap(), "C:\\");
        }
        let name = r"\\?\Volume{6f6b8a78-15c5-4679-8123-e0d5adebeaaa}\";
        assert_eq!(source_root(name).unwrap(), name);
        for text in [
            r"\\.\PhysicalDrive0",
            r"\\server\share",
            "C:/file.dd",
            "C:\\Windows",
            "C",
            "日".repeat(20).as_str(),
            r"\\?\Volume{bad}\",
        ] {
            assert!(source_root(text).is_err(), "{text}");
        }
    }
    #[test]
    fn variable_extent_responses_are_bounded_and_reject_truncation() {
        let first = offset_of!(VOLUME_DISK_EXTENTS, Extents);
        let size = size_of::<DISK_EXTENT>();
        let mut bytes = vec![0u8; first + 2 * size];
        bytes[..4].copy_from_slice(&2u32.to_le_bytes());
        for (i, disk) in [3u32, 9].into_iter().enumerate() {
            let start = first + i * size;
            bytes[start..start + 4].copy_from_slice(&disk.to_le_bytes());
            let off = start + offset_of!(DISK_EXTENT, StartingOffset);
            bytes[off..off + 8].copy_from_slice(&4096i64.to_le_bytes());
            let len = start + offset_of!(DISK_EXTENT, ExtentLength);
            bytes[len..len + 8].copy_from_slice(&8192i64.to_le_bytes());
        }
        assert_eq!(parse_extents(&bytes).unwrap()[1].disk_number, 9);
        assert!(parse_extents(&bytes[..bytes.len() - 1]).is_err());
        bytes[..4].copy_from_slice(&u32::MAX.to_le_bytes());
        assert!(parse_extents(&bytes).is_err());
        bytes[..4].fill(0);
        assert!(parse_extents(&bytes).is_err());
    }

    #[test]
    fn real_volume_queries_reject_a_same_disk_destination_before_writing() -> Result<()> {
        let drive = std::env::var("SystemDrive").context("Missing Windows system drive")?;
        let output = PathBuf::from(format!("{drive}\\Kumade-Rejected-{}", uuid::Uuid::new_v4()));
        let result = run(&Options {
            source: drive,
            output: output.clone(),
            reserve_mib: 0,
            quiet: true,
        });
        let message = format!("{:#}", result.unwrap_err());
        ensure!(
            message.contains("same volume") || message.contains("same physical disk"),
            "Unexpected error: {message}"
        );
        ensure!(
            !output.exists(),
            "Rejected acquisition created an output directory"
        );
        Ok(())
    }

    #[test]
    fn raw_partition_roundtrip_reads_the_last_sector_and_verifies_every_byte() -> Result<()> {
        use std::process::Command;
        struct Mounted(PathBuf);
        impl Drop for Mounted {
            fn drop(&mut self) {
                let _=Command::new("powershell.exe").args(["-NoProfile","-NonInteractive","-Command","Dismount-DiskImage -ImagePath $env:KUMADE_TEST_IMAGE -ErrorAction Stop | Out-Null"]).env("KUMADE_TEST_IMAGE",&self.0).output();
            }
        }
        let temp = tempfile::tempdir()?;
        let image = temp.path().join("partition-test.vhdx");
        let script = temp.path().join("diskpart.txt");
        let setup = r#"
$ErrorActionPreference='Stop'
$ProgressPreference='SilentlyContinue'
[Console]::OutputEncoding=New-Object System.Text.UTF8Encoding($false)
@"
create vdisk file="$env:KUMADE_TEST_IMAGE" maximum=64 type=expandable
select vdisk file="$env:KUMADE_TEST_IMAGE"
attach vdisk
create partition primary
format fs=ntfs quick label=KumadeRawTest
"@ | Set-Content -LiteralPath $env:KUMADE_TEST_SCRIPT -Encoding ascii
& diskpart.exe /s $env:KUMADE_TEST_SCRIPT | Out-Null
try {
    $disk=Get-DiskImage -ImagePath $env:KUMADE_TEST_IMAGE | Get-Disk
    $volumes=@($disk | Get-Partition | Get-Volume | Where-Object FileSystem -eq NTFS)
    if ($volumes.Count -ne 1) { throw 'Test requires exactly one initialized NTFS partition' }
    Set-Disk -Number $disk.Number -IsReadOnly $true
    $volumes[0].UniqueId
} catch {
    Dismount-DiskImage -ImagePath $env:KUMADE_TEST_IMAGE -ErrorAction SilentlyContinue | Out-Null
    throw
}
"#;
        let output = Command::new("powershell.exe")
            .args(["-NoProfile", "-NonInteractive", "-Command", setup])
            .env("KUMADE_TEST_IMAGE", &image)
            .env("KUMADE_TEST_SCRIPT", &script)
            .output()?;
        ensure!(
            output.status.success(),
            "Fixture setup failed: {}{}",
            String::from_utf8_lossy(&output.stdout),
            String::from_utf8_lossy(&output.stderr)
        );
        let _mounted = Mounted(image);
        let name = String::from_utf8(output.stdout)?
            .trim()
            .trim_start_matches('﻿')
            .to_owned();
        source_root(&name)?;
        let file = open_volume(&name, true)?;
        let length = u64::try_from(i64_at(
            &ioctl(&file, IOCTL_DISK_GET_LENGTH_INFO, &[], 8)?,
            0,
        )?)?;
        let geometry = ioctl(
            &file,
            IOCTL_DISK_GET_DRIVE_GEOMETRY,
            &[],
            size_of::<DISK_GEOMETRY>(),
        )?;
        let sector = u32_at(&geometry, offset_of!(DISK_GEOMETRY, BytesPerSector))?;
        let info = volume_info(&name, &file)?;
        ensure!(
            info.extents.len() == 1 && info.extents[0].length == length,
            "Unexpected test partition geometry"
        );
        ioctl(&file, FSCTL_ALLOW_EXTENDED_DASD_IO, &[], 0)?;
        let mut reader = crate::raw::DeviceReader::new(file, length, sector as usize)?;
        let partial = temp.path().join("test.dd.partial");
        let final_image = temp.path().join("test.dd");
        let mut saved = new_output(&partial)?;
        let mut copied = 0;
        let hash = copy_exact(&mut reader, &mut saved, length, &mut copied, |_| {})?;
        saved.sync_all()?;
        assert_eq!(saved.metadata()?.len(), length);
        assert_eq!(copied, length);
        saved.seek(SeekFrom::Start(0))?;
        assert_eq!(verify_image(&mut saved, length, &hash, |_| {})?, hash);
        // Independently compare every sector with the now-read-only volume, including its tail.
        reader.seek(SeekFrom::Start(0))?;
        saved.seek(SeekFrom::Start(0))?;
        let mut a = vec![0u8; 64 * 1024];
        let mut b = vec![0u8; 64 * 1024];
        let mut compared = 0;
        while compared < length {
            let size = (length - compared).min(a.len() as u64) as usize;
            reader.read_exact(&mut a[..size])?;
            saved.read_exact(&mut b[..size])?;
            assert_eq!(&a[..size], &b[..size]);
            compared += size as u64;
        }
        drop(saved);
        promote_image(&partial, &final_image)?;
        assert_eq!(crate::collect::hash_file(&final_image)?, (length, hash));
        Ok(())
    }
    #[test]
    fn image_finalization_never_overwrites_an_existing_file() {
        let dir = tempfile::tempdir().unwrap();
        let partial = dir.path().join("C.dd.partial");
        let image = dir.path().join("C.dd");
        fs::write(&partial, b"new").unwrap();
        fs::write(&image, b"existing").unwrap();
        assert!(promote_image(&partial, &image).is_err());
        assert_eq!(fs::read(&image).unwrap(), b"existing");
        assert_eq!(fs::read(&partial).unwrap(), b"new");
        fs::remove_file(&image).unwrap();
        promote_image(&partial, &image).unwrap();
        assert_eq!(fs::read(&image).unwrap(), b"new");
    }
}
