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

use super::{Snapshot, encode_ea, normalize_ea, sddl_equivalent, split_kernel_ea, unhex};
use crate::model::*;
use anyhow::{Context, Result, ensure};
use std::{
    collections::BTreeSet,
    fs::{File, OpenOptions},
    os::windows::{ffi::OsStrExt, fs::OpenOptionsExt, io::AsRawHandle},
    path::Path,
    ptr,
};
use windows_sys::Wdk::Storage::FileSystem::{NtQueryEaFile, NtSetEaFile};
use windows_sys::Win32::{
    Foundation::*,
    Security::{
        Authorization::{
            ConvertSecurityDescriptorToStringSecurityDescriptorW, GetSecurityInfo, SE_FILE_OBJECT,
        },
        *,
    },
    Storage::FileSystem::*,
    System::{
        IO::{DeviceIoControl, IO_STATUS_BLOCK},
        Ioctl::{
            FSCTL_QUERY_USN_JOURNAL, FSCTL_SET_COMPRESSION, FSCTL_SET_SPARSE, USN_JOURNAL_DATA_V0,
        },
        SystemServices::{
            ACCESS_FILTER_SECURITY_INFORMATION, ACCESS_SYSTEM_SECURITY,
            PROCESS_TRUST_LABEL_SECURITY_INFORMATION,
        },
        Threading::{GetCurrentProcess, OpenProcessToken},
    },
};

/// Security information understood by every supported Windows 10 build.
const SECURITY_BASE: u32 = OWNER_SECURITY_INFORMATION
    | GROUP_SECURITY_INFORMATION
    | DACL_SECURITY_INFORMATION
    | SACL_SECURITY_INFORMATION
    | LABEL_SECURITY_INFORMATION
    | ATTRIBUTE_SECURITY_INFORMATION
    | SCOPE_SECURITY_INFORMATION
    | PROCESS_TRUST_LABEL_SECURITY_INFORMATION as u32;
/// Access-filter ACEs were added in Windows 10 1703. Capture and readback use
/// the same mask, falling back when a kernel rejects the newer flag.
const SECURITY: u32 = SECURITY_BASE | ACCESS_FILTER_SECURITY_INFORMATION as u32;
const SECURITY_MASKS: [u32; 2] = [SECURITY, SECURITY_BASE];

pub fn wide(path: &Path) -> Vec<u16> {
    path.as_os_str().encode_wide().chain(Some(0)).collect()
}

pub fn enable_privileges() -> Result<()> {
    let mut token = ptr::null_mut();
    // SAFETY: current process is valid and token is a writable handle output.
    ensure!(
        // SAFETY: current process is valid and token is a writable handle output.
        unsafe {
            OpenProcessToken(
                GetCurrentProcess(),
                TOKEN_ADJUST_PRIVILEGES | TOKEN_QUERY,
                &mut token,
            )
        } != 0,
        "Cannot open process token: {}",
        std::io::Error::last_os_error()
    );
    let result = (|| {
        for name in [
            "SeBackupPrivilege",
            "SeRestorePrivilege",
            "SeSecurityPrivilege",
            "SeManageVolumePrivilege",
        ] {
            let name_wide: Vec<_> = name.encode_utf16().chain(Some(0)).collect();
            let mut luid = LUID::default();
            // SAFETY: the name is terminated and luid is a writable output.
            ensure!(
                // SAFETY: the name is terminated and luid is a writable output.
                unsafe { LookupPrivilegeValueW(ptr::null(), name_wide.as_ptr(), &mut luid) } != 0,
                "Cannot resolve {name}"
            );
            let state = TOKEN_PRIVILEGES {
                PrivilegeCount: 1,
                Privileges: [LUID_AND_ATTRIBUTES {
                    Luid: luid,
                    Attributes: SE_PRIVILEGE_ENABLED,
                }],
            };
            // SAFETY: token and one-entry TOKEN_PRIVILEGES are valid; clear the documented last-error result before adjusting.
            unsafe {
                SetLastError(0);
            }
            // SAFETY: valid token and input state; previous state is not requested.
            let ok = unsafe {
                AdjustTokenPrivileges(token, 0, &state, 0, ptr::null_mut(), ptr::null_mut())
            };
            // SAFETY: thread-local last-error query immediately follows the API.
            let error = unsafe { GetLastError() };
            ensure!(
                ok != 0 && error != ERROR_NOT_ALL_ASSIGNED,
                "VHDX metadata preservation requires {name}; run elevated as an administrator (Windows error {error})"
            );
        }
        Ok(())
    })();
    // SAFETY: this function owns the successful OpenProcessToken handle.
    unsafe {
        CloseHandle(token);
    }
    result
}

fn open_metadata(path: &Path, write: bool) -> Result<File> {
    let access = if write {
        GENERIC_READ
            | GENERIC_WRITE
            | FILE_READ_ATTRIBUTES
            | FILE_WRITE_ATTRIBUTES
            | FILE_READ_EA
            | FILE_WRITE_EA
            | READ_CONTROL
            | WRITE_DAC
            | WRITE_OWNER
            | ACCESS_SYSTEM_SECURITY
    } else {
        FILE_READ_ATTRIBUTES | FILE_READ_EA | READ_CONTROL | ACCESS_SYSTEM_SECURITY
    };
    Ok(OpenOptions::new()
        .access_mode(access)
        .share_mode(FILE_SHARE_READ | FILE_SHARE_WRITE | FILE_SHARE_DELETE)
        .custom_flags(FILE_FLAG_BACKUP_SEMANTICS | FILE_FLAG_OPEN_REPARSE_POINT)
        .open(path)?)
}

fn basic(file: &File) -> Result<FILE_BASIC_INFO> {
    let mut info = FILE_BASIC_INFO::default();
    // SAFETY: handle is live and output is exactly FILE_BASIC_INFO-sized.
    ensure!(
        // SAFETY: handle is live and output is exactly FILE_BASIC_INFO-sized.
        unsafe {
            GetFileInformationByHandleEx(
                file.as_raw_handle(),
                FileBasicInfo,
                (&mut info as *mut FILE_BASIC_INFO).cast(),
                size_of::<FILE_BASIC_INFO>() as u32,
            )
        } != 0,
        "GetFileInformationByHandleEx: {}",
        std::io::Error::last_os_error()
    );
    ensure!(
        info.FileAttributes & FILE_ATTRIBUTE_REPARSE_POINT == 0,
        "Reparse-backed metadata restoration is unsupported"
    );
    Ok(info)
}

/// The complete self-relative descriptor and the information mask it was read with.
fn descriptor(file: &File) -> Result<(Vec<u8>, u32)> {
    let mut code = 0;
    for mask in SECURITY_MASKS {
        let mut descriptor = ptr::null_mut();
        // SAFETY: live file handle; only the descriptor output is requested. Windows
        // allocates a complete self-relative descriptor for backup/restore.
        code = unsafe {
            GetSecurityInfo(
                file.as_raw_handle(),
                SE_FILE_OBJECT,
                mask,
                ptr::null_mut(),
                ptr::null_mut(),
                ptr::null_mut(),
                ptr::null_mut(),
                &mut descriptor,
            )
        };
        if code == ERROR_INVALID_PARAMETER && mask != SECURITY_BASE {
            // An older kernel rejects a flag it does not know; retry without it.
            continue;
        }
        ensure!(
            code == 0,
            "Cannot read complete file security: {}",
            std::io::Error::from_raw_os_error(code as i32)
        );
        // SAFETY: successful API returned a valid security descriptor.
        let length = unsafe { GetSecurityDescriptorLength(descriptor) } as usize;
        let result = if (20..=1024 * 1024).contains(&length) {
            // SAFETY: descriptor points to the API allocation of the stated length.
            Ok((
                unsafe { std::slice::from_raw_parts(descriptor.cast(), length) }.to_vec(),
                mask,
            ))
        } else {
            Err(anyhow::anyhow!("Invalid security descriptor length"))
        };
        // SAFETY: GetSecurityInfo allocated the descriptor with LocalAlloc.
        unsafe {
            LocalFree(descriptor);
        }
        return result;
    }
    anyhow::bail!(
        "Cannot read complete file security: {}",
        std::io::Error::from_raw_os_error(code as i32)
    )
}

fn restore_security(file: &File, data: &[u8]) -> Result<()> {
    let _validated = aligned_descriptor(data)?;
    // BackupWrite preserves the original auto-inheritance flags and absent
    // SACL state; ordinary security-setting APIs normalize these properties.
    let mut frame = Vec::with_capacity(20 + data.len());
    frame.extend_from_slice(&3u32.to_le_bytes()); // BACKUP_SECURITY_DATA
    frame.extend_from_slice(&0u32.to_le_bytes());
    frame.extend_from_slice(&(data.len() as u64).to_le_bytes());
    frame.extend_from_slice(&0u32.to_le_bytes()); // no stream name
    frame.extend_from_slice(data);
    let mut context = ptr::null_mut();
    let result = (|| -> Result<()> {
        let mut at = 0;
        while at < frame.len() {
            let mut written = 0;
            // SAFETY: synchronous destination with security/restore access;
            // frame contains a validated bounded security backup stream.
            ensure!(
                // SAFETY: complete bounded security frame and live synchronous destination/context.
                unsafe {
                    BackupWrite(
                        file.as_raw_handle(),
                        frame[at..].as_ptr(),
                        (frame.len() - at) as u32,
                        &mut written,
                        0,
                        1,
                        &mut context,
                    )
                } != 0,
                "BackupWrite security: {}",
                std::io::Error::last_os_error()
            );
            ensure!(
                written > 0 && written as usize <= frame.len() - at,
                "Invalid BackupWrite byte count"
            );
            at += written as usize;
        }
        Ok(())
    })();
    let mut released = true;
    if !context.is_null() {
        let mut written = 0;
        // SAFETY: abort releases only the BackupWrite-owned context after the
        // complete stream has been processed (or after a handled write error).
        released = unsafe {
            BackupWrite(
                file.as_raw_handle(),
                ptr::null(),
                0,
                &mut written,
                1,
                1,
                &mut context,
            )
        } != 0;
    }
    result?;
    ensure!(released, "Cannot release security restoration context");
    Ok(())
}

fn aligned_descriptor(data: &[u8]) -> Result<Vec<u32>> {
    ensure!(
        data.len() >= 20 && data.len() <= 1024 * 1024,
        "Invalid security descriptor size"
    );
    let mut aligned = vec![0u32; data.len().div_ceil(4)];
    // SAFETY: destination allocation has at least data.len() initialized bytes; regions are disjoint.
    unsafe {
        ptr::copy_nonoverlapping(data.as_ptr(), aligned.as_mut_ptr().cast::<u8>(), data.len());
    }
    // SAFETY: this descriptor was read from Windows and copied into an aligned buffer.
    ensure!(
        // SAFETY: this descriptor was read from Windows and copied into an aligned buffer.
        unsafe { IsValidSecurityDescriptor(aligned.as_ptr().cast_mut().cast()) } != 0,
        "Invalid security descriptor"
    );
    Ok(aligned)
}

fn sddl(data: &[u8], mask: u32) -> Result<String> {
    let aligned = aligned_descriptor(data)?;
    let mut text = ptr::null_mut();
    let mut length = 0;
    let mut converted = false;
    for mask in [mask, SECURITY_BASE] {
        // SAFETY: descriptor is aligned/validated and output string/length are writable.
        converted = unsafe {
            ConvertSecurityDescriptorToStringSecurityDescriptorW(
                aligned.as_ptr().cast_mut().cast(),
                1,
                mask,
                &mut text,
                &mut length,
            )
        } != 0;
        if converted || mask == SECURITY_BASE {
            break;
        }
    }
    ensure!(converted, "Cannot format security descriptor");
    // SAFETY: successful API allocated a terminated UTF-16 string of length characters.
    let chars = unsafe { std::slice::from_raw_parts(text, length as usize) };
    let end = chars.iter().position(|&c| c == 0).unwrap_or(chars.len());
    let result = String::from_utf16(&chars[..end]);
    // SAFETY: Windows allocated the string with LocalAlloc and it is no longer used.
    unsafe {
        LocalFree(text.cast());
    }
    Ok(result?)
}

fn ea(file: &File) -> Result<Vec<u8>> {
    let mut bytes = vec![0u8; 65536];
    let mut status = IO_STATUS_BLOCK::default();
    // SAFETY: synchronous file handle, correctly sized initialized EA buffer and live status output; no name filter.
    let code = unsafe {
        NtQueryEaFile(
            file.as_raw_handle(),
            &mut status,
            bytes.as_mut_ptr().cast(),
            bytes.len() as u32,
            false,
            ptr::null(),
            0,
            ptr::null(),
            true,
        )
    };
    if code == STATUS_NO_EAS_ON_FILE {
        return Ok(Vec::new());
    }
    ensure!(
        code >= 0,
        "NtQueryEaFile failed: NTSTATUS {:#010x}",
        code as u32
    );
    ensure!(
        status.Information <= bytes.len(),
        "Invalid extended attribute length"
    );
    bytes.truncate(status.Information);
    normalize_ea(&bytes)?;
    Ok(bytes)
}

fn note(snapshot: &mut Snapshot, text: &str) {
    if !snapshot.notes.is_empty() {
        snapshot.notes.push_str("; ");
    }
    snapshot.notes.push_str(text);
}

pub fn file_identity(file: &File) -> Result<String> {
    let mut identity = BY_HANDLE_FILE_INFORMATION::default();
    // SAFETY: live source handle and correctly sized file information output.
    ensure!(
        // SAFETY: live source handle and correctly sized file information output.
        unsafe { GetFileInformationByHandle(file.as_raw_handle(), &mut identity) } != 0,
        "Cannot capture source file identity: {}",
        std::io::Error::last_os_error()
    );
    Ok(format!(
        "win:{:08x}:{:016x}",
        identity.dwVolumeSerialNumber,
        (u64::from(identity.nFileIndexHigh) << 32) | u64::from(identity.nFileIndexLow)
    ))
}

pub fn capture(path: &Path, snapshot: &mut Snapshot) -> Result<()> {
    let file = open_metadata(path, false)?;
    let info = basic(&file)?;
    snapshot.creation_filetime = Some(info.CreationTime);
    snapshot.access_filetime = Some(info.LastAccessTime);
    snapshot.write_filetime = Some(info.LastWriteTime);
    snapshot.change_filetime = Some(info.ChangeTime);
    snapshot.attributes = Some(info.FileAttributes);
    snapshot.source_file_id = Some(file_identity(&file)?);
    let mut errors = Vec::new();
    match descriptor(&file) {
        Ok((data, mask)) => {
            snapshot.security_descriptor_hex = Some(hex(&data));
            match sddl(&data, mask) {
                Ok(text) => snapshot.sddl = Some(text),
                Err(e) => errors.push(e.to_string()),
            }
        }
        Err(e) => errors.push(format!("security: {e:#}")),
    }
    match ea(&file) {
        Ok(data) => snapshot.extended_attributes_hex = Some(hex(&data)),
        Err(e) => errors.push(format!("extended attributes: {e:#}")),
    }
    ensure!(errors.is_empty(), "{}", errors.join("; "));
    Ok(())
}

pub fn restore(path: &Path, snapshot: &mut Snapshot) -> Result<()> {
    let file = open_metadata(path, true)?;
    let original = snapshot.attributes.context("Missing original attributes")?;
    let captured_ea = snapshot.extended_attributes_hex.clone();
    let captured_security = snapshot.security_descriptor_hex.clone();
    let captured_sddl = snapshot.sddl.clone().unwrap_or_default();
    let mut errors = Vec::new();
    // Restore compression/sparse state separately; physical allocation and file
    // IDs necessarily belong to the newly created destination filesystem.
    for (flag, code, input) in [
        (FILE_ATTRIBUTE_SPARSE_FILE, FSCTL_SET_SPARSE, vec![1u8]),
        (
            FILE_ATTRIBUTE_COMPRESSED,
            FSCTL_SET_COMPRESSION,
            2u16.to_le_bytes().to_vec(),
        ),
    ] {
        if original & flag != 0 {
            let mut returned = 0;
            // SAFETY: output handle is owned and input has the documented FSCTL layout.
            if unsafe {
                DeviceIoControl(
                    file.as_raw_handle(),
                    code,
                    input.as_ptr().cast(),
                    input.len() as u32,
                    ptr::null_mut(),
                    0,
                    &mut returned,
                    ptr::null_mut(),
                )
            } == 0
            {
                errors.push(format!(
                    "storage attribute {flag:#x}: {}",
                    std::io::Error::last_os_error()
                ));
            }
        }
    }
    if original & FILE_ATTRIBUTE_ENCRYPTED != 0 {
        errors.push("Original EFS encryption cannot be reproduced with the source key".into());
    }
    if snapshot.capture_status == "RawBasic" {
        // NTFS system files: Windows exposes neither their security nor their
        // extended attributes, so only times and attributes can be reproduced.
        ensure!(errors.is_empty(), "{}", errors.join("; "));
        return Ok(());
    }
    if let Some(data) = &captured_ea {
        let data = unhex(data)?;
        // Kernel-namespace entries are accepted by NtSetEaFile from user mode but
        // never stored; keep them out of the write and the readback comparison.
        let (user, kernel) = split_kernel_ea(normalize_ea(&data)?);
        if !user.is_empty() {
            let chain = encode_ea(&user);
            let mut status = IO_STATUS_BLOCK::default();
            // SAFETY: freshly encoded, validated EA chain, live synchronous destination and status output.
            let code = unsafe {
                NtSetEaFile(
                    file.as_raw_handle(),
                    &mut status,
                    chain.as_ptr().cast(),
                    chain.len() as u32,
                )
            };
            if code < 0 {
                errors.push(format!("NtSetEaFile: NTSTATUS {:#010x}", code as u32));
            }
        }
        match ea(&file) {
            Ok(current) => {
                if normalize_ea(&current)? != user {
                    errors.push("Extended attribute readback differs".into());
                }
            }
            Err(e) => errors.push(e.to_string()),
        }
        if !kernel.is_empty() {
            note(
                snapshot,
                &format!(
                    "Kernel-namespace extended attributes are kept in the inventory only; Windows ignores them from user mode: {}",
                    kernel.join(", ")
                ),
            );
        }
    } else {
        errors.push("Extended attributes were not captured".into());
    }
    if let Some(data) = &captured_security {
        let data = unhex(data)?;
        if let Err(error) = restore_security(&file, &data) {
            errors.push(format!("Owner/group/DACL/SACL restoration: {error:#}"));
        } else {
            match descriptor(&file).and_then(|(sd, mask)| sddl(&sd, mask)) {
                Ok(actual) => match sddl_equivalent(&captured_sddl, &actual) {
                    Some(text) => {
                        if !text.is_empty() {
                            note(snapshot, &text);
                        }
                    }
                    None => errors.push(format!("Security descriptor readback differs: {actual}")),
                },
                Err(e) => errors.push(e.to_string()),
            }
        }
    } else {
        errors.push("Security descriptor was not captured".into());
    }
    ensure!(errors.is_empty(), "{}", errors.join("; "));
    Ok(())
}

pub fn restore_times(path: &Path, snapshot: &Snapshot) -> Result<()> {
    let file = open_metadata(path, true)?;
    let original = snapshot.attributes.context("Missing original attributes")?;
    let mut errors = Vec::new();
    let mut info = FILE_BASIC_INFO {
        CreationTime: snapshot
            .creation_filetime
            .context("Missing creation time")?,
        LastAccessTime: snapshot.access_filetime.context("Missing access time")?,
        LastWriteTime: snapshot.write_filetime.context("Missing write time")?,
        ChangeTime: snapshot.change_filetime.context("Missing change time")?,
        FileAttributes: original
            & (FILE_ATTRIBUTE_READONLY
                | FILE_ATTRIBUTE_HIDDEN
                | FILE_ATTRIBUTE_SYSTEM
                | FILE_ATTRIBUTE_ARCHIVE
                | FILE_ATTRIBUTE_TEMPORARY
                | FILE_ATTRIBUTE_OFFLINE
                | FILE_ATTRIBUTE_NOT_CONTENT_INDEXED),
    };
    if info.FileAttributes == 0 {
        info.FileAttributes = FILE_ATTRIBUTE_NORMAL;
    }
    // SAFETY: valid writable destination handle and a full FILE_BASIC_INFO input.
    if unsafe {
        SetFileInformationByHandle(
            file.as_raw_handle(),
            FileBasicInfo,
            (&mut info as *mut FILE_BASIC_INFO).cast(),
            size_of::<FILE_BASIC_INFO>() as u32,
        )
    } == 0
    {
        errors.push(format!(
            "NTFS basic times/attributes: {}",
            std::io::Error::last_os_error()
        ));
    } else {
        match basic(&file) {
            Ok(actual) => {
                if [
                    actual.CreationTime,
                    actual.LastAccessTime,
                    actual.LastWriteTime,
                    actual.ChangeTime,
                ] != [
                    info.CreationTime,
                    info.LastAccessTime,
                    info.LastWriteTime,
                    info.ChangeTime,
                ] {
                    errors.push("NTFS basic timestamp readback differs (including an unset/unsupported timestamp)".into());
                }
                // NORMAL is a sentinel, not a persistent flag alongside other attributes.
                if (actual.FileAttributes & !FILE_ATTRIBUTE_NORMAL)
                    != (original & !FILE_ATTRIBUTE_NORMAL)
                {
                    errors.push(format!(
                        "Attribute readback differs: source {original:#x}, destination {:#x}",
                        actual.FileAttributes
                    ));
                }
            }
            Err(e) => errors.push(e.to_string()),
        }
    }
    ensure!(errors.is_empty(), "{}", errors.join("; "));
    Ok(())
}

/// Bytes of live USN journal data, `NextUsn - FirstUsn`. NTFS keeps `$J`
/// allocated beyond the written records, so this bounds what a sparse-aware
/// copy of the stream will store.
pub fn usn_journal_live_bytes(device: &Path) -> Option<u64> {
    let volume = crate::platform::open_source(device).ok()?;
    let mut data = USN_JOURNAL_DATA_V0::default();
    let mut returned = 0;
    // SAFETY: read handle to the volume device and an output buffer of exactly
    // USN_JOURNAL_DATA_V0 size; no input buffer.
    let ok = unsafe {
        DeviceIoControl(
            volume.as_raw_handle(),
            FSCTL_QUERY_USN_JOURNAL,
            ptr::null(),
            0,
            (&mut data as *mut USN_JOURNAL_DATA_V0).cast(),
            size_of::<USN_JOURNAL_DATA_V0>() as u32,
            &mut returned,
            ptr::null_mut(),
        )
    } != 0;
    (ok && data.NextUsn >= data.FirstUsn).then(|| (data.NextUsn - data.FirstUsn) as u64)
}

pub fn augment_streams(plan: &mut Plan) -> Result<()> {
    let mut known: BTreeSet<_> = plan
        .files
        .iter()
        .filter_map(|f| {
            f.stream.as_ref().map(|stream| {
                (
                    f.source_id.clone(),
                    f.relative_path.clone(),
                    stream.to_ascii_lowercase(),
                )
            })
        })
        .collect();
    let mut additions = Vec::new();
    for file in &plan.files {
        // Raw-only candidates (no planning-time metadata) are NTFS system files
        // that Windows refuses to open by name; their named streams come from
        // the catalog, so enumeration would only report a spurious failure.
        if file.stream.is_some() || file.before.is_none() {
            continue;
        }
        let path = wide(&file.source_path);
        let mut data = WIN32_FIND_STREAM_DATA::default();
        // SAFETY: terminated source path and correctly sized writable stream output.
        let find = unsafe {
            FindFirstStreamW(
                path.as_ptr(),
                FindStreamInfoStandard,
                (&mut data as *mut WIN32_FIND_STREAM_DATA).cast(),
                0,
            )
        };
        if find == INVALID_HANDLE_VALUE {
            let error = std::io::Error::last_os_error();
            if error.raw_os_error() != Some(ERROR_HANDLE_EOF as i32) {
                plan.issues.push(Issue {
                    source_id: file.source_id.clone(),
                    path: file.source_path.display().to_string(),
                    status: "Failed".into(),
                    reason: format!("Alternate data streams could not be inventoried: {error}"),
                });
            }
            continue;
        }
        let result = (|| -> Result<()> {
            loop {
                let end = data
                    .cStreamName
                    .iter()
                    .position(|&c| c == 0)
                    .context("Unterminated NTFS stream name")?;
                let name = String::from_utf16(&data.cStreamName[..end])?;
                if name != "::$DATA" {
                    let stream = name
                        .strip_prefix(':')
                        .and_then(|n| n.strip_suffix(":$DATA"))
                        .context("Unsupported NTFS stream type")?;
                    ensure!(
                        !stream.is_empty() && data.StreamSize >= 0,
                        "Invalid NTFS stream metadata"
                    );
                    if known.insert((
                        file.source_id.clone(),
                        file.relative_path.clone(),
                        stream.to_ascii_lowercase(),
                    )) {
                        let mut item = file.clone();
                        item.id = uuid::Uuid::new_v4().to_string();
                        item.stream = Some(stream.into());
                        let size = data.StreamSize as u64;
                        item.before = Some(Fingerprint {
                            size,
                            ..file.before.clone().unwrap_or_default()
                        });
                        plan.known_bytes = plan
                            .known_bytes
                            .checked_add(size)
                            .context("Stream size overflow")?;
                        for coverage in plan.coverage.iter_mut().filter(|c| {
                            c.source_id == item.source_id && item.artifacts.contains(&c.artifact_id)
                        }) {
                            coverage.discovered += 1;
                        }
                        additions.push(item);
                    }
                }
                // SAFETY: live enumeration handle and full writable stream output.
                if unsafe {
                    FindNextStreamW(find, (&mut data as *mut WIN32_FIND_STREAM_DATA).cast())
                } == 0
                {
                    let error = std::io::Error::last_os_error();
                    ensure!(
                        error.raw_os_error() == Some(ERROR_HANDLE_EOF as i32),
                        "Stream enumeration failed: {error}"
                    );
                    break;
                }
            }
            Ok(())
        })();
        // SAFETY: this function owns the successful FindFirstStreamW search handle.
        unsafe {
            FindClose(find);
        }
        if let Err(error) = result {
            plan.issues.push(Issue {
                source_id: file.source_id.clone(),
                path: file.source_path.display().to_string(),
                status: "Failed".into(),
                reason: format!("Stream inventory incomplete: {error:#}"),
            });
        }
    }
    plan.files.extend(additions);
    Ok(())
}
