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

//! Windows-specific handles stay behind a small, compile-checked boundary.
use crate::model::SourceDiscovery;
#[cfg(any(windows, test))]
use crate::model::{Issue, Source};
use anyhow::{Result, bail};
use std::{
    fs::{File, OpenOptions},
    path::Path,
};

/// Resolve existing paths, including Windows volumes without a DOS drive name.
pub fn canonicalize(path: &Path) -> std::io::Result<std::path::PathBuf> {
    #[cfg(windows)]
    {
        windows::canonicalize_with(path, |path| std::fs::canonicalize(path))
    }
    #[cfg(not(windows))]
    {
        path.canonicalize()
    }
}

#[cfg(any(windows, test))]
fn record_source(report: &mut SourceDiscovery, id: String, path: &Path, result: Result<Source>) {
    match result {
        Ok(source) => report.sources.push(source),
        Err(error) => report.issues.push(Issue {
            source_id: id,
            path: path.display().to_string(),
            status: "Failed".into(),
            reason: format!("Volume could not be prepared: {error:#}"),
        }),
    }
}

/// Resolve a path's actual local volume, following mount points and path aliases.
#[cfg(windows)]
pub(crate) fn volume_identity(path: &Path) -> Result<Option<String>> {
    windows::volume_for_path(path)
}

/// `IsWow64Process2` reports IMAGE_FILE_MACHINE_UNKNOWN for the process machine of an
/// x64 build running under the x64 emulation of Windows on ARM64, not only for native
/// processes, so the native machine must match the build architecture as well.
#[cfg_attr(not(windows), allow(dead_code))]
pub(crate) fn native_machine_matches(
    process_machine: u16,
    native_machine: u16,
    build_machine: u16,
) -> bool {
    process_machine == 0 && native_machine == build_machine
}

/// Refuse WOW64 and ARM64 x64 emulation for features that must run as a native process:
/// VSS requesters are unsupported there and an emulated scanner cannot see native address
/// space. The message names the Kumade build to use on this Windows.
#[cfg(windows)]
pub fn require_native_build(feature: &str) -> Result<()> {
    use windows_sys::Win32::System::Threading::{GetCurrentProcess, IsWow64Process2};
    let (mut process, mut native) = (0u16, 0u16);
    anyhow::ensure!(
        // SAFETY: current process pseudo-handle and two initialized writable u16 values.
        unsafe { IsWow64Process2(GetCurrentProcess(), &mut process, &mut native) } != 0,
        "Cannot determine the native Windows architecture: {}",
        std::io::Error::last_os_error()
    );
    let build = match std::env::consts::ARCH {
        "aarch64" => 0xaa64,
        "x86_64" => 0x8664,
        "x86" => 0x014c,
        _ => bail!("{feature}: unsupported build architecture"),
    };
    anyhow::ensure!(
        native_machine_matches(process, native, build),
        "{feature} requires a native-architecture build running without WOW64 or emulation; use Kumade's {} build on this Windows",
        match native {
            0xaa64 => "win-aarch64",
            0x8664 => "win-x64",
            0x014c => "win-x86",
            _ => "native",
        }
    );
    Ok(())
}

pub fn computer_name() -> String {
    std::env::var("COMPUTERNAME")
        .or_else(|_| std::env::var("HOSTNAME"))
        .unwrap_or_else(|_| "UnknownComputer".into())
}

pub fn is_remote_windows_path(text: &str) -> bool {
    let value = text.replace('/', "\\").to_ascii_uppercase();
    value.starts_with("\\\\?\\UNC\\")
        || value.starts_with("\\??\\UNC\\")
        || (value.starts_with("\\\\") && !value.starts_with("\\\\?\\"))
}

/// Protect a newly created evidence root, without modifying any source ACL.
pub fn protect_output_root(root: &Path) -> Result<&'static str> {
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        std::fs::set_permissions(root, std::fs::Permissions::from_mode(0o700))?;
        Ok("OwnerOnly")
    }
    #[cfg(windows)]
    {
        use std::{os::windows::ffi::OsStrExt, ptr};
        use windows_sys::Win32::{
            Foundation::LocalFree,
            Security::{Authorization::ConvertStringSecurityDescriptorToSecurityDescriptorW, *},
            Storage::FileSystem::{GetVolumeInformationW, GetVolumePathNameW},
        };
        let path: Vec<u16> = root.as_os_str().encode_wide().chain(Some(0)).collect();
        let mut volume = vec![0u16; 32768];
        let mut flags = 0;
        // SAFETY: path is NUL-terminated and volume is a sized writable buffer.
        if unsafe { GetVolumePathNameW(path.as_ptr(), volume.as_mut_ptr(), volume.len() as u32) }
            == 0
        {
            bail!(
                "Cannot inspect destination volume: {}",
                std::io::Error::last_os_error()
            );
        }
        // SAFETY: volume is an API-supplied terminated path; optional outputs are null.
        if unsafe {
            GetVolumeInformationW(
                volume.as_ptr(),
                ptr::null_mut(),
                0,
                ptr::null_mut(),
                ptr::null_mut(),
                &mut flags,
                ptr::null_mut(),
                0,
            )
        } == 0
        {
            bail!("Cannot inspect destination ACL capability");
        }
        if flags & 0x8 == 0 {
            return Ok("FilesystemHasNoPersistentACLs");
        }
        // OW is Owner Rights. Children inherit only owner, Administrators and SYSTEM access.
        let sddl: Vec<u16> = "D:P(A;OICI;FA;;;SY)(A;OICI;FA;;;BA)(A;OICI;FA;;;OW)"
            .encode_utf16()
            .chain(Some(0))
            .collect();
        let mut descriptor = ptr::null_mut();
        // SAFETY: descriptor is initialized by the conversion API; SDDL is terminated.
        if unsafe {
            ConvertStringSecurityDescriptorToSecurityDescriptorW(
                sddl.as_ptr(),
                1,
                &mut descriptor,
                ptr::null_mut(),
            )
        } == 0
        {
            bail!("Cannot build evidence-directory ACL");
        }
        // SAFETY: descriptor is live and the path names the new owned output directory.
        let result = unsafe {
            SetFileSecurityW(
                path.as_ptr(),
                DACL_SECURITY_INFORMATION | PROTECTED_DACL_SECURITY_INFORMATION,
                descriptor,
            )
        };
        let error = std::io::Error::last_os_error();
        // SAFETY: the SDDL API allocated this buffer with LocalAlloc; it is no longer used.
        unsafe {
            LocalFree(descriptor);
        }
        if result == 0 {
            return Err(error.into());
        }
        Ok("OwnerAdministratorsSystem")
    }
    #[cfg(not(any(unix, windows)))]
    {
        let _ = root;
        bail!("Output permission hardening is unsupported on this platform")
    }
}

pub fn enable_sparse_output(file: &File) -> bool {
    #[cfg(unix)]
    {
        let _ = file;
        true
    }
    #[cfg(windows)]
    {
        use std::{os::windows::io::AsRawHandle, ptr};
        use windows_sys::Win32::System::{IO::DeviceIoControl, Ioctl::FSCTL_SET_SPARSE};
        let mut bytes = 0;
        // SAFETY: the file is an owned writable output; this FSCTL requires no input.
        unsafe {
            DeviceIoControl(
                file.as_raw_handle(),
                FSCTL_SET_SPARSE,
                ptr::null(),
                0,
                ptr::null_mut(),
                0,
                &mut bytes,
                ptr::null_mut(),
            ) != 0
        }
    }
    #[cfg(not(any(unix, windows)))]
    {
        let _ = file;
        false
    }
}

pub fn open_source(path: &Path) -> Result<File> {
    let mut options = OpenOptions::new();
    options.read(true);
    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt;
        options.custom_flags(libc::O_NOFOLLOW);
    }
    #[cfg(windows)]
    {
        use std::os::windows::fs::OpenOptionsExt;
        use windows_sys::Win32::Storage::FileSystem::*;
        options
            .share_mode(FILE_SHARE_READ | FILE_SHARE_WRITE | FILE_SHARE_DELETE)
            .custom_flags(FILE_FLAG_OPEN_REPARSE_POINT | FILE_FLAG_BACKUP_SEMANTICS);
    }
    Ok(options.open(path)?)
}

pub fn is_reparse_directory(path: &Path) -> bool {
    #[cfg(windows)]
    {
        use std::os::windows::fs::MetadataExt;
        path.symlink_metadata()
            .is_ok_and(|m| m.file_attributes() & 0x400 != 0)
    }
    #[cfg(not(windows))]
    {
        let _ = path;
        false
    }
}

/// Check the object actually opened, rather than trusting its earlier pathname.
pub fn validate_open_file(file: &File, root: &Path) -> Result<()> {
    if !file.metadata()?.is_file() {
        bail!("Source is not a regular file");
    }
    #[cfg(unix)]
    {
        use std::os::fd::AsRawFd;
        #[cfg(target_os = "linux")]
        {
            let actual = std::fs::read_link(format!("/proc/self/fd/{}", file.as_raw_fd()))?;
            if !actual.starts_with(root) {
                bail!("Opened source escaped its planned root");
            }
        }
        #[cfg(target_os = "macos")]
        {
            use std::os::unix::ffi::OsStringExt;
            // F_GETPATH resolves the opened descriptor, including any parent
            // symlink swap that occurred after directory enumeration.
            let mut path = vec![0_u8; libc::PATH_MAX as usize];
            // SAFETY: F_GETPATH writes at most PATH_MAX bytes to this owned buffer.
            let code = unsafe { libc::fcntl(file.as_raw_fd(), libc::F_GETPATH, path.as_mut_ptr()) };
            if code == -1 {
                bail!(
                    "Cannot verify final source path: {}",
                    std::io::Error::last_os_error()
                );
            }
            let end = path
                .iter()
                .position(|b| *b == 0)
                .ok_or_else(|| anyhow::anyhow!("Unterminated final source path"))?;
            path.truncate(end);
            let actual = std::path::PathBuf::from(std::ffi::OsString::from_vec(path));
            if !actual.starts_with(root) {
                bail!("Opened source escaped its planned root");
            }
        }
        #[cfg(not(any(target_os = "linux", target_os = "macos")))]
        {
            let _ = (file.as_raw_fd(), root);
            bail!("Handle-based source-path validation is unavailable on this platform");
        }
    }
    #[cfg(windows)]
    {
        let root = root
            .to_str()
            .ok_or_else(|| anyhow::anyhow!("Unsupported source-root name"))?;
        // Compare paths in the same volume namespace. DOS-name lookup fails
        // for an accessible recovery/EFI volume that has no drive letter.
        let shadow = root
            .to_ascii_lowercase()
            .starts_with("\\\\?\\globalroot\\device\\harddiskvolumeshadowcopy");
        let flags = if shadow {
            windows_sys::Win32::Storage::FileSystem::VOLUME_NAME_NT
        } else if root.to_ascii_lowercase().starts_with("\\\\?\\volume{") {
            windows_sys::Win32::Storage::FileSystem::VOLUME_NAME_GUID
        } else {
            windows_sys::Win32::Storage::FileSystem::VOLUME_NAME_DOS
        };
        let actual = windows::final_path(file, flags)?;
        let actual = if shadow {
            std::path::PathBuf::from(format!("\\\\?\\GLOBALROOT{}", actual.to_string_lossy()))
        } else {
            actual
        };
        let actual = actual
            .to_str()
            .ok_or_else(|| anyhow::anyhow!("Unsupported final source name"))?;
        let root = root.trim_end_matches('\\');
        // Ignore ASCII drive/path casing, but require a full component boundary.
        if actual.len() <= root.len()
            || !actual
                .get(..root.len())
                .is_some_and(|p| p.eq_ignore_ascii_case(root))
            || actual.as_bytes().get(root.len()) != Some(&b'\\')
        {
            bail!("Opened source escaped its planned root");
        }
        use std::os::windows::fs::MetadataExt;
        if file.metadata()?.file_attributes() & 0x400 != 0 {
            bail!("Reparse-point payload is not acquired through native reads");
        }
    }
    Ok(())
}

/// Every local fixed volume, lettered or not, with the catalog scope: logs,
/// profiles and Recycle Bins live on data volumes too, so every volume is
/// checked for every selected artifact. NTFS volumes add their raw metadata
/// files. Removable media is not acquired by default (docs/architecture.md,
/// default collection policy); the running Windows volume is acquired whatever
/// drive type Windows reports for it. `destination` is the directory or container path this run
/// will write to: the volume that merely holds the output is not evidence and
/// is excluded by identity, unless it is the running Windows volume, which is
/// always acquired.
#[cfg(not(windows))]
pub fn live_sources(_destination: Option<&Path>) -> Result<SourceDiscovery> {
    bail!(
        "Live acquisition requires Windows. Use --source <WINDOWS-VOLUME-DIRECTORY> for offline collection."
    )
}

#[cfg(windows)]
pub fn live_sources(destination: Option<&Path>) -> Result<SourceDiscovery> {
    windows::live_sources(destination)
}

#[cfg(not(windows))]
pub fn enable_backup_privilege() -> Result<()> {
    bail!("Windows privileges are not available")
}
#[cfg(windows)]
pub fn enable_backup_privilege() -> Result<()> {
    windows::enable_backup_privilege()
}

#[cfg(windows)]
mod windows {
    use super::*;
    use anyhow::{Context, ensure};
    use std::{mem::size_of, path::PathBuf, ptr};
    use windows_sys::Win32::{
        Foundation::*,
        Security::*,
        Storage::FileSystem::*,
        System::{
            Registry::*,
            Threading::*,
            WindowsProgramming::{DRIVE_FIXED, DRIVE_REMOTE},
        },
    };

    pub(super) fn final_path(file: &File, flags: u32) -> std::io::Result<std::path::PathBuf> {
        use std::os::windows::{ffi::OsStringExt, io::AsRawHandle};
        let mut buffer = vec![0u16; 32768];
        // SAFETY: file owns a live handle and the buffer has the advertised capacity.
        let length = unsafe {
            GetFinalPathNameByHandleW(
                file.as_raw_handle(),
                buffer.as_mut_ptr(),
                buffer.len() as u32,
                flags,
            )
        };
        if length == 0 {
            return Err(std::io::Error::last_os_error());
        }
        if length as usize >= buffer.len() {
            return Err(std::io::Error::new(
                std::io::ErrorKind::InvalidData,
                "Final path exceeds the Windows path limit",
            ));
        }
        Ok(std::ffi::OsString::from_wide(&buffer[..length as usize]).into())
    }

    pub(super) fn canonicalize_with(
        path: &Path,
        normal: impl FnOnce(&Path) -> std::io::Result<std::path::PathBuf>,
    ) -> std::io::Result<std::path::PathBuf> {
        match normal(path) {
            Ok(path) => Ok(path),
            Err(error) if error.raw_os_error() == Some(ERROR_PATH_NOT_FOUND as i32) => {
                use std::os::windows::fs::OpenOptionsExt;
                // Opening with zero desired access resolves identity without reading payloads.
                // Follow the explicitly supplied root, just as canonicalize normally does.
                let file = OpenOptions::new()
                    .access_mode(0)
                    .share_mode(FILE_SHARE_READ | FILE_SHARE_WRITE | FILE_SHARE_DELETE)
                    .custom_flags(FILE_FLAG_BACKUP_SEMANTICS)
                    .open(path)?;
                final_path(&file, VOLUME_NAME_GUID)
            }
            Err(error) => Err(error),
        }
    }

    fn wide(text: &str) -> Vec<u16> {
        text.encode_utf16().chain(Some(0)).collect()
    }

    pub fn enable_backup_privilege() -> Result<()> {
        // SAFETY: the token output is initialized only by OpenProcessToken.
        let mut token = ptr::null_mut();
        ensure!(
            // SAFETY: the current process handle is valid and token is writable.
            unsafe {
                OpenProcessToken(
                    GetCurrentProcess(),
                    TOKEN_ADJUST_PRIVILEGES | TOKEN_QUERY,
                    &mut token,
                )
            } != 0,
            "OpenProcessToken: {}",
            std::io::Error::last_os_error()
        );
        let result = (|| {
            // SAFETY: TOKEN_ELEVATION has an all-zero valid representation.
            let mut elevation: TOKEN_ELEVATION = unsafe { std::mem::zeroed() };
            let mut returned = 0;
            ensure!(
                // SAFETY: valid token and correctly sized writable output.
                unsafe {
                    GetTokenInformation(
                        token,
                        TokenElevation,
                        &mut elevation as *mut _ as *mut _,
                        size_of::<TOKEN_ELEVATION>() as u32,
                        &mut returned,
                    )
                } != 0,
                "Cannot inspect elevation"
            );
            ensure!(
                elevation.TokenIsElevated != 0,
                "Full live collection needs an elevated local administrator; run as administrator or select an offline --source"
            );
            let mut luid = LUID {
                LowPart: 0,
                HighPart: 0,
            };
            ensure!(
                // SAFETY: the name is NUL-terminated; luid is writable.
                unsafe {
                    LookupPrivilegeValueW(
                        ptr::null(),
                        wide("SeBackupPrivilege").as_ptr(),
                        &mut luid,
                    )
                } != 0,
                "Cannot resolve backup privilege"
            );
            let state = TOKEN_PRIVILEGES {
                PrivilegeCount: 1,
                Privileges: [LUID_AND_ATTRIBUTES {
                    Luid: luid,
                    Attributes: SE_PRIVILEGE_ENABLED,
                }],
            };
            // SAFETY: token and the single privilege entry are valid; no previous state requested.
            unsafe {
                SetLastError(0);
            }
            ensure!(
                // SAFETY: state layout matches TOKEN_PRIVILEGES for one entry.
                unsafe {
                    AdjustTokenPrivileges(token, 0, &state, 0, ptr::null_mut(), ptr::null_mut())
                } != 0,
                "Cannot enable backup privilege"
            );
            ensure!(
                // SAFETY: GetLastError reads the thread's error value.
                unsafe { GetLastError() } != ERROR_NOT_ALL_ASSIGNED,
                "Token does not hold SeBackupPrivilege"
            );
            Ok(())
        })();
        // SAFETY: this function exclusively owns the token handle.
        unsafe {
            CloseHandle(token);
        }
        result
    }

    fn profile_paths() -> Result<Vec<std::path::PathBuf>> {
        let mut key = ptr::null_mut();
        let path = wide("SOFTWARE\\Microsoft\\Windows NT\\CurrentVersion\\ProfileList");
        // SAFETY: static root, valid path and output key.
        let code =
            unsafe { RegOpenKeyExW(HKEY_LOCAL_MACHINE, path.as_ptr(), 0, KEY_READ, &mut key) };
        ensure!(
            code == 0,
            "Cannot enumerate ProfileList: Windows error {code}"
        );
        let result = (|| {
            let mut paths = Vec::new();
            for index in 0.. {
                let mut name = vec![0u16; 512];
                let mut length = name.len() as u32;
                // SAFETY: registry key is open and the buffer capacity matches length.
                let code = unsafe {
                    RegEnumKeyExW(
                        key,
                        index,
                        name.as_mut_ptr(),
                        &mut length,
                        ptr::null(),
                        ptr::null_mut(),
                        ptr::null_mut(),
                        ptr::null_mut(),
                    )
                };
                if code == ERROR_NO_MORE_ITEMS {
                    break;
                }
                ensure!(
                    code == 0,
                    "ProfileList enumeration failed: Windows error {code}"
                );
                name.truncate(length as usize);
                name.push(0);
                let mut bytes = 0;
                // SAFETY: size query with null data; the strings are NUL-terminated.
                let code = unsafe {
                    RegGetValueW(
                        key,
                        name.as_ptr(),
                        wide("ProfileImagePath").as_ptr(),
                        RRF_RT_REG_SZ | RRF_RT_REG_EXPAND_SZ,
                        ptr::null_mut(),
                        ptr::null_mut(),
                        &mut bytes,
                    )
                };
                if code == ERROR_FILE_NOT_FOUND {
                    continue;
                }
                ensure!(
                    code == 0 && bytes < 1024 * 1024,
                    "Cannot size ProfileImagePath: Windows error {code}"
                );
                let mut data = vec![0u16; (bytes as usize).div_ceil(2)];
                // SAFETY: capacity matches the queried byte count; API expands REG_EXPAND_SZ.
                let code = unsafe {
                    RegGetValueW(
                        key,
                        name.as_ptr(),
                        wide("ProfileImagePath").as_ptr(),
                        RRF_RT_REG_SZ | RRF_RT_REG_EXPAND_SZ,
                        ptr::null_mut(),
                        data.as_mut_ptr() as *mut _,
                        &mut bytes,
                    )
                };
                ensure!(
                    code == 0,
                    "Cannot read ProfileImagePath: Windows error {code}"
                );
                let length = data.iter().position(|&c| c == 0).unwrap_or(data.len());
                paths.push(std::path::PathBuf::from(String::from_utf16(
                    &data[..length],
                )?));
            }
            Ok(paths)
        })();
        // SAFETY: this function owns the open registry key.
        unsafe {
            RegCloseKey(key);
        }
        result
    }

    pub(super) fn windows_volume_name() -> Result<String> {
        let mut directory = vec![0u16; 32768];
        // SAFETY: writable buffer with its actual UTF-16 capacity.
        let length = unsafe {
            windows_sys::Win32::System::SystemInformation::GetSystemWindowsDirectoryW(
                directory.as_mut_ptr(),
                directory.len() as u32,
            )
        } as usize;
        ensure!(
            length > 0 && length < directory.len(),
            "Cannot resolve the Windows directory"
        );
        let path = PathBuf::from(String::from_utf16(&directory[..length])?);
        volume_for_path(&path)?.context("The running Windows volume must be local")
    }

    /// Resolve the actual volume, including junctions, mounted folders, GUID
    /// paths and differently cased drive aliases. Never compare path prefixes
    /// to decide which volume holds evidence output.
    pub(super) fn volume_for_path(path: &Path) -> Result<Option<String>> {
        use std::os::windows::ffi::OsStrExt;
        if is_remote_windows_path(&path.to_string_lossy()) {
            return Ok(None);
        }
        // Start from a verified existing ancestor: trailing output components
        // may not exist, and GetVolumePathName accepts invalid path tails.
        let absolute = if path.is_absolute() {
            path.to_owned()
        } else {
            std::env::current_dir()?.join(path)
        };
        let mut existing = absolute.as_path();
        while !existing.try_exists()? {
            existing = existing
                .parent()
                .context("Destination path has no existing ancestor")?;
        }
        let existing = crate::platform::canonicalize(existing)?;
        let input: Vec<u16> = existing.as_os_str().encode_wide().chain(Some(0)).collect();
        let mut mount = vec![0u16; 32768];
        ensure!(
            // SAFETY: terminated existing path and owned writable buffer.
            unsafe { GetVolumePathNameW(input.as_ptr(), mount.as_mut_ptr(), mount.len() as u32) }
                != 0,
            "Cannot resolve volume mount point: {}",
            std::io::Error::last_os_error()
        );
        // A mapped network drive is remote even if its path has a DOS letter.
        // SAFETY: the mount buffer contains the terminated API result.
        if unsafe { GetDriveTypeW(mount.as_ptr()) } == DRIVE_REMOTE {
            return Ok(None);
        }
        let mut volume = vec![0u16; 1024];
        ensure!(
            // SAFETY: terminated mount point and owned writable buffer.
            unsafe {
                GetVolumeNameForVolumeMountPointW(
                    mount.as_ptr(),
                    volume.as_mut_ptr(),
                    volume.len() as u32,
                )
            } != 0,
            "Cannot resolve volume identity: {}",
            std::io::Error::last_os_error()
        );
        let end = volume
            .iter()
            .position(|&c| c == 0)
            .context("Invalid volume name")?;
        Ok(Some(String::from_utf16(&volume[..end])?))
    }

    pub fn live_sources(destination: Option<&Path>) -> Result<SourceDiscovery> {
        enable_backup_privilege()?;
        let system_volume = windows_volume_name()?;
        let destination_volume = destination.map(volume_for_path).transpose()?.flatten();
        let profiles = profile_paths()?;
        let mut report = SourceDiscovery::default();
        let mut volume = vec![0u16; 1024];
        // SAFETY: writable buffer with advertised capacity.
        let handle = unsafe { FindFirstVolumeW(volume.as_mut_ptr(), volume.len() as u32) };
        ensure!(
            handle != INVALID_HANDLE_VALUE,
            "Cannot enumerate volumes: {}",
            std::io::Error::last_os_error()
        );
        let result: Result<()> = (|| {
            loop {
                let n = volume
                    .iter()
                    .position(|&c| c == 0)
                    .context("Invalid volume name")?;
                let guid = String::from_utf16(&volume[..n])?;
                let system = guid.eq_ignore_ascii_case(&system_volume);
                // Local fixed volumes only; removable media stays an explicit choice.
                // SAFETY: volume contains the API-supplied NUL-terminated volume path.
                if system || unsafe { GetDriveTypeW(volume.as_ptr()) } == DRIVE_FIXED {
                    let unavailable_id =
                        format!("Volume-{}", &crate::model::sha256(guid.as_bytes())[..12]);
                    let attempted = (|| -> Result<Option<Source>> {
                        let mut needed = 0;
                        // SAFETY: null buffer is a documented size query.
                        unsafe {
                            GetVolumePathNamesForVolumeNameW(
                                volume.as_ptr(),
                                ptr::null_mut(),
                                0,
                                &mut needed,
                            );
                        }
                        ensure!(
                            needed > 0 && needed < 1024 * 1024,
                            "Cannot size mount points for {guid}"
                        );
                        let mut mounts = vec![0u16; needed as usize];
                        ensure!(
                            // SAFETY: mount buffer has the queried capacity.
                            unsafe {
                                GetVolumePathNamesForVolumeNameW(
                                    volume.as_ptr(),
                                    mounts.as_mut_ptr(),
                                    needed,
                                    &mut needed,
                                )
                            } != 0,
                            "Cannot enumerate volume mount points"
                        );
                        let mount = mounts
                            .split(|&c| c == 0)
                            .filter(|s| !s.is_empty())
                            .map(String::from_utf16)
                            .collect::<std::result::Result<Vec<_>, _>>()?
                            .into_iter()
                            .min_by_key(|s| s.len())
                            .unwrap_or(guid.clone());
                        let id = if mount.len() == 3 && mount.as_bytes()[1] == b':' {
                            mount[..1].to_uppercase()
                        } else {
                            format!("Volume-{}", &crate::model::sha256(guid.as_bytes())[..12])
                        };
                        if !system
                            && destination_volume
                                .as_ref()
                                .is_some_and(|d| d.eq_ignore_ascii_case(&guid))
                        {
                            report.issues.push(Issue {
                                source_id: id, path: mount, status: "Excluded".into(),
                                reason: "Destination volume: this run writes its output here, so the volume is not acquired (only the running Windows volume is acquired regardless)".into(),
                            });
                            return Ok(None);
                        }
                        let mut fsname = vec![0u16; 64];
                        // SAFETY: optional outputs are null; fsname is a valid writable buffer.
                        let inspected = unsafe {
                            GetVolumeInformationW(
                                volume.as_ptr(),
                                ptr::null_mut(),
                                0,
                                ptr::null_mut(),
                                ptr::null_mut(),
                                ptr::null_mut(),
                                fsname.as_mut_ptr(),
                                fsname.len() as u32,
                            )
                        };
                        if inspected == 0 {
                            let error = std::io::Error::last_os_error();
                            // Unformatted, BitLocker-locked and empty removable
                            // volumes hold nothing a live collection can read;
                            // they are recorded without failing the run.
                            let unreadable = [
                                ERROR_NOT_READY,
                                ERROR_UNRECOGNIZED_VOLUME,
                                ERROR_NO_MEDIA_IN_DRIVE,
                            ]
                            .iter()
                            .any(|&code| error.raw_os_error() == Some(code as i32));
                            if !system && unreadable {
                                report.issues.push(Issue {
                                    source_id: id,
                                    path: mount,
                                    status: "Excluded".into(),
                                    reason: format!(
                                        "Volume has no readable file system (unformatted, locked or no media): {error}"
                                    ),
                                });
                                return Ok(None);
                            }
                            bail!("Cannot inspect filesystem type: {error}");
                        }
                        let end = fsname.iter().position(|&c| c == 0).unwrap_or(fsname.len());
                        let ntfs = String::from_utf16(&fsname[..end])?.eq_ignore_ascii_case("NTFS");
                        let mut source = crate::discovery::directory_source(
                            Path::new(&mount),
                            &id,
                            &computer_name(),
                        )?;
                        if ntfs {
                            source.raw_device = Some(guid.trim_end_matches('\\').into());
                        }
                        for profile in &profiles {
                            if !profile.is_absolute()
                                || is_remote_windows_path(&profile.to_string_lossy())
                            {
                                source.excluded_profiles.push(profile.display().to_string());
                                continue;
                            }
                            if let Ok(path) = crate::platform::canonicalize(profile)
                                && path.starts_with(&source.root)
                            {
                                source.profile_roots.push(path);
                            }
                        }
                        source.profile_roots.sort();
                        source.profile_roots.dedup();
                        source.live = true;
                        Ok(Some(source))
                    })();
                    match attempted {
                        Ok(Some(source)) => {
                            record_source(&mut report, unavailable_id, Path::new(&guid), Ok(source))
                        }
                        Ok(None) => {}
                        Err(error) => {
                            record_source(&mut report, unavailable_id, Path::new(&guid), Err(error))
                        }
                    }
                }
                // SAFETY: handle is live and the buffer is writable.
                if unsafe { FindNextVolumeW(handle, volume.as_mut_ptr(), volume.len() as u32) } == 0
                {
                    // SAFETY: this call reads the immediately preceding API result.
                    let e = unsafe { GetLastError() };
                    if e != ERROR_NO_MORE_FILES {
                        report.issues.push(Issue {
                            source_id: "VolumeEnumeration".into(),
                            path: "Local fixed volumes".into(),
                            status: "Failed".into(),
                            reason: format!("Volume enumeration stopped: Windows error {e}"),
                        });
                    }
                    break;
                }
            }
            Ok(())
        })();
        // SAFETY: handle is exclusively owned by this enumeration.
        unsafe {
            FindVolumeClose(handle);
        }
        result?;
        ensure!(
            !report.sources.is_empty(),
            "No accessible fixed volumes were discovered: {}",
            report
                .issues
                .iter()
                .map(|i| i.reason.as_str())
                .collect::<Vec<_>>()
                .join("; ")
        );
        Ok(report)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    #[cfg(windows)]
    use std::path::PathBuf;

    #[cfg(windows)]
    #[test]
    fn live_sources_keep_the_windows_volume_and_exclude_only_a_secondary_destination_volume() {
        fn is_system(system: &str, source: &Source) -> bool {
            source.raw_device.as_ref().is_some_and(|device| {
                device
                    .to_string_lossy()
                    .eq_ignore_ascii_case(system.trim_end_matches('\\'))
            })
        }
        let system = windows::windows_volume_name().unwrap();
        let sources = live_sources(None).unwrap().sources;
        assert_eq!(sources.iter().filter(|s| is_system(&system, s)).count(), 1);
        // Every local volume keeps the catalog scope; nothing is metadata-only by default.
        assert!(sources.iter().all(|s| s.live && !s.metadata_only));
        // Output on the Windows volume never removes that volume from scope.
        let windows_root = sources
            .iter()
            .find(|s| is_system(&system, s))
            .unwrap()
            .root
            .clone();
        let report = live_sources(Some(&windows_root.join("Kumade-Results"))).unwrap();
        assert_eq!(report.sources.len(), sources.len());
        assert!(report.sources.iter().any(|s| is_system(&system, s)));
        // A secondary volume that holds the output is excluded with a durable reason.
        if let Some(secondary) = sources.iter().find(|s| !is_system(&system, s)) {
            let mut aliases = vec![
                secondary.root.clone(),
                PathBuf::from(secondary.root.to_string_lossy().to_ascii_lowercase()),
            ];
            // Non-NTFS volumes are sources too but have no raw device to alias.
            if let Some(device) = &secondary.raw_device {
                aliases.push(PathBuf::from(format!("{}\\", device.display())));
            }
            for alias in aliases {
                let report = live_sources(Some(&alias.join("Kumade-Results"))).unwrap();
                assert!(
                    report.sources.iter().all(|s| s.id != secondary.id),
                    "{}",
                    alias.display()
                );
                assert!(report.sources.iter().any(|s| is_system(&system, s)));
                assert!(report.issues.iter().any(|i| i.source_id == secondary.id
                    && i.status == "Excluded"
                    && i.reason.starts_with("Destination volume")));
            }
        }
    }

    #[cfg(windows)]
    #[test]
    fn volume_identity_is_preserved_through_guid_paths_and_uncreated_destinations() {
        use std::os::windows::fs::OpenOptionsExt;
        use windows_sys::Win32::Storage::FileSystem::*;
        let temp = tempfile::tempdir().unwrap();
        let handle = OpenOptions::new()
            .access_mode(0)
            .custom_flags(FILE_FLAG_BACKUP_SEMANTICS)
            .open(temp.path())
            .unwrap();
        let guid_path = windows::final_path(&handle, VOLUME_NAME_GUID).unwrap();
        let normal = windows::volume_for_path(temp.path()).unwrap().unwrap();
        let future = guid_path
            .join("not-created")
            .join("HOST_2026-11-20_15-23-12.vhdx");
        assert_eq!(
            windows::volume_for_path(&future).unwrap().as_deref(),
            Some(normal.as_str())
        );
        let differently_cased = PathBuf::from(temp.path().to_string_lossy().to_ascii_lowercase());
        assert_eq!(
            windows::volume_for_path(&differently_cased)
                .unwrap()
                .as_deref(),
            Some(normal.as_str())
        );
        assert_eq!(
            windows::volume_for_path(Path::new(r"\\example.invalid\share\capture")).unwrap(),
            None
        );
    }

    #[test]
    fn unavailable_volume_does_not_discard_an_accessible_source() {
        let temp = tempfile::tempdir().unwrap();
        let source = crate::discovery::directory_source(temp.path(), "C", "HOST01").unwrap();
        let mut report = SourceDiscovery::default();
        record_source(
            &mut report,
            "UnavailableVolume".into(),
            Path::new("unavailable-volume"),
            Err(std::io::Error::new(std::io::ErrorKind::PermissionDenied, "fixture denied").into()),
        );
        record_source(&mut report, "C".into(), temp.path(), Ok(source));
        assert_eq!(report.sources.len(), 1);
        assert_eq!(report.sources[0].id, "C");
        assert_eq!(report.issues.len(), 1);
        assert_eq!(report.issues[0].status, "Failed");
        assert!(report.issues[0].reason.contains("fixture denied"));
    }

    #[cfg(windows)]
    #[test]
    fn missing_dos_volume_name_falls_back_to_a_resolved_guid_path() {
        let temp = tempfile::tempdir().unwrap();
        let resolved = super::windows::canonicalize_with(temp.path(), |_| {
            Err(std::io::Error::from_raw_os_error(3))
        })
        .unwrap();
        assert!(
            resolved
                .to_string_lossy()
                .to_ascii_lowercase()
                .starts_with("\\\\?\\volume{")
        );
        assert!(resolved.is_dir());
        assert_eq!(
            std::fs::canonicalize(&resolved).unwrap(),
            std::fs::canonicalize(temp.path()).unwrap()
        );
    }

    #[cfg(windows)]
    #[test]
    fn canonicalization_does_not_mask_access_denied() {
        let result = super::windows::canonicalize_with(Path::new("does-not-exist"), |_| {
            Err(std::io::Error::from_raw_os_error(5))
        });
        assert_eq!(result.unwrap_err().raw_os_error(), Some(5));
    }

    #[cfg(windows)]
    #[test]
    fn source_containment_uses_the_guid_namespace_when_the_root_does() {
        use std::os::windows::fs::OpenOptionsExt;
        use windows_sys::Win32::Storage::FileSystem::*;
        let temp = tempfile::tempdir().unwrap();
        let inside = temp.path().join("inside");
        let outside = temp.path().join("outside");
        std::fs::create_dir_all(&inside).unwrap();
        std::fs::create_dir_all(&outside).unwrap();
        std::fs::write(inside.join("input"), b"fixture").unwrap();
        let root_handle = OpenOptions::new()
            .access_mode(0)
            .custom_flags(FILE_FLAG_BACKUP_SEMANTICS)
            .open(&inside)
            .unwrap();
        let other_handle = OpenOptions::new()
            .access_mode(0)
            .custom_flags(FILE_FLAG_BACKUP_SEMANTICS)
            .open(&outside)
            .unwrap();
        let guid_root = super::windows::final_path(&root_handle, VOLUME_NAME_GUID).unwrap();
        let other_root = super::windows::final_path(&other_handle, VOLUME_NAME_GUID).unwrap();
        let file = open_source(&inside.join("input")).unwrap();
        validate_open_file(&file, &guid_root).unwrap();
        assert!(validate_open_file(&file, &other_root).is_err());
    }
}
