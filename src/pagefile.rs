// Copyright (C) 2026 Shirofune Security Co., Ltd.
// SPDX-License-Identifier: RPL-1.5
//! RAM-paired active paging files. Live NTFS reads are deliberately not VSS reads.
use crate::{collect, model::*};
#[cfg(any(windows, test))]
use anyhow::Context;
use anyhow::{Result, ensure};
use std::{
    fs,
    io::{self, Write},
    path::{Path, PathBuf},
    time::{Duration, Instant},
};

pub const INVENTORY: &str = "Memory/Pagefiles.json";
pub const ARTIFACT: &str = "windows.memory.pagefile";

pub fn load(root: &Path) -> Result<Vec<Record>> {
    let path = root.join(INVENTORY);
    if !path.exists() {
        return Ok(Vec::new());
    }
    let rows: Vec<Record> = serde_json::from_reader(fs::File::open(path)?)?;
    let mut ids = std::collections::HashSet::new();
    for row in &rows {
        ensure!(
            row.artifact_ids == ARTIFACT
                && row.source_id == "Memory"
                && ids.insert(&row.observation_id),
            "Invalid paired-pagefile inventory"
        );
        if let Some(name) = &row.relative_output_path {
            ensure!(
                name.starts_with("Memory/Pagefile")
                    && name.ends_with(".sys")
                    && !name[7..].contains(['/', '\\']),
                "Invalid paired-pagefile payload path"
            );
        }
    }
    Ok(rows)
}
pub fn failure(computer: &str, error: String) -> Record {
    Record {
        schema_version: SCHEMA_VERSION,
        observation_id: uuid::Uuid::new_v4().to_string(),
        computer: computer.into(),
        source_id: "Memory".into(),
        source_path: "Active Windows paging files".into(),
        stream_name: None,
        artifact_ids: ARTIFACT.into(),
        relative_output_path: None,
        method: "ActivePagefileQuery".into(),
        status: "Failed".into(),
        reason: error,
        started_utc: utc_now(),
        finished_utc: utc_now(),
        logical_size: None,
        bytes_read: 0,
        sha256: None,
        verified: false,
        changed_during_read: false,
        created_utc: None,
        modified_utc: None,
        accessed_utc: None,
        source_file_id: None,
    }
}
#[derive(Debug)]
pub struct Input {
    pub source: Source,
    pub file: PlannedFile,
}

/// Query active pagefiles, rather than only configured next-boot registry values.
#[cfg(windows)]
pub fn discover(computer: &str) -> Result<Vec<Input>> {
    use std::os::windows::ffi::OsStrExt;
    use windows_sys::Win32::Storage::FileSystem::{
        GetVolumeNameForVolumeMountPointW, GetVolumePathNameW,
    };
    #[link(name = "ntdll")]
    unsafe extern "system" {
        fn NtQuerySystemInformation(
            class: u32,
            data: *mut core::ffi::c_void,
            length: u32,
            returned: *mut u32,
        ) -> i32;
    }
    let mut buffer = vec![0u64; 8192];
    let used;
    loop {
        let mut returned = 0u32;
        // SAFETY: aligned writable storage and its actual size, bounded to 8 MiB.
        let status = unsafe {
            NtQuerySystemInformation(
                18,
                buffer.as_mut_ptr().cast(),
                (buffer.len() * 8) as u32,
                &mut returned,
            )
        };
        if status == 0 {
            used = returned as usize;
            break;
        }
        ensure!(
            status as u32 == 0xc0000004 && buffer.len() * 8 < 8 * 1024 * 1024,
            "Active paging-file query failed: NTSTATUS {:#x}",
            status as u32
        );
        buffer.resize((buffer.len() * 2).max((returned as usize).div_ceil(8)), 0);
        ensure!(
            buffer.len() * 8 <= 8 * 1024 * 1024,
            "Paging-file query exceeded 8 MiB"
        );
    }
    ensure!(used <= buffer.len() * 8, "Invalid paging-file query length");
    // SAFETY: initialized aligned storage is alive throughout parsing; only used bytes are exposed.
    let data = unsafe { std::slice::from_raw_parts(buffer.as_ptr().cast::<u8>(), used) };
    let mut paths = active_paths(data, buffer.as_ptr() as usize, std::mem::size_of::<usize>())?;
    let mut seen = std::collections::HashSet::new();
    paths.retain(|p| seen.insert(p.to_string_lossy().to_ascii_lowercase()));
    paths
        .into_iter()
        .map(|path| {
            let wide: Vec<u16> = path.as_os_str().encode_wide().chain(Some(0)).collect();
            let mut mount = vec![0u16; 32768];
            ensure!(
                // SAFETY: NUL-terminated input and writable UTF-16 output buffer.
                unsafe {
                    GetVolumePathNameW(wide.as_ptr(), mount.as_mut_ptr(), mount.len() as u32)
                } != 0,
                "Cannot locate paging-file volume: {}",
                io::Error::last_os_error()
            );
            let end = mount
                .iter()
                .position(|c| *c == 0)
                .context("Unterminated volume path")?;
            let root = PathBuf::from(String::from_utf16(&mount[..end])?);
            let mut guid = vec![0u16; 32768];
            ensure!(
                // SAFETY: NUL-terminated volume mount point and writable UTF-16 buffer.
                unsafe {
                    GetVolumeNameForVolumeMountPointW(
                        mount.as_ptr(),
                        guid.as_mut_ptr(),
                        guid.len() as u32,
                    )
                } != 0,
                "Cannot resolve paging-file raw volume: {}",
                io::Error::last_os_error()
            );
            let end = guid
                .iter()
                .position(|c| *c == 0)
                .context("Unterminated volume GUID")?;
            let raw = String::from_utf16(&guid[..end])?;
            let relative = path.strip_prefix(&root)?.to_path_buf();
            let source = Source {
                id: "Memory".into(),
                root: crate::platform::canonicalize(&root)?,
                computer: computer.into(),
                live: true,
                raw_device: Some(raw.trim_end_matches('\\').into()),
                profile_roots: Vec::new(),
                excluded_profiles: Vec::new(),
                metadata_only: false,
                snapshot: None,
            };
            let stat = crate::raw::RawVolume::open(source.raw_device.as_ref().unwrap())?
                .stat(&relative, None)?;
            let file = PlannedFile {
                id: uuid::Uuid::new_v4().to_string(),
                source_id: "Memory".into(),
                source_path: path,
                relative_path: relative,
                stream: None,
                artifacts: vec![ARTIFACT.into()],
                before: Some(Fingerprint {
                    size: stat.size,
                    identity: Some(stat.identity),
                    ..Default::default()
                }),
                expected_sha256: None,
            };
            Ok(Input { source, file })
        })
        .collect()
}
#[cfg(not(windows))]
pub fn discover(_computer: &str) -> Result<Vec<Input>> {
    anyhow::bail!("Active pagefile acquisition requires live Windows")
}

/// Checked SYSTEM_PAGEFILE_INFORMATION parser. UNICODE_STRING pointers must fall inside the returned buffer.
#[cfg(any(windows, test))]
fn active_paths(data: &[u8], base: usize, pointer_size: usize) -> Result<Vec<PathBuf>> {
    ensure!(
        matches!(pointer_size, 4 | 8),
        "Invalid native pointer width"
    );
    let mut offset = 0;
    let mut result = Vec::new();
    while offset < data.len() {
        let size = if pointer_size == 8 { 32 } else { 24 };
        let entry = data
            .get(offset..offset + size)
            .context("Truncated paging-file information")?;
        let next = u32::from_le_bytes(entry[..4].try_into()?) as usize;
        let length = u16::from_le_bytes(entry[16..18].try_into()?) as usize;
        let maximum = u16::from_le_bytes(entry[18..20].try_into()?) as usize;
        let ptr = if pointer_size == 8 {
            u64::from_le_bytes(entry[24..32].try_into()?) as usize
        } else {
            u32::from_le_bytes(entry[20..24].try_into()?) as usize
        };
        ensure!(
            length > 0 && length.is_multiple_of(2) && length <= maximum,
            "Invalid active pagefile name length"
        );
        let start = ptr
            .checked_sub(base)
            .context("Paging-file name pointer precedes query buffer")?;
        let bytes = data
            .get(
                start
                    ..start
                        .checked_add(length)
                        .context("Paging-file name overflow")?,
            )
            .context("Paging-file name outside query buffer")?;
        let text = String::from_utf16(
            &bytes
                .as_chunks::<2>()
                .0
                .iter()
                .map(|v| u16::from_le_bytes([v[0], v[1]]))
                .collect::<Vec<_>>(),
        )?;
        let text = text.strip_prefix("\\??\\").unwrap_or(&text);
        ensure!(
            text.as_bytes().get(1) == Some(&b':')
                && text.as_bytes().first().is_some_and(u8::is_ascii_alphabetic)
                && text.as_bytes().get(2) == Some(&b'\\')
                && !text.contains('\0'),
            "Unsupported active pagefile path"
        );
        result.push(text.into());
        if next == 0 {
            break;
        }
        ensure!(
            next >= size && next.is_multiple_of(pointer_size),
            "Invalid paging-file entry offset"
        );
        offset = offset
            .checked_add(next)
            .context("Paging-file offset overflow")?;
        ensure!(
            offset < data.len(),
            "Paging-file entry outside query buffer"
        );
    }
    Ok(result)
}

struct GuardedWriter {
    file: fs::File,
    directory: PathBuf,
    reserve: u64,
    deadline: Instant,
}
impl Write for GuardedWriter {
    fn write(&mut self, bytes: &[u8]) -> io::Result<usize> {
        if Instant::now() >= self.deadline {
            return Err(io::Error::other("Pagefile capture timed out"));
        }
        if fs2::available_space(&self.directory)? < self.reserve.saturating_add(bytes.len() as u64)
        {
            return Err(io::Error::other("Pagefile staging reserve reached"));
        }
        self.file.write(bytes)
    }
    fn flush(&mut self) -> io::Result<()> {
        self.file.flush()
    }
}

pub fn acquire(
    root: &Path,
    computer: &str,
    inputs: Vec<Input>,
    reserve: u64,
    timeout: Duration,
) -> Result<Vec<Record>> {
    let deadline = Instant::now() + timeout;
    let mut cache = std::collections::HashMap::new();
    let mut rows = Vec::new();
    for (index, input) in inputs.into_iter().enumerate() {
        let mut row = failure(computer, String::new());
        row.observation_id = input.file.id.clone();
        row.source_path = input.file.source_path.display().to_string();
        row.method = "Native".into();
        row.logical_size = input.file.before.as_ref().map(|f| f.size);
        let name = format!("Memory/Pagefile{index}.sys");
        let target = root.join(&name);
        let outcome = (|| -> Result<()> {
            let output = fs::OpenOptions::new()
                .create_new(true)
                .write(true)
                .open(&target)?;
            let mut writer = GuardedWriter {
                file: output,
                directory: root.into(),
                reserve,
                deadline,
            };
            let (before, after) = collect::copy_source(
                &input.source,
                &input.file,
                &mut cache,
                false,
                &mut row.method,
                &mut writer,
                |_, _| Ok(()),
            )?;
            writer.file.sync_all()?;
            ensure!(
                row.logical_size == Some(before.size),
                "Pagefile resized between planning and capture"
            );
            row.created_utc = before.created_ns.clone();
            row.modified_utc = before.modified_ns.clone();
            row.accessed_utc = before.accessed_ns.clone();
            row.source_file_id = before.identity.clone();
            row.changed_during_read = !crate::discovery::same_version(&before, &after);
            // The pagefile contents can change without an NTFS timestamp update.
            row.status = "Acquired".into();
            row.reason = "Live paging-file bytes preserved and hashed; captured concurrently with RAM, not atomically. NTFS metadata stability does not establish content stability. PagefileN output numbering is acquisition order, not a proven Windows paging-file index.".into();
            if row.changed_during_read {
                row.status = "Partial".into();
                row.reason
                    .push_str(" Source metadata changed during acquisition.");
            }
            Ok(())
        })();
        row.finished_utc = utc_now();
        if target.exists() {
            let (bytes, digest) = collect::hash_file(&target)?;
            row.bytes_read = bytes;
            row.sha256 = Some(digest);
            row.relative_output_path = Some(name);
            row.verified = true;
        }
        if let Err(error) = outcome {
            row.status = "Failed".into();
            row.reason = format!("{error:#}");
        }
        rows.push(row);
    }
    Ok(rows)
}

/// Avoid a second, later copy when --paging also selected the same active file.
pub fn deduplicate_plan(plan: &mut Plan, rows: &[Record]) {
    fn key(path: &Path) -> String {
        let text = path.to_string_lossy().replace('/', "\\");
        text.strip_prefix("\\\\?\\")
            .unwrap_or(&text)
            .to_ascii_lowercase()
    }
    let paths: std::collections::HashSet<_> = rows
        .iter()
        .filter(|r| r.artifact_ids == ARTIFACT)
        .map(|r| key(Path::new(&r.source_path)))
        .collect();
    let sources = &plan.sources;
    plan.files.retain(|file| {
        let paired = file.stream.is_none()
            && (paths.contains(&key(&file.source_path))
                || sources
                    .iter()
                    .find(|s| s.id == file.source_id)
                    .is_some_and(|s| {
                        paths.contains(&key(&s.live_root().join(&file.relative_path)))
                    }));
        if paired {
            if let Some(before) = &file.before {
                plan.known_bytes = plan.known_bytes.saturating_sub(before.size);
            } else {
                plan.unknown_sizes = plan.unknown_sizes.saturating_sub(1);
            }
        }
        !paired
    });
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn pagefile_names_are_bounded_and_both_pointer_widths_work() {
        for width in [4, 8] {
            let mut data = vec![0; 128];
            let base = 0x1000usize;
            let name: Vec<_> = "\\??\\C:\\pagefile.sys"
                .encode_utf16()
                .flat_map(u16::to_le_bytes)
                .collect();
            data[16..18].copy_from_slice(&(name.len() as u16).to_le_bytes());
            data[18..20].copy_from_slice(&(name.len() as u16).to_le_bytes());
            let pointer = if width == 8 { 24 } else { 20 };
            data[pointer..pointer + width]
                .copy_from_slice(&((base + 64) as u64).to_le_bytes()[..width]);
            data[64..64 + name.len()].copy_from_slice(&name);
            assert_eq!(
                active_paths(&data, base, width).unwrap(),
                vec![PathBuf::from("C:\\pagefile.sys")]
            );
            data[pointer..pointer + width].fill(0xff);
            assert!(active_paths(&data, base, width).is_err());
        }
    }
    #[test]
    fn explicit_paging_does_not_duplicate_paired_files_or_remove_other_streams() {
        let make = |id: &str, path: &str, stream: Option<&str>| PlannedFile {
            id: id.into(),
            source_id: "C".into(),
            source_path: path.into(),
            relative_path: "pagefile.sys".into(),
            stream: stream.map(str::to_string),
            artifacts: vec!["windows.paging".into()],
            before: Some(Fingerprint {
                size: 100,
                ..Default::default()
            }),
            expected_sha256: None,
        };
        let mut plan = Plan {
            schema_version: 1,
            created_utc: utc_now(),
            catalog_sha256: String::new(),
            sources: vec![],
            files: vec![
                make("page", r"\\?\C:\pagefile.sys", None),
                make("swap", r"C:\swapfile.sys", None),
                make("ads", r"C:\pagefile.sys", Some("other")),
            ],
            coverage: vec![],
            issues: vec![],
            known_bytes: 300,
            unknown_sizes: 0,
            memory_requested: true,
            entropy_scan: None,
        };
        let mut row = failure("HOST", String::new());
        row.source_path = r"c:\PAGEFILE.sys".into();
        deduplicate_plan(&mut plan, &[row]);
        assert_eq!(
            plan.files.iter().map(|f| f.id.as_str()).collect::<Vec<_>>(),
            vec!["swap", "ads"]
        );
        assert_eq!(plan.known_bytes, 200);
    }
    #[test]
    fn pagefile_copy_and_partial_bytes_are_preserved() {
        let temp = tempfile::tempdir().unwrap();
        let source = temp.path().join("input");
        fs::create_dir(&source).unwrap();
        fs::write(source.join("pagefile.sys"), b"paged out evidence").unwrap();
        let output = temp.path().join("out");
        fs::create_dir_all(output.join("Memory")).unwrap();
        let make = || Input {
            source: Source {
                id: "Memory".into(),
                root: crate::platform::canonicalize(&source).unwrap(),
                computer: "TEST".into(),
                live: true,
                raw_device: None,
                profile_roots: vec![],
                excluded_profiles: vec![],
                metadata_only: false,
                snapshot: None,
            },
            file: PlannedFile {
                id: "PAGE".into(),
                source_id: "Memory".into(),
                source_path: source.join("pagefile.sys"),
                relative_path: "pagefile.sys".into(),
                stream: None,
                artifacts: vec![ARTIFACT.into()],
                before: Some(Fingerprint {
                    size: 18,
                    ..Default::default()
                }),
                expected_sha256: None,
            },
        };
        let rows = acquire(&output, "TEST", vec![make()], 0, Duration::from_secs(10)).unwrap();
        assert_eq!(rows[0].status, "Acquired", "{}", rows[0].reason);
        assert_eq!(rows[0].bytes_read, 18);
        assert_eq!(
            fs::read(output.join("Memory/Pagefile0.sys")).unwrap(),
            b"paged out evidence"
        );
        let output2 = temp.path().join("expired");
        fs::create_dir_all(output2.join("Memory")).unwrap();
        let rows = acquire(&output2, "TEST", vec![make()], 0, Duration::ZERO).unwrap();
        assert_eq!(rows[0].status, "Failed");
        assert!(rows[0].relative_output_path.is_some());
    }
}
