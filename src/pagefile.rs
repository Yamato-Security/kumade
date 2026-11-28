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

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Kind {
    Pagefile,
    Swapfile,
}
impl Kind {
    fn artifact(self) -> &'static str {
        match self {
            Self::Pagefile => ARTIFACT,
            Self::Swapfile => "windows.memory.swapfile",
        }
    }
    fn payload(self, index: usize) -> String {
        match self {
            Self::Pagefile => format!("Memory/Pagefile{index}.sys"),
            Self::Swapfile => "Memory/Swapfile.sys".into(),
        }
    }
    pub fn failure(self, computer: &str, error: String) -> Record {
        let mut row = failure(computer, error);
        if self == Self::Swapfile {
            row.artifact_ids = self.artifact().into();
            row.source_path = "Windows system-volume swapfile.sys".into();
            row.method = "SwapfileDiscovery".into();
        }
        row
    }
}

pub fn load(root: &Path) -> Result<Vec<Record>> {
    let path = root.join(INVENTORY);
    if !path.exists() {
        return Ok(Vec::new());
    }
    let rows: Vec<Record> = serde_json::from_reader(fs::File::open(path)?)?;
    let mut ids = std::collections::HashSet::new();
    for row in &rows {
        ensure!(
            matches!(
                row.artifact_ids.as_str(),
                ARTIFACT | "windows.memory.swapfile"
            ) && row.source_id == "Memory"
                && ids.insert(&row.observation_id),
            "Invalid paired-pagefile inventory"
        );
        if let Some(name) = &row.relative_output_path {
            ensure!(
                if row.artifact_ids == Kind::Swapfile.artifact() {
                    name == "Memory/Swapfile.sys"
                } else {
                    name.strip_prefix("Memory/Pagefile")
                        .and_then(|n| n.strip_suffix(".sys"))
                        .is_some_and(|n| !n.is_empty() && n.bytes().all(|c| c.is_ascii_digit()))
                },
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
fn active_pagefiles() -> Result<Vec<PathBuf>> {
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
    active_paths(data, buffer.as_ptr() as usize, std::mem::size_of::<usize>())
}

#[cfg(windows)]
fn mount_point(path: &Path) -> Result<PathBuf> {
    use std::os::windows::ffi::OsStrExt;
    use windows_sys::Win32::Storage::FileSystem::GetVolumePathNameW;
    let wide: Vec<u16> = path.as_os_str().encode_wide().chain(Some(0)).collect();
    let mut mount = vec![0u16; 32768];
    ensure!(
        // SAFETY: NUL-terminated input and writable UTF-16 output buffer.
        unsafe { GetVolumePathNameW(wide.as_ptr(), mount.as_mut_ptr(), mount.len() as u32) } != 0,
        "Cannot locate paging-file volume: {}",
        io::Error::last_os_error()
    );
    let end = mount
        .iter()
        .position(|c| *c == 0)
        .context("Unterminated volume path")?;
    Ok(PathBuf::from(String::from_utf16(&mount[..end])?))
}

#[cfg(windows)]
fn input(computer: &str, kind: Kind, path: &Path) -> Result<Option<Input>> {
    use std::os::windows::ffi::OsStrExt;
    use windows_sys::Win32::Storage::FileSystem::GetVolumeNameForVolumeMountPointW;
    let root = mount_point(path)?;
    let mount: Vec<_> = root.as_os_str().encode_wide().chain(Some(0)).collect();
    let mut guid = vec![0u16; 32768];
    ensure!(
        // SAFETY: NUL-terminated volume mount point and writable UTF-16 buffer.
        unsafe {
            GetVolumeNameForVolumeMountPointW(mount.as_ptr(), guid.as_mut_ptr(), guid.len() as u32)
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
    let mut volume = crate::raw::RawVolume::open(source.raw_device.as_ref().unwrap())?;
    let stat = match volume.stat(&relative, None) {
        Ok(stat) => stat,
        Err(e) if kind == Kind::Swapfile && crate::raw::is_missing(&e) => return Ok(None),
        Err(e) => return Err(e),
    };
    let file = PlannedFile {
        id: uuid::Uuid::new_v4().to_string(),
        source_id: "Memory".into(),
        source_path: path.to_owned(),
        relative_path: relative,
        stream: None,
        artifacts: vec![kind.artifact().into()],
        before: Some(Fingerprint {
            size: stat.size,
            identity: Some(stat.identity),
            ..Default::default()
        }),
        expected_sha256: None,
    };
    Ok(Some(Input { source, file }))
}
#[cfg(windows)]
pub fn discover(computer: &str, kind: Kind, records: &mut Vec<Record>) -> Result<Vec<Input>> {
    let swap_path = || {
        Ok::<_, anyhow::Error>(
            mount_point(&crate::platform::system_windows_directory()?)?.join("swapfile.sys"),
        )
    };
    let mut paths = match kind {
        Kind::Swapfile => vec![swap_path()?],
        Kind::Pagefile => {
            let mut paths = active_pagefiles()?;
            if paths.iter().any(|p| {
                p.file_name()
                    .is_some_and(|n| n.eq_ignore_ascii_case(std::ffi::OsStr::new("swapfile.sys")))
            }) {
                let swap = swap_path()?;
                paths.retain(|p| !p.as_os_str().eq_ignore_ascii_case(swap.as_os_str()));
            }
            paths
        }
    };
    let mut seen = std::collections::HashSet::new();
    paths.retain(|p| seen.insert(p.to_string_lossy().to_ascii_lowercase()));
    let mut inputs = Vec::new();
    for path in paths {
        let mut row = match input(computer, kind, &path) {
            Ok(Some(file)) => {
                inputs.push(file);
                continue;
            }
            Ok(None) => {
                let mut row = kind.failure(
                    computer,
                    "No swapfile.sys on the running Windows volume".into(),
                );
                row.status = "NotPresent".into();
                row
            }
            Err(e) => kind.failure(computer, format!("{e:#}")),
        };
        row.source_path = path.display().to_string();
        records.push(row);
    }
    Ok(inputs)
}
#[cfg(not(windows))]
pub fn discover(_computer: &str, _kind: Kind, _records: &mut Vec<Record>) -> Result<Vec<Input>> {
    anyhow::bail!("Paired acquisition requires live Windows")
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

/// Begin reading paging files once DumpIt has written RAM payload, not merely
/// while its executable/driver is starting. Never wait indefinitely if startup fails.
pub fn wait_for_ram(
    path: &Path,
    stopped: &std::sync::atomic::AtomicBool,
    timeout: Duration,
) -> Result<()> {
    let started = Instant::now();
    loop {
        if fs::metadata(path).is_ok_and(|m| m.len() > 8192) {
            return Ok(());
        }
        ensure!(
            !stopped.load(std::sync::atomic::Ordering::Acquire),
            "RAM provider stopped before producing payload; paired pagefile capture did not start"
        );
        ensure!(
            started.elapsed() < timeout,
            "Timed out waiting for RAM provider payload"
        );
        std::thread::sleep(Duration::from_millis(10));
    }
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
    kind: Kind,
    inputs: Vec<Input>,
    reserve: u64,
    timeout: Duration,
) -> Result<Vec<Record>> {
    let deadline = Instant::now() + timeout;
    let mut cache = std::collections::HashMap::new();
    let mut rows = Vec::new();
    for (index, input) in inputs.into_iter().enumerate() {
        let mut row = kind.failure(computer, String::new());
        row.observation_id = input.file.id.clone();
        row.source_path = input.file.source_path.display().to_string();
        row.method = "Native".into();
        row.logical_size = input.file.before.as_ref().map(|f| f.size);
        let name = kind.payload(index);
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
            row.logical_size = Some(before.size);
            row.created_utc = before.created_ns.clone();
            row.modified_utc = before.modified_ns.clone();
            row.accessed_utc = before.accessed_ns.clone();
            row.source_file_id = before.identity.clone();
            // As for disk artifacts: a file whose size or metadata moved since it was
            // discovered, or while it was read, is a complete copy of a changed file
            // and is recorded as Partial with its bytes, not as a failure.
            row.changed_during_read = !crate::discovery::same_version(&before, &after)
                || input
                    .file
                    .before
                    .as_ref()
                    .is_some_and(|planned| !crate::discovery::same_version(planned, &before));
            // The pagefile contents can change without an NTFS timestamp update.
            row.status = "Acquired".into();
            row.reason = "Live file read during the RAM acquisition phase. See the read intervals; Windows can change content without updating NTFS timestamps.".into();
            if row.changed_during_read {
                row.status = "Partial".into();
                row.reason
                    .push_str(" Source metadata changed since planning or during acquisition.");
            }
            Ok(())
        })();
        row.finished_utc = utc_now();
        if target.exists() {
            let (bytes, digest) = collect::hash_file(&target)?;
            row.bytes_read = bytes;
            row.sha256 = Some(digest);
            row.relative_output_path = Some(name);
        }
        match outcome {
            // The stored bytes were hashed; a failed copy keeps its bytes and hash but, like
            // a retained `.partial` disk payload, is not a verified acquisition.
            Ok(()) => row.verified = row.relative_output_path.is_some(),
            Err(error) => {
                row.status = "Failed".into();
                row.reason = format!("{error:#}");
            }
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
        .filter(|r| {
            matches!(
                r.artifact_ids.as_str(),
                ARTIFACT | "windows.memory.swapfile"
            ) && r.relative_output_path.is_some()
        })
        .map(|r| key(Path::new(&r.source_path)))
        .collect();
    if paths.is_empty() {
        return;
    }
    let sources = &plan.sources;
    plan.files.retain(|file| {
        let source = sources.iter().find(|s| s.id == file.source_id);
        let historical = source
            .and_then(|s| s.snapshot.as_ref())
            .is_some_and(|s| s.owned_by_collector != Some(true));
        let paired = file.stream.is_none()
            && !historical
            && (paths.contains(&key(&file.source_path))
                || source.is_some_and(|s| {
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
    fn paired_copy_waits_for_ram_bytes_and_startup_failure_cannot_hang() {
        use std::sync::atomic::AtomicBool;
        let t = tempfile::tempdir().unwrap();
        let path = t.path().join("Memory.dmp");
        let stopped = AtomicBool::new(true);
        assert!(wait_for_ram(&path, &stopped, Duration::from_secs(10)).is_err());
        assert!(wait_for_ram(&path, &AtomicBool::new(false), Duration::ZERO).is_err());
        fs::write(&path, vec![0; 8192]).unwrap();
        assert!(wait_for_ram(&path, &stopped, Duration::from_secs(10)).is_err());
        fs::OpenOptions::new()
            .write(true)
            .open(&path)
            .unwrap()
            .set_len(12288)
            .unwrap();
        wait_for_ram(&path, &stopped, Duration::from_secs(10)).unwrap();
    }
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
        row.relative_output_path = Some("Memory/Pagefile0.sys".into());
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
        let rows = acquire(
            &output,
            "TEST",
            Kind::Pagefile,
            vec![make()],
            0,
            Duration::from_secs(10),
        )
        .unwrap();
        assert_eq!(rows[0].status, "Acquired", "{}", rows[0].reason);
        assert_eq!(rows[0].bytes_read, 18);
        assert_eq!(
            fs::read(output.join("Memory/Pagefile0.sys")).unwrap(),
            b"paged out evidence"
        );
        fs::write(source.join("swapfile.sys"), b"swap evidence").unwrap();
        let mut swap = make();
        swap.file.source_path = source.join("swapfile.sys");
        swap.file.relative_path = "swapfile.sys".into();
        swap.file.id = "SWAP".into();
        swap.file.artifacts = vec![Kind::Swapfile.artifact().into()];
        swap.file.before.as_mut().unwrap().size = 13;
        let swaps = acquire(
            &output,
            "TEST",
            Kind::Swapfile,
            vec![swap],
            0,
            Duration::from_secs(10),
        )
        .unwrap();
        assert_eq!(swaps[0].status, "Acquired");
        assert_eq!(
            swaps[0].relative_output_path.as_deref(),
            Some("Memory/Swapfile.sys")
        );
        assert_eq!(
            fs::read(output.join("Memory/Swapfile.sys")).unwrap(),
            b"swap evidence"
        );
        let inventory: Vec<_> = rows.iter().chain(&swaps).collect();
        collect::write_json_new(&output.join(INVENTORY), &inventory).unwrap();
        assert_eq!(load(&output).unwrap().len(), 2);
        let output2 = temp.path().join("expired");
        fs::create_dir_all(output2.join("Memory")).unwrap();
        let rows = acquire(
            &output2,
            "TEST",
            Kind::Pagefile,
            vec![make()],
            0,
            Duration::ZERO,
        )
        .unwrap();
        assert_eq!(rows[0].status, "Failed");
        assert!(rows[0].relative_output_path.is_some());
        assert!(
            !rows[0].verified,
            "a failed copy is not a verified acquisition"
        );
        // A file that grew since discovery is copied in full and recorded as Partial.
        let output3 = temp.path().join("grown");
        fs::create_dir_all(output3.join("Memory")).unwrap();
        let mut input = make();
        input.file.before.as_mut().unwrap().size = 10;
        let rows = acquire(
            &output3,
            "TEST",
            Kind::Pagefile,
            vec![input],
            0,
            Duration::from_secs(10),
        )
        .unwrap();
        assert_eq!(rows[0].status, "Partial", "{}", rows[0].reason);
        assert!(rows[0].changed_during_read && rows[0].verified);
        assert_eq!((rows[0].bytes_read, rows[0].logical_size), (18, Some(18)));
        assert!(
            rows[0].reason.contains("since planning"),
            "{}",
            rows[0].reason
        );
        assert_eq!(
            fs::read(output3.join("Memory/Pagefile0.sys")).unwrap(),
            b"paged out evidence"
        );
    }
}
