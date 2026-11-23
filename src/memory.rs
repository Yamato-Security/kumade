// Copyright (C) 2026 Shirofune Security Co., Ltd.
// SPDX-License-Identifier: RPL-1.5

//! Explicit, external DumpIt acquisition. Vendor executables are never redistributed.
use crate::{collect, model::*, platform};
use anyhow::{Context, Result, bail, ensure};
use serde::{Deserialize, Serialize};
use std::{
    fs,
    io::{Read, Seek, SeekFrom},
    path::{Path, PathBuf},
    process::{Command, Stdio},
    time::{Duration, Instant},
};

#[derive(Clone, Debug, clap::Args)]
#[group(id = "DumpItMemoryOptions")]
pub struct Args {
    /// DumpIt toolkit directory or executable (otherwise tools/DumpIt beside Kumade)
    #[arg(long, value_name = "FILE_OR_DIR")]
    pub dumpit: Option<PathBuf>,
    /// Trust a different DumpIt release by its independently verified SHA-256
    #[arg(long, value_name="SHA256", value_parser=parse_digest, requires="dumpit")]
    pub dumpit_sha256: Option<String>,
    /// RAM capture deadline in seconds
    #[arg(long, default_value_t=1800, value_parser=clap::value_parser!(u64).range(1..=86400))]
    pub memory_timeout: u64,
    /// Explicit RAM staging parent (required with --memory and SFTP; prefer external storage)
    #[arg(long, value_name = "DIR")]
    pub memory_staging_dir: Option<PathBuf>,
}
impl Default for Args {
    fn default() -> Self {
        Self {
            dumpit: None,
            dumpit_sha256: None,
            memory_timeout: 1800,
            memory_staging_dir: None,
        }
    }
}
pub fn parse_digest(value: &str) -> std::result::Result<String, String> {
    if value.len() != 64 || !value.bytes().all(|c| c.is_ascii_hexdigit()) {
        return Err("Expected 64 hexadecimal SHA-256 characters".into());
    }
    Ok(value.to_ascii_lowercase())
}
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Architecture {
    X86,
    X64,
    Arm64,
}
impl Architecture {
    pub fn folder(self) -> &'static str {
        match self {
            Self::X86 => "x86",
            Self::X64 => "x64",
            Self::Arm64 => "ARM64",
        }
    }
    fn machine(self) -> u16 {
        match self {
            Self::X86 => 0x14c,
            Self::X64 => 0x8664,
            Self::Arm64 => 0xaa64,
        }
    }
    fn pinned(self) -> &'static str {
        match self {
            Self::X86 => "f4f353821178bdaf3e29b49db6e6d80c543081ac7a4312e5fdb5583b96815839",
            Self::X64 => "6a484c1db7718949c7027abde97e164c7e7e4e4214e3e29fe48ac4364c0cd23c",
            Self::Arm64 => "13bca00d0042748780b761fb93768754dfd96f48944e6cec75618cad93b3b5d5",
        }
    }
}
pub fn native_architecture() -> Result<Architecture> {
    #[cfg(windows)]
    {
        use windows_sys::Win32::System::Threading::{GetCurrentProcess, IsWow64Process2};
        let (mut process, mut native) = (0u16, 0u16);
        // SAFETY: current process pseudo-handle and initialized writable machine codes.
        ensure!(
            unsafe { IsWow64Process2(GetCurrentProcess(), &mut process, &mut native) } != 0,
            "Cannot determine native Windows architecture: {}",
            std::io::Error::last_os_error()
        );
        match native {
            0x14c => Ok(Architecture::X86),
            0x8664 => Ok(Architecture::X64),
            0xaa64 => Ok(Architecture::Arm64),
            v => bail!("Unsupported Windows architecture: {v}"),
        }
    }
    #[cfg(not(windows))]
    bail!("RAM acquisition requires live Windows")
}
pub fn physical_bytes() -> Result<u64> {
    #[cfg(windows)]
    {
        use windows_sys::Win32::System::SystemInformation::{GlobalMemoryStatusEx, MEMORYSTATUSEX};
        let mut status = MEMORYSTATUSEX {
            dwLength: std::mem::size_of::<MEMORYSTATUSEX>() as u32,
            ..Default::default()
        };
        // SAFETY: initialized output structure with its documented size.
        ensure!(
            unsafe { GlobalMemoryStatusEx(&mut status) } != 0,
            "Cannot determine physical RAM size: {}",
            std::io::Error::last_os_error()
        );
        Ok(status.ullTotalPhys)
    }
    #[cfg(not(windows))]
    bail!("RAM sizing requires Windows")
}
fn tool_path(args: &Args, arch: Architecture) -> Result<PathBuf> {
    let base = match &args.dumpit {
        Some(p) => p.clone(),
        None => std::env::current_exe()?
            .parent()
            .context("Executable has no parent")?
            .join("tools/DumpIt"),
    };
    let path = if base.is_dir() {
        base.join(arch.folder()).join("DumpIt.exe")
    } else {
        base
    };
    platform::canonicalize(&path).with_context(|| {
        format!(
            "Cannot find {} DumpIt; use --dumpit <toolkit-directory>",
            arch.folder()
        )
    })
}
/// Keep the verified executable open with write/delete sharing denied until the child exits.
fn trusted_tool(args: &Args, arch: Architecture) -> Result<(PathBuf, fs::File, String)> {
    let path = tool_path(args, arch)?;
    let mut options = fs::OpenOptions::new();
    options.read(true);
    #[cfg(windows)]
    {
        use std::os::windows::fs::OpenOptionsExt;
        options.share_mode(windows_sys::Win32::Storage::FileSystem::FILE_SHARE_READ);
    }
    let mut file = options.open(&path)?;
    ensure!(
        file.metadata()?.is_file(),
        "DumpIt must be a regular executable file"
    );
    let mut hasher = sha2::Sha256::new();
    use sha2::Digest;
    let mut buffer = [0u8; 65536];
    loop {
        let n = file.read(&mut buffer)?;
        if n == 0 {
            break;
        }
        hasher.update(&buffer[..n]);
    }
    let digest = hex(&hasher.finalize());
    let expected = args.dumpit_sha256.as_deref().unwrap_or(arch.pinned());
    ensure!(
        digest == expected,
        "Unrecognized DumpIt SHA-256; verify the vendor binary independently before using --dumpit-sha256"
    );
    file.seek(SeekFrom::Start(0))?;
    let mut dos = [0; 64];
    file.read_exact(&mut dos)?;
    ensure!(&dos[..2] == b"MZ", "DumpIt has no DOS executable header");
    let offset = u32::from_le_bytes(dos[60..64].try_into()?) as u64;
    file.seek(SeekFrom::Start(offset))?;
    let mut pe = [0; 6];
    file.read_exact(&mut pe)?;
    ensure!(
        &pe[..4] == b"PE\0\0" && u16::from_le_bytes(pe[4..6].try_into()?) == arch.machine(),
        "DumpIt executable does not match native Windows architecture"
    );
    Ok((path, file, digest))
}

#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(rename_all = "PascalCase")]
pub struct DumpLayout {
    pub machine: u32,
    pub dump_type: u32,
    pub runs: u32,
    pub pages: u64,
    pub expected_bytes: u64,
}
/// Full, uncompressed Microsoft crash dump only. Bound descriptor reads to the header.
/// Layout references: Volatility Foundation's crash.json/crash64.json and crash layer.
/// This checks structure/length, not the coherence of a changing live machine's pages.
pub fn validate_dump(path: &Path, arch: Architecture) -> Result<DumpLayout> {
    let mut file = platform::open_source(path)?;
    let length = file.metadata()?.len();
    let mut signature = [0; 8];
    file.read_exact(&mut signature)
        .context("Incomplete RAM dump header")?;
    let (size, machine_offset, type_offset, runs_offset, run_start, width, run_end) =
        match &signature {
            b"PAGEDU64" => (8192, 48, 3992, 136, 152, 8, 840),
            b"PAGEDUMP" => (4096, 32, 3976, 100, 108, 4, 800),
            _ => bail!("Not an uncompressed Microsoft full-memory dump"),
        };
    let mut header = vec![0; size];
    file.seek(SeekFrom::Start(0))?;
    file.read_exact(&mut header)?;
    let u32_at = |offset| {
        u32::from_le_bytes(
            header[offset..offset + 4]
                .try_into()
                .expect("bounded header"),
        )
    };
    let number = |offset| {
        if width == 8 {
            u64::from_le_bytes(header[offset..offset + 8].try_into().expect("bounded run"))
        } else {
            u32_at(offset) as u64
        }
    };
    let machine = u32_at(machine_offset);
    let dump_type = u32_at(type_offset);
    let runs = u32_at(runs_offset);
    ensure!(
        machine == arch.machine() as u32,
        "RAM dump architecture differs from Windows"
    );
    ensure!(
        dump_type == 1,
        "Unsupported RAM dump type {dump_type}; full-memory type 1 required"
    );
    ensure!(
        runs > 0 && runs as usize <= (run_end - run_start) / (2 * width),
        "Invalid RAM physical-run count"
    );
    let mut pages = 0u64;
    let mut previous_end = 0;
    for i in 0..runs as usize {
        let offset = run_start + i * width * 2;
        let base = number(offset);
        let count = number(offset + width);
        ensure!(
            count > 0 && base >= previous_end,
            "Empty, unordered or overlapping RAM physical runs"
        );
        previous_end = base
            .checked_add(count)
            .context("Physical page range overflow")?;
        pages = pages
            .checked_add(count)
            .context("Physical page count overflow")?;
    }
    let declared_pages = if width == 8 {
        u64::from_le_bytes(header[runs_offset + 8..runs_offset + 16].try_into()?)
    } else {
        u32_at(runs_offset + 4) as u64
    };
    ensure!(
        pages == declared_pages,
        "RAM physical page count differs from descriptor"
    );
    ensure!(
        (width == 4) == (arch == Architecture::X86),
        "RAM dump header width differs from architecture"
    );
    let expected_bytes = pages
        .checked_mul(4096)
        .and_then(|n| n.checked_add(size as u64))
        .context("RAM dump length overflow")?;
    let required = u64::from_le_bytes(header[4000..4008].try_into()?);
    ensure!(
        required == expected_bytes,
        "RAM dump RequiredDumpSpace differs from physical runs"
    );
    ensure!(
        length == expected_bytes,
        "RAM dump length mismatch: expected {expected_bytes}, found {length}"
    );
    Ok(DumpLayout {
        machine,
        dump_type,
        runs,
        pages,
        expected_bytes,
    })
}

fn record(computer: &str) -> Record {
    Record {
        schema_version: 1,
        observation_id: uuid::Uuid::new_v4().to_string(),
        computer: computer.into(),
        source_id: "Memory".into(),
        source_path: "Physical RAM".into(),
        stream_name: None,
        artifact_ids: "windows.memory".into(),
        relative_output_path: None,
        method: "DumpIt".into(),
        status: "Failed".into(),
        reason: String::new(),
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
pub(crate) fn unavailable(root: &Path, computer: &str, reason: &str) -> Result<Record> {
    fs::create_dir(root.join("Memory"))?;
    let mut row = record(computer);
    row.reason = reason.into();
    row.finished_utc = utc_now();
    collect::write_json_new(
        &root.join("Memory/Acquisition.json"),
        &serde_json::json!({"SchemaVersion":1,"Provider":"DumpIt","Record":row}),
    )?;
    Ok(row)
}
const LOG_LIMIT: u64 = 256 * 1024;
fn drain(mut reader: impl Read) -> Result<Vec<u8>> {
    let mut retained = Vec::new();
    let mut buf = [0; 8192];
    loop {
        let n = reader.read(&mut buf)?;
        if n == 0 {
            break;
        }
        let keep = n.min((LOG_LIMIT as usize).saturating_sub(retained.len()));
        retained.extend_from_slice(&buf[..keep]);
    }
    Ok(retained)
}
fn execute(
    mut command: Command,
    output: &Path,
    reserve: u64,
    timeout: Duration,
    quiet: bool,
    estimate: u64,
) -> Result<(std::process::ExitStatus, Vec<u8>, Vec<u8>)> {
    #[cfg(windows)]
    let job = crate::live_info::QueryJob::new()?;
    let mut child = command
        .stdin(Stdio::null())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .context("Cannot start DumpIt")?;
    #[cfg(windows)]
    if let Err(error) = job.assign(&child) {
        let _ = child.kill();
        let _ = child.wait();
        return Err(error);
    }
    let stdout = child.stdout.take().context("Missing capture stdout")?;
    let stderr = child.stderr.take().context("Missing capture stderr")?;
    let out = std::thread::spawn(move || drain(stdout));
    let err = std::thread::spawn(move || drain(stderr));
    let bar = crate::ui::progress_bar(estimate.max(1), quiet);
    let start = Instant::now();
    let mut failure = None;
    let status = loop {
        match child.try_wait() {
            Ok(Some(s)) => break Some(s),
            Ok(None) => {}
            Err(e) => {
                failure = Some(format!("Cannot monitor DumpIt: {e}"));
                break None;
            }
        }
        bar.set_position(fs::metadata(output).map_or(0, |m| m.len()).min(estimate));
        if start.elapsed() >= timeout {
            failure = Some("DumpIt capture timed out".into());
            break None;
        }
        match fs2::available_space(output.parent().context("Missing RAM staging parent")?) {
            Ok(n) if n >= reserve => {}
            Ok(_) => {
                failure = Some("RAM staging free-space reserve reached".into());
                break None;
            }
            Err(e) => {
                failure = Some(format!("Cannot monitor RAM staging free space: {e}"));
                break None;
            }
        }
        std::thread::sleep(Duration::from_millis(100));
    };
    if failure.is_some() {
        let _ = child.kill();
        let _ = child.wait();
    }
    #[cfg(windows)]
    drop(job);
    bar.finish_and_clear();
    let stdout = out
        .join()
        .map_err(|_| anyhow::anyhow!("RAM stdout reader panicked"))??;
    let stderr = err
        .join()
        .map_err(|_| anyhow::anyhow!("RAM stderr reader panicked"))??;
    // Always preserve bounded provider diagnostics, including timeout/nonzero exit.
    fs::write(
        output
            .parent()
            .context("Missing memory directory")?
            .join("DumpIt-stdout.txt"),
        &stdout,
    )?;
    fs::write(
        output
            .parent()
            .context("Missing memory directory")?
            .join("DumpIt-stderr.txt"),
        &stderr,
    )?;
    if let Some(message) = failure {
        bail!("{message}");
    }
    Ok((status.context("No capture exit status")?, stdout, stderr))
}
fn diagnostics(stdout: &[u8]) -> (Option<u64>, Option<u32>) {
    let text = String::from_utf8_lossy(stdout);
    let mut inaccessible = None;
    let mut nt_status = None;
    for line in text.lines() {
        let Some((label, value)) = line.split_once(':') else {
            continue;
        };
        let label = label.to_ascii_lowercase();
        if label.contains("inacessible pages") || label.contains("inaccessible pages") {
            inaccessible = value
                .split_whitespace()
                .next()
                .and_then(|v| v.replace(',', "").parse().ok());
        }
        if label.contains("ntstatus") {
            nt_status = value
                .trim()
                .strip_prefix("0x")
                .and_then(|v| u32::from_str_radix(v.trim(), 16).ok());
        }
    }
    (inaccessible, nt_status)
}

/// Errors become explicit failed acquisition records; any partial bytes are retained and hashed.
pub fn acquire(
    root: &Path,
    computer: &str,
    args: &Args,
    reserve: u64,
    quiet: bool,
) -> Result<Record> {
    let directory = root.join("Memory");
    fs::create_dir(&directory)?;
    let path = directory.join("Memory.dmp");
    let mut row = record(computer);
    let mut tool_hash = None;
    let mut layout = None;
    let mut exit_code = None;
    let mut inaccessible_pages = None;
    let mut nt_status = None;
    let outcome = (|| -> Result<()> {
        let arch = native_architecture()?;
        let (tool, _guard, digest) = trusted_tool(args, arch)?;
        tool_hash = Some(digest);
        let estimate = physical_bytes()?;
        ensure!(
            fs2::available_space(&directory)?
                >= estimate
                    .checked_add(64 * 1024 * 1024)
                    .and_then(|n| n.checked_add(reserve))
                    .context("RAM size estimate overflow")?,
            "Insufficient RAM staging free space; need physical RAM plus 64 MiB header headroom and the free-space reserve"
        );
        ensure!(!path.exists(), "RAM output already exists");
        if !quiet {
            crate::ui::status("Acquiring physical RAM with DumpIt before other evidence…");
        }
        let mut command = Command::new(&tool);
        command
            .current_dir(&directory)
            .args([
                "/QUIET",
                "/TYPE",
                "DMP",
                "/NOCOMPRESS",
                "/NOLYTICS",
                "/NOJSON",
                "/OUTPUT",
            ])
            .arg(&path);
        let (status, stdout, _) = execute(
            command,
            &path,
            reserve,
            Duration::from_secs(args.memory_timeout),
            quiet,
            estimate,
        )?;
        exit_code = status.code();
        (inaccessible_pages, nt_status) = diagnostics(&stdout);
        ensure!(
            status.success(),
            "DumpIt failed with exit status {status}; inspect Memory/DumpIt-stdout.txt and DumpIt-stderr.txt"
        );
        ensure!(
            nt_status.is_none_or(|code| code == 0),
            "DumpIt reported nonzero NtStatus: {nt_status:?}; inspect provider logs"
        );
        layout = Some(validate_dump(&path, arch)?);
        Ok(())
    })();
    if path.exists() {
        ensure!(
            path.symlink_metadata()?.is_file() && !platform::is_reparse_directory(&path),
            "Unsafe RAM output"
        );
        let (bytes, digest) = collect::hash_file(&path)?;
        row.bytes_read = bytes;
        row.logical_size = Some(bytes);
        row.sha256 = Some(digest);
        row.relative_output_path = Some("Memory/Memory.dmp".into());
        row.verified = true;
    }
    match outcome {
        Ok(()) => {
            row.status = "Acquired".into();
            row.reason="DumpIt exit success; full-dump physical runs/length checked and stored bytes SHA-256 verified. Live RAM is not an atomic snapshot.".into();
            if row.status == "Partial" {
                row.reason.push_str(&format!(
                    " DumpIt reported {} inaccessible pages.",
                    inaccessible_pages.unwrap_or(0)
                ));
            }
        }
        Err(e) => {
            row.reason = format!("{e:#}");
            if !quiet {
                eprintln!("RAM acquisition failed: {}", row.reason);
            }
        }
    }
    row.finished_utc = utc_now();
    collect::write_json_new(
        &directory.join("Acquisition.json"),
        &serde_json::json!({"SchemaVersion":1,"Provider":"DumpIt","ToolSHA256":tool_hash,"ExitCode":exit_code,"InaccessiblePages":inaccessible_pages,"NtStatus":nt_status,"DumpLayout":layout,"Record":row,"Arguments":["/QUIET","/TYPE","DMP","/NOCOMPRESS","/NOLYTICS","/NOJSON","/OUTPUT","Memory.dmp"],"LogRetentionBytesPerStream":LOG_LIMIT,"Limitations":["Live RAM is non-atomic; integrity hashes are not proof of semantic completeness","Driver load/unload changes the live host; platform security can block acquisition","DumpIt requires a staged file even for SFTP delivery"]}),
    )?;
    Ok(row)
}

#[cfg(test)]
mod tests {
    use super::*;
    fn dump(root: &Path, arch: Architecture) -> PathBuf {
        let (size, machine, dtype, runs, start, width) = if arch == Architecture::X86 {
            (4096, 32, 3976, 100, 108, 4)
        } else {
            (8192, 48, 3992, 136, 152, 8)
        };
        let mut h = vec![0; size + 4096 * 2];
        h[..8].copy_from_slice(if arch == Architecture::X86 {
            b"PAGEDUMP"
        } else {
            b"PAGEDU64"
        });
        h[machine..machine + 4].copy_from_slice(&(arch.machine() as u32).to_le_bytes());
        h[dtype..dtype + 4].copy_from_slice(&1u32.to_le_bytes());
        h[runs..runs + 4].copy_from_slice(&1u32.to_le_bytes());
        if width == 8 {
            h[runs + 8..runs + 16].copy_from_slice(&2u64.to_le_bytes());
            h[start + 8..start + 16].copy_from_slice(&2u64.to_le_bytes());
        } else {
            h[runs + 4..runs + 8].copy_from_slice(&2u32.to_le_bytes());
            h[start + 4..start + 8].copy_from_slice(&2u32.to_le_bytes());
        }
        let len = h.len() as u64;
        h[4000..4008].copy_from_slice(&len.to_le_bytes());
        let path = root.join("Memory.dmp");
        fs::write(&path, h).unwrap();
        path
    }
    #[test]
    fn full_dump_architectures_and_lengths() {
        for arch in [Architecture::X86, Architecture::X64, Architecture::Arm64] {
            let t = tempfile::tempdir().unwrap();
            let p = dump(t.path(), arch);
            assert_eq!(validate_dump(&p, arch).unwrap().pages, 2);
            let f = fs::OpenOptions::new().write(true).open(&p).unwrap();
            f.set_len(f.metadata().unwrap().len() - 1).unwrap();
            assert!(
                validate_dump(&p, arch)
                    .unwrap_err()
                    .to_string()
                    .contains("length mismatch")
            );
        }
    }
    #[test]
    fn malformed_and_wrong_arch_dump_never_passes() {
        let t = tempfile::tempdir().unwrap();
        let p = dump(t.path(), Architecture::X64);
        assert!(validate_dump(&p, Architecture::Arm64).is_err());
        for (offset, value) in [(3992, 2u32), (136, u32::MAX), (144, 3), (160, 0), (4000, 1)] {
            let p = dump(t.path(), Architecture::X64);
            let mut f = fs::OpenOptions::new().write(true).open(&p).unwrap();
            f.seek(SeekFrom::Start(offset)).unwrap();
            std::io::Write::write_all(&mut f, &value.to_le_bytes()).unwrap();
            drop(f);
            assert!(
                validate_dump(&p, Architecture::X64).is_err(),
                "offset {offset}"
            );
        }
        fs::write(&p, b"not a dump").unwrap();
        assert!(validate_dump(&p, Architecture::X64).is_err());
    }
    #[test]
    fn trusted_tool_requires_hash_and_native_pe_architecture() {
        let t = tempfile::tempdir().unwrap();
        let p = t.path().join("tool with spaces.exe");
        let mut bytes = vec![0u8; 128];
        bytes[..2].copy_from_slice(b"MZ");
        bytes[60..64].copy_from_slice(&64u32.to_le_bytes());
        bytes[64..68].copy_from_slice(b"PE\0\0");
        bytes[68..70].copy_from_slice(&0xaa64u16.to_le_bytes());
        fs::write(&p, &bytes).unwrap();
        let mut args = Args {
            dumpit: Some(p.clone()),
            ..Default::default()
        };
        assert!(trusted_tool(&args, Architecture::Arm64).is_err());
        args.dumpit_sha256 = Some(collect::hash_file(&p).unwrap().1);
        assert!(trusted_tool(&args, Architecture::Arm64).is_ok());
        assert!(trusted_tool(&args, Architecture::X64).is_err());
        assert!(parse_digest("1234").is_err());
        assert!(parse_digest(&"z".repeat(64)).is_err());
        assert_eq!(parse_digest(&"A".repeat(64)).unwrap(), "a".repeat(64));
    }
    #[test]
    fn toolkit_directory_uses_native_arch_subdirectory() {
        let t = tempfile::tempdir().unwrap();
        let d = t.path().join("ARM64");
        fs::create_dir(&d).unwrap();
        fs::write(d.join("DumpIt.exe"), b"fixture").unwrap();
        let args = Args {
            dumpit: Some(t.path().into()),
            ..Default::default()
        };
        assert_eq!(
            tool_path(&args, Architecture::Arm64).unwrap(),
            platform::canonicalize(&d.join("DumpIt.exe")).unwrap()
        );
        assert!(tool_path(&args, Architecture::X86).is_err());
    }
    #[test]
    fn child_fixture() {
        if let Ok(mode) = std::env::var("KUMADE_RAM_TEST_CHILD") {
            if mode == "hang" {
                std::thread::sleep(Duration::from_secs(120));
            }
            if mode == "fail" {
                println!("provider failed");
                std::process::exit(7);
            }
            if mode == "flood" {
                for _ in 0..100 {
                    println!("{}", "x".repeat(8192));
                }
            }
        }
    }
    fn child(mode: &str) -> Command {
        let mut c = Command::new(std::env::current_exe().unwrap());
        c.args(["--exact", "memory::tests::child_fixture", "--nocapture"])
            .env("KUMADE_RAM_TEST_CHILD", mode);
        c
    }
    #[test]
    fn provider_timeout_and_nonzero_keep_diagnostics() {
        let t = tempfile::tempdir().unwrap();
        let p = t.path().join("dump with spaces.dmp");
        let start = Instant::now();
        assert!(execute(child("hang"), &p, 0, Duration::from_millis(150), true, 1).is_err());
        assert!(start.elapsed() < Duration::from_secs(20));
        assert!(t.path().join("DumpIt-stderr.txt").exists());
        let (status, stdout, _) =
            execute(child("fail"), &p, 0, Duration::from_secs(20), true, 1).unwrap();
        assert_eq!(status.code(), Some(7));
        assert!(String::from_utf8_lossy(&stdout).contains("provider failed"));
        let (_, stdout, _) =
            execute(child("flood"), &p, 0, Duration::from_secs(20), true, 1).unwrap();
        assert_eq!(stdout.len(), LOG_LIMIT as usize);
    }
    #[test]
    fn provider_inaccessible_pages_and_ntstatus_are_retained() {
        assert_eq!(
            diagnostics(
                b"Total of inacessible pages: 5\r\nNtStatus (troubleshooting): 0xC0000022\r\n"
            ),
            (Some(5), Some(0xc0000022))
        );
        assert_eq!(
            diagnostics(b"Total of inaccessible pages: 0\nNtStatus: 0x00000000"),
            (Some(0), Some(0))
        );
        assert_eq!(diagnostics(b"unknown output"), (None, None));
    }
    #[test]
    fn no_provider_is_never_success() {
        let t = tempfile::tempdir().unwrap();
        let args = Args {
            dumpit: Some(t.path().join("missing.exe")),
            ..Default::default()
        };
        let r = acquire(t.path(), "TEST", &args, 0, true).unwrap();
        assert_eq!(r.status, "Failed");
        assert!(r.relative_output_path.is_none());
        assert!(!r.verified);
        assert!(t.path().join("Memory/Acquisition.json").exists());
    }
}
