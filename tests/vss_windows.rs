// Copyright (C) 2026 Shirofune Security Co., Ltd.
// SPDX-License-Identifier: RPL-1.5
//! Isolated native-Windows VSS proof; never snapshots a runner's system volume.
#![cfg(windows)]
use anyhow::{Context, Result, ensure};
use kumade::{
    catalog::{DEFAULT_CATALOG, Rules},
    collect, discovery,
    model::{Record, SourceDiscovery},
    platform, verify, vss,
};
use std::{
    fs::{self, OpenOptions},
    io::{Read, Seek, SeekFrom, Write},
    os::windows::{fs::OpenOptionsExt, io::AsRawHandle},
    path::{Path, PathBuf},
    process::Command,
};

fn native_shell() -> Result<PathBuf> {
    let root = PathBuf::from(std::env::var_os("SystemRoot").context("SystemRoot missing")?);
    ["Sysnative", "System32"]
        .into_iter()
        .map(|p| root.join(p).join("WindowsPowerShell/v1.0/powershell.exe"))
        .find(|p| p.is_file())
        .context("Native PowerShell missing")
}
struct Mounted {
    image: PathBuf,
    shell: PathBuf,
}
impl Drop for Mounted {
    fn drop(&mut self) {
        let _=Command::new(&self.shell).args(["-NoProfile","-NonInteractive","-Command","Dismount-DiskImage -ImagePath $env:KUMADE_VSS_TEST_IMAGE -ErrorAction Stop | Out-Null"]).env("KUMADE_VSS_TEST_IMAGE",&self.image).output();
    }
}
#[derive(serde::Deserialize)]
#[serde(rename_all = "PascalCase")]
struct Volumes {
    ntfs: String,
}
fn record_rows(root: &Path) -> Result<Vec<Record>> {
    fs::read_to_string(root.join("Manifest.jsonl"))?
        .lines()
        .map(|l| Ok(serde_json::from_str(l)?))
        .collect()
}

#[test]
fn locked_file_snapshot_content_raw_ntfs_cleanup_and_cli_backends() -> Result<()> {
    #[cfg(target_arch = "x86")]
    {
        // The normal x86 Windows CI binary runs under WOW64; it must fail closed.
        if let Err(error) = vss::check_host() {
            ensure!(
                error.to_string().contains("native"),
                "Unexpected VSS rejection: {error:#}"
            );
            eprintln!("VSS creation requires a native requester; x86 WOW64 rejection verified.");
            return Ok(());
        }
    }
    vss::check_host()?;
    let temp = tempfile::tempdir()?;
    let image = temp.path().join("vss-test.vhdx");
    let script = temp.path().join("diskpart.txt");
    let shell = native_shell()?;
    // The provider’s default diff-area quota must exceed its minimum allocation.
    // A tiny NTFS volume can report VSS support yet fail with insufficient storage.
    let setup = r#"
$ErrorActionPreference='Stop'; $ProgressPreference='SilentlyContinue'
[Console]::OutputEncoding=New-Object System.Text.UTF8Encoding($false)
@"
create vdisk file="$env:KUMADE_VSS_TEST_IMAGE" maximum=8192 type=expandable
select vdisk file="$env:KUMADE_VSS_TEST_IMAGE"
attach vdisk
create partition primary
format fs=ntfs quick label=KumadeVssTest
assign
"@ | Set-Content -LiteralPath $env:KUMADE_VSS_TEST_SCRIPT -Encoding ascii
& diskpart.exe /s $env:KUMADE_VSS_TEST_SCRIPT | Out-Null
try {
    $volumes=@(Get-DiskImage -ImagePath $env:KUMADE_VSS_TEST_IMAGE | Get-Disk | Get-Partition | Get-Volume)
    $n=@($volumes | Where-Object FileSystem -eq NTFS)
    if ($n.Count -ne 1) { throw 'Expected one isolated NTFS volume' }
    # Only the freshly created test volume: never change runner/system quotas.
    $storage = & vssadmin.exe add shadowstorage "/for=$($n[0].UniqueId)" "/on=$($n[0].UniqueId)" /maxsize=1GB 2>&1
    if ($LASTEXITCODE -ne 0) { throw "Cannot configure owned fixture shadow storage: $storage" }
    @{Ntfs=$n[0].UniqueId} | ConvertTo-Json -Compress
} catch {Dismount-DiskImage -ImagePath $env:KUMADE_VSS_TEST_IMAGE -ErrorAction SilentlyContinue | Out-Null; throw}
"#;
    let output = Command::new(&shell)
        .args(["-NoProfile", "-NonInteractive", "-Command", setup])
        .env("KUMADE_VSS_TEST_IMAGE", &image)
        .env("KUMADE_VSS_TEST_SCRIPT", &script)
        .output()?;
    ensure!(
        output.status.success(),
        "Fixture setup failed: {}{}",
        String::from_utf8_lossy(&output.stdout),
        String::from_utf8_lossy(&output.stderr)
    );
    let _mounted = Mounted {
        image,
        shell: shell.clone(),
    };
    let text = String::from_utf8(output.stdout)?;
    let volumes: Volumes = serde_json::from_str(text.trim().trim_start_matches('﻿'))?;
    let source_root = platform::canonicalize(Path::new(&volumes.ntfs))?;
    let prefetch = source_root.join("Windows/Prefetch");
    fs::create_dir_all(&prefetch)?;
    // Ordinary test file, not an OS-configured pagefile. The acquisition policy
    // must refuse its reserved paging name and account for that refusal.
    fs::write(source_root.join("pagefile.sys"), b"excluded paging fixture")?;
    let path = prefetch.join("LOCKED.pf");
    let mut locked = OpenOptions::new()
        .write(true)
        .read(true)
        .create_new(true)
        .share_mode(0)
        .open(&path)?;
    locked.write_all(b"before snapshot")?;
    locked.sync_all()?;
    ensure!(
        fs::read(&path).is_err(),
        "Fixture must block ordinary live reads"
    );
    let mut source = discovery::directory_source(&source_root, "VSS-TEST", "VSS-TEST")?;
    source.live = true;
    source.raw_device = Some(PathBuf::from(volumes.ntfs.trim_end_matches('\\')));
    let mut discovered = SourceDiscovery {
        sources: vec![source],
        issues: Vec::new(),
    };
    let mut owned = match vss::prepare_sources(&mut discovered, 120) {
        Ok(session) => session,
        Err(error) => {
            let diagnostics = Command::new(&shell)
                .args(["-NoProfile", "-NonInteractive", "-Command", "Get-WinEvent -FilterHashtable @{LogName='Application';ProviderName='VSS';StartTime=(Get-Date).AddMinutes(-5)} -ErrorAction SilentlyContinue | Select-Object -First 5 TimeCreated,Id,Message | Format-List | Out-String -Width 180"])
                .output()?;
            anyhow::bail!(
                "{error:#}\nVSS diagnostics: {}{}",
                String::from_utf8_lossy(&diagnostics.stdout),
                String::from_utf8_lossy(&diagnostics.stderr)
            );
        }
    };
    assert_eq!(discovered.sources.len(), 1);
    let snapshot = owned.snapshots()[0].clone();
    let snapshot_root = vss::snapshot_device_root(&snapshot.device_object)?;
    locked.seek(SeekFrom::Start(0))?;
    locked.write_all(b"after snapshot!")?;
    locked.sync_all()?;
    assert_eq!(
        fs::read(snapshot_root.join("Windows/Prefetch/LOCKED.pf"))?,
        b"before snapshot"
    );
    // Raw NTFS must use the same frozen content, never fall back to live bytes.
    let mut raw = kumade::raw::RawVolume::open(&snapshot.device_object)?;
    let mut raw_bytes = Vec::new();
    raw.copy_file_with_attributes(
        Path::new("Windows/Prefetch/LOCKED.pf"),
        None,
        &mut raw_bytes,
        |_, _| Ok(()),
    )?;
    assert_eq!(raw_bytes, b"before snapshot");
    drop(raw);
    // Exercise forensic-copy's unbuffered handle and final partition sector too.
    let device = OpenOptions::new()
        .read(true)
        .share_mode(3)
        .custom_flags(windows_sys::Win32::Storage::FileSystem::FILE_FLAG_NO_BUFFERING)
        .open(&snapshot.device_object)?;
    let mut length = 0i64;
    let mut returned = 0;
    ensure!(
        // SAFETY: read-only device, correctly sized length output and output count.
        unsafe {
            windows_sys::Win32::System::IO::DeviceIoControl(
                device.as_raw_handle(),
                windows_sys::Win32::System::Ioctl::IOCTL_DISK_GET_LENGTH_INFO,
                std::ptr::null(),
                0,
                (&mut length as *mut i64).cast(),
                8,
                &mut returned,
                std::ptr::null_mut(),
            )
        } != 0,
        "Snapshot partition length query failed: {}",
        std::io::Error::last_os_error()
    );
    ensure!(
        // SAFETY: synchronous read-only device; control has no input/output payload.
        unsafe {
            windows_sys::Win32::System::IO::DeviceIoControl(
                device.as_raw_handle(),
                windows_sys::Win32::System::Ioctl::FSCTL_ALLOW_EXTENDED_DASD_IO,
                std::ptr::null(),
                0,
                std::ptr::null_mut(),
                0,
                &mut returned,
                std::ptr::null_mut(),
            )
        } != 0,
        "Snapshot extended partition access failed: {}",
        std::io::Error::last_os_error()
    );
    let mut device = kumade::raw::DeviceReader::new(device, u64::try_from(length)?, 512)?;
    device.seek(SeekFrom::End(-512))?;
    device.read_exact(&mut [0u8; 512])?;
    drop(device);
    let rules = Rules::load(DEFAULT_CATALOG)?;
    let mut plan = discovery::build_plan(
        discovered.sources,
        &rules,
        &["windows.prefetch".into(), "windows.ntfs.mft".into()],
        false,
    )?;
    plan.issues.extend(discovered.issues);
    let options = collect::Options {
        threads: 2,
        reserve_bytes: 0,
        quiet: true,
        verbose: false,
        ntfs_metadata: false,
        host_reserve: None,
        live_info: None,
        process_scan: None,
        early: None,
        entropy: None,
    };
    let (root, summary) = collect::collect(&plan, &temp.path().join("direct"), &options)?;
    assert_eq!(summary.completeness, "CompleteWithinSelectedPrototypeScope");
    let rows = record_rows(&root)?;
    let row = rows
        .iter()
        .find(|r| r.source_path.ends_with("LOCKED.pf"))
        .context("Locked file not collected")?;
    ensure!(
        row.status == "Acquired",
        "Snapshot file acquisition failed: {}",
        row.reason
    );
    assert_eq!(row.method, "VssNativeRead");
    assert_eq!(
        fs::read(root.join(row.relative_output_path.as_ref().unwrap()))?,
        b"before snapshot"
    );
    let mft = rows
        .iter()
        .find(|r| r.artifact_ids.contains("windows.ntfs.mft"))
        .context("MFT missing")?;
    ensure!(
        mft.status == "Acquired",
        "Snapshot MFT acquisition failed: {}",
        mft.reason
    );
    assert_eq!(mft.method, "VssRawNTFS");
    assert_eq!(
        &fs::read(root.join(mft.relative_output_path.as_ref().unwrap()))?[..4],
        b"FILE"
    );
    assert!(verify::verify(&root)?.1);
    // Another requester's snapshot must survive deletion of the first set.
    let other = vss::Session::create(std::slice::from_ref(&volumes.ntfs), 120)?;
    let other_root = vss::snapshot_device_root(&other.snapshots()[0].device_object)?;
    owned.close()?;
    assert_eq!(
        fs::read(other_root.join("Windows/Prefetch/LOCKED.pf"))?,
        b"after snapshot!"
    );
    drop(other); // error/unwind paths use the same owned-session RAII cleanup
    ensure!(
        !snapshot_root.exists() && !other_root.exists(),
        "Owned snapshot roots remain readable after cleanup"
    );
    drop(locked);
    // CLI integration exercises explicit volume selection and all artifact output backends.
    for mode in ["directory", "vhdx", "e01"] {
        let parent = temp.path().join(mode);
        let mut command = Command::new(env!("CARGO_BIN_EXE_kumade"));
        command.args([
            "collect",
            "--vss",
            "--volume",
            &volumes.ntfs,
            "--artifact",
            "windows.prefetch",
            "--no-live-info",
            "--reserve-mib",
            "0",
            "-q",
        ]);
        match mode {
            "directory" => {
                command.arg("-o").arg(&parent);
            }
            "vhdx" => {
                command.arg("--vhdx").arg(parent.with_extension("vhdx"));
            }
            _ => {
                command.arg("--e01").arg(parent.with_extension("E01"));
            }
        }
        let output = command.output()?;
        ensure!(
            output.status.success(),
            "{mode} VSS CLI failed: {}{}",
            String::from_utf8_lossy(&output.stdout),
            String::from_utf8_lossy(&output.stderr)
        );
        if mode == "directory" {
            let root = fs::read_dir(&parent)?
                .next()
                .context("Missing run directory")??
                .path();
            assert!(verify::verify(&root)?.1);
            let plan: serde_json::Value =
                serde_json::from_slice(&fs::read(root.join("Plan.json"))?)?;
            assert_eq!(
                plan["Sources"][0]["Snapshot"]["Consistency"],
                "CrashConsistent"
            );
            assert_eq!(plan["Sources"][0]["Snapshot"]["WritersParticipated"], false);
            assert!(
                plan["Sources"][0]["Snapshot"]["OriginalVolume"]
                    .as_str()
                    .context("Missing original-volume provenance")?
                    .eq_ignore_ascii_case(&volumes.ntfs)
            );
            let rows = record_rows(&root)?;
            assert_eq!(
                rows.len(),
                1,
                "Explicit selection must acquire only the isolated fixture"
            );
            assert!(
                rows.iter()
                    .all(|r| r.method == "VssNativeRead" && r.status == "Acquired")
            );
            assert!(rows[0].source_path.ends_with("LOCKED.pf"));
        }
    }
    let parent = temp.path().join("paging");
    let output = Command::new(env!("CARGO_BIN_EXE_kumade"))
        .args([
            "collect",
            "--vss",
            "--volume",
            &volumes.ntfs,
            "--artifact",
            "windows.paging",
            "--no-live-info",
            "--reserve-mib",
            "0",
            "-q",
            "-o",
        ])
        .arg(&parent)
        .output()?;
    ensure!(
        output.status.code() == Some(3),
        "Omitted paging must return Partial: {}{}",
        String::from_utf8_lossy(&output.stdout),
        String::from_utf8_lossy(&output.stderr)
    );
    let root = fs::read_dir(parent)?
        .next()
        .context("Missing paging run")??
        .path();
    let rows = record_rows(&root)?;
    assert_eq!(rows.iter().filter(|r| r.status == "Failed").count(), 1);
    assert_eq!(rows.iter().filter(|r| r.status == "NotPresent").count(), 2);
    // The requester has exited and cleaned up its snapshot; verification must
    // still accept the sealed records and retain the partial completeness state.
    assert_eq!(verify::verify(&root)?, (0, false));
    let output = Command::new(env!("CARGO_BIN_EXE_kumade"))
        .arg("verify")
        .arg(&root)
        .output()?;
    ensure!(
        output.status.code() == Some(3),
        "Partial verification returned the wrong exit code: {}{}",
        String::from_utf8_lossy(&output.stdout),
        String::from_utf8_lossy(&output.stderr)
    );
    assert!(String::from_utf8_lossy(&output.stdout).contains("Integrity verified"));
    Ok(())
}
