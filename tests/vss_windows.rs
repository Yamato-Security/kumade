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
    io::{Seek, SeekFrom, Write},
    os::windows::fs::OpenOptionsExt,
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
    fat: String,
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
    let setup = r#"
$ErrorActionPreference='Stop'; $ProgressPreference='SilentlyContinue'
[Console]::OutputEncoding=New-Object System.Text.UTF8Encoding($false)
@"
create vdisk file="$env:KUMADE_VSS_TEST_IMAGE" maximum=2048 type=expandable
select vdisk file="$env:KUMADE_VSS_TEST_IMAGE"
attach vdisk
create partition primary size=1024
format fs=ntfs quick label=KumadeVssTest
create partition primary
format fs=fat32 quick label=KumadeVssFat
"@ | Set-Content -LiteralPath $env:KUMADE_VSS_TEST_SCRIPT -Encoding ascii
& diskpart.exe /s $env:KUMADE_VSS_TEST_SCRIPT | Out-Null
try {
    $volumes=@(Get-DiskImage -ImagePath $env:KUMADE_VSS_TEST_IMAGE | Get-Disk | Get-Partition | Get-Volume)
    $n=@($volumes | Where-Object FileSystem -eq NTFS); $f=@($volumes | Where-Object FileSystem -eq FAT32)
    if ($n.Count -ne 1 -or $f.Count -ne 1) { throw 'Expected isolated NTFS and FAT32 volumes' }
    @{Ntfs=$n[0].UniqueId;Fat=$f[0].UniqueId} | ConvertTo-Json -Compress
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
    let _mounted = Mounted { image, shell };
    let text = String::from_utf8(output.stdout)?;
    let volumes: Volumes = serde_json::from_str(text.trim().trim_start_matches('﻿'))?;
    let source_root = platform::canonicalize(Path::new(&volumes.ntfs))?;
    let prefetch = source_root.join("Windows/Prefetch");
    fs::create_dir_all(&prefetch)?;
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
    let mut fat = discovery::directory_source(Path::new(&volumes.fat), "UNSUPPORTED", "VSS-TEST")?;
    fat.live = true;
    let mut discovered = SourceDiscovery {
        sources: vec![source, fat],
        issues: Vec::new(),
    };
    let mut owned = vss::prepare_sources(&mut discovered, 120)?;
    assert_eq!(discovered.sources.len(), 1);
    assert!(
        discovered
            .issues
            .iter()
            .any(|i| i.source_id == "UNSUPPORTED"
                && i.status == "Unsupported"
                && i.reason.contains("no live fallback"))
    );
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
    };
    let (root, summary) = collect::collect(&plan, &temp.path().join("direct"), &options)?;
    assert_eq!(summary.completeness, "Partial"); // explicitly unsupported FAT volume
    let rows = record_rows(&root)?;
    let row = rows
        .iter()
        .find(|r| r.source_path.ends_with("LOCKED.pf"))
        .context("Locked file not collected")?;
    ensure!(
        row.status == "Collected",
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
        mft.status == "Collected",
        "Snapshot MFT acquisition failed: {}",
        mft.reason
    );
    assert_eq!(mft.method, "VssRawNTFS");
    assert_eq!(
        &fs::read(root.join(mft.relative_output_path.as_ref().unwrap()))?[..4],
        b"FILE"
    );
    assert!(!verify::verify(&root)?.1);
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
                record_rows(&root)?
                    .iter()
                    .all(|r| r.method == "VssNativeRead")
            );
        }
    }
    Ok(())
}
