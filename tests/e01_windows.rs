// Copyright (C) 2026 Shirofune Security Co., Ltd.
// SPDX-License-Identifier: RPL-1.5
//! Elevated Windows round trip: open the real CLI's E01 directly as an NTFS disk.
#![cfg(windows)]
use anyhow::{Context, Result, ensure};
use ewf_image::Image;
use kumade::{
    e01::ContainerReport,
    metadata::Snapshot,
    model::{Record, Summary, sha256},
};
use ntfs::{Ntfs, NtfsReadSeek, indexes::NtfsFileNameIndex};
use std::{
    fs,
    io::{self, Read, Seek, SeekFrom},
    path::Path,
    process::Command,
};

struct Partition<'a> {
    image: &'a Image,
    start: u64,
    length: u64,
    position: u64,
}
impl Read for Partition<'_> {
    fn read(&mut self, buffer: &mut [u8]) -> io::Result<usize> {
        let wanted = (self.length - self.position).min(buffer.len() as u64) as usize;
        let n = self
            .image
            .read_at(&mut buffer[..wanted], self.start + self.position)
            .map_err(io::Error::other)?;
        self.position += n as u64;
        Ok(n)
    }
}
impl Seek for Partition<'_> {
    fn seek(&mut self, target: SeekFrom) -> io::Result<u64> {
        let pos = match target {
            SeekFrom::Start(p) => i128::from(p),
            SeekFrom::Current(p) => i128::from(self.position) + i128::from(p),
            SeekFrom::End(p) => i128::from(self.length) + i128::from(p),
        };
        if !(0..=i128::from(self.length)).contains(&pos) {
            return Err(io::Error::other("seek outside test partition"));
        }
        self.position = pos as u64;
        Ok(self.position)
    }
}
fn read(
    ntfs: &Ntfs,
    disk: &mut Partition<'_>,
    path: &str,
    stream: Option<&str>,
) -> Result<Vec<u8>> {
    let mut file = ntfs.root_directory(disk)?;
    for component in path.split('/') {
        let index = file.directory_index(disk)?;
        let mut finder = index.finder();
        let entry = NtfsFileNameIndex::find(&mut finder, ntfs, disk, component)
            .context("missing collected path")??;
        file = entry.to_file(ntfs, disk)?;
    }
    let item = file
        .data(disk, stream.unwrap_or_default())
        .context("missing stream")??;
    let attribute = item.to_attribute()?;
    let mut value = attribute.value(disk)?;
    ensure!(
        value.len() <= 64 * 1024 * 1024,
        "unexpected fixture payload size"
    );
    let mut bytes = Vec::new();
    let mut buffer = [0u8; 8192];
    loop {
        let n = value.read(disk, &mut buffer)?;
        if n == 0 {
            break;
        }
        bytes.extend_from_slice(&buffer[..n]);
    }
    Ok(bytes)
}

#[test]
fn e01_cli_preserves_sealed_payloads_named_streams_and_ntfs_metadata() -> Result<()> {
    let temp = tempfile::tempdir()?;
    let source = temp.path().join("source");
    let prefetch = source.join("Windows/Prefetch");
    fs::create_dir_all(&prefetch)?;
    fs::write(prefetch.join("ONE.pf"), b"one collected file")?;
    fs::write(prefetch.join("TWO.pf"), b"another collected file")?;
    fs::write(
        prefetch.join("ONE.pf:Zone.Identifier"),
        b"[ZoneTransfer]\r\nZoneId=3\r\n",
    )?;
    let output = temp.path().join("Evidence 'quoted'.e01");
    let binary = std::env::var_os("KUMADE_E01_WINDOWS_BINARY")
        .unwrap_or_else(|| env!("CARGO_BIN_EXE_kumade").into());
    let run = Command::new(binary)
        .args(["collect", "-d"])
        .arg(&source)
        .args([
            "--computer",
            "SYNTHETIC",
            "--artifact",
            "windows.prefetch",
            "--no-wizard",
            "--e01",
        ])
        .arg(&output)
        .args(["--e01-size-gib", "1", "--reserve-mib", "0", "-T", "2", "-v"])
        .output()?;
    ensure!(
        run.status.success(),
        "{}{}",
        String::from_utf8_lossy(&run.stdout),
        String::from_utf8_lossy(&run.stderr)
    );
    let mut receipt = output.as_os_str().to_owned();
    receipt.push(".json");
    let report: ContainerReport = serde_json::from_slice(&fs::read(receipt)?)?;
    assert!(report.verified);
    assert_eq!(report.logical_bytes, 1024 * 1024 * 1024);
    let summary = report.collection.as_ref().unwrap();
    assert_eq!(summary.collected, 3);
    assert_eq!(summary.metadata_errors, 0);
    let image = Image::open(&output)?;
    // Locate the Basic Data partition, allowing Windows to create an MSR too.
    let mut header = [0u8; 92];
    assert_eq!(image.read_at(&mut header, 512)?, header.len());
    let table = u64::from_le_bytes(header[72..80].try_into()?) * 512;
    let count = u32::from_le_bytes(header[80..84].try_into()?);
    let entry_size = u32::from_le_bytes(header[84..88].try_into()?);
    let mut entry = [0u8; 128];
    let mut found = false;
    for i in 0..count {
        assert_eq!(
            image.read_at(&mut entry, table + u64::from(i) * u64::from(entry_size))?,
            entry.len()
        );
        if entry[..16]
            == [
                0xa2, 0xa0, 0xd0, 0xeb, 0xe5, 0xb9, 0x33, 0x44, 0x87, 0xc0, 0x68, 0xb6, 0xb7, 0x26,
                0x99, 0xc7,
            ]
        {
            found = true;
            break;
        }
    }
    ensure!(found, "missing NTFS Basic Data partition");
    let first = u64::from_le_bytes(entry[32..40].try_into()?);
    let last = u64::from_le_bytes(entry[40..48].try_into()?);
    let mut disk = Partition {
        image: &image,
        start: first * 512,
        length: (last - first + 1) * 512,
        position: 0,
    };
    let mut ntfs = Ntfs::new(&mut disk)?;
    ntfs.read_upcase_table(&mut disk)?;
    let root = ntfs.root_directory(&mut disk)?;
    let index = root.directory_index(&mut disk)?;
    let mut entries = index.entries();
    let mut collection = None;
    while let Some(entry) = entries.next(&mut disk) {
        let entry = entry?;
        let name = entry
            .key()
            .context("missing index key")??
            .name()
            .to_string_lossy();
        if name.starts_with("SYNTHETIC_") {
            collection = Some(name);
            break;
        }
    }
    let root = collection.context("missing collection root")?;
    let saved: Summary = serde_json::from_slice(&read(
        &ntfs,
        &mut disk,
        &format!("{root}/Summary.json"),
        None,
    )?)?;
    assert_eq!(saved.run_id, summary.run_id);
    let manifest = read(&ntfs, &mut disk, &format!("{root}/Manifest.jsonl"), None)?;
    let records: Vec<Record> = String::from_utf8(manifest)?
        .lines()
        .map(serde_json::from_str)
        .collect::<Result<_, _>>()?;
    assert_eq!(records.len(), 3);
    for record in &records {
        assert!(record.verified);
        let path = record.relative_output_path.as_ref().unwrap();
        let (base, stream) = path
            .split_once(':')
            .map_or((path.as_str(), None), |(p, s)| (p, Some(s)));
        let data = read(&ntfs, &mut disk, &format!("{root}/{base}"), stream)?;
        assert_eq!(Some(sha256(&data)), record.sha256);
    }
    let inventory = read(
        &ntfs,
        &mut disk,
        &format!("{root}/NTFS-Metadata.jsonl"),
        None,
    )?;
    let snapshots: Vec<Snapshot> = String::from_utf8(inventory)?
        .lines()
        .map(serde_json::from_str)
        .collect::<Result<_, _>>()?;
    for snapshot in &snapshots {
        assert_eq!(snapshot.restore_status, "Restored");
        let mut file = ntfs.root_directory(&mut disk)?;
        let path = format!("{root}/{}", snapshot.relative_output_path);
        for part in path.split('/') {
            let index = file.directory_index(&mut disk)?;
            let mut finder = index.finder();
            file = NtfsFileNameIndex::find(&mut finder, &ntfs, &mut disk, part)
                .unwrap()?
                .to_file(&ntfs, &mut disk)?;
        }
        let info = file.info()?;
        assert_eq!(
            info.creation_time().nt_timestamp() as i64,
            snapshot.creation_filetime.unwrap()
        );
        assert_eq!(
            info.access_time().nt_timestamp() as i64,
            snapshot.access_filetime.unwrap()
        );
        assert_eq!(
            info.modification_time().nt_timestamp() as i64,
            snapshot.write_filetime.unwrap()
        );
        assert_eq!(
            info.mft_record_modification_time().nt_timestamp() as i64,
            snapshot.change_filetime.unwrap()
        );
    }
    let seal: serde_json::Value =
        serde_json::from_slice(&read(&ntfs, &mut disk, &format!("{root}/Seal.json"), None)?)?;
    for (name, hash) in seal["MetadataSHA256"].as_object().unwrap() {
        assert_eq!(
            sha256(&read(&ntfs, &mut disk, &format!("{root}/{name}"), None)?),
            hash.as_str().unwrap()
        );
    }
    for segment in &report.segments {
        assert!(Path::new(&segment.file).is_relative());
    }
    assert!(
        !fs::read_dir(temp.path())?.any(|e| e
            .unwrap()
            .file_name()
            .to_string_lossy()
            .starts_with(".kumade-e01-")),
        "successful collection removes staging"
    );
    Ok(())
}
