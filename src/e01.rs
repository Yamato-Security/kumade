// Copyright (C) 2026 Shirofune Security Co., Ltd.
// SPDX-License-Identifier: RPL-1.5
//
// This file is subject to the Reciprocal Public License (RPL), version 1.5.
// Distributed WITHOUT WARRANTY. See LICENSE for the complete terms.

//! Compressed EWF1 physical output containing the collected NTFS filesystem.
//! Encoding stages at most one 512 MiB segment; no full raw-disk spool is used.
use crate::{
    collect::{self, Options},
    model::{self, Plan, Summary},
    paths, platform, ui,
};
use anyhow::{Context, Result, ensure};
use ewf_image::{
    Image, OpenOptions, OpenStrictness, SequentialOptions, SequentialWriter, VerifyOptions,
    WriteCompression, WriteFormat,
};
use serde::{Deserialize, Serialize};
use std::{
    fs,
    io::Read,
    ops::ControlFlow,
    path::{Path, PathBuf},
};

const CHUNK: u64 = 32 * 1024;
const CHUNKS_PER_SEGMENT: u64 = 16_375;
const SEGMENT_CAPACITY: u64 = CHUNK * CHUNKS_PER_SEGMENT;
const MAX_SEGMENTS: u64 = 99 + 22 * 26 * 26; // E01..E99, EAA..ZZZ.
pub(crate) const MAX_CAPACITY: u64 = SEGMENT_CAPACITY * MAX_SEGMENTS;
const WRITER_HEADROOM: u64 = 2 * 512 * 1024 * 1024;

#[derive(Debug, Serialize, Deserialize)]
#[serde(rename_all = "PascalCase")]
pub struct Segment {
    pub file: String,
    pub size: u64,
    #[serde(rename = "SHA256")]
    pub sha256: String,
}

#[derive(Debug, Serialize, Deserialize)]
#[serde(rename_all = "PascalCase")]
pub struct ContainerReport {
    pub schema_version: u32,
    pub format: String,
    pub logical_bytes: u64,
    #[serde(rename = "MediaSHA256")]
    pub media_sha256: String,
    pub verified: bool,
    pub segments: Vec<Segment>,
    pub collection: Option<Summary>,
}

fn receipt_path(image: &Path) -> PathBuf {
    let mut name = image.as_os_str().to_owned();
    name.push(".json");
    PathBuf::from(name)
}

fn segment_path(first: &Path, number: u64) -> Result<PathBuf> {
    ensure!(
        (1..=MAX_SEGMENTS).contains(&number),
        "E01 segment count exceeds its filename range"
    );
    if number == 1 {
        return Ok(first.to_owned());
    }
    let ext = if number < 100 {
        format!("E{number:02}")
    } else {
        let n = number - 100;
        format!(
            "{}{}{}",
            char::from(b'E' + (n / 676) as u8),
            char::from(b'A' + (n % 676 / 26) as u8),
            char::from(b'A' + (n % 26) as u8)
        )
    };
    // libewf's globbing on case-sensitive filesystems expects one consistent
    // prefix case throughout a set. The writer itself uses uppercase suffixes.
    let ext = if first
        .extension()
        .is_some_and(|s| s.to_string_lossy().starts_with('e'))
    {
        ext.to_ascii_lowercase()
    } else {
        ext
    };
    Ok(first.with_extension(ext))
}

/// Refuse an existing segment family or receipt, including dangling symlinks.
pub fn validate_new_image_path(image: &Path) -> Result<()> {
    ensure!(
        image
            .extension()
            .is_some_and(|s| s.eq_ignore_ascii_case("e01")),
        "--e01 requires a .e01 filename"
    );
    ensure!(
        !image
            .file_name()
            .is_some_and(|s| s.to_string_lossy().contains(':')),
        "E01 destination cannot be an alternate stream"
    );
    let parent = image
        .parent()
        .filter(|p| !p.as_os_str().is_empty())
        .unwrap_or(Path::new("."));
    let stem = image
        .file_stem()
        .context("E01 destination has no filename")?
        .to_string_lossy();
    let entries = match fs::read_dir(parent) {
        Ok(entries) => entries,
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => return Ok(()),
        Err(e) => return Err(e).context("Cannot inspect E01 destination"),
    };
    let receipt = receipt_path(image);
    for entry in entries {
        let path = entry?.path();
        let same_stem = path
            .file_stem()
            .is_some_and(|s| s.to_string_lossy().eq_ignore_ascii_case(&stem));
        let ext = path
            .extension()
            .unwrap_or_default()
            .to_string_lossy()
            .to_ascii_uppercase();
        let family = same_stem
            && ext.len() == 3
            && ext.as_bytes()[0].is_ascii_uppercase()
            && ext.as_bytes()[0] >= b'E'
            && (ext.as_bytes()[1..].iter().all(u8::is_ascii_uppercase)
                || (ext.starts_with('E') && ext.as_bytes()[1..].iter().all(u8::is_ascii_digit)));
        let same_receipt = path.file_name().is_some_and(|s| {
            receipt.file_name().is_some_and(|r| {
                s.to_string_lossy()
                    .eq_ignore_ascii_case(&r.to_string_lossy())
            })
        });
        ensure!(
            !family && !same_receipt,
            "Refusing to overwrite an existing E01 segment set or receipt: {}",
            path.display()
        );
    }
    Ok(())
}

fn check_space(parent: &Path, reserve: u64) -> Result<()> {
    ensure!(
        fs2::available_space(parent)? >= reserve.saturating_add(WRITER_HEADROOM),
        "Insufficient host free space for E01 compression scratch and the free-space reserve"
    );
    Ok(())
}

fn read_capacity(remaining: u64, capacity: usize) -> usize {
    // Narrow only after clamping: a 4 GiB multiple otherwise wraps to zero on x86.
    remaining.min(capacity as u64) as usize
}

/// Write and verify an exactly sized, sector-aligned raw disk stream. The receipt
/// is published last. It attests container integrity, not the completeness of a
/// collection or the validity of the original forensic artifacts.
pub fn write_image(
    source: impl Read,
    size: u64,
    output: &Path,
    options: &Options,
    summary: Option<&Summary>,
) -> Result<ContainerReport> {
    write_with_segments(
        source,
        size,
        output,
        options,
        summary,
        CHUNKS_PER_SEGMENT as u32,
    )
}

fn write_with_segments(
    mut source: impl Read,
    size: u64,
    output: &Path,
    options: &Options,
    summary: Option<&Summary>,
    chunks_per_segment: u32,
) -> Result<ContainerReport> {
    ensure!(
        size > 0 && size.is_multiple_of(512) && size <= MAX_CAPACITY,
        "E01 disk size must be nonzero, sector-aligned and within the segment-set limit"
    );
    ensure!(
        (1..=128).contains(&options.threads),
        "Threads must be in 1..=128"
    );
    let output = paths::resolve_future(output)?;
    validate_new_image_path(&output)?;
    let parent = output.parent().context("E01 output has no parent")?;
    ensure!(
        !platform::is_remote_windows_path(&output.to_string_lossy()),
        "E01 output must be local"
    );
    fs::create_dir_all(parent)?;
    check_space(parent, options.reserve_bytes)?;
    let work = tempfile::Builder::new()
        .prefix(".kumade-e01-encode-")
        .tempdir_in(parent)?;
    platform::protect_output_root(work.path())?;
    let staged = work
        .path()
        .join(output.file_name().context("Missing E01 filename")?);
    let bar = ui::progress_bar(size, options.quiet || options.verbose);
    let result = (|| {
        let mut settings = SequentialOptions::new(size);
        settings.chunks_per_segment = chunks_per_segment;
        settings.write.format = WriteFormat::Ewf1Physical;
        settings.write.compression = WriteCompression::Zlib;
        settings
            .write
            .metadata
            .set_header_value("acquiry_software", "Kumade");
        // EWF1 headers carry only a version field; name the tool in it so that
        // libewf and EnCase show who wrote the container.
        settings.write.metadata.set_header_value(
            "acquiry_software_version",
            concat!("Kumade ", env!("CARGO_PKG_VERSION")),
        );
        settings.write.metadata.set_header_value(
            "description",
            "Logical triage collection in a newly created NTFS disk; not a source-disk image",
        );
        let pool = rayon::ThreadPoolBuilder::new()
            .num_threads(options.threads)
            .build()?;
        let mut writer = SequentialWriter::create(&staged, settings)?;
        let mut buffer = vec![0u8; 1024 * 1024];
        let mut consumed = 0u64;
        while consumed < size {
            check_space(parent, options.reserve_bytes)?;
            let capacity = read_capacity(size - consumed, buffer.len());
            source
                .read_exact(&mut buffer[..capacity])
                .context("NTFS staging stream ended before its declared size")?;
            pool.install(|| writer.write_all(&buffer[..capacity]))?;
            consumed += capacity as u64;
            bar.set_position(consumed);
        }
        ensure!(
            source.read(&mut [0u8; 1])? == 0,
            "NTFS staging stream exceeds its declared size"
        );
        let written = pool.install(|| writer.finish())?;
        bar.finish_and_clear();
        if !options.quiet {
            ui::status("Verifying E01 container hashes…");
        }
        // Fresh output must be well formed; recovery-mode tolerance is for
        // damaged input evidence, not a newly generated container.
        let image = Image::open_with_options(
            &staged,
            OpenOptions::default().with_strictness(OpenStrictness::Strict),
        )?;
        let verify_bar = ui::progress_bar(size, options.quiet || options.verbose);
        let verification = image.verify_with_progress(
            &VerifyOptions::default()
                .with_parallelism(options.threads)
                .with_expected_sha256(written.computed_sha256),
            |p| {
                verify_bar.set_position(p.bytes_processed);
                ControlFlow::Continue(())
            },
        );
        verify_bar.finish_and_clear();
        let verification = verification?;
        ensure!(
            verification.references_match() == Some(true) && verification.bytes_verified == size,
            "E01 container hash verification failed"
        );
        drop(image);
        let mut report = ContainerReport {
            schema_version: 1,
            format: "EWF1Physical".into(),
            logical_bytes: size,
            media_sha256: model::hex(&written.computed_sha256),
            verified: true,
            segments: Vec::new(),
            collection: summary.cloned(),
        };
        for (i, path) in written.segment_paths.iter().enumerate() {
            let target = segment_path(&output, i as u64 + 1)?;
            ensure!(
                path.file_name()
                    .zip(target.file_name())
                    .is_some_and(|(a, b)| a
                        .to_string_lossy()
                        .eq_ignore_ascii_case(&b.to_string_lossy())),
                "Unexpected E01 segment filename"
            );
            let (bytes, sha256) = collect::hash_file(path)?;
            report.segments.push(Segment {
                file: target.file_name().unwrap().to_string_lossy().into_owned(),
                size: bytes,
                sha256,
            });
        }
        let receipt = work.path().join("container-report.json");
        collect::write_json_new(&receipt, &report)?;
        // Check the complete namespace before the first publication. The OS
        // no-overwrite commit also protects against another creator racing us.
        validate_new_image_path(&output)?;
        for (i, path) in written.segment_paths.iter().enumerate() {
            collect::commit_payload(path, &segment_path(&output, i as u64 + 1)?)?;
        }
        collect::commit_payload(&receipt, &receipt_path(&output))?;
        Ok(report)
    })();
    bar.finish_and_clear();
    if result.is_err() {
        return match retain(work) {
            Some(retained) => result.with_context(|| {
                format!(
                    "E01 encoding/publication failed; owned staging retained at {}",
                    retained.display()
                )
            }),
            None => result.context("E01 encoding/publication failed"),
        };
    }
    work.close()
        .context("Verified E01 saved, but encoding scratch cleanup failed")?;
    result
}

/// Collect into NTFS first, then preserve that disk in compressed E01 segments.
pub fn collect(
    plan: &Plan,
    output: &Path,
    size_gib: Option<u64>,
    options: &Options,
) -> Result<Summary> {
    #[cfg(not(windows))]
    {
        let _ = (plan, output, size_gib, options);
        anyhow::bail!("E01 collection requires Windows");
    }
    #[cfg(windows)]
    {
        let mut configured = options.clone();
        let owns_early = configured.early.is_none();
        if owns_early {
            let resolved = paths::resolve_future(output)?;
            configured.early = crate::early::prepare(
                resolved.parent().context("E01 output has no parent")?,
                plan.sources
                    .first()
                    .map(|s| s.computer.as_str())
                    .unwrap_or("UnknownComputer"),
                plan.memory_requested,
                configured.live_info.as_ref(),
            )?;
        }
        let options = &configured;
        let output = paths::resolve_future(output)?;
        validate_new_image_path(&output)?;
        ensure!(
            !platform::is_remote_windows_path(&output.to_string_lossy()),
            "E01 output must be local"
        );
        let parent = output.parent().context("E01 output has no parent")?;
        fs::create_dir_all(parent)?;
        check_space(parent, options.reserve_bytes)?;
        let work = tempfile::Builder::new()
            .prefix(".kumade-e01-ntfs-")
            .tempdir_in(parent)?;
        platform::protect_output_root(work.path())?;
        let result: Result<Summary> = (|| {
            let stage = work.path().join("collection.vhdx");
            if !options.quiet {
                ui::field("E01 container", output.display());
            }
            // Leave space for both the NTFS stage and compressed output. The
            // result can be less compressible than anticipated; writes still
            // enforce the physical reserve throughout encoding.
            let raw_known = crate::metadata::raw_candidate_sizes(plan).known;
            let output_headroom = plan
                .known_bytes
                .checked_add(options.early.as_ref().map_or(0, |e| e.bytes))
                .and_then(|n| n.checked_add(raw_known))
                .and_then(|n| n.checked_add(WRITER_HEADROOM))
                .and_then(|n| n.checked_add(512 * 1024 * 1024))
                .and_then(|n| n.checked_add(options.reserve_bytes))
                .context("E01 staging space estimate overflow")?;
            let stage_options = Options {
                threads: options.threads,
                reserve_bytes: output_headroom,
                quiet: options.quiet,
                verbose: options.verbose,
                ntfs_metadata: false,
                host_reserve: None,
                live_info: options.live_info.clone(),
                process_scan: options.process_scan.clone(),
                early: options.early.clone(),
                entropy: options.entropy.clone(),
            };
            let summary =
                crate::vhdx::collect_staged(plan, &stage, size_gib, &stage_options, MAX_CAPACITY)?;
            if !options.quiet {
                ui::status("Compressing the read-only NTFS disk into E01…");
            }
            let report = crate::vhdx::read_staged_disk(&stage, |reader, size| {
                write_image(reader, size, &output, options, Some(&summary))
            })?;
            if !options.quiet {
                let bytes: u64 = report.segments.iter().map(|s| s.size).sum();
                ui::field("Logical media SHA256", &report.media_sha256);
                ui::field(
                    "Results saved",
                    format!(
                        "{} ( {} segments / {} )",
                        output.display(),
                        ui::count(report.segments.len() as u64),
                        collect::human_bytes(bytes)
                    ),
                );
            }
            Ok(summary)
        })();
        match result {
            Ok(summary) => {
                if owns_early && let Some(capture) = &options.early {
                    capture.cleanup()?;
                }

                let path = work.keep();
                if let Err(e) = fs::remove_dir_all(&path) {
                    eprintln!(
                        "Verified E01 saved; NTFS staging cleanup failed at {}: {e}",
                        path.display()
                    );
                }
                Ok(summary)
            }
            Err(error) => match retain(work) {
                Some(retained) => Err(error).with_context(|| {
                    format!(
                        "E01 collection failed; NTFS staging retained at {}",
                        retained.display()
                    )
                }),
                None => Err(error).context("E01 collection failed"),
            },
        }
    }
}

/// Keep a scratch directory that holds anything (partial segments, a staged
/// disk) for inspection; a run refused before it wrote anything, such as a
/// capacity check, leaves no empty protected directory behind.
fn retain(work: tempfile::TempDir) -> Option<PathBuf> {
    let path = work.keep();
    let empty = fs::read_dir(&path).is_ok_and(|mut entries| entries.next().is_none());
    if empty && fs::remove_dir(&path).is_ok() {
        None
    } else {
        Some(path)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::io::Cursor;

    fn options() -> Options {
        Options {
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
        }
    }

    #[test]
    fn read_sizes_do_not_wrap_at_four_gib_on_x86() {
        for remaining in [1, u32::MAX as u64 + 1, 8 * 1024 * 1024 * 1024, u64::MAX] {
            assert_eq!(
                read_capacity(remaining, 1024 * 1024),
                remaining.min(1024 * 1024) as usize
            );
        }
        assert_eq!(read_capacity(0, 1024), 0);
    }

    #[test]
    fn e01_round_trip_is_standard_segmented_and_byte_exact() {
        let root = tempfile::tempdir().unwrap();
        let path = root.path().join("Evidence 'quoted'.e01");
        let raw: Vec<u8> = (0..2 * 1024 * 1024 + 512)
            .map(|i| if i % 11 == 0 { (i % 251) as u8 } else { 0 })
            .collect();
        let report = write_with_segments(
            Cursor::new(&raw),
            raw.len() as u64,
            &path,
            &options(),
            None,
            32,
        )
        .unwrap();
        assert!(report.verified);
        assert_eq!(report.segments.len(), 3);
        assert_eq!(report.media_sha256, model::sha256(&raw));
        assert_eq!(fs::read(&path).unwrap()[..8], *b"EVF\x09\x0d\x0a\xff\0");
        let image = Image::open_with_options(
            &path,
            OpenOptions::default().with_strictness(OpenStrictness::Strict),
        )
        .unwrap();
        assert_eq!(image.media_size(), raw.len() as u64);
        let mut restored = Vec::new();
        image.cursor().read_to_end(&mut restored).unwrap();
        assert_eq!(restored, raw);
        for segment in &report.segments {
            let file = root.path().join(&segment.file);
            assert_eq!(
                collect::hash_file(&file).unwrap(),
                (segment.size, segment.sha256.clone())
            );
        }
        let receipt: ContainerReport =
            serde_json::from_slice(&fs::read(receipt_path(&path)).unwrap()).unwrap();
        assert_eq!(receipt.media_sha256, report.media_sha256);
        assert_eq!(
            fs::read_dir(root.path()).unwrap().count(),
            4,
            "successful encoding removes its scratch"
        );
        // Optional independent reader, used in Linux CI and local qualification.
        if let Some(tool) = std::env::var_os("KUMADE_EWFVERIFY") {
            let checked = std::process::Command::new(tool)
                .arg("-q")
                .arg(&path)
                .output()
                .unwrap();
            assert!(
                checked.status.success(),
                "{}{}",
                String::from_utf8_lossy(&checked.stdout),
                String::from_utf8_lossy(&checked.stderr)
            );
        }
    }

    #[test]
    fn failed_or_oversize_input_never_gets_a_completion_receipt() {
        for actual in [0, 512, 1536] {
            let root = tempfile::tempdir().unwrap();
            let path = root.path().join("failed.E01");
            assert!(
                write_image(Cursor::new(vec![0; actual]), 1024, &path, &options(), None).is_err()
            );
            assert!(!path.exists());
            assert!(!receipt_path(&path).exists());
        }
    }

    #[test]
    fn destination_and_receipt_collisions_are_refused_without_changing_input() {
        for name in [
            "case.E01",
            "case.e01",
            "case.E02",
            "case.EAA",
            "case.ZZZ",
            "case.E01.json",
        ] {
            let root = tempfile::tempdir().unwrap();
            let old = root.path().join(name);
            fs::write(&old, b"original evidence").unwrap();
            assert!(
                write_image(
                    Cursor::new(vec![0; 512]),
                    512,
                    &root.path().join("case.E01"),
                    &options(),
                    None
                )
                .is_err()
            );
            assert_eq!(fs::read(&old).unwrap(), b"original evidence");
            assert_eq!(fs::read_dir(root.path()).unwrap().count(), 1);
        }
        for name in ["case.raw", "case.Ex01", "case.E02", "case:stream.e01"] {
            assert!(validate_new_image_path(Path::new(name)).is_err());
        }
        assert!(segment_path(Path::new("case.E01"), MAX_SEGMENTS + 1).is_err());
    }

    #[test]
    fn only_scratch_that_holds_something_is_retained() {
        let root = tempfile::tempdir().unwrap();
        let empty = tempfile::Builder::new()
            .prefix(".kumade-e01-ntfs-")
            .tempdir_in(root.path())
            .unwrap();
        let empty_path = empty.path().to_owned();
        assert_eq!(retain(empty), None);
        assert!(!empty_path.exists());
        let used = tempfile::Builder::new()
            .prefix(".kumade-e01-encode-")
            .tempdir_in(root.path())
            .unwrap();
        fs::write(used.path().join("case.E01"), b"partial").unwrap();
        let used_path = used.path().to_owned();
        assert_eq!(retain(used), Some(used_path.clone()));
        assert!(used_path.join("case.E01").exists());
    }

    #[cfg(unix)]
    #[test]
    fn dangling_segment_links_are_never_replaced() {
        let root = tempfile::tempdir().unwrap();
        let link = root.path().join("case.E02");
        std::os::unix::fs::symlink(root.path().join("missing"), &link).unwrap();
        assert!(validate_new_image_path(&root.path().join("case.E01")).is_err());
        assert!(
            fs::symlink_metadata(&link)
                .unwrap()
                .file_type()
                .is_symlink()
        );
    }
}
