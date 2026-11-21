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
//! No acquisition implementation is copied from the GPL/AGPL reference tools.
use crate::model::Fingerprint;
use anyhow::{Context, Result, bail, ensure};
use ntfs::{
    Ntfs, NtfsAttributeFlags, NtfsAttributeType, NtfsFile, NtfsReadSeek,
    attribute_value::NtfsAttributeValue, indexes::NtfsFileNameIndex,
};
use std::{
    fs::File,
    io::{self, Read, Seek, SeekFrom, Write},
    path::{Component, Path},
};

const BLOCK: usize = 64 * 1024;
#[repr(align(4096))]
struct Aligned([u8; BLOCK]);

/// All underlying reads have sector-aligned positions, lengths and buffers.
/// Logical seeks are checked using i128, including u64 positions above i64::MAX.
pub struct DeviceReader {
    file: File,
    length: u64,
    position: u64,
    block_start: Option<u64>,
    valid: usize,
    sector: usize,
    buffer: Box<Aligned>,
}

impl DeviceReader {
    pub fn new(file: File, length: u64, sector: usize) -> Result<Self> {
        ensure!(
            sector.is_power_of_two() && sector <= 4096 && BLOCK.is_multiple_of(sector),
            "Unsupported device sector size"
        );
        ensure!(
            length > 0 && length.is_multiple_of(sector as u64),
            "Invalid sector-aligned device size"
        );
        Ok(Self {
            file,
            length,
            position: 0,
            block_start: None,
            valid: 0,
            sector,
            buffer: Box::new(Aligned([0; BLOCK])),
        })
    }
    fn invalidate(&mut self) {
        self.block_start = None;
        self.valid = 0;
    }
}

impl Read for DeviceReader {
    fn read(&mut self, out: &mut [u8]) -> io::Result<usize> {
        if out.is_empty() || self.position >= self.length {
            return Ok(0);
        }
        let start = self.position / BLOCK as u64 * BLOCK as u64;
        if self.block_start != Some(start) {
            self.file.seek(SeekFrom::Start(start))?;
            self.valid = (self.length - start).min(BLOCK as u64) as usize;
            debug_assert_eq!(self.valid % self.sector, 0);
            self.file.read_exact(&mut self.buffer.0[..self.valid])?;
            self.block_start = Some(start);
        }
        let offset = (self.position - start) as usize;
        let n = out.len().min(self.valid - offset);
        out[..n].copy_from_slice(&self.buffer.0[offset..offset + n]);
        self.position = self
            .position
            .checked_add(n as u64)
            .ok_or_else(|| io::Error::other("Read position overflow"))?;
        Ok(n)
    }
}
impl Seek for DeviceReader {
    fn seek(&mut self, target: SeekFrom) -> io::Result<u64> {
        let next = match target {
            SeekFrom::Start(n) => i128::from(n),
            SeekFrom::Current(n) => i128::from(self.position) + i128::from(n),
            SeekFrom::End(n) => i128::from(self.length) + i128::from(n),
        };
        self.position = u64::try_from(next).map_err(|_| {
            io::Error::new(
                io::ErrorKind::InvalidInput,
                "Seek outside representable device offsets",
            )
        })?;
        Ok(self.position)
    }
}

pub trait ReadSeek: Read + Seek {}
impl<T: Read + Seek + ?Sized> ReadSeek for T {}

pub struct RawVolume {
    device: DeviceReader,
    ntfs: Ntfs,
}
pub struct RawResult {
    pub before: Fingerprint,
    pub after: Fingerprint,
    pub bytes: u64,
}
/// Basic information of a raw NTFS object, read without touching its data.
#[derive(Clone, Debug)]
pub struct RawStat {
    /// `$STANDARD_INFORMATION` times as NTFS 100 ns FILETIME ticks (zero = unset).
    pub created: u64,
    pub modified: u64,
    pub changed: u64,
    pub accessed: u64,
    /// Win32-style file attributes, including the directory flag and the
    /// sparse flag when any `$DATA` attribute of the file is sparse.
    pub attributes: u32,
    pub directory: bool,
    /// `ntfs:<record>:<sequence>`, the same identity the raw copy records.
    pub identity: String,
    /// Logical and allocated size of the selected `$DATA` stream; zero when
    /// the object has no such stream (directories, stream-only files).
    pub size: u64,
    pub allocated: u64,
}

fn locate<'n>(ntfs: &'n Ntfs, device: &mut DeviceReader, relative: &Path) -> Result<NtfsFile<'n>> {
    let mut file = ntfs.root_directory(device)?;
    for part in relative.components() {
        let Component::Normal(name) = part else {
            bail!("Unsafe raw relative path")
        };
        let name = name.to_str().context("Unsupported NTFS name encoding")?;
        let index = file.directory_index(device)?;
        let mut finder = index.finder();
        let entry =
            NtfsFileNameIndex::find(&mut finder, ntfs, device, name).ok_or_else(|| {
                io::Error::new(
                    io::ErrorKind::NotFound,
                    format!("NTFS object not present: {}", relative.display()),
                )
            })??;
        file = entry.to_file(ntfs, device)?;
    }
    Ok(file)
}

pub fn is_missing(error: &anyhow::Error) -> bool {
    error.chain().any(|e| {
        e.downcast_ref::<io::Error>()
            .is_some_and(|e| e.kind() == io::ErrorKind::NotFound)
    })
}

pub(crate) fn filetime(ticks: u64) -> Option<String> {
    // NTFS uses zero for an unset timestamp. Do not turn it into a claimed
    // observation at 1601-01-01; Windows also cannot restore that sentinel
    // through FileTimes. Original NTFS bytes remain unchanged in acquisition.
    if ticks == 0 {
        return None;
    }
    let unix = i128::from(ticks) - 116_444_736_000_000_000;
    let seconds = i64::try_from(unix.div_euclid(10_000_000)).ok()?;
    chrono::DateTime::from_timestamp(seconds, (unix.rem_euclid(10_000_000) * 100) as u32)
        .map(|t| t.to_rfc3339_opts(chrono::SecondsFormat::Nanos, true))
}

impl RawVolume {
    pub fn open(path: &Path) -> Result<Self> {
        let file = crate::platform::open_source(path)
            .with_context(|| format!("Cannot open raw source {}", path.display()))?;
        let (length, sector) = device_geometry(&file)?;
        let mut device = DeviceReader::new(file, length, sector)?;
        let mut ntfs = Ntfs::new(&mut device).context("Not a supported NTFS volume")?;
        ntfs.read_upcase_table(&mut device)?;
        Ok(Self { device, ntfs })
    }

    /// Inspect logical unnamed DATA through the same locked-file backend as acquisition.
    /// The callback borrows a seekable NTFS stream; no temporary copy is created.
    pub fn inspect_file<T>(
        &mut self,
        relative: &Path,
        inspect: impl FnOnce(&mut dyn ReadSeek, u64) -> Result<T>,
    ) -> Result<(T, Fingerprint, Fingerprint)> {
        self.device.invalidate();
        let before = self.stat(relative, None)?;
        ensure!(
            !before.directory && before.attributes & 0x400 == 0,
            "Raw reparse/directory content is unsupported"
        );
        let result = {
            let file = locate(&self.ntfs, &mut self.device, relative)?;
            let item = file
                .data(&mut self.device, "")
                .context("NTFS DATA is absent")??;
            let attribute = item.to_attribute()?;
            ensure!(
                !attribute
                    .flags()
                    .intersects(NtfsAttributeFlags::COMPRESSED | NtfsAttributeFlags::ENCRYPTED),
                "Raw compressed/encrypted DATA needs a supported logical-read backend"
            );
            let value = attribute.value(&mut self.device)?;
            let size = value.len();
            let mut reader = value.attach(&mut self.device);
            inspect(&mut reader, size)?
        };
        self.device.invalidate();
        let after = self.stat(relative, None)?;
        let fingerprint = |s: RawStat| Fingerprint {
            size: s.size,
            modified_ns: filetime(s.modified),
            created_ns: filetime(s.created),
            accessed_ns: filetime(s.accessed),
            identity: Some(s.identity),
        };
        Ok((result, fingerprint(before), fingerprint(after)))
    }

    pub fn copy_file(
        &mut self,
        relative: &Path,
        stream: Option<&str>,
        writer: &mut impl Write,
    ) -> Result<RawResult> {
        self.copy_file_with_attributes(relative, stream, writer, |_, _| Ok(()))
    }

    /// Basic information of an NTFS object: `$STANDARD_INFORMATION` times and
    /// attributes, the file reference, and the logical/allocated size of the
    /// selected `$DATA` stream. Windows does not expose its own system files
    /// (`$MFT`, `$LogFile`, `$Extend\$UsnJrnl`, …) to file APIs, so this is the
    /// only metadata source for them. Sizes count allocated clusters, which is
    /// what a sparse-aware copy of the stream occupies.
    pub fn stat(&mut self, relative: &Path, stream: Option<&str>) -> Result<RawStat> {
        self.device.invalidate();
        let file = locate(&self.ntfs, &mut self.device, relative)?;
        let info = file.info()?;
        let mut stat = RawStat {
            created: info.creation_time().nt_timestamp(),
            modified: info.modification_time().nt_timestamp(),
            changed: info.mft_record_modification_time().nt_timestamp(),
            accessed: info.access_time().nt_timestamp(),
            attributes: info.file_attributes().bits(),
            directory: file.is_directory(),
            identity: format!(
                "ntfs:{}:{}",
                file.file_record_number(),
                file.sequence_number()
            ),
            size: 0,
            allocated: 0,
        };
        if stat.directory {
            // Win32 reports the directory flag; $STANDARD_INFORMATION does not store it.
            stat.attributes |= 0x10;
        }
        // The sparse flag is per $DATA attribute; Win32 reports it on the file
        // when any stream is sparse.
        let mut attributes = file.attributes();
        while let Some(item) = attributes.next(&mut self.device) {
            let item = item?;
            let attribute = item.to_attribute()?;
            if attribute.ty()? == NtfsAttributeType::Data
                && attribute.flags().contains(NtfsAttributeFlags::SPARSE)
            {
                stat.attributes |= 0x200;
            }
        }
        match file.data(&mut self.device, stream.unwrap_or_default()) {
            Some(item) => {
                let item = item?;
                let attribute = item.to_attribute()?;
                let value = attribute.value(&mut self.device)?;
                stat.size = value.len();
                stat.allocated = match &value {
                    NtfsAttributeValue::NonResident(value) => {
                        let mut allocated = 0u64;
                        for run in value.data_runs() {
                            let run = run?;
                            // Sparse runs have no data position and occupy nothing.
                            if run.data_position().value().is_some() {
                                allocated = allocated
                                    .checked_add(run.allocated_size())
                                    .context("Allocated size overflow")?;
                            }
                        }
                        allocated
                    }
                    _ => stat.size,
                };
            }
            None => ensure!(
                stream.is_none(),
                io::Error::new(io::ErrorKind::NotFound, "NTFS data stream is absent")
            ),
        }
        Ok(stat)
    }

    pub fn copy_file_with_attributes<W: Write>(
        &mut self,
        relative: &Path,
        stream: Option<&str>,
        writer: &mut W,
        mut attributes: impl FnMut(u32, &mut W) -> Result<()>,
    ) -> Result<RawResult> {
        self.device.invalidate();
        let file = locate(&self.ntfs, &mut self.device, relative)?;
        let entry_number = file.file_record_number();
        let sequence = file.sequence_number();
        let info = file.info()?;
        let item = file
            .data(&mut self.device, stream.unwrap_or_default())
            .ok_or_else(|| {
                io::Error::new(io::ErrorKind::NotFound, "NTFS data stream is absent")
            })??;
        let attr = item.to_attribute()?;
        ensure!(
            !attr
                .flags()
                .intersects(NtfsAttributeFlags::COMPRESSED | NtfsAttributeFlags::ENCRYPTED),
            "Raw compressed/encrypted data requires a supported logical-read backend"
        );
        // Reparse-backed/WOF data cannot be advertised as an ordinary logical file.
        ensure!(
            info.file_attributes().bits() & 0x400 == 0,
            "Raw reparse-backed file content is unsupported"
        );
        let mut value = attr.value(&mut self.device)?;
        let size = value.len();
        let before = Fingerprint {
            size,
            modified_ns: filetime(info.modification_time().nt_timestamp()),
            created_ns: filetime(info.creation_time().nt_timestamp()),
            accessed_ns: filetime(info.access_time().nt_timestamp()),
            identity: Some(format!("ntfs:{entry_number}:{sequence}")),
        };
        // Sparse is also a per-DATA attribute. Qualify the write policy from
        // that flag even when the standard-information flag is incomplete.
        let storage_attributes = info.file_attributes().bits()
            | if attr.flags().contains(NtfsAttributeFlags::SPARSE) {
                0x200
            } else {
                0
            };
        attributes(storage_attributes, writer)?;
        let mut buffer = vec![0_u8; 1024 * 1024];
        let mut bytes = 0_u64;
        loop {
            let n = value.read(&mut self.device, &mut buffer)?;
            if n == 0 {
                break;
            }
            writer.write_all(&buffer[..n])?;
            bytes = bytes
                .checked_add(n as u64)
                .context("Data length overflow")?;
            ensure!(bytes <= size, "NTFS stream exceeded declared size");
        }
        ensure!(bytes == size, "NTFS short read: {bytes}/{size}");
        drop(value);
        self.device.invalidate();
        let after_file = self.ntfs.file(&mut self.device, entry_number)?;
        let after_info = after_file.info()?;
        let after_item = after_file
            .data(&mut self.device, stream.unwrap_or_default())
            .context("NTFS stream disappeared during read")??;
        let after = Fingerprint {
            size: after_item.to_attribute()?.value_length(),
            modified_ns: filetime(after_info.modification_time().nt_timestamp()),
            created_ns: filetime(after_info.creation_time().nt_timestamp()),
            accessed_ns: filetime(after_info.access_time().nt_timestamp()),
            identity: Some(format!(
                "ntfs:{}:{}",
                after_file.file_record_number(),
                after_file.sequence_number()
            )),
        };
        Ok(RawResult {
            before,
            after,
            bytes,
        })
    }
}

fn image_geometry(metadata: io::Result<std::fs::Metadata>) -> Result<Option<(u64, usize)>> {
    match metadata {
        Ok(metadata) if metadata.is_file() => Ok(Some((metadata.len(), 512))),
        Ok(_) => Ok(None),
        // Raw volume handles support device IOCTLs but not ordinary file
        // metadata queries (ERROR_INVALID_PARAMETER on Windows). Continue to
        // the read-only volume length and sector-size queries in that case.
        #[cfg(windows)]
        Err(_) => Ok(None),
        #[cfg(not(windows))]
        Err(error) => Err(error.into()),
    }
}

pub(crate) fn device_geometry(file: &File) -> Result<(u64, usize)> {
    if let Some(geometry) = image_geometry(file.metadata())? {
        return Ok(geometry);
    }
    #[cfg(windows)]
    {
        use std::{mem::size_of, os::windows::io::AsRawHandle, ptr};
        use windows_sys::Win32::System::{
            IO::DeviceIoControl,
            Ioctl::{DISK_GEOMETRY, IOCTL_DISK_GET_DRIVE_GEOMETRY, IOCTL_DISK_GET_LENGTH_INFO},
        };
        let mut length = 0_i64;
        let mut returned = 0;
        ensure!(
            // SAFETY: handle is read-only; length has exactly the IOCTL output layout.
            unsafe {
                DeviceIoControl(
                    file.as_raw_handle(),
                    IOCTL_DISK_GET_LENGTH_INFO,
                    ptr::null(),
                    0,
                    &mut length as *mut _ as *mut _,
                    8,
                    &mut returned,
                    ptr::null_mut(),
                )
            } != 0,
            "Cannot query raw volume length: {}",
            io::Error::last_os_error()
        );
        // SAFETY: all-zero DISK_GEOMETRY is valid for an API output buffer.
        let mut geometry: DISK_GEOMETRY = unsafe { std::mem::zeroed() };
        ensure!(
            // SAFETY: geometry is writable with the advertised structure size.
            unsafe {
                DeviceIoControl(
                    file.as_raw_handle(),
                    IOCTL_DISK_GET_DRIVE_GEOMETRY,
                    ptr::null(),
                    0,
                    &mut geometry as *mut _ as *mut _,
                    size_of::<DISK_GEOMETRY>() as u32,
                    &mut returned,
                    ptr::null_mut(),
                )
            } != 0,
            "Cannot query raw sector size"
        );
        Ok((u64::try_from(length)?, geometry.BytesPerSector as usize))
    }
    #[cfg(not(windows))]
    bail!(
        "Raw devices are supported on Windows; use a plain NTFS image file for cross-platform tests"
    )
}

#[cfg(test)]
mod time_tests {
    use super::filetime;

    #[test]
    fn unset_ntfs_time_is_not_an_observation_at_the_windows_epoch() {
        assert_eq!(filetime(0), None);
    }

    #[test]
    fn real_ntfs_times_retain_their_100ns_precision() {
        assert_eq!(
            filetime(1).as_deref(),
            Some("1601-01-01T00:00:00.000000100Z")
        );
        assert_eq!(
            filetime(116_444_736_000_000_000).as_deref(),
            Some("1970-01-01T00:00:00.000000000Z")
        );
        assert_eq!(
            filetime(116_444_736_000_000_001).as_deref(),
            Some("1970-01-01T00:00:00.000000100Z")
        );
    }

    #[cfg(windows)]
    #[test]
    fn raw_volume_metadata_error_does_not_prevent_device_geometry_queries() {
        assert_eq!(
            super::image_geometry(Err(std::io::Error::from_raw_os_error(87))).unwrap(),
            None
        );
    }
}
