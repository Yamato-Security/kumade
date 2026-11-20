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

//! Native SDK bridge ownership. All calls stay on the creating COM thread.
use super::*;
use std::{ffi::c_void, marker::PhantomData, os::windows::ffi::OsStrExt, ptr, rc::Rc};
use windows_sys::{
    Win32::System::Threading::{GetCurrentProcess, IsWow64Process2},
    core::GUID,
};

#[repr(C)]
struct NativeSnapshot {
    id: GUID,
    set: GUID,
    provider: GUID,
    created: i64,
    attributes: i32,
    count: i32,
    original: [u16; 128],
    device: [u16; 512],
}
unsafe extern "C" {
    fn kumade_vss_open(output: *mut *mut c_void) -> i32;
    fn kumade_vss_supported(client: *mut c_void, volume: *const u16, supported: *mut i32) -> i32;
    fn kumade_vss_start(client: *mut c_void) -> i32;
    fn kumade_vss_add(client: *mut c_void, volume: *const u16, id: *mut GUID) -> i32;
    fn kumade_vss_commit(client: *mut c_void, timeout: u32) -> i32;
    fn kumade_vss_properties(
        client: *mut c_void,
        id: *const GUID,
        output: *mut NativeSnapshot,
    ) -> i32;
    fn kumade_vss_close(client: *mut c_void) -> i32;
    #[cfg(test)]
    fn kumade_vss_snapshot_size() -> usize;
}
fn check(code: i32, operation: &str) -> Result<()> {
    let detail = match code as u32 {
        0x8004231f => "Insufficient shadow-copy storage",
        0x80042316 => "Another snapshot set is already in progress",
        0x80070005 => "Access denied: run from an elevated Administrator session",
        0x800705b4 => "Snapshot creation timed out",
        _ => "VSS request did not complete",
    };
    ensure!(
        code >= 0,
        "{operation} failed: {detail} (HRESULT 0x{:08X}); check VSS services, volume support, free shadow storage and Windows Application/VSS logs",
        code as u32
    );
    Ok(())
}
fn wide(s: &str) -> Vec<u16> {
    std::ffi::OsStr::new(s)
        .encode_wide()
        .chain(Some(0))
        .collect()
}
fn id(g: &GUID) -> String {
    uuid::Uuid::from_fields(g.data1, g.data2, g.data3, &g.data4).to_string()
}
fn string(s: &[u16]) -> Result<String> {
    let end = s
        .iter()
        .position(|&c| c == 0)
        .context("Unterminated VSS string")?;
    Ok(String::from_utf16(&s[..end])?)
}

pub(super) fn check_host() -> Result<()> {
    let (mut process, mut native) = (0u16, 0u16);
    ensure!(
        // SAFETY: pseudo handle and two valid output words.
        unsafe { IsWow64Process2(GetCurrentProcess(), &mut process, &mut native) } != 0,
        "Cannot determine the native Windows architecture"
    );
    ensure!(
        process == 0,
        "VSS requesters cannot run under WOW64/emulation; use Kumade's native {} build",
        match native {
            0xaa64 => "ARM64",
            0x8664 => "x64",
            _ => "architecture",
        }
    );
    crate::platform::enable_backup_privilege()
        .context("VSS acquisition requires an elevated Administrator session")
}

pub(super) struct Session {
    client: *mut c_void,
    pub snapshots: Vec<Snapshot>,
    _same_thread: PhantomData<Rc<()>>,
}
impl Session {
    pub fn create(
        volumes: &[String],
        timeout_seconds: u64,
        skip_unsupported: bool,
    ) -> Result<(Self, Vec<String>)> {
        check_host()?;
        ensure!(
            !volumes.is_empty() && volumes.len() <= 64,
            "VSS requires between 1 and 64 source volumes"
        );
        ensure!(
            (1..=3600).contains(&timeout_seconds),
            "VSS timeout must be between 1 and 3600 seconds"
        );
        let mut client = ptr::null_mut();
        check(
            // SAFETY: output pointer is initialized; bridge owns SDK COM setup/teardown.
            unsafe { kumade_vss_open(&mut client) },
            "Initialize VSS requester",
        )?;
        ensure!(!client.is_null(), "VSS returned no requester");
        let mut session = Self {
            client,
            snapshots: Vec::new(),
            _same_thread: PhantomData,
        };
        let mut availability = Vec::new();
        for v in volumes {
            let root = super::volume_identifier(v)?;
            let normalized =
                crate::platform::volume_identity(&root)?.context("VSS volume is not local")?;
            let mut yes = 0;
            let name = wide(&normalized);
            check(
                // SAFETY: owned client and live terminated volume string/output.
                unsafe { kumade_vss_supported(client, name.as_ptr(), &mut yes) },
                "Query VSS volume support",
            )?;
            availability.push((normalized, yes != 0));
        }
        let (supported, unsupported) = super::partition_volumes(availability, skip_unsupported)?;
        check(
            // SAFETY: initialized requester, called once before adding any volumes.
            unsafe { kumade_vss_start(client) },
            "Start VSS snapshot set",
        )?;
        let mut ids = Vec::new();
        for volume in &supported {
            let name = wide(volume);
            let mut snapshot = GUID::from_u128(0);
            check(
                // SAFETY: set exists and input/output memory lives through the call.
                unsafe { kumade_vss_add(client, name.as_ptr(), &mut snapshot) },
                "Add volume to VSS snapshot set",
            )?;
            ids.push(snapshot);
        }
        check(
            // SAFETY: owned requester with its complete set; bridge bounds async wait/cancel.
            unsafe { kumade_vss_commit(client, (timeout_seconds * 1000) as u32) },
            "Create VSS snapshot set",
        )?;
        for (volume, snapshot) in supported.iter().zip(ids) {
            let mut out = std::mem::MaybeUninit::<NativeSnapshot>::uninit();
            check(
                // SAFETY: bridge initializes the entire ABI output on success.
                unsafe { kumade_vss_properties(client, &snapshot, out.as_mut_ptr()) },
                "Read owned VSS snapshot properties",
            )?;
            // SAFETY: the successful bridge call fully initialized all primitive fields.
            let out = unsafe { out.assume_init() };
            ensure!(
                out.count >= 0 && out.count as usize == supported.len(),
                "VSS snapshot-set count differs from selected volumes"
            );
            let original = string(&out.original)?;
            ensure!(
                original.eq_ignore_ascii_case(volume),
                "VSS returned a different source volume"
            );
            ensure!(
                out.attributes & 0x10 != 0 && out.attributes & 0x9 == 0,
                "VSS returned an unexpected persistence/writer context"
            );
            let device = PathBuf::from(string(&out.device)?);
            snapshot_device_root(&device)?;
            let created = u64::try_from(out.created)
                .ok()
                .and_then(crate::raw::filetime)
                .context("Invalid VSS snapshot timestamp")?;
            session.snapshots.push(Snapshot {
                snapshot_id: id(&out.id),
                snapshot_set_id: id(&out.set),
                provider_id: id(&out.provider),
                original_volume: original.clone(),
                original_root: original.into(),
                device_object: device,
                created_utc: created,
                attributes: out.attributes,
                consistency: "CrashConsistent".into(),
                writers_participated: false,
            });
        }
        Ok((session, unsupported))
    }
    pub fn close(&mut self) -> Result<()> {
        let client = std::mem::replace(&mut self.client, ptr::null_mut());
        if client.is_null() {
            return Ok(());
        }
        check(
            // SAFETY: ownership is consumed once on the creating thread; bridge frees it.
            unsafe { kumade_vss_close(client) },
            "Delete this run's VSS snapshot set",
        )
    }
}
impl Drop for Session {
    fn drop(&mut self) {
        if let Err(e) = self.close() {
            eprintln!(
                "VSS cleanup failed: {e:#}. Only the current run's set was targeted; consult snapshot IDs in Plan.json."
            );
        }
    }
}
#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn sdk_snapshot_layout_matches_rust() {
        assert_eq!(
            // SAFETY: returns a constant structure size, with no inputs or side effects.
            unsafe { kumade_vss_snapshot_size() },
            std::mem::size_of::<NativeSnapshot>()
        );
    }
    #[test]
    fn emulated_requesters_are_rejected_before_creating_a_snapshot() {
        let (mut p, mut n) = (0, 0);
        assert_ne!(
            // SAFETY: pseudo process handle and live output words.
            unsafe { IsWow64Process2(GetCurrentProcess(), &mut p, &mut n) },
            0
        );
        if p != 0 {
            assert!(check_host().unwrap_err().to_string().contains("native"));
        }
    }
}
