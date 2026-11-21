// Copyright (C) 2026 Shirofune Security Co., Ltd.
// SPDX-License-Identifier: RPL-1.5
//! Read-only Windows memory adapter. One owned handle binds bytes and process identity.
use super::*;
use boreal::memory::{FragmentedMemory, MemoryParams, Region, RegionDescription};
use std::{
    mem::size_of,
    os::windows::io::{AsRawHandle, FromRawHandle, OwnedHandle},
    sync::{Arc, Mutex},
};
use windows_sys::Win32::{
    Foundation::{
        ERROR_INVALID_PARAMETER, ERROR_NO_MORE_FILES, FILETIME, GetLastError, INVALID_HANDLE_VALUE,
    },
    System::{
        Diagnostics::{Debug::ReadProcessMemory, ToolHelp::*},
        Memory::{MEM_COMMIT, MEMORY_BASIC_INFORMATION, PAGE_GUARD, PAGE_NOACCESS, VirtualQueryEx},
        ProcessStatus::{GetProcessMemoryInfo, PROCESS_MEMORY_COUNTERS},
        SystemInformation::{GetNativeSystemInfo, SYSTEM_INFO},
        Threading::{
            GetCurrentProcess, GetExitCodeProcess, GetProcessTimes, OpenProcess,
            PROCESS_QUERY_INFORMATION, PROCESS_VM_READ, QueryFullProcessImageNameW,
        },
    },
};

fn handle(h: &OwnedHandle) -> windows_sys::Win32::Foundation::HANDLE {
    h.as_raw_handle()
}

pub fn require_native() -> Result<()> {
    crate::platform::require_native_build("Process memory scanning")
}
pub fn list_processes() -> Result<Vec<(u32, String)>> {
    // SAFETY: documented snapshot flags; no external pointers.
    let raw = unsafe { CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0) };
    ensure!(
        raw != INVALID_HANDLE_VALUE,
        "Cannot enumerate processes: {}",
        std::io::Error::last_os_error()
    );
    // SAFETY: successful snapshot gives an owned handle, closed by OwnedHandle.
    let snapshot = unsafe { OwnedHandle::from_raw_handle(raw) };
    let mut entry = PROCESSENTRY32W {
        dwSize: size_of::<PROCESSENTRY32W>() as u32,
        ..Default::default()
    };
    let mut rows = Vec::new();
    // SAFETY: live snapshot and correctly sized writable entry.
    let mut ok = unsafe { Process32FirstW(handle(&snapshot), &mut entry) };
    while ok != 0 {
        let end = entry
            .szExeFile
            .iter()
            .position(|c| *c == 0)
            .unwrap_or(entry.szExeFile.len());
        rows.push((
            entry.th32ProcessID,
            String::from_utf16_lossy(&entry.szExeFile[..end]),
        ));
        // SAFETY: same valid snapshot and output structure.
        ok = unsafe { Process32NextW(handle(&snapshot), &mut entry) };
    }
    // SAFETY: capture the error immediately after the last enumeration call.
    ensure!(
        // SAFETY: capture the error immediately after the last enumeration call.
        unsafe { GetLastError() } == ERROR_NO_MORE_FILES,
        "Process enumeration ended unexpectedly: {}",
        std::io::Error::last_os_error()
    );
    Ok(rows)
}

#[derive(Debug, Default)]
struct Stats {
    bytes: u64,
    reads: u64,
    failures: u64,
    guards: u64,
    query_error: Option<String>,
    expired: bool,
}
#[derive(Debug)]
struct ProcessMemory {
    process: OwnedHandle,
    buffer: Vec<u8>,
    current: Option<RegionDescription>,
    next_address: usize,
    max_address: usize,
    deadline: Instant,
    stats: Arc<Mutex<Stats>>,
    first_pass: bool,
}
impl FragmentedMemory for ProcessMemory {
    fn reset(&mut self) {
        self.current = None;
        self.next_address = 0;
        self.first_pass = false;
    }
    fn next(&mut self, params: &MemoryParams) -> Option<RegionDescription> {
        loop {
            if Instant::now() >= self.deadline {
                self.stats.lock().unwrap().expired = true;
                return None;
            }
            if self.next_address > self.max_address {
                return None;
            }
            let mut info = MEMORY_BASIC_INFORMATION::default();
            // SAFETY: process handle lives with this adapter; output is correctly sized and writable.
            let size = unsafe {
                VirtualQueryEx(
                    handle(&self.process),
                    self.next_address as *const _,
                    &mut info,
                    size_of::<MEMORY_BASIC_INFORMATION>(),
                )
            };
            if size == 0 {
                let error = std::io::Error::last_os_error();
                // Querying beyond a process's maximum user address is the documented terminator.
                if error.raw_os_error() != Some(ERROR_INVALID_PARAMETER as i32) {
                    self.stats.lock().unwrap().query_error = Some(error.to_string());
                }
                return None;
            }
            let start = info.BaseAddress as usize;
            let end = start.checked_add(info.RegionSize)?;
            let chunk_start = self.next_address.max(start);
            if end <= chunk_start {
                self.stats.lock().unwrap().query_error = Some("Non-advancing memory region".into());
                return None;
            }
            if info.State != MEM_COMMIT || info.Protect & (PAGE_NOACCESS | PAGE_GUARD) != 0 {
                if self.first_pass && info.State == MEM_COMMIT && info.Protect & PAGE_GUARD != 0 {
                    self.stats.lock().unwrap().guards += 1;
                }
                self.next_address = end;
                continue;
            }
            let length = (end - chunk_start)
                .min(
                    params
                        .memory_chunk_size
                        .unwrap_or(params.max_fetched_region_size),
                )
                .min(params.max_fetched_region_size);
            self.next_address = chunk_start.checked_add(length)?;
            let desc = RegionDescription {
                start: chunk_start,
                length,
            };
            self.current = Some(desc);
            return Some(desc);
        }
    }
    fn fetch(&mut self, _: &MemoryParams) -> Option<Region<'_>> {
        if Instant::now() >= self.deadline {
            self.stats.lock().unwrap().expired = true;
            return None;
        }
        let desc = self.current?;
        self.buffer.resize(desc.length, 0);
        let mut read = 0;
        // SAFETY: source belongs to the held read-only process handle; destination allocation is at least desc.length bytes.
        let ok = unsafe {
            ReadProcessMemory(
                handle(&self.process),
                desc.start as *const _,
                self.buffer.as_mut_ptr().cast(),
                self.buffer.len(),
                &mut read,
            )
        };
        let mut stats = self.stats.lock().unwrap();
        stats.reads += 1;
        stats.bytes += read as u64;
        if ok == 0 || read != desc.length {
            stats.failures += 1;
        }
        drop(stats);
        self.buffer.truncate(read);
        if read == 0 {
            None
        } else {
            Some(Region {
                start: desc.start,
                mem: &self.buffer,
            })
        }
    }
}
fn filetime(t: FILETIME) -> u64 {
    (u64::from(t.dwHighDateTime) << 32) | u64::from(t.dwLowDateTime)
}
fn times(h: windows_sys::Win32::Foundation::HANDLE) -> Result<(FILETIME, u64)> {
    let (mut created, mut exited, mut kernel, mut user) = (
        FILETIME::default(),
        FILETIME::default(),
        FILETIME::default(),
        FILETIME::default(),
    );
    // SAFETY: handle is live and four initialized output FILETIMEs are writable.
    ensure!(
        // SAFETY: handle is live and four initialized output FILETIMEs are writable.
        unsafe { GetProcessTimes(h, &mut created, &mut exited, &mut kernel, &mut user) } != 0,
        "Cannot query process times: {}",
        std::io::Error::last_os_error()
    );
    Ok((created, filetime(kernel) + filetime(user)))
}
pub fn metrics() -> Metrics {
    // SAFETY: current process pseudo-handle requires no closing.
    let h = unsafe { GetCurrentProcess() };
    let mut mem = PROCESS_MEMORY_COUNTERS {
        cb: size_of::<PROCESS_MEMORY_COUNTERS>() as u32,
        ..Default::default()
    };
    // SAFETY: valid current process and correctly sized initialized counters.
    let ok =
        unsafe { GetProcessMemoryInfo(h, &mut mem, size_of::<PROCESS_MEMORY_COUNTERS>() as u32) };
    Metrics {
        cpu_seconds: times(h).map_or(0.0, |t| t.1 as f64 / 10_000_000.0),
        peak_working_set_bytes: if ok == 0 {
            0
        } else {
            mem.PeakWorkingSetSize as u64
        },
    }
}

pub fn scan(
    scanner: &Scanner,
    pid: u32,
    name: String,
    options: &Options,
) -> (ProcessResult, Vec<Detection>) {
    let start = Instant::now();
    let mut row = ProcessResult::new(pid, name);
    let result = (|| -> Result<_> {
        // SAFETY: request read/query access only, never writes or suspends target processes.
        let raw = unsafe { OpenProcess(PROCESS_QUERY_INFORMATION | PROCESS_VM_READ, 0, pid) };
        ensure!(
            !raw.is_null(),
            "Cannot open process: {}",
            std::io::Error::last_os_error()
        );
        // SAFETY: successful OpenProcess returns a uniquely owned handle.
        let process = unsafe { OwnedHandle::from_raw_handle(raw) };
        let (created, _) = times(handle(&process))?;
        let ticks = filetime(created) as i128 - 116_444_736_000_000_000i128;
        row.process_created_utc = chrono::DateTime::from_timestamp(
            ticks.div_euclid(10_000_000) as i64,
            (ticks.rem_euclid(10_000_000) * 100) as u32,
        )
        .map(|v| v.to_rfc3339_opts(chrono::SecondsFormat::Nanos, true))
        .unwrap_or_default();
        let mut path = vec![0u16; 32768];
        let mut length = path.len() as u32;
        // SAFETY: same live process, path capacity matches the supplied length.
        if unsafe {
            QueryFullProcessImageNameW(handle(&process), 0, path.as_mut_ptr(), &mut length)
        } != 0
        {
            row.image_path = String::from_utf16_lossy(&path[..length as usize]);
            row.process_name = row
                .image_path
                .rsplit(['\\', '/'])
                .next()
                .unwrap_or("")
                .into();
        } else {
            // The snapshot's name could belong to a recycled PID; never present it as verified identity.
            row.process_name.clear();
        }
        let mut system = SYSTEM_INFO::default();
        // SAFETY: correctly initialized writable native system information.
        unsafe { GetNativeSystemInfo(&mut system) };
        let stats = Arc::new(Mutex::new(Stats::default()));
        // Retain a separate borrowed owner until scanning completes so exit state uses the same PID generation.
        let exited_handle = process.try_clone()?;
        let memory = ProcessMemory {
            process,
            buffer: Vec::new(),
            current: None,
            next_address: 0,
            max_address: system.lpMaximumApplicationAddress as usize,
            deadline: start + Duration::from_secs(options.timeout),
            stats: stats.clone(),
            first_pass: true,
        };
        let (error, found) = match scanner.scan_fragmented(memory) {
            Ok(found) => (None, found),
            Err((e, found)) => (Some(e.to_string()), found),
        };
        let s = stats.lock().unwrap();
        row.bytes_read = s.bytes;
        row.read_calls = s.reads;
        row.read_failures = s.failures;
        row.guard_regions_skipped = s.guards;
        let mut exit = 0;
        // SAFETY: owned clone of the exact scanned process and writable status.
        let live =
            unsafe { GetExitCodeProcess(handle(&exited_handle), &mut exit) } != 0 && exit == 259;
        let mut messages = Vec::new();
        if let Some(e) = error {
            messages.push(e);
        }
        if let Some(e) = &s.query_error {
            messages.push(format!("Memory enumeration: {e}"));
        }
        if s.expired {
            messages.push("Per-process deadline reached".into());
        }
        if s.failures > 0 {
            messages.push(format!("{} memory reads were incomplete", s.failures));
        }
        if s.bytes == 0 {
            messages.push("No process bytes were readable".into());
        }
        if !live {
            messages.push("Process exited during scan or exit state unavailable".into());
        }
        row.status = if messages.is_empty() {
            "Scanned"
        } else {
            "Partial"
        }
        .into();
        row.message = messages.join("; ");
        Ok(found)
    })();
    row.elapsed_seconds = start.elapsed().as_secs_f64();
    let found = match result {
        Ok(found) => detections(scanner, found, &row),
        Err(e) => {
            row.message = format!("{e:#}");
            vec![]
        }
    };
    row.matches = found.len();
    (row, found)
}

pub(super) fn enable_debug_privilege() -> Result<()> {
    use windows_sys::Win32::{
        Foundation::{ERROR_NOT_ALL_ASSIGNED, LUID, SetLastError},
        Security::*,
    };
    let mut raw = std::ptr::null_mut();
    // SAFETY: valid current process and writable token handle output.
    ensure!(
        // SAFETY: valid current process and writable token handle output.
        unsafe {
            windows_sys::Win32::System::Threading::OpenProcessToken(
                GetCurrentProcess(),
                TOKEN_ADJUST_PRIVILEGES | TOKEN_QUERY,
                &mut raw,
            )
        } != 0,
        "Cannot open process token: {}",
        std::io::Error::last_os_error()
    );
    // SAFETY: successful call transfers ownership of the handle to us.
    let token = unsafe { OwnedHandle::from_raw_handle(raw) };
    let mut luid = LUID::default();
    let name: Vec<u16> = "SeDebugPrivilege\0".encode_utf16().collect();
    // SAFETY: terminated UTF-16 input, initialized writable LUID output.
    ensure!(
        // SAFETY: terminated UTF-16 input, initialized writable LUID output.
        unsafe { LookupPrivilegeValueW(std::ptr::null(), name.as_ptr(), &mut luid) } != 0,
        "Cannot resolve SeDebugPrivilege"
    );
    let state = TOKEN_PRIVILEGES {
        PrivilegeCount: 1,
        Privileges: [LUID_AND_ATTRIBUTES {
            Luid: luid,
            Attributes: SE_PRIVILEGE_ENABLED,
        }],
    };
    // SAFETY: thread-local last error reset before AdjustTokenPrivileges.
    unsafe { SetLastError(0) };
    // SAFETY: live owned token and correctly sized single-entry privilege structure.
    ensure!(
        // SAFETY: live owned token and correctly sized single-entry privilege structure.
        unsafe {
            AdjustTokenPrivileges(
                handle(&token),
                0,
                &state,
                0,
                std::ptr::null_mut(),
                std::ptr::null_mut(),
            )
        } != 0,
        "Cannot enable SeDebugPrivilege"
    );
    // SAFETY: capture last error immediately; this call succeeds even if privilege was not held.
    ensure!(
        // SAFETY: capture last error immediately; this call succeeds even if privilege was not held.
        unsafe { GetLastError() } != ERROR_NOT_ALL_ASSIGNED,
        "Token does not hold SeDebugPrivilege; run elevated for broader access"
    );
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn failed_memory_fetch_is_accounted_for_without_zero_filling() {
        // SAFETY: current process pseudo-handle is always live and is immediately duplicated.
        let borrowed =
            unsafe { std::os::windows::io::BorrowedHandle::borrow_raw(GetCurrentProcess()) };
        let stats = Arc::new(Mutex::new(Stats::default()));
        let mut mem = ProcessMemory {
            process: borrowed.try_clone_to_owned().unwrap(),
            buffer: vec![],
            current: Some(RegionDescription {
                start: 1,
                length: 4096,
            }),
            next_address: 1,
            max_address: usize::MAX,
            deadline: Instant::now() + Duration::from_secs(5),
            stats: stats.clone(),
            first_pass: true,
        };
        let params = MemoryParams {
            max_fetched_region_size: 4096,
            memory_chunk_size: Some(4096),
            can_refetch_regions: true,
        };
        assert!(mem.fetch(&params).is_none());
        let s = stats.lock().unwrap();
        assert_eq!(s.failures, 1);
        assert_eq!(s.bytes, 0);
    }
    #[test]
    fn expired_adapter_stops_and_records_expiration() {
        // SAFETY: current process pseudo-handle is always live and is immediately duplicated.
        let borrowed =
            unsafe { std::os::windows::io::BorrowedHandle::borrow_raw(GetCurrentProcess()) };
        let stats = Arc::new(Mutex::new(Stats::default()));
        let mut mem = ProcessMemory {
            process: borrowed.try_clone_to_owned().unwrap(),
            buffer: vec![],
            current: None,
            next_address: 0,
            max_address: usize::MAX,
            deadline: Instant::now(),
            stats: stats.clone(),
            first_pass: true,
        };
        let params = MemoryParams {
            max_fetched_region_size: 4096,
            memory_chunk_size: Some(4096),
            can_refetch_regions: true,
        };
        assert!(mem.next(&params).is_none());
        assert!(stats.lock().unwrap().expired);
    }
}
