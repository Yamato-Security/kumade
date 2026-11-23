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

//! Acquisition planning, bounded copying and evidence verification.

//! Bounded parallelism inside strict volatility barriers, including native ADS dependencies.
use crate::model::*;
use std::collections::{BTreeMap, HashMap};
pub const LABELS: [&str; 10] = [
    "USN journal",
    "NTFS transaction log",
    "MFT and mirror",
    "Windows event logs",
    "Registry and recovery logs",
    "Active databases and queues",
    "Execution traces",
    "Other forensic artifacts",
    "Bulk user data and caches",
    "Paging and existing memory dumps",
];
pub fn disk_priority(item: &PlannedFile) -> usize {
    let path = item
        .relative_path
        .to_string_lossy()
        .replace('\\', "/")
        .to_ascii_lowercase();
    let name = path.rsplit('/').next().unwrap_or("");
    let has = |id: &str| item.artifacts.iter().any(|a| a == id);
    if has("windows.ntfs.usn")
        || crate::metadata::is_usn_journal(&item.relative_path, item.stream.as_deref())
    {
        0
    } else if has("windows.ntfs.logfile") || name == "$logfile" {
        1
    } else if has("windows.ntfs.mft") || matches!(name, "$mft" | "$mftmirr") {
        2
    } else if has("windows.eventlogs") || path.ends_with(".evtx") {
        3
    } else if item
        .artifacts
        .iter()
        .any(|a| a.starts_with("windows.registry."))
        || has("windows.amcache")
    {
        4
    } else if [
        "windows.srum",
        "windows.sum",
        "windows.bits",
        "windows.wmi",
        "windows.activities",
        "windows.notifications",
    ]
    .iter()
    .any(|id| has(id))
        || item
            .artifacts
            .iter()
            .any(|a| a.starts_with("windows.browsers."))
    {
        5
    } else if ["windows.prefetch", "windows.pca", "windows.powershell"]
        .iter()
        .any(|id| has(id))
    {
        6
    } else if has("windows.paging") {
        9
    } else if [
        "windows.outlook",
        "windows.thunderbird",
        "windows.collaboration",
        "windows.recycle",
        "windows.shellcache",
    ]
    .iter()
    .any(|id| has(id))
    {
        8
    } else {
        7
    }
}
/// A native file and all its ADS share the earliest priority of the group.
/// The base/stream barrier then applies *within* that priority, never after all disk files.
pub fn batches(files: &[PlannedFile], native: bool) -> Vec<(usize, Vec<&PlannedFile>)> {
    let mut priorities = HashMap::new();
    for f in files {
        priorities
            .entry((&f.source_id, &f.relative_path))
            .and_modify(|p: &mut usize| *p = (*p).min(disk_priority(f)))
            .or_insert(disk_priority(f));
    }
    let mut groups = BTreeMap::new();
    for f in files {
        let p = priorities[&(&f.source_id, &f.relative_path)];
        groups
            .entry((p, usize::from(native && f.stream.is_some())))
            .or_insert_with(Vec::new)
            .push(f);
    }
    groups.into_iter().map(|((p, _), v)| (p, v)).collect()
}
pub fn live_priority(name: &str) -> u8 {
    match name {
        "Processes" => 0,
        "TcpConnections" | "UdpEndpoints" | "DnsCache" | "LogonSessions" | "LogonAssociations"
        | "SmbSessions" | "SmbConnections" | "SmbOpenFiles" => 1,
        "Routes" | "Neighbors" | "IpAddresses" | "IpConfiguration" => 2,
        "WindowsPackages" | "AppxPackages" | "InstalledSoftware" | "Hotfixes" => 4,
        _ => 3,
    }
}
