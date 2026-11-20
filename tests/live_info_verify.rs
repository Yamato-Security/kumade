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

//! Inventory-only output verification, exercised without PowerShell.
use kumade::{collect::hash_file, live_info::Entry};
use serde_json::json;
use std::{collections::BTreeMap, fs, path::Path};

/// Write the files `live-info` leaves behind for one successful provider.
fn write_inventory(root: &Path) {
    let directory = root.join("LiveInfo");
    fs::create_dir_all(&directory).unwrap();
    fs::write(
        directory.join("HostInfo.csv"),
        "Computer,CollectedUtc,Provider,Name\nHOST,2026-11-20T00:00:00Z,HostInfo,HOST\n",
    )
    .unwrap();
    let (bytes, sha256) = hash_file(&directory.join("HostInfo.csv")).unwrap();
    let entry = Entry {
        provider: "HostInfo".into(),
        status: "Success".into(),
        rows: 1,
        started_utc: "2026-11-20T00:00:00Z".into(),
        finished_utc: "2026-11-20T00:00:01Z".into(),
        elapsed_seconds: 1.0,
        output_file: "LiveInfo/HostInfo.csv".into(),
        bytes,
        sha256,
        message: String::new(),
    };
    fs::write(
        directory.join("Manifest.json"),
        json!({"SchemaVersion":1,"SnapshotType":"NonAtomicLiveQueries","Entries":[entry]})
            .to_string(),
    )
    .unwrap();
    let mut csv = csv::Writer::from_path(directory.join("Manifest.csv")).unwrap();
    csv.serialize(&entry).unwrap();
    csv.flush().unwrap();
    let mut hashes = BTreeMap::new();
    for name in [
        "LiveInfo/HostInfo.csv",
        "LiveInfo/Manifest.json",
        "LiveInfo/Manifest.csv",
    ] {
        hashes.insert(name, hash_file(&root.join(name)).unwrap().1);
    }
    fs::write(
        directory.join("Seal.json"),
        json!({"SchemaVersion":1,"FileSHA256":hashes,"Signature":"NotConfigured"}).to_string(),
    )
    .unwrap();
}

#[test]
fn inventory_only_output_verifies_and_detects_tampering() {
    let temp = tempfile::tempdir().unwrap();
    write_inventory(temp.path());
    assert_eq!(kumade::verify::verify(temp.path()).unwrap(), (1, true));
    assert_eq!(kumade::live_info::verify(temp.path()).unwrap(), (1, 0));
    fs::write(
        temp.path().join("LiveInfo/HostInfo.csv"),
        "Computer,CollectedUtc,Provider,Name\nHOST,2026-11-20T00:00:00Z,HostInfo,OTHER\n",
    )
    .unwrap();
    assert!(kumade::verify::verify(temp.path()).is_err());
}

#[test]
fn an_unsealed_collection_does_not_pass_on_its_inventory_seal() {
    let temp = tempfile::tempdir().unwrap();
    write_inventory(temp.path());
    // A collection that stopped after the inventory has Run.json but no outer Seal.json.
    fs::write(temp.path().join("Run.json"), "{}").unwrap();
    let error = kumade::verify::verify(temp.path()).unwrap_err();
    assert!(
        format!("{error:#}").contains("no completed seal"),
        "{error:#}"
    );
}
