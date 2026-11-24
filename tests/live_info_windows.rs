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

#![cfg(windows)]
use kumade::live_info::{self, Format, Options};
use serde_json::Value;
use std::{
    fs,
    net::{TcpListener, TcpStream},
};

fn rows(root: &std::path::Path, name: &str) -> Vec<Value> {
    fs::read_to_string(root.join(format!("LiveInfo/{name}.jsonl")))
        .unwrap()
        .lines()
        .map(|l| serde_json::from_str(l).unwrap())
        .collect()
}
#[test]
fn all_builtin_providers_run_on_a_live_windows_host_and_seal_their_results() {
    let temp = tempfile::tempdir().unwrap();
    let result = live_info::collect_into(
        temp.path(),
        &Options {
            format: Format::Jsonl,
            threads: 2,
            timeout_seconds: 45,
            reserve_bytes: 0,
            quiet: true,
            ..Default::default()
        },
    )
    .unwrap();
    assert_eq!(result.entries.len(), live_info::datasets().len());
    for entry in &result.entries {
        assert!(
            !entry.message.contains("ParserError"),
            "{}: {}",
            entry.provider,
            entry.message
        );
        assert!(
            !entry.message.contains("Unexpected token"),
            "{}: {}",
            entry.provider,
            entry.message
        );
        assert!(
            !entry.message.contains("Invalid provider JSON"),
            "{}: {}",
            entry.provider,
            entry.message
        );
        if matches!(
            entry.provider.as_str(),
            "HostInfo"
                | "OperatingSystem"
                | "OsBuild"
                | "TimeZone"
                | "Processes"
                | "LocalUsers"
                | "IpConfiguration"
                | "SystemLocale"
                | "CollectorLocale"
                | "InputLanguages"
                | "KeyboardLayouts"
                | "InstalledUiLanguages"
        ) {
            assert_eq!(
                entry.status, "Success",
                "{}: {}",
                entry.provider, entry.message
            );
            assert!(entry.rows > 0);
        }
        for row in rows(temp.path(), &entry.provider) {
            assert!(row["Computer"].as_str().is_some_and(|s| !s.is_empty()));
            assert!(row["CollectedUtc"].as_str().unwrap().ends_with('Z'));
            assert_eq!(row["Provider"], entry.provider);
            let text = |key: &str| row[key].as_str().map(str::to_owned);
            match entry.provider.as_str() {
                // Enumerations are exported by name, never as bare integers.
                "FirewallRules" | "FirewallProfiles" => {
                    assert!(
                        matches!(text("Enabled").as_deref(), Some("True" | "False")),
                        "{row}"
                    )
                }
                "IpAddresses" => assert!(text("PrefixOrigin").is_some(), "{row}"),
                "DnsCache" => assert!(
                    text("RecordName").is_some() && text("RecordType").is_some(),
                    "{row}"
                ),
                "Hotfixes" => assert!(
                    row["InstalledOn"].is_null()
                        || text("InstalledOn").is_some_and(|d| {
                            d.len() == 10 && d.as_bytes()[4] == b'-' && d.as_bytes()[7] == b'-'
                        }),
                    "{row}"
                ),
                "WindowsPackages" => assert!(
                    !text("InstallTimeUtc").is_some_and(|t| t.starts_with("0001-")),
                    "{row}"
                ),
                "ScheduledTasks" => {
                    // A task without triggers has an empty list, not one null trigger.
                    for trigger in row["Triggers"].as_array().unwrap() {
                        assert!(trigger["TriggerType"].as_str().is_some(), "{row}");
                    }
                    for action in row["Actions"].as_array().unwrap() {
                        assert!(
                            action["Execute"].is_string() || action["ClassId"].is_string(),
                            "{row}"
                        );
                    }
                }
                "WmiEventConsumers" | "WmiEventFilters" => {
                    if entry.provider == "WmiEventConsumers" {
                        assert!(
                            text("ConsumerClass").is_some_and(|c| !c.is_empty()),
                            "{row}"
                        );
                    }
                    assert!(
                        row["CreatorSID"].is_null()
                            || text("CreatorSID").is_some_and(|s| s.starts_with("S-1-")),
                        "{row}"
                    );
                }
                _ => {}
            }
        }
    }
    let mut locale_buffer = [0_u16; 85];
    // SAFETY: a writable UTF-16 buffer of the stated length.
    let size = unsafe {
        windows_sys::Win32::Globalization::GetSystemDefaultLocaleName(
            locale_buffer.as_mut_ptr(),
            locale_buffer.len() as i32,
        )
    };
    assert!(size > 0);
    let native_locale = String::from_utf16(&locale_buffer[..size as usize - 1]).unwrap();
    assert!(
        rows(temp.path(), "SystemLocale")[0]["LocaleName"]
            .as_str()
            .unwrap()
            .eq_ignore_ascii_case(&native_locale)
    );
    let collector = rows(temp.path(), "CollectorLocale");
    assert_eq!(collector[0]["Scope"], "CollectorAccount");
    let sid = collector[0]["UserSid"].as_str().unwrap();
    assert!(sid.starts_with("S-1-"));
    for row in rows(temp.path(), "InputLanguages") {
        assert_eq!(row["UserSid"], sid);
        assert_eq!(row["Scope"], "CollectorAccount");
        assert!(row["InputMethodTips"].is_array());
    }
    for name in [
        "LoadedUserKeyboardLayouts",
        "LoadedUserRegionalSettings",
        "LoadedUserLanguages",
    ] {
        let entry = result.entries.iter().find(|e| e.provider == name).unwrap();
        assert!(
            matches!(entry.status.as_str(), "Success" | "Empty"),
            "{name}: {}",
            entry.message
        );
        for row in rows(temp.path(), name) {
            match row["Scope"].as_str().unwrap() {
                "LoadedUserHive" => assert_eq!(row["UserSid"], row["HiveName"]),
                "SystemDefaultHive" => {
                    assert_eq!(row["HiveName"], ".DEFAULT");
                    assert!(row["UserSid"].is_null());
                }
                other => panic!("Unrecognized user hive scope: {other}"),
            }
        }
    }
    assert_eq!(
        result.failures(),
        0,
        "{:?}",
        result
            .entries
            .iter()
            .filter(|e| !matches!(e.status.as_str(), "Success" | "Empty"))
            .collect::<Vec<_>>()
    );
    assert_eq!(
        live_info::verify(temp.path()).unwrap(),
        (result.entries.len(), result.failures())
    );
    fs::write(temp.path().join("LiveInfo/HostInfo.jsonl"), b"modified").unwrap();
    assert!(live_info::verify(temp.path()).is_err());
}
#[test]
fn live_socket_has_endpoint_and_process_context_and_formats_are_readable() {
    let listener = TcpListener::bind("127.0.0.1:0").unwrap();
    let port = listener.local_addr().unwrap().port();
    let _connection = TcpStream::connect(listener.local_addr().unwrap()).unwrap();
    let (_accepted, _) = listener.accept().unwrap();
    let temp = tempfile::tempdir().unwrap();
    let result = live_info::collect_into(
        temp.path(),
        &Options {
            format: Format::Jsonl,
            selected: vec!["TcpConnections".into()],
            reserve_bytes: 0,
            quiet: true,
            ..Default::default()
        },
    )
    .unwrap();
    assert_eq!(result.failures(), 0, "{:?}", result.entries);
    let data = rows(temp.path(), "TcpConnections");
    assert!(
        data.iter().any(|r| r["LocalPort"] == port
            && r["OwningProcess"] == std::process::id()
            && r["ExecutablePath"].as_str().is_some_and(|s| !s.is_empty())),
        "test socket absent from the collected endpoint/process context"
    );
    for format in [Format::Csv, Format::Json] {
        let temp = tempfile::tempdir().unwrap();
        let result = live_info::collect_into(
            temp.path(),
            &Options {
                format,
                selected: vec!["HostInfo".into()],
                reserve_bytes: 0,
                quiet: true,
                ..Default::default()
            },
        )
        .unwrap();
        assert_eq!(result.failures(), 0, "{:?}", result.entries);
        match format {
            Format::Csv => {
                let mut csv =
                    csv::Reader::from_path(temp.path().join("LiveInfo/HostInfo.csv")).unwrap();
                assert!(csv.headers().unwrap().iter().any(|h| h == "Computer"));
                assert!(csv.records().next().unwrap().is_ok());
            }
            Format::Json => {
                let data: Value = serde_json::from_slice(
                    &fs::read(temp.path().join("LiveInfo/HostInfo.json")).unwrap(),
                )
                .unwrap();
                assert!(data.as_array().is_some_and(|a| a.len() == 1));
            }
            _ => unreachable!(),
        }
    }
}

#[test]
fn live_inventory_is_inside_a_normal_collection_seal() {
    let temp = tempfile::tempdir().unwrap();
    let source = temp.path().join("source");
    fs::create_dir_all(source.join("Windows/Prefetch")).unwrap();
    fs::write(source.join("Windows/Prefetch/ONE.pf"), b"fixture").unwrap();
    let mut volume = kumade::discovery::directory_source(&source, "C", "TEST").unwrap();
    volume.live = true;
    let catalog = kumade::catalog::Rules::load(kumade::catalog::DEFAULT_CATALOG).unwrap();
    let plan =
        kumade::discovery::build_plan(vec![volume], &catalog, &["windows.prefetch".into()], false)
            .unwrap();
    let options = kumade::collect::Options {
        remote: None,
        threads: 1,
        reserve_bytes: 0,
        quiet: true,
        verbose: false,
        ntfs_metadata: false,
        host_reserve: None,
        process_scan: None,
        early: None,
        entropy: None,
        live_info: Some(Options {
            selected: vec!["HostInfo".into()],
            reserve_bytes: 0,
            quiet: true,
            ..Default::default()
        }),
    };
    let (root, summary) =
        kumade::collect::collect(&plan, &temp.path().join("results"), &options).unwrap();
    assert_eq!(summary.live_info_failed_providers, 0);
    let (_, complete) = kumade::verify::verify(&root).unwrap();
    assert!(complete);
    let seal: Value = serde_json::from_slice(&fs::read(root.join("Seal.json")).unwrap()).unwrap();
    assert!(seal["MetadataSHA256"]["LiveInfo/HostInfo.csv"].is_string());
    fs::write(root.join("LiveInfo/HostInfo.csv"), b"modified").unwrap();
    assert!(kumade::verify::verify(&root).is_err());
}
