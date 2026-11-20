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

use serde::{Deserialize, Serialize};
use std::path::PathBuf;

pub const SCHEMA_VERSION: u32 = 1;

pub fn utc_now() -> String {
    chrono::Utc::now().to_rfc3339_opts(chrono::SecondsFormat::Nanos, true)
}

#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(rename_all = "PascalCase")]
pub struct Source {
    pub id: String,
    pub root: PathBuf,
    pub computer: String,
    pub live: bool,
    pub raw_device: Option<PathBuf>,
    pub profile_roots: Vec<PathBuf>,
    #[serde(default)]
    pub excluded_profiles: Vec<String>,
}

#[derive(Default, Debug)]
pub struct SourceDiscovery {
    pub sources: Vec<Source>,
    pub issues: Vec<Issue>,
}

#[derive(Clone, Debug, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "PascalCase")]
pub struct Fingerprint {
    pub size: u64,
    pub modified_ns: Option<String>,
    pub created_ns: Option<String>,
    pub accessed_ns: Option<String>,
    pub identity: Option<String>,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(rename_all = "PascalCase")]
pub struct PlannedFile {
    pub id: String,
    pub source_id: String,
    pub source_path: PathBuf,
    pub relative_path: PathBuf,
    pub stream: Option<String>,
    pub artifacts: Vec<String>,
    pub before: Option<Fingerprint>,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(rename_all = "PascalCase")]
pub struct Issue {
    pub source_id: String,
    pub path: String,
    pub status: String,
    pub reason: String,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(rename_all = "PascalCase")]
pub struct Coverage {
    pub source_id: String,
    pub artifact_id: String,
    pub discovered: u64,
    pub status: String,
    pub reason: String,
}

#[derive(Clone, Debug, Serialize)]
#[serde(rename_all = "PascalCase")]
pub struct FamilyCoverage {
    pub source_id: String,
    pub artifact_id: String,
    pub planned: u64,
    pub acquired: u64,
    pub partial: u64,
    pub failed: u64,
    pub not_present: u64,
    pub status: String,
    pub reason: String,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(rename_all = "PascalCase")]
pub struct Plan {
    pub schema_version: u32,
    pub created_utc: String,
    pub catalog_sha256: String,
    pub sources: Vec<Source>,
    pub files: Vec<PlannedFile>,
    pub coverage: Vec<Coverage>,
    pub issues: Vec<Issue>,
    pub known_bytes: u64,
    pub unknown_sizes: u64,
    pub memory_requested: bool,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(rename_all = "PascalCase")]
pub struct Record {
    pub schema_version: u32,
    pub observation_id: String,
    pub computer: String,
    pub source_id: String,
    pub source_path: String,
    pub stream_name: Option<String>,
    pub artifact_ids: String,
    pub relative_output_path: Option<String>,
    pub method: String,
    pub status: String,
    pub reason: String,
    pub started_utc: String,
    pub finished_utc: String,
    pub logical_size: Option<u64>,
    pub bytes_read: u64,
    #[serde(rename = "SHA-256")]
    pub sha256: Option<String>,
    pub verified: bool,
    pub changed_during_read: bool,
    pub created_utc: Option<String>,
    pub modified_utc: Option<String>,
    pub accessed_utc: Option<String>,
    pub source_file_id: Option<String>,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(rename_all = "PascalCase")]
pub struct Summary {
    pub schema_version: u32,
    pub run_id: String,
    pub version: String,
    pub started_utc: String,
    pub finished_utc: String,
    pub completeness: String,
    pub collected: u64,
    pub partial: u64,
    pub failed: u64,
    pub discovery_errors: u64,
    pub bytes_acquired: u64,
    pub catalog_sha256: String,
    #[serde(default)]
    pub metadata_errors: u64,
    #[serde(default)]
    pub live_info_failed_providers: u64,
}

pub fn sha256(data: &[u8]) -> String {
    use sha2::{Digest, Sha256};
    hex(&Sha256::digest(data))
}

pub fn hex(bytes: &[u8]) -> String {
    const DIGITS: &[u8; 16] = b"0123456789abcdef";
    let mut out = String::with_capacity(bytes.len() * 2);
    for &b in bytes {
        out.push(DIGITS[(b >> 4) as usize] as char);
        out.push(DIGITS[(b & 15) as usize] as char);
    }
    out
}
