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

use crate::{catalog::Rules, model::*, paths};
use anyhow::{Context, Result, bail};
use std::{
    collections::BTreeMap,
    fs,
    path::{Path, PathBuf},
    time::SystemTime,
};
use walkdir::WalkDir;

pub fn fingerprint(meta: &fs::Metadata) -> Fingerprint {
    fn timestamp(value: std::io::Result<SystemTime>) -> Option<String> {
        value.ok().map(|v| {
            chrono::DateTime::<chrono::Utc>::from(v)
                .to_rfc3339_opts(chrono::SecondsFormat::Nanos, true)
        })
    }
    #[cfg(unix)]
    let identity = {
        use std::os::unix::fs::MetadataExt;
        Some(format!("posix:{}:{}", meta.dev(), meta.ino()))
    };
    #[cfg(not(unix))]
    let identity = None;
    Fingerprint {
        size: meta.len(),
        modified_ns: timestamp(meta.modified()),
        created_ns: timestamp(meta.created()),
        accessed_ns: timestamp(meta.accessed()),
        identity,
    }
}

pub fn same_version(a: &Fingerprint, b: &Fingerprint) -> bool {
    fn time_eq(a: &Option<String>, b: &Option<String>) -> bool {
        match (a, b) {
            (Some(a), Some(b)) => match (
                chrono::DateTime::parse_from_rfc3339(a),
                chrono::DateTime::parse_from_rfc3339(b),
            ) {
                (Ok(a), Ok(b)) => a == b,
                _ => a == b,
            },
            _ => true, // Missing metadata is unknown, not proof of a change.
        }
    }
    let identity_eq = match (&a.identity, &b.identity) {
        (Some(a), Some(b)) if a.split(':').next() == b.split(':').next() => a == b,
        _ => true, // Native and raw identities can be from different namespaces.
    };
    a.size == b.size
        && time_eq(&a.modified_ns, &b.modified_ns)
        && time_eq(&a.created_ns, &b.created_ns)
        && identity_eq
}

pub fn directory_source(root: &Path, id: &str, computer: &str) -> Result<Source> {
    let root = crate::platform::canonicalize(root)
        .with_context(|| format!("Cannot resolve source {}", root.display()))?;
    if !root.is_dir() {
        bail!(
            "Source must be a Windows volume directory: {}",
            root.display()
        );
    }
    let mut profiles = Vec::new();
    for base in ["Users", "Documents and Settings", "Windows/ServiceProfiles"] {
        let Some(parent) = find_case_path(&root, Path::new(base))? else {
            continue;
        };
        for entry in fs::read_dir(parent)? {
            let entry = entry?;
            if entry.file_type()?.is_dir() {
                profiles.push(entry.path());
            }
        }
    }
    for path in [
        "Windows/System32/config/systemprofile",
        "Windows/SysWOW64/config/systemprofile",
    ] {
        if let Some(path) = find_case_path(&root, Path::new(path))? {
            profiles.push(path);
        }
    }
    profiles.sort();
    profiles.dedup();
    Ok(Source {
        id: id.to_owned(),
        root,
        computer: computer.to_owned(),
        live: false,
        raw_device: None,
        profile_roots: profiles,
        excluded_profiles: Vec::new(),
    })
}

/// Resolve only explicit components. Never follow a source link during planning.
pub fn find_case_path(root: &Path, relative: &Path) -> Result<Option<PathBuf>> {
    let mut current = root.to_owned();
    for part in relative.components() {
        let std::path::Component::Normal(name) = part else {
            bail!("Unsafe catalog path")
        };
        let exact = current.join(name);
        if let Ok(meta) = exact.symlink_metadata() {
            if meta.file_type().is_symlink() {
                return Ok(None);
            }
            current = exact;
            continue;
        }
        let entries = match fs::read_dir(&current) {
            Ok(v) => v,
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => return Ok(None),
            Err(e) => return Err(e.into()),
        };
        let mut found = None;
        for entry in entries {
            let entry = entry?;
            if entry
                .file_name()
                .to_str()
                .zip(name.to_str())
                .is_some_and(|(a, b)| a.eq_ignore_ascii_case(b))
            {
                if entry.file_type()?.is_symlink() {
                    continue;
                }
                if found.is_some() {
                    bail!("Case-ambiguous source path: {}", exact.display());
                }
                found = Some(entry.path());
            }
        }
        let Some(next) = found else { return Ok(None) };
        current = next;
    }
    Ok(Some(current))
}

pub fn build_plan(
    sources: Vec<Source>,
    rules: &Rules,
    only: &[String],
    memory: bool,
) -> Result<Plan> {
    for id in only {
        if !rules.catalog.artifacts.iter().any(|d| &d.id == id) {
            bail!("Unknown artifact ID: {id}");
        }
    }
    let enabled = |i: usize| only.is_empty() || only.contains(&rules.catalog.artifacts[i].id);
    let mut source_ids = std::collections::HashSet::new();
    for s in &sources {
        if s.id.is_empty() || !source_ids.insert(&s.id) {
            bail!("Source identifiers must be non-empty and unique");
        }
    }
    let profiles_enabled = rules
        .profiles
        .iter()
        .enumerate()
        .any(|(i, p)| enabled(i) && !p.is_empty());
    let mut plan = Plan {
        schema_version: SCHEMA_VERSION,
        created_utc: utc_now(),
        catalog_sha256: rules.sha256.clone(),
        sources,
        files: Vec::new(),
        coverage: Vec::new(),
        issues: Vec::new(),
        known_bytes: 0,
        unknown_sizes: 0,
        memory_requested: memory,
    };
    let mut files: BTreeMap<(String, PathBuf, Option<String>), PlannedFile> = BTreeMap::new();
    for source in &plan.sources {
        let mut counts = vec![0_u64; rules.catalog.artifacts.len()];
        let profile_relative = |path: &Path| -> Option<String> {
            source.profile_roots.iter().find_map(|p| {
                path.strip_prefix(p)
                    .ok()
                    .and_then(|r| paths::relative_text(r).ok())
            })
        };
        let walker = WalkDir::new(&source.root)
            .follow_links(false)
            .sort_by_file_name()
            .into_iter()
            .filter_entry(|e| {
                if !e.file_type().is_dir() || e.depth() == 0 {
                    return true;
                }
                if crate::platform::is_reparse_directory(e.path()) {
                    return false;
                }
                let Ok(relative) = e.path().strip_prefix(&source.root) else {
                    return false;
                };
                let Ok(text) = paths::relative_text(relative) else {
                    return true;
                };
                let p = profile_relative(e.path());
                (profiles_enabled && source.profile_roots.iter().any(|r| r.starts_with(e.path())))
                    || rules.can_descend_selected(&text, p.as_deref(), only)
            });
        for entry in walker {
            let entry = match entry {
                Ok(e) => e,
                Err(e) => {
                    plan.issues.push(Issue {
                        source_id: source.id.clone(),
                        path: e
                            .path()
                            .map(|p| p.display().to_string())
                            .unwrap_or_default(),
                        status: "Failed".into(),
                        reason: format!("Directory enumeration failed: {e}"),
                    });
                    continue;
                }
            };
            if entry.file_type().is_symlink() {
                plan.issues.push(Issue {
                    source_id: source.id.clone(),
                    path: entry.path().display().to_string(),
                    status: "Excluded".into(),
                    reason: "Symbolic link traversal is disabled".into(),
                });
                continue;
            }
            if !entry.file_type().is_file() {
                continue;
            }
            let relative = entry.path().strip_prefix(&source.root)?;
            let text = match paths::relative_text(relative) {
                Ok(p) => p,
                Err(e) => {
                    plan.issues.push(Issue {
                        source_id: source.id.clone(),
                        path: entry.path().display().to_string(),
                        status: "Unsupported".into(),
                        reason: e.to_string(),
                    });
                    continue;
                }
            };
            let profile = profile_relative(entry.path());
            let indexes: Vec<_> = rules
                .matching(&text, profile.as_deref())
                .into_iter()
                .filter(|i| enabled(*i))
                .collect();
            if indexes.is_empty() {
                continue;
            }
            let meta = match entry.metadata() {
                Ok(m) => Some(fingerprint(&m)),
                Err(e) => {
                    plan.issues.push(Issue {
                        source_id: source.id.clone(),
                        path: text.clone(),
                        status: "Failed".into(),
                        reason: format!("Cannot stat discovered file: {e}"),
                    });
                    None
                }
            };
            let key = (source.id.clone(), relative.to_owned(), None);
            let ids = indexes
                .iter()
                .map(|&i| {
                    counts[i] += 1;
                    rules.catalog.artifacts[i].id.clone()
                })
                .collect();
            files.insert(
                key,
                PlannedFile {
                    id: uuid::Uuid::new_v4().to_string(),
                    source_id: source.id.clone(),
                    source_path: entry.path().to_owned(),
                    relative_path: relative.to_owned(),
                    stream: None,
                    artifacts: ids,
                    before: meta,
                },
            );
        }
        if source.raw_device.is_some() {
            for (i, d) in rules
                .catalog
                .artifacts
                .iter()
                .enumerate()
                .filter(|(i, _)| enabled(*i))
            {
                for raw in &d.raw_paths {
                    let (base, stream) = raw
                        .rsplit_once(':')
                        .map(|(b, s)| (b, Some(s.to_owned())))
                        .unwrap_or((raw.as_str(), None));
                    let relative = PathBuf::from(base);
                    let key = (source.id.clone(), relative.clone(), stream.clone());
                    if let Some(existing) = files.get_mut(&key) {
                        if !existing.artifacts.contains(&d.id) {
                            existing.artifacts.push(d.id.clone());
                            counts[i] += 1;
                        }
                        continue;
                    }
                    // Raw-only paths are resolved during acquisition, including legitimate absence.
                    files.insert(
                        key,
                        PlannedFile {
                            id: uuid::Uuid::new_v4().to_string(),
                            source_id: source.id.clone(),
                            source_path: source.root.join(&relative),
                            relative_path: relative,
                            stream,
                            artifacts: vec![d.id.clone()],
                            before: None,
                        },
                    );
                    counts[i] += 1;
                }
            }
        }
        let enumeration_incomplete = plan.issues.iter().any(|i| {
            i.source_id == source.id && (i.status == "Failed" || i.status == "Unsupported")
        });
        for (i, d) in rules.catalog.artifacts.iter().enumerate() {
            let (status, reason) = if !enabled(i) {
                ("Excluded", "Artifact selection explicitly narrowed scope")
            } else if counts[i] > 0 {
                (
                    "Planned",
                    "Discovered files or raw metadata candidates; acquisition outcome is separate",
                )
            } else if enumeration_incomplete {
                (
                    "Unknown",
                    "Enumeration was incomplete; absence is not established",
                )
            } else {
                (
                    "NotPresent",
                    "No files matched in successfully enumerated locations; see discovery errors",
                )
            };
            plan.coverage.push(Coverage {
                source_id: source.id.clone(),
                artifact_id: d.id.clone(),
                discovered: counts[i],
                status: status.into(),
                reason: reason.into(),
            });
        }
    }
    plan.files = files.into_values().collect();
    for file in &plan.files {
        if let Some(meta) = &file.before {
            plan.known_bytes = plan
                .known_bytes
                .checked_add(meta.size)
                .context("Planned size exceeds u64")?;
        } else {
            plan.unknown_sizes += 1;
        }
    }
    Ok(plan)
}
