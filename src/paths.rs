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

use anyhow::{Context, Result, bail};
use std::path::{Component, Path, PathBuf};

/// Canonicalize a future path without requiring its leaf to exist.
pub fn resolve_future(path: &Path) -> Result<PathBuf> {
    let absolute = if path.is_absolute() {
        path.to_owned()
    } else {
        std::env::current_dir()?.join(path)
    };
    let mut missing = Vec::new();
    let mut ancestor = absolute.as_path();
    while !ancestor.exists() {
        let name = ancestor
            .file_name()
            .context("Path has no existing ancestor")?;
        missing.push(name.to_owned());
        ancestor = ancestor.parent().context("Path has no existing ancestor")?;
    }
    let mut result = crate::platform::canonicalize(ancestor)?;
    for name in missing.into_iter().rev() {
        result.push(name);
    }
    if result
        .components()
        .any(|c| matches!(c, Component::ParentDir))
    {
        bail!("Parent components are not allowed in an output path");
    }
    Ok(result)
}

pub fn relative_text(path: &Path) -> Result<String> {
    let mut parts = Vec::new();
    for component in path.components() {
        match component {
            Component::Normal(name) => parts.push(
                name.to_str()
                    .context("Filename is not losslessly representable as UTF-8")?
                    .to_owned(),
            ),
            _ => bail!("Unsafe relative path: {}", path.display()),
        }
    }
    Ok(parts.join("/"))
}

/// Reversible UTF-8 encoding prevents collisions on Windows and across platforms.
pub fn encode_component(name: &str) -> String {
    let stem = name
        .split('.')
        .next()
        .unwrap_or_default()
        .to_ascii_uppercase();
    let reserved = matches!(stem.as_str(), "CON" | "PRN" | "AUX" | "NUL")
        || (stem.len() == 4
            && (stem.starts_with("COM") || stem.starts_with("LPT"))
            && matches!(stem.as_bytes()[3], b'1'..=b'9'));
    let mut encoded = String::new();
    for (i, c) in name.char_indices() {
        if c == '%'
            || c.is_control()
            || "<>:\"/\\|?*".contains(c)
            || ((c == '.' || c == ' ') && name[i..].chars().all(|v| v == '.' || v == ' '))
            || (reserved && i == 0)
        {
            let mut buf = [0; 4];
            for b in c.encode_utf8(&mut buf).as_bytes() {
                encoded.push_str(&format!("%{b:02X}"));
            }
        } else {
            encoded.push(c);
        }
    }
    if encoded.is_empty() {
        "%00".into()
    } else {
        encoded
    }
}

/// Files and directories Kumade itself writes at the root of a collection.
/// Drive directories sit beside them, so no source may take one of these names.
pub const RUN_ROOT_NAMES: [&str; 16] = [
    "Plan.json",
    "client_info.json",
    "Run.json",
    "Manifest.jsonl",
    "Manifest.csv",
    "Coverage.csv",
    "DiscoveryIssues.csv",
    "Errors.csv",
    "Summary.json",
    "Seal.json",
    "LiveInfo",
    "NTFS-Metadata.jsonl",
    "NTFS-Metadata.csv",
    "HighEntropyBinaries.csv",
    "HighEntropyBinaries.jsonl",
    "EntropySummary.json",
];

/// Windows filesystems are case-insensitive, so the comparison is too.
pub fn is_run_root_name(name: &str) -> bool {
    RUN_ROOT_NAMES
        .iter()
        .any(|reserved| reserved.eq_ignore_ascii_case(name))
}

/// One stable name for the folder and auto-named containers, in UTC.
pub fn run_name(computer: &str, started_utc: &str) -> Result<String> {
    let started = chrono::DateTime::parse_from_rfc3339(started_utc)
        .context("Invalid collection start time")?
        .with_timezone(&chrono::Utc);
    Ok(format!(
        "{}_{}",
        encode_component(computer),
        started.format("%Y-%m-%d_%H-%M-%S")
    ))
}

/// A directory (including a not-yet-created one) selects the automatic name;
/// a full filename remains an explicit override.
pub fn image_destination(input: &Path, run: &str, extension: &str) -> Result<PathBuf> {
    if input.is_dir() || input.extension().is_none() {
        Ok(input.join(format!("{run}.{extension}")))
    } else if input
        .extension()
        .and_then(|s| s.to_str())
        .is_some_and(|s| s.eq_ignore_ascii_case(extension))
    {
        Ok(input.to_owned())
    } else {
        bail!("Expected a directory or a .{extension} filename");
    }
}

pub fn output_relative(source: &str, relative: &Path, stream: Option<&str>) -> Result<PathBuf> {
    let mut result = PathBuf::from(encode_component(source));
    for (index, part) in relative_text(relative)?.split('/').enumerate() {
        // Reserve a namespace for unrepresentably long exported names.
        result.push(
            if index == 0 && part.eq_ignore_ascii_case("_KumadeLongPaths") {
                format!("%5F{}", &part[1..])
            } else {
                encode_component(part)
            },
        );
    }
    if let Some(stream) = stream {
        result.push(encode_component(stream));
    }
    // Leave headroom below conservative Windows maximum path limits.
    if result.as_os_str().len() > 240 {
        let original = relative_text(relative)?;
        let id = crate::model::sha256(
            format!("{source}\0{original}\0{}", stream.unwrap_or_default()).as_bytes(),
        );
        result = PathBuf::from(encode_component(source))
            .join("_KumadeLongPaths")
            .join(id);
    }
    Ok(result)
}

pub fn safe_join(root: &Path, relative: &str) -> Result<PathBuf> {
    if relative.is_empty()
        || relative.contains('\\')
        || relative.contains(':')
        || relative.starts_with('/')
    {
        bail!("Unsafe manifest path");
    }
    let p = Path::new(relative);
    if p.components().any(|c| !matches!(c, Component::Normal(_))) {
        bail!("Unsafe manifest path");
    }
    let candidate = root.join(p);
    if candidate.symlink_metadata()?.file_type().is_symlink() {
        bail!("Manifest payload is a symbolic link");
    }
    let canonical = crate::platform::canonicalize(&candidate)?;
    if !canonical.starts_with(crate::platform::canonicalize(root)?) {
        bail!("Manifest payload escapes the collection");
    }
    Ok(canonical)
}
