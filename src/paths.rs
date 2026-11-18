// Copyright (c) 2026 Shirofune Security Co., Ltd.
// SPDX-License-Identifier: RPL-1.5

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
    let mut result = ancestor.canonicalize()?;
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

pub fn output_relative(source: &str, relative: &Path, stream: Option<&str>) -> Result<PathBuf> {
    let mut result = PathBuf::from("Evidence")
        .join("Live")
        .join(encode_component(source));
    for part in relative_text(relative)?.split('/') {
        result.push(encode_component(part));
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
        result = PathBuf::from("Evidence")
            .join("LongPaths")
            .join(encode_component(source))
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
    let canonical = candidate.canonicalize()?;
    if !canonical.starts_with(root.canonicalize()?) {
        bail!("Manifest payload escapes the collection");
    }
    Ok(canonical)
}
