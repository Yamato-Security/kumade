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

use anyhow::{Context, Result, ensure};
use globset::{GlobBuilder, GlobMatcher};
use serde::{Deserialize, Serialize};
use std::collections::HashSet;

pub const DEFAULT_CATALOG: &str = include_str!("../artifacts/default.yaml");

#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(rename_all = "PascalCase", deny_unknown_fields)]
pub struct Definition {
    pub id: String,
    pub name: String,
    pub category: String,
    #[serde(default)]
    pub patterns: Vec<String>,
    #[serde(default)]
    pub profile_patterns: Vec<String>,
    #[serde(default)]
    pub raw_paths: Vec<String>,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(rename_all = "PascalCase", deny_unknown_fields)]
pub struct Catalog {
    pub schema_version: u32,
    pub artifacts: Vec<Definition>,
}

#[derive(Clone)]
pub struct Pattern {
    whole: GlobMatcher,
    parts: Vec<Option<GlobMatcher>>,
}

impl Pattern {
    pub fn new(value: &str) -> Result<Self> {
        ensure!(
            !value.starts_with('/')
                && !value.contains('\\')
                && !value.contains(':')
                && !value.split('/').any(|p| p == ".." || p.is_empty()),
            "Invalid catalog path: {value}"
        );
        fn compile(value: &str) -> Result<GlobMatcher> {
            Ok(GlobBuilder::new(value)
                .case_insensitive(true)
                .literal_separator(true)
                .build()?
                .compile_matcher())
        }
        let parts = value
            .split('/')
            .map(|p| {
                if p == "**" {
                    Ok(None)
                } else {
                    compile(p).map(Some)
                }
            })
            .collect::<Result<_>>()?;
        Ok(Self {
            whole: compile(value)?,
            parts,
        })
    }
    pub fn matches(&self, path: &str) -> bool {
        self.whole.is_match(path)
    }
    pub fn can_descend(&self, dir: &str) -> bool {
        let pieces: Vec<_> = dir.split('/').filter(|v| !v.is_empty()).collect();
        // NFA states avoid exponential recursion with repeated ** patterns.
        let mut states = HashSet::from([0]);
        for segment in pieces {
            let mut expanded = states.clone();
            for (i, part) in self.parts.iter().enumerate() {
                if expanded.contains(&i) && part.is_none() {
                    expanded.insert(i + 1);
                }
            }
            let mut next = HashSet::new();
            for i in expanded {
                match self.parts.get(i) {
                    Some(None) => {
                        next.insert(i);
                    }
                    Some(Some(m)) if m.is_match(segment) => {
                        next.insert(i + 1);
                    }
                    _ => {}
                }
            }
            if next.is_empty() {
                return false;
            }
            states = next;
        }
        !states.is_empty()
    }
}

pub struct Rules {
    pub catalog: Catalog,
    pub sha256: String,
    pub files: Vec<Vec<Pattern>>,
    pub profiles: Vec<Vec<Pattern>>,
}

impl Rules {
    pub fn load(text: &str) -> Result<Self> {
        let catalog: Catalog =
            serde_yaml_ng::from_str(text).context("Invalid acquisition catalog")?;
        ensure!(
            catalog.schema_version == 1,
            "Unsupported catalog schema version"
        );
        ensure!(!catalog.artifacts.is_empty(), "Catalog has no artifacts");
        let mut ids = HashSet::new();
        let mut files = Vec::new();
        let mut profiles = Vec::new();
        for d in &catalog.artifacts {
            ensure!(
                d.id.chars()
                    .all(|c| c.is_ascii_alphanumeric() || ".-_".contains(c)),
                "Artifact IDs must use ASCII letters, numbers, dot, dash or underscore"
            );
            ensure!(
                !d.id.is_empty() && ids.insert(d.id.clone()),
                "Empty or duplicate artifact ID: {}",
                d.id
            );
            ensure!(
                !d.patterns.is_empty() || !d.profile_patterns.is_empty() || !d.raw_paths.is_empty(),
                "Artifact {} has no selectors",
                d.id
            );
            files.push(
                d.patterns
                    .iter()
                    .map(|p| Pattern::new(p))
                    .collect::<Result<_>>()?,
            );
            profiles.push(
                d.profile_patterns
                    .iter()
                    .map(|p| Pattern::new(p))
                    .collect::<Result<_>>()?,
            );
            for p in &d.raw_paths {
                let (base, stream) = p
                    .rsplit_once(':')
                    .map(|(b, s)| (b, Some(s)))
                    .unwrap_or((p.as_str(), None));
                ensure!(
                    !p.starts_with('/')
                        && !p.contains('\\')
                        && !base.contains(':')
                        && !base.split('/').any(|s| s == ".." || s.is_empty())
                        && stream.is_none_or(|s| !s.is_empty() && !s.contains('/')),
                    "Invalid raw path"
                );
            }
        }
        Ok(Self {
            catalog,
            sha256: crate::model::sha256(text.as_bytes()),
            files,
            profiles,
        })
    }
    pub fn matching(&self, relative: &str, profile_relative: Option<&str>) -> Vec<usize> {
        self.files
            .iter()
            .zip(&self.profiles)
            .enumerate()
            .filter_map(|(i, (f, p))| {
                (f.iter().any(|m| m.matches(relative))
                    || profile_relative.is_some_and(|r| p.iter().any(|m| m.matches(r))))
                .then_some(i)
            })
            .collect()
    }
    pub fn can_descend(&self, relative: &str, profile_relative: Option<&str>) -> bool {
        self.can_descend_selected(relative, profile_relative, &[])
    }
    pub fn can_descend_selected(
        &self,
        relative: &str,
        profile_relative: Option<&str>,
        only: &[String],
    ) -> bool {
        let enabled = |i: usize| only.is_empty() || only.contains(&self.catalog.artifacts[i].id);
        self.files
            .iter()
            .enumerate()
            .filter(|(i, _)| enabled(*i))
            .flat_map(|(_, v)| v)
            .any(|m| m.can_descend(relative))
            || profile_relative.is_some_and(|r| {
                self.profiles
                    .iter()
                    .enumerate()
                    .filter(|(i, _)| enabled(*i))
                    .flat_map(|(_, v)| v)
                    .any(|m| m.can_descend(r))
            })
    }
}
