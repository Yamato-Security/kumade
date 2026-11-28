// Copyright (C) 2026 Shirofune Security Co., Ltd.
// SPDX-License-Identifier: RPL-1.5
//! Compressed Forge inputs. No ZIP member is ever extracted onto the filesystem.
use anyhow::{Context, Result, ensure};
use clap::{Args, ValueEnum};
use serde::{Deserialize, Serialize};
use std::{
    fs::{self, File},
    io::{Cursor, Read, Write},
    path::{Path, PathBuf},
    time::Duration,
};

const MAX_ARCHIVE: u64 = 64 * 1024 * 1024;
const MAX_RULES: u64 = 128 * 1024 * 1024;
#[derive(Clone, Copy, Debug, PartialEq, Eq, ValueEnum, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum RuleSet {
    Core,
    Extended,
    Full,
}
impl RuleSet {
    pub fn name(self) -> &'static str {
        match self {
            Self::Core => "core",
            Self::Extended => "extended",
            Self::Full => "full",
        }
    }
}
impl std::fmt::Display for RuleSet {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(self.name())
    }
}
impl Default for RuleSet {
    fn default() -> Self {
        match option_env!("KUMADE_BUNDLED_YARA_SET") {
            Some("extended") => Self::Extended,
            Some("full") => Self::Full,
            _ => Self::Core,
        }
    }
}
#[derive(Debug, Serialize)]
#[serde(rename_all = "PascalCase")]
pub struct Provenance {
    pub kind: String,
    pub ruleset: String,
    pub release: Option<String>,
    pub origin: String,
    #[serde(rename = "ArchiveSHA256")]
    pub archive_sha256: Option<String>,
    #[serde(rename = "RulesSHA256")]
    pub rules_sha256: String,
}
pub struct Loaded {
    pub source: String,
    pub provenance: Provenance,
}
pub(crate) fn read_bounded(mut reader: impl Read, limit: u64) -> Result<Vec<u8>> {
    let mut bytes = Vec::new();
    reader.by_ref().take(limit + 1).read_to_end(&mut bytes)?;
    ensure!(
        bytes.len() as u64 <= limit,
        "Rule download/source exceeds size limit"
    );
    Ok(bytes)
}
pub(crate) fn archive_source(bytes: impl AsRef<[u8]>, set: RuleSet) -> Result<Vec<u8>> {
    let bytes = bytes.as_ref();
    ensure!(
        bytes.len() as u64 <= MAX_ARCHIVE,
        "Forge ZIP exceeds size limit"
    );
    let mut zip = zip::ZipArchive::new(Cursor::new(bytes)).context("Invalid Forge ZIP")?;
    ensure!(zip.len() <= 1024, "Too many Forge archive entries");
    let expected = format!("packages/{}/yara-rules-{}.yar", set.name(), set.name());
    // Duplicates make by_name ambiguous. Multiple packs are not official Forge bundles.
    let mut count = 0;
    for i in 0..zip.len() {
        let file = zip.by_index_raw(i)?;
        if file.name()? == expected {
            count += 1;
        }
        for other in [RuleSet::Core, RuleSet::Extended, RuleSet::Full] {
            ensure!(
                other == set
                    || file.name()?
                        != format!("packages/{}/yara-rules-{}.yar", other.name(), other.name()),
                "ZIP contains multiple or a different Forge ruleset"
            );
        }
    }
    ensure!(
        count == 1,
        "Forge archive must contain exactly one expected rule member"
    );
    let file = zip.by_name(&expected)?;
    ensure!(
        !file.is_dir() && !file.is_symlink(),
        "Rule member must be a regular file"
    );
    ensure!(file.size() <= MAX_RULES, "Forge rule source is too large");
    read_bounded(file, MAX_RULES)
}
fn archive_set(bytes: &[u8]) -> Result<RuleSet> {
    let mut zip = zip::ZipArchive::new(Cursor::new(bytes)).context("Invalid Forge ZIP")?;
    ensure!(zip.len() <= 1024, "Too many Forge archive entries");
    let mut found = None;
    for set in [RuleSet::Core, RuleSet::Extended, RuleSet::Full] {
        let name = format!("packages/{}/yara-rules-{}.yar", set.name(), set.name());
        if zip.by_name(&name).is_ok() {
            ensure!(found.is_none(), "ZIP contains multiple Forge rulesets");
            found = Some(set);
        }
    }
    found.context("ZIP has no supported Forge rule member")
}
pub(crate) fn rule_url(set: RuleSet, release: &str) -> Result<String> {
    ensure!(
        release == "latest" || (release.len() == 8 && release.bytes().all(|b| b.is_ascii_digit())),
        "--rules-release must be latest or an eight-digit tag such as 20261122"
    );
    let base = if release == "latest" {
        "https://github.com/YARAHQ/yara-forge/releases/latest/download".into()
    } else {
        format!("https://github.com/YARAHQ/yara-forge/releases/download/{release}")
    };
    Ok(format!("{base}/yara-forge-rules-{}.zip", set.name()))
}
fn agent() -> ureq::Agent {
    ureq::Agent::config_builder()
        .https_only(true)
        .timeout_global(Some(Duration::from_secs(120)))
        .build()
        .into()
}
#[derive(Deserialize)]
struct Release {
    tag_name: String,
    assets: Vec<Asset>,
}
#[derive(Deserialize)]
struct Asset {
    name: String,
    size: u64,
    digest: Option<String>,
}
fn download(set: RuleSet, release: &str) -> Result<(Vec<u8>, String, String)> {
    rule_url(set, release)?;
    let path = if release == "latest" {
        "latest".into()
    } else {
        format!("tags/{release}")
    };
    let mut response = agent()
        .get(&format!(
            "https://api.github.com/repos/YARAHQ/yara-forge/releases/{path}"
        ))
        .header("User-Agent", "Kumade")
        .call()
        .context("Cannot resolve YARA Forge release")?;
    let metadata: Release =
        serde_json::from_slice(&read_bounded(response.body_mut().as_reader(), 1024 * 1024)?)?;
    ensure!(
        metadata.tag_name != "latest",
        "Forge release must resolve to a dated tag"
    );
    let url = rule_url(set, &metadata.tag_name)?;
    ensure!(
        release == "latest" || release == metadata.tag_name,
        "Forge release metadata differs from requested tag"
    );
    let name = format!("yara-forge-rules-{}.zip", set.name());
    let assets: Vec<_> = metadata.assets.iter().filter(|a| a.name == name).collect();
    ensure!(
        assets.len() == 1,
        "Forge package asset is missing or ambiguous"
    );
    let asset = assets[0];
    ensure!(asset.size <= MAX_ARCHIVE, "Forge ZIP exceeds size limit");
    let digest = asset
        .digest
        .as_deref()
        .and_then(|s| s.strip_prefix("sha256:"))
        .context("Forge asset has no SHA-256 digest")?;
    ensure!(
        digest.len() == 64 && digest.bytes().all(|b| b.is_ascii_hexdigit()),
        "Invalid Forge asset digest"
    );
    let mut response = agent()
        .get(&url)
        .call()
        .context("Cannot download Forge ZIP (use --rules for offline scanning)")?;
    let bytes = read_bounded(response.body_mut().as_reader(), MAX_ARCHIVE)?;
    ensure!(
        bytes.len() as u64 == asset.size,
        "Downloaded Forge ZIP size differs from release metadata"
    );
    ensure!(
        crate::model::sha256(&bytes).eq_ignore_ascii_case(digest),
        "Forge ZIP hash differs from release metadata"
    );
    archive_source(&bytes, set)?;
    Ok((bytes, metadata.tag_name, url))
}
fn from_archive(
    bytes: &[u8],
    set: RuleSet,
    release: Option<String>,
    kind: &str,
    origin: String,
) -> Result<Loaded> {
    let source = String::from_utf8(archive_source(bytes, set)?).context("Rules must be UTF-8")?;
    Ok(Loaded {
        provenance: Provenance {
            kind: kind.into(),
            ruleset: set.name().into(),
            release,
            origin,
            archive_sha256: Some(crate::model::sha256(bytes)),
            rules_sha256: crate::model::sha256(source.as_bytes()),
        },
        source,
    })
}
#[cfg(any(
    feature = "bundled-yara-core",
    feature = "bundled-yara-extended",
    feature = "bundled-yara-full"
))]
fn bundled() -> Option<(&'static [u8], &'static str, &'static str)> {
    Some((
        include_bytes!(concat!(env!("OUT_DIR"), "/yara-forge.zip")),
        env!("KUMADE_BUNDLED_YARA_RELEASE"),
        env!("KUMADE_BUNDLED_YARA_SHA256"),
    ))
}
#[cfg(not(any(
    feature = "bundled-yara-core",
    feature = "bundled-yara-extended",
    feature = "bundled-yara-full"
)))]
fn bundled() -> Option<(&'static [u8], &'static str, &'static str)> {
    None
}
pub(crate) fn has_bundle() -> bool {
    bundled().is_some()
}
pub fn bundle_description() -> String {
    match bundled() {
        Some((_, tag, hash)) => format!("{} / {} / SHA-256 {}", RuleSet::default(), tag, hash),
        None => "None; use a local ZIP or download rules".into(),
    }
}
/// Explicit local inputs take precedence; a matching embedded pack never uses the network.
pub fn load(path: Option<&Path>, set: RuleSet, release: &str) -> Result<Loaded> {
    rule_url(set, release)?;
    if let Some(path) = path {
        let bytes = read_bounded(
            File::open(path).context("Cannot open local rules")?,
            MAX_RULES,
        )?;
        let is_zip = path
            .extension()
            .is_some_and(|s| s.eq_ignore_ascii_case("zip"))
            || bytes.starts_with(b"PK\x03\x04");
        if is_zip {
            let set = archive_set(&bytes)?;
            return from_archive(&bytes, set, None, "LocalZip", path.display().to_string());
        }
        let source = String::from_utf8(bytes).context("Rules must be UTF-8")?;
        return Ok(Loaded {
            provenance: Provenance {
                kind: "LocalSource".into(),
                ruleset: "local".into(),
                release: None,
                origin: path.display().to_string(),
                archive_sha256: None,
                rules_sha256: crate::model::sha256(source.as_bytes()),
            },
            source,
        });
    }
    if let Some((bytes, tag, digest)) = bundled()
        && set == RuleSet::default()
        && (release == "latest" || release == tag)
    {
        ensure!(
            crate::model::sha256(bytes) == digest,
            "Embedded Forge ZIP hash differs"
        );
        return from_archive(
            bytes,
            set,
            Some(tag.into()),
            "BundledZip",
            format!("embedded:{}", set.name()),
        );
    }
    let (bytes, tag, url) = download(set, release)?;
    from_archive(&bytes, set, Some(tag), "DownloadedZip", url)
}
#[derive(Args, Debug)]
pub struct UpdateOptions {
    /// YARA Forge ruleset to download
    #[arg(long, value_enum, default_value_t)]
    pub ruleset: RuleSet,
    /// Forge release tag YYYYMMDD or latest
    #[arg(long, default_value = "latest")]
    pub rules_release: String,
    /// Destination for versioned ZIP files (default: same directory as this executable)
    #[arg(short, long, value_name = "DIR")]
    pub output: Option<PathBuf>,
    /// Suppress routine messages
    #[arg(short, long)]
    pub quiet: bool,
}
fn update_directory(output: Option<&Path>) -> Result<PathBuf> {
    match output {
        Some(path) => Ok(path.to_path_buf()),
        None => Ok(std::env::current_exe()?
            .parent()
            .context("Executable has no parent")?
            .to_path_buf()),
    }
}
pub fn update(options: &UpdateOptions) -> Result<u8> {
    let directory = update_directory(options.output.as_deref())?;
    if !options.quiet {
        crate::ui::banner();
        crate::ui::field("Ruleset", options.ruleset);
        crate::ui::status("Downloading and validating compressed YARA Forge rules…");
    }
    let (bytes, tag, url) = download(options.ruleset, &options.rules_release)?;
    // Compile before publishing an update. Failed updates never replace usable packs.
    let loaded = from_archive(
        &bytes,
        options.ruleset,
        Some(tag.clone()),
        "DownloadedZip",
        url,
    )?;
    crate::yara_scan::compile(&loaded.source, 60, 16)?;
    fs::create_dir_all(&directory)?;
    let path = directory.join(format!(
        "yara-forge-rules-{}-{tag}.zip",
        options.ruleset.name()
    ));
    persist_zip(&directory, &path, &bytes)?;
    if !options.quiet {
        crate::ui::field("Release", tag);
        crate::ui::field("Archive SHA-256", crate::model::sha256(&bytes));
        crate::ui::field("Results saved", path.display());
        crate::ui::field(
            "Use for collection",
            format!("--scan-processes --yara-rules \"{}\"", path.display()),
        );
        crate::ui::field(
            "Use for process scanning",
            format!("scan-processes --rules \"{}\" -o <RESULTS>", path.display()),
        );
    }
    Ok(0)
}
fn persist_zip(directory: &Path, path: &Path, bytes: &[u8]) -> Result<()> {
    let mut temporary = tempfile::NamedTempFile::new_in(directory)?;
    temporary.write_all(bytes)?;
    temporary.as_file().sync_all()?;
    match temporary.persist_noclobber(path) {
        Ok(_) => Ok(()),
        Err(error) if error.error.kind() == std::io::ErrorKind::AlreadyExists => {
            let existing = read_bounded(File::open(path)?, MAX_ARCHIVE)?;
            ensure!(
                existing == bytes,
                "An existing versioned ZIP has different contents; refusing overwrite"
            );
            Ok(())
        }
        Err(error) => Err(error.error.into()),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    fn fixture(set: RuleSet, extra: Option<(&str, &str)>) -> Vec<u8> {
        let mut writer = zip::ZipWriter::new(Cursor::new(Vec::new()));
        let options = zip::write::SimpleFileOptions::default()
            .compression_method(zip::CompressionMethod::Deflated);
        writer
            .start_file(
                format!("packages/{}/yara-rules-{}.yar", set.name(), set.name()),
                options,
            )
            .unwrap();
        writer
            .write_all(
                b"rule inert_zip_control { strings: $x=\"Kumade_Zip_Test_Control\" condition: $x }",
            )
            .unwrap();
        if let Some((name, data)) = extra {
            writer.start_file(name, options).unwrap();
            writer.write_all(data.as_bytes()).unwrap();
        }
        writer.finish().unwrap().into_inner()
    }
    #[test]
    fn zip_is_read_in_memory_and_archive_paths_are_never_extracted() {
        let temp = tempfile::tempdir().unwrap();
        let zip = temp.path().join("full.ZIP");
        fs::write(
            &zip,
            fixture(
                RuleSet::Full,
                Some(("../../unexpected.yar", "include \"secret.txt\"")),
            ),
        )
        .unwrap();
        let loaded = load(Some(&zip), RuleSet::Core, "latest").unwrap();
        assert_eq!(loaded.provenance.kind, "LocalZip");
        assert_eq!(loaded.provenance.ruleset, "full");
        assert_eq!(fs::read_dir(temp.path()).unwrap().count(), 1);
        let scanner = crate::yara_scan::compile(&loaded.source, 1, 1).unwrap();
        assert_eq!(
            scanner
                .scan_mem(b"Kumade_Zip_Test_Control")
                .unwrap()
                .rules
                .len(),
            1
        );
        assert!(archive_source(fixture(RuleSet::Core, None), RuleSet::Full).is_err());
    }
    #[test]
    fn mixed_packs_and_corrupt_members_are_rejected() {
        let bytes = fixture(
            RuleSet::Core,
            Some((
                "packages/full/yara-rules-full.yar",
                "rule b { condition: true }",
            )),
        );
        assert!(archive_set(&bytes).is_err());
        assert!(archive_source(bytes, RuleSet::Core).is_err());
        let mut bytes = fixture(RuleSet::Core, None);
        bytes.truncate(bytes.len() / 2);
        assert!(archive_source(bytes, RuleSet::Core).is_err());
    }
    #[test]
    fn updates_default_to_the_executable_directory_and_honor_explicit_output() {
        let executable = std::env::current_exe().unwrap();
        assert_eq!(
            update_directory(None).unwrap(),
            executable.parent().unwrap()
        );
        let explicit = Path::new("chosen-output-codex");
        assert_eq!(update_directory(Some(explicit)).unwrap(), explicit);
    }
    #[test]
    fn publishing_a_zip_is_idempotent_and_never_clobbers_different_contents() {
        let temp = tempfile::tempdir().unwrap();
        let p = temp.path().join("rules.zip");
        persist_zip(temp.path(), &p, b"original").unwrap();
        persist_zip(temp.path(), &p, b"original").unwrap();
        assert!(persist_zip(temp.path(), &p, b"changed").is_err());
        assert_eq!(fs::read(p).unwrap(), b"original");
        assert_eq!(fs::read_dir(temp.path()).unwrap().count(), 1);
    }
    #[cfg(any(
        feature = "bundled-yara-core",
        feature = "bundled-yara-extended",
        feature = "bundled-yara-full"
    ))]
    #[test]
    fn embedded_pack_loads_without_network_or_extraction_and_preserves_all_rules() {
        let loaded = load(None, RuleSet::default(), "latest").unwrap();
        assert_eq!(loaded.provenance.kind, "BundledZip");
        assert_eq!(
            loaded.provenance.release.as_deref(),
            Some(env!("KUMADE_BUNDLED_YARA_RELEASE"))
        );
        let expected: usize = loaded
            .source
            .lines()
            .find_map(|s| s.trim().strip_prefix("* Number of Rules: "))
            .unwrap()
            .parse()
            .unwrap();
        let scanner = crate::yara_scan::compile(&loaded.source, 60, 16).unwrap();
        assert_eq!(scanner.rules().count(), expected);
    }
}
