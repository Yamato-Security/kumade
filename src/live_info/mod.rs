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

//! Bounded, read-only live Windows inventory, separate from copied source artifacts.
use anyhow::{Context, Result, ensure};
use base64::{Engine, engine::general_purpose::STANDARD};
use rayon::prelude::*;
use serde::{Deserialize, Serialize};
use serde_json::{Map, Value, json};
use std::{
    fs::{self, OpenOptions},
    io::{Read, Write},
    path::{Path, PathBuf},
    process::{Command, Stdio},
    time::{Duration, Instant},
};

const LIMIT: usize = 32 * 1024 * 1024;
const ERROR_LIMIT: usize = 64 * 1024;
const ROW_LIMIT: usize = 100_000;
const COMMON: &str = include_str!("common.ps1");
const META: [&str; 3] = ["Computer", "CollectedUtc", "Provider"];

#[derive(Clone, Copy, Debug, Default, clap::ValueEnum, Serialize)]
#[serde(rename_all = "lowercase")]
pub enum Format {
    #[default]
    Csv,
    Json,
    Jsonl,
}
impl Format {
    fn extension(self) -> &'static str {
        match self {
            Self::Csv => "csv",
            Self::Json => "json",
            Self::Jsonl => "jsonl",
        }
    }
}
#[derive(Clone, Debug)]
pub struct Options {
    pub format: Format,
    pub threads: usize,
    pub timeout_seconds: u64,
    pub reserve_bytes: u64,
    pub quiet: bool,
    pub selected: Vec<String>,
    pub host_reserve: Option<crate::collect::HostReserve>,
}
impl Default for Options {
    fn default() -> Self {
        Self {
            format: Format::Csv,
            threads: 2,
            timeout_seconds: 90,
            reserve_bytes: 64 * 1024 * 1024,
            quiet: false,
            selected: Vec::new(),
            host_reserve: None,
        }
    }
}
#[derive(Clone, Deserialize)]
#[serde(rename_all = "PascalCase")]
pub struct Dataset {
    pub name: String,
    pub fields: Vec<String>,
    pub query: String,
    pub reference: String,
    pub helper: Option<String>,
}
pub fn datasets() -> Vec<Dataset> {
    serde_json::from_str(include_str!("datasets.json")).expect("embedded dataset catalog")
}
#[derive(Serialize, Deserialize, Debug)]
#[serde(rename_all = "PascalCase")]
pub struct Entry {
    pub provider: String,
    pub status: String,
    pub rows: usize,
    pub started_utc: String,
    pub finished_utc: String,
    pub elapsed_seconds: f64,
    pub output_file: String,
    pub bytes: u64,
    pub sha256: String,
    pub message: String,
}
pub struct Outcome {
    pub entries: Vec<Entry>,
    pub files: Vec<String>,
}
fn failure_count(entries: &[Entry]) -> u64 {
    let all_unsupported = !entries.is_empty() && entries.iter().all(|e| e.status == "Unsupported");
    entries
        .iter()
        .filter(|e| match e.status.as_str() {
            "Success" | "Empty" => false,
            "Unsupported" => {
                all_unsupported
                    || matches!(
                        e.provider.as_str(),
                        "HostInfo" | "OperatingSystem" | "Processes" | "IpConfiguration"
                    )
            }
            _ => true,
        })
        .count() as u64
}
impl Outcome {
    pub fn failures(&self) -> u64 {
        failure_count(&self.entries)
    }
}

struct Capture {
    stdout: Vec<u8>,
    stderr: Vec<u8>,
    success: bool,
    stop: Option<&'static str>,
}

fn script(dataset: &Dataset) -> String {
    // The query is compiled into the binary; callers can only select named providers.
    let helper = match dataset.helper.as_deref() {
        None => String::new(),
        Some("Locale") => {
            let query = match dataset.name.as_str() {
                "SystemLocale" => include_str!("locale/SystemLocale.ps1"),
                "CollectorLocale" => include_str!("locale/CollectorLocale.ps1"),
                "InputLanguages" => include_str!("locale/InputLanguages.ps1"),
                "KeyboardLayouts" => include_str!("locale/KeyboardLayouts.ps1"),
                "InstalledUiLanguages" => include_str!("locale/InstalledUiLanguages.ps1"),
                "LoadedUserKeyboardLayouts" => include_str!("locale/LoadedUserKeyboardLayouts.ps1"),
                "LoadedUserRegionalSettings" => {
                    include_str!("locale/LoadedUserRegionalSettings.ps1")
                }
                "LoadedUserLanguages" => include_str!("locale/LoadedUserLanguages.ps1"),
                "InputMethodEditors" => include_str!("locale/InputMethodEditors.ps1"),
                _ => panic!("unknown locale provider"),
            };
            format!(
                "{}\nfunction Read-LocaleInventory([string]$provider) {{\n{}\n}}",
                include_str!("locale.ps1"),
                query
            )
        }
        Some(_) => panic!("unknown embedded helper"),
    };
    format!(
        r#"{COMMON}
{helper}
try {{
 $count=0
 & {{ {} }} | ForEach-Object {{
   $count++;if($count -gt {ROW_LIMIT}){{throw 'Record limit exceeded'}}
   $record=[ordered]@{{Computer=[Environment]::MachineName;CollectedUtc=[DateTime]::UtcNow.ToString('o');Provider='{}'}}
   foreach($key in $_.Keys){{$record[$key]=$_[$key]}}
   [Console]::WriteLine((@{{Kind='Row';Data=$record}} | ConvertTo-Json -Compress -Depth 12))
 }}
 [Console]::WriteLine((@{{Kind='Complete';Rows=$count}} | ConvertTo-Json -Compress))
}} catch {{
 $status='Failed'
 if($_.Exception -is [Management.Automation.CommandNotFoundException] -or $_.FullyQualifiedErrorId -match 'InvalidNamespace|InvalidClass|0x8004100e|0x80041010'){{$status='Unsupported'}}
 [Console]::WriteLine((@{{Kind='Error';Status=$status;Message=$_.Exception.Message}} | ConvertTo-Json -Compress))
 exit 1
}}
"#,
        dataset.query, dataset.name
    )
}
fn encoded_script(script: &str) -> String {
    STANDARD.encode(
        script
            .encode_utf16()
            .flat_map(u16::to_le_bytes)
            .collect::<Vec<_>>(),
    )
}
fn drain(reader: impl Read, limit: usize) -> std::io::Result<Vec<u8>> {
    let mut b = Vec::new();
    reader.take(limit as u64 + 1).read_to_end(&mut b)?;
    Ok(b)
}
// A query may load a Windows provider that starts helper processes. Kill the
// whole owned process tree before joining pipe readers, even on normal exit.
#[cfg(windows)]
struct QueryJob(windows_sys::Win32::Foundation::HANDLE);
#[cfg(windows)]
impl QueryJob {
    fn new() -> Result<Self> {
        use windows_sys::Win32::System::JobObjects::*;
        // SAFETY: null security/name pointers request an unnamed owned job.
        let handle = unsafe { CreateJobObjectW(std::ptr::null(), std::ptr::null()) };
        ensure!(
            !handle.is_null(),
            "Cannot create a provider process job: {}",
            std::io::Error::last_os_error()
        );
        let job = Self(handle);
        let mut limits = JOBOBJECT_EXTENDED_LIMIT_INFORMATION::default();
        limits.BasicLimitInformation.LimitFlags = JOB_OBJECT_LIMIT_KILL_ON_JOB_CLOSE;
        // SAFETY: live owned job and a correctly sized, initialized limits structure.
        ensure!(
            // SAFETY: live owned job and a correctly sized initialized limits structure.
            unsafe {
                SetInformationJobObject(
                    handle,
                    JobObjectExtendedLimitInformation,
                    (&limits as *const JOBOBJECT_EXTENDED_LIMIT_INFORMATION).cast(),
                    std::mem::size_of_val(&limits) as u32,
                )
            } != 0,
            "Cannot set provider job limits: {}",
            std::io::Error::last_os_error()
        );
        Ok(job)
    }
    fn assign(&self, child: &std::process::Child) -> Result<()> {
        use std::os::windows::io::AsRawHandle;
        // SAFETY: the job and child handles remain live for this call.
        ensure!(
            // SAFETY: the job and child handles remain live for this call.
            unsafe {
                windows_sys::Win32::System::JobObjects::AssignProcessToJobObject(
                    self.0,
                    child.as_raw_handle(),
                )
            } != 0,
            "Cannot isolate the provider process: {}",
            std::io::Error::last_os_error()
        );
        Ok(())
    }
}
#[cfg(windows)]
impl Drop for QueryJob {
    fn drop(&mut self) {
        // SAFETY: this object uniquely owns the job handle; closing kills remaining members.
        unsafe {
            windows_sys::Win32::Foundation::CloseHandle(self.0);
        }
    }
}

fn execute(mut command: Command, timeout: Duration) -> Result<Capture> {
    #[cfg(windows)]
    let mut job = Some(QueryJob::new()?);
    let mut child = command
        .stdin(Stdio::null())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .context("Cannot start the built-in PowerShell provider")?;
    #[cfg(windows)]
    if let Err(error) = job.as_ref().expect("owned job").assign(&child) {
        let _ = child.kill();
        let _ = child.wait();
        return Err(error);
    }
    let out = child.stdout.take().context("Missing stdout pipe")?;
    let err = child.stderr.take().context("Missing stderr pipe")?;
    // Draining concurrently prevents either pipe from blocking the provider. Closing a
    // full pipe stops further output; the process is still subject to the deadline.
    let stdout = std::thread::spawn(move || drain(out, LIMIT));
    let stderr = std::thread::spawn(move || drain(err, ERROR_LIMIT));
    let start = Instant::now();
    let mut stop = None;
    let status = loop {
        match child.try_wait() {
            Ok(Some(s)) => break s,
            Ok(None) => {}
            Err(e) => {
                let _ = child.kill();
                let _ = child.wait();
                #[cfg(windows)]
                drop(job.take());
                let _ = stdout.join();
                let _ = stderr.join();
                return Err(e.into());
            }
        }
        if start.elapsed() >= timeout {
            stop = Some("TimedOut");
            let _ = child.kill();
            break child.wait()?;
        }
        std::thread::sleep(Duration::from_millis(25));
    };
    #[cfg(windows)]
    drop(job.take());
    let stdout = stdout
        .join()
        .map_err(|_| anyhow::anyhow!("Provider stdout reader panicked"))??;
    let stderr = stderr
        .join()
        .map_err(|_| anyhow::anyhow!("Provider stderr reader panicked"))??;
    if stdout.len() > LIMIT || stderr.len() > ERROR_LIMIT {
        stop = Some("OutputLimit")
    }
    Ok(Capture {
        stdout,
        stderr,
        success: status.success(),
        stop,
    })
}

fn parse(dataset: &Dataset, capture: Capture) -> (Vec<Value>, String, String) {
    let mut rows = Vec::new();
    let mut complete = false;
    let mut error = None;
    let mut expected = None;
    // Invalid UTF-8 or a cut final line is an error, rather than silent replacement.
    for bytes in capture
        .stdout
        .split(|b| *b == b'\n')
        .filter(|s| !s.iter().all(u8::is_ascii_whitespace))
    {
        let value: Value = match serde_json::from_slice(bytes) {
            Ok(v) => v,
            Err(e) => {
                error = Some(("Failed".into(), format!("Invalid provider JSON: {e}")));
                break;
            }
        };
        match value["Kind"].as_str() {
            Some("Row") if !complete && rows.len() < ROW_LIMIT => {
                let Some(object) = value["Data"].as_object() else {
                    error = Some(("Failed".into(), "Non-object provider row".into()));
                    break;
                };
                let mut normalized = Map::new();
                for key in META
                    .into_iter()
                    .map(String::from)
                    .chain(dataset.fields.clone())
                {
                    normalized.insert(
                        key.clone(),
                        object
                            .iter()
                            .find(|(k, _)| k.eq_ignore_ascii_case(&key))
                            .map(|(_, v)| v.clone())
                            .unwrap_or(Value::Null),
                    );
                }
                if normalized["Computer"].as_str().is_none()
                    || normalized["CollectedUtc"]
                        .as_str()
                        .and_then(|t| chrono::DateTime::parse_from_rfc3339(t).ok())
                        .is_none()
                    || normalized["Provider"] != dataset.name
                {
                    error = Some(("Failed".into(), "Missing or invalid row provenance".into()));
                    break;
                }
                rows.push(Value::Object(normalized));
            }
            Some("Complete") if !complete => {
                complete = true;
                expected = value["Rows"].as_u64()
            }
            Some("Error") => {
                let s = if value["Status"] == "Unsupported" {
                    "Unsupported"
                } else {
                    "Failed"
                };
                error = Some((
                    s.into(),
                    value["Message"]
                        .as_str()
                        .unwrap_or("Provider error")
                        .to_owned(),
                ));
                break;
            }
            _ => {
                error = Some((
                    "Failed".into(),
                    "Unexpected provider protocol record".into(),
                ));
                break;
            }
        }
    }
    let (mut status, message) = if let Some(stop) = capture.stop {
        (stop.to_owned(), format!("Provider stopped: {stop}"))
    } else if let Some(error) = error {
        error
    } else if !capture.success || !complete || expected != Some(rows.len() as u64) {
        (
            "Failed".into(),
            format!(
                "Provider did not finish cleanly: {}",
                String::from_utf8_lossy(&capture.stderr)
            ),
        )
    } else if rows.is_empty() {
        ("Empty".into(), String::new())
    } else {
        ("Success".into(), String::new())
    };
    if !rows.is_empty() && !matches!(status.as_str(), "Success" | "Empty") {
        status = "Partial".into()
    }
    (rows, status, message)
}
fn write_rows(path: &Path, dataset: &Dataset, rows: &[Value], format: Format) -> Result<()> {
    let file = OpenOptions::new().write(true).create_new(true).open(path)?;
    let mut out = std::io::BufWriter::new(file);
    match format {
        Format::Csv => {
            let mut csv = csv::Writer::from_writer(&mut out);
            let headers: Vec<_> = META
                .into_iter()
                .map(String::from)
                .chain(dataset.fields.clone())
                .collect();
            csv.write_record(&headers)?;
            for row in rows {
                csv.write_record(headers.iter().map(|k| match &row[k] {
                    Value::Null => String::new(),
                    Value::String(s) => s.clone(),
                    v => v.to_string(),
                }))?
            }
            csv.flush()?;
        }
        Format::Json => {
            serde_json::to_writer_pretty(&mut out, rows)?;
            out.write_all(b"\n")?
        }
        Format::Jsonl => {
            for row in rows {
                serde_json::to_writer(&mut out, row)?;
                out.write_all(b"\n")?
            }
        }
    }
    out.flush()?;
    out.get_ref().sync_all()?;
    Ok(())
}
#[cfg(windows)]
fn powershell() -> Result<PathBuf> {
    let mut buffer = [0u16; 260];
    // SAFETY: a writable buffer of the specified number of UTF-16 code units.
    let n = unsafe {
        windows_sys::Win32::System::SystemInformation::GetWindowsDirectoryW(
            buffer.as_mut_ptr(),
            buffer.len() as u32,
        )
    } as usize;
    ensure!(
        n > 0 && n < buffer.len(),
        "Cannot resolve the Windows directory"
    );
    let windows = PathBuf::from(String::from_utf16(&buffer[..n])?);
    for dir in ["Sysnative", "System32"] {
        let exe = windows
            .join(dir)
            .join("WindowsPowerShell/v1.0/powershell.exe");
        if exe.is_file() {
            return Ok(exe);
        }
    }
    anyhow::bail!("Windows PowerShell is unavailable")
}
#[cfg(not(windows))]
fn powershell() -> Result<PathBuf> {
    anyhow::bail!("Live response inventory requires Windows")
}

/// The embedded providers named by `selected` (case-insensitive), or all of them.
pub fn select(selected: &[String]) -> Result<Vec<Dataset>> {
    let mut specs = datasets();
    for name in selected {
        ensure!(
            specs.iter().any(|s| s.name.eq_ignore_ascii_case(name)),
            "Unknown live-info dataset: {name}"
        );
    }
    if !selected.is_empty() {
        specs.retain(|s| selected.iter().any(|n| s.name.eq_ignore_ascii_case(n)));
    }
    Ok(specs)
}

/// Write a new LiveInfo directory into an already protected collection root.
pub fn collect_into(root: &Path, options: &Options) -> Result<Outcome> {
    ensure!(cfg!(windows), "Live response inventory requires Windows");
    ensure!(
        (1..=8).contains(&options.threads),
        "Live-info workers must be in 1..=8"
    );
    ensure!(
        (1..=3600).contains(&options.timeout_seconds),
        "Live-info timeout must be in 1..=3600 seconds"
    );
    let specs = select(&options.selected)?;
    let exe = powershell();
    let directory = root.join("LiveInfo");
    fs::create_dir(&directory)?;
    let pool = rayon::ThreadPoolBuilder::new()
        .num_threads(options.threads)
        .build()?;
    if !options.quiet {
        crate::ui::status("Collecting live response inventory…")
    }
    let bar = (!options.quiet).then(|| crate::ui::progress_bar(specs.len() as u64, false)); // shared terminal styling
    let entries: Result<Vec<_>> = pool.install(|| {
        specs
            .par_iter()
            .map(|dataset| {
                let started = crate::model::utc_now();
                let timer = Instant::now();
                let result = (|| -> Result<_> {
                    ensure!(
                        fs2::available_space(&directory)?
                            >= options.reserve_bytes.saturating_add(2 * LIMIT as u64),
                        "Live-info destination free-space reserve reached"
                    );
                    if let Some(host) = &options.host_reserve {
                        ensure!(
                            fs2::available_space(&host.path)?
                                >= host.bytes.saturating_add(2 * LIMIT as u64),
                            "Live-info physical host free-space reserve reached"
                        );
                    }
                    let captured = (|| -> Result<Capture> {
                        let exe = exe.as_ref().map_err(|e| anyhow::anyhow!("{e:#}"))?;
                        let mut command = Command::new(exe);
                        command.args([
                            "-NoLogo",
                            "-NoProfile",
                            "-NonInteractive",
                            "-EncodedCommand",
                            &encoded_script(&script(dataset)),
                        ]);
                        execute(command, Duration::from_secs(options.timeout_seconds))
                    })();
                    let (rows, status, message) = match captured {
                        Ok(c) => parse(dataset, c),
                        Err(e) => (vec![], "Failed".into(), format!("{e:#}")),
                    };
                    let name = format!("{}.{}", dataset.name, options.format.extension());
                    let path = directory.join(&name);
                    write_rows(&path, dataset, &rows, options.format)?;
                    let (bytes, sha256) = crate::collect::hash_file(&path)?;
                    Ok(Entry {
                        provider: dataset.name.clone(),
                        status,
                        rows: rows.len(),
                        started_utc: started,
                        finished_utc: crate::model::utc_now(),
                        elapsed_seconds: timer.elapsed().as_secs_f64(),
                        output_file: format!("LiveInfo/{name}"),
                        bytes,
                        sha256,
                        message,
                    })
                })();
                if let Some(bar) = &bar {
                    bar.inc(1)
                }
                result
            })
            .collect()
    });
    if let Some(bar) = bar {
        bar.finish_and_clear()
    }
    let entries = entries?;
    crate::collect::write_json_new(
        &directory.join("Manifest.json"),
        &json!({"SchemaVersion":1,"SnapshotType":"NonAtomicLiveQueries","Entries":entries}),
    )?;
    let mut csv = csv::Writer::from_writer(
        OpenOptions::new()
            .write(true)
            .create_new(true)
            .open(directory.join("Manifest.csv"))?,
    );
    for entry in &entries {
        csv.serialize(entry)?
    }
    csv.flush()?;
    let mut files: Vec<_> = entries.iter().map(|e| e.output_file.clone()).collect();
    files.extend([
        "LiveInfo/Manifest.json".into(),
        "LiveInfo/Manifest.csv".into(),
    ]);
    let mut hashes = std::collections::BTreeMap::new();
    for file in &files {
        hashes.insert(file.clone(), crate::collect::hash_file(&root.join(file))?.1);
    }
    crate::collect::write_json_new(
        &directory.join("Seal.json"),
        &json!({"SchemaVersion":1,"FileSHA256":hashes,"Signature":"NotConfigured"}),
    )?;
    files.push("LiveInfo/Seal.json".into());
    Ok(Outcome { entries, files })
}

/// Verify the sealed live inventory, including every data table and manifest.
pub fn verify(root: &Path) -> Result<(usize, u64)> {
    let seal: Value = serde_json::from_reader(std::fs::File::open(crate::paths::safe_join(
        root,
        "LiveInfo/Seal.json",
    )?)?)?;
    ensure!(
        seal["SchemaVersion"] == 1,
        "Unsupported live-info seal schema"
    );
    let hashes = seal["FileSHA256"]
        .as_object()
        .context("Missing live-info hashes")?;
    for name in ["LiveInfo/Manifest.json", "LiveInfo/Manifest.csv"] {
        ensure!(
            hashes.contains_key(name),
            "Missing live-info manifest digest"
        );
    }
    for (name, expected) in hashes {
        ensure!(
            crate::collect::hash_file(&crate::paths::safe_join(root, name)?)?.1
                == expected.as_str().context("Invalid live-info hash")?,
            "Live-info hash differs: {name}"
        );
    }
    let manifest: Value = serde_json::from_reader(std::fs::File::open(crate::paths::safe_join(
        root,
        "LiveInfo/Manifest.json",
    )?)?)?;
    ensure!(
        manifest["SchemaVersion"] == 1,
        "Unsupported live-info manifest schema"
    );
    let entries: Vec<Entry> = serde_json::from_value(manifest["Entries"].clone())?;
    let mut seen = std::collections::HashSet::new();
    for entry in &entries {
        ensure!(seen.insert(&entry.provider), "Duplicate live-info provider");
        ensure!(
            entry.output_file.starts_with("LiveInfo/")
                && hashes.get(&entry.output_file).and_then(Value::as_str) == Some(&entry.sha256),
            "Unsealed live-info data file"
        );
        ensure!(
            fs::metadata(crate::paths::safe_join(root, &entry.output_file)?)?.len() == entry.bytes,
            "Live-info size differs"
        );
    }
    let failed = failure_count(&entries);
    Ok((entries.len(), failed))
}

#[cfg(test)]
mod tests {
    use super::*;
    fn capture(lines: Value) -> Capture {
        Capture {
            stdout: lines.to_string().into_bytes(),
            stderr: vec![],
            success: true,
            stop: None,
        }
    }
    fn specimen() -> (Dataset, Value) {
        let s = datasets().remove(0);
        let v = json!({"Kind":"Row","Data":{"Computer":"HOST","CollectedUtc":"2026-11-20T01:02:03.1234567Z","Provider":s.name,"Name":"Japanese 日本語\ncomma,quote\"","PartOfDomain":true,"TotalPhysicalMemory":123456789012345_u64}});
        (s, v)
    }
    #[test]
    fn schemas_and_scripts_are_bounded_read_only_and_unique() {
        let mut names = std::collections::HashSet::new();
        for s in datasets() {
            assert!(names.insert(s.name.clone()));
            assert!(s.name.chars().all(|c| c.is_ascii_alphanumeric()));
            let mut fields = std::collections::HashSet::new();
            for f in s.fields.iter().map(String::as_str).chain(META) {
                assert!(f.starts_with(char::is_uppercase));
                assert!(fields.insert(f));
            }
            assert!(
                s.reference.starts_with("https://docs.velociraptor.app/")
                    || s.reference.starts_with("https://learn.microsoft.com/")
            );
            assert!(!s.query.to_ascii_lowercase().contains("win32_product"));
            let script = script(&s);
            let lower = script.to_ascii_lowercase();
            for reserved in ["home", "pid", "host", "profile", "pshome", "codex_home"] {
                for (at, _) in lower.match_indices(&format!("${reserved}")) {
                    let rest = lower[at + reserved.len() + 1..].trim_start();
                    assert!(
                        !rest.starts_with('='),
                        "{} assigns reserved ${reserved}",
                        s.name
                    );
                }
            }
            let decoded = STANDARD.decode(encoded_script(&script)).unwrap();
            let units: Vec<_> = decoded
                .as_chunks::<2>()
                .0
                .iter()
                .map(|s| u16::from_le_bytes([s[0], s[1]]))
                .collect();
            assert_eq!(String::from_utf16(&units).unwrap(), script);
            // Windows' CreateProcess command-line limit includes base64 and arguments.
            assert!(encoded_script(&script).len() < 30_000);
        }
    }
    #[test]
    fn selection_is_case_insensitive_and_rejects_unknown_names() {
        assert_eq!(select(&[]).unwrap().len(), datasets().len());
        let picked = select(&["hostinfo".into(), "TCPConnections".into()]).unwrap();
        assert_eq!(
            picked.iter().map(|d| d.name.as_str()).collect::<Vec<_>>(),
            ["HostInfo", "TcpConnections"]
        );
        assert!(select(&["Nope".into()]).is_err());
    }
    #[test]
    fn missing_completion_invalid_json_and_provider_errors_never_look_empty() {
        let (s, v) = specimen();
        let (rows, status, _) = parse(&s, capture(v.clone()));
        assert_eq!(rows.len(), 1);
        assert_eq!(status, "Partial");
        let (_, status, _) = parse(&s, capture(json!({"Kind":"Complete","Rows":0})));
        assert_eq!(status, "Empty");
        let (_, status, _) = parse(&s, capture(json!({"Kind":"Complete","Rows":2})));
        assert_eq!(status, "Failed");
        let (_, status, _) = parse(
            &s,
            capture(json!({"Kind":"Error","Status":"Unsupported","Message":"invalid namespace"})),
        );
        assert_eq!(status, "Unsupported");
        let (_, status, _) = parse(
            &s,
            Capture {
                stdout: b"broken json".to_vec(),
                stderr: vec![],
                success: true,
                stop: None,
            },
        );
        assert_eq!(status, "Failed");
        for stop in ["TimedOut", "OutputLimit"] {
            let mut c = capture(v.clone());
            c.stop = Some(stop);
            let (_, status, message) = parse(&s, c);
            assert_eq!(status, "Partial");
            assert!(message.contains(stop));
        }
    }
    #[test]
    fn csv_json_jsonl_preserve_quotes_unicode_nulls_numbers_and_booleans() {
        let (s, v) = specimen();
        let mut c = capture(v);
        c.stdout
            .extend_from_slice(b"\n{\"Kind\":\"Complete\",\"Rows\":1}\n");
        let (rows, status, _) = parse(&s, c);
        assert_eq!(status, "Success");
        let temp = tempfile::tempdir().unwrap();
        for format in [Format::Csv, Format::Json, Format::Jsonl] {
            let path = temp.path().join(format.extension());
            write_rows(&path, &s, &rows, format).unwrap();
            match format {
                Format::Csv => {
                    let mut r = csv::Reader::from_path(&path).unwrap();
                    let names = r.headers().unwrap().clone();
                    let row = r.records().next().unwrap().unwrap();
                    let name = names.iter().position(|k| k == "Name").unwrap();
                    assert_eq!(row.get(name), rows[0]["Name"].as_str());
                }
                Format::Json => assert_eq!(
                    serde_json::from_reader::<_, Value>(std::fs::File::open(path).unwrap())
                        .unwrap(),
                    json!(rows)
                ),
                Format::Jsonl => assert_eq!(
                    serde_json::from_str::<Value>(std::fs::read_to_string(path).unwrap().trim())
                        .unwrap(),
                    rows[0]
                ),
            }
        }
    }
    #[test]
    fn provenance_is_required_and_schema_case_is_normalized() {
        let (s, mut row) = specimen();
        row["Data"]["Computer"] = Value::Null;
        let (_, status, _) = parse(&s, capture(row));
        assert_eq!(status, "Failed");
        let mut s = s;
        s.fields = vec!["IpAddress".into()];
        let row = json!({"Kind":"Row","Data":{"Computer":"HOST","CollectedUtc":"2026-11-20T01:02:03Z","Provider":s.name,"IPAddress":["::1","127.0.0.1"]}});
        let (rows, _, _) = parse(&s, capture(row));
        assert_eq!(rows[0]["IpAddress"], json!(["::1", "127.0.0.1"]));
    }
    #[cfg(windows)]
    #[test]
    fn keyboard_substitution_chains_cycles_and_invalid_ids_are_reported() {
        let name = format!("KumadeLocaleTest-{}", uuid::Uuid::new_v4());
        let body = format!(
            r#"{}
$path='HKCU:\Software\{}'
$key=New-Item -Path $path -ErrorAction Stop
try {{
 $key.SetValue('d0010404','00000411',[Microsoft.Win32.RegistryValueKind]::String)
 $resolved=Resolve-KeyboardLayout $key 'D0010404'
 $key.SetValue('00000411','d0010404',[Microsoft.Win32.RegistryValueKind]::String)
 $cycle=Resolve-KeyboardLayout $key 'd0010404'
 $invalid=Resolve-KeyboardLayout $key '../../not-a-layout'
 for($i=0;$i -lt 20;$i++){{$key.SetValue(('D{{0:X7}}' -f $i),('D{{0:X7}}' -f ($i+1)),[Microsoft.Win32.RegistryValueKind]::String)}}
 $deep=Resolve-KeyboardLayout $key 'D0000000'
 [Console]::WriteLine((@{{Resolved=$resolved;Cycle=$cycle;Invalid=$invalid;Deep=$deep}} | ConvertTo-Json -Compress -Depth 8))
}} finally {{ $key.Close();Remove-Item -LiteralPath $path -Recurse -Force }}
"#,
            include_str!("locale.ps1"),
            name
        );
        let mut command = Command::new(powershell().unwrap());
        command.args([
            "-NoProfile",
            "-NonInteractive",
            "-EncodedCommand",
            &encoded_script(&body),
        ]);
        // This checks locale semantics, not launch performance. A cold native
        // PowerShell start on the loaded x86 runner can exceed 30 seconds.
        // Use the normal provider deadline and retain diagnostics on failure.
        let capture = execute(command, Duration::from_secs(90)).unwrap();
        assert!(
            capture.success,
            "stop={:?}; stdout={}; stderr={}",
            capture.stop,
            String::from_utf8_lossy(&capture.stdout),
            String::from_utf8_lossy(&capture.stderr)
        );
        let value: Value = serde_json::from_slice(&capture.stdout).unwrap();
        assert_eq!(value["Resolved"]["LayoutId"], "00000411");
        assert_eq!(value["Resolved"]["State"], "Substituted");
        assert_eq!(value["Cycle"]["State"], "SubstitutionCycle");
        assert_eq!(value["Invalid"]["State"], "InvalidLayoutId");
        assert_eq!(value["Deep"]["State"], "DepthLimit");
    }
    #[cfg(windows)]
    #[test]
    fn deadline_terminates_provider_descendants() {
        // The provider has to start a second PowerShell and print its PID before
        // the deadline fires. Cold starts on a loaded runner (the x86 build in
        // particular, with other tests spawning PowerShell at the same time) have
        // taken longer than 5 s, which left stdout empty and nothing to check.
        // The deadline therefore grows until the PID arrives; the termination
        // check itself is the same at every step.
        let script = r#"$c=Start-Process -FilePath ($PSHOME+'\powershell.exe') -ArgumentList '-NoProfile -NonInteractive -Command Start-Sleep -Seconds 300' -PassThru; [Console]::WriteLine($c.Id); Start-Sleep -Seconds 300"#;
        let mut reported = None;
        for seconds in [5, 15, 45] {
            let mut command = Command::new(powershell().unwrap());
            command.args([
                "-NoProfile",
                "-NonInteractive",
                "-EncodedCommand",
                &encoded_script(script),
            ]);
            let capture = execute(command, Duration::from_secs(seconds)).unwrap();
            assert_eq!(capture.stop, Some("TimedOut"));
            let stdout = String::from_utf8(capture.stdout).unwrap();
            if !stdout.trim().is_empty() {
                eprintln!("helper PID reported within a {seconds} s deadline");
                reported = Some(stdout.trim().parse::<u32>().expect("helper PID"));
                break;
            }
        }
        let id = reported.expect("helper never reported its child PID within 45 s");
        use windows_sys::Win32::{Foundation::*, System::Threading::*};
        // SAFETY: querying/waiting on a process ID returned by the test's own provider.
        let handle = unsafe {
            OpenProcess(
                PROCESS_SYNCHRONIZE | PROCESS_QUERY_LIMITED_INFORMATION,
                0,
                id,
            )
        };
        if !handle.is_null() {
            // SAFETY: live process handle with SYNCHRONIZE access.
            let result = unsafe { WaitForSingleObject(handle, 5000) };
            // SAFETY: the test uniquely owns this process handle.
            unsafe {
                CloseHandle(handle);
            }
            assert_eq!(
                result, WAIT_OBJECT_0,
                "provider child survived the deadline"
            );
        }
    }
    #[cfg(unix)]
    #[test]
    fn provider_deadline_kills_a_stalled_process() {
        let mut cmd = Command::new("/bin/sh");
        cmd.args(["-c", "exec sleep 10"]);
        let start = Instant::now();
        let c = execute(cmd, Duration::from_millis(100)).unwrap();
        assert_eq!(c.stop, Some("TimedOut"));
        assert!(start.elapsed() < Duration::from_secs(3));
    }
}
