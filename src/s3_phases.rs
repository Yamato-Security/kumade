// Copyright (C) 2026 Shirofune Security Co., Ltd.
// SPDX-License-Identifier: RPL-1.5

//! Stage evidence in a protected S3 workspace. Uploaders only read sealed
//! phase plans; resuming a delivery never calls a live acquisition provider.
use crate::{
    collect,
    early::Capture,
    model::{Record, Source, Summary, hex, sha256, utc_now},
    paths, platform,
    s3::{Bucket, ConnectionArgs, Location, S3Args, VerifyArgs},
    sftp_verify::{MAX_METADATA, relative},
    ui,
};
use anyhow::{Context, Result, ensure};
use serde::{Deserialize, Serialize, de::DeserializeOwned};
use sha2::{Digest, Sha256};
use std::{
    collections::{HashMap, HashSet},
    fs::{self, File, OpenOptions},
    io::{self, BufRead, BufReader, Read, Write},
    path::{Path, PathBuf},
    sync::mpsc,
    thread::{self, JoinHandle},
};
use uuid::Uuid;

#[path = "s3_hybrid.rs"]
pub(crate) mod hybrid;

const PHASES: [&str; 5] = ["live", "memory", "hot-disk", "recovered-disk", "collection"];

#[derive(clap::Args)]
pub struct ResumeArgs {
    /// Protected run workspace printed by collect
    #[arg(long)]
    pub workspace: PathBuf,
    /// Original s3://BUCKET/PREFIX supplied to collect
    #[arg(long)]
    pub s3: Location,
    #[command(flatten)]
    pub connection: ConnectionArgs,
}

#[derive(Serialize, Deserialize)]
#[serde(rename_all = "PascalCase")]
struct Session {
    id: Uuid,
    computer: String,
    started_utc: String,
    parent_uri: String,
    endpoint: Option<String>,
    region: String,
    part_mib: u16,
    #[serde(default)]
    hybrid: bool,
}
impl Session {
    fn location(&self, parent: &Location) -> Result<Location> {
        let folder = paths::run_name(&self.computer, &self.started_utc)?.replace('#', "%23");
        format!(
            "{}/{folder}_{}/",
            parent.uri().trim_end_matches('/'),
            self.id
        )
        .parse()
    }
    fn check_destination(&self, parent: &Location, connection: &ConnectionArgs) -> Result<()> {
        ensure!(
            self.parent_uri == parent.uri()
                && self.endpoint.as_deref() == connection.s3_endpoint.as_ref().map(|u| u.as_str()),
            "Supply the original S3 destination and endpoint"
        );
        ensure!(
            connection
                .s3_region
                .as_ref()
                .is_none_or(|r| r == &self.region),
            "S3 region differs from the original run"
        );
        ensure!(
            (5..=256).contains(&self.part_mib),
            "Invalid recovery part size"
        );
        Ok(())
    }
}

#[derive(Clone, Deserialize, Serialize)]
#[serde(rename_all = "PascalCase")]
struct Entry {
    path: String,
    bytes: u64,
    sha256: String,
}
#[derive(Deserialize, Serialize)]
#[serde(rename_all = "PascalCase")]
struct Plan {
    directory: String,
    partial: bool,
    files: Vec<Entry>,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    observations: Vec<Record>,
}
#[derive(Deserialize, Serialize)]
#[serde(rename_all = "PascalCase")]
struct Member {
    #[serde(flatten)]
    file: Entry,
    chunks: Vec<Chunk>,
}
#[derive(Deserialize, Serialize)]
#[serde(rename_all = "PascalCase")]
struct Manifest {
    kind: String,
    session: Uuid,
    phase: String,
    computer: String,
    started_utc: String,
    partial: bool,
    files: Vec<Member>,
    observations: Vec<Record>,
}
#[derive(Deserialize, Serialize)]
#[serde(rename_all = "PascalCase")]
struct Published {
    name: String,
    sha256: String,
    partial: bool,
}
#[derive(Deserialize, Serialize)]
#[serde(rename_all = "PascalCase")]
struct Chunk {
    sha256: String,
    bytes: u64,
    key: String,
}

fn digest_valid(s: &str) -> bool {
    s.len() == 64
        && s.bytes()
            .all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(&b))
}
fn json<T: DeserializeOwned>(path: &Path) -> Result<T> {
    ensure!(
        path.symlink_metadata()?.is_file() && !platform::is_reparse_directory(path),
        "Unsafe recovery metadata"
    );
    Ok(serde_json::from_reader(BufReader::new(File::open(path)?))?)
}
fn save(path: &Path, value: &impl Serialize) -> Result<()> {
    let parent = path.parent().context("Missing metadata parent")?;
    let mut tmp = tempfile::NamedTempFile::new_in(parent)?;
    {
        let mut writer = std::io::BufWriter::new(tmp.as_file_mut());
        serde_json::to_writer(&mut writer, value)?;
        writer.flush()?;
    }
    tmp.as_file().sync_all()?;
    tmp.persist_noclobber(path)?;
    #[cfg(unix)]
    File::open(parent)?.sync_all()?;
    Ok(())
}
fn staged_file(root: &Path, name: &str) -> Result<File> {
    relative(name)?;
    let path = paths::safe_join(root, name)?;
    let input = platform::open_source(&path)?;
    ensure!(
        input.metadata()?.is_file(),
        "Expected a staged regular file"
    );
    platform::validate_open_file(&input, root)?;
    Ok(input)
}
fn sealed_entry(root: &Path, name: &str, digest: &str) -> Result<Entry> {
    ensure!(digest_valid(digest), "Invalid seal digest for {name}");
    Ok(Entry {
        path: name.into(),
        bytes: staged_file(root, name)?.metadata()?.len(),
        sha256: digest.into(),
    })
}
fn sealed_json<T: DeserializeOwned>(root: &Path, entry: &Entry) -> Result<T> {
    ensure!(entry.bytes <= MAX_METADATA, "Oversized sealed metadata");
    let mut data = Vec::new();
    staged_file(root, &entry.path)?
        .take(entry.bytes + 1)
        .read_to_end(&mut data)?;
    ensure!(
        data.len() as u64 == entry.bytes && sha256(&data) == entry.sha256,
        "Staged metadata changed: {}",
        entry.path
    );
    Ok(serde_json::from_slice(&data)?)
}

// The same sealed inputs produce these plans after a process restart. No
// provider is called and an interrupted, unsealed capture is never published.
fn volatile_plans(
    workspace: &Path,
    root: &Path,
    computer: &str,
    seal_hash: &str,
    mut queue: impl FnMut(&str, &Plan) -> Result<()>,
) -> Result<()> {
    let directory = folder(workspace, root)?;
    let seal: serde_json::Value = sealed_json(root, &sealed_entry(root, "Seal.json", seal_hash)?)?;
    ensure!(
        seal["Kind"] == "KumadeEarlyVolatile"
            && seal["SchemaVersion"] == 1
            && seal["Computer"] == computer,
        "Unexpected early seal"
    );
    let hashes = seal["Hashes"]
        .as_object()
        .context("Missing early evidence inventory")?;
    if let Some(hash) = hashes.get("LiveInfo/Seal.json") {
        let live_seal = sealed_entry(
            root,
            "LiveInfo/Seal.json",
            hash.as_str().context("Invalid live seal")?,
        )?;
        let index: serde_json::Value = sealed_json(root, &live_seal)?;
        let mut files = vec![];
        for (name, hash) in index["FileSHA256"]
            .as_object()
            .context("Missing live inventory")?
        {
            ensure!(name.starts_with("LiveInfo/"), "File outside live phase");
            files.push(sealed_entry(
                root,
                name,
                hash.as_str().context("Invalid live hash")?,
            )?);
        }
        let manifest = files
            .iter()
            .find(|f| f.path == "LiveInfo/Manifest.json")
            .context("Missing live manifest")?;
        let mut meta: serde_json::Value = sealed_json(root, manifest)?;
        let entries = serde_json::from_value(meta["Entries"].take())?;
        let info = crate::live_info::Outcome {
            entries,
            files: vec![],
        };
        files.push(live_seal);
        queue(
            "live",
            &Plan {
                directory: directory.clone(),
                files,
                partial: info.failures() > 0,
                observations: vec![],
            },
        )?;
    }
    let request = sealed_entry(
        root,
        "MemoryRequest.json",
        seal["Hashes"]["MemoryRequest.json"]
            .as_str()
            .context("Missing memory request hash")?,
    )?;
    if let Some(row) = sealed_json::<Option<Record>>(root, &request)? {
        let mut files = vec![request];
        let mut rows = vec![row];
        for (name, hash) in hashes.iter().filter(|(n, _)| n.starts_with("Memory/")) {
            let entry = sealed_entry(root, name, hash.as_str().context("Invalid memory hash")?)?;
            if name == crate::pagefile::INVENTORY {
                rows.extend(sealed_json::<Vec<Record>>(root, &entry)?);
            }
            files.push(entry);
        }
        for (name, (bytes, hash)) in recorded(&rows)? {
            ensure!(
                files
                    .iter()
                    .any(|e| e.path == name && e.bytes == bytes && e.sha256 == hash),
                "RAM or pagefile differs from capture: {name}"
            );
        }
        queue(
            "memory",
            &Plan {
                directory,
                files,
                partial: rows.iter().any(|r| r.status != "Acquired"),
                observations: rows,
            },
        )?;
    }
    Ok(())
}
fn recorded(rows: &[Record]) -> Result<HashMap<String, (u64, String)>> {
    let mut known = HashMap::new();
    for row in rows {
        if let (Some(path), Some(hash)) = (&row.relative_output_path, &row.sha256) {
            ensure!(digest_valid(hash), "Invalid staged acquisition hash");
            ensure!(
                known
                    .insert(path.clone(), (row.bytes_read, hash.clone()))
                    .is_none(),
                "Duplicate staged observation path"
            );
        }
    }
    Ok(known)
}
fn folder(workspace: &Path, root: &Path) -> Result<String> {
    let name = paths::relative_text(root.strip_prefix(workspace)?)?;
    ensure!(relative(&name)?.len() == 1, "Invalid phase source root");
    Ok(name)
}

fn collection_plan(workspace: &Path, root: &Path, summary: &Summary) -> Result<Plan> {
    let rows: Vec<Record> = BufReader::new(File::open(root.join("Manifest.jsonl"))?)
        .lines()
        .map(|s| Ok(serde_json::from_str(&s?)?))
        .collect::<Result<_>>()?;
    let mut known = recorded(&rows)?;
    let seal: serde_json::Value = json(&root.join("Seal.json"))?;
    for (name, hash) in seal["MetadataSHA256"]
        .as_object()
        .context("Invalid local collection seal")?
    {
        known.insert(
            name.clone(),
            (
                staged_file(root, name)?.metadata()?.len(),
                hash.as_str().context("Invalid sealed hash")?.into(),
            ),
        );
    }
    known.insert(
        "Seal.json".into(),
        collect::hash_file(&root.join("Seal.json"))?,
    );
    let mut files: Vec<_> = known
        .into_iter()
        .map(|(path, (bytes, sha256))| Entry {
            path,
            bytes,
            sha256,
        })
        .collect();
    files.sort_by(|a, b| a.path.cmp(&b.path));
    let plan = Plan {
        directory: folder(workspace, root)?,
        partial: summary.completeness == "Partial",
        files,
        observations: vec![],
    };
    Ok(plan)
}
pub struct Run {
    computer: String,
    pub(crate) disk: Option<hybrid::Disk>,
    _acquisition_lock: File,
    root: PathBuf,
    signal: Option<mpsc::Sender<()>>,
    worker: Option<JoinHandle<Result<()>>>,
}
impl Run {
    pub fn workspace(&self) -> &Path {
        &self.root
    }
    pub fn start(args: &S3Args, parent: &Path, sources: &[Source], started: &str) -> Result<Self> {
        ensure!(
            parent.is_dir(),
            "The S3 workspace requires an existing protected destination"
        );
        for source in sources {
            ensure!(
                !parent.starts_with(&source.root),
                "Recovery storage must be outside the evidence source. Use --s3-hybrid-dir or --s3-recovery-dir on a separate destination, or select --s3-direct."
            );
            #[cfg(windows)]
            if source.live
                && let Some(vol) = platform::volume_identity(parent)?
            {
                ensure!(
                    Some(vol) != platform::volume_identity(&source.root)?,
                    "Use --s3-hybrid-dir or --s3-recovery-dir on a separate volume, or select --s3-direct."
                );
            }
        }
        let dest = args.s3.as_ref().context("Missing S3 destination")?.clone();
        let id = Uuid::new_v4();
        let root = parent.join(format!("kumade-recovery-{id}"));
        fs::create_dir(&root).with_context(|| {
            format!(
                "Cannot create S3 workspace in {}. Choose a writable evidence directory.",
                parent.display()
            )
        })?;
        ensure!(
            platform::protect_output_root(&root)? != "FilesystemHasNoPersistentACLs",
            "Recovery storage must support access controls"
        );
        let region = args
            .connection
            .s3_region
            .clone()
            .or_else(|| std::env::var("AWS_REGION").ok())
            .or_else(|| std::env::var("AWS_DEFAULT_REGION").ok())
            .unwrap_or_else(|| "us-east-1".into());
        let session = Session {
            id,
            computer: sources.first().context("Missing source")?.computer.clone(),
            started_utc: started.into(),
            parent_uri: dest.uri(),
            endpoint: args
                .connection
                .s3_endpoint
                .as_ref()
                .map(ToString::to_string),
            region,
            part_mib: args.s3_part_mib.unwrap_or(8),
            hybrid: args.s3_recovery_dir.is_none(),
        };
        save(&root.join("Session.json"), &session)?;
        ui::field("S3 recovery workspace", root.display());
        let acquisition_lock = File::create_new(root.join("Acquisition.lock"))?;
        fs2::FileExt::try_lock_exclusive(&acquisition_lock)?;
        let upload_lock = File::create_new(root.join("Upload.lock"))?;
        drop(upload_lock);
        let (tx, rx) = mpsc::channel();
        let workspace = root.clone();
        let connection = args.connection.clone();
        let disk = if session.hybrid {
            ui::field(
                "S3 hybrid mode",
                "Volatile evidence retained here; disk files stream directly to S3",
            );
            Some(hybrid::Disk::open(&root, &session, &dest, &connection)?)
        } else {
            None
        };
        let worker = thread::spawn(move || {
            let result = (|| -> Result<()> {
                let mut uploader = Uploader::open(&workspace, &dest, &connection)?;
                for () in rx {
                    uploader.publish_available()?;
                }
                Ok(())
            })();
            if let Err(error) = &result {
                eprintln!(
                    "S3 upload paused: {error:#}. Acquisition continues in {}",
                    workspace.display()
                );
            }
            result
        });
        Ok(Self {
            computer: session.computer,
            disk,
            _acquisition_lock: acquisition_lock,
            root,
            signal: Some(tx),
            worker: Some(worker),
        })
    }
    fn queue(&self, scope: &str, plan: &Plan) -> Result<()> {
        save(&self.root.join(format!("{scope}-plan.json")), plan)?;
        // Failure of the delivery worker must never stop acquisition.
        if let Some(tx) = &self.signal {
            let _ = tx.send(());
        }
        Ok(())
    }
    pub fn volatile(&self, capture: &Capture) -> Result<()> {
        volatile_plans(
            &self.root,
            capture.path(),
            &self.computer,
            capture.seal_hash(),
            |scope, plan| self.queue(scope, plan),
        )
    }
    pub fn hot_disk(&self, root: &Path, rows: &[Record], discovery_failed: bool) -> Result<()> {
        let rows: Vec<_> = rows
            .iter()
            .filter(|r| r.source_id != "Memory")
            .cloned()
            .collect();
        let files = recorded(&rows)?
            .into_iter()
            .map(|(path, (bytes, sha256))| Entry {
                path,
                bytes,
                sha256,
            })
            .collect();
        self.queue(
            "hot-disk",
            &Plan {
                directory: folder(&self.root, root)?,
                partial: discovery_failed
                    || rows
                        .iter()
                        .any(|r| matches!(r.status.as_str(), "Partial" | "Failed")),
                files,
                observations: rows,
            },
        )
    }
    pub fn complete(mut self, root: &Path, summary: &Summary) -> Result<()> {
        self.queue("collection", &collection_plan(&self.root, root, summary)?)?;
        self.join()
    }
    fn join(&mut self) -> Result<()> {
        self.signal.take();
        self.worker
            .take()
            .context("Missing upload worker")?
            .join()
            .map_err(|_| anyhow::anyhow!("S3 upload worker stopped"))?
    }
}
impl Drop for Run {
    fn drop(&mut self) {
        if self.worker.is_some()
            && let Err(e) = self.join()
        {
            eprintln!("S3 upload interrupted: {e:#}");
        }
    }
}

fn open_lock(root: &Path, name: &str) -> Result<File> {
    let file = OpenOptions::new()
        .read(true)
        .write(true)
        .open(paths::safe_join(root, name)?)?;
    platform::validate_open_file(&file, root)?;
    Ok(file)
}
struct Uploader {
    root: PathBuf,
    session: Session,
    location: Location,
    bucket: Bucket,
    _lock: File,
    log: File,
    uploaded: HashMap<String, (u64, String)>,
}
impl Uploader {
    fn open(root: &Path, parent: &Location, connection: &ConnectionArgs) -> Result<Self> {
        let root = platform::canonicalize(root)?;
        let session: Session = json(&root.join("Session.json"))?;
        session.check_destination(parent, connection)?;
        let lock = open_lock(&root, "Upload.lock")?;
        fs2::FileExt::try_lock_exclusive(&lock)
            .context("Another uploader owns this recovery workspace")?;
        let location = session.location(parent)?;
        let mut connection = connection.clone();
        connection.s3_region = Some(session.region.clone());
        let bucket = Bucket::connect(
            location.clone(),
            &connection,
            usize::from(session.part_mib) << 20,
            true,
        )?;
        // A terminated writer may leave a torn last line. Leave that journal
        // untouched and append into a fresh, exclusively created segment.
        let mut uploaded = HashMap::new();
        for entry in fs::read_dir(&root)? {
            let entry = entry?;
            let file = entry.file_name();
            let Some(name) = file.to_str() else { continue };
            if !name.starts_with("Uploaded-") || !name.ends_with(".jsonl") {
                continue;
            }
            let mut reader = BufReader::new(staged_file(&root, name)?);
            let mut line = Vec::new();
            loop {
                line.clear();
                if reader.by_ref().take(4097).read_until(b'\n', &mut line)? == 0 {
                    break;
                }
                ensure!(line.len() <= 4096, "Invalid upload journal record length");
                if !line.ends_with(b"\n") {
                    break;
                }
                let row: Chunk = serde_json::from_slice(&line)?;
                validate_key(session.id, &row.key)?;
                ensure!(digest_valid(&row.sha256), "Invalid upload journal digest");
                if let Some((size, key)) = uploaded.insert(row.sha256, (row.bytes, row.key.clone()))
                {
                    ensure!(
                        size == row.bytes && key == row.key,
                        "Conflicting acknowledged objects"
                    );
                }
            }
        }
        let log = File::create_new(root.join(format!("Uploaded-{}.jsonl", Uuid::new_v4())))?;
        Ok(Self {
            root,
            session,
            location,
            bucket,
            _lock: lock,
            log,
            uploaded,
        })
    }
    fn cached_chunk(&self, hash: &str, size: u64) -> Result<Option<Chunk>> {
        self.uploaded
            .get(hash)
            .map(|(bytes, key)| {
                ensure!(*bytes == size, "Conflicting acknowledged chunk size");
                Ok(Chunk {
                    sha256: hash.into(),
                    bytes: size,
                    key: key.clone(),
                })
            })
            .transpose()
    }
    fn upload_chunk(&mut self, data: Vec<u8>) -> Result<Chunk> {
        let bytes = data.len() as u64;
        let digest = sha256(&data);
        if let Some(chunk) = self.cached_chunk(&digest, bytes)? {
            return Ok(chunk);
        }
        // Allocate a fresh immutable key on each attempt. A lost acknowledgement
        // can leave an orphan, but can never substitute another writer's bytes.
        let chunk = store_chunk(&self.bucket, &self.location, self.session.id, data, digest)?;
        let mut line = serde_json::to_vec(&chunk)?;
        line.push(b'\n');
        self.log.write_all(&line)?;
        self.log.sync_data()?;
        self.uploaded
            .insert(chunk.sha256.clone(), (chunk.bytes, chunk.key.clone()));
        Ok(chunk)
    }
    fn member(&mut self, dir: &Path, file: Entry) -> Result<Member> {
        relative(&file.path)?;
        if self.session.hybrid
            && let Some(ack) = hybrid::acknowledged(&self.root, self.session.id, &file)?
        {
            return Ok(ack);
        }
        ensure!(digest_valid(&file.sha256), "Invalid staged hash");
        let chunk_size = u64::from(self.session.part_mib) << 20;
        let large = file.bytes > chunk_size;
        let cache = self.root.join(format!("large-{}.json", file.sha256));
        if large && cache.try_exists()? {
            let chunks = json(&cache)?;
            let member = Member { file, chunks };
            validate_chunks(self.session.id, &member)?;
            return Ok(member);
        }
        if !large && let Some(chunk) = self.cached_chunk(&file.sha256, file.bytes)? {
            return Ok(Member {
                file,
                chunks: vec![chunk],
            });
        }
        let mut input = staged_file(dir, &file.path)?;
        ensure!(
            input.metadata()?.len() == file.bytes,
            "Staged evidence size changed: {}",
            file.path
        );
        let mut hash = Sha256::new();
        let mut left = file.bytes;
        let mut chunks = vec![];
        loop {
            let size = left.min(chunk_size) as usize;
            let mut data = vec![0; size];
            input.read_exact(&mut data)?;
            hash.update(&data);
            left -= size as u64;
            if left == 0 {
                ensure!(
                    input.read(&mut [0])? == 0 && hex(&hash.finalize_reset()) == file.sha256,
                    "Staged evidence changed: {}",
                    file.path
                );
            }
            chunks.push(self.upload_chunk(data)?);
            if left == 0 {
                break;
            }
        }
        if large {
            save(&cache, &chunks)?;
        }
        Ok(Member { file, chunks })
    }
    fn publish_available(&mut self) -> Result<()> {
        for scope in PHASES {
            let marker = self.root.join(format!("{scope}-published.json"));
            let path = self.root.join(format!("{scope}-plan.json"));
            if marker.try_exists()? || !path.try_exists()? {
                continue;
            }
            let plan: Plan = json(&path)?;
            ensure!(
                relative(&plan.directory)?.len() == 1,
                "Invalid phase source"
            );
            let source = paths::safe_join(&self.root, &plan.directory)?;
            let mut manifest = Manifest {
                kind: "KumadeS3PhaseV1".into(),
                session: self.session.id,
                phase: scope.into(),
                computer: self.session.computer.clone(),
                started_utc: self.session.started_utc.clone(),
                partial: plan.partial,
                files: vec![],
                observations: plan.observations,
            };
            for file in plan.files {
                manifest.files.push(self.member(&source, file)?);
            }
            let name = format!("{}-phase-{scope}-{}.json", self.session.id, Uuid::new_v4());
            let data = serde_json::to_vec(&manifest)?;
            ensure!(
                data.len() as u64 <= MAX_METADATA,
                "Phase manifest exceeds 128 MiB"
            );
            let published = Published {
                name: name.clone(),
                sha256: sha256(&data),
                partial: manifest.partial,
            };
            let uri = format!("{}/{}", self.location.uri(), name);
            self.bucket
                .put(&self.location.key(&name)?, data)
                .with_context(|| {
                    format!(
                        "Phase delivery unconfirmed: {uri} (expected SHA-256 {})",
                        published.sha256
                    )
                })?;
            save(&marker, &published)?;
            print_phase(scope, &self.location, &published);
        }
        Ok(())
    }
}
fn print_phase(scope: &str, location: &Location, p: &Published) {
    ui::field(
        &format!("S3 {scope} URI"),
        format!("{}/{}", location.uri(), p.name),
    );
    ui::field(&format!("S3 {scope} SHA256"), &p.sha256);
}
pub fn resume(args: &ResumeArgs) -> Result<u8> {
    let mut up = Uploader::open(&args.workspace, &args.s3, &args.connection)?;
    for scope in PHASES {
        let saved = up.root.join(format!("{scope}-published.json"));
        if saved.try_exists()? {
            print_phase(scope, &up.location, &json(&saved)?);
        }
    }
    // Publish already sealed phases even if a crash damaged later acquisition metadata.
    up.publish_available()?;
    // If the process exited between sealing the disk collection and publishing
    // its transfer plan, rebuild that plan only from the frozen local case.
    let acquisition_lock = open_lock(&up.root, "Acquisition.lock")?;
    if fs2::FileExt::try_lock_exclusive(&acquisition_lock).is_ok()
        && !up.root.join("collection-plan.json").try_exists()?
    {
        for entry in fs::read_dir(&up.root)? {
            let entry = entry?;
            if !entry
                .file_name()
                .to_string_lossy()
                .starts_with(".kumade-volatile-")
            {
                continue;
            }
            let name = entry.file_name();
            let stage = paths::safe_join(&up.root, name.to_str().context("Invalid stage name")?)?;
            if !stage.join("Seal.json").is_file() {
                continue;
            }
            let (_, hash) = collect::hash_file(&paths::safe_join(&stage, "Seal.json")?)?;
            volatile_plans(
                &up.root,
                &stage,
                &up.session.computer,
                &hash,
                |scope, plan| {
                    let dest = up.root.join(format!("{scope}-plan.json"));
                    if !dest.try_exists()? {
                        save(&dest, plan)?;
                    }
                    Ok(())
                },
            )?;
        }
        let case = up.root.join(paths::run_name(
            &up.session.computer,
            &up.session.started_utc,
        )?);
        if case.join("Seal.json").is_file() {
            if up.session.hybrid {
                if let Err(error) = hybrid::validate_seal(&up.root, &case, up.session.id) {
                    hybrid::recover(&up.root, &case, up.session.id)?;
                    up.publish_available()?;
                    return Err(error).context("Final collection did not verify; available disk receipts recovered independently");
                }
            } else {
                crate::verify::verify(&case)?;
            }
            let summary = json(&case.join("Summary.json"))?;
            save(
                &up.root.join("collection-plan.json"),
                &collection_plan(&up.root, &case, &summary)?,
            )?;
        } else if up.session.hybrid {
            hybrid::recover(&up.root, &case, up.session.id)?;
        }
    }
    up.publish_available()?;
    let final_marker = up.root.join("collection-published.json");
    if !final_marker.try_exists()? {
        ui::field(
            "Acquisition state",
            "Incomplete; available sealed phases uploaded",
        );
        return Ok(3);
    }
    Ok(if json::<Published>(&final_marker)?.partial {
        3
    } else {
        0
    })
}
fn store_chunk(
    bucket: &Bucket,
    location: &Location,
    id: Uuid,
    data: Vec<u8>,
    digest: String,
) -> Result<Chunk> {
    let bytes = data.len() as u64;
    let key = format!("{id}-data-{}", Uuid::new_v4());
    bucket.put(&location.key(&key)?, data)?;
    Ok(Chunk {
        sha256: digest,
        bytes,
        key,
    })
}

fn validate_key(id: Uuid, key: &str) -> Result<()> {
    let nonce = key
        .strip_prefix(&format!("{id}-data-"))
        .context("Foreign phase object")?;
    ensure!(
        Uuid::parse_str(nonce)?.to_string() == nonce,
        "Invalid phase object ID"
    );
    Ok(())
}
fn validate_chunks(id: Uuid, member: &Member) -> Result<()> {
    ensure!(!member.chunks.is_empty(), "Missing evidence chunks");
    let mut total = 0u64;
    for part in &member.chunks {
        validate_key(id, &part.key)?;
        ensure!(
            digest_valid(&part.sha256) && (part.bytes > 0 || member.chunks.len() == 1),
            "Invalid evidence chunk"
        );
        total = total
            .checked_add(part.bytes)
            .context("Chunk length overflow")?;
    }
    ensure!(
        total == member.file.bytes,
        "Evidence chunks do not cover the file"
    );
    Ok(())
}
fn read_member(
    bucket: &Bucket,
    member: &Member,
    output: &mut dyn Write,
    buf: &mut [u8],
) -> Result<()> {
    let mut whole = Sha256::new();
    for part in &member.chunks {
        let mut input = bucket.open(&part.key)?;
        let mut size = 0u64;
        let mut hash = Sha256::new();
        loop {
            let n = input.read(buf)?;
            if n == 0 {
                break;
            }
            size = size.checked_add(n as u64).context("Chunk size overflow")?;
            ensure!(size <= part.bytes, "Chunk exceeds recorded length");
            hash.update(&buf[..n]);
            whole.update(&buf[..n]);
            output.write_all(&buf[..n])?;
        }
        ensure!(
            size == part.bytes && hex(&hash.finalize()) == part.sha256,
            "Chunk size or SHA-256 mismatch"
        );
    }
    ensure!(
        hex(&whole.finalize()) == member.file.sha256,
        "Evidence file SHA-256 mismatch"
    );
    Ok(())
}

pub(crate) fn verify(args: &VerifyArgs, bucket: &Bucket, name: &str) -> Result<u8> {
    ensure!(digest_valid(&args.sha256), "Expected lowercase SHA-256");
    let mut data = Vec::new();
    bucket
        .open(name)?
        .take(MAX_METADATA + 1)
        .read_to_end(&mut data)?;
    ensure!(
        data.len() as u64 <= MAX_METADATA && sha256(&data) == args.sha256,
        "Phase manifest SHA-256 mismatch"
    );
    let m: Manifest = serde_json::from_slice(&data)?;
    ensure!(
        m.kind == "KumadeS3PhaseV1" && PHASES.contains(&m.phase.as_str()),
        "Unknown phase manifest"
    );
    let prefix = format!("{}-phase-{}-", m.session, m.phase);
    let nonce = name
        .strip_prefix(&prefix)
        .and_then(|v| v.strip_suffix(".json"))
        .context("Phase identity mismatch")?;
    ensure!(
        Uuid::parse_str(nonce)?.to_string() == nonce,
        "Invalid phase publication ID"
    );
    let receipt = paths::resolve_future(&args.receipt)?;
    ensure!(!receipt.exists(), "Receipt must be new");
    let dest = args
        .restore
        .as_ref()
        .map(|p| paths::resolve_future(p))
        .transpose()?;
    if let Some(dest) = &dest {
        ensure!(
            !dest.exists() && !receipt.starts_with(dest) && !dest.starts_with(&receipt),
            "Restore and receipt must be separate and new"
        );
    }
    let mut names = HashSet::new();
    let mut parents = HashSet::new();
    let mut bytes = 0u64;
    for obj in &m.files {
        let parts = relative(&obj.file.path)?;
        let path = obj.file.path.to_lowercase();
        ensure!(
            !parents.contains(&path) && names.insert(path),
            "Conflicting phase paths"
        );
        for end in 1..parts.len() {
            let p = parts[..end].join("/").to_lowercase();
            ensure!(!names.contains(&p), "Conflicting phase paths");
            parents.insert(p);
        }
        validate_chunks(m.session, obj)?;
        ensure!(digest_valid(&obj.file.sha256), "Invalid member SHA-256");
        bytes = bytes
            .checked_add(obj.file.bytes)
            .context("Phase size overflow")?;
    }
    ensure!(
        bytes <= args.max_decoded_gib * (1 << 30),
        "Phase exceeds decoded quota"
    );
    if m.phase == "collection" {
        for file in [
            "Plan.json",
            "Run.json",
            "Manifest.jsonl",
            "Manifest.csv",
            "DiscoveryIssues.csv",
            "Coverage.csv",
            "Errors.csv",
            "Seal.json",
            "Summary.json",
        ] {
            ensure!(
                m.files.iter().any(|f| f.file.path == file),
                "Incomplete collection manifest: {file}"
            );
        }
    }
    let staged = dest
        .as_ref()
        .map(|d| -> Result<_> {
            let t = tempfile::Builder::new()
                .prefix(".kumade-unverified-")
                .tempdir_in(d.parent().context("Missing restore parent")?)?;
            ensure!(
                platform::protect_output_root(t.path())? != "FilesystemHasNoPersistentACLs",
                "Restore requires access controls"
            );
            Ok(t)
        })
        .transpose()?;
    let mut buffer = vec![0; 1024 * 1024];
    for obj in &m.files {
        if let Some(stage) = &staged {
            let path = stage.path().join(&obj.file.path);
            let parent = path.parent().context("Missing restore parent")?;
            fs::create_dir_all(parent)?;
            ensure!(
                platform::canonicalize(parent)?.starts_with(stage.path()),
                "Unsafe restore path"
            );
            let mut file = File::create_new(&path)?;
            platform::validate_open_file(&file, stage.path())?;
            read_member(bucket, obj, &mut file, &mut buffer)?;
            file.sync_all()?;
        } else if m.phase == "collection" && obj.file.path == "Summary.json" {
            ensure!(
                obj.file.bytes <= MAX_METADATA,
                "Oversized collection summary"
            );
            let mut json = Vec::new();
            read_member(bucket, obj, &mut json, &mut buffer)?;
            let summary: Summary = serde_json::from_slice(&json)?;
            ensure!(
                (summary.completeness == "Partial") == m.partial,
                "Collection completeness differs from its phase manifest"
            );
        } else {
            read_member(bucket, obj, &mut io::sink(), &mut buffer)?;
        }
    }
    if let (Some(stage), Some(dest)) = (staged, dest) {
        if m.phase == "collection" {
            let (_, complete) = crate::verify::verify(stage.path())?;
            ensure!(
                complete != m.partial,
                "Collection completeness differs from its phase manifest"
            );
        }
        crate::sftp_verify::publish_restore(stage, &dest)?;
    }
    save(
        &receipt,
        &serde_json::json!({"Kind":"KumadeVerifiedS3Phase","Session":m.session,"Phase":m.phase,"Computer":m.computer,"ManifestSHA256":args.sha256,"VerifiedUTC":utc_now(),"Files":m.files.len(),"Bytes":bytes,"Partial":m.partial}),
    )?;
    ui::field("Verified S3 phase", &m.phase);
    ui::field("Receipt", receipt.display());
    Ok(if m.partial { 3 } else { 0 })
}
