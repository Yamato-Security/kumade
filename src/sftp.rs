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

//! Direct SFTP payload streaming. Completed objects are never reopened or replaced.
use crate::{collect, discovery, model::*, paths, raw::RawVolume};
use anyhow::{Context, Result, bail, ensure};
use base64::{Engine, engine::general_purpose::STANDARD_NO_PAD};
use flate2::{Compression, write::GzEncoder};
use russh::{
    client,
    keys::{HashAlg, PublicKeyOrCertificate},
};
use russh_sftp::{
    client::{RawSftpSession, error::Error as SftpError, rawsession::PendingWrite},
    protocol::{FileAttributes, OpenFlags, SftpHandle, StatusCode},
};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use std::{
    collections::{BTreeMap, HashMap, VecDeque},
    io::{self, IsTerminal, Read, Write},
    path::{Path, PathBuf},
    sync::{
        Arc, Mutex,
        atomic::{AtomicBool, Ordering},
    },
    time::Duration,
};
use zeroize::Zeroizing;

#[derive(clap::Args, Clone, Default)]
pub struct Args {
    /// Stream evidence to this SFTP host (no local payload copies)
    #[arg(long, value_name="HOST", conflicts_with_all=["output","vhdx","e01"])]
    pub sftp: Option<String>,
    /// Temporary upload-only account name
    #[arg(long, requires = "sftp")]
    pub sftp_user: Option<String>,
    /// Required pinned SSH host-key fingerprint, e.g. SHA256:... from the server administrator
    #[arg(long, requires = "sftp")]
    pub sftp_host_key: Option<String>,
    /// SFTP port (default: 22)
    #[arg(long, requires="sftp", value_parser=clap::value_parser!(u16).range(1..))]
    pub sftp_port: Option<u16>,
    /// Pre-provisioned upload directory inside the server chroot (default: /incoming)
    #[arg(long, requires = "sftp")]
    pub sftp_directory: Option<String>,
    /// Read the password from the first stdin line instead of a hidden terminal prompt
    #[arg(long, requires = "sftp", conflicts_with = "wizard")]
    pub sftp_password_stdin: bool,
    /// Parent for private metadata-only staging (default: system temporary directory)
    #[arg(long, requires = "sftp")]
    pub sftp_staging_dir: Option<PathBuf>,
    /// Per-operation network deadline in seconds (default: 60)
    #[arg(long, requires="sftp", value_parser=clap::value_parser!(u64).range(1..=3600))]
    pub sftp_timeout: Option<u64>,
    /// Disable gzip payload compression (sparse zero ranges will use network bandwidth)
    #[arg(long, requires = "sftp")]
    pub sftp_no_compression: bool,
}
impl Args {
    pub fn validate(&self) -> Result<()> {
        if let Some(host) = &self.sftp {
            ensure!(
                !host.is_empty()
                    && !host.chars().any(char::is_control)
                    && !host.contains('@')
                    && !host.contains('/'),
                "Use a host name/address, without credentials or a URL, for --sftp"
            );
            let user = self
                .sftp_user
                .as_deref()
                .context("--sftp requires --sftp-user")?;
            ensure!(
                !user.is_empty() && !user.chars().any(char::is_control),
                "Invalid SFTP user name"
            );
            let pin = self
                .sftp_host_key
                .as_deref()
                .context("--sftp requires --sftp-host-key SHA256:...")?;
            let decoded = STANDARD_NO_PAD.decode(
                pin.strip_prefix("SHA256:")
                    .context("Host key must use SHA256:...")?,
            )?;
            ensure!(
                decoded.len() == 32,
                "Host-key fingerprint must contain a SHA-256 digest"
            );
            let directory = self.directory();
            ensure!(
                directory.starts_with('/')
                    && !directory.contains('\\')
                    && !directory.contains('%')
                    && !directory.chars().any(char::is_control)
                    && directory.split('/').all(|x| x != ".." && x != "."),
                "Use an absolute SFTP directory without parent components or controls"
            );
        }
        Ok(())
    }
    pub fn directory(&self) -> &str {
        self.sftp_directory
            .as_deref()
            .unwrap_or("/incoming")
            .trim_end_matches('/')
    }
    pub fn password(&self) -> Result<Zeroizing<String>> {
        let password = if self.sftp_password_stdin {
            // A terminal would echo the typed password; the hidden prompt is for that.
            ensure!(
                !std::io::stdin().is_terminal(),
                "--sftp-password-stdin expects a piped password; omit it to use the hidden prompt"
            );
            let mut bytes = Zeroizing::new(Vec::new());
            let mut input = std::io::stdin().lock();
            for _ in 0..4097 {
                let mut b = [0];
                if input.read(&mut b)? == 0 || b[0] == b'\n' {
                    break;
                }
                bytes.push(b[0]);
            }
            ensure!(bytes.len() <= 4096, "SFTP password line exceeds 4096 bytes");
            if bytes.last() == Some(&b'\r') {
                bytes.pop();
            }
            Zeroizing::new(String::from_utf8(bytes.to_vec()).context("Password must be UTF-8")?)
        } else {
            ensure!(
                std::io::stdin().is_terminal(),
                "Use --sftp-password-stdin for noninteractive authentication"
            );
            Zeroizing::new(rpassword::prompt_password("Temporary SFTP password: ")?)
        };
        ensure!(
            !password.is_empty() && !password.contains('\0'),
            "Empty/NUL SFTP passwords are not accepted"
        );
        Ok(password)
    }
}

pub trait RemoteWrite: Write + Send {
    fn finish(self: Box<Self>) -> Result<()>;
}
pub trait Store: Send + Sync {
    fn create(&self, name: &str, mode: u32) -> Result<Box<dyn RemoteWrite>>;
}
struct HostPin(String);
impl client::Handler for HostPin {
    type Error = russh::Error;
    async fn check_server_key(
        &mut self,
        key: &PublicKeyOrCertificate,
    ) -> std::result::Result<bool, Self::Error> {
        Ok(key.certificate().is_none()
            && key.public_key().fingerprint(HashAlg::Sha256).to_string() == self.0)
    }
}
struct Network {
    runtime: Arc<tokio::runtime::Runtime>,
    raw: Arc<RawSftpSession>,
    _session: Mutex<client::Handle<HostPin>>,
    timeout: Duration,
    broken: AtomicBool,
}
impl Network {
    fn wait<T>(
        &self,
        future: impl std::future::Future<Output = std::result::Result<T, SftpError>>,
    ) -> Result<T> {
        ensure!(
            !self.broken.load(Ordering::Relaxed),
            "SFTP connection failed; no retry or local payload fallback"
        );
        let result = self.runtime.block_on(async {
            tokio::time::timeout(self.timeout, future)
                .await
                .context("SFTP operation timed out")?
                .map_err(anyhow::Error::from)
        });
        if result.is_err() {
            self.broken.store(true, Ordering::Relaxed);
        }
        result
    }
}
/// Each write request carries 32 KiB, the size OpenSSH's own client uses. The
/// gzip encoder hands over much smaller pieces (a median of 79 bytes on an
/// incompressible input), so they are coalesced into full requests first.
const REQUEST_BYTES: usize = 32 * 1024;
/// Requests in flight per open object before the oldest acknowledgement is
/// awaited. A bounded sliding window keeps every worker streaming without
/// the bursts that make other workers' control and journal requests wait.
const IN_FLIGHT: usize = 16;
struct NetworkFile {
    connection: Arc<Network>,
    handle: SftpHandle,
    offset: u64,
    buffer: Vec<u8>,
    in_flight: VecDeque<PendingWrite>,
}
impl NetworkFile {
    fn broken<T>(&mut self, error: anyhow::Error) -> io::Result<T> {
        self.connection.broken.store(true, Ordering::Relaxed);
        self.in_flight.clear();
        Err(io::Error::other(format!("{error:#}")))
    }
    /// Sends the coalesced piece at the next sequential offset.
    fn send_piece(&mut self) -> io::Result<()> {
        if self.buffer.is_empty() {
            return Ok(());
        }
        if self.connection.broken.load(Ordering::Relaxed) {
            return self.broken(anyhow::anyhow!("SFTP connection is unusable"));
        }
        let pending = match self.connection.raw.write_nowait(
            self.handle.as_bytes(),
            self.offset,
            &self.buffer,
        ) {
            Ok(pending) => pending,
            Err(error) => return self.broken(error.into()),
        };
        self.offset = match self.offset.checked_add(self.buffer.len() as u64) {
            Some(offset) => offset,
            None => return self.broken(anyhow::anyhow!("SFTP offset overflow")),
        };
        self.buffer.clear();
        self.in_flight.push_back(pending);
        if self.in_flight.len() >= IN_FLIGHT {
            self.drain(IN_FLIGHT - 1)?;
        }
        Ok(())
    }
    /// Waits for acknowledgements, oldest first, until at most `keep` requests
    /// remain in flight. A request that makes no progress within the operation
    /// deadline fails the connection; nothing is retried or rewritten.
    fn drain(&mut self, keep: usize) -> io::Result<()> {
        while self.in_flight.len() > keep {
            let pending = self.in_flight.pop_front().expect("in-flight request");
            let c = &self.connection;
            let result = c.runtime.block_on(async {
                tokio::time::timeout(c.timeout, pending)
                    .await
                    .context("SFTP write timed out")?
                    .map_err(anyhow::Error::from)
            });
            if let Err(error) = result {
                return self.broken(error);
            }
        }
        Ok(())
    }
}
impl Write for NetworkFile {
    fn write(&mut self, data: &[u8]) -> io::Result<usize> {
        if data.is_empty() {
            return Ok(0);
        }
        if self.connection.broken.load(Ordering::Relaxed) {
            return Err(io::Error::other("SFTP connection is unusable"));
        }
        let n = data.len().min(REQUEST_BYTES - self.buffer.len());
        self.buffer.extend_from_slice(&data[..n]);
        if self.buffer.len() >= REQUEST_BYTES {
            self.send_piece()?;
        }
        Ok(n)
    }
    fn flush(&mut self) -> io::Result<()> {
        self.send_piece()?;
        self.drain(0)?;
        self.connection
            .wait(self.connection.raw.fsync(&self.handle))
            .map(|_| ())
            .map_err(|e| io::Error::other(format!("{e:#}")))
    }
}
impl RemoteWrite for NetworkFile {
    fn finish(mut self: Box<Self>) -> Result<()> {
        self.flush()?;
        self.connection
            .wait(self.connection.raw.close(&self.handle))?;
        Ok(())
    }
}
struct NetworkStore {
    connection: Arc<Network>,
    directory: String,
}
impl Store for NetworkStore {
    fn create(&self, name: &str, mode: u32) -> Result<Box<dyn RemoteWrite>> {
        validate_object_name(name)?;
        let path = format!("{}/{}", self.directory, name);
        let handle = self
            .connection
            .wait(self.connection.raw.open(
                path,
                OpenFlags::WRITE | OpenFlags::CREATE | OpenFlags::EXCLUDE,
                FileAttributes {
                    permissions: Some(mode),
                    ..Default::default()
                },
            ))?
            .handle;
        Ok(Box::new(NetworkFile {
            connection: self.connection.clone(),
            handle,
            offset: 0,
            buffer: Vec::with_capacity(REQUEST_BYTES),
            in_flight: VecDeque::new(),
        }))
    }
}
fn denied<T>(result: std::result::Result<T, SftpError>, operation: &str) -> Result<()> {
    match result {
        Err(SftpError::Status(s))
            if matches!(
                s.status_code,
                StatusCode::PermissionDenied | StatusCode::OpUnsupported
            ) =>
        {
            Ok(())
        }
        _ => bail!(
            "Upload-only server protection failed: {operation} was allowed or not explicitly denied"
        ),
    }
}
async fn protection_probe(raw: &RawSftpSession, directory: &str) -> Result<()> {
    let path = format!("{directory}/probe-{}", uuid::Uuid::new_v4());
    let other = format!("{path}-other");
    let handle = raw
        .open(
            path.clone(),
            OpenFlags::WRITE | OpenFlags::CREATE | OpenFlags::EXCLUDE,
            FileAttributes {
                permissions: Some(0o777),
                ..Default::default()
            },
        )
        .await?
        .handle;
    raw.write(
        &handle,
        0,
        b"Kumade upload-only permission probe\n".to_vec(),
    )
    .await?;
    let attrs = FileAttributes {
        permissions: Some(0o600),
        ..Default::default()
    };
    denied(raw.fsetstat(&handle, attrs.clone()).await, "fsetstat")?;
    raw.fsync(&handle).await?;
    raw.close(&handle).await?;
    denied(
        raw.open(path.clone(), OpenFlags::READ, FileAttributes::default())
            .await,
        "read/reopen",
    )?;
    denied(
        raw.open(
            path.clone(),
            OpenFlags::WRITE | OpenFlags::TRUNCATE,
            FileAttributes::default(),
        )
        .await,
        "truncate/reopen",
    )?;
    denied(raw.setstat(path.clone(), attrs).await, "chmod/setstat")?;
    denied(raw.remove(path.clone()).await, "remove")?;
    denied(raw.rename(path.clone(), other.clone()).await, "rename")?;
    denied(
        raw.posix_rename(path.clone(), other.clone()).await,
        "posix-rename",
    )?;
    denied(raw.hardlink(path.clone(), other.clone()).await, "hardlink")?;
    denied(raw.symlink(other.clone(), path.clone()).await, "symlink")?;
    denied(raw.opendir(directory.to_owned()).await, "directory listing")?;
    Ok(())
}

#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(rename_all = "PascalCase")]
pub struct Object {
    pub name: String,
    pub relative_path: String,
    pub encoding: String,
    pub logical_bytes: u64,
    pub logical_sha256: String,
    pub stored_bytes: u64,
    pub stored_sha256: String,
}
/// The remote object is created on the first stored byte (or at `finish` for an
/// empty object), so a source that turns out to be absent leaves nothing behind.
struct Counted {
    sink: Option<Box<dyn RemoteWrite>>,
    pending: Option<(Arc<dyn Store>, String)>,
    hash: Sha256,
    bytes: u64,
}
impl Counted {
    fn sink(&mut self) -> io::Result<&mut Box<dyn RemoteWrite>> {
        if self.sink.is_none() {
            let (store, name) = self
                .pending
                .take()
                .ok_or_else(|| io::Error::other("Remote object was discarded"))?;
            let sink = store
                .create(&name, 0)
                .map_err(|e| io::Error::other(format!("{e:#}")))?;
            self.sink = Some(sink);
        }
        Ok(self.sink.as_mut().expect("created sink"))
    }
}
impl Write for Counted {
    fn write(&mut self, b: &[u8]) -> io::Result<usize> {
        let n = self.sink()?.write(b)?;
        self.hash.update(&b[..n]);
        self.bytes = self
            .bytes
            .checked_add(n as u64)
            .ok_or_else(|| io::Error::other("Stored byte count overflow"))?;
        Ok(n)
    }
    fn flush(&mut self) -> io::Result<()> {
        match self.sink.as_mut() {
            Some(sink) => sink.flush(),
            None => Ok(()),
        }
    }
}
enum Encoded {
    Plain(Counted),
    Gzip(Box<GzEncoder<Counted>>),
}
struct Upload {
    encoded: Encoded,
    logical: Sha256,
    bytes: u64,
    name: String,
    relative: String,
}
impl Write for Upload {
    fn write(&mut self, b: &[u8]) -> io::Result<usize> {
        let n = match &mut self.encoded {
            Encoded::Plain(w) => w.write(b)?,
            Encoded::Gzip(w) => w.write(b)?,
        };
        self.logical.update(&b[..n]);
        self.bytes = self
            .bytes
            .checked_add(n as u64)
            .ok_or_else(|| io::Error::other("Logical byte count overflow"))?;
        Ok(n)
    }
    fn flush(&mut self) -> io::Result<()> {
        match &mut self.encoded {
            Encoded::Plain(w) => w.flush(),
            Encoded::Gzip(w) => w.flush(),
        }
    }
}
impl Upload {
    fn finish(self) -> Result<Object> {
        let gzip = matches!(&self.encoded, Encoded::Gzip(_));
        let mut stored = match self.encoded {
            Encoded::Plain(w) => w,
            Encoded::Gzip(w) => w.finish()?,
        };
        // An empty source still becomes an (empty) exclusive remote object.
        stored.sink()?;
        stored.sink.take().context("Missing SFTP sink")?.finish()?;
        Ok(Object {
            name: self.name,
            relative_path: self.relative,
            encoding: if gzip { "gzip" } else { "none" }.into(),
            logical_bytes: self.bytes,
            logical_sha256: hex(&self.logical.finalize()),
            stored_bytes: stored.bytes,
            stored_sha256: hex(&stored.hash.finalize()),
        })
    }
    /// Abandon an upload before any byte reached the server: no remote object
    /// is created, so an absent source is not represented by a stub object.
    fn discard(self) -> Result<()> {
        ensure!(
            self.bytes == 0,
            "Cannot discard a partially streamed object"
        );
        let created = match self.encoded {
            Encoded::Plain(counted) => counted.sink.is_some(),
            Encoded::Gzip(mut encoder) => {
                // Drop writes the gzip trailer; without a pending object that
                // write fails harmlessly instead of creating the object late.
                encoder.get_mut().pending = None;
                encoder.get_ref().sink.is_some()
            }
        };
        ensure!(!created, "Remote object already exists; cannot discard");
        Ok(())
    }
}

pub struct Target {
    store: Arc<dyn Store>,
    id: String,
    gzip: bool,
    objects: Mutex<BTreeMap<String, Object>>,
    journal: Mutex<Option<Upload>>,
    publishing: AtomicBool,
}
impl Target {
    pub fn id(&self) -> &str {
        &self.id
    }
    pub fn from_store(store: Arc<dyn Store>, gzip: bool) -> Result<Arc<Self>> {
        let id = uuid::Uuid::new_v4().to_string();
        let target = Arc::new(Self {
            store,
            id,
            gzip,
            objects: Mutex::default(),
            journal: Mutex::new(None),
            publishing: AtomicBool::new(false),
        });
        *target
            .journal
            .lock()
            .map_err(|_| anyhow::anyhow!("SFTP journal lock"))? =
            Some(target.begin("journal.jsonl".into(), "RemoteJournal.jsonl".into(), false)?);
        target.event(&serde_json::json!({"Event":"Start","DeliveryId":target.id,"StartedUtc":utc_now(),"PayloadReadback":"PendingTrustedServerVerification"}))?;
        Ok(target)
    }
    pub fn connect(args: &Args, password: Zeroizing<String>) -> Result<Arc<Self>> {
        args.validate()?;
        let runtime = Arc::new(
            tokio::runtime::Builder::new_multi_thread()
                .worker_threads(2)
                .enable_all()
                .build()?,
        );
        let timeout = Duration::from_secs(args.sftp_timeout.unwrap_or(60));
        let (session, raw) = runtime.block_on(async {
            tokio::time::timeout(timeout, async {
                let config = client::Config {
                    keepalive_interval: Some(Duration::from_secs(15)),
                    keepalive_max: 3,
                    // russh leaves Nagle's algorithm on by default. Every SFTP
                    // request is a small trailing segment after its payload, so
                    // the delayed-ACK interaction costs tens of milliseconds per
                    // request; OpenSSH's own clients disable it as well.
                    nodelay: true,
                    ..Default::default()
                };
                let mut session = client::connect(
                    Arc::new(config),
                    (
                        args.sftp.as_deref().context("Missing SFTP host")?,
                        args.sftp_port.unwrap_or(22),
                    ),
                    HostPin(args.sftp_host_key.clone().context("Missing host pin")?),
                )
                .await
                .context("SSH connection/host-key verification failed")?;
                ensure!(
                    session
                        .authenticate_password(
                            args.sftp_user.as_deref().context("Missing SFTP user")?,
                            password.as_str()
                        )
                        .await?
                        .success(),
                    "SFTP password authentication failed"
                );
                let mut channel = session.channel_open_session().await?;
                channel.request_subsystem(true, "sftp").await?;
                loop {
                    match channel.wait().await {
                        Some(russh::ChannelMsg::Success) => break,
                        Some(russh::ChannelMsg::Failure) | None => {
                            bail!("Server refused the SFTP subsystem")
                        }
                        _ => {}
                    }
                }
                let raw = RawSftpSession::new_with_config(
                    channel.into_stream(),
                    russh_sftp::client::Config {
                        request_timeout_secs: timeout.as_secs(),
                        ..Default::default()
                    },
                );
                let version = raw.init().await?;
                ensure!(
                    version.version == 3 && version.extensions.contains_key("fsync@openssh.com"),
                    "SFTP v3 with fsync@openssh.com is required"
                );
                protection_probe(&raw, args.directory()).await?;
                Ok::<_, anyhow::Error>((session, Arc::new(raw)))
            })
            .await
            .context("SFTP connection/protection probe timed out")?
        })?;
        drop(password);
        let store = Arc::new(NetworkStore {
            connection: Arc::new(Network {
                runtime,
                raw,
                _session: Mutex::new(session),
                timeout,
                broken: AtomicBool::new(false),
            }),
            directory: args.directory().into(),
        });
        Self::from_store(store, !args.sftp_no_compression)
    }
    fn begin(&self, suffix: String, relative: String, gzip: bool) -> Result<Upload> {
        let name = format!("{}-{suffix}", self.id);
        validate_object_name(&name)?;
        let counted = Counted {
            sink: None,
            pending: Some((self.store.clone(), name.clone())),
            hash: Sha256::new(),
            bytes: 0,
        };
        Ok(Upload {
            encoded: if gzip {
                Encoded::Gzip(Box::new(GzEncoder::new(counted, Compression::fast())))
            } else {
                Encoded::Plain(counted)
            },
            logical: Sha256::new(),
            bytes: 0,
            name,
            relative,
        })
    }
    fn event(&self, value: &impl Serialize) -> Result<()> {
        let mut guard = self
            .journal
            .lock()
            .map_err(|_| anyhow::anyhow!("SFTP journal poisoned"))?;
        let journal = guard.as_mut().context("SFTP journal is closed")?;
        serde_json::to_writer(&mut *journal, value)?;
        journal.write_all(b"\n")?;
        journal.flush()?;
        Ok(())
    }
    pub fn checkpoint(&self, record: &Record) -> Result<()> {
        let object = self
            .objects
            .lock()
            .map_err(|_| anyhow::anyhow!("SFTP inventory poisoned"))?
            .get(&record.observation_id)
            .cloned();
        self.event(&serde_json::json!({"Event":"Acquisition","Record":record,"Object":object}))
    }
    fn retain(&self, id: String, object: Object) -> Result<()> {
        self.objects
            .lock()
            .map_err(|_| anyhow::anyhow!("SFTP inventory poisoned"))?
            .insert(id, object);
        Ok(())
    }
    /// Main may have already uploaded volatile evidence before VSS/disk discovery.
    pub fn upload_early(&self, capture: &crate::early::Capture) -> Result<()> {
        let digest = crate::collect::hash_file(&capture.path().join("Seal.json"))?.1;
        let exists = self
            .objects
            .lock()
            .map_err(|_| anyhow::anyhow!("SFTP object lock"))?
            .get("metadata:Early/Seal.json")
            .cloned();
        if let Some(object) = exists {
            ensure!(
                object.logical_sha256 == digest,
                "Early evidence changed after upload"
            );
            return Ok(());
        }
        self.upload_tree(capture.path(), "Early")
    }
    pub fn require_object(&self, path: &str, bytes: u64, digest: &str) -> Result<()> {
        let objects = self
            .objects
            .lock()
            .map_err(|_| anyhow::anyhow!("SFTP object lock"))?;
        let object = objects
            .values()
            .find(|o| o.relative_path == path)
            .context("Missing transferred RAM payload")?;
        ensure!(
            object.logical_bytes == bytes && object.logical_sha256 == digest,
            "Transferred RAM payload differs from capture"
        );
        Ok(())
    }
    pub fn upload_tree(&self, root: &Path, prefix: &str) -> Result<()> {
        for entry in walkdir::WalkDir::new(root).follow_links(false) {
            let entry = entry?;
            if entry.file_type().is_dir() {
                continue;
            }
            ensure!(
                entry.file_type().is_file() && !crate::platform::is_reparse_directory(entry.path()),
                "Unsafe staged metadata"
            );
            let relative = paths::relative_text(entry.path().strip_prefix(root)?)?;
            let logical = if prefix.is_empty() {
                relative
            } else {
                format!("{prefix}/{relative}")
            };
            let suffix = format!("meta-{}", uuid::Uuid::new_v4());
            let compress = logical == "Early/Memory/Memory.dmp" && self.gzip;
            let mut upload = self.begin(suffix, logical.clone(), compress)?;
            let mut input = crate::platform::open_source(entry.path())?;
            crate::platform::validate_open_file(&input, &crate::platform::canonicalize(root)?)?;
            io::copy(&mut input, &mut upload)?;
            let object = upload.finish()?;
            self.event(&serde_json::json!({"Event":"Metadata","Object":object}))?;
            self.retain(format!("metadata:{logical}"), object)?;
        }
        Ok(())
    }
    pub fn publish(&self, root: &Path, summary: &Summary) -> Result<(String, String)> {
        ensure!(
            !self.publishing.swap(true, Ordering::SeqCst),
            "Delivery publication already attempted; in-place retries are refused"
        );
        self.upload_tree(root, "")?;
        self.event(&serde_json::json!({"Event":"End","FinishedUtc":utc_now(),"AcquisitionState":summary.completeness}))?;
        let journal = self
            .journal
            .lock()
            .map_err(|_| anyhow::anyhow!("SFTP journal poisoned"))?
            .take()
            .context("Journal already published")?
            .finish()?;
        self.retain("journal".into(), journal)?;
        let objects: Vec<_> = self
            .objects
            .lock()
            .map_err(|_| anyhow::anyhow!("SFTP inventory poisoned"))?
            .values()
            .cloned()
            .collect();
        let mut delivery = self.begin("delivery.json".into(), "Delivery.json".into(), false)?;
        serde_json::to_writer(
            &mut delivery,
            &serde_json::json!({"SchemaVersion":1,"Kind":"KumadeSftpDelivery","DeliveryId":self.id,"CollectionName":root.file_name().context("Missing collection name")?.to_string_lossy(),"Objects":objects,"Summary":summary,"ReadbackVerification":"PendingTrustedServerVerification","FinishedUtc":utc_now()}),
        )?;
        let object = delivery.finish()?;
        Ok((object.name, object.logical_sha256))
    }
}
pub fn validate_object_name(name: &str) -> Result<()> {
    ensure!(
        !name.is_empty()
            && name.len() <= 200
            && name
                .bytes()
                .all(|b| b.is_ascii_alphanumeric() || matches!(b, b'-' | b'.')),
        "Unsafe remote object name"
    );
    Ok(())
}
fn relative_payload(item: &PlannedFile) -> Result<String> {
    if item.stream.is_some() {
        // Keep unnamed files and named streams in disjoint namespaces.
        let p =
            paths::output_relative(&item.source_id, &item.relative_path, item.stream.as_deref())?;
        Ok(format!("_KumadeStreams/{}", paths::relative_text(&p)?))
    } else {
        paths::relative_text(&paths::output_relative(
            &item.source_id,
            &item.relative_path,
            None,
        )?)
    }
}
pub(crate) fn acquire(
    mut record: Record,
    source: &Source,
    item: &PlannedFile,
    cache: &mut HashMap<PathBuf, RawVolume>,
    target: &Arc<Target>,
) -> Record {
    let result = (|| -> Result<()> {
        let relative = relative_payload(item)?;
        let suffix = format!("payload-{}", sha256(item.id.as_bytes()));
        let remote_name = format!("{}-{suffix}", target.id);
        target.event(&serde_json::json!({"Event":"BeginPayload","RemoteName":remote_name,"ObservationId":item.id,"SourceId":source.id,"SourcePath":record.source_path,"StreamName":item.stream,"RelativePath":relative}))?;
        let mut upload = target.begin(suffix, relative.clone(), target.gzip)?;
        let copied = collect::copy_source(
            source,
            item,
            cache,
            cfg!(windows),
            &mut record.method,
            &mut upload,
            |_, _| Ok(()),
        );
        record.bytes_read = upload.bytes;
        record.sha256 = Some(hex(&upload.logical.clone().finalize()));
        if let Err(e) = &copied {
            // Opening a missing raw device also returns NotFound. Only a
            // successfully opened provider can establish a missing NTFS
            // object/stream; never count provider failure as artifact absence.
            let raw_available = source
                .raw_device
                .as_ref()
                .is_none_or(|device| cache.contains_key(device));
            if item.before.is_none()
                && crate::raw::is_missing(e)
                && record.bytes_read == 0
                && raw_available
                && source.root.is_dir()
            {
                // Nothing was streamed: no remote object, output path or hash.
                upload.discard()?;
                record.sha256 = None;
                record.status = "NotPresent".into();
                record.reason = format!("{e:#}");
                return Ok(());
            }
        }
        let mut object = upload.finish()?;
        match copied {
            Ok((before, after)) => {
                record.logical_size = Some(before.size);
                record.created_utc = before.created_ns.clone();
                record.modified_utc = before.modified_ns.clone();
                record.accessed_utc = before.accessed_ns.clone();
                record.source_file_id = before.identity.clone();
                record.changed_during_read = !discovery::same_version(&before, &after)
                    || item
                        .before
                        .as_ref()
                        .is_some_and(|p| !discovery::same_version(p, &before));
                record.status = if record.changed_during_read
                    || item
                        .expected_sha256
                        .as_ref()
                        .is_some_and(|h| Some(h) != record.sha256.as_ref())
                {
                    "Partial"
                } else {
                    "Transferred"
                }
                .into();
                record.reason=if record.status=="Partial"{"Source metadata/content changed; streamed version retained; server readback is pending"}else{"SFTP write/fsync/close acknowledged; trusted server readback is pending"}.into();
            }
            Err(e) => {
                record.status = "Failed".into();
                object.relative_path = format!("{relative}.{}.partial", item.id);
                record.reason = format!("{e:#}; partial remote content retained");
            }
        }
        record.relative_output_path = Some(object.relative_path.clone());
        target.retain(item.id.clone(), object)?;
        Ok(())
    })();
    if let Err(e) = result {
        record.status = "Failed".into();
        record.reason = format!("SFTP acquisition failed: {e:#}; no local payload fallback");
    }
    record.finished_utc = utc_now();
    record
}

/// Private metadata-only staging is retained on every unsuccessful delivery.
pub struct Staging {
    directory: Option<tempfile::TempDir>,
}
impl Staging {
    pub fn new(parent: &Path) -> Result<Self> {
        // Do not silently create an arbitrary parent tree on the evidence disk.
        ensure!(
            parent.is_dir(),
            "SFTP staging parent must already be a directory"
        );
        let directory = tempfile::Builder::new()
            .prefix("kumade-sftp-metadata-")
            .tempdir_in(parent)?;
        let protection = crate::platform::protect_output_root(directory.path()).and_then(|policy| {
            ensure!(policy != "FilesystemHasNoPersistentACLs", "Metadata staging requires persistent access controls; choose an NTFS or other protected staging filesystem");
            Ok(())
        });
        if let Err(e) = protection {
            let retained = directory.keep();
            bail!(
                "Cannot protect metadata staging {}: {e:#}",
                retained.display()
            );
        }
        Ok(Self {
            directory: Some(directory),
        })
    }
    pub fn path(&self) -> &Path {
        self.directory.as_ref().expect("active staging").path()
    }
    pub fn cleanup(&mut self) -> Result<()> {
        if let Some(directory) = self.directory.take() {
            let path = directory.keep();
            std::fs::remove_dir_all(&path).with_context(|| {
                format!(
                    "Delivery completed but metadata staging cleanup failed: {}",
                    path.display()
                )
            })?;
        }
        Ok(())
    }
}
impl Drop for Staging {
    fn drop(&mut self) {
        if let Some(directory) = self.directory.take() {
            eprintln!(
                "SFTP metadata retained after incomplete delivery: {}",
                directory.keep().display()
            );
        }
    }
}
