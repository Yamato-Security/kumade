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

//! A virtual, upload-only SFTP endpoint. No OS account or SSH shell is exposed.
use crate::{
    collect,
    model::{hex, utc_now},
    paths, platform, ui,
};
use anyhow::{Context, Result, ensure};
use base64::{Engine, engine::general_purpose::URL_SAFE_NO_PAD};
use russh::{
    Channel, ChannelId,
    server::{self, Auth, ChannelOpenHandle, Msg, Session},
};
use russh_sftp::protocol::{
    FileAttributes, Handle, Name, OpenFlags, Packet, SftpHandle, SftpString, Status, StatusCode,
    Version,
};
use sha2::{Digest, Sha256};
use std::{
    collections::{BTreeMap, HashMap, VecDeque},
    fs::{self, File, OpenOptions},
    io::{self, Write},
    net::{IpAddr, SocketAddr},
    path::PathBuf,
    sync::{Arc, Mutex},
    time::{Duration, Instant},
};
use subtle::ConstantTimeEq;
use zeroize::Zeroizing;

#[derive(clap::Args, Clone)]
pub struct Options {
    /// Bind address (explicitly select a network interface for remote collection)
    #[arg(long, default_value = "127.0.0.1:2222")]
    pub listen: SocketAddr,
    /// Evidence parent; creates a new protected session directory
    #[arg(short, long)]
    pub output: PathBuf,
    /// Number of independent collectors to issue temporary credentials to
    #[arg(long, default_value_t=1, value_parser=clap::value_parser!(u32).range(1..=64))]
    pub sources: u32,
    /// Credential lifetime: seconds, or a suffix s/m/h (maximum: 7 days)
    #[arg(long, default_value="2h", value_parser=parse_duration)]
    pub expires: Duration,
    /// Maximum stored upload bytes per source in GiB (compressed bytes)
    #[arg(long, default_value_t=100, value_parser=clap::value_parser!(u64).range(1..=65536))]
    pub max_gib: u64,
    /// Maximum decoded bytes per source during readback in GiB
    #[arg(long, default_value_t=1024, value_parser=clap::value_parser!(u64).range(1..=1048576))]
    pub max_decoded_gib: u64,
    /// Maximum upload objects per source, including journals and probes
    #[arg(long, default_value_t=100000, value_parser=clap::value_parser!(u32).range(1..=1000000))]
    pub max_files: u32,
    /// Maximum simultaneous SSH connections (authenticated or not)
    #[arg(long, default_value_t=8, value_parser=clap::value_parser!(u32).range(1..=64))]
    pub max_connections: u32,
    /// Accept connections only from these exact IP addresses; repeat
    #[arg(long = "allow-ip")]
    pub allow_ips: Vec<IpAddr>,
    /// Keep this much free disk space in MiB
    #[arg(long, default_value_t = 2048)]
    pub reserve_mib: u64,
}
pub fn parse_duration(value: &str) -> std::result::Result<Duration, String> {
    let (number, multiplier) = match value.as_bytes().last() {
        Some(b's') => (&value[..value.len() - 1], 1u64),
        Some(b'm') => (&value[..value.len() - 1], 60),
        Some(b'h') => (&value[..value.len() - 1], 3600),
        _ => (value, 1),
    };
    let seconds = number
        .parse::<u64>()
        .ok()
        .and_then(|n| n.checked_mul(multiplier))
        .filter(|n| (1..=604800).contains(n))
        .ok_or_else(|| "Use 1s through 168h, for example --expires 2h".to_owned())?;
    Ok(Duration::from_secs(seconds))
}
#[derive(Clone)]
pub(crate) struct Closed {
    bytes: u64,
    hash: String,
}
struct State {
    incoming: PathBuf,
    username_hash: [u8; 32],
    password_hash: [u8; 32],
    deadline: Instant,
    revoked: bool,
    final_object: Option<(String, String)>,
    delivery_id: Option<String>,
    used: u64,
    files: u32,
    uploads: HashMap<Vec<u8>, Upload>,
    resumable: HashMap<String, Capability>,
    max_bytes: u64,
    max_files: u32,
    reserve: u64,
    pending_bytes: Arc<Mutex<u64>>,
    closed: BTreeMap<String, Closed>,
    sessions: HashMap<uuid::Uuid, server::Handle>,
    failures: VecDeque<Instant>,
    io_failed: bool,
}
type Shared = Arc<Mutex<State>>;
impl State {
    fn live(&self) -> bool {
        !self.revoked && Instant::now() < self.deadline
    }
    fn authorize(&mut self, user: &str, password: &str) -> bool {
        let now = Instant::now();
        while self
            .failures
            .front()
            .is_some_and(|t| now.duration_since(*t) > Duration::from_secs(60))
        {
            self.failures.pop_front();
        }
        if !self.live() || self.failures.len() >= 10 || password.len() > 4096 {
            return false;
        }
        let user_hash: [u8; 32] = Sha256::digest(user.as_bytes()).into();
        let password_hash: [u8; 32] = Sha256::digest(password.as_bytes()).into();
        let accepted = bool::from(
            user_hash.ct_eq(&self.username_hash) & password_hash.ct_eq(&self.password_hash),
        );
        if !accepted {
            self.failures.push_back(now);
        }
        accepted
    }
}
// Routing uses the generated credential, never an address or a collector-supplied hostname.
type Accounts = Arc<HashMap<[u8; 32], Shared>>;

struct SshSession {
    accounts: Accounts,
    authenticated: Option<Shared>,
    connection_id: uuid::Uuid,
    channel: Option<Channel<Msg>>,
    opened: bool,
}
impl Drop for SshSession {
    fn drop(&mut self) {
        if let Some(account) = &self.authenticated
            && let Ok(mut state) = account.lock()
        {
            state.sessions.remove(&self.connection_id);
        }
    }
}
impl server::Handler for SshSession {
    type Error = anyhow::Error;
    async fn auth_password(&mut self, user: &str, password: &str) -> Result<Auth> {
        let username_hash: [u8; 32] = Sha256::digest(user.as_bytes()).into();
        self.authenticated = None;
        if let Some(account) = self.accounts.get(&username_hash) {
            let mut state = account
                .lock()
                .map_err(|_| anyhow::anyhow!("Receiver state poisoned"))?;
            if state.authorize(user, password) {
                self.authenticated = Some(account.clone());
            }
        }
        Ok(if self.authenticated.is_some() {
            Auth::Accept
        } else {
            Auth::reject()
        })
    }
    async fn channel_open_session(
        &mut self,
        channel: Channel<Msg>,
        reply: ChannelOpenHandle,
        session: &mut Session,
    ) -> Result<()> {
        if let Some(account) = &self.authenticated
            && !self.opened
        {
            {
                let mut state = account
                    .lock()
                    .map_err(|_| anyhow::anyhow!("Receiver state poisoned"))?;
                if !state.live() {
                    return Ok(());
                }
                state.sessions.insert(self.connection_id, session.handle());
            }
            self.opened = true;
            self.channel = Some(channel);
            reply.accept().await;
        } // Dropping reply rejects it.
        Ok(())
    }
    async fn subsystem_request(
        &mut self,
        id: ChannelId,
        name: &str,
        session: &mut Session,
    ) -> Result<()> {
        if name == "sftp"
            && let Some(account) = &self.authenticated
            && account
                .lock()
                .map_err(|_| anyhow::anyhow!("Receiver state poisoned"))?
                .live()
            && let Some(channel) = self.channel.take().filter(|c| c.id() == id)
        {
            session.channel_success(id)?;
            russh_sftp::server::run(
                channel.into_stream(),
                Files {
                    state: account.clone(),
                    owner: uuid::Uuid::new_v4(),
                    initialized: false,
                },
            )
            .await;
        } else {
            session.channel_failure(id)?;
        }
        Ok(())
    }
    async fn exec_request(&mut self, id: ChannelId, _: &[u8], session: &mut Session) -> Result<()> {
        session.channel_failure(id)?;
        Ok(())
    }
    #[allow(clippy::too_many_arguments)]
    async fn pty_request(
        &mut self,
        id: ChannelId,
        _: &str,
        _: u32,
        _: u32,
        _: u32,
        _: u32,
        _: &[(russh::Pty, u32)],
        session: &mut Session,
    ) -> Result<()> {
        session.channel_failure(id)?;
        Ok(())
    }
    async fn env_request(
        &mut self,
        id: ChannelId,
        _: &str,
        _: &str,
        session: &mut Session,
    ) -> Result<()> {
        session.channel_failure(id)?;
        Ok(())
    }
    async fn shell_request(&mut self, id: ChannelId, session: &mut Session) -> Result<()> {
        session.channel_failure(id)?;
        Ok(())
    }
}
struct Upload {
    owner: uuid::Uuid,
    file: File,
    name: String,
    bytes: u64,
    hash: Sha256,
    broken: bool,
}
struct Files {
    state: Shared,
    owner: uuid::Uuid,
    initialized: bool,
}
fn ok(id: u32) -> Status {
    Status {
        id,
        status_code: StatusCode::Ok,
        error_message: "OK".into(),
        language_tag: "en-US".into(),
    }
}
fn object_name(path: &SftpString) -> std::result::Result<&str, StatusCode> {
    let name = path
        .strip_prefix("/incoming/")
        .ok_or(StatusCode::PermissionDenied)?;
    crate::sftp::validate_object_name(name).map_err(|_| StatusCode::PermissionDenied)?;
    if !name.starts_with("probe-") {
        let prefix = name.get(..36).ok_or(StatusCode::PermissionDenied)?;
        if uuid::Uuid::parse_str(prefix)
            .ok()
            .is_none_or(|id| id.to_string() != prefix)
            || name.as_bytes().get(36) != Some(&b'-')
        {
            return Err(StatusCode::PermissionDenied);
        }
        let suffix = &name[37..];
        if !(suffix == "journal.jsonl"
            || suffix == "delivery.json"
            || suffix.starts_with("payload-")
            || suffix.starts_with("meta-"))
        {
            return Err(StatusCode::PermissionDenied);
        }
    } else if uuid::Uuid::parse_str(&name[6..]).is_err() {
        return Err(StatusCode::PermissionDenied);
    }
    Ok(name)
}
struct Capability {
    secret_hash: [u8; 32],
    // None after CLOSE. Retain the digest so an ambiguous CLOSE can be confirmed.
    handle: Option<Vec<u8>>,
}

fn create_upload(state: &mut State, name: &str, owner: uuid::Uuid) -> Result<Vec<u8>, StatusCode> {
    if !state.live() || state.files >= state.max_files || state.uploads.len() >= 256 {
        return Err(StatusCode::PermissionDenied);
    }
    if !name.starts_with("probe-") {
        let delivery = &name[..36];
        if state.delivery_id.as_ref().is_some_and(|id| id != delivery) {
            return Err(StatusCode::PermissionDenied);
        }
        state.delivery_id = Some(delivery.into());
    } else if state.delivery_id.is_some() || state.files >= 16 {
        return Err(StatusCode::PermissionDenied);
    }
    let mut options = OpenOptions::new();
    options.write(true).create_new(true);
    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt;
        options.mode(0o600);
    }
    let file = options.open(state.incoming.join(name)).map_err(|e| {
        if e.kind() == io::ErrorKind::AlreadyExists {
            StatusCode::PermissionDenied
        } else {
            StatusCode::Failure
        }
    })?;
    state.files += 1;
    let handle = uuid::Uuid::new_v4().to_string().into_bytes();
    state.uploads.insert(
        handle.clone(),
        Upload {
            owner,
            file,
            name: name.to_owned(),
            bytes: 0,
            hash: Sha256::new(),
            broken: false,
        },
    );
    Ok(handle)
}

impl Files {
    fn attach(&mut self, id: u32, data: Vec<u8>) -> Result<Packet, StatusCode> {
        let data = Zeroizing::new(data);
        if !self.initialized || data.len() > 32 + "/incoming/".len() + 200 {
            return Err(StatusCode::BadMessage);
        }
        let (secret, path) = data.split_at_checked(32).ok_or(StatusCode::BadMessage)?;
        let path = std::str::from_utf8(path)
            .map_err(|_| StatusCode::BadMessage)?
            .to_owned();
        let name = object_name(&path)?;
        if name.starts_with("probe-") {
            return Err(StatusCode::PermissionDenied);
        }
        let secret_hash: [u8; 32] = Sha256::digest(secret).into();
        let mut state = self.state.lock().map_err(|_| StatusCode::Failure)?;
        if !state.live() {
            return Err(StatusCode::PermissionDenied);
        }
        let (bytes, handle) = if let Some(cap) = state.resumable.get(name) {
            if !bool::from(secret_hash.ct_eq(&cap.secret_hash)) {
                return Err(StatusCode::PermissionDenied);
            }
            if let Some(previous) = cap.handle.clone() {
                // Transfer ownership under the same lock as WRITE. Any later packets
                // from the old connection are rejected, even during a half-open TCP session.
                let prior = state.uploads.get(&previous).ok_or(StatusCode::Failure)?;
                if prior.broken {
                    return Err(StatusCode::Failure);
                }
                let bytes = prior.bytes;
                let mut upload = state.uploads.remove(&previous).ok_or(StatusCode::Failure)?;
                upload.owner = self.owner;
                let fresh = uuid::Uuid::new_v4().to_string().into_bytes();
                state.uploads.insert(fresh.clone(), upload);
                state
                    .resumable
                    .get_mut(name)
                    .ok_or(StatusCode::Failure)?
                    .handle = Some(fresh.clone());
                (bytes, Some(fresh))
            } else {
                (
                    state.closed.get(name).ok_or(StatusCode::Failure)?.bytes,
                    None,
                )
            }
        } else {
            let fresh = create_upload(&mut state, name, self.owner)?;
            state.resumable.insert(
                name.to_owned(),
                Capability {
                    secret_hash,
                    handle: Some(fresh.clone()),
                },
            );
            (0, Some(fresh))
        };
        let mut reply = Vec::with_capacity(45);
        reply.push(u8::from(handle.is_none()));
        reply.extend_from_slice(&bytes.to_be_bytes());
        if let Some(handle) = handle {
            reply.extend_from_slice(&handle);
        }
        Ok(Packet::ExtendedReply(russh_sftp::protocol::ExtendedReply {
            id,
            data: reply,
        }))
    }
}

impl russh_sftp::server::Handler for Files {
    type Error = StatusCode;
    fn unimplemented(&self) -> StatusCode {
        StatusCode::PermissionDenied
    }
    async fn init(
        &mut self,
        version: u32,
        _: HashMap<String, String>,
    ) -> std::result::Result<Version, StatusCode> {
        if self.initialized || version < 3 {
            return Err(StatusCode::BadMessage);
        }
        self.initialized = true;
        let mut version = Version::new();
        version
            .extensions
            .insert("fsync@openssh.com".into(), "1".into());
        version
            .extensions
            .insert(crate::sftp::STREAM_OPEN.into(), "1".into());
        Ok(version)
    }
    async fn realpath(
        &mut self,
        id: u32,
        path: SftpString,
    ) -> std::result::Result<Name, StatusCode> {
        if !matches!(path.as_str(), "/incoming" | "/" | ".") {
            return Err(StatusCode::PermissionDenied);
        }
        Ok(Name {
            id,
            files: vec![russh_sftp::protocol::File::dummy("/incoming")],
        })
    }
    async fn open(
        &mut self,
        id: u32,
        path: SftpString,
        flags: OpenFlags,
        _: FileAttributes,
    ) -> std::result::Result<Handle, StatusCode> {
        if !self.initialized
            || flags.bits() != (OpenFlags::WRITE | OpenFlags::CREATE | OpenFlags::EXCLUDE).bits()
        {
            return Err(StatusCode::PermissionDenied);
        }
        let name = object_name(&path)?;
        let mut state = self.state.lock().map_err(|_| StatusCode::Failure)?;
        let handle = create_upload(&mut state, name, self.owner)?;
        Ok(Handle {
            id,
            handle: handle.into(),
        })
    }
    async fn write(
        &mut self,
        id: u32,
        handle: SftpHandle,
        offset: u64,
        data: Vec<u8>,
    ) -> std::result::Result<Status, StatusCode> {
        let mut state = self.state.lock().map_err(|_| StatusCode::Failure)?;
        if !state.live() {
            return Err(StatusCode::PermissionDenied);
        }
        let state = &mut *state;
        let upload = state
            .uploads
            .get_mut(handle.as_bytes())
            .filter(|u| u.owner == self.owner)
            .ok_or(StatusCode::PermissionDenied)?;
        if upload.broken || offset != upload.bytes || data.len() > 128 * 1024 {
            return Err(StatusCode::PermissionDenied);
        }
        let end = upload
            .bytes
            .checked_add(data.len() as u64)
            .ok_or(StatusCode::Failure)?;
        let total = state
            .used
            .checked_add(data.len() as u64)
            .ok_or(StatusCode::Failure)?;
        if total > state.max_bytes
            || (upload.name.ends_with("-delivery.json") && end > crate::sftp_verify::MAX_METADATA)
        {
            return Err(StatusCode::Failure);
        }
        let size = data.len() as u64;
        // Count concurrent writes against the shared disk reserve while allowing
        // the writes themselves to proceed independently on each source.
        {
            let mut pending = state
                .pending_bytes
                .lock()
                .map_err(|_| StatusCode::Failure)?;
            let with_upload = pending.checked_add(size).ok_or(StatusCode::Failure)?;
            let free = fs2::available_space(&state.incoming).map_err(|_| StatusCode::Failure)?;
            if free.saturating_sub(state.reserve) < with_upload {
                return Err(StatusCode::Failure);
            }
            *pending = with_upload;
        }
        state.used = total; // Conservatively retain source quota on a partial OS write.
        let written = upload.file.write_all(&data);
        *state
            .pending_bytes
            .lock()
            .map_err(|_| StatusCode::Failure)? -= size;
        if written.is_err() {
            upload.broken = true;
            state.io_failed = true;
            return Err(StatusCode::Failure);
        }
        upload.bytes = end;
        upload.hash.update(&data);
        Ok(ok(id))
    }
    async fn extended(
        &mut self,
        id: u32,
        request: String,
        data: Vec<u8>,
    ) -> std::result::Result<Packet, StatusCode> {
        if request == crate::sftp::STREAM_OPEN {
            return self.attach(id, data);
        }
        if request != "fsync@openssh.com" || data.len() < 4 {
            return Err(StatusCode::PermissionDenied);
        }
        let size =
            u32::from_be_bytes(data[..4].try_into().map_err(|_| StatusCode::BadMessage)?) as usize;
        if size > 64 || size.checked_add(4) != Some(data.len()) {
            return Err(StatusCode::BadMessage);
        }
        let state = self.state.lock().map_err(|_| StatusCode::Failure)?;
        if !state.live() {
            return Err(StatusCode::PermissionDenied);
        }
        let upload = state
            .uploads
            .get(&data[4..])
            .filter(|u| u.owner == self.owner)
            .ok_or(StatusCode::PermissionDenied)?;
        if upload.broken {
            return Err(StatusCode::Failure);
        }
        upload.file.sync_all().map_err(|_| StatusCode::Failure)?;
        Ok(Packet::Status(ok(id)))
    }
    async fn close(
        &mut self,
        id: u32,
        handle: SftpHandle,
    ) -> std::result::Result<Status, StatusCode> {
        let mut state = self.state.lock().map_err(|_| StatusCode::Failure)?;
        if !state.live() {
            return Err(StatusCode::PermissionDenied);
        }
        let upload = state
            .uploads
            .get(handle.as_bytes())
            .filter(|u| u.owner == self.owner)
            .ok_or(StatusCode::PermissionDenied)?;
        // A delivery descriptor cannot finalize while another writer remains open.
        if upload.name.ends_with("-delivery.json") && (state.uploads.len() != 1 || state.io_failed)
        {
            return Err(StatusCode::Failure);
        }
        let upload = state
            .uploads
            .remove(handle.as_bytes())
            .ok_or(StatusCode::PermissionDenied)?;
        if upload.broken || upload.file.sync_all().is_err() {
            state.io_failed = true;
            return Err(StatusCode::Failure);
        }
        let completed = Closed {
            bytes: upload.bytes,
            hash: hex(&upload.hash.finalize()),
        };
        let name = upload.name.clone();
        drop(upload.file);
        state.closed.insert(name.clone(), completed.clone());
        if let Some(capability) = state.resumable.get_mut(&name) {
            capability.handle = None;
        }
        if name.ends_with("-delivery.json") {
            state.final_object = Some((name, completed.hash));
            state.revoked = true;
        }
        Ok(ok(id))
    }
}
impl Drop for Files {
    fn drop(&mut self) {
        if let Ok(mut state) = self.state.lock() {
            let state = &mut *state;
            state.uploads.retain(|_, upload| {
                upload.owner != self.owner || state.resumable.contains_key(&upload.name)
            });
        }
    }
}

fn peer_allowed(peer: IpAddr, allow_ips: &[IpAddr]) -> bool {
    allow_ips.is_empty()
        || allow_ips
            .iter()
            .any(|allowed| allowed.to_canonical() == peer.to_canonical())
}

pub fn run(options: &Options) -> Result<u8> {
    tokio::runtime::Builder::new_multi_thread()
        .worker_threads(2)
        .enable_all()
        .build()?
        .block_on(serve(options))
}
async fn serve(options: &Options) -> Result<u8> {
    ensure!(
        (1..=64).contains(&options.sources),
        "Use 1 through 64 sources"
    );
    let parent = paths::resolve_future(&options.output)?;
    fs::create_dir_all(&parent)?;
    let root = parent.join(format!(
        "Kumade-Receive-{}-{}",
        chrono::Utc::now().format("%Y-%m-%d_%H-%M-%S"),
        uuid::Uuid::new_v4()
    ));
    fs::create_dir(&root)?;
    ensure!(
        platform::protect_output_root(&root)? != "FilesystemHasNoPersistentACLs",
        "Receiver storage requires persistent access controls"
    );
    let root = platform::canonicalize(&root)?;
    let listener = tokio::net::TcpListener::bind(options.listen).await?;
    let addr = listener.local_addr()?;
    let key = russh::keys::PrivateKey::random(&mut rand::rng(), russh::keys::Algorithm::Ed25519)?;
    let pin = key
        .public_key()
        .fingerprint(russh::keys::HashAlg::Sha256)
        .to_string();
    let deadline = Instant::now()
        .checked_add(options.expires)
        .context("Expiry overflow")?;
    let expires_utc = chrono::Utc::now() + chrono::Duration::from_std(options.expires)?;
    let max_bytes = options
        .max_gib
        .checked_mul(1 << 30)
        .context("Quota overflow")?;
    let max_decoded_bytes = options
        .max_decoded_gib
        .checked_mul(1 << 30)
        .context("Decoded quota overflow")?;
    let reserve = options
        .reserve_mib
        .checked_mul(1 << 20)
        .context("Reserve overflow")?;
    let mut accounts = HashMap::new();
    let mut pending = Vec::new();
    let mut credentials = Vec::new();
    let pending_bytes = Arc::new(Mutex::new(0));
    for number in 1..=options.sources {
        let label = format!("source-{number:02}");
        let source_root = if options.sources == 1 {
            root.clone()
        } else {
            let path = root.join(&label);
            fs::create_dir(&path)?;
            path
        };
        let incoming = source_root.join("incoming");
        fs::create_dir(&incoming)?;
        let username = format!("ku{}", uuid::Uuid::new_v4().simple());
        let password = Zeroizing::new(URL_SAFE_NO_PAD.encode(rand::random::<[u8; 32]>()));
        let username_hash = Sha256::digest(username.as_bytes()).into();
        let account = Arc::new(Mutex::new(State {
            incoming,
            username_hash,
            password_hash: Sha256::digest(password.as_bytes()).into(),
            deadline,
            revoked: false,
            final_object: None,
            delivery_id: None,
            used: 0,
            files: 0,
            uploads: HashMap::new(),
            resumable: HashMap::new(),
            max_bytes,
            max_files: options.max_files,
            reserve,
            pending_bytes: pending_bytes.clone(),
            closed: BTreeMap::new(),
            sessions: HashMap::new(),
            failures: VecDeque::new(),
            io_failed: false,
        }));
        collect::write_json_new(
            &source_root.join("Receiver.json"),
            &serde_json::json!({"SchemaVersion":1,"StartedUtc":utc_now(),"ExpiresUtc":expires_utc.to_rfc3339(),"Username":username,"HostKeyFingerprint":pin,"Listen":addr.to_string(),"MaxStoredGiB":options.max_gib,"MaxDecodedGiB":options.max_decoded_gib,"MaxFiles":options.max_files,"AllowIPs":options.allow_ips}),
        )?;
        accounts.insert(username_hash, account.clone());
        pending.push((source_root, account));
        credentials.push((label, username, password));
    }
    let accounts = Arc::new(accounts);
    ui::banner();
    ui::field("SFTP receiver", addr);
    ui::field("Evidence directory", root.display());
    ui::field("SSH fingerprint", &pin);
    ui::field("Expires UTC", expires_utc.to_rfc3339());
    ui::field(
        "Stored quota per source",
        format!("{} GiB / {} objects", options.max_gib, options.max_files),
    );
    for (label, username, password) in credentials {
        if options.sources > 1 {
            ui::field("Source", label);
        }
        ui::field("Temporary username", username);
        ui::field("Temporary password", password.as_str());
    }
    ui::status(
        "Upload-only access. Each credential is revoked after its final delivery, expiry or Ctrl+C.",
    );
    io::stdout().flush()?;
    let config = Arc::new(server::Config {
        keys: vec![key],
        max_auth_attempts: 3,
        inactivity_timeout: Some(Duration::from_secs(30)),
        auth_rejection_time: Duration::from_secs(1),
        nodelay: true,
        channel_buffer_size: 8,
        event_buffer_size: 32,
        window_size: 1024 * 1024,
        ..Default::default()
    });
    let mut connections = tokio::task::JoinSet::new();
    let mut finalizers = tokio::task::JoinSet::new();
    // Verification can decode large manifests; keep only one readback active.
    let readback = Arc::new(tokio::sync::Semaphore::new(1));
    let mut tick = tokio::time::interval(Duration::from_millis(100));
    while !pending.is_empty() {
        let interrupted = tokio::select! {
            _ = tick.tick() => false,
            signal = tokio::signal::ctrl_c() => { signal?; true },
            Some(_) = connections.join_next(), if !connections.is_empty() => continue,
            accepted = listener.accept() => {
                let (stream, peer) = accepted?;
                if connections.len() < options.max_connections as usize && peer_allowed(peer.ip(), &options.allow_ips) {
                    let config = config.clone();
                    let handler = SshSession {
                        accounts: accounts.clone(),
                        authenticated: None,
                        connection_id: uuid::Uuid::new_v4(),
                        channel: None,
                        opened: false,
                    };
                    connections.spawn(async move {
                        if let Ok(Ok(session)) = tokio::time::timeout(Duration::from_secs(15),
                            server::run_stream(config, stream, handler)).await {
                            let _ = session.await;
                        }
                    });
                }
                continue
            }
        };
        for index in (0..pending.len()).rev() {
            let (source_root, account) = &pending[index];
            let mut state = account
                .lock()
                .map_err(|_| anyhow::anyhow!("Receiver state poisoned"))?;
            let reason = if state.final_object.is_some() {
                "FinalDelivery"
            } else if interrupted {
                "Interrupted"
            } else if !state.live() {
                "Expired"
            } else {
                continue;
            };
            state.revoked = true;
            // Retain partial evidence on disk, release its handles as soon as this slot closes.
            state.uploads.clear();
            state.resumable.clear();
            let final_object = state.final_object.take();
            let closed = std::mem::take(&mut state.closed);
            let handles = state.sessions.drain().map(|(_, handle)| handle).collect();
            drop(state);
            finalizers.spawn(finish_source(
                source_root.clone(),
                reason,
                final_object,
                closed,
                handles,
                max_decoded_bytes,
                readback.clone(),
            ));
            pending.swap_remove(index);
        }
    }
    drop(listener);
    let mut code = 0;
    let mut first_error = None;
    while let Some(result) = finalizers.join_next().await {
        match result
            .context("Receiver readback task failed")
            .and_then(|r| r)
        {
            Ok(source_code) => code = code.max(source_code),
            Err(error) => {
                eprintln!("{error:#}");
                first_error.get_or_insert(error);
            }
        }
    }
    connections.abort_all();
    while connections.join_next().await.is_some() {}
    match first_error {
        Some(error) => Err(error),
        None => Ok(code),
    }
}

async fn finish_source(
    root: PathBuf,
    reason: &'static str,
    final_object: Option<(String, String)>,
    closed: BTreeMap<String, Closed>,
    handles: Vec<server::Handle>,
    max_decoded_bytes: u64,
    readback: Arc<tokio::sync::Semaphore>,
) -> Result<u8> {
    // No further writes/authentication can pass the state lock. Let the final
    // CLOSE acknowledgement reach the collector before disconnecting idle peers.
    tokio::time::sleep(Duration::from_millis(500)).await;
    for handle in handles {
        let _ = tokio::time::timeout(
            Duration::from_secs(2),
            handle.disconnect(
                russh::Disconnect::ByApplication,
                "Upload credentials revoked".into(),
                "en".into(),
            ),
        )
        .await;
    }
    ui::field("Receiver directory", root.display());
    ui::field("Credentials", "Revoked");
    if let Some((name, digest)) = final_object {
        ui::status("Reading back received objects and verifying hashes…");
        let _permit = readback.acquire().await?;
        let inputs = crate::sftp_verify::Inputs {
            incoming: root.join("incoming"),
            delivery: name.clone(),
            sha256: digest.clone(),
            max_decoded_bytes,
            restore: None,
        };
        let result =
            tokio::task::spawn_blocking(move || crate::sftp_verify::verify(&inputs, Some(&closed)))
                .await?;
        match result {
            Ok(receipt) => {
                collect::write_json_new(&root.join("ReadbackReceipt.json"), &receipt)?;
                ui::field("Readback integrity", "Verified");
                ui::field("Delivery object", name);
                ui::field("Delivery SHA256", digest);
                ui::field("Acquisition state", &receipt.acquisition_state);
                ui::field("Receipt", root.join("ReadbackReceipt.json").display());
                Ok(if receipt.acquisition_state == "Partial" {
                    3
                } else {
                    0
                })
            }
            Err(error) => {
                collect::write_json_new(
                    &root.join("VerificationFailure.json"),
                    &serde_json::json!({"FinishedUtc":utc_now(),"Status":"Failed","Reason":format!("{error:#}")}),
                )?;
                Err(error).with_context(|| {
                    format!(
                        "Server readback failed; evidence retained in {}",
                        root.display()
                    )
                })
            }
        }
    } else {
        collect::write_json_new(
            &root.join("ReceiverInterrupted.json"),
            &serde_json::json!({"FinishedUtc":utc_now(),"Status":reason,"CompletedObjects":closed.len(),"ReadbackVerified":false}),
        )?;
        ui::field(
            "Collection",
            format!("{reason}; incomplete evidence retained"),
        );
        Ok(3)
    }
}

pub(crate) fn closed_info(value: &Closed) -> (u64, &str) {
    (value.bytes, &value.hash)
}

#[cfg(test)]
mod tests {
    use super::*;
    use russh_sftp::server::Handler;
    fn fixture() -> (tempfile::TempDir, Files) {
        let root = tempfile::tempdir().unwrap();
        let incoming = platform::canonicalize(root.path()).unwrap();
        let state = Arc::new(Mutex::new(State {
            incoming,
            username_hash: Sha256::digest(b"user").into(),
            password_hash: Sha256::digest(b"secret").into(),
            deadline: Instant::now() + Duration::from_secs(30),
            revoked: false,
            final_object: None,
            delivery_id: None,
            used: 0,
            files: 0,
            uploads: HashMap::new(),
            resumable: HashMap::new(),
            max_bytes: 1024 * 1024,
            max_files: 100,
            reserve: 0,
            pending_bytes: Arc::default(),
            closed: BTreeMap::new(),
            sessions: HashMap::new(),
            failures: VecDeque::new(),
            io_failed: false,
        }));
        (
            root,
            Files {
                state,
                owner: uuid::Uuid::new_v4(),
                initialized: false,
            },
        )
    }
    #[test]
    fn allowlist_matches_mapped_ipv4_without_admitting_other_peers() {
        let ipv4: IpAddr = "192.0.2.20".parse().unwrap();
        let mapped: IpAddr = "::ffff:192.0.2.20".parse().unwrap();
        assert!(peer_allowed(mapped, &[ipv4]));
        assert!(peer_allowed(ipv4, &[mapped]));
        assert!(peer_allowed(ipv4, &[ipv4]));
        assert!(peer_allowed(mapped, &[]));
        for other in [
            "192.0.2.21",
            "::ffff:192.0.2.21",
            "::192.0.2.20",
            "::1",
            "2001:db8::20",
        ] {
            assert!(!peer_allowed(other.parse().unwrap(), &[ipv4]), "{other}");
        }
        let native: IpAddr = "2001:db8::20".parse().unwrap();
        assert!(peer_allowed(native, &[native]));
        assert!(!peer_allowed(ipv4, &[native]));
    }
    #[tokio::test]
    async fn credentials_namespaces_and_resource_limits_are_independent_per_source() {
        use russh::server::Handler as _;
        let (first_dir, mut first) = fixture();
        let (second_dir, mut second) = fixture();
        let first_key: [u8; 32] = Sha256::digest(b"user").into();
        let second_key: [u8; 32] = Sha256::digest(b"second").into();
        {
            let mut state = second.state.lock().unwrap();
            state.username_hash = second_key;
            state.password_hash = Sha256::digest(b"second password").into();
        }
        let pending_bytes = first.state.lock().unwrap().pending_bytes.clone();
        second.state.lock().unwrap().pending_bytes = pending_bytes.clone();
        first.state.lock().unwrap().max_bytes = 3;
        let mut session = SshSession {
            accounts: Arc::new(HashMap::from([
                (first_key, first.state.clone()),
                (second_key, second.state.clone()),
            ])),
            authenticated: None,
            connection_id: uuid::Uuid::new_v4(),
            channel: None,
            opened: false,
        };
        session.auth_password("second", "secret").await.unwrap();
        assert!(session.authenticated.is_none());
        session
            .auth_password("second", "second password")
            .await
            .unwrap();
        assert!(Arc::ptr_eq(
            session.authenticated.as_ref().unwrap(),
            &second.state
        ));

        let delivery = uuid::Uuid::new_v4();
        let name = format!("{delivery}-payload-test");
        let path = format!("/incoming/{name}");
        let flags = OpenFlags::WRITE | OpenFlags::CREATE | OpenFlags::EXCLUDE;
        first.init(3, HashMap::new()).await.unwrap();
        second.init(3, HashMap::new()).await.unwrap();
        let a = first
            .open(1, path.clone(), flags, FileAttributes::default())
            .await
            .unwrap()
            .handle;
        let b = second
            .open(1, path, flags, FileAttributes::default())
            .await
            .unwrap()
            .handle;
        assert!(
            first
                .write(2, a.clone(), 0, b"over quota".to_vec())
                .await
                .is_err()
        );
        first.write(3, a.clone(), 0, b"one".to_vec()).await.unwrap();
        first.close(4, a).await.unwrap();
        let descriptor = first
            .open(
                5,
                format!("/incoming/{delivery}-delivery.json"),
                flags,
                FileAttributes::default(),
            )
            .await
            .unwrap()
            .handle;
        first.close(6, descriptor).await.unwrap();
        assert!(!first.state.lock().unwrap().live());
        // An outstanding reservation on the same disk affects both collectors.
        *pending_bytes.lock().unwrap() = u64::MAX - 1;
        assert!(second.write(2, b.clone(), 0, vec![42]).await.is_err());
        *pending_bytes.lock().unwrap() = 0;
        second
            .write(2, b.clone(), 0, b"second payload".to_vec())
            .await
            .unwrap();
        second.close(3, b).await.unwrap();
        assert_eq!(fs::read(first_dir.path().join(&name)).unwrap(), b"one");
        assert_eq!(
            fs::read(second_dir.path().join(&name)).unwrap(),
            b"second payload"
        );
    }

    #[tokio::test]
    async fn upload_is_create_only_and_append_only_even_with_an_open_handle() {
        let (root, mut files) = fixture();
        files.init(3, HashMap::new()).await.unwrap();
        let name = format!("{}-payload-test", uuid::Uuid::new_v4());
        let path = format!("/incoming/{name}");
        let flags = OpenFlags::WRITE | OpenFlags::CREATE | OpenFlags::EXCLUDE;
        let handle = files
            .open(1, path.clone(), flags, FileAttributes::default())
            .await
            .unwrap()
            .handle;
        files
            .write(2, handle.clone(), 0, b"first".to_vec())
            .await
            .unwrap();
        assert!(
            files
                .write(3, handle.clone(), 0, b"overwrite".to_vec())
                .await
                .is_err()
        );
        assert!(
            files
                .write(4, handle.clone(), 100, b"gap".to_vec())
                .await
                .is_err()
        );
        assert!(files.read(5, handle.clone(), 0, 5).await.is_err());
        assert!(
            files
                .fsetstat(6, handle.clone(), FileAttributes::default())
                .await
                .is_err()
        );
        assert!(
            files
                .setstat(7, path.clone(), FileAttributes::default())
                .await
                .is_err()
        );
        assert!(files.remove(8, path.clone()).await.is_err());
        assert!(
            files
                .rename(9, path.clone(), "/incoming/other".into())
                .await
                .is_err()
        );
        assert!(
            files
                .symlink(10, "/incoming/link".into(), path.clone())
                .await
                .is_err()
        );
        assert!(files.opendir(11, "/incoming".into()).await.is_err());
        files.close(12, handle.clone()).await.unwrap();
        assert!(files.write(13, handle, 5, b"later".to_vec()).await.is_err());
        assert!(
            files
                .open(14, path.clone(), flags, FileAttributes::default())
                .await
                .is_err()
        );
        assert!(
            files
                .open(
                    15,
                    path,
                    OpenFlags::WRITE | OpenFlags::TRUNCATE,
                    FileAttributes::default()
                )
                .await
                .is_err()
        );
        assert_eq!(fs::read(root.path().join(name)).unwrap(), b"first");
    }
    fn attach_result(
        files: &mut Files,
        name: &str,
        secret: u8,
    ) -> Result<(bool, u64, SftpHandle), StatusCode> {
        let mut request = vec![secret; 32];
        request.extend_from_slice(format!("/incoming/{name}").as_bytes());
        let Packet::ExtendedReply(reply) = files.attach(1, request)? else {
            panic!("unexpected reply")
        };
        Ok((
            reply.data[0] == 1,
            u64::from_be_bytes(reply.data[1..9].try_into().unwrap()),
            reply.data[9..].to_vec().into(),
        ))
    }

    #[tokio::test]
    async fn resume_transfers_only_append_authority_and_preserves_sealed_objects() {
        let (root, mut first) = fixture();
        let name = format!("{}-payload-test", uuid::Uuid::new_v4());
        first.init(3, HashMap::new()).await.unwrap();
        let (sealed, bytes, old_handle) = attach_result(&mut first, &name, 24).unwrap();
        assert!(!sealed);
        assert_eq!(bytes, 0);
        first
            .write(2, old_handle.clone(), 0, b"first".to_vec())
            .await
            .unwrap();

        let mut second = Files {
            state: first.state.clone(),
            owner: uuid::Uuid::new_v4(),
            initialized: true,
        };
        assert!(
            second
                .write(3, old_handle.clone(), 5, vec![42])
                .await
                .is_err()
        );
        assert!(second.close(3, old_handle.clone()).await.is_err());
        let mut fsync_request = (old_handle.as_bytes().len() as u32).to_be_bytes().to_vec();
        fsync_request.extend_from_slice(old_handle.as_bytes());
        assert!(
            second
                .extended(3, "fsync@openssh.com".into(), fsync_request)
                .await
                .is_err()
        );
        assert!(attach_result(&mut second, &name, 25).is_err());
        let (sealed, bytes, fresh) = attach_result(&mut second, &name, 24).unwrap();
        assert!(!sealed);
        assert_eq!(bytes, 5);
        assert!(
            first
                .write(4, old_handle.clone(), 5, vec![42])
                .await
                .is_err()
        );
        assert!(first.close(5, old_handle).await.is_err());
        drop(first);
        assert!(second.write(6, fresh.clone(), 0, vec![42]).await.is_err());
        assert!(second.write(7, fresh.clone(), 6, vec![42]).await.is_err());
        second
            .write(8, fresh.clone(), 5, b"-last".to_vec())
            .await
            .unwrap();
        second.close(9, fresh.clone()).await.unwrap();
        assert!(second.write(10, fresh, 10, vec![42]).await.is_err());
        let (sealed, bytes, no_handle) = attach_result(&mut second, &name, 24).unwrap();
        assert!(sealed && no_handle.as_bytes().is_empty());
        assert_eq!(bytes, 10);
        assert!(attach_result(&mut second, &name, 25).is_err());
        assert_eq!(fs::read(root.path().join(&name)).unwrap(), b"first-last");
        let state = second.state.lock().unwrap();
        assert_eq!((state.used, state.files), (10, 1));
        assert_eq!(
            state.closed[&name].hash,
            crate::model::sha256(b"first-last")
        );
    }

    #[tokio::test]
    async fn disconnected_stream_blocks_finalization_until_reattached_and_closed() {
        let (_root, mut first) = fixture();
        let id = uuid::Uuid::new_v4();
        let payload = format!("{id}-payload-test");
        let delivery = format!("{id}-delivery.json");
        first.init(3, HashMap::new()).await.unwrap();
        attach_result(&mut first, &payload, 42).unwrap();
        let mut second = Files {
            state: first.state.clone(),
            owner: uuid::Uuid::new_v4(),
            initialized: true,
        };
        drop(first);
        let (_, _, handle) = attach_result(&mut second, &delivery, 43).unwrap();
        assert!(second.close(2, handle.clone()).await.is_err());
        let (_, _, pending) = attach_result(&mut second, &payload, 42).unwrap();
        second.close(3, pending).await.unwrap();
        second.close(4, handle).await.unwrap();
        assert!(attach_result(&mut second, &payload, 42).is_err());
    }
    #[tokio::test]
    async fn expiry_revokes_existing_handles_and_quotas_are_not_bypassed() {
        let (_root, mut files) = fixture();
        files.init(3, HashMap::new()).await.unwrap();
        files.state.lock().unwrap().max_bytes = 4;
        let handle = files
            .open(
                1,
                format!("/incoming/{}-payload-test", uuid::Uuid::new_v4()),
                OpenFlags::WRITE | OpenFlags::CREATE | OpenFlags::EXCLUDE,
                FileAttributes::default(),
            )
            .await
            .unwrap()
            .handle;
        assert!(
            files
                .write(2, handle.clone(), 0, b"12345".to_vec())
                .await
                .is_err()
        );
        files
            .write(3, handle.clone(), 0, b"1234".to_vec())
            .await
            .unwrap();
        assert!(
            files
                .write(4, handle.clone(), 4, b"5".to_vec())
                .await
                .is_err()
        );
        files.state.lock().unwrap().deadline = Instant::now();
        assert!(files.write(5, handle.clone(), 4, Vec::new()).await.is_err());
        assert!(files.close(6, handle).await.is_err());
    }
    #[tokio::test]
    async fn final_delivery_cannot_freeze_another_open_upload() {
        let (_root, mut files) = fixture();
        files.init(3, HashMap::new()).await.unwrap();
        let id = uuid::Uuid::new_v4();
        let flags = OpenFlags::WRITE | OpenFlags::CREATE | OpenFlags::EXCLUDE;
        let payload = files
            .open(
                1,
                format!("/incoming/{id}-payload-test"),
                flags,
                FileAttributes::default(),
            )
            .await
            .unwrap()
            .handle;
        let delivery = files
            .open(
                2,
                format!("/incoming/{id}-delivery.json"),
                flags,
                FileAttributes::default(),
            )
            .await
            .unwrap()
            .handle;
        assert!(files.close(3, delivery.clone()).await.is_err());
        files.close(4, payload).await.unwrap();
        files.close(5, delivery).await.unwrap();
        assert!(files.state.lock().unwrap().revoked);
        assert!(!files.state.lock().unwrap().authorize("user", "secret"));
        assert!(
            files
                .open(
                    6,
                    format!("/incoming/{id}-meta-later"),
                    flags,
                    FileAttributes::default()
                )
                .await
                .is_err()
        );
    }

    #[test]
    fn auth_expiry_rate_limit_and_paths_are_fail_closed() {
        let (_, files) = fixture();
        let mut state = files.state.lock().unwrap();
        assert!(state.authorize("user", "secret"));
        for _ in 0..10 {
            assert!(!state.authorize("user", "wrong"));
        }
        assert!(!state.authorize("user", "secret"));
        state.failures.clear();
        state.revoked = true;
        assert!(!state.authorize("user", "secret"));
        for name in [
            "/incoming/../escape",
            "/incoming/file/child",
            "/incoming/not-a-delivery",
            "/incoming/probe-invalid",
            "/incoming/CON",
            "C:/file",
        ] {
            assert!(object_name(&name.into()).is_err());
        }
        for input in ["0", "-1s", "169h", "1d", "999999999999999h"] {
            assert!(parse_duration(input).is_err());
        }
        assert_eq!(parse_duration("2h").unwrap(), Duration::from_secs(7200));
    }
}
