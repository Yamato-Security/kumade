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
    /// Credential lifetime: seconds, or a suffix s/m/h (maximum: 7 days)
    #[arg(long, default_value="2h", value_parser=parse_duration)]
    pub expires: Duration,
    /// Maximum stored upload bytes in GiB (compressed bytes)
    #[arg(long, default_value_t=100, value_parser=clap::value_parser!(u64).range(1..=65536))]
    pub max_gib: u64,
    /// Maximum total decoded bytes during readback in GiB
    #[arg(long, default_value_t=1024, value_parser=clap::value_parser!(u64).range(1..=1048576))]
    pub max_decoded_gib: u64,
    /// Maximum number of upload objects, including journals and probes
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
    open: u32,
    max_bytes: u64,
    max_files: u32,
    reserve: u64,
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
struct SshSession {
    state: Shared,
    channel: Option<Channel<Msg>>,
    accepted: bool,
    opened: bool,
}
impl server::Handler for SshSession {
    type Error = anyhow::Error;
    async fn auth_password(&mut self, user: &str, password: &str) -> Result<Auth> {
        self.accepted = self
            .state
            .lock()
            .map_err(|_| anyhow::anyhow!("Receiver state poisoned"))?
            .authorize(user, password);
        Ok(if self.accepted {
            Auth::Accept
        } else {
            Auth::reject()
        })
    }
    async fn channel_open_session(
        &mut self,
        channel: Channel<Msg>,
        reply: ChannelOpenHandle,
        _: &mut Session,
    ) -> Result<()> {
        if self.accepted
            && !self.opened
            && self
                .state
                .lock()
                .map_err(|_| anyhow::anyhow!("Receiver state poisoned"))?
                .live()
        {
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
            && self.accepted
            && self
                .state
                .lock()
                .map_err(|_| anyhow::anyhow!("Receiver state poisoned"))?
                .live()
            && let Some(channel) = self.channel.take().filter(|c| c.id() == id)
        {
            session.channel_success(id)?;
            russh_sftp::server::run(
                channel.into_stream(),
                Files {
                    state: self.state.clone(),
                    handles: HashMap::new(),
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
    file: File,
    name: String,
    bytes: u64,
    hash: Sha256,
    broken: bool,
}
struct Files {
    state: Shared,
    handles: HashMap<Vec<u8>, Upload>,
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
        let name = object_name(&path)?.to_owned();
        let mut state = self.state.lock().map_err(|_| StatusCode::Failure)?;
        if !state.live() || state.files >= state.max_files || state.open >= 256 {
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
        let file = options.open(state.incoming.join(&name)).map_err(|e| {
            if e.kind() == io::ErrorKind::AlreadyExists {
                StatusCode::PermissionDenied
            } else {
                StatusCode::Failure
            }
        })?;
        state.files += 1;
        state.open += 1;
        let handle = uuid::Uuid::new_v4().to_string().into_bytes();
        self.handles.insert(
            handle.clone(),
            Upload {
                file,
                name,
                bytes: 0,
                hash: Sha256::new(),
                broken: false,
            },
        );
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
        let upload = self
            .handles
            .get_mut(handle.as_bytes())
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
            || fs2::available_space(&state.incoming).map_err(|_| StatusCode::Failure)?
                < state.reserve.saturating_add(data.len() as u64)
        {
            return Err(StatusCode::Failure);
        }
        state.used = total; // Conservatively retain the reservation on a partial OS write.
        if upload.file.write_all(&data).is_err() {
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
        let upload = self
            .handles
            .get(&data[4..])
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
        let upload = self
            .handles
            .get(handle.as_bytes())
            .ok_or(StatusCode::PermissionDenied)?;
        // A delivery descriptor cannot finalize while another writer remains open.
        if upload.name.ends_with("-delivery.json") && (state.open != 1 || state.io_failed) {
            return Err(StatusCode::Failure);
        }
        let upload = self
            .handles
            .remove(handle.as_bytes())
            .ok_or(StatusCode::PermissionDenied)?;
        state.open -= 1;
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
            state.open = state.open.saturating_sub(self.handles.len() as u32);
        }
    }
}

pub fn run(options: &Options) -> Result<u8> {
    tokio::runtime::Builder::new_multi_thread()
        .worker_threads(2)
        .enable_all()
        .build()?
        .block_on(serve(options))
}
async fn serve(options: &Options) -> Result<u8> {
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
    let incoming = root.join("incoming");
    fs::create_dir(&incoming)?;
    let listener = tokio::net::TcpListener::bind(options.listen).await?;
    let key = russh::keys::PrivateKey::random(&mut rand::rng(), russh::keys::Algorithm::Ed25519)?;
    let pin = key
        .public_key()
        .fingerprint(russh::keys::HashAlg::Sha256)
        .to_string();
    let username = format!("ku{}", uuid::Uuid::new_v4().simple());
    let password = Zeroizing::new(URL_SAFE_NO_PAD.encode(rand::random::<[u8; 32]>()));
    let started = Instant::now();
    let expires_utc = chrono::Utc::now() + chrono::Duration::from_std(options.expires)?;
    let state = Arc::new(Mutex::new(State {
        incoming: incoming.clone(),
        username_hash: Sha256::digest(username.as_bytes()).into(),
        password_hash: Sha256::digest(password.as_bytes()).into(),
        deadline: started
            .checked_add(options.expires)
            .context("Expiry overflow")?,
        revoked: false,
        final_object: None,
        delivery_id: None,
        used: 0,
        files: 0,
        open: 0,
        max_bytes: options
            .max_gib
            .checked_mul(1 << 30)
            .context("Quota overflow")?,
        max_files: options.max_files,
        reserve: options
            .reserve_mib
            .checked_mul(1 << 20)
            .context("Reserve overflow")?,
        closed: BTreeMap::new(),
        sessions: HashMap::new(),
        failures: VecDeque::new(),
        io_failed: false,
    }));
    collect::write_json_new(
        &root.join("Receiver.json"),
        &serde_json::json!({"SchemaVersion":1,"StartedUtc":utc_now(),"ExpiresUtc":expires_utc.to_rfc3339(),"Username":username,"HostKeyFingerprint":pin,"Listen":listener.local_addr()?.to_string(),"MaxStoredGiB":options.max_gib,"MaxDecodedGiB":options.max_decoded_gib,"MaxFiles":options.max_files,"AllowIPs":options.allow_ips}),
    )?;
    ui::banner();
    ui::field("SFTP receiver", listener.local_addr()?);
    ui::field("Evidence directory", root.display());
    ui::field("Temporary username", &username);
    ui::field("Temporary password", password.as_str());
    ui::field("SSH fingerprint", &pin);
    ui::field("Expires UTC", expires_utc.to_rfc3339());
    ui::field(
        "Stored quota",
        format!("{} GiB / {} objects", options.max_gib, options.max_files),
    );
    ui::status(
        "Upload-only access. Credentials are revoked after the final delivery, expiry or Ctrl+C.",
    );
    io::stdout().flush()?;
    drop(password);
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
    let mut tasks = tokio::task::JoinSet::new();
    let mut tick = tokio::time::interval(Duration::from_millis(100));
    let reason = loop {
        tokio::select! {
            _=tick.tick()=>{let state=state.lock().map_err(|_|anyhow::anyhow!("Receiver state poisoned"))?;if state.final_object.is_some(){break "FinalDelivery";} else if !state.live(){break "Expired";}},
            signal=tokio::signal::ctrl_c()=>{signal?;break "Interrupted";},
            Some(_)=tasks.join_next(),if !tasks.is_empty()=>{},
            accept=listener.accept()=>{let (stream,peer)=accept?;
                if tasks.len()>=options.max_connections as usize || (!options.allow_ips.is_empty()&&!options.allow_ips.contains(&peer.ip())){continue;}
                let config=config.clone();let state=state.clone();
                tasks.spawn(async move {
                    let id=uuid::Uuid::new_v4();
                    let session=tokio::time::timeout(Duration::from_secs(15),server::run_stream(config,stream,SshSession{state:state.clone(),channel:None,accepted:false,opened:false})).await;
                    if let Ok(Ok(session))=session {
                        if let Ok(mut guard)=state.lock(){guard.sessions.insert(id,session.handle());}
                        let _=session.await;
                        if let Ok(mut guard)=state.lock(){guard.sessions.remove(&id);}
                    }
                });
            }
        }
    };
    drop(listener);
    let (final_object, closed, handles) = {
        let mut guard = state
            .lock()
            .map_err(|_| anyhow::anyhow!("Receiver state poisoned"))?;
        guard.revoked = true;
        (
            guard.final_object.clone(),
            guard.closed.clone(),
            guard.sessions.values().cloned().collect::<Vec<_>>(),
        )
    };
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
    tasks.abort_all();
    while tasks.join_next().await.is_some() {}
    ui::field("Credentials", "Revoked");
    if let Some((name, digest)) = final_object {
        ui::status("Reading back received objects and verifying hashes…");
        let inputs = crate::sftp_verify::Inputs {
            incoming,
            delivery: name.clone(),
            sha256: digest.clone(),
            max_decoded_bytes: options
                .max_decoded_gib
                .checked_mul(1 << 30)
                .context("Decoded quota overflow")?,
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
                Err(error).context("Server readback failed; all received evidence was retained")
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
            open: 0,
            max_bytes: 1024 * 1024,
            max_files: 100,
            reserve: 0,
            closed: BTreeMap::new(),
            sessions: HashMap::new(),
            failures: VecDeque::new(),
            io_failed: false,
        }));
        (
            root,
            Files {
                state,
                handles: HashMap::new(),
                initialized: false,
            },
        )
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
