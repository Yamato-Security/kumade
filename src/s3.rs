// Copyright (C) 2026 Shirofune Security Co., Ltd.
// SPDX-License-Identifier: RPL-1.5

//! Direct delivery to a general-purpose S3 bucket. Ordinary source bytes are
//! read once. The only rewindable upload buffer is the current multipart part.
use crate::{
    model::{Record, sha256},
    paths,
    sftp::{Object, RemoteWrite, Store, Target},
};
use anyhow::{Context, Result, ensure};
use aws_sdk_s3::{
    Client,
    config::{
        BehaviorVersion, ConfigBag, Credentials, Intercept, Region, RuntimeComponents,
        interceptors::BeforeTransmitInterceptorContextRef, retry::RetryConfig,
        timeout::TimeoutConfig,
    },
    error::{BoxError, ProvideErrorMetadata, SdkError},
    primitives::ByteStream,
    types::{ChecksumAlgorithm, CompletedMultipartUpload, CompletedPart},
};
use aws_smithy_http_client::{Builder as HttpBuilder, tls};
use base64::{Engine, engine::general_purpose::STANDARD};
use sha2::{Digest, Sha256};
use std::{
    env,
    io::{self, Read, Write},
    path::PathBuf,
    sync::{
        Arc, OnceLock,
        atomic::{AtomicU32, Ordering},
    },
    time::Duration,
};
use url::Url;
use uuid::Uuid;

#[derive(clap::Args, Clone)]
pub struct S3Args {
    /// Stream to s3://BUCKET/PREFIX using temporary AWS credentials
    #[arg(long, conflicts_with_all = ["output", "e01", "vhdx", "sftp"])]
    pub s3: Option<Location>,
    #[command(flatten)]
    pub connection: ConnectionArgs,
    /// Existing protected parent for local collection metadata
    #[arg(long, requires = "s3")]
    pub s3_staging_dir: Option<PathBuf>,
    /// Multipart buffer per active stream (MiB, default 8, maximum 10,000 parts/object)
    #[arg(long, requires="s3", value_parser=clap::value_parser!(u16).range(5..=256))]
    pub s3_part_mib: Option<u16>,
}

#[derive(clap::Args, Clone)]
pub struct ConnectionArgs {
    /// AWS region (default: AWS_REGION, AWS_DEFAULT_REGION or us-east-1)
    #[arg(long, requires = "s3")]
    pub s3_region: Option<String>,
    /// Explicit S3-compatible HTTPS endpoint (HTTP allowed on loopback for testing)
    #[arg(long, requires="s3", value_parser=parse_endpoint)]
    pub s3_endpoint: Option<Url>,
}

#[derive(clap::Args)]
pub struct VerifyArgs {
    /// Full s3:// URI of the final UUID-delivery.json printed by the collector
    #[arg(long)]
    pub s3: Location,
    #[command(flatten)]
    pub connection: ConnectionArgs,
    /// SHA-256 recorded independently from the collector
    #[arg(long)]
    pub sha256: String,
    /// New local receipt file
    #[arg(long)]
    pub receipt: PathBuf,
    /// Optional new local directory for restored evidence
    #[arg(long)]
    pub restore: Option<PathBuf>,
    /// Maximum total decoded GiB
    #[arg(long, default_value_t=1024, value_parser=clap::value_parser!(u64).range(1..=1048576))]
    pub max_decoded_gib: u64,
}

fn parse_endpoint(value: &str) -> Result<Url> {
    let url = Url::parse(value)?;
    let loopback = match url.host() {
        Some(url::Host::Ipv4(ip)) => ip.is_loopback(),
        Some(url::Host::Ipv6(ip)) => ip.is_loopback(),
        _ => false,
    };
    ensure!(
        url.has_host()
            && url.username().is_empty()
            && url.password().is_none()
            && url.path() == "/"
            && url.query().is_none()
            && url.fragment().is_none()
            && (url.scheme() == "https" || (url.scheme() == "http" && loopback)),
        "Use an HTTPS endpoint origin, or an HTTP loopback IP for testing"
    );
    Ok(url)
}

#[derive(Clone, Debug)]
pub struct Location {
    bucket: String,
    prefix: String,
}
impl std::str::FromStr for Location {
    type Err = anyhow::Error;
    fn from_str(value: &str) -> Result<Self> {
        let path = value
            .strip_prefix("s3://")
            .context("Use s3://BUCKET/PREFIX")?;
        let (bucket, prefix) = path.split_once('/').unwrap_or((path, ""));
        let valid_edge = |b: u8| b.is_ascii_lowercase() || b.is_ascii_digit();
        ensure!(
            (3..=63).contains(&bucket.len())
                && bucket
                    .bytes()
                    .all(|b| valid_edge(b) || b == b'-' || b == b'.')
                && valid_edge(bucket.as_bytes()[0])
                && valid_edge(bucket.as_bytes()[bucket.len() - 1])
                && !bucket.contains("..")
                && bucket.parse::<std::net::Ipv4Addr>().is_err(),
            "Invalid S3 bucket name"
        );
        ensure!(!prefix.starts_with('/'), "Empty component in S3 prefix");
        let prefix = prefix.strip_suffix('/').unwrap_or(prefix);
        ensure!(
            prefix.len() <= 1024
                && !prefix
                    .chars()
                    .any(|c| c.is_control() || matches!(c, '\\' | '?' | '#'))
                && (prefix.is_empty()
                    || prefix
                        .split('/')
                        .all(|p| !p.is_empty() && p != "." && p != "..")),
            "Invalid S3 key prefix"
        );
        Ok(Self {
            bucket: bucket.into(),
            prefix: prefix.into(),
        })
    }
}
impl Location {
    fn key(&self, name: &str) -> Result<String> {
        let key = if self.prefix.is_empty() {
            name.into()
        } else {
            format!("{}/{name}", self.prefix)
        };
        ensure!(key.len() <= 1024, "S3 key exceeds 1024 bytes");
        Ok(key)
    }
    fn uri(&self) -> String {
        format!("s3://{}/{}", self.bucket, self.prefix)
    }
}

/// Counts transmissions of one request. When S3 stores a create-only write but its
/// response is lost, the SDK's automatic retry is refused because the key now exists.
#[derive(Clone, Debug, Default)]
struct Attempts(Arc<AtomicU32>);
impl Intercept for Attempts {
    fn name(&self) -> &'static str {
        "KumadeAttempts"
    }
    fn read_before_attempt(
        &self,
        _: &BeforeTransmitInterceptorContextRef<'_>,
        _: &RuntimeComponents,
        _: &mut ConfigBag,
    ) -> Result<(), BoxError> {
        self.0.fetch_add(1, Ordering::Relaxed);
        Ok(())
    }
}
impl Attempts {
    /// Accept a conflict only after this request was retried, because an earlier attempt
    /// may have been stored before its acknowledgement was lost. A conflict on the first
    /// attempt is a genuine collision. verify-s3 checks every stored hash either way.
    fn retried_conflict<E: ProvideErrorMetadata, R>(
        &self,
        error: &SdkError<E, R>,
        codes: &[&str],
    ) -> bool {
        self.0.load(Ordering::Relaxed) > 1
            && error
                .as_service_error()
                .and_then(|e| e.code())
                .is_some_and(|code| codes.contains(&code))
    }
}

#[derive(Clone)]
pub(crate) struct Bucket {
    location: Location,
    client: Client,
    runtime: Arc<tokio::runtime::Runtime>,
    part_bytes: usize,
    // Once a remote write has failed, withhold the final descriptor and retain local metadata.
    upload_error: Arc<OnceLock<String>>,
}
impl Bucket {
    fn connect(
        location: Location,
        args: &ConnectionArgs,
        part_bytes: usize,
        collecting: bool,
    ) -> Result<Self> {
        // Explicit environment credentials avoid invoking credential_process or inspecting
        // an acquired host's profiles; no endpoint is taken from that host's AWS config.
        let token = env::var("AWS_SESSION_TOKEN").ok().filter(|s| !s.is_empty());
        ensure!(
            !collecting || token.is_some(),
            "Collection requires temporary credentials with AWS_SESSION_TOKEN"
        );
        let credential = |name| {
            env::var(name)
                .ok()
                .filter(|s| !s.is_empty())
                .with_context(|| format!("Missing {name}"))
        };
        let creds = Credentials::new(
            credential("AWS_ACCESS_KEY_ID")?,
            credential("AWS_SECRET_ACCESS_KEY")?,
            token,
            None,
            "Kumade",
        );
        let region = args
            .s3_region
            .clone()
            .or_else(|| env::var("AWS_REGION").ok())
            .or_else(|| env::var("AWS_DEFAULT_REGION").ok())
            .unwrap_or_else(|| "us-east-1".into());
        ensure!(
            !region.is_empty()
                && region.len() <= 64
                && region
                    .bytes()
                    .all(|b| b.is_ascii_lowercase() || b.is_ascii_digit() || b == b'-'),
            "Invalid AWS region"
        );
        let runtime = Arc::new(
            tokio::runtime::Builder::new_multi_thread()
                .worker_threads(2)
                .enable_all()
                .build()?,
        );
        let http = HttpBuilder::new()
            .tls_provider(tls::Provider::Rustls(
                tls::rustls_provider::CryptoMode::Ring,
            ))
            .build_https();
        let mut config = aws_sdk_s3::Config::builder()
            .behavior_version(BehaviorVersion::latest())
            .region(Region::new(region))
            .credentials_provider(creds)
            .http_client(http)
            .retry_config(RetryConfig::standard().with_max_attempts(5))
            .timeout_config(
                TimeoutConfig::builder()
                    .connect_timeout(Duration::from_secs(15))
                    .operation_attempt_timeout(Duration::from_secs(300))
                    .build(),
            );
        if let Some(endpoint) = &args.s3_endpoint {
            config = config
                .endpoint_url(endpoint.as_str())
                .force_path_style(true);
        }
        Ok(Self {
            client: Client::from_conf(config.build()),
            location,
            runtime,
            part_bytes,
            upload_error: Arc::default(),
        })
    }
    fn check_upload(&self) -> Result<()> {
        if let Some(reason) = self.upload_error.get() {
            anyhow::bail!("S3 delivery interrupted: {reason}");
        }
        Ok(())
    }
    fn put(&self, key: &str, data: Vec<u8>) -> Result<()> {
        let checksum = STANDARD.encode(Sha256::digest(&data));
        let attempts = Attempts::default();
        match self.runtime.block_on(
            self.client
                .put_object()
                .bucket(&self.location.bucket)
                .key(key)
                .if_none_match("*")
                .checksum_sha256(checksum)
                .body(data.into())
                .customize()
                .interceptor(attempts.clone())
                .send(),
        ) {
            Ok(_) => Ok(()),
            Err(e) if attempts.retried_conflict(&e, &["PreconditionFailed"]) => Ok(()),
            Err(e) => Err(e).with_context(|| format!("Create-only S3 PUT failed for {key}")),
        }
    }
    pub(crate) fn open(&self, name: &str) -> Result<Box<dyn Read>> {
        crate::sftp::validate_object_name(name)?;
        let key = self.location.key(name)?;
        let response = self
            .runtime
            .block_on(
                self.client
                    .get_object()
                    .bucket(&self.location.bucket)
                    .key(&key)
                    .send(),
            )
            .with_context(|| format!("S3 readback failed for {key}"))?;
        Ok(Box::new(tokio_util::io::SyncIoBridge::new_with_handle(
            response.body.into_async_read(),
            self.runtime.handle().clone(),
        )))
    }
}
impl Store for Bucket {
    fn create(&self, name: &str, _: u32) -> Result<Box<dyn RemoteWrite>> {
        crate::sftp::validate_object_name(name)?;
        self.check_upload()?;
        Ok(Box::new(Upload {
            bucket: self.clone(),
            key: self.location.key(name)?,
            buffer: Vec::new(),
            id: None,
            parts: Vec::new(),
            failure: None,
        }))
    }
    fn checkpoint(&self, record: &Record, object: Option<&Object>) -> Result<()> {
        self.check_upload()?;
        let key = self.location.key(&format!(
            "checkpoints/{}.json",
            sha256(record.observation_id.as_bytes())
        ))?;
        self.put(
            &key,
            serde_json::to_vec(&serde_json::json!({"Record":record, "Object":object}))?,
        )
    }
}

struct Upload {
    bucket: Bucket,
    key: String,
    buffer: Vec<u8>,
    id: Option<String>,
    parts: Vec<CompletedPart>,
    failure: Option<String>,
}
impl Upload {
    fn part(&mut self) -> Result<()> {
        ensure!(
            self.parts.len() < 10_000,
            "S3 object exceeds 10,000 parts; increase --s3-part-mib for this collection"
        );
        let s = &self.bucket;
        if self.id.is_none() {
            let response = s
                .runtime
                .block_on(
                    s.client
                        .create_multipart_upload()
                        .bucket(&s.location.bucket)
                        .key(&self.key)
                        .checksum_algorithm(ChecksumAlgorithm::Sha256)
                        .send(),
                )
                .context("Initiate S3 multipart upload")?;
            self.id = Some(response.upload_id.context("Missing S3 upload ID")?);
        }
        let data = std::mem::take(&mut self.buffer);
        let checksum = STANDARD.encode(Sha256::digest(&data));
        let number = (self.parts.len() + 1) as i32;
        // ByteStream::from(Vec) is replayable by the SDK, including a dropped response.
        let part = s
            .runtime
            .block_on(
                s.client
                    .upload_part()
                    .bucket(&s.location.bucket)
                    .key(&self.key)
                    .set_upload_id(self.id.clone())
                    .part_number(number)
                    .checksum_sha256(&checksum)
                    .body(ByteStream::from(data))
                    .send(),
            )
            .with_context(|| format!("Upload S3 part {number}"))?;
        ensure!(
            part.checksum_sha256
                .as_deref()
                .is_none_or(|actual| actual == checksum),
            "S3 part checksum mismatch"
        );
        self.parts.push(
            CompletedPart::builder()
                .part_number(number)
                .e_tag(part.e_tag.context("Missing S3 part ETag")?)
                .checksum_sha256(checksum)
                .build(),
        );
        Ok(())
    }
}
impl Write for Upload {
    fn write(&mut self, data: &[u8]) -> io::Result<usize> {
        if let Some(error) = &self.failure {
            return Err(io::Error::other(error.clone()));
        }
        if data.is_empty() {
            return Ok(0);
        }
        // Wait for another byte before promoting an exactly-part-sized single PUT.
        if self.buffer.len() == self.bucket.part_bytes
            && let Err(e) = self.part()
        {
            self.failure = Some(format!("{e:#}"));
            self.bucket.upload_error.get_or_init(|| format!("{e:#}"));
            return Err(io::Error::other(format!("{e:#}")));
        }
        let n = data.len().min(self.bucket.part_bytes - self.buffer.len());
        self.buffer.extend_from_slice(&data[..n]);
        Ok(n)
    }
    fn flush(&mut self) -> io::Result<()> {
        Ok(())
    } // Only complete objects are visible in S3.
}
impl Upload {
    fn complete(&mut self) -> Result<()> {
        if let Some(error) = &self.failure {
            anyhow::bail!("{error}");
        }
        if self.id.is_none() {
            return self.bucket.put(&self.key, std::mem::take(&mut self.buffer));
        }
        if !self.buffer.is_empty() {
            self.part()?;
        }
        let s = &self.bucket;
        let parts = CompletedMultipartUpload::builder()
            .set_parts(Some(std::mem::take(&mut self.parts)))
            .build();
        let attempts = Attempts::default();
        match s.runtime.block_on(
            s.client
                .complete_multipart_upload()
                .bucket(&s.location.bucket)
                .key(&self.key)
                .set_upload_id(self.id.clone())
                .if_none_match("*")
                .multipart_upload(parts)
                .customize()
                .interceptor(attempts.clone())
                .send(),
        ) {
            Ok(_) => {}
            // A completed upload ID can also be reported as no longer existing.
            Err(e) if attempts.retried_conflict(&e, &["PreconditionFailed", "NoSuchUpload"]) => {}
            Err(e) => {
                return Err(e).with_context(|| {
                    format!(
                        "Create-only S3 multipart completion failed for {}",
                        self.key
                    )
                });
            }
        }
        self.id = None;
        Ok(())
    }
}
impl RemoteWrite for Upload {
    fn finish(mut self: Box<Self>) -> Result<()> {
        let result = self.complete();
        if let Err(e) = &result {
            self.bucket.upload_error.get_or_init(|| format!("{e:#}"));
        }
        result
    }
}
impl Drop for Upload {
    fn drop(&mut self) {
        if let Some(id) = self.id.take() {
            let s = &self.bucket;
            // Aborting an unfinished multipart upload does not delete a completed object.
            // A bucket lifecycle rule also covers power loss or expired credentials.
            let _ = s.runtime.block_on(
                s.client
                    .abort_multipart_upload()
                    .bucket(&s.location.bucket)
                    .key(&self.key)
                    .upload_id(id)
                    .send(),
            );
        }
    }
}

pub fn connect(args: &S3Args, computer: &str, started: &str) -> Result<(Arc<Target>, String)> {
    let mut location = args.s3.clone().context("Missing S3 destination")?;
    let id = Uuid::new_v4();
    location.prefix = location.key(&format!(
        "{}_{id}",
        paths::run_name(computer, started)?.replace('#', "%23")
    ))?;
    // Validate the longest expected key before collecting evidence.
    location.key(&format!("{id}-payload-{}", "0".repeat(64)))?;
    let uri = format!("{}/{}-delivery.json", location.uri(), id);
    let bucket = Bucket::connect(
        location,
        &args.connection,
        usize::from(args.s3_part_mib.unwrap_or(8)) << 20,
        true,
    )?;
    bucket.put(
        &bucket.location.key("started.json")?,
        serde_json::to_vec(&serde_json::json!({
            "DeliveryId":id.to_string(),"StartedUtc":started,"Computer":computer
        }))?,
    )?;
    let target = Target::new_delivery(Arc::new(bucket), true, id, "KumadeS3Delivery")?;
    Ok((target, uri))
}

pub fn verify(args: &VerifyArgs) -> Result<u8> {
    let mut location = args.s3.clone();
    let (prefix, name) = location
        .prefix
        .rsplit_once('/')
        .context("Use the full delivery URI printed by the collector")?;
    let delivery = name.to_owned();
    let id = Uuid::parse_str(
        name.strip_suffix("-delivery.json")
            .context("Expected UUID-delivery.json")?,
    )?;
    ensure!(
        delivery == format!("{id}-delivery.json"),
        "Invalid delivery object name"
    );
    location.prefix = prefix.to_owned();
    let bucket = Bucket::connect(location, &args.connection, 0, false)?;
    crate::sftp_verify::run_s3(args, &bucket, &delivery)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn destination_and_endpoint_validation_preserves_the_requested_scope() {
        for invalid in [
            "https://bucket/path",
            "s3://",
            "s3://a",
            "s3://user@bucket/b",
            "s3://127.0.0.1/c",
            "s3://bucket//",
            "s3://bucket/a/../b",
            "s3://bucket/a//b",
            "s3://bucket/p?query",
        ] {
            assert!(invalid.parse::<Location>().is_err(), "{invalid}");
        }
        let location: Location = "s3://case-bucket/incident/host/".parse().unwrap();
        assert_eq!(location.key("item").unwrap(), "incident/host/item");
        assert!(location.key(&"a".repeat(1024)).is_err());
        for invalid in [
            "http://collector.example",
            "https://name:secret@host",
            "https://host/path",
            "file:///tmp",
        ] {
            assert!(parse_endpoint(invalid).is_err(), "{invalid}");
        }
        assert!(parse_endpoint("http://127.0.0.1:9000").is_ok());
        assert!(parse_endpoint("https://storage.example").is_ok());
    }
}
