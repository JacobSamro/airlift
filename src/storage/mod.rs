//! Tigris (S3-compatible) object storage adapter.
//!
//! Update assets are content-addressable and namespaced per org:
//! `orgs/<org_id>/assets/sha256/<hex>`. In-progress uploads land at a temporary
//! key and are server-side-copied to their final content-addressed key once the
//! digest is verified, so asset bytes are never re-uploaded.

#![allow(dead_code)] // parts are wired up by later build phases
use std::time::Duration;

use aws_sdk_s3::config::{Credentials, Region};
use aws_sdk_s3::presigning::PresigningConfig;
use aws_sdk_s3::primitives::ByteStream;
use aws_sdk_s3::types::{CompletedMultipartUpload, CompletedPart};
use aws_sdk_s3::Client;

use crate::config::StorageConfig;
use crate::error::{Error, Result};

/// Handle to the object store.
#[derive(Clone)]
pub struct Storage {
    /// Client for the real S3 API (uploads, copy, delete, head).
    client: Client,
    /// Client whose endpoint is the CDN/custom domain; used to sign pull
    /// redirects so the URL is served from (and valid for) that host. Equals
    /// `client` when no CDN URL is configured.
    presign_client: Client,
    bucket: String,
    presign_ttl: Duration,
}

fn map_s3<E: std::fmt::Display>(ctx: &str, e: E) -> Error {
    Error::Other(anyhow::anyhow!("storage {ctx}: {e}"))
}

impl Storage {
    fn build_client(cfg: &StorageConfig, endpoint: &str) -> Client {
        let creds = Credentials::new(
            cfg.access_key_id.clone(),
            cfg.secret_access_key.clone(),
            None,
            None,
            "airlift",
        );
        let s3_cfg = aws_sdk_s3::Config::builder()
            .behavior_version(aws_sdk_s3::config::BehaviorVersion::latest())
            .region(Region::new(cfg.region.clone()))
            .endpoint_url(endpoint)
            .credentials_provider(creds)
            .force_path_style(cfg.force_path_style)
            // Only add/validate flexible checksums when an operation requires
            // them. Keeps wire traffic lean and maximizes compatibility with
            // S3-compatible stores (Tigris, RustFS, MinIO) that may not support
            // the SDK's newer default CRC32 trailers.
            .request_checksum_calculation(
                aws_sdk_s3::config::RequestChecksumCalculation::WhenRequired,
            )
            .response_checksum_validation(
                aws_sdk_s3::config::ResponseChecksumValidation::WhenRequired,
            )
            .build();
        Client::from_conf(s3_cfg)
    }

    /// Build the S3 client(s) for the configured Tigris endpoint (+ optional CDN).
    pub async fn new(cfg: &StorageConfig) -> Result<Self> {
        let client = Self::build_client(cfg, &cfg.endpoint);
        let presign_client = if cfg.cdn_url.trim().is_empty() {
            client.clone()
        } else {
            Self::build_client(cfg, cfg.cdn_url.trim())
        };

        Ok(Self {
            client,
            presign_client,
            bucket: cfg.bucket.clone(),
            presign_ttl: Duration::from_secs(cfg.presign_ttl_secs),
        })
    }

    /// Final content-addressed key for an asset (`sha256` = hex digest).
    pub fn asset_key(org_id: &str, sha256: &str) -> String {
        format!("orgs/{org_id}/assets/sha256/{sha256}")
    }

    /// Key for a launch bundle's sourcemap (private; never presigned for
    /// devices — only the server reads it, to symbolicate stacks).
    pub fn sourcemap_key(org_id: &str, bundle_sha256: &str) -> String {
        format!("orgs/{org_id}/sourcemaps/{bundle_sha256}.map")
    }

    /// Key for a bsdiff patch between two launch bundles.
    pub fn patch_key(org_id: &str, from_sha256: &str, to_sha256: &str) -> String {
        format!("orgs/{org_id}/patches/{from_sha256}-{to_sha256}")
    }

    /// Temporary key for an in-progress upload.
    pub fn upload_key(org_id: &str, upload_id: &str) -> String {
        format!("orgs/{org_id}/_uploads/{upload_id}")
    }

    // ── blob existence / delivery ──────────────────────────────────

    /// Whether an object exists, returning its size. (Storage-level probe;
    /// the hot path uses the DB index instead.)
    #[allow(dead_code)]
    pub async fn head(&self, key: &str) -> Result<Option<i64>> {
        match self
            .client
            .head_object()
            .bucket(&self.bucket)
            .key(key)
            .send()
            .await
        {
            Ok(out) => Ok(Some(out.content_length().unwrap_or(0))),
            Err(e) => {
                if e.as_service_error()
                    .map(|s| s.is_not_found())
                    .unwrap_or(false)
                {
                    Ok(None)
                } else {
                    Err(map_s3("head", e.into_service_error()))
                }
            }
        }
    }

    /// Presigned GET URL handed to expo-updates clients (served from Tigris/CDN).
    pub async fn presign_get(&self, key: &str) -> Result<String> {
        let cfg =
            PresigningConfig::expires_in(self.presign_ttl).map_err(|e| map_s3("presign cfg", e))?;
        let req = self
            .presign_client
            .get_object()
            .bucket(&self.bucket)
            .key(key)
            .presigned(cfg)
            .await
            .map_err(|e| map_s3("presign", e))?;
        Ok(req.uri().to_string())
    }

    /// Fetch a whole object into memory (used by the patch worker; bundles
    /// are MB-scale).
    pub async fn get(&self, key: &str) -> Result<Vec<u8>> {
        let out = self
            .client
            .get_object()
            .bucket(&self.bucket)
            .key(key)
            .send()
            .await
            .map_err(|e| map_s3("get", e))?;
        let data = out
            .body
            .collect()
            .await
            .map_err(|e| map_s3("get body", e))?;
        Ok(data.into_bytes().to_vec())
    }

    /// Open an object as a streaming response body (plus its length when
    /// known), without buffering it. A missing object fails here, before any
    /// bytes are sent, so callers can still fall back.
    pub async fn get_stream(&self, key: &str) -> Result<(Option<i64>, axum::body::Body)> {
        let out = self
            .client
            .get_object()
            .bucket(&self.bucket)
            .key(key)
            .send()
            .await
            .map_err(|e| map_s3("get", e))?;
        let len = out.content_length();
        let reader = out.body.into_async_read();
        let body = axum::body::Body::from_stream(tokio_util::io::ReaderStream::new(reader));
        Ok((len, body))
    }

    pub async fn delete(&self, key: &str) -> Result<()> {
        self.client
            .delete_object()
            .bucket(&self.bucket)
            .key(key)
            .send()
            .await
            .map_err(|e| map_s3("delete", e))?;
        Ok(())
    }

    // ── multipart upload ───────────────────────────────────────────

    pub async fn create_multipart(&self, key: &str) -> Result<String> {
        let out = self
            .client
            .create_multipart_upload()
            .bucket(&self.bucket)
            .key(key)
            .send()
            .await
            .map_err(|e| map_s3("create_multipart", e))?;
        out.upload_id()
            .map(|s| s.to_string())
            .ok_or_else(|| map_s3("create_multipart", "missing upload id"))
    }

    /// Upload one part, returning the completed-part descriptor.
    pub async fn upload_part(
        &self,
        key: &str,
        upload_id: &str,
        part_number: i32,
        body: Vec<u8>,
    ) -> Result<CompletedPart> {
        let out = self
            .client
            .upload_part()
            .bucket(&self.bucket)
            .key(key)
            .upload_id(upload_id)
            .part_number(part_number)
            .body(ByteStream::from(body))
            .send()
            .await
            .map_err(|e| map_s3("upload_part", e))?;
        Ok(CompletedPart::builder()
            .set_e_tag(out.e_tag().map(|s| s.to_string()))
            .part_number(part_number)
            .build())
    }

    pub async fn complete_multipart(
        &self,
        key: &str,
        upload_id: &str,
        parts: Vec<CompletedPart>,
    ) -> Result<()> {
        let completed = CompletedMultipartUpload::builder()
            .set_parts(Some(parts))
            .build();
        self.client
            .complete_multipart_upload()
            .bucket(&self.bucket)
            .key(key)
            .upload_id(upload_id)
            .multipart_upload(completed)
            .send()
            .await
            .map_err(|e| map_s3("complete_multipart", e))?;
        Ok(())
    }

    pub async fn abort_multipart(&self, key: &str, upload_id: &str) -> Result<()> {
        self.client
            .abort_multipart_upload()
            .bucket(&self.bucket)
            .key(key)
            .upload_id(upload_id)
            .send()
            .await
            .map_err(|e| map_s3("abort_multipart", e))?;
        Ok(())
    }

    /// Server-side copy (used to move a verified upload to its final key).
    pub async fn copy(&self, from_key: &str, to_key: &str) -> Result<()> {
        let source = format!("{}/{}", self.bucket, from_key);
        self.client
            .copy_object()
            .bucket(&self.bucket)
            .key(to_key)
            .copy_source(&source)
            .send()
            .await
            .map_err(|e| map_s3("copy", e))?;
        Ok(())
    }

    /// Store a small object in a single request (used for small assets).
    pub async fn put(&self, key: &str, body: Vec<u8>) -> Result<()> {
        self.client
            .put_object()
            .bucket(&self.bucket)
            .key(key)
            .body(ByteStream::from(body))
            .send()
            .await
            .map_err(|e| map_s3("put", e))?;
        Ok(())
    }
}
