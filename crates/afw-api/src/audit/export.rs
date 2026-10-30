//! Export of the audit chain head ("anchor": `{seq, hash, at}`) to immutable storage (EF-53):
//! an append-only JSON-lines file (`fsync` after each line) and, optionally, an S3 object
//! written with Object Lock in COMPLIANCE mode. `GET /audit/verify` checks the chain against
//! these anchors, which detects a complete rewrite of the chain in the database.

use std::io::Write;
use std::path::{Path, PathBuf};
use std::time::Duration;

use base64::Engine;
use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};

use super::sigv4;
use crate::AppState;
use crate::error::ApiError;

/// Name of the anchors file in `AFW_AUDIT_EXPORT_DIR`.
pub const ANCHORS_FILE: &str = "audit-anchors.jsonl";

/// Exported chain head.
#[derive(Serialize, Deserialize, Clone, Debug, PartialEq)]
pub struct Anchor {
    pub seq: i64,
    pub hash: String,
    /// Export time.
    pub at: DateTime<Utc>,
}

/// S3-compatible target (`AFW_AUDIT_S3_*`). The bucket must have Object Lock enabled.
#[derive(Clone, PartialEq)]
pub struct S3Config {
    /// `AFW_AUDIT_S3_ENDPOINT`, e.g. `https://s3.eu-west-3.amazonaws.com` (path-style URLs).
    pub endpoint: String,
    pub bucket: String,
    /// `AFW_AUDIT_S3_REGION`, default `us-east-1`.
    pub region: String,
    pub access_key_id: String,
    pub secret_access_key: String,
    /// `AFW_AUDIT_S3_PREFIX`, default empty.
    pub prefix: String,
    /// `AFW_AUDIT_S3_RETENTION_DAYS`, default 365.
    pub retention_days: u32,
}

impl std::fmt::Debug for S3Config {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("S3Config")
            .field("endpoint", &self.endpoint)
            .field("bucket", &self.bucket)
            .field("region", &self.region)
            .field("prefix", &self.prefix)
            .field("retention_days", &self.retention_days)
            .finish_non_exhaustive()
    }
}

/// Export settings.
#[derive(Clone, Debug, Default, PartialEq)]
pub struct AuditExportConfig {
    /// `AFW_AUDIT_EXPORT_DIR`: directory of the append-only anchors file.
    pub dir: Option<PathBuf>,
    pub s3: Option<S3Config>,
    /// `AFW_AUDIT_EXPORT_INTERVAL` (seconds, or with an `s`/`m`/`h` suffix), default 1 h;
    /// zero disables the periodic task.
    pub interval: Duration,
}

/// Parses `3600`, `90s`, `15m`, `1h`.
pub fn parse_interval(v: &str) -> Option<Duration> {
    let v = v.trim();
    let (num, mult) = match v.chars().last()? {
        's' => (&v[..v.len() - 1], 1),
        'm' => (&v[..v.len() - 1], 60),
        'h' => (&v[..v.len() - 1], 3600),
        _ => (v, 1),
    };
    num.trim()
        .parse::<u64>()
        .ok()
        .map(|n| Duration::from_secs(n * mult))
}

impl AuditExportConfig {
    pub fn from_env() -> anyhow::Result<Self> {
        let var = |k: &str| std::env::var(k).ok().filter(|v| !v.trim().is_empty());
        let interval = match var("AFW_AUDIT_EXPORT_INTERVAL") {
            None => Duration::from_secs(3600),
            Some(v) => parse_interval(&v)
                .ok_or_else(|| anyhow::anyhow!("invalid AFW_AUDIT_EXPORT_INTERVAL {v:?}"))?,
        };
        let s3 = match (
            var("AFW_AUDIT_S3_ENDPOINT"),
            var("AFW_AUDIT_S3_BUCKET"),
            var("AFW_AUDIT_S3_ACCESS_KEY_ID"),
            var("AFW_AUDIT_S3_SECRET_ACCESS_KEY"),
        ) {
            (Some(endpoint), Some(bucket), Some(access_key_id), Some(secret_access_key)) => {
                Some(S3Config {
                    endpoint: endpoint.trim_end_matches('/').to_owned(),
                    bucket,
                    region: var("AFW_AUDIT_S3_REGION").unwrap_or_else(|| "us-east-1".into()),
                    access_key_id,
                    secret_access_key,
                    prefix: var("AFW_AUDIT_S3_PREFIX").unwrap_or_default(),
                    retention_days: var("AFW_AUDIT_S3_RETENTION_DAYS")
                        .map(|v| v.parse())
                        .transpose()
                        .map_err(|_| {
                            anyhow::anyhow!("AFW_AUDIT_S3_RETENTION_DAYS must be an integer")
                        })?
                        .unwrap_or(365),
                })
            }
            (None, None, None, None) => None,
            _ => anyhow::bail!(
                "AFW_AUDIT_S3_ENDPOINT, _BUCKET, _ACCESS_KEY_ID and _SECRET_ACCESS_KEY go together"
            ),
        };
        Ok(Self {
            dir: var("AFW_AUDIT_EXPORT_DIR").map(PathBuf::from),
            s3,
            interval,
        })
    }

    pub fn has_target(&self) -> bool {
        self.dir.is_some() || self.s3.is_some()
    }
}

fn pool(state: &AppState) -> Result<&sqlx::PgPool, ApiError> {
    state
        .pool
        .as_ref()
        .ok_or_else(|| ApiError::Internal("no database configured".into()))
}

fn append_line(dir: &Path, line: &str) -> std::io::Result<()> {
    std::fs::create_dir_all(dir)?;
    let mut opts = std::fs::OpenOptions::new();
    opts.create(true).append(true);
    #[cfg(unix)]
    std::os::unix::fs::OpenOptionsExt::mode(&mut opts, 0o640);
    let mut f = opts.open(dir.join(ANCHORS_FILE))?;
    f.write_all(line.as_bytes())?;
    f.write_all(b"\n")?;
    f.sync_all()
}

/// Anchors of the file (malformed lines are reported, never ignored silently).
pub fn read_file_anchors(dir: &Path) -> Result<Vec<Anchor>, ApiError> {
    let path = dir.join(ANCHORS_FILE);
    let content = match std::fs::read_to_string(&path) {
        Ok(c) => c,
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => return Ok(vec![]),
        Err(e) => {
            return Err(ApiError::Internal(format!(
                "reading {}: {e}",
                path.display()
            )));
        }
    };
    content
        .lines()
        .filter(|l| !l.trim().is_empty())
        .map(|l| {
            serde_json::from_str(l).map_err(|e| {
                ApiError::Internal(format!("malformed anchor in {}: {e}", path.display()))
            })
        })
        .collect()
}

async fn put_s3(cfg: &S3Config, anchor: &Anchor, body: &[u8]) -> Result<String, ApiError> {
    let key = format!(
        "{}audit-anchor-{:020}-{}.json",
        cfg.prefix,
        anchor.seq,
        anchor.at.format("%Y%m%dT%H%M%SZ")
    );
    let path: String = std::iter::once(cfg.bucket.as_str())
        .chain(key.split('/'))
        .map(sigv4::uri_encode_segment)
        .collect::<Vec<_>>()
        .join("/");
    let url = reqwest::Url::parse(&format!("{}/{path}", cfg.endpoint))
        .map_err(|e| ApiError::Internal(format!("invalid S3 endpoint: {e}")))?;
    let host = match (url.host_str(), url.port()) {
        (Some(h), Some(p)) => format!("{h}:{p}"),
        (Some(h), None) => h.to_owned(),
        _ => return Err(ApiError::Internal("S3 endpoint without host".into())),
    };
    let digest = Sha256::digest(body);
    let payload_hex = hex::encode(digest);
    let retain_until = (Utc::now() + chrono::Duration::days(i64::from(cfg.retention_days)))
        .to_rfc3339_opts(chrono::SecondsFormat::Secs, true);
    let now = Utc::now();
    let headers: Vec<(String, String)> = vec![
        ("content-type".into(), "application/json".into()),
        ("host".into(), host),
        (
            "x-amz-checksum-sha256".into(),
            base64::engine::general_purpose::STANDARD.encode(digest),
        ),
        ("x-amz-content-sha256".into(), payload_hex.clone()),
        ("x-amz-date".into(), sigv4::amz_date(now)),
        ("x-amz-object-lock-mode".into(), "COMPLIANCE".into()),
        ("x-amz-object-lock-retain-until-date".into(), retain_until),
        ("x-amz-sdk-checksum-algorithm".into(), "SHA256".into()),
    ];
    let auth = sigv4::authorization(
        &sigv4::SigningParams {
            access_key_id: &cfg.access_key_id,
            secret_access_key: &cfg.secret_access_key,
            region: &cfg.region,
            service: "s3",
            at: now,
        },
        "PUT",
        &format!("/{path}"),
        &headers,
        &payload_hex,
    );
    let client = reqwest::Client::builder()
        .timeout(Duration::from_secs(30))
        .build()
        .map_err(|e| ApiError::Internal(e.to_string()))?;
    let mut req = client
        .put(url)
        .header("authorization", auth)
        .body(body.to_vec());
    for (k, v) in headers.iter().filter(|(k, _)| k != "host") {
        req = req.header(k, v);
    }
    let res = req
        .send()
        .await
        .map_err(|e| ApiError::Internal(format!("S3 export: {e}")))?;
    if !res.status().is_success() {
        let status = res.status();
        let text = res.text().await.unwrap_or_default();
        return Err(ApiError::Internal(format!(
            "S3 export refused ({status}): {}",
            text.chars().take(500).collect::<String>()
        )));
    }
    Ok(key)
}

/// Exports the current chain head to every configured target and records it.
pub async fn anchor_now(state: &AppState) -> Result<Anchor, ApiError> {
    let cfg = state.audit_export.clone();
    if !cfg.has_target() {
        return Err(ApiError::BadRequest(
            "no audit export target configured (AFW_AUDIT_EXPORT_DIR or AFW_AUDIT_S3_*)".into(),
        ));
    }
    let db = pool(state)?;
    let head: Option<(i64, String)> =
        sqlx::query_as("SELECT seq, hash FROM audit_log ORDER BY seq DESC LIMIT 1")
            .fetch_optional(db)
            .await?;
    let (seq, hash) = head.ok_or_else(|| ApiError::BadRequest("the audit log is empty".into()))?;
    let now = Utc::now();
    let anchor = Anchor {
        seq,
        hash,
        at: DateTime::from_timestamp(now.timestamp(), 0).unwrap_or(now),
    };
    let line = serde_json::to_string(&anchor).map_err(|e| ApiError::Internal(e.to_string()))?;
    if let Some(dir) = cfg.dir.clone() {
        let l = line.clone();
        tokio::task::spawn_blocking(move || append_line(&dir, &l))
            .await
            .map_err(|e| ApiError::Internal(e.to_string()))?
            .map_err(|e| ApiError::Internal(format!("writing the audit anchor: {e}")))?;
    }
    let s3_key = match &cfg.s3 {
        Some(s3) => Some(put_s3(s3, &anchor, line.as_bytes()).await?),
        None => None,
    };
    sqlx::query(
        "INSERT INTO audit_anchors (seq, hash, at, file, s3_key) VALUES ($1, $2, $3, $4, $5)",
    )
    .bind(anchor.seq)
    .bind(&anchor.hash)
    .bind(anchor.at)
    .bind(cfg.dir.is_some())
    .bind(s3_key)
    .execute(db)
    .await?;
    Ok(anchor)
}

/// [`anchor_now`] when the head moved since the last export (periodic task).
pub async fn anchor_if_moved(state: &AppState) -> Result<Option<Anchor>, ApiError> {
    let db = pool(state)?;
    let head: Option<i64> = sqlx::query_scalar("SELECT max(seq) FROM audit_log")
        .fetch_one(db)
        .await?;
    let Some(head) = head else {
        return Ok(None);
    };
    let last: Option<i64> = sqlx::query_scalar("SELECT max(seq) FROM audit_anchors")
        .fetch_one(db)
        .await?;
    if last == Some(head) {
        return Ok(None);
    }
    anchor_now(state).await.map(Some)
}

/// Starts the periodic export (`AFW_AUDIT_EXPORT_INTERVAL`) when a target is configured.
pub fn spawn_periodic(state: AppState) -> Option<tokio::task::JoinHandle<()>> {
    let cfg = state.audit_export.clone();
    if !cfg.has_target() || cfg.interval.is_zero() {
        return None;
    }
    Some(tokio::spawn(async move {
        let mut tick = tokio::time::interval(cfg.interval);
        tick.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Delay);
        loop {
            tick.tick().await;
            match anchor_if_moved(&state).await {
                Ok(Some(a)) => tracing::info!(seq = a.seq, "audit chain head exported"),
                Ok(None) => {}
                Err(e) => tracing::error!(error = %e, "audit export failed"),
            }
        }
    }))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn intervals() {
        assert_eq!(parse_interval("3600"), Some(Duration::from_secs(3600)));
        assert_eq!(parse_interval("90s"), Some(Duration::from_secs(90)));
        assert_eq!(parse_interval("15m"), Some(Duration::from_secs(900)));
        assert_eq!(parse_interval("1h"), Some(Duration::from_secs(3600)));
        assert_eq!(parse_interval("x"), None);
        assert_eq!(parse_interval(""), None);
    }

    #[test]
    fn file_is_append_only_jsonl() {
        let dir = tempfile::tempdir().unwrap();
        for seq in [1, 2] {
            let a = Anchor {
                seq,
                hash: "h".into(),
                at: Utc::now(),
            };
            append_line(dir.path(), &serde_json::to_string(&a).unwrap()).unwrap();
        }
        let anchors = read_file_anchors(dir.path()).unwrap();
        assert_eq!(anchors.iter().map(|a| a.seq).collect::<Vec<_>>(), [1, 2]);
        std::fs::write(dir.path().join(ANCHORS_FILE), "garbage\n").unwrap();
        assert!(read_file_anchors(dir.path()).is_err());
    }
}
