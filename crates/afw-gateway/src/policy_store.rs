//! Installed policy store: load, verify, compile, persist atomically, swap atomically.
//!
//! Fail closed: without a valid policy the active engine is [`CompiledPolicy::deny_all`]
//! (`Implicit::NoPolicy`). An invalid new policy never replaces the last valid one (EF-23).

use std::io::Write;
use std::path::{Path, PathBuf};
use std::sync::{Arc, RwLock};

use afw_core::InstalledPolicy;
use chrono::Utc;

use crate::dlp::{ContentScanner, build_scanner};
use crate::engine::CompiledPolicy;

/// Everything derived from one installed policy.
pub struct ActivePolicy {
    pub engine: CompiledPolicy,
    pub scanner: Arc<dyn ContentScanner>,
    pub installed: Option<InstalledPolicy>,
}

impl ActivePolicy {
    pub fn deny_all() -> Self {
        Self {
            engine: CompiledPolicy::deny_all(),
            scanner: build_scanner(&[]).expect("empty scanner always builds"),
            installed: None,
        }
    }

    pub fn revision(&self) -> Option<u64> {
        self.installed.as_ref().map(|p| p.revision)
    }

    pub fn settings(&self) -> afw_core::policy::PolicySettings {
        self.installed
            .as_ref()
            .map(|p| p.document.settings.clone())
            .unwrap_or_default()
    }
}

#[derive(Debug, thiserror::Error)]
pub enum InstallError {
    #[error("rejected policy: {0}")]
    Integrity(#[from] afw_core::PolicyIntegrityError),
    #[error("policy revision {offered} is older than active revision {active} (not a rollback)")]
    Downgrade { offered: u64, active: u64 },
    #[error("policy does not compile: {0}")]
    Compile(String),
    #[error("data classes: {0}")]
    Scanner(String),
    #[error("cannot persist policy: {0}")]
    Persist(#[from] std::io::Error),
    #[error("invalid policy file: {0}")]
    Parse(String),
}

pub struct PolicyStore {
    path: Option<PathBuf>,
    active: RwLock<Arc<ActivePolicy>>,
}

impl PolicyStore {
    /// Empty store: deny everything.
    pub fn deny_all(path: Option<PathBuf>) -> Self {
        Self {
            path,
            active: RwLock::new(Arc::new(ActivePolicy::deny_all())),
        }
    }

    /// Loads `path` if present. A missing, corrupt or invalid file leaves the store in
    /// deny-all mode (logged), never in an open mode.
    pub fn load(path: PathBuf) -> Self {
        let store = Self::deny_all(Some(path.clone()));
        match std::fs::read(&path) {
            Ok(bytes) => match parse(&bytes).and_then(|p| store.build(p)) {
                Ok(active) => store.swap(active),
                Err(e) => tracing::error!(path = %path.display(), error = %e, "persisted policy rejected: denying everything"),
            },
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => {
                tracing::warn!(path = %path.display(), "no persisted policy: denying everything")
            }
            Err(e) => tracing::error!(path = %path.display(), error = %e, "cannot read policy: denying everything"),
        }
        store
    }

    pub fn current(&self) -> Arc<ActivePolicy> {
        self.active.read().unwrap_or_else(|e| e.into_inner()).clone()
    }

    pub fn revision(&self) -> Option<u64> {
        self.current().revision()
    }

    /// Verifies, compiles, persists and activates `policy`. On error the active policy is
    /// unchanged.
    pub fn install(&self, policy: InstalledPolicy) -> Result<u64, InstallError> {
        policy.verify()?;
        let active_rev = self.revision();
        if !policy.may_replace(active_rev) {
            return Err(InstallError::Downgrade {
                offered: policy.revision,
                active: active_rev.unwrap_or_default(),
            });
        }
        let rev = policy.revision;
        let active = self.build(policy)?;
        if let (Some(path), Some(p)) = (&self.path, &active.installed) {
            write_atomic(path, &serde_json::to_vec_pretty(p).expect("policy serializes"))?;
        }
        self.swap(active);
        Ok(rev)
    }

    /// Parses raw JSON then installs it (standalone mode, console payloads).
    pub fn install_bytes(&self, bytes: &[u8]) -> Result<u64, InstallError> {
        self.install(parse(bytes)?)
    }

    fn build(&self, policy: InstalledPolicy) -> Result<ActivePolicy, InstallError> {
        policy.verify()?;
        let engine = CompiledPolicy::compile(&policy, Utc::now()).map_err(|e| InstallError::Compile(e.to_string()))?;
        let scanner = build_scanner(engine.data_class_specs()).map_err(InstallError::Scanner)?;
        Ok(ActivePolicy {
            engine,
            scanner,
            installed: Some(policy),
        })
    }

    fn swap(&self, active: ActivePolicy) {
        *self.active.write().unwrap_or_else(|e| e.into_inner()) = Arc::new(active);
    }
}

fn parse(bytes: &[u8]) -> Result<InstalledPolicy, InstallError> {
    serde_json::from_slice(bytes).map_err(|e| InstallError::Parse(e.to_string()))
}

/// Writes `data` to `path` atomically (temp file in the same directory, fsync, rename, fsync dir).
pub fn write_atomic(path: &Path, data: &[u8]) -> std::io::Result<()> {
    let dir = path.parent().unwrap_or(Path::new("."));
    std::fs::create_dir_all(dir)?;
    let tmp = dir.join(format!(
        ".{}.tmp-{}",
        path.file_name().and_then(|n| n.to_str()).unwrap_or("file"),
        std::process::id()
    ));
    {
        let mut f = std::fs::OpenOptions::new()
            .write(true)
            .create(true)
            .truncate(true)
            .open(&tmp)?;
        f.write_all(data)?;
        f.sync_all()?;
    }
    std::fs::rename(&tmp, path)?;
    if let Ok(d) = std::fs::File::open(dir) {
        let _ = d.sync_all();
    }
    Ok(())
}
