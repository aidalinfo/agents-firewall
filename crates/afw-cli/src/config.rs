//! `~/.config/afw/config.toml`: console URL, API token (file mode 0600, never printed) and
//! optional extra CA certificate.

use std::path::{Path, PathBuf};

use anyhow::{Context, Result, bail};
use serde::{Deserialize, Serialize};

#[derive(Clone, Debug, Default, Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct Config {
    /// Console URL (`https://afw.example.org`), `/api/v1` is appended by the client.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub url: Option<String>,
    /// API token (bearer). Never printed.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub token: Option<String>,
    /// Extra trusted CA certificate (PEM file), for a console with a private CA.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub ca_cert: Option<String>,
}

/// Default location: `$XDG_CONFIG_HOME/afw/config.toml`, else `~/.config/afw/config.toml`.
pub fn default_path() -> Option<PathBuf> {
    if let Some(x) = std::env::var_os("XDG_CONFIG_HOME").filter(|v| !v.is_empty()) {
        return Some(PathBuf::from(x).join("afw/config.toml"));
    }
    std::env::var_os("HOME")
        .filter(|v| !v.is_empty())
        .map(|h| PathBuf::from(h).join(".config/afw/config.toml"))
}

impl Config {
    /// Reads the file; a missing file is an empty configuration.
    pub fn load(path: &Path) -> Result<Self> {
        match std::fs::read_to_string(path) {
            Ok(s) => toml::from_str(&s).with_context(|| format!("invalid {}", path.display())),
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => Ok(Self::default()),
            Err(e) => Err(e).with_context(|| format!("cannot read {}", path.display())),
        }
    }

    /// Writes the file with mode 0600 (directory 0700), atomically.
    pub fn save(&self, path: &Path) -> Result<()> {
        let dir = path
            .parent()
            .filter(|p| !p.as_os_str().is_empty())
            .unwrap_or(Path::new("."));
        std::fs::create_dir_all(dir).with_context(|| format!("cannot create {}", dir.display()))?;
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            let _ = std::fs::set_permissions(dir, std::fs::Permissions::from_mode(0o700));
        }
        let body = toml::to_string(self)?;
        let tmp = path.with_extension("toml.tmp");
        write_private(&tmp, body.as_bytes())?;
        std::fs::rename(&tmp, path).with_context(|| format!("cannot write {}", path.display()))?;
        Ok(())
    }
}

/// Creates (or truncates) a file readable by its owner only, then writes `data`.
pub fn write_private(path: &Path, data: &[u8]) -> Result<()> {
    use std::io::Write;
    let mut opts = std::fs::OpenOptions::new();
    opts.write(true).create(true).truncate(true);
    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt;
        opts.mode(0o600);
    }
    let mut f = opts
        .open(path)
        .with_context(|| format!("cannot write {}", path.display()))?;
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        f.set_permissions(std::fs::Permissions::from_mode(0o600))?;
    }
    f.write_all(data)?;
    Ok(())
}

/// Warns (does not fail) when the configuration file is readable by others.
pub fn check_permissions(path: &Path) -> Option<String> {
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        if let Ok(m) = std::fs::metadata(path)
            && m.permissions().mode() & 0o077 != 0
        {
            return Some(format!(
                "warning: {} is readable by other users (chmod 600 it): it holds your API token",
                path.display()
            ));
        }
    }
    let _ = path;
    None
}

/// Rejects a token that cannot be sent as a header value.
pub fn validate_token(token: &str) -> Result<String> {
    let t = token.trim();
    if t.is_empty() {
        bail!("the API token is empty");
    }
    if t.chars().any(|c| c.is_control() || c == ' ') {
        bail!("the API token contains spaces or control characters");
    }
    Ok(t.to_string())
}
