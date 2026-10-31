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
        if !dir.exists() {
            // Only a directory we create is restricted to its owner (never chmod an existing
            // one, e.g. a shared ~/.config).
            std::fs::create_dir_all(dir)
                .with_context(|| format!("cannot create {}", dir.display()))?;
            #[cfg(unix)]
            {
                use std::os::unix::fs::PermissionsExt;
                let _ = std::fs::set_permissions(dir, std::fs::Permissions::from_mode(0o700));
            }
        }
        let body = toml::to_string(self)?;
        write_atomic(path, body.as_bytes(), Some(0o600))
    }
}

/// Atomic replacement of `path` (a symbolic link is followed: its target is replaced). The
/// temporary file has a random name in the same directory, is created with `create_new` and
/// directly with its final mode: `mode`, else the mode of the existing file, else 0600.
pub fn write_atomic(path: &Path, data: &[u8], mode: Option<u32>) -> Result<()> {
    use std::io::Write;
    let target = match std::fs::canonicalize(path) {
        Ok(t) => t,
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => path.to_path_buf(),
        Err(e) => return Err(e).with_context(|| format!("cannot resolve {}", path.display())),
    };
    let dir = target
        .parent()
        .filter(|p| !p.as_os_str().is_empty())
        .unwrap_or(Path::new("."));
    let name = target
        .file_name()
        .map(|n| n.to_string_lossy().into_owned())
        .unwrap_or_else(|| "file".into());
    let tmp = dir.join(format!(".{name}.{}.afw-tmp", uuid::Uuid::new_v4().simple()));
    #[allow(unused_mut)]
    let mut final_mode = mode.unwrap_or(0o600);
    #[cfg(unix)]
    if mode.is_none()
        && let Ok(m) = std::fs::metadata(&target)
    {
        use std::os::unix::fs::PermissionsExt;
        final_mode = m.permissions().mode() & 0o7777;
    }
    let mut opts = std::fs::OpenOptions::new();
    opts.write(true).create_new(true);
    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt;
        opts.mode(final_mode);
    }
    let result = (|| -> Result<()> {
        let mut f = opts
            .open(&tmp)
            .with_context(|| format!("cannot create {}", tmp.display()))?;
        #[cfg(unix)]
        {
            // The umask may have removed bits: set the exact mode.
            use std::os::unix::fs::PermissionsExt;
            f.set_permissions(std::fs::Permissions::from_mode(final_mode))?;
        }
        f.write_all(data)?;
        f.sync_all()?;
        std::fs::rename(&tmp, &target)
            .with_context(|| format!("cannot write {}", target.display()))?;
        Ok(())
    })();
    if result.is_err() {
        let _ = std::fs::remove_file(&tmp);
    }
    result
}

/// Reads one line from the terminal (fd 0) without echo; the echo is restored afterwards.
#[cfg(unix)]
pub fn read_secret_from_tty() -> Result<String> {
    use std::io::BufRead;
    // SAFETY: plain termios calls on fd 0 with a zero-initialised struct filled by tcgetattr.
    let mut term: libc::termios = unsafe { std::mem::zeroed() };
    if unsafe { libc::tcgetattr(0, &mut term) } != 0 {
        bail!("cannot read the terminal settings");
    }
    let saved = term;
    term.c_lflag &= !libc::ECHO;
    term.c_lflag |= libc::ECHONL;
    if unsafe { libc::tcsetattr(0, libc::TCSANOW, &term) } != 0 {
        bail!("cannot disable the terminal echo");
    }
    let mut line = String::new();
    let r = std::io::stdin().lock().read_line(&mut line);
    // SAFETY: restores the settings read above.
    unsafe { libc::tcsetattr(0, libc::TCSANOW, &saved) };
    r?;
    Ok(line)
}

#[cfg(not(unix))]
pub fn read_secret_from_tty() -> Result<String> {
    bail!("reading the token from a terminal is not supported here: pipe it on stdin")
}

/// `true` when fd 0 is a terminal.
pub fn stdin_is_tty() -> bool {
    #[cfg(unix)]
    {
        // SAFETY: isatty only inspects the descriptor.
        unsafe { libc::isatty(0) == 1 }
    }
    #[cfg(not(unix))]
    {
        false
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

#[cfg(all(test, unix))]
mod tests {
    use std::os::unix::fs::PermissionsExt;

    use super::*;

    fn mode(p: &Path) -> u32 {
        std::fs::metadata(p).unwrap().permissions().mode() & 0o777
    }

    #[test]
    fn save_restricts_only_a_directory_it_creates() {
        let tmp = tempfile::tempdir().unwrap();
        let shared = tmp.path().join("shared");
        std::fs::create_dir(&shared).unwrap();
        std::fs::set_permissions(&shared, std::fs::Permissions::from_mode(0o755)).unwrap();
        let cfg = Config {
            token: Some("t".into()),
            ..Default::default()
        };
        cfg.save(&shared.join("config.toml")).unwrap();
        assert_eq!(mode(&shared), 0o755, "existing directory untouched");
        assert_eq!(mode(&shared.join("config.toml")), 0o600);
        let fresh = tmp.path().join("new/afw");
        cfg.save(&fresh.join("config.toml")).unwrap();
        assert_eq!(mode(&fresh), 0o700);
        // No temporary file left behind.
        assert_eq!(std::fs::read_dir(&shared).unwrap().count(), 1);
    }

    #[test]
    fn write_atomic_follows_symlinks_and_keeps_the_mode() {
        let tmp = tempfile::tempdir().unwrap();
        let real_dir = tmp.path().join("real");
        std::fs::create_dir(&real_dir).unwrap();
        let target = real_dir.join("docker-compose.yml");
        std::fs::write(&target, "old").unwrap();
        std::fs::set_permissions(&target, std::fs::Permissions::from_mode(0o640)).unwrap();
        let link = tmp.path().join("compose.yml");
        std::os::unix::fs::symlink(&target, &link).unwrap();
        write_atomic(&link, b"new", None).unwrap();
        assert!(
            std::fs::symlink_metadata(&link)
                .unwrap()
                .file_type()
                .is_symlink()
        );
        assert_eq!(std::fs::read_to_string(&target).unwrap(), "new");
        assert_eq!(mode(&target), 0o640);
    }
}
