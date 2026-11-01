//! On-disk key material: `ca.crt` (0644) / `ca.key` (0600) pairs and private
//! key files.
//!
//! Hardening (unix):
//! - storage directories are created 0700; an existing one must be a directory
//!   owned by the effective uid and not writable by group or others;
//! - private keys are opened with `O_NOFOLLOW` and checked with `fstat` on the
//!   open descriptor: regular file, owned by the effective uid, no group/other
//!   permission bits;
//! - a new CA pair is written into `<dir>/.ca-staging/` (key, then certificate,
//!   each written atomically) and then moved into place, key first. On the next
//!   load, a staging directory holding a certificate is a complete pair whose
//!   move was interrupted: it is finished (only if it agrees with what is
//!   already in place); a staging directory without a certificate was never
//!   committed and is discarded.

use std::fs;
use std::io::{Read, Write};
use std::path::{Path, PathBuf};

use rcgen::{CertificateParams, KeyPair};
use rustls::pki_types::CertificateDer;

use crate::{TlsError, certs_from_pem};

pub(crate) const CA_CERT_FILE: &str = "ca.crt";
pub(crate) const CA_KEY_FILE: &str = "ca.key";
pub(crate) const CA_STAGING_DIR: &str = ".ca-staging";

fn io_err(path: &Path) -> impl FnOnce(std::io::Error) -> TlsError + '_ {
    move |source| TlsError::Io {
        path: path.to_path_buf(),
        source,
    }
}

fn inconsistent(dir: &Path, reason: impl Into<String>) -> TlsError {
    TlsError::InconsistentStore {
        dir: dir.to_path_buf(),
        reason: reason.into(),
    }
}

/// A loaded certificate authority, ready to sign.
pub(crate) struct CaMaterial {
    pub cert_der: CertificateDer<'static>,
    pub cert_pem: String,
    pub key: KeyPair,
    /// rcgen view of the CA used as issuer (same subject and key identifier
    /// as the stored certificate, so issued certificates chain to it).
    pub issuer: rcgen::Certificate,
}

#[cfg(unix)]
fn euid() -> u32 {
    // SAFETY: geteuid has no preconditions and cannot fail.
    unsafe { libc::geteuid() }
}

#[cfg(unix)]
fn check_owner_and_mode(
    path: &Path,
    meta: &fs::Metadata,
    forbidden_bits: u32,
) -> Result<(), TlsError> {
    use std::os::unix::fs::MetadataExt;
    let (uid, me) = (meta.uid(), euid());
    if uid != me {
        return Err(TlsError::WrongOwner {
            path: path.to_path_buf(),
            uid,
            expected: me,
        });
    }
    let mode = meta.mode() & 0o7777;
    if mode & forbidden_bits != 0 {
        return Err(TlsError::InsecurePermissions {
            path: path.to_path_buf(),
            mode,
        });
    }
    Ok(())
}

/// Validates an existing storage directory, or creates it (and any missing
/// parents) with mode 0700.
pub(crate) fn prepare_dir(dir: &Path) -> Result<(), TlsError> {
    match fs::metadata(dir) {
        Ok(meta) => {
            if !meta.is_dir() {
                return Err(TlsError::NotARegularFile {
                    path: dir.to_path_buf(),
                });
            }
            #[cfg(unix)]
            check_owner_and_mode(dir, &meta, 0o022)?;
            Ok(())
        }
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => {
            let mut b = fs::DirBuilder::new();
            b.recursive(true);
            #[cfg(unix)]
            {
                use std::os::unix::fs::DirBuilderExt;
                b.mode(0o700);
            }
            b.create(dir).map_err(io_err(dir))?;
            #[cfg(unix)]
            {
                // The umask may have narrowed the mode; set it exactly.
                use std::os::unix::fs::PermissionsExt;
                fs::set_permissions(dir, fs::Permissions::from_mode(0o700)).map_err(io_err(dir))?;
            }
            Ok(())
        }
        Err(e) => Err(io_err(dir)(e)),
    }
}

/// Reads a private key: opened without following symlinks, then checked on
/// the descriptor (regular file, our uid, no group/other bits).
pub(crate) fn read_private_key(path: &Path) -> Result<KeyPair, TlsError> {
    let mut opts = fs::OpenOptions::new();
    opts.read(true);
    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt;
        opts.custom_flags(libc::O_NOFOLLOW);
    }
    let mut file = opts.open(path).map_err(|source| {
        #[cfg(unix)]
        if source.raw_os_error() == Some(libc::ELOOP) {
            return TlsError::NotARegularFile {
                path: path.to_path_buf(),
            };
        }
        TlsError::Io {
            path: path.to_path_buf(),
            source,
        }
    })?;
    let meta = file.metadata().map_err(io_err(path))?;
    if !meta.file_type().is_file() {
        return Err(TlsError::NotARegularFile {
            path: path.to_path_buf(),
        });
    }
    #[cfg(unix)]
    check_owner_and_mode(path, &meta, 0o077)?;
    let mut pem = String::new();
    file.read_to_string(&mut pem).map_err(io_err(path))?;
    Ok(KeyPair::from_pem(&pem)?)
}

/// Atomically writes a file with the given mode (temp file + rename).
pub(crate) fn write_file(path: &Path, contents: &[u8], mode: u32) -> Result<(), TlsError> {
    let tmp: PathBuf = {
        let mut name = path.file_name().unwrap_or_default().to_os_string();
        name.push(".tmp");
        path.with_file_name(name)
    };
    let _ = fs::remove_file(&tmp);
    let mut opts = fs::OpenOptions::new();
    opts.write(true).create_new(true);
    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt;
        opts.mode(mode);
    }
    #[cfg(not(unix))]
    let _ = mode;
    let mut f = opts.open(&tmp).map_err(io_err(&tmp))?;
    f.write_all(contents).map_err(io_err(&tmp))?;
    #[cfg(unix)]
    {
        // The umask may have narrowed the mode; set it exactly.
        use std::os::unix::fs::PermissionsExt;
        f.set_permissions(fs::Permissions::from_mode(mode))
            .map_err(io_err(&tmp))?;
    }
    f.sync_all().map_err(io_err(&tmp))?;
    drop(f);
    fs::rename(&tmp, path).map_err(io_err(path))
}

/// Flushes directory entries (renames) to disk.
fn sync_dir(dir: &Path) -> Result<(), TlsError> {
    #[cfg(unix)]
    fs::File::open(dir)
        .and_then(|d| d.sync_all())
        .map_err(io_err(dir))?;
    #[cfg(not(unix))]
    let _ = dir;
    Ok(())
}

fn exists(path: &Path) -> bool {
    fs::symlink_metadata(path).is_ok()
}

/// Finishes or discards an interrupted CA creation (see module docs).
fn recover_staging(dir: &Path) -> Result<(), TlsError> {
    let staging = dir.join(CA_STAGING_DIR);
    let meta = match fs::symlink_metadata(&staging) {
        Ok(m) => m,
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => return Ok(()),
        Err(e) => return Err(io_err(&staging)(e)),
    };
    if !meta.is_dir() {
        return Err(inconsistent(
            dir,
            format!("{CA_STAGING_DIR} is not a directory"),
        ));
    }
    if exists(&staging.join(CA_CERT_FILE)) {
        // Complete pair: move what is left, in the original order.
        for name in [CA_KEY_FILE, CA_CERT_FILE] {
            let staged = staging.join(name);
            let target = dir.join(name);
            match (exists(&staged), exists(&target)) {
                (true, true) => {
                    let a = fs::read(&staged).map_err(io_err(&staged))?;
                    let b = fs::read(&target).map_err(io_err(&target))?;
                    if a != b {
                        return Err(inconsistent(
                            dir,
                            format!("{CA_STAGING_DIR}/{name} conflicts with {name}"),
                        ));
                    }
                    fs::remove_file(&staged).map_err(io_err(&staged))?;
                }
                (true, false) => fs::rename(&staged, &target).map_err(io_err(&target))?,
                (false, true) => {}
                (false, false) => {
                    return Err(inconsistent(dir, format!("{name} lost during creation")));
                }
            }
        }
        sync_dir(dir)?;
    }
    fs::remove_dir_all(&staging).map_err(io_err(&staging))
}

/// Loads the CA in `dir`, or creates it with `params` if neither file exists.
/// One file without the other (outside of a recoverable staging state) is an
/// error: we never silently replace an authority agents may already trust.
pub(crate) fn load_or_create_ca(
    dir: &Path,
    params: impl FnOnce() -> Result<CertificateParams, TlsError>,
) -> Result<CaMaterial, TlsError> {
    prepare_dir(dir)?;
    recover_staging(dir)?;
    let cert_path = dir.join(CA_CERT_FILE);
    let key_path = dir.join(CA_KEY_FILE);
    match (exists(&cert_path), exists(&key_path)) {
        (true, true) => load_ca(dir, &cert_path, &key_path),
        (false, false) => {
            let key = KeyPair::generate_for(&rcgen::PKCS_ECDSA_P256_SHA256)?;
            let cert = params()?.self_signed(&key)?;
            let staging = dir.join(CA_STAGING_DIR);
            prepare_dir(&staging)?;
            // Key first, certificate last: the staged certificate marks a complete pair.
            write_file(
                &staging.join(CA_KEY_FILE),
                key.serialize_pem().as_bytes(),
                0o600,
            )?;
            write_file(&staging.join(CA_CERT_FILE), cert.pem().as_bytes(), 0o644)?;
            sync_dir(&staging)?;
            fs::rename(staging.join(CA_KEY_FILE), &key_path).map_err(io_err(&key_path))?;
            fs::rename(staging.join(CA_CERT_FILE), &cert_path).map_err(io_err(&cert_path))?;
            sync_dir(dir)?;
            fs::remove_dir(&staging).map_err(io_err(&staging))?;
            load_ca(dir, &cert_path, &key_path)
        }
        _ => Err(inconsistent(
            dir,
            format!("exactly one of {CA_CERT_FILE} and {CA_KEY_FILE} exists"),
        )),
    }
}

fn load_ca(dir: &Path, cert_path: &Path, key_path: &Path) -> Result<CaMaterial, TlsError> {
    let key = read_private_key(key_path)?;
    let cert_pem = fs::read_to_string(cert_path).map_err(io_err(cert_path))?;
    let mut certs = certs_from_pem(&cert_pem)?;
    if certs.len() != 1 {
        return Err(inconsistent(
            dir,
            format!("{CA_CERT_FILE} must hold exactly one certificate"),
        ));
    }
    let cert_der = certs.remove(0);
    {
        let (_, x509) = x509_parser::parse_x509_certificate(&cert_der)
            .map_err(|e| TlsError::InvalidCertificate(e.to_string()))?;
        if x509.public_key().raw != key.public_key_der().as_slice() {
            return Err(inconsistent(
                dir,
                format!("{CA_CERT_FILE} does not match {CA_KEY_FILE}"),
            ));
        }
        let is_ca = x509
            .basic_constraints()
            .map_err(|e| TlsError::InvalidCertificate(e.to_string()))?
            .is_some_and(|bc| bc.value.ca);
        if !is_ca {
            return Err(inconsistent(
                dir,
                format!("{CA_CERT_FILE} is not a CA certificate"),
            ));
        }
    }
    let issuer = CertificateParams::from_ca_cert_der(&cert_der)?.self_signed(&key)?;
    Ok(CaMaterial {
        cert_der,
        cert_pem,
        key,
        issuer,
    })
}
