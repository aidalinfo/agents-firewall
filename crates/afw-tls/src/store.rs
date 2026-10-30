//! On-disk key material: `ca.crt` (0644) / `ca.key` (0600) pairs and private
//! key files. Private keys are created with mode 0600 from the start (no
//! window where they are readable by others) and refused on load if group or
//! other users have any access, or if the path is not a regular file.

use std::fs;
use std::io::Write;
use std::path::{Path, PathBuf};

use rcgen::{CertificateParams, KeyPair};
use rustls::pki_types::CertificateDer;

use crate::{TlsError, certs_from_pem};

pub(crate) const CA_CERT_FILE: &str = "ca.crt";
pub(crate) const CA_KEY_FILE: &str = "ca.key";

fn io_err(path: &Path) -> impl FnOnce(std::io::Error) -> TlsError + '_ {
    move |source| TlsError::Io {
        path: path.to_path_buf(),
        source,
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

/// Creates the directory (0700 on unix) if missing.
pub(crate) fn ensure_dir(dir: &Path) -> Result<(), TlsError> {
    if dir.is_dir() {
        return Ok(());
    }
    let mut b = fs::DirBuilder::new();
    b.recursive(true);
    #[cfg(unix)]
    {
        use std::os::unix::fs::DirBuilderExt;
        b.mode(0o700);
    }
    b.create(dir).map_err(io_err(dir))
}

/// Reads a private key file after checking it is a regular file with no
/// group/other permissions.
pub(crate) fn read_private_key(path: &Path) -> Result<KeyPair, TlsError> {
    let meta = fs::symlink_metadata(path).map_err(io_err(path))?;
    if !meta.file_type().is_file() {
        return Err(TlsError::NotARegularFile {
            path: path.to_path_buf(),
        });
    }
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        let mode = meta.permissions().mode() & 0o777;
        if mode & 0o077 != 0 {
            return Err(TlsError::InsecurePermissions {
                path: path.to_path_buf(),
                mode,
            });
        }
    }
    let pem = fs::read_to_string(path).map_err(io_err(path))?;
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
    f.sync_all().map_err(io_err(&tmp))?;
    drop(f);
    #[cfg(unix)]
    {
        // The umask may have narrowed the mode; set it exactly.
        use std::os::unix::fs::PermissionsExt;
        fs::set_permissions(&tmp, fs::Permissions::from_mode(mode)).map_err(io_err(&tmp))?;
    }
    fs::rename(&tmp, path).map_err(io_err(path))
}

/// Loads the CA in `dir`, or creates it with `params` if neither file exists.
/// One file without the other is an error: we never silently replace an
/// authority that agents may already trust.
pub(crate) fn load_or_create_ca(
    dir: &Path,
    params: impl FnOnce() -> Result<CertificateParams, TlsError>,
) -> Result<CaMaterial, TlsError> {
    let cert_path = dir.join(CA_CERT_FILE);
    let key_path = dir.join(CA_KEY_FILE);
    let cert_exists = fs::symlink_metadata(&cert_path).is_ok();
    let key_exists = fs::symlink_metadata(&key_path).is_ok();
    match (cert_exists, key_exists) {
        (true, true) => load_ca(dir, &cert_path, &key_path),
        (false, false) => {
            ensure_dir(dir)?;
            let key = KeyPair::generate_for(&rcgen::PKCS_ECDSA_P256_SHA256)?;
            let cert = params()?.self_signed(&key)?;
            write_file(&key_path, key.serialize_pem().as_bytes(), 0o600)?;
            write_file(&cert_path, cert.pem().as_bytes(), 0o644)?;
            load_ca(dir, &cert_path, &key_path)
        }
        _ => Err(TlsError::InconsistentStore {
            dir: dir.to_path_buf(),
            reason: format!("exactly one of {CA_CERT_FILE} and {CA_KEY_FILE} exists"),
        }),
    }
}

fn load_ca(dir: &Path, cert_path: &Path, key_path: &Path) -> Result<CaMaterial, TlsError> {
    let key = read_private_key(key_path)?;
    let cert_pem = fs::read_to_string(cert_path).map_err(io_err(cert_path))?;
    let mut certs = certs_from_pem(&cert_pem)?;
    if certs.len() != 1 {
        return Err(TlsError::InconsistentStore {
            dir: dir.to_path_buf(),
            reason: format!("{CA_CERT_FILE} must hold exactly one certificate"),
        });
    }
    let cert_der = certs.remove(0);
    {
        let (_, x509) = x509_parser::parse_x509_certificate(&cert_der)
            .map_err(|e| TlsError::InvalidCertificate(e.to_string()))?;
        if x509.public_key().raw != key.public_key_der().as_slice() {
            return Err(TlsError::InconsistentStore {
                dir: dir.to_path_buf(),
                reason: format!("{CA_CERT_FILE} does not match {CA_KEY_FILE}"),
            });
        }
        let is_ca = x509
            .basic_constraints()
            .map_err(|e| TlsError::InvalidCertificate(e.to_string()))?
            .is_some_and(|bc| bc.value.ca);
        if !is_ca {
            return Err(TlsError::InconsistentStore {
                dir: dir.to_path_buf(),
                reason: format!("{CA_CERT_FILE} is not a CA certificate"),
            });
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
