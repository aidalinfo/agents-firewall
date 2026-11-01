//! Shared helpers: real TLS handshakes over tokio loopback sockets.
#![allow(dead_code)]

use std::sync::Arc;

use rustls::pki_types::{CertificateDer, ServerName};
use rustls::{ClientConfig, RootCertStore, ServerConfig};
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::{TcpListener, TcpStream};
use tokio_rustls::{TlsAcceptor, TlsConnector};

pub struct Outcome {
    pub client: Result<(), String>,
    pub server: Result<Option<Vec<CertificateDer<'static>>>, String>,
    /// Certificate chain presented by the server, as seen by the client.
    pub server_chain: Option<Vec<CertificateDer<'static>>>,
}

impl Outcome {
    pub fn ok(&self) -> bool {
        self.client.is_ok() && self.server.is_ok()
    }
}

/// Runs a full handshake plus a one-byte round trip so that late alerts
/// (TLS 1.3 client-certificate rejection) surface on both sides.
pub async fn handshake(
    server: Arc<ServerConfig>,
    client: Arc<ClientConfig>,
    server_name: &str,
) -> Outcome {
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();
    let acceptor = TlsAcceptor::from(server);
    let server_task = tokio::spawn(async move {
        let (tcp, _) = listener.accept().await.map_err(|e| e.to_string())?;
        let mut tls = acceptor.accept(tcp).await.map_err(|e| e.to_string())?;
        let mut buf = [0u8; 1];
        tls.read_exact(&mut buf).await.map_err(|e| e.to_string())?;
        tls.write_all(&buf).await.map_err(|e| e.to_string())?;
        tls.flush().await.map_err(|e| e.to_string())?;
        let peer = tls.get_ref().1.peer_certificates().map(|c| c.to_vec());
        Ok::<_, String>(peer)
    });

    let connector = TlsConnector::from(client);
    let name = ServerName::try_from(server_name.to_string()).unwrap();
    let mut server_chain = None;
    let client_res = async {
        let tcp = TcpStream::connect(addr).await.map_err(|e| e.to_string())?;
        let mut tls = connector
            .connect(name, tcp)
            .await
            .map_err(|e| e.to_string())?;
        server_chain = tls.get_ref().1.peer_certificates().map(|c| c.to_vec());
        tls.write_all(b"x").await.map_err(|e| e.to_string())?;
        tls.flush().await.map_err(|e| e.to_string())?;
        let mut buf = [0u8; 1];
        tls.read_exact(&mut buf).await.map_err(|e| e.to_string())?;
        Ok::<_, String>(())
    }
    .await;
    let server_res = server_task.await.unwrap();
    Outcome {
        client: client_res,
        server: server_res,
        server_chain,
    }
}

pub fn provider() -> Arc<rustls::crypto::CryptoProvider> {
    Arc::new(rustls::crypto::ring::default_provider())
}

/// Client trusting exactly the given PEM roots, no client auth.
pub fn client_trusting(pem: &str) -> Arc<ClientConfig> {
    let mut roots = RootCertStore::empty();
    for c in rustls_pemfile::certs(&mut pem.as_bytes()) {
        roots.add(c.unwrap()).unwrap();
    }
    Arc::new(
        ClientConfig::builder_with_provider(provider())
            .with_safe_default_protocol_versions()
            .unwrap()
            .with_root_certificates(roots)
            .with_no_client_auth(),
    )
}

/// Client with the public web PKI only (what an unconfigured agent would use).
pub fn webpki_client() -> Arc<ClientConfig> {
    let roots = RootCertStore {
        roots: webpki_roots::TLS_SERVER_ROOTS.to_vec(),
    };
    Arc::new(
        ClientConfig::builder_with_provider(provider())
            .with_safe_default_protocol_versions()
            .unwrap()
            .with_root_certificates(roots)
            .with_no_client_auth(),
    )
}

/// Builds a self-signed server certificate (not chained to anything trusted).
pub fn self_signed_server(name: &str) -> Arc<ServerConfig> {
    let key = rcgen::KeyPair::generate().unwrap();
    let cert = rcgen::CertificateParams::new(vec![name.to_string()])
        .unwrap()
        .self_signed(&key)
        .unwrap();
    let key_der = rustls::pki_types::PrivateKeyDer::Pkcs8(key.serialize_der().into());
    Arc::new(
        ServerConfig::builder_with_provider(provider())
            .with_safe_default_protocol_versions()
            .unwrap()
            .with_no_client_auth()
            .with_single_cert(vec![cert.der().clone()], key_der)
            .unwrap(),
    )
}
