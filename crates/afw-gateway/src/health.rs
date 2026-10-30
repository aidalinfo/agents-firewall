//! Health (stub).
use std::sync::Arc;
pub async fn serve(_s: Arc<crate::GatewayState>, l: tokio::net::TcpListener) {
    while let Ok((c, _)) = l.accept().await { drop(c); }
}
