//! DNS (stub).
use std::sync::Arc;
pub async fn serve_udp(_s: Arc<crate::GatewayState>, _u: Arc<tokio::net::UdpSocket>) { std::future::pending::<()>().await }
pub async fn serve_tcp(_s: Arc<crate::GatewayState>, _l: tokio::net::TcpListener) { std::future::pending::<()>().await }
