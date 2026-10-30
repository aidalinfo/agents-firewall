//! Console client (stub).
use std::sync::Arc;
pub async fn run(_s: Arc<crate::GatewayState>, _url: String) { std::future::pending::<()>().await }
pub async fn write_local(_s: Arc<crate::GatewayState>) { std::future::pending::<()>().await }
