//! Transparent listener (`:15001`): connections redirected by nftables; the original
//! destination comes from `SO_ORIGINAL_DST`, the agent from the source address.

use std::sync::Arc;

use tokio::net::TcpListener;

use crate::flow::{Target, handle};
use crate::state::GatewayState;

pub async fn serve(state: Arc<GatewayState>, listener: TcpListener) {
    loop {
        let (stream, peer) = match listener.accept().await {
            Ok(x) => x,
            Err(e) => {
                tracing::warn!(error = %e, "transparent accept failed");
                tokio::time::sleep(std::time::Duration::from_millis(50)).await;
                continue;
            }
        };
        let state = state.clone();
        tokio::spawn(async move {
            let _ = stream.set_nodelay(true);
            let orig = match state.orig_dst.original_dst(&stream) {
                Ok(o) => o,
                Err(e) => {
                    // Unknown destination: never guess, refuse.
                    tracing::warn!(%peer, error = %e, "no original destination: connection refused");
                    crate::io::reset(stream);
                    return;
                }
            };
            let local = stream.local_addr().ok();
            if Some(orig) == local || state.own_addresses.contains(&orig.ip()) {
                // Not redirected, or aimed at the gateway itself: loop guard.
                crate::io::reset(stream);
                return;
            }
            handle(state, stream, peer, Target::Addr(orig)).await;
        });
    }
}
