//! Logs side of the gateway protocol: [`crate::gateways::ports::LogsPort`], plugged into
//! [`crate::AppState::ports`] by [`crate::AppState::new`]. Batch idempotency (`batch_id`) is
//! handled by the gateways module; events are upserted by id (never overwritten).

use afw_core::events::GatewayEvent;
use afw_core::protocol::GatewayCommand;
use uuid::Uuid;

use super::{captures, ingest};
use crate::AppState;
use crate::gateways::ports::{LogsPort, PortFuture};


#[derive(Clone, Copy, Debug, Default)]
pub struct LogsPortImpl;

impl LogsPort for LogsPortImpl {
    fn ingest_gateway_events<'a>(
        &'a self,
        state: &'a AppState,
        gateway_id: Uuid,
        events: Vec<GatewayEvent>,
    ) -> PortFuture<'a, ()> {
        Box::pin(async move {
            ingest::ingest_gateway_events(state, gateway_id, events).await?;
            Ok(())
        })
    }

    fn pending_commands<'a>(
        &'a self,
        state: &'a AppState,
        gateway_id: Uuid,
    ) -> PortFuture<'a, Vec<GatewayCommand>> {
        Box::pin(async move {
            let pool = ingest::pool(state)?;
            captures::pending_commands(pool, gateway_id).await
        })
    }

    fn store_capture<'a>(
        &'a self,
        state: &'a AppState,
        gateway_id: Uuid,
        capture_id: Uuid,
        data: bytes::Bytes,
    ) -> PortFuture<'a, ()> {
        Box::pin(async move {
            captures::store_capture(state, gateway_id, capture_id, &data).await?;
            Ok(())
        })
    }
}
