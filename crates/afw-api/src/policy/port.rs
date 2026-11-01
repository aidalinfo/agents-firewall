//! Policy side of the `PolicyPort` used by the gateway protocol and enrollments (lot L7c,
//! `crate::gateways::ports::PolicyPort`, plugged into `AppState::ports`).
//!
//! [`PolicyPortImpl`] is plugged by [`crate::AppState::new`].

use afw_core::InstalledPolicy;
use afw_core::api::EnrollmentRequest;
use afw_core::policy::{Agent, PolicyDocument};
use afw_core::protocol::PolicyAck;
use uuid::Uuid;

use super::agents::create_agent;
use super::store::{self, open_session, owner_key};
use super::{install, pool};
use crate::AppState;
use crate::auth::Principal;

pub use crate::gateways::ports::PortFuture;

#[derive(Clone, Copy, Debug, Default)]
pub struct PolicyPortImpl;

impl PolicyPortImpl {
    /// Policy the gateway should run (its desired revision), `None` when nothing is installed.
    pub fn installed_policy_for<'a>(
        &'a self,
        state: &'a AppState,
        gateway_id: Uuid,
    ) -> PortFuture<'a, Option<InstalledPolicy>> {
        Box::pin(async move { install::installed_policy_for(pool(state)?, gateway_id).await })
    }

    /// Installation result reported by the gateway.
    pub fn record_install_ack<'a>(
        &'a self,
        state: &'a AppState,
        gateway_id: Uuid,
        ack: PolicyAck,
    ) -> PortFuture<'a, ()> {
        Box::pin(async move { install::record_install_ack(pool(state)?, gateway_id, &ack).await })
    }

    /// Currently published policy, `None` when none is published.
    pub fn current_policy<'a>(
        &'a self,
        state: &'a AppState,
    ) -> PortFuture<'a, Option<PolicyDocument>> {
        Box::pin(async move {
            let mut conn = pool(state)?.acquire().await?;
            Ok(store::latest_revision(&mut conn).await?.map(|(_, d)| d))
        })
    }

    /// Creates the agent in `session_id`, or in the caller's open session, or in a new session;
    /// returns it with the session id. Session rules and EF-51 apply (same path as
    /// `POST /agents`).
    pub fn create_agent<'a>(
        &'a self,
        state: &'a AppState,
        principal: &'a Principal,
        session_id: Option<Uuid>,
        request: &'a EnrollmentRequest,
    ) -> PortFuture<'a, (Agent, Uuid)> {
        Box::pin(async move {
            let mut tx = pool(state)?.begin().await?;
            let session_id = match session_id {
                Some(id) => id,
                None => {
                    let key = owner_key(principal);
                    let open = store::sessions_where(
                        &mut tx,
                        "owner_key = $1 AND state = 'open'",
                        Some(&key),
                    )
                    .await?;
                    match open.first() {
                        Some(s) => s.id,
                        None => {
                            open_session(
                                &mut tx,
                                principal,
                                Some(format!("enrollment {}", request.name)),
                            )
                            .await?
                            .id
                        }
                    }
                }
            };
            let agent = Agent {
                id: Uuid::new_v4(),
                name: request.name.clone(),
                zone_id: request.zone_id,
                kind: request.kind,
                gateway_id: Some(request.gateway_id),
                addresses: vec![],
                labels: Default::default(),
                hermes: request.hermes,
                mcp_admin: false,
            };
            let agent = create_agent(&mut tx, principal, session_id, agent).await?;
            tx.commit().await?;
            Ok((agent, session_id))
        })
    }
}

impl crate::gateways::ports::PolicyPort for PolicyPortImpl {
    fn installed_policy_for<'a>(
        &'a self,
        state: &'a AppState,
        gateway_id: Uuid,
    ) -> PortFuture<'a, Option<InstalledPolicy>> {
        PolicyPortImpl::installed_policy_for(self, state, gateway_id)
    }
    fn record_install_ack<'a>(
        &'a self,
        state: &'a AppState,
        gateway_id: Uuid,
        ack: PolicyAck,
    ) -> PortFuture<'a, ()> {
        PolicyPortImpl::record_install_ack(self, state, gateway_id, ack)
    }
    fn current_policy<'a>(&'a self, state: &'a AppState) -> PortFuture<'a, Option<PolicyDocument>> {
        PolicyPortImpl::current_policy(self, state)
    }
    fn create_agent<'a>(
        &'a self,
        state: &'a AppState,
        principal: &'a Principal,
        session_id: Option<Uuid>,
        request: &'a EnrollmentRequest,
    ) -> PortFuture<'a, (Agent, Uuid)> {
        PolicyPortImpl::create_agent(self, state, principal, session_id, request)
    }
}
