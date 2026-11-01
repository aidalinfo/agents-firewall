//! Authorization helpers of `Principal` (no database).

use afw_api::auth::Principal;
use afw_core::api::Role;
use afw_core::events::Interface;
use afw_core::policy::{Agent, AgentKind, PolicyDocument, Zone, ZoneMode};
use uuid::Uuid;

const OWN: Uuid = Uuid::from_u128(1);
const DELEGATED: Uuid = Uuid::from_u128(2);
const OTHER: Uuid = Uuid::from_u128(3);
const MCP_AGENT: Uuid = Uuid::from_u128(10);

fn mcp() -> Principal {
    Principal {
        agent_id: Some(MCP_AGENT),
        ..Principal::for_tests(Role::McpAgent)
    }
}

fn policy() -> PolicyDocument {
    let zone = |id, delegated| Zone {
        id,
        name: id.to_string(),
        comment: String::new(),
        mode: ZoneMode::Enforce,
        delegated_to_mcp: delegated,
    };
    PolicyDocument {
        // Its own zone is delegated too: it must still be refused.
        zones: vec![zone(OWN, true), zone(DELEGATED, true), zone(OTHER, false)],
        agents: vec![Agent {
            id: MCP_AGENT,
            name: "ops-bot".into(),
            zone_id: OWN,
            kind: AgentKind::Container,
            gateway_id: None,
            addresses: vec![],
            labels: Default::default(),
            hermes: false,
            mcp_admin: true,
        }],
        ..Default::default()
    }
}

#[test]
fn roles_are_ordered_and_mcp_is_not_admin() {
    let viewer = Principal::for_tests(Role::Viewer);
    assert!(viewer.require(Role::Viewer).is_ok());
    assert!(viewer.require(Role::Auditor).is_err());
    assert!(!viewer.can_see_content());
    let auditor = Principal::for_tests(Role::Auditor);
    assert!(auditor.require(Role::Auditor).is_ok());
    assert!(auditor.require(Role::Admin).is_err());
    assert!(auditor.can_see_content());
    let admin = Principal::for_tests(Role::Admin);
    assert!(admin.require(Role::Admin).is_ok());
    assert!(admin.require_policy_write().is_ok());

    let mcp = mcp();
    assert!(mcp.require(Role::Admin).is_err());
    assert!(mcp.require(Role::Auditor).is_err());
    assert!(mcp.require(Role::Viewer).is_ok());
    assert!(mcp.require_policy_write().is_ok());
    assert_eq!(mcp.interface, Interface::Mcp);
    assert!(!mcp.can_see_content());

    for p in [viewer, auditor] {
        assert!(p.require_policy_write().is_err());
        assert!(p.require_zone_write(OTHER, None, &[]).is_err());
    }
}

#[test]
fn delegated_agent_cannot_touch_own_zone() {
    let mcp = mcp();
    let doc = policy();
    assert_eq!(mcp.zone_scope(&doc), (Some(OWN), vec![OWN, DELEGATED]));
    assert!(mcp.require_zone_write_in(&doc, DELEGATED).is_ok());
    assert!(mcp.require_zone_write_in(&doc, OWN).is_err());
    assert!(mcp.require_zone_write_in(&doc, OTHER).is_err());
    // Unknown own zone (agent absent from the policy): fail closed.
    assert!(
        mcp.require_zone_write(DELEGATED, None, &[DELEGATED])
            .is_err()
    );
    // Admin may write anywhere.
    let admin = Principal::for_tests(Role::Admin);
    assert!(admin.require_zone_write_in(&doc, OWN).is_ok());
    assert!(admin.require_zone_write_in(&doc, OTHER).is_ok());
}

#[test]
fn plugin_token_is_limited_to_the_plugin_routes() {
    let plugin = Principal::for_tests(Role::AgentPlugin);
    assert!(plugin.require_plugin().is_ok());
    for r in [Role::Viewer, Role::Auditor, Role::Admin, Role::AgentPlugin] {
        assert!(plugin.require(r).is_err(), "{r:?}");
    }
    assert!(plugin.require_policy_write().is_err());
    assert!(plugin.require_zone_write(OTHER, None, &[OTHER]).is_err());
    assert!(!plugin.can_see_content());
    for r in [Role::Admin, Role::Auditor, Role::Viewer, Role::McpAgent] {
        assert!(Principal::for_tests(r).require_plugin().is_err(), "{r:?}");
    }
}
