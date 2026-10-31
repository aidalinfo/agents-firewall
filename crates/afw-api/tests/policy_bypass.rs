//! Bypass tests of the MCP agent's rights (EF-51, EF-52), written before the implementation.
//! Skipped when `AFW_TEST_DATABASE_URL` is not set.

mod policy_support;

use std::collections::HashMap;
use std::sync::Arc;

use afw_api::ApiError;
use afw_api::policy::{FlowFuture, FlowLookup};
use afw_core::events::{DecisionRef, FlowEvent, Verdict};
use afw_core::policy::L4Proto;
use axum::http::StatusCode;
use policy_support::*;
use serde_json::{Value, json};
use uuid::Uuid;

/// Published policy shared by the bypass tests.
struct Fixture {
    env: Env,
    mcp: String,
    mcp_agent: Uuid,
    z_own: Uuid,
    z_del: Uuid,
    z_other: Uuid,
    a_del: Uuid,
    shared_obj: Uuid,
    del_obj: Uuid,
    free_obj: Uuid,
    https: Uuid,
    r_own: Uuid,
    r_del: Uuid,
    r_base: Uuid,
    own_flow: Uuid,
}

struct Flows(HashMap<Uuid, FlowEvent>);

impl FlowLookup for Flows {
    fn get_flow(&self, id: Uuid) -> FlowFuture<'_> {
        let flow = self.0.get(&id).cloned();
        Box::pin(async move { Ok::<_, ApiError>(flow) })
    }
}

fn flow(id: Uuid, agent: Uuid, zone: Uuid, domain: &str) -> FlowEvent {
    FlowEvent {
        id,
        gateway_id: Uuid::new_v4(),
        agent_id: Some(agent),
        zone_id: Some(zone),
        src: "10.0.0.5:40000".parse().unwrap(),
        dst: "93.184.216.34:443".parse().unwrap(),
        protocol: L4Proto::Tcp,
        app: None,
        domain: Some(domain.to_owned()),
        sni: Some(domain.to_owned()),
        bytes_out: 10,
        bytes_in: 10,
        started_at: chrono::Utc::now(),
        ended_at: None,
        verdict: Verdict::Deny,
        decision: DecisionRef {
            rule_id: None,
            rule_number: None,
            rule_name: "cleanup".into(),
            revision: Some(1),
            layer: "implicit".into(),
            reason: "default deny".into(),
        },
        internal: false,
        llm_provider: false,
        tls_inspected: true,
        data_classes: vec![],
        observed: false,
        content_inspected: true,
    }
}

async fn fixture() -> Option<Fixture> {
    let (z_own, z_del, z_other) = (Uuid::new_v4(), Uuid::new_v4(), Uuid::new_v4());
    let mcp_agent = Uuid::new_v4();
    let own_flow = Uuid::new_v4();
    let flows = Flows(HashMap::from([(
        own_flow,
        flow(own_flow, mcp_agent, z_own, "evil.example.org"),
    )]));
    let env = env_with(Some(Arc::new(flows))).await?;
    let ids: Vec<Uuid> = (0..8).map(|_| Uuid::new_v4()).collect();
    let (a_del, shared_obj, del_obj, free_obj, https, r_own, r_del, r_base) = (
        ids[0], ids[1], ids[2], ids[3], ids[4], ids[5], ids[6], ids[7],
    );
    let a = &env.admin;
    let s = env.open(a).await;
    // The MCP agent's own zone is delegated too: its own zone must stay out of reach anyway.
    env.create(a, s, "zones", zone(z_own, "own", true)).await;
    env.create(a, s, "zones", zone(z_del, "delegated", true))
        .await;
    env.create(a, s, "zones", zone(z_other, "other", false))
        .await;
    let mut me = agent(mcp_agent, "admin-agent", z_own, true);
    me["addresses"] = json!(["10.0.0.5"]);
    env.create(a, s, "agents", me).await;
    env.create(a, s, "agents", agent(a_del, "worker", z_del, false))
        .await;
    env.create(
        a,
        s,
        "objects",
        domain(shared_obj, "shared", "api.example.com"),
    )
    .await;
    env.create(a, s, "objects", domain(del_obj, "del", "docs.example.com"))
        .await;
    env.create(
        a,
        s,
        "objects",
        domain(free_obj, "free", "free.example.com"),
    )
    .await;
    env.create(a, s, "services", tcp_service(https, "https", 443))
        .await;
    env.create(
        a,
        s,
        "rules",
        zone_rule(r_own, "own-accept", z_own, 1, &[shared_obj]),
    )
    .await;
    env.create(
        a,
        s,
        "rules",
        zone_rule(r_del, "del-accept", z_del, 1, &[del_obj]),
    )
    .await;
    env.create(a, s, "rules", baseline_rule(r_base, "no-metadata", 1, &[]))
        .await;
    assert_eq!(env.publish(a, s).await, 1);
    let mcp = env.token("mcp_agent", "admin-agent", Some(mcp_agent)).await;
    Some(Fixture {
        env,
        mcp,
        mcp_agent,
        z_own,
        z_del,
        z_other,
        a_del,
        shared_obj,
        del_obj,
        free_obj,
        https,
        r_own,
        r_del,
        r_base,
        own_flow,
    })
}

macro_rules! fixture_or_skip {
    () => {
        match fixture().await {
            Some(f) => f,
            None => {
                eprintln!("AFW_TEST_DATABASE_URL not set: skipped");
                return;
            }
        }
    };
}

impl Fixture {
    async fn mcp_call(&self, method: &str, path: &str, s: Uuid, body: Option<Value>) -> StatusCode {
        self.env
            .call(method, path, &self.mcp, Some(s), body)
            .await
            .0
    }

    async fn mcp_publish(&self, s: Uuid) -> (StatusCode, Value) {
        self.env
            .call(
                "POST",
                &format!("/sessions/{s}/publish"),
                &self.mcp,
                None,
                Some(json!({"comment": "mcp change"})),
            )
            .await
    }
}

#[tokio::test]
async fn delegated_agent_cannot_touch_own_zone() {
    let f = fixture_or_skip!();
    let s = f.env.open(&f.mcp).await;
    let forbidden = StatusCode::FORBIDDEN;
    // New rule in its own zone.
    let rule = zone_rule(Uuid::new_v4(), "widen-self", f.z_own, 1, &[f.free_obj]);
    assert_eq!(f.mcp_call("POST", "/rules", s, Some(rule)).await, forbidden);
    // Edit / delete / move a rule of its own zone.
    let mut edited = zone_rule(f.r_own, "own-accept", f.z_own, 1, &[]);
    edited["comment"] = json!("any destination");
    assert_eq!(
        f.mcp_call("PUT", &format!("/rules/{}", f.r_own), s, Some(edited))
            .await,
        forbidden
    );
    assert_eq!(
        f.mcp_call("DELETE", &format!("/rules/{}", f.r_own), s, None)
            .await,
        forbidden
    );
    assert_eq!(
        f.mcp_call(
            "POST",
            &format!("/rules/{}/move", f.r_own),
            s,
            Some(json!({"position": 2}))
        )
        .await,
        forbidden
    );
    // The zone itself (switch to observe = allow everything).
    let mut z = zone(f.z_own, "own", true);
    z["mode"] = json!("observe");
    assert_eq!(
        f.mcp_call("PUT", &format!("/zones/{}", f.z_own), s, Some(z))
            .await,
        forbidden
    );
    assert_eq!(
        f.mcp_call("DELETE", &format!("/zones/{}", f.z_own), s, None)
            .await,
        forbidden
    );
    // Its own agent record, or moving an agent into its zone.
    let me = agent(f.mcp_agent, "admin-agent", f.z_del, true);
    assert_eq!(
        f.mcp_call("PUT", &format!("/agents/{}", f.mcp_agent), s, Some(me))
            .await,
        forbidden
    );
    let moved = agent(f.a_del, "worker", f.z_own, false);
    assert_eq!(
        f.mcp_call("PUT", &format!("/agents/{}", f.a_del), s, Some(moved))
            .await,
        forbidden
    );
    // Moving a delegated rule into its own layer.
    assert_eq!(
        f.mcp_call(
            "POST",
            &format!("/rules/{}/move", f.r_del),
            s,
            Some(json!({"position": 1, "layer": {"type": "zone", "zone_id": f.z_own}}))
        )
        .await,
        forbidden
    );
    // A shared object used by a rule of its own zone: editing it widens its own rule.
    let widened = domain(f.shared_obj, "shared", "*");
    assert_eq!(
        f.mcp_call(
            "PUT",
            &format!("/objects/{}", f.shared_obj),
            s,
            Some(widened)
        )
        .await,
        forbidden
    );
    // A group gaining the shared object is fine only while unused; editing a group used by
    // its own rule is refused through the same where-used check.
    // Inspection rules covering all zones (thus its own) or its own zone explicitly.
    let insp_all = json!({"id": Uuid::new_v4(), "name": "bypass-all", "position": 1,
                          "zones": [], "destinations": [], "action": "bypass"});
    assert_eq!(
        f.mcp_call("POST", "/inspection-rules", s, Some(insp_all))
            .await,
        forbidden
    );
    let insp_own = json!({"id": Uuid::new_v4(), "name": "bypass-own", "position": 1,
                          "zones": [f.z_own], "destinations": [], "action": "bypass"});
    assert_eq!(
        f.mcp_call("POST", "/inspection-rules", s, Some(insp_own))
            .await,
        forbidden
    );
    // Allow-from-log for a flow of its own zone.
    let (st, _) = f
        .env
        .call(
            "POST",
            &format!("/sessions/{s}/allow-from-log"),
            &f.mcp,
            None,
            Some(json!({"flow_id": f.own_flow})),
        )
        .await;
    assert_eq!(st, forbidden);
    // Nothing leaked into the session.
    let (_, sess) = f
        .env
        .call("GET", &format!("/sessions/{s}"), &f.mcp, None, None)
        .await;
    assert_eq!(sess["changes"], 0, "{sess}");
}

#[tokio::test]
async fn delegated_agent_cannot_touch_baseline_or_undelegated_zones() {
    let f = fixture_or_skip!();
    let s = f.env.open(&f.mcp).await;
    let forbidden = StatusCode::FORBIDDEN;
    let base = baseline_rule(Uuid::new_v4(), "new-base", 2, &[]);
    assert_eq!(f.mcp_call("POST", "/rules", s, Some(base)).await, forbidden);
    let mut base = baseline_rule(f.r_base, "no-metadata", 1, &[]);
    base["enabled"] = json!(false);
    assert_eq!(
        f.mcp_call("PUT", &format!("/rules/{}", f.r_base), s, Some(base))
            .await,
        forbidden
    );
    assert_eq!(
        f.mcp_call("DELETE", &format!("/rules/{}", f.r_base), s, None)
            .await,
        forbidden
    );
    assert_eq!(
        f.mcp_call(
            "POST",
            &format!("/rules/{}/move", f.r_del),
            s,
            Some(json!({"position": 1, "layer": {"type": "baseline"}}))
        )
        .await,
        forbidden
    );
    // Zone not delegated.
    let rule = zone_rule(Uuid::new_v4(), "x", f.z_other, 1, &[f.free_obj]);
    assert_eq!(f.mcp_call("POST", "/rules", s, Some(rule)).await, forbidden);
    // Self-delegation and new zones.
    let z = zone(f.z_other, "other", true);
    assert_eq!(
        f.mcp_call("PUT", &format!("/zones/{}", f.z_other), s, Some(z))
            .await,
        forbidden
    );
    let z = zone(Uuid::new_v4(), "new", true);
    assert_eq!(f.mcp_call("POST", "/zones", s, Some(z)).await, forbidden);
    // Changing the delegation flag of a delegated zone is a human decision.
    let z = zone(f.z_del, "delegated", false);
    assert_eq!(
        f.mcp_call("PUT", &format!("/zones/{}", f.z_del), s, Some(z))
            .await,
        forbidden
    );
    // Impersonation: an agent of a delegated zone claiming the MCP agent's own address would
    // move the MCP agent's traffic into that zone.
    let mut twin = agent(Uuid::new_v4(), "twin", f.z_del, false);
    twin["addresses"] = json!(["10.0.0.5"]);
    assert_eq!(
        f.mcp_call("POST", "/agents", s, Some(twin)).await,
        StatusCode::FORBIDDEN
    );
    let mut moved = agent(f.a_del, "worker", f.z_del, false);
    moved["addresses"] = json!(["10.0.0.77"]);
    assert_eq!(
        f.mcp_call("PUT", &format!("/agents/{}", f.a_del), s, Some(moved))
            .await,
        StatusCode::FORBIDDEN,
        "the MCP agent cannot set agent addresses"
    );
    // Without addresses, an agent of a delegated zone may be created and renamed.
    let plain = Uuid::new_v4();
    assert_eq!(
        f.mcp_call(
            "POST",
            "/agents",
            s,
            Some(agent(plain, "plain", f.z_del, false))
        )
        .await,
        StatusCode::CREATED
    );
    assert_eq!(
        f.mcp_call(
            "PUT",
            &format!("/agents/{plain}"),
            s,
            Some(agent(plain, "plain2", f.z_del, false))
        )
        .await,
        StatusCode::OK
    );
    assert_eq!(
        f.mcp_call("DELETE", &format!("/agents/{plain}"), s, None)
            .await,
        StatusCode::NO_CONTENT
    );
    // Granting MCP administration to another agent.
    let a = agent(Uuid::new_v4(), "second-admin", f.z_del, true);
    assert_eq!(f.mcp_call("POST", "/agents", s, Some(a)).await, forbidden);
    // Global settings.
    let settings = json!({"internal_networks": [], "max_buffered_body": 1,
                          "max_stored_body": 1,
                          "retention_days": {"flows": 1, "http": 1, "captures": 1}});
    assert_eq!(
        f.mcp_call("PUT", "/settings", s, Some(settings)).await,
        forbidden
    );
    // Import of a whole document.
    assert_eq!(
        f.env
            .call(
                "POST",
                &format!("/sessions/{s}/import"),
                &f.mcp,
                None,
                Some(json!({}))
            )
            .await
            .0,
        forbidden
    );
    // Rollback to an older revision, installs of an older revision, approvals.
    assert_eq!(
        f.env
            .call("POST", "/revisions/1/revert", &f.mcp, None, None)
            .await
            .0,
        forbidden
    );
    // Using another caller's session.
    let admin_session = f.env.open(&f.env.admin).await;
    let rule = zone_rule(Uuid::new_v4(), "y", f.z_del, 1, &[f.free_obj]);
    assert_eq!(
        f.mcp_call("POST", "/rules", admin_session, Some(rule))
            .await,
        forbidden
    );
    // Nothing leaked into the MCP session.
    let (_, sess) = f
        .env
        .call("GET", &format!("/sessions/{s}"), &f.mcp, None, None)
        .await;
    assert_eq!(sess["changes"], 0, "{sess}");
}

#[tokio::test]
async fn delegated_agent_cannot_install_old_revision_or_decide_approvals() {
    let f = fixture_or_skip!();
    // Second revision by a human.
    let s = f.env.open(&f.env.admin).await;
    f.env
        .create(
            &f.env.admin,
            s,
            "objects",
            domain(Uuid::new_v4(), "x", "x.example.com"),
        )
        .await;
    assert_eq!(f.env.publish(&f.env.admin, s).await, 2);
    let gw = f.env.gateway().await;
    let install = |token: &str, revision: u64| {
        let body = json!({"revision": revision, "gateways": [gw]});
        let token = token.to_owned();
        let env = &f.env;
        async move {
            env.call("POST", "/installs", &token, None, Some(body))
                .await
                .0
        }
    };
    assert_eq!(
        install(&f.mcp, 1).await,
        StatusCode::FORBIDDEN,
        "rollback by the MCP agent"
    );
    assert_eq!(
        install(&f.mcp, 2).await,
        StatusCode::FORBIDDEN,
        "latest revision, but published by a human"
    );
    // A revision the MCP agent published itself may be installed by it.
    let s = f.env.open(&f.mcp).await;
    let rule = zone_rule(Uuid::new_v4(), "narrow", f.z_del, 1, &[f.free_obj]);
    assert_eq!(
        f.mcp_call("POST", "/rules", s, Some(rule)).await,
        StatusCode::CREATED
    );
    let (st, rev) = f.mcp_publish(s).await;
    assert_eq!(st, StatusCode::CREATED, "{rev}");
    assert_eq!(install(&f.mcp, 3).await, StatusCode::ACCEPTED);
    assert_eq!(
        install(&f.mcp, 3).await,
        StatusCode::ACCEPTED,
        "reinstall of its own install"
    );
    // A human rolls back: the MCP agent can no longer reinstall over it.
    assert_eq!(install(&f.env.admin, 2).await, StatusCode::ACCEPTED);
    assert_eq!(install(&f.mcp, 3).await, StatusCode::FORBIDDEN);
    // Approval decided by the MCP agent: refused (and by a viewer).
    let s = f.env.open(&f.mcp).await;
    let rule = zone_rule(Uuid::new_v4(), "any", f.z_del, 1, &[]);
    assert_eq!(
        f.mcp_call("POST", "/rules", s, Some(rule)).await,
        StatusCode::CREATED
    );
    let (st, approval) = f.mcp_publish(s).await;
    assert_eq!(st, StatusCode::ACCEPTED, "{approval}");
    let id = approval["id"].as_str().unwrap();
    for token in [&f.mcp, &f.env.viewer, &f.env.auditor] {
        let (st, _) = f
            .env
            .call(
                "POST",
                &format!("/approvals/{id}/decision"),
                token,
                None,
                Some(json!({"approve": true})),
            )
            .await;
        assert_eq!(st, StatusCode::FORBIDDEN);
    }
}

#[tokio::test]
async fn delegated_agent_can_edit_delegated_zone_without_approval_when_narrow() {
    let f = fixture_or_skip!();
    let s = f.env.open(&f.mcp).await;
    let rule = zone_rule(Uuid::new_v4(), "free", f.z_del, 1, &[f.free_obj]);
    let mut rule = rule;
    rule["services"] = json!([f.https]);
    assert_eq!(
        f.mcp_call("POST", "/rules", s, Some(rule)).await,
        StatusCode::CREATED
    );
    // An object used only by delegated rules may be edited.
    let obj = domain(f.del_obj, "del", "docs2.example.com");
    assert_eq!(
        f.mcp_call("PUT", &format!("/objects/{}", f.del_obj), s, Some(obj))
            .await,
        StatusCode::OK
    );
    // Inspection rule restricted to the delegated zone.
    let insp = json!({"id": Uuid::new_v4(), "name": "bypass-del", "position": 1,
                      "zones": [f.z_del], "destinations": [f.free_obj], "action": "bypass"});
    assert_eq!(
        f.mcp_call("POST", "/inspection-rules", s, Some(insp)).await,
        StatusCode::CREATED
    );
    let (st, rev) = f.mcp_publish(s).await;
    assert_eq!(st, StatusCode::CREATED, "{rev}");
    assert_eq!(rev["number"], 2);
    assert_eq!(rev["interface"], "mcp");
}

/// Builds the resources (collection, body) of a widening case.
type CaseBuilder = dyn Fn(&Fixture) -> Vec<(&'static str, Value)>;

#[tokio::test]
async fn widening_by_mcp_agent_requires_human_approval() {
    let f = fixture_or_skip!();
    let cases: Vec<(&str, Box<CaseBuilder>)> = vec![
        (
            "any destination",
            Box::new(|f| vec![("rules", zone_rule(Uuid::new_v4(), "any", f.z_del, 1, &[]))]),
        ),
        (
            "first-level wildcard",
            Box::new(|f| {
                let o = Uuid::new_v4();
                vec![
                    ("objects", domain(o, "dotcom", "*.com")),
                    ("rules", zone_rule(Uuid::new_v4(), "com", f.z_del, 1, &[o])),
                ]
            }),
        ),
        (
            "any object",
            Box::new(|f| {
                let o = Uuid::new_v4();
                vec![
                    ("objects", any_object(o, "anything")),
                    (
                        "rules",
                        zone_rule(Uuid::new_v4(), "anyobj", f.z_del, 1, &[o]),
                    ),
                ]
            }),
        ),
        (
            "group containing a wildcard",
            Box::new(|f| {
                let (o, g) = (Uuid::new_v4(), Uuid::new_v4());
                vec![
                    ("objects", domain(o, "star", "*")),
                    ("objects", group(g, "grp", &[o])),
                    ("rules", zone_rule(Uuid::new_v4(), "grp", f.z_del, 1, &[g])),
                ]
            }),
        ),
        (
            "secret data class allowed out",
            Box::new(|f| {
                let c = Uuid::new_v4();
                let mut r = zone_rule(Uuid::new_v4(), "secret-out", f.z_del, 1, &[f.free_obj]);
                r["data_classes"] = json!([c]);
                vec![("data-classes", secret_class(c, "aws")), ("rules", r)]
            }),
        ),
    ];
    for (label, build) in cases {
        let s = f.env.open(&f.mcp).await;
        for (collection, body) in build(&f) {
            let (st, out) = f
                .env
                .call(
                    "POST",
                    &format!("/{collection}"),
                    &f.mcp,
                    Some(s),
                    Some(body),
                )
                .await;
            assert_eq!(st, StatusCode::CREATED, "{label}: {out}");
        }
        let (st, approval) = f.mcp_publish(s).await;
        assert_eq!(st, StatusCode::ACCEPTED, "{label}: {approval}");
        assert_eq!(approval["status"], "pending", "{label}");
        // Still pending: publishing again is a conflict, no revision is created.
        let (st, _) = f.mcp_publish(s).await;
        assert_eq!(st, StatusCode::CONFLICT, "{label}");
        let (_, revs) = f
            .env
            .call("GET", "/revisions", &f.env.viewer, None, None)
            .await;
        assert_eq!(revs["items"].as_array().unwrap().len(), 1, "{label}");
        // A human rejects: still no publication.
        let id = approval["id"].as_str().unwrap().to_owned();
        let (st, _) = f
            .env
            .call(
                "POST",
                &format!("/approvals/{id}/decision"),
                &f.env.admin,
                None,
                Some(json!({"approve": false, "comment": "no"})),
            )
            .await;
        assert_eq!(st, StatusCode::OK);
        let (st, _) = f.mcp_publish(s).await;
        assert_eq!(st, StatusCode::CONFLICT, "{label}: rejected");
        let (st, _) = f
            .env
            .call(
                "POST",
                &format!("/sessions/{s}/discard"),
                &f.mcp,
                None,
                None,
            )
            .await;
        assert_eq!(st, StatusCode::OK);
    }
}

#[tokio::test]
async fn approved_widening_publishes_and_later_edits_need_a_new_approval() {
    let f = fixture_or_skip!();
    let s = f.env.open(&f.mcp).await;
    let r = Uuid::new_v4();
    let rule = zone_rule(r, "any", f.z_del, 1, &[]);
    assert_eq!(
        f.mcp_call("POST", "/rules", s, Some(rule)).await,
        StatusCode::CREATED
    );
    let (st, approval) = f.mcp_publish(s).await;
    assert_eq!(st, StatusCode::ACCEPTED);
    let id = approval["id"].as_str().unwrap().to_owned();
    let (_, sess) = f
        .env
        .call("GET", &format!("/sessions/{s}"), &f.mcp, None, None)
        .await;
    assert_eq!(sess["approval_id"], json!(id));
    let (st, listed) = f
        .env
        .call("GET", "/approvals?status=pending", &f.env.admin, None, None)
        .await;
    assert_eq!(st, StatusCode::OK);
    assert_eq!(listed.as_array().unwrap().len(), 1);
    let (st, decided) = f
        .env
        .call(
            "POST",
            &format!("/approvals/{id}/decision"),
            &f.env.admin,
            None,
            Some(json!({"approve": true})),
        )
        .await;
    assert_eq!(st, StatusCode::OK, "{decided}");
    assert_eq!(decided["status"], "approved");
    // A second decision is a conflict.
    let (st, _) = f
        .env
        .call(
            "POST",
            &format!("/approvals/{id}/decision"),
            &f.env.admin2,
            None,
            Some(json!({"approve": false})),
        )
        .await;
    assert_eq!(st, StatusCode::CONFLICT);
    // Editing the draft after approval invalidates it.
    let mut rule = zone_rule(r, "any", f.z_del, 1, &[]);
    rule["comment"] = json!("changed after approval");
    assert_eq!(
        f.mcp_call("PUT", &format!("/rules/{r}"), s, Some(rule.clone()))
            .await,
        StatusCode::OK
    );
    let (st, again) = f.mcp_publish(s).await;
    assert_eq!(st, StatusCode::ACCEPTED, "new approval needed: {again}");
    let id2 = again["id"].as_str().unwrap().to_owned();
    assert_ne!(id2, id);
    f.env
        .call(
            "POST",
            &format!("/approvals/{id2}/decision"),
            &f.env.admin,
            None,
            Some(json!({"approve": true})),
        )
        .await;
    let (st, rev) = f.mcp_publish(s).await;
    assert_eq!(st, StatusCode::CREATED, "{rev}");
    assert_eq!(rev["number"], 2);
}

#[tokio::test]
async fn widening_through_an_edited_object_requires_approval() {
    let f = fixture_or_skip!();
    let s = f.env.open(&f.mcp).await;
    // del_obj is used by an accept rule of the delegated zone: making it "*" widens that rule.
    let obj = domain(f.del_obj, "del", "*");
    assert_eq!(
        f.mcp_call("PUT", &format!("/objects/{}", f.del_obj), s, Some(obj))
            .await,
        StatusCode::OK
    );
    let (st, body) = f.mcp_publish(s).await;
    assert_eq!(st, StatusCode::ACCEPTED, "{body}");
}

#[tokio::test]
async fn publish_rechecks_delegation_revoked_after_the_change() {
    let f = fixture_or_skip!();
    let s = f.env.open(&f.mcp).await;
    let rule = zone_rule(Uuid::new_v4(), "free", f.z_del, 1, &[f.free_obj]);
    assert_eq!(
        f.mcp_call("POST", "/rules", s, Some(rule)).await,
        StatusCode::CREATED
    );
    // A human revokes the delegation and publishes.
    let h = f.env.open(&f.env.admin).await;
    let (st, _) = f
        .env
        .call(
            "PUT",
            &format!("/zones/{}", f.z_del),
            &f.env.admin,
            Some(h),
            Some(zone(f.z_del, "delegated", false)),
        )
        .await;
    assert_eq!(st, StatusCode::OK);
    f.env.publish(&f.env.admin, h).await;
    let (st, body) = f.mcp_publish(s).await;
    assert_eq!(st, StatusCode::FORBIDDEN, "{body}");
}

#[tokio::test]
async fn read_roles_and_plugin_token() {
    let f = fixture_or_skip!();
    for t in [&f.env.viewer, &f.env.auditor, &f.mcp, &f.env.admin] {
        let (st, objs) = f.env.call("GET", "/objects", t, None, None).await;
        assert_eq!(st, StatusCode::OK);
        assert_eq!(objs.as_array().unwrap().len(), 3);
    }
    let (st, _) = f
        .env
        .call("GET", "/objects", &f.env.plugin, None, None)
        .await;
    assert_eq!(st, StatusCode::FORBIDDEN);
    // Viewers and auditors cannot open sessions nor write.
    for t in [&f.env.viewer, &f.env.auditor, &f.env.plugin] {
        let (st, _) = f.env.call("POST", "/sessions", t, None, None).await;
        assert_eq!(st, StatusCode::FORBIDDEN);
    }
    let (st, _) = f.env.call("GET", "/objects", "nope", None, None).await;
    assert_eq!(st, StatusCode::UNAUTHORIZED);
}

// ---- Review of PR #13: bypass tests -------------------------------------------------------

fn eval_from_mcp(
    doc: &afw_core::policy::PolicyDocument,
    rev: u64,
    host: &str,
    ip: &str,
    classes: Vec<Uuid>,
) -> afw_engine::Decision {
    let installed = afw_core::installed::InstalledPolicy {
        format: afw_core::installed::INSTALLED_POLICY_FORMAT,
        revision: rev,
        published_at: chrono::Utc::now(),
        published_by: "x".into(),
        sha256: afw_core::installed::installed_sha256(rev, false, doc),
        rollback: false,
        document: doc.clone(),
    };
    let c = afw_engine::CompiledPolicy::compile(&installed, chrono::Utc::now()).unwrap();
    c.evaluate(&afw_engine::FlowContext {
        agent_ip: "10.0.0.5".parse().unwrap(),
        dst_ip: Some(ip.parse().unwrap()),
        dst_ip_trusted: true,
        dst_port: 443,
        l4: L4Proto::Tcp,
        app: None,
        host: Some(host.into()),
        method: None,
        path: None,
        data_classes: classes,
        now: chrono::Utc::now(),
    })
}

async fn latest_doc(f: &Fixture, n: u64) -> afw_core::policy::PolicyDocument {
    let (st, body) = f
        .env
        .call("GET", &format!("/revisions/{n}"), &f.env.admin, None, None)
        .await;
    assert_eq!(st, StatusCode::OK);
    serde_json::from_value(body["document"].clone()).unwrap()
}

/// Admin narrows the fixture's catch-all baseline deny to the metadata address (revision 2), so
/// that only the zone layers and implicit rules decide.
async fn narrow_baseline(f: &Fixture) {
    let a = &f.env.admin;
    let s = f.env.open(a).await;
    let md = Uuid::new_v4();
    f.env
        .create(
            a,
            s,
            "objects",
            json!({"id": md, "name": "md", "category": "cloud_metadata",
        "spec": {"type": "host", "ip": "169.254.169.254"}}),
        )
        .await;
    let (st, b) = f
        .env
        .call(
            "PUT",
            &format!("/rules/{}", f.r_base),
            a,
            Some(s),
            Some(baseline_rule(f.r_base, "no-metadata", 1, &[md])),
        )
        .await;
    assert_eq!(st, StatusCode::OK, "{b}");
    assert_eq!(f.env.publish(a, s).await, 2);
}

/// EF-51: an object of category `internal` (used by no rule) changes the implicit decision of
/// EVERY zone, including the MCP agent's own zone (implicit internal allow).
#[tokio::test]
async fn review_internal_category_object_opens_own_zone() {
    let f = fixture_or_skip!();
    // Before: the MCP's own traffic to the attacker is denied.
    narrow_baseline(&f).await;
    let doc = latest_doc(&f, 2).await;
    let d = eval_from_mcp(&doc, 2, "exfil.attacker.net", "203.0.113.9", vec![]);
    assert_eq!(d.verdict, Verdict::Deny, "before");
    let s = f.env.open(&f.mcp).await;
    let mut o = domain(Uuid::new_v4(), "harmless", "exfil.attacker.net");
    o["category"] = json!("internal");
    // Refused at creation (stricter than refusing the publication).
    let created = f.mcp_call("POST", "/objects", s, Some(o)).await;
    if created != StatusCode::CREATED {
        assert_eq!(created, StatusCode::FORBIDDEN);
        return;
    }
    let (st, body) = f.mcp_publish(s).await;
    let doc = latest_doc(&f, 3).await;
    let d = eval_from_mcp(&doc, 3, "exfil.attacker.net", "203.0.113.9", vec![]);
    assert!(
        !(st == StatusCode::CREATED && d.verdict == Verdict::Allow),
        "BYPASS: MCP published {body} and its own zone now reaches the attacker: {:?}",
        d.implicit
    );
}

/// EF-51: an agent created in a delegated zone with a public address makes that address an
/// internal destination for every zone (implicit allow from the MCP's own zone).
#[tokio::test]
async fn review_agent_address_opens_own_zone() {
    let f = fixture_or_skip!();
    narrow_baseline(&f).await;
    assert_eq!(
        eval_from_mcp(
            &latest_doc(&f, 2).await,
            2,
            "203.0.113.9",
            "203.0.113.9",
            vec![]
        )
        .verdict,
        Verdict::Deny
    );
    let s = f.env.open(&f.mcp).await;
    let mut a = agent(Uuid::new_v4(), "decoy", f.z_del, false);
    a["addresses"] = json!(["203.0.113.9"]);
    // Refused at creation (stricter than refusing the publication).
    let created = f.mcp_call("POST", "/agents", s, Some(a)).await;
    if created != StatusCode::CREATED {
        assert_eq!(created, StatusCode::FORBIDDEN);
        return;
    }
    let (st, body) = f.mcp_publish(s).await;
    let doc = latest_doc(&f, 3).await;
    let d = eval_from_mcp(&doc, 3, "203.0.113.9", "203.0.113.9", vec![]);
    assert!(
        !(st == StatusCode::CREATED && d.verdict == Verdict::Allow),
        "BYPASS: MCP published {body} and its own zone now reaches 203.0.113.9: {:?}",
        d.implicit
    );
}

/// EF-51/EF-52: an `llm_provider` object (used by no rule) exempts the destination from every
/// data-class rule, including the baseline secret-deny rule applied to the MCP's own zone.
#[tokio::test]
async fn review_llm_category_exempts_own_zone_from_dlp() {
    let f = fixture_or_skip!();
    narrow_baseline(&f).await;
    // Admin: baseline rule "deny secrets anywhere" + an accept-any rule in the MCP zone.
    let a = &f.env.admin;
    let s = f.env.open(a).await;
    let sec = Uuid::new_v4();
    f.env
        .create(a, s, "data-classes", secret_class(sec, "aws"))
        .await;
    let mut b = baseline_rule(Uuid::new_v4(), "no-secrets", 2, &[]);
    b["data_classes"] = json!([sec]);
    f.env.create(a, s, "rules", b).await;
    let any = Uuid::new_v4();
    f.env
        .create(
            a,
            s,
            "objects",
            domain(any, "attacker", "exfil.attacker.net"),
        )
        .await;
    f.env
        .create(
            a,
            s,
            "rules",
            zone_rule(Uuid::new_v4(), "own-to-attacker", f.z_own, 2, &[any]),
        )
        .await;
    assert_eq!(f.env.publish(a, s).await, 3);
    let doc = latest_doc(&f, 3).await;
    assert_eq!(
        eval_from_mcp(&doc, 3, "exfil.attacker.net", "203.0.113.9", vec![sec]).verdict,
        Verdict::Deny
    );
    // MCP: new llm_provider object for the same destination, used by nothing.
    let s = f.env.open(&f.mcp).await;
    let mut o = domain(Uuid::new_v4(), "my llm", "exfil.attacker.net");
    o["category"] = json!("llm_provider");
    // Refused at creation (stricter than refusing the publication).
    let created = f.mcp_call("POST", "/objects", s, Some(o)).await;
    if created != StatusCode::CREATED {
        assert_eq!(created, StatusCode::FORBIDDEN);
        return;
    }
    let (st, body) = f.mcp_publish(s).await;
    let doc = latest_doc(&f, 4).await;
    let d = eval_from_mcp(&doc, 4, "exfil.attacker.net", "203.0.113.9", vec![sec]);
    assert!(
        !(st == StatusCode::CREATED && d.verdict == Verdict::Allow),
        "BYPASS: MCP published {body}; secrets from its own zone now leave: {:?}",
        d.rule_name
    );
}

/// EF-52: the whole IPv4 Internet through two /1 networks is not detected as a widening.
#[tokio::test]
async fn review_two_half_internets_need_no_approval() {
    let f = fixture_or_skip!();
    let s = f.env.open(&f.mcp).await;
    let (h1, h2) = (Uuid::new_v4(), Uuid::new_v4());
    for (id, cidr) in [(h1, "0.0.0.0/1"), (h2, "128.0.0.0/1")] {
        let o = json!({"id": id, "name": cidr, "spec": {"type": "network", "cidr": cidr}});
        assert_eq!(
            f.mcp_call("POST", "/objects", s, Some(o)).await,
            StatusCode::CREATED
        );
    }
    let r = zone_rule(Uuid::new_v4(), "internet", f.z_del, 1, &[h1, h2]);
    assert_eq!(
        f.mcp_call("POST", "/rules", s, Some(r)).await,
        StatusCode::CREATED
    );
    let (st, body) = f.mcp_publish(s).await;
    assert_eq!(
        st,
        StatusCode::ACCEPTED,
        "BYPASS EF-52: published without approval: {body}"
    );
}

/// EF-52: switching a delegated zone to observe mode (= everything allowed) needs no approval.
#[tokio::test]
async fn review_observe_mode_needs_no_approval() {
    let f = fixture_or_skip!();
    let s = f.env.open(&f.mcp).await;
    let mut z = zone(f.z_del, "delegated", true);
    z["mode"] = json!("observe");
    assert_eq!(
        f.mcp_call("PUT", &format!("/zones/{}", f.z_del), s, Some(z))
            .await,
        StatusCode::OK
    );
    let (st, body) = f.mcp_publish(s).await;
    assert_eq!(
        st,
        StatusCode::ACCEPTED,
        "BYPASS EF-52: published without approval: {body}"
    );
}

/// A human rolled the gateways back to revision 1; the MCP agent re-installs the latest
/// revision, undoing the human rollback.
#[tokio::test]
async fn review_mcp_undoes_human_rollback() {
    let f = fixture_or_skip!();
    let a = &f.env.admin;
    let s = f.env.open(a).await;
    f.env
        .create(
            a,
            s,
            "objects",
            domain(Uuid::new_v4(), "x", "x.example.com"),
        )
        .await;
    assert_eq!(f.env.publish(a, s).await, 2);
    let gw = f.env.gateway().await;
    let (st, _) = f
        .env
        .call(
            "POST",
            "/installs",
            a,
            None,
            Some(json!({"revision": 1, "gateways": [gw]})),
        )
        .await;
    assert_eq!(st, StatusCode::ACCEPTED);
    let (st, _) = f
        .env
        .call(
            "POST",
            "/installs",
            &f.mcp,
            None,
            Some(json!({"revision": 2, "gateways": [gw]})),
        )
        .await;
    assert_ne!(st, StatusCode::ACCEPTED, "MCP undid a human rollback");
}
