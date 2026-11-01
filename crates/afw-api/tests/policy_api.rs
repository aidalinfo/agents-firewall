//! Functional tests of the policy API (lot L7a). Skipped when `AFW_TEST_DATABASE_URL` is not set.

mod policy_support;

use std::collections::HashMap;
use std::sync::Arc;

use afw_api::ApiError;
use afw_api::policy::install::{installed_policy_for, record_install_ack};
use afw_api::policy::{FlowFuture, FlowLookup};
use afw_core::events::{DecisionRef, FlowEvent, Verdict};
use afw_core::policy::L4Proto;
use afw_core::protocol::PolicyAck;
use axum::http::StatusCode;
use policy_support::*;
use serde_json::{Value, json};
use uuid::Uuid;

macro_rules! env_or_skip {
    ($e:expr) => {
        match $e.await {
            Some(env) => env,
            None => {
                eprintln!("AFW_TEST_DATABASE_URL not set: skipped");
                return;
            }
        }
    };
}

fn ids(v: &Value) -> Vec<String> {
    v.as_array()
        .unwrap()
        .iter()
        .map(|x| x["id"].as_str().unwrap().to_owned())
        .collect()
}

#[tokio::test]
async fn crud_reads_draft_or_published_state() {
    let env = env_or_skip!(env());
    let a = &env.admin;
    let s = env.open(a).await;
    let o = Uuid::new_v4();
    env.create(a, s, "objects", domain(o, "example", "example.com"))
        .await;
    // Not published yet.
    let (_, published) = env.call("GET", "/objects", a, None, None).await;
    assert!(ids(&published).is_empty());
    let (_, draft) = env.call("GET", "/objects", a, Some(s), None).await;
    assert_eq!(ids(&draft), vec![o.to_string()]);
    let (st, _) = env
        .call("GET", &format!("/objects/{o}"), a, None, None)
        .await;
    assert_eq!(st, StatusCode::NOT_FOUND);
    // Duplicate id, path/body mismatch, unknown fields, missing session.
    let (st, _) = env
        .call(
            "POST",
            "/objects",
            a,
            Some(s),
            Some(domain(o, "dup", "dup.com")),
        )
        .await;
    assert_eq!(st, StatusCode::CONFLICT);
    let (st, _) = env
        .call(
            "PUT",
            &format!("/objects/{}", Uuid::new_v4()),
            a,
            Some(s),
            Some(domain(o, "x", "x.com")),
        )
        .await;
    assert_eq!(st, StatusCode::BAD_REQUEST);
    let mut bad = domain(Uuid::new_v4(), "typo", "typo.com");
    bad["destination"] = json!([]);
    let (st, _) = env.call("POST", "/objects", a, Some(s), Some(bad)).await;
    assert!(st.is_client_error(), "unknown field refused: {st}");
    let (st, _) = env
        .call(
            "POST",
            "/objects",
            a,
            None,
            Some(domain(Uuid::new_v4(), "n", "n.com")),
        )
        .await;
    assert_eq!(st, StatusCode::BAD_REQUEST, "session header required");
    // Update then publish.
    let (st, upd) = env
        .call(
            "PUT",
            &format!("/objects/{o}"),
            a,
            Some(s),
            Some(domain(o, "example", "www.example.com")),
        )
        .await;
    assert_eq!(st, StatusCode::OK, "{upd}");
    assert_eq!(env.publish(a, s).await, 1);
    let (st, got) = env
        .call("GET", &format!("/objects/{o}"), &env.viewer, None, None)
        .await;
    assert_eq!(st, StatusCode::OK);
    assert_eq!(got["spec"]["pattern"], "www.example.com");
    // Every resource kind.
    let s = env.open(a).await;
    let (z, svc, dc, ag, r, ir) = (
        Uuid::new_v4(),
        Uuid::new_v4(),
        Uuid::new_v4(),
        Uuid::new_v4(),
        Uuid::new_v4(),
        Uuid::new_v4(),
    );
    env.create(a, s, "zones", zone(z, "prod", false)).await;
    env.create(a, s, "services", tcp_service(svc, "https", 443))
        .await;
    env.create(a, s, "data-classes", secret_class(dc, "aws"))
        .await;
    env.create(a, s, "agents", agent(ag, "bot", z, false)).await;
    env.create(a, s, "rules", zone_rule(r, "web", z, 1, &[o]))
        .await;
    env.create(
        a,
        s,
        "inspection-rules",
        json!({"id": ir, "name": "pinning", "position": 1, "zones": [z],
               "destinations": [o], "action": "bypass"}),
    )
    .await;
    for (col, id) in [
        ("zones", z),
        ("services", svc),
        ("data-classes", dc),
        ("agents", ag),
        ("rules", r),
        ("inspection-rules", ir),
    ] {
        let (st, _) = env
            .call("GET", &format!("/{col}/{id}"), a, Some(s), None)
            .await;
        assert_eq!(st, StatusCode::OK, "{col}");
    }
    // A zone rule's empty sources become the zone itself; other sources are refused.
    let mut empty = zone_rule(Uuid::new_v4(), "empty-src", z, 2, &[o]);
    empty["sources"] = json!([]);
    let created = env.create(a, s, "rules", empty).await;
    assert_eq!(created["sources"], json!([z]));
    let mut foreign = zone_rule(Uuid::new_v4(), "foreign", z, 3, &[o]);
    foreign["sources"] = json!([Uuid::new_v4()]);
    let (st, _) = env.call("POST", "/rules", a, Some(s), Some(foreign)).await;
    assert_eq!(st, StatusCode::BAD_REQUEST);
    // Referenced resources cannot be deleted.
    let (st, _) = env
        .call("DELETE", &format!("/objects/{o}"), a, Some(s), None)
        .await;
    assert_eq!(st, StatusCode::CONFLICT);
    let (st, _) = env
        .call("DELETE", &format!("/zones/{z}"), a, Some(s), None)
        .await;
    assert_eq!(st, StatusCode::CONFLICT);
    let (st, _) = env
        .call(
            "DELETE",
            &format!("/inspection-rules/{ir}"),
            a,
            Some(s),
            None,
        )
        .await;
    assert_eq!(st, StatusCode::NO_CONTENT);
    // Settings.
    let (st, settings) = env.call("GET", "/settings", a, Some(s), None).await;
    assert_eq!(st, StatusCode::OK);
    assert_eq!(settings["retention_days"]["flows"], 30);
    let mut new_settings = settings.clone();
    new_settings["retention_days"]["flows"] = json!(90);
    let (st, _) = env
        .call("PUT", "/settings", a, Some(s), Some(new_settings))
        .await;
    assert_eq!(st, StatusCode::OK);
    assert_eq!(env.publish(a, s).await, 2);
    let (_, settings) = env.call("GET", "/settings", a, None, None).await;
    assert_eq!(settings["retention_days"]["flows"], 90);
    // Session closed: further changes refused.
    let (st, _) = env
        .call(
            "POST",
            "/zones",
            a,
            Some(s),
            Some(zone(Uuid::new_v4(), "late", false)),
        )
        .await;
    assert_eq!(st, StatusCode::CONFLICT);
}

#[tokio::test]
async fn where_used_lists_rules_groups_and_inspection_rules() {
    let env = env_or_skip!(env());
    let a = &env.admin;
    let s = env.open(a).await;
    let (z, o, g, r1, r2, ir) = (
        Uuid::new_v4(),
        Uuid::new_v4(),
        Uuid::new_v4(),
        Uuid::new_v4(),
        Uuid::new_v4(),
        Uuid::new_v4(),
    );
    env.create(a, s, "zones", zone(z, "z", false)).await;
    env.create(a, s, "objects", domain(o, "o", "o.example.com"))
        .await;
    env.create(a, s, "objects", group(g, "g", &[o])).await;
    env.create(a, s, "rules", zone_rule(r1, "direct", z, 1, &[o]))
        .await;
    env.create(a, s, "rules", zone_rule(r2, "via-group", z, 2, &[g]))
        .await;
    env.create(
        a,
        s,
        "inspection-rules",
        json!({"id": ir, "name": "i", "position": 1, "destinations": [o], "action": "inspect"}),
    )
    .await;
    let (st, wu) = env
        .call("GET", &format!("/objects/{o}/where-used"), a, Some(s), None)
        .await;
    assert_eq!(st, StatusCode::OK, "{wu}");
    let refs: Vec<(String, String)> = wu["references"]
        .as_array()
        .unwrap()
        .iter()
        .map(|r| {
            (
                r["kind"].as_str().unwrap().to_owned(),
                r["id"].as_str().unwrap().to_owned(),
            )
        })
        .collect();
    for (kind, id) in [
        ("object", g),
        ("rule", r1),
        ("rule", r2),
        ("inspection_rule", ir),
    ] {
        assert!(
            refs.contains(&(kind.to_owned(), id.to_string())),
            "{kind} {id}: {wu}"
        );
    }
    let (st, _) = env
        .call(
            "GET",
            &format!("/objects/{}/where-used", Uuid::new_v4()),
            a,
            Some(s),
            None,
        )
        .await;
    assert_eq!(st, StatusCode::NOT_FOUND);
}

#[tokio::test]
async fn locks_between_sessions_and_discard() {
    let env = env_or_skip!(env());
    let (a, b) = (&env.admin, &env.admin2);
    let s0 = env.open(a).await;
    let o = Uuid::new_v4();
    env.create(a, s0, "objects", domain(o, "o", "o.example.com"))
        .await;
    env.publish(a, s0).await;

    let s1 = env.open(a).await;
    let s2 = env.open(b).await;
    // One open session per caller.
    let (st, _) = env.call("POST", "/sessions", a, None, None).await;
    assert_eq!(st, StatusCode::CONFLICT);
    let (st, cur) = env.call("GET", "/sessions/current", a, None, None).await;
    assert_eq!(st, StatusCode::OK);
    assert_eq!(cur["id"], json!(s1));
    let (st, _) = env
        .call("GET", "/sessions/current", &env.auditor, None, None)
        .await;
    assert_eq!(st, StatusCode::NOT_FOUND);

    let (st, _) = env
        .call(
            "PUT",
            &format!("/objects/{o}"),
            a,
            Some(s1),
            Some(domain(o, "o", "a.example.com")),
        )
        .await;
    assert_eq!(st, StatusCode::OK);
    let (st, body) = env
        .call(
            "PUT",
            &format!("/objects/{o}"),
            b,
            Some(s2),
            Some(domain(o, "o", "b.example.com")),
        )
        .await;
    assert_eq!(st, StatusCode::LOCKED, "{body}");
    assert!(body["detail"].as_str().unwrap().contains("alice"), "{body}");
    let (st, _) = env
        .call("DELETE", &format!("/objects/{o}"), b, Some(s2), None)
        .await;
    assert_eq!(st, StatusCode::LOCKED);
    // Session listing shows the lock.
    let (_, sess) = env
        .call("GET", &format!("/sessions/{s1}"), b, None, None)
        .await;
    assert_eq!(sess["changes"], 1);
    assert_eq!(sess["locks"][0]["id"], json!(o));
    let (_, open) = env.call("GET", "/sessions", &env.viewer, None, None).await;
    assert_eq!(open.as_array().unwrap().len(), 2);
    // Another admin may not publish someone else's session.
    let (st, _) = env
        .call(
            "POST",
            &format!("/sessions/{s1}/publish"),
            b,
            None,
            Some(json!({"comment": "x"})),
        )
        .await;
    assert_eq!(st, StatusCode::FORBIDDEN);
    // Discard releases the lock.
    let (st, discarded) = env
        .call("POST", &format!("/sessions/{s1}/discard"), a, None, None)
        .await;
    assert_eq!(st, StatusCode::OK);
    assert_eq!(discarded["state"], "discarded");
    let (st, _) = env
        .call(
            "PUT",
            &format!("/objects/{o}"),
            b,
            Some(s2),
            Some(domain(o, "o", "b.example.com")),
        )
        .await;
    assert_eq!(st, StatusCode::OK);
    // Reverting to the published value drops the change.
    let (st, _) = env
        .call(
            "PUT",
            &format!("/objects/{o}"),
            b,
            Some(s2),
            Some(domain(o, "o", "o.example.com")),
        )
        .await;
    assert_eq!(st, StatusCode::OK);
    let (_, sess) = env
        .call("GET", &format!("/sessions/{s2}"), b, None, None)
        .await;
    assert_eq!(sess["changes"], 0);
    // Publishing an empty session is a conflict.
    let (st, _) = env
        .call(
            "POST",
            &format!("/sessions/{s2}/publish"),
            b,
            None,
            Some(json!({"comment": "x"})),
        )
        .await;
    assert_eq!(st, StatusCode::CONFLICT);
}

#[tokio::test]
async fn publish_creates_numbered_revisions_with_diff() {
    let env = env_or_skip!(env());
    let a = &env.admin;
    let s = env.open(a).await;
    let (z, o, r) = (Uuid::new_v4(), Uuid::new_v4(), Uuid::new_v4());
    env.create(a, s, "zones", zone(z, "z", false)).await;
    env.create(a, s, "objects", domain(o, "o", "o.example.com"))
        .await;
    env.create(a, s, "rules", zone_rule(r, "r", z, 1, &[o]))
        .await;
    assert_eq!(env.publish(a, s).await, 1);
    let s = env.open(a).await;
    let mut rule = zone_rule(r, "r", z, 1, &[o]);
    rule["action"] = json!("deny");
    env.call("PUT", &format!("/rules/{r}"), a, Some(s), Some(rule))
        .await;
    let o2 = Uuid::new_v4();
    env.create(a, s, "objects", domain(o2, "o2", "o2.example.com"))
        .await;
    assert_eq!(env.publish(a, s).await, 2);

    let (st, page) = env
        .call("GET", "/revisions?limit=1", &env.viewer, None, None)
        .await;
    assert_eq!(st, StatusCode::OK);
    assert_eq!(page["items"][0]["number"], 2);
    assert_eq!(page["items"][0]["published_by"]["name"], "alice");
    let cursor = page["next_cursor"].as_str().unwrap().to_owned();
    let (_, page2) = env
        .call(
            "GET",
            &format!("/revisions?limit=1&cursor={cursor}"),
            a,
            None,
            None,
        )
        .await;
    assert_eq!(page2["items"][0]["number"], 1);
    assert!(page2["next_cursor"].is_null());

    let (st, detail) = env.call("GET", "/revisions/2", a, None, None).await;
    assert_eq!(st, StatusCode::OK);
    assert_eq!(detail["document"]["objects"].as_array().unwrap().len(), 2);
    assert_eq!(detail["revision"]["sha256"].as_str().unwrap().len(), 64);
    let (st, diff) = env.call("GET", "/revisions/2/diff", a, None, None).await;
    assert_eq!(st, StatusCode::OK);
    assert_eq!(diff["from"], 1);
    assert_eq!(diff["to"], 2);
    let changes = diff["changes"].as_array().unwrap();
    assert_eq!(changes.len(), 2, "{diff}");
    let modified = changes.iter().find(|c| c["kind"] == "modified").unwrap();
    assert_eq!(modified["resource"]["kind"], "rule");
    assert_eq!(modified["before"]["action"], "accept");
    assert_eq!(modified["after"]["action"], "deny");
    assert!(
        changes
            .iter()
            .any(|c| c["kind"] == "added" && c["resource"]["id"] == json!(o2))
    );
    let (_, full) = env
        .call("GET", "/revisions/2/diff?against=0", a, None, None)
        .await;
    assert_eq!(full["changes"].as_array().unwrap().len(), 4);
    let (st, _) = env.call("GET", "/revisions/9", a, None, None).await;
    assert_eq!(st, StatusCode::NOT_FOUND);

    // Broken reference: refused at publish (deleting a referenced object in the draft is
    // refused, so build it through import of a rule pointing to a missing object).
    let s = env.open(a).await;
    let ghost = Uuid::new_v4();
    let (st, out) = env
        .call(
            "POST",
            &format!("/sessions/{s}/import"),
            a,
            None,
            Some(json!({"rules": [zone_rule(Uuid::new_v4(), "ghost", z, 5, &[ghost])]})),
        )
        .await;
    assert_eq!(st, StatusCode::OK, "{out}");
    let (st, out) = env
        .call(
            "POST",
            &format!("/sessions/{s}/publish"),
            a,
            None,
            Some(json!({"comment": "x"})),
        )
        .await;
    assert_eq!(st, StatusCode::CONFLICT, "{out}");
    assert!(
        out["detail"].as_str().unwrap().contains(&ghost.to_string()),
        "{out}"
    );

    // Revert opens a session whose draft equals revision 1.
    env.call("POST", &format!("/sessions/{s}/discard"), a, None, None)
        .await;
    let (st, sess) = env.call("POST", "/revisions/1/revert", a, None, None).await;
    assert_eq!(st, StatusCode::CREATED, "{sess}");
    let rs: Uuid = sess["id"].as_str().unwrap().parse().unwrap();
    assert_eq!(sess["changes"], 2);
    assert_eq!(env.publish(a, rs).await, 3);
    let (_, d) = env
        .call("GET", "/revisions/3/diff?against=1", a, None, None)
        .await;
    assert!(d["changes"].as_array().unwrap().is_empty(), "{d}");
}

#[tokio::test]
async fn rules_move_renumbers_the_layer() {
    let env = env_or_skip!(env());
    let a = &env.admin;
    let s = env.open(a).await;
    let z = Uuid::new_v4();
    env.create(a, s, "zones", zone(z, "z", false)).await;
    let rs: Vec<Uuid> = (0..3).map(|_| Uuid::new_v4()).collect();
    for (i, r) in rs.iter().enumerate() {
        env.create(
            a,
            s,
            "rules",
            zone_rule(*r, &format!("r{i}"), z, i as u32 + 1, &[]),
        )
        .await;
    }
    let (st, moved) = env
        .call(
            "POST",
            &format!("/rules/{}/move", rs[2]),
            a,
            Some(s),
            Some(json!({"position": 1})),
        )
        .await;
    assert_eq!(st, StatusCode::OK, "{moved}");
    assert_eq!(moved["position"], 1);
    let (_, rules) = env.call("GET", "/rules", a, Some(s), None).await;
    let pos: HashMap<String, u64> = rules
        .as_array()
        .unwrap()
        .iter()
        .map(|r| {
            (
                r["id"].as_str().unwrap().to_owned(),
                r["position"].as_u64().unwrap(),
            )
        })
        .collect();
    assert_eq!(pos[&rs[2].to_string()], 1);
    assert_eq!(pos[&rs[0].to_string()], 2);
    assert_eq!(pos[&rs[1].to_string()], 3);
    // Rules are listed in evaluation order.
    assert_eq!(
        ids(&rules),
        vec![rs[2].to_string(), rs[0].to_string(), rs[1].to_string()]
    );
}

#[tokio::test]
async fn verify_reports_expired_rules_and_unused_objects() {
    let env = env_or_skip!(env());
    let a = &env.admin;
    let s = env.open(a).await;
    let (z, used, unused, r) = (
        Uuid::new_v4(),
        Uuid::new_v4(),
        Uuid::new_v4(),
        Uuid::new_v4(),
    );
    env.create(a, s, "zones", zone(z, "z", false)).await;
    env.create(a, s, "objects", domain(used, "used", "u.example.com"))
        .await;
    env.create(a, s, "objects", domain(unused, "unused", "n.example.com"))
        .await;
    let mut rule = zone_rule(r, "old", z, 1, &[used]);
    rule["expires_at"] = json!("2020-01-01T00:00:00Z");
    env.create(a, s, "rules", rule).await;
    let (st, report) = env.call("GET", "/verify", a, Some(s), None).await;
    assert_eq!(st, StatusCode::OK, "{report}");
    assert!(report["revision"].is_null());
    let findings = report["findings"].as_array().unwrap();
    assert!(
        findings.contains(&json!({"type": "expired", "rule": r})),
        "{report}"
    );
    assert!(
        findings.contains(&json!({"type": "unused_object", "id": unused})),
        "{report}"
    );
    assert!(!findings.contains(&json!({"type": "unused_object", "id": used})));
    env.publish(a, s).await;
    let (_, report) = env
        .call("GET", "/verify?revision=1", &env.viewer, None, None)
        .await;
    assert_eq!(report["revision"], 1);
    assert!(!report["findings"].as_array().unwrap().is_empty());
}

#[tokio::test]
async fn install_ack_and_rollback() {
    let env = env_or_skip!(env());
    let a = &env.admin;
    let gw = env.gateway().await;
    let s = env.open(a).await;
    env.create(
        a,
        s,
        "objects",
        domain(Uuid::new_v4(), "o", "o.example.com"),
    )
    .await;
    env.publish(a, s).await;
    let s = env.open(a).await;
    env.create(
        a,
        s,
        "objects",
        domain(Uuid::new_v4(), "o2", "o2.example.com"),
    )
    .await;
    env.publish(a, s).await;

    assert!(installed_policy_for(&env.pool, gw).await.unwrap().is_none());
    let (st, _) = env
        .call(
            "POST",
            "/installs",
            &env.viewer,
            None,
            Some(json!({"revision": 1, "gateways": [gw]})),
        )
        .await;
    assert_eq!(st, StatusCode::FORBIDDEN);
    let (st, _) = env
        .call(
            "POST",
            "/installs",
            a,
            None,
            Some(json!({"revision": 7, "gateways": [gw]})),
        )
        .await;
    assert_eq!(st, StatusCode::NOT_FOUND);
    let (st, res) = env
        .call(
            "POST",
            "/installs",
            a,
            None,
            Some(json!({"revision": 2, "gateways": [gw]})),
        )
        .await;
    assert_eq!(st, StatusCode::ACCEPTED, "{res}");
    assert_eq!(res["installs"][0]["state"], "pending");
    let p = installed_policy_for(&env.pool, gw).await.unwrap().unwrap();
    assert_eq!(p.revision, 2);
    assert!(!p.rollback);
    p.verify().unwrap();
    assert_eq!(p.document.objects.len(), 2);

    record_install_ack(
        &env.pool,
        gw,
        &PolicyAck {
            revision: 2,
            ok: true,
            error: None,
        },
    )
    .await
    .unwrap();
    let (_, list) = env
        .call(
            "GET",
            &format!("/installs?gateway={gw}"),
            &env.viewer,
            None,
            None,
        )
        .await;
    assert_eq!(list["items"][0]["state"], "installed");
    assert!(!list["items"][0]["acked_at"].is_null());

    // Rollback = install an older revision; the installed policy carries the rollback flag.
    let (st, _) = env
        .call(
            "POST",
            "/installs",
            a,
            None,
            Some(json!({"revision": 1, "gateways": [gw]})),
        )
        .await;
    assert_eq!(st, StatusCode::ACCEPTED);
    let p = installed_policy_for(&env.pool, gw).await.unwrap().unwrap();
    assert_eq!(p.revision, 1);
    assert!(p.rollback);
    p.verify().unwrap();
    assert!(p.may_replace(Some(2)));
    record_install_ack(
        &env.pool,
        gw,
        &PolicyAck {
            revision: 1,
            ok: false,
            error: Some("compile error".into()),
        },
    )
    .await
    .unwrap();
    let (_, list) = env
        .call(
            "GET",
            &format!("/installs?gateway={gw}&revision=1"),
            a,
            None,
            None,
        )
        .await;
    assert_eq!(list["items"].as_array().unwrap().len(), 1);
    assert_eq!(list["items"][0]["state"], "failed");
    assert_eq!(list["items"][0]["error"], "compile error");

    // Empty gateway list = every known gateway.
    let (st, res) = env
        .call("POST", "/installs", a, None, Some(json!({"revision": 2})))
        .await;
    assert_eq!(st, StatusCode::ACCEPTED);
    assert_eq!(res["installs"].as_array().unwrap().len(), 1);
    assert_eq!(res["installs"][0]["gateway_id"], json!(gw));
}

struct Flows(HashMap<Uuid, FlowEvent>);

impl FlowLookup for Flows {
    fn get_flow(&self, id: Uuid) -> FlowFuture<'_> {
        let flow = self.0.get(&id).cloned();
        Box::pin(async move { Ok::<_, ApiError>(flow) })
    }
}

#[tokio::test]
async fn allow_from_log_prefills_a_rule_at_the_top_of_the_zone() {
    let (z, ag, flow_id, flow2) = (
        Uuid::new_v4(),
        Uuid::new_v4(),
        Uuid::new_v4(),
        Uuid::new_v4(),
    );
    let make = |id: Uuid| FlowEvent {
        id,
        gateway_id: Uuid::new_v4(),
        agent_id: Some(ag),
        zone_id: None,
        src: "10.0.0.5:40000".parse().unwrap(),
        dst: "93.184.216.34:443".parse().unwrap(),
        protocol: L4Proto::Tcp,
        app: None,
        domain: Some("API.Example.org".into()),
        sni: None,
        bytes_out: 1,
        bytes_in: 1,
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
        deny_mode: None,
    };
    let flows = Flows(HashMap::from([
        (flow_id, make(flow_id)),
        (flow2, make(flow2)),
    ]));
    let env = env_or_skip!(env_with(Some(Arc::new(flows))));
    let a = &env.admin;
    let s = env.open(a).await;
    let existing = Uuid::new_v4();
    env.create(a, s, "zones", zone(z, "z", false)).await;
    env.create(a, s, "agents", agent(ag, "bot", z, false)).await;
    env.create(a, s, "rules", zone_rule(existing, "first", z, 1, &[]))
        .await;
    env.publish(a, s).await;

    let s = env.open(a).await;
    let (st, out) = env
        .call(
            "POST",
            &format!("/sessions/{s}/allow-from-log"),
            a,
            None,
            Some(json!({"flow_id": flow_id})),
        )
        .await;
    assert_eq!(st, StatusCode::CREATED, "{out}");
    let rule = &out["rule"];
    assert_eq!(rule["action"], "accept");
    assert_eq!(rule["position"], 1);
    assert_eq!(rule["track"], "detailed");
    assert_eq!(rule["sources"], json!([z]));
    assert_eq!(rule["layer"], json!({"type": "zone", "zone_id": z}));
    assert!(
        rule["comment"]
            .as_str()
            .unwrap()
            .contains(&flow_id.to_string())
    );
    assert_eq!(rule["services"].as_array().unwrap().len(), 1);
    let created = &out["created_object"];
    assert_eq!(
        created["spec"],
        json!({"type": "domain", "pattern": "api.example.org"})
    );
    // The previous first rule moved down; the draft holds both.
    let (_, first) = env
        .call("GET", &format!("/rules/{existing}"), a, Some(s), None)
        .await;
    assert_eq!(first["position"], 2);
    // The second time, the object (and service) are reused.
    let (st, out2) = env
        .call(
            "POST",
            &format!("/sessions/{s}/allow-from-log"),
            a,
            None,
            Some(json!({"flow_id": flow2})),
        )
        .await;
    assert_eq!(st, StatusCode::CREATED);
    assert!(out2["created_object"].is_null(), "{out2}");
    assert_eq!(out2["rule"]["destinations"], rule["destinations"]);
    assert_eq!(out2["rule"]["services"], rule["services"]);
    let (st, _) = env
        .call(
            "POST",
            &format!("/sessions/{s}/allow-from-log"),
            a,
            None,
            Some(json!({"flow_id": Uuid::new_v4()})),
        )
        .await;
    assert_eq!(st, StatusCode::NOT_FOUND);
    // Publishable as is.
    env.publish(a, s).await;
}

#[tokio::test]
async fn every_mutation_is_audited_with_interface_and_session() {
    let env = env_or_skip!(env());
    let a = &env.admin;
    let (st, sess) = env
        .call_iface("POST", "/sessions", a, None, None, Some("cli"))
        .await;
    assert_eq!(st, StatusCode::CREATED);
    let s: Uuid = sess["id"].as_str().unwrap().parse().unwrap();
    let o = Uuid::new_v4();
    let (st, _) = env
        .call_iface(
            "POST",
            "/objects",
            a,
            Some(s),
            Some(domain(o, "o", "o.com")),
            Some("cli"),
        )
        .await;
    assert_eq!(st, StatusCode::CREATED);
    let (st, _) = env
        .call_iface(
            "PUT",
            &format!("/objects/{o}"),
            a,
            Some(s),
            Some(domain(o, "o", "p.com")),
            Some("ui"),
        )
        .await;
    assert_eq!(st, StatusCode::OK);
    env.publish(a, s).await;
    let rows: Vec<(String, String, Option<Uuid>, String, serde_json::Value)> = sqlx::query_as(
        "SELECT action, interface, session_id, target, diff FROM audit_log ORDER BY seq",
    )
    .fetch_all(&env.pool)
    .await
    .unwrap();
    let actions: Vec<&str> = rows.iter().map(|r| r.0.as_str()).collect();
    assert_eq!(
        actions,
        [
            "session.open",
            "object.create",
            "object.update",
            "session.publish"
        ]
    );
    assert_eq!(rows[1].1, "cli");
    assert_eq!(rows[2].1, "ui");
    assert!(rows.iter().all(|r| r.2 == Some(s)));
    assert_eq!(rows[1].3, format!("object:{o}"));
    assert_eq!(rows[2].4["before"]["spec"]["pattern"], "o.com");
    assert_eq!(rows[2].4["after"]["spec"]["pattern"], "p.com");
    // Refused mutations leave no trace and no change.
    let s = env.open(a).await;
    let (st, _) = env
        .call(
            "POST",
            "/objects",
            &env.viewer,
            Some(s),
            Some(domain(Uuid::new_v4(), "v", "v.com")),
        )
        .await;
    assert_eq!(st, StatusCode::FORBIDDEN);
    let n: i64 =
        sqlx::query_scalar("SELECT count(*) FROM audit_log WHERE action = 'object.create'")
            .fetch_one(&env.pool)
            .await
            .unwrap();
    assert_eq!(n, 1);
    // Install is audited too.
    let (st, _) = env
        .call(
            "POST",
            "/installs",
            a,
            None,
            Some(json!({"revision": 1, "gateways": [env.gateway().await]})),
        )
        .await;
    assert_eq!(st, StatusCode::ACCEPTED);
    let n: i64 =
        sqlx::query_scalar("SELECT count(*) FROM audit_log WHERE action = 'install.request'")
            .fetch_one(&env.pool)
            .await
            .unwrap();
    assert_eq!(n, 1);
    let entries = afw_api::audit::load(&env.pool, 1, 1000).await.unwrap();
    assert_eq!(afw_core::audit::verify_chain(&entries), Ok(()));
}

#[tokio::test]
async fn import_merges_a_document_into_the_session() {
    let env = env_or_skip!(env());
    let a = &env.admin;
    let s = env.open(a).await;
    let (z, o, r) = (Uuid::new_v4(), Uuid::new_v4(), Uuid::new_v4());
    let doc = json!({
        "zones": [zone(z, "imported", false)],
        "objects": [domain(o, "o", "o.example.com")],
        "rules": [zone_rule(r, "r", z, 1, &[o])],
    });
    let (st, out) = env
        .call("POST", &format!("/sessions/{s}/import"), a, None, Some(doc))
        .await;
    assert_eq!(st, StatusCode::OK, "{out}");
    assert_eq!(out["changes"], 3);
    let (_, rules) = env.call("GET", "/rules", a, Some(s), None).await;
    assert_eq!(ids(&rules), vec![r.to_string()]);
    assert_eq!(env.publish(a, s).await, 1);
    let (st, _) = env
        .call(
            "POST",
            &format!("/sessions/{s}/import"),
            a,
            None,
            Some(json!({"bogus": 1})),
        )
        .await;
    assert!(st.is_client_error());
}

struct Stats(afw_api::policy::RuleStats);

impl afw_api::policy::RuleStatsSource for Stats {
    fn rule_stats(&self) -> afw_api::policy::StatsFuture<'_> {
        let s = self.0.clone();
        Box::pin(async move { Ok::<_, ApiError>(s) })
    }
}

#[tokio::test]
async fn rule_views_and_rulebase() {
    let mut env = env_or_skip!(env());
    let (za, zb, base, r1, r2, r3) = (
        Uuid::new_v4(),
        Uuid::new_v4(),
        Uuid::new_v4(),
        Uuid::new_v4(),
        Uuid::new_v4(),
        Uuid::new_v4(),
    );
    let hit_at = chrono::Utc::now();
    env.state.rule_stats = Some(Arc::new(Stats(HashMap::from([(r1, (42, Some(hit_at)))]))));
    let a = env.admin.clone();
    let s = env.open(&a).await;
    env.create(&a, s, "zones", zone(za, "alpha", false)).await;
    env.create(&a, s, "zones", zone(zb, "beta", false)).await;
    env.create(&a, s, "rules", baseline_rule(base, "metadata", 1, &[]))
        .await;
    let mut rule = zone_rule(r1, "web", za, 1, &[]);
    rule["section"] = json!("Web");
    env.create(&a, s, "rules", rule).await;
    let mut rule = zone_rule(r2, "old", za, 2, &[]);
    rule["expires_at"] = json!("2020-01-01T00:00:00Z");
    rule["comment"] = json!("legacy access");
    env.create(&a, s, "rules", rule).await;
    env.create(&a, s, "rules", zone_rule(r3, "b1", zb, 1, &[]))
        .await;
    env.publish(&a, s).await;

    // Pending change and lock in another session.
    let s2 = env.open(&env.admin2).await;
    let mut rule = zone_rule(r3, "b1-renamed", zb, 1, &[]);
    rule["enabled"] = json!(false);
    let (st, _) = env
        .call(
            "PUT",
            &format!("/rules/{r3}"),
            &env.admin2,
            Some(s2),
            Some(rule),
        )
        .await;
    assert_eq!(st, StatusCode::OK);

    let (st, views) = env.call("GET", "/rules", &env.viewer, None, None).await;
    assert_eq!(st, StatusCode::OK, "{views}");
    let views = views.as_array().unwrap().clone();
    let numbers: Vec<u64> = views
        .iter()
        .map(|v| v["number"].as_u64().unwrap())
        .collect();
    assert_eq!(numbers, [1, 2, 3, 4]);
    assert_eq!(views[0]["id"], json!(base));
    assert_eq!(views[1]["id"], json!(r1));
    assert_eq!(views[1]["hits"], 42);
    assert!(!views[1]["last_hit_at"].is_null());
    assert_eq!(
        views[1]["action"], "accept",
        "a rule view is a superset of the rule"
    );
    assert_eq!(views[2]["expired"], true);
    assert_eq!(views[3]["locked_by"]["name"], "bob");
    assert!(views[3]["pending_change"].is_null(), "no session given");
    assert_eq!(views[3]["name"], "b1", "published state without session");
    let (_, mine) = env.call("GET", "/rules", &env.admin2, Some(s2), None).await;
    let r3v = mine
        .as_array()
        .unwrap()
        .iter()
        .find(|v| v["id"] == json!(r3))
        .unwrap()
        .clone();
    assert_eq!(r3v["pending_change"], "update");
    assert_eq!(r3v["name"], "b1-renamed");
    // Filters.
    let (_, only_a) = env
        .call("GET", &format!("/rules?zone_id={za}"), &a, None, None)
        .await;
    assert_eq!(ids(&only_a), vec![r1.to_string(), r2.to_string()]);
    let (_, q) = env.call("GET", "/rules?q=LEGACY", &a, None, None).await;
    assert_eq!(ids(&q), vec![r2.to_string()]);

    let (st, rb) = env.call("GET", "/rulebase", &env.viewer, None, None).await;
    assert_eq!(st, StatusCode::OK, "{rb}");
    assert_eq!(rb["baseline"]["sections"][0]["rules"][0]["id"], json!(base));
    let zones = rb["zones"].as_array().unwrap();
    assert_eq!(zones[0]["zone"]["name"], "alpha");
    assert_eq!(zones[0]["mode"], "enforce");
    let sections = zones[0]["sections"].as_array().unwrap();
    assert_eq!(sections[0]["name"], "Web");
    assert!(sections[1]["name"].is_null());
    assert_eq!(zones[0]["cleanup_number"], 4);
    assert_eq!(zones[1]["zone"]["name"], "beta");
    assert_eq!(zones[1]["cleanup_number"], 5);
}

#[tokio::test]
async fn allow_from_log_options_and_changes() {
    let (z, ag, f1, f2, f3, f4) = (
        Uuid::new_v4(),
        Uuid::new_v4(),
        Uuid::new_v4(),
        Uuid::new_v4(),
        Uuid::new_v4(),
        Uuid::new_v4(),
    );
    let make = |id: Uuid, domain: &str| FlowEvent {
        id,
        gateway_id: Uuid::new_v4(),
        agent_id: Some(ag),
        zone_id: None,
        src: "10.0.0.5:40000".parse().unwrap(),
        dst: "93.184.216.34:443".parse().unwrap(),
        protocol: L4Proto::Tcp,
        app: None,
        domain: Some(domain.into()),
        sni: None,
        bytes_out: 1,
        bytes_in: 1,
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
        deny_mode: None,
    };
    let flows = Flows(HashMap::from([
        (f1, make(f1, "api.github.com")),
        (f2, make(f2, "pypi.org")),
        (f3, make(f3, "files.pythonhosted.org")),
        (f4, make(f4, "registry.npmjs.org")),
    ]));
    let env = env_or_skip!(env_with(Some(Arc::new(flows))));
    let a = &env.admin;
    let s = env.open(a).await;
    env.create(a, s, "zones", zone(z, "build", false)).await;
    env.create(a, s, "agents", agent(ag, "bot", z, false)).await;
    env.publish(a, s).await;
    let s = env.open(a).await;
    let path = format!("/sessions/{s}/allow-from-log");
    let allow = |body: Value| env.call("POST", &path, a, None, Some(body));

    let (st, out) = allow(json!({"flow_id": f1, "destination": "wildcard",
                                 "expires_in_days": 7, "track": "log"}))
    .await;
    assert_eq!(st, StatusCode::CREATED, "{out}");
    assert_eq!(out["created_object"]["spec"]["pattern"], "*.github.com");
    assert_eq!(out["rule"]["track"], "log");
    assert!(!out["rule"]["expires_at"].is_null());
    assert_eq!(out["rule"]["number"], 1);
    assert_eq!(out["rule"]["pending_change"], "create");
    let kinds: Vec<&str> = out["changes"]
        .as_array()
        .unwrap()
        .iter()
        .map(|c| c["resource"]["kind"].as_str().unwrap())
        .collect();
    assert_eq!(kinds, ["object", "service", "rule"], "{out}");
    // A wildcard of a registrable domain would be a whole TLD: refused.
    let (st, _) = allow(json!({"flow_id": f2, "destination": "wildcard"})).await;
    assert_eq!(st, StatusCode::BAD_REQUEST);
    // Group: the exact object goes into the zone's group, reused the second time.
    let (st, g1) = allow(json!({"flow_id": f3, "destination": "group"})).await;
    assert_eq!(st, StatusCode::CREATED, "{g1}");
    assert_eq!(
        g1["created_object"]["spec"]["pattern"],
        "files.pythonhosted.org"
    );
    let group_id = g1["rule"]["destinations"][0].clone();
    let (_, group) = env
        .call(
            "GET",
            &format!("/objects/{}", group_id.as_str().unwrap()),
            a,
            Some(s),
            None,
        )
        .await;
    assert_eq!(group["spec"]["type"], "group");
    let (st, g2) = allow(json!({"flow_id": f4, "destination": "group"})).await;
    assert_eq!(st, StatusCode::CREATED);
    assert_eq!(g2["rule"]["destinations"][0], group_id);
    let (_, group) = env
        .call(
            "GET",
            &format!("/objects/{}", group_id.as_str().unwrap()),
            a,
            Some(s),
            None,
        )
        .await;
    assert_eq!(group["spec"]["members"].as_array().unwrap().len(), 2);
    let (st, _) = allow(json!({"flow_id": f4, "destination": "nope"})).await;
    assert_eq!(st, StatusCode::BAD_REQUEST);
    env.publish(a, s).await;
}

#[tokio::test]
async fn session_name_and_pending_install_survive_a_reload() {
    let env = env_or_skip!(env());
    let a = &env.admin;
    let (st, sess) = env
        .call(
            "POST",
            "/sessions",
            a,
            None,
            Some(json!({"name": "ouvrir github"})),
        )
        .await;
    assert_eq!(st, StatusCode::CREATED, "{sess}");
    assert_eq!(sess["name"], "ouvrir github");
    let s: Uuid = sess["id"].as_str().unwrap().parse().unwrap();
    let (st, _) = env
        .call(
            "POST",
            "/sessions",
            &env.admin2,
            None,
            Some(json!({"bogus": 1})),
        )
        .await;
    assert_eq!(st, StatusCode::BAD_REQUEST);
    env.create(a, s, "objects", domain(Uuid::new_v4(), "o", "o.com"))
        .await;
    let n = env.publish(a, s).await;
    // No open session, but a published revision waiting for installation.
    let (st, cur) = env.call("GET", "/sessions/current", a, None, None).await;
    assert_eq!(st, StatusCode::OK, "{cur}");
    assert_eq!(cur["id"], json!(s));
    assert_eq!(cur["state"], "published");
    assert_eq!(cur["pending_install"], n);
    // A new open session still shows the pending installation.
    let s2 = env.open(a).await;
    let (_, cur) = env.call("GET", "/sessions/current", a, None, None).await;
    assert_eq!(cur["id"], json!(s2));
    assert_eq!(cur["pending_install"], n);
    let (st, _) = env
        .call(
            "POST",
            "/installs",
            a,
            None,
            Some(json!({"revision": n, "gateways": [env.gateway().await]})),
        )
        .await;
    assert_eq!(st, StatusCode::ACCEPTED);
    let (_, cur) = env.call("GET", "/sessions/current", a, None, None).await;
    assert!(cur["pending_install"].is_null(), "{cur}");
    env.call("POST", &format!("/sessions/{s2}/discard"), a, None, None)
        .await;
    let (st, _) = env.call("GET", "/sessions/current", a, None, None).await;
    assert_eq!(st, StatusCode::NOT_FOUND);
}

#[tokio::test]
async fn intent_policy_defaults_to_hermes_builtin_and_is_versioned() {
    let env = env_or_skip!(env());
    let (st, p) = env
        .call("GET", "/intent-policy", &env.plugin, None, None)
        .await;
    assert_eq!(st, StatusCode::OK, "{p}");
    assert_eq!(p["version"], 0);
    let classes = p["action_classes"].as_array().unwrap();
    assert_eq!(classes.len(), 9);
    assert!(
        classes
            .iter()
            .any(|c| c["id"] == "infra_destructive" && c["decision"] == "gate")
    );
    let (st, _) = env
        .call("GET", "/intent-policy", &env.viewer, None, None)
        .await;
    assert_eq!(st, StatusCode::OK);
    let new = json!({"version": 99, "action_classes": [
        {"id": "irreversible", "name": "Suppression", "tools": [], "patterns": ["(?i)drop"],
         "decision": "deny"}]});
    for t in [&env.viewer, &env.auditor, &env.plugin] {
        let (st, _) = env
            .call("PUT", "/intent-policy", t, None, Some(new.clone()))
            .await;
        assert_eq!(st, StatusCode::FORBIDDEN);
    }
    let mcp = env.token("mcp_agent", "mcp", Some(Uuid::new_v4())).await;
    let (st, _) = env
        .call("PUT", "/intent-policy", &mcp, None, Some(new.clone()))
        .await;
    assert_eq!(
        st,
        StatusCode::FORBIDDEN,
        "the MCP agent cannot relax its own gating"
    );
    let (st, out) = env
        .call("PUT", "/intent-policy", &env.admin, None, Some(new.clone()))
        .await;
    assert_eq!(st, StatusCode::OK, "{out}");
    assert_eq!(out["version"], 1);
    let (_, p) = env
        .call("GET", "/intent-policy", &env.plugin, None, None)
        .await;
    assert_eq!(p["version"], 1);
    assert_eq!(p["action_classes"][0]["decision"], "deny");
    let mut typo = new.clone();
    typo["action_class"] = json!([]);
    let (st, _) = env
        .call("PUT", "/intent-policy", &env.admin, None, Some(typo))
        .await;
    assert_eq!(st, StatusCode::BAD_REQUEST);
    let n: i64 =
        sqlx::query_scalar("SELECT count(*) FROM audit_log WHERE action = 'intent_policy.update'")
            .fetch_one(&env.pool)
            .await
            .unwrap();
    assert_eq!(n, 1);
}

#[tokio::test]
async fn policy_port_for_gateways_and_enrollments() {
    use afw_api::auth::Principal;
    use afw_api::policy::port::PolicyPortImpl;
    use afw_core::api::{EnrollmentRequest, Role};
    use afw_core::policy::AgentKind;
    let env = env_or_skip!(env());
    // The gateway registry of lot L7c, linked by value.
    let (gw, gone) = (env.gateway().await, env.gateway().await);
    sqlx::query("UPDATE gateways SET deleted_at = now() WHERE id = $1")
        .bind(gone)
        .execute(&env.pool)
        .await
        .unwrap();
    let port = PolicyPortImpl;
    assert!(port.current_policy(&env.state).await.unwrap().is_none());
    let a = &env.admin;
    let z = Uuid::new_v4();
    let s = env.open(a).await;
    env.create(a, s, "zones", zone(z, "z", false)).await;
    env.publish(a, s).await;
    assert_eq!(
        port.current_policy(&env.state)
            .await
            .unwrap()
            .unwrap()
            .zones
            .len(),
        1
    );
    // Unknown or deleted gateway refused; empty list = registered gateways.
    let (st, _) = env
        .call(
            "POST",
            "/installs",
            a,
            None,
            Some(json!({"revision": 1, "gateways": [gone]})),
        )
        .await;
    assert_eq!(st, StatusCode::NOT_FOUND);
    let (st, res) = env
        .call("POST", "/installs", a, None, Some(json!({"revision": 1})))
        .await;
    assert_eq!(st, StatusCode::ACCEPTED);
    assert_eq!(res["installs"].as_array().unwrap().len(), 1);
    let desired: Option<i64> =
        sqlx::query_scalar("SELECT desired_revision FROM gateways WHERE id = $1")
            .bind(gw)
            .fetch_one(&env.pool)
            .await
            .unwrap();
    assert_eq!(desired, Some(1));
    let p = port
        .installed_policy_for(&env.state, gw)
        .await
        .unwrap()
        .unwrap();
    p.verify().unwrap();
    port.record_install_ack(
        &env.state,
        gw,
        PolicyAck {
            revision: 1,
            ok: true,
            error: None,
        },
    )
    .await
    .unwrap();
    let active: Option<i64> =
        sqlx::query_scalar("SELECT active_revision FROM gateways WHERE id = $1")
            .bind(gw)
            .fetch_one(&env.pool)
            .await
            .unwrap();
    assert_eq!(active, Some(1));
    // Enrollment: agent created in a new session of the caller, then in the same one.
    let mut admin = Principal::for_tests(Role::Admin);
    admin.actor.id = "enroller".into();
    let req = EnrollmentRequest {
        name: "bot".into(),
        zone_id: z,
        kind: AgentKind::Kubernetes,
        gateway_id: gw,
        hermes: true,
    };
    let (agent, sid) = port
        .create_agent(&env.state, &admin, None, &req)
        .await
        .unwrap();
    assert_eq!(agent.zone_id, z);
    assert!(agent.hermes);
    let (_, sid2) = port
        .create_agent(&env.state, &admin, None, &req)
        .await
        .unwrap();
    assert_eq!(sid, sid2);
    let n: i64 =
        sqlx::query_scalar("SELECT count(*) FROM policy_session_changes WHERE session_id = $1")
            .bind(sid)
            .fetch_one(&env.pool)
            .await
            .unwrap();
    assert_eq!(n, 2);
    // A viewer cannot enroll.
    let viewer = Principal::for_tests(Role::Viewer);
    assert!(
        port.create_agent(&env.state, &viewer, None, &req)
            .await
            .is_err()
    );
}

#[tokio::test]
async fn review_minor_fixes() {
    let env = env_or_skip!(env());
    let (a, b) = (&env.admin, &env.admin2);
    let z = Uuid::new_v4();
    let s = env.open(a).await;
    env.create(a, s, "zones", zone(z, "z", false)).await;
    // Agent addresses must be internal (for everyone).
    let mut public = agent(Uuid::new_v4(), "public", z, false);
    public["addresses"] = json!(["203.0.113.9"]);
    let (st, body) = env.call("POST", "/agents", a, Some(s), Some(public)).await;
    assert_eq!(st, StatusCode::BAD_REQUEST, "{body}");
    let mut internal = agent(Uuid::new_v4(), "internal", z, false);
    internal["addresses"] = json!(["10.1.2.3"]);
    env.create(a, s, "agents", internal).await;
    assert_eq!(env.publish(a, s).await, 1);

    // A lock is released when the entity returns to its published state.
    let (s1, s2) = (env.open(a).await, env.open(b).await);
    let path = format!("/zones/{z}");
    let mut observe = zone(z, "z", false);
    observe["mode"] = json!("observe");
    assert_eq!(
        env.call("PUT", &path, a, Some(s1), Some(observe)).await.0,
        StatusCode::OK
    );
    assert_eq!(
        env.call("PUT", &path, b, Some(s2), Some(zone(z, "zz", false)))
            .await
            .0,
        StatusCode::LOCKED
    );
    assert_eq!(
        env.call("PUT", &path, a, Some(s1), Some(zone(z, "z", false)))
            .await
            .0,
        StatusCode::OK
    );
    let (_, sess) = env
        .call("GET", &format!("/sessions/{s1}"), a, None, None)
        .await;
    assert!(sess["locks"].as_array().unwrap().is_empty(), "{sess}");
    assert_eq!(
        env.call("PUT", &path, b, Some(s2), Some(zone(z, "zz", false)))
            .await
            .0,
        StatusCode::OK
    );
    assert_eq!(env.publish(b, s2).await, 2);

    // Acknowledgement of a revision that is not the desired one: never active.
    let gw = env.gateway().await;
    let (st, _) = env
        .call(
            "POST",
            "/installs",
            a,
            None,
            Some(json!({"revision": 2, "gateways": [gw]})),
        )
        .await;
    assert_eq!(st, StatusCode::ACCEPTED);
    record_install_ack(
        &env.pool,
        gw,
        &PolicyAck {
            revision: 1,
            ok: true,
            error: None,
        },
    )
    .await
    .unwrap();
    let state = afw_api::policy::install::gateway_policy_state(&env.pool, gw)
        .await
        .unwrap()
        .unwrap();
    assert_eq!(state.active_revision, None);
    record_install_ack(
        &env.pool,
        gw,
        &PolicyAck {
            revision: 2,
            ok: true,
            error: None,
        },
    )
    .await
    .unwrap();
    let state = afw_api::policy::install::gateway_policy_state(&env.pool, gw)
        .await
        .unwrap()
        .unwrap();
    assert_eq!(state.active_revision, Some(2));

    // A tampered revision is never served.
    sqlx::query(
        "UPDATE revisions SET document = jsonb_set(document, '{zones,0,mode}', '\"observe\"') \
         WHERE number = 2",
    )
    .execute(&env.pool)
    .await
    .unwrap();
    assert!(installed_policy_for(&env.pool, gw).await.is_err());
    let (st, _) = env.call("GET", "/revisions/2", a, None, None).await;
    assert_eq!(st, StatusCode::INTERNAL_SERVER_ERROR);
    let (st, _) = env.call("GET", "/zones", a, None, None).await;
    assert_eq!(st, StatusCode::INTERNAL_SERVER_ERROR);
}

#[tokio::test]
async fn allow_from_log_public_suffixes_and_group_by_id() {
    let (z, ag, f1, f2, f3) = (
        Uuid::new_v4(),
        Uuid::new_v4(),
        Uuid::new_v4(),
        Uuid::new_v4(),
        Uuid::new_v4(),
    );
    let make = |id: Uuid, domain: &str| FlowEvent {
        id,
        gateway_id: Uuid::new_v4(),
        agent_id: Some(ag),
        zone_id: None,
        src: "10.0.0.5:40000".parse().unwrap(),
        dst: "93.184.216.34:443".parse().unwrap(),
        protocol: L4Proto::Tcp,
        app: None,
        domain: Some(domain.into()),
        sni: None,
        bytes_out: 1,
        bytes_in: 1,
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
        deny_mode: None,
    };
    let flows = Flows(HashMap::from([
        (f1, make(f1, "example.co.uk")),
        (f2, make(f2, "a.example.co.uk")),
        (f3, make(f3, "b.example.co.uk")),
    ]));
    let env = env_or_skip!(env_with(Some(Arc::new(flows))));
    let a = &env.admin;
    let s = env.open(a).await;
    env.create(a, s, "zones", zone(z, "build", false)).await;
    env.create(a, s, "agents", agent(ag, "bot", z, false)).await;
    env.publish(a, s).await;
    let s = env.open(a).await;
    let path = format!("/sessions/{s}/allow-from-log");
    let allow = |body: Value| env.call("POST", &path, a, None, Some(body));
    let (st, out) = allow(json!({"flow_id": f1, "destination": "wildcard"})).await;
    assert_eq!(st, StatusCode::BAD_REQUEST, "*.co.uk refused: {out}");
    let (st, out) = allow(json!({"flow_id": f2, "destination": "wildcard"})).await;
    assert_eq!(st, StatusCode::CREATED, "{out}");
    assert_eq!(out["created_object"]["spec"]["pattern"], "*.example.co.uk");
    // Group found by id even after a rename; a look-alike group by name is ignored.
    let (_, g1) = allow(json!({"flow_id": f2, "destination": "group"})).await;
    let gid: Uuid = g1["rule"]["destinations"][0]
        .as_str()
        .unwrap()
        .parse()
        .unwrap();
    let (_, mut group) = env
        .call("GET", &format!("/objects/{gid}"), a, Some(s), None)
        .await;
    let original_name = group["name"].clone();
    group["name"] = json!("renamed");
    let (st, _) = env
        .call("PUT", &format!("/objects/{gid}"), a, Some(s), Some(group))
        .await;
    assert_eq!(st, StatusCode::OK);
    let decoy = Uuid::new_v4();
    let mut fake = group_json(decoy, original_name.as_str().unwrap());
    fake["comment"] = json!("decoy");
    env.create(a, s, "objects", fake).await;
    let (_, g2) = allow(json!({"flow_id": f3, "destination": "group"})).await;
    assert_eq!(g2["rule"]["destinations"][0], json!(gid));
    env.publish(a, s).await;
}

fn group_json(id: Uuid, name: &str) -> Value {
    group(id, name, &[])
}

#[tokio::test]
async fn logs_end_to_end_allow_from_log_hits_and_status() {
    use afw_core::events::{GatewayEvent, RuleHit};
    let env = env_or_skip!(env());
    let a = &env.admin;
    let (z, ag, r1) = (Uuid::new_v4(), Uuid::new_v4(), Uuid::new_v4());
    let (st, sess) = env.call("POST", "/sessions", a, None, None).await;
    assert_eq!(st, StatusCode::CREATED);
    assert!(sess["base_revision"].is_null());
    assert_eq!(sess["next_revision"], 1);
    let s: Uuid = sess["id"].as_str().unwrap().parse().unwrap();
    env.create(a, s, "zones", zone(z, "build", false)).await;
    let mut bot = agent(ag, "bot", z, false);
    bot["addresses"] = json!(["10.0.0.5"]);
    env.create(a, s, "agents", bot).await;
    env.create(a, s, "rules", zone_rule(r1, "first", z, 1, &[]))
        .await;
    assert_eq!(env.publish(a, s).await, 1);
    // The logs module reads the published revisions (names of agents and zones, retention).
    let loaded = env
        .state
        .logs
        .load_policy(None)
        .await
        .expect("policy loaded by L7b");
    assert_eq!(loaded.zones[0].name, "build");
    assert_eq!(loaded.agents[0].name, "bot");
    assert_eq!(loaded.settings.retention_days.flows, 30);

    // A denied flow ingested from a gateway, then "Allow" from the log (real lookup).
    let gw = env.gateway().await;
    let flow_id = Uuid::new_v4();
    let flow = FlowEvent {
        id: flow_id,
        gateway_id: gw,
        agent_id: Some(ag),
        zone_id: Some(z),
        src: "10.0.0.5:40000".parse().unwrap(),
        dst: "140.82.112.3:443".parse().unwrap(),
        protocol: L4Proto::Tcp,
        app: None,
        domain: Some("api.github.com".into()),
        sni: Some("api.github.com".into()),
        bytes_out: 100,
        bytes_in: 0,
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
        deny_mode: None,
    };
    afw_api::logs::ingest_gateway_events(&env.state, gw, vec![GatewayEvent::Flow(flow)])
        .await
        .unwrap();
    let s = env.open(a).await;
    let (_, cur) = env
        .call("GET", &format!("/sessions/{s}"), a, None, None)
        .await;
    assert_eq!(cur["base_revision"], 1);
    assert_eq!(cur["next_revision"], 2);
    let (st, out) = env
        .call(
            "POST",
            &format!("/sessions/{s}/allow-from-log"),
            a,
            None,
            Some(json!({"flow_id": flow_id})),
        )
        .await;
    assert_eq!(st, StatusCode::CREATED, "{out}");
    assert_eq!(out["created_object"]["spec"]["pattern"], "api.github.com");
    assert_eq!(out["rule"]["position"], 1);
    assert_eq!(env.publish(a, s).await, 2);

    // Rule hits reported by the gateway show up in the rule views.
    let hit_at = chrono::Utc::now();
    afw_api::logs::ingest_gateway_events(
        &env.state,
        gw,
        vec![GatewayEvent::RuleHits {
            hits: vec![RuleHit {
                rule_id: r1,
                revision: 2,
                hits: 7,
                last_hit_at: hit_at,
            }],
        }],
    )
    .await
    .unwrap();
    let (_, views) = env.call("GET", "/rules", &env.viewer, None, None).await;
    let first = views
        .as_array()
        .unwrap()
        .iter()
        .find(|v| v["id"] == json!(r1))
        .unwrap()
        .clone();
    assert_eq!(first["hits"], 7, "{first}");
    assert!(!first["last_hit_at"].is_null());

    // Policy status: 1 of 2 gateways on the installed revision.
    let gw2 = env.gateway().await;
    let (st, _) = env
        .call(
            "POST",
            "/installs",
            a,
            None,
            Some(json!({"revision": 2, "gateways": [gw, gw2]})),
        )
        .await;
    assert_eq!(st, StatusCode::ACCEPTED);
    record_install_ack(
        &env.pool,
        gw,
        &PolicyAck {
            revision: 2,
            ok: true,
            error: None,
        },
    )
    .await
    .unwrap();
    sqlx::query("UPDATE gateways SET stats = '{\"p95_ms\": 2.5}' WHERE id = $1")
        .bind(gw)
        .execute(&env.pool)
        .await
        .unwrap();
    let (st, status) = env
        .call("GET", "/policy/status", &env.viewer, None, None)
        .await;
    assert_eq!(st, StatusCode::OK, "{status}");
    assert_eq!(status["latest_revision"], 2);
    assert_eq!(status["installed_revision"], 2);
    assert_eq!(status["gateways_total"], 2);
    assert_eq!(status["gateways_on_revision"], 1);
    assert_eq!(status["pending_installs"], 1);
    assert_eq!(status["p95_ms"], 2.5);
    let (st, _) = env
        .call("GET", "/policy/status", &env.plugin, None, None)
        .await;
    assert_eq!(st, StatusCode::FORBIDDEN);
}
