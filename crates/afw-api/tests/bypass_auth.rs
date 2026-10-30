//! Bypass tests of authentication and authorization (lot L7c): API tokens, roles, OIDC.
//! Skipped when `AFW_TEST_DATABASE_URL` is not set.

mod support;

use std::sync::Arc;

use afw_api::auth::oidc::OidcVerifier;
use axum::http::StatusCode;
use serde_json::json;
use support::*;
use uuid::Uuid;

fn app_with_oidc(pool: &sqlx::PgPool, oidc: &FakeOidc) -> axum::Router {
    let mut state = state(pool);
    state.oidc = Some(Arc::new(OidcVerifier::new(oidc.settings())));
    afw_api::router(state)
}

#[tokio::test]
async fn api_token_lifecycle_secret_shown_once_and_revocation() {
    let pool = pool_or_skip!();
    let app = afw_api::router(state(&pool));
    let admin = token(&pool, "admin", None).await;

    let created = call_with(
        &app,
        "POST",
        "/api/v1/tokens",
        Some(&admin),
        Some(json!({"name": "ci", "role": "viewer", "agent_id": null, "expires_at": null})),
        &[("x-afw-interface", "cli")],
    )
    .await;
    assert_eq!(created.status, StatusCode::CREATED, "{}", created.text());
    let body = created.json();
    let secret = body["secret"].as_str().unwrap().to_owned();
    assert!(secret.starts_with("afw_"), "{secret}");
    assert!(secret.len() >= 40);
    let id = body["token"]["id"].as_str().unwrap().to_owned();
    assert_eq!(body["token"]["role"], "viewer");

    // The secret is never stored nor listed.
    let stored: String = sqlx::query_scalar("SELECT token_sha256 FROM api_tokens WHERE id = $1")
        .bind(Uuid::parse_str(&id).unwrap())
        .fetch_one(&pool)
        .await
        .unwrap();
    assert_ne!(stored, secret);
    let list = call(&app, "GET", "/api/v1/tokens", Some(&admin), None).await;
    assert_eq!(list.status, StatusCode::OK);
    assert!(!list.text().contains(&secret));
    assert!(!list.text().contains("sha256"));
    assert!(
        list.json()
            .as_array()
            .unwrap()
            .iter()
            .any(|t| t["id"] == id.as_str())
    );

    let me = call(&app, "GET", "/api/v1/me", Some(&secret), None).await;
    assert_eq!(me.status, StatusCode::OK);
    assert_eq!(me.json()["role"], "viewer");

    // Revocation is immediate.
    let del = call(
        &app,
        "DELETE",
        &format!("/api/v1/tokens/{id}"),
        Some(&admin),
        None,
    )
    .await;
    assert_eq!(del.status, StatusCode::NO_CONTENT);
    let me = call(&app, "GET", "/api/v1/me", Some(&secret), None).await;
    assert_eq!(me.status, StatusCode::UNAUTHORIZED);
    let again = call(
        &app,
        "DELETE",
        &format!("/api/v1/tokens/{id}"),
        Some(&admin),
        None,
    )
    .await;
    assert_eq!(again.status, StatusCode::NOT_FOUND);

    // Both mutations are audited with the declared interface, without the secret.
    let audit = afw_api::audit::load(&pool, 1, 1000).await.unwrap();
    let actions: Vec<_> = audit.iter().map(|e| e.action.as_str()).collect();
    assert!(actions.contains(&"token.create"), "{actions:?}");
    assert!(actions.contains(&"token.revoke"), "{actions:?}");
    assert!(
        audit
            .iter()
            .all(|e| e.interface == afw_core::events::Interface::Cli)
    );
    assert!(!serde_json::to_string(&audit).unwrap().contains(&secret));
}

#[tokio::test]
async fn non_admins_cannot_manage_tokens_or_escalate() {
    let pool = pool_or_skip!();
    let app = afw_api::router(state(&pool));
    let new_admin = json!({"name": "x", "role": "admin", "agent_id": null, "expires_at": null});
    for role in ["viewer", "auditor", "mcp_agent", "agent_plugin"] {
        let agent = matches!(role, "mcp_agent" | "agent_plugin").then(Uuid::new_v4);
        let t = token(&pool, role, agent).await;
        let res = call(&app, "POST", "/api/v1/tokens", Some(&t), Some(new_admin.clone())).await;
        assert_eq!(res.status, StatusCode::FORBIDDEN, "{role} creates a token");
        let res = call(&app, "GET", "/api/v1/tokens", Some(&t), None).await;
        assert_eq!(res.status, StatusCode::FORBIDDEN, "{role} lists tokens");
        let res = call(
            &app,
            "DELETE",
            &format!("/api/v1/tokens/{}", Uuid::new_v4()),
            Some(&t),
            None,
        )
        .await;
        assert_eq!(res.status, StatusCode::FORBIDDEN, "{role} revokes a token");
        let res = call(
            &app,
            "POST",
            "/api/v1/gateways/registration-tokens",
            Some(&t),
            Some(json!({"name": "gw"})),
        )
        .await;
        assert_eq!(res.status, StatusCode::FORBIDDEN, "{role} registers a gateway");
    }
    // The plugin token reaches nothing of the general API.
    let plugin = token(&pool, "agent_plugin", Some(Uuid::new_v4())).await;
    for uri in ["/api/v1/me", "/api/v1/audit", "/api/v1/gateways"] {
        let res = call(&app, "GET", uri, Some(&plugin), None).await;
        assert_eq!(res.status, StatusCode::FORBIDDEN, "plugin on {uri}");
    }
    // Anonymous: 401 everywhere except the public OIDC configuration.
    for uri in [
        "/api/v1/me",
        "/api/v1/tokens",
        "/api/v1/audit",
        "/api/v1/gateways",
    ] {
        let res = call(&app, "GET", uri, None, None).await;
        assert_eq!(res.status, StatusCode::UNAUTHORIZED, "anonymous on {uri}");
    }
}

#[tokio::test]
async fn token_creation_is_validated() {
    let pool = pool_or_skip!();
    let app = afw_api::router(state(&pool));
    let admin = token(&pool, "admin", None).await;
    let past = (chrono::Utc::now() - chrono::Duration::hours(1)).to_rfc3339();
    for (body, why) in [
        (
            json!({"name": "m", "role": "mcp_agent", "agent_id": null, "expires_at": null}),
            "agent role without agent",
        ),
        (
            json!({"name": "p", "role": "agent_plugin", "agent_id": null, "expires_at": null}),
            "plugin role without agent",
        ),
        (
            json!({"name": "v", "role": "viewer", "agent_id": Uuid::new_v4(), "expires_at": null}),
            "human role bound to an agent",
        ),
        (
            json!({"name": "v", "role": "viewer", "agent_id": null, "expires_at": past}),
            "already expired",
        ),
        (
            json!({"name": "", "role": "viewer", "agent_id": null, "expires_at": null}),
            "empty name",
        ),
        (
            json!({"name": "v", "role": "viewer", "agent_id": null, "expires_at": null, "admin": true}),
            "unknown field",
        ),
        (json!({"name": "v", "role": "root"}), "unknown role"),
    ] {
        let res = call(&app, "POST", "/api/v1/tokens", Some(&admin), Some(body)).await;
        assert_eq!(res.status, StatusCode::BAD_REQUEST, "{why}: {}", res.text());
        assert_eq!(res.headers["content-type"], "application/problem+json");
    }
    // A single active mcp_agent token.
    let mcp = json!({"name": "m", "role": "mcp_agent", "agent_id": Uuid::new_v4(), "expires_at": null});
    let first = call(&app, "POST", "/api/v1/tokens", Some(&admin), Some(mcp.clone())).await;
    assert_eq!(first.status, StatusCode::CREATED, "{}", first.text());
    let second = call(&app, "POST", "/api/v1/tokens", Some(&admin), Some(mcp)).await;
    assert_eq!(second.status, StatusCode::CONFLICT);
    // The mcp agent token authenticates with the mcp interface, whatever the header says.
    let secret = first.json()["secret"].as_str().unwrap().to_owned();
    let me = call_with(
        &app,
        "GET",
        "/api/v1/me",
        Some(&secret),
        None,
        &[("x-afw-interface", "ui")],
    )
    .await;
    assert_eq!(me.status, StatusCode::OK);
    assert_eq!(me.json()["role"], "mcp_agent");
    // No policy known: the MCP agent may write nowhere (fail closed).
    assert_eq!(me.json()["writable_zones"], json!([]));
}

#[tokio::test]
async fn oidc_valid_token_maps_groups_to_roles() {
    let pool = pool_or_skip!();
    let idp = FakeOidc::start().await;
    let app = app_with_oidc(&pool, &idp);
    for (groups, role) in [
        (vec!["afw-viewers"], "viewer"),
        (vec!["afw-auditors", "afw-viewers"], "auditor"),
        (vec!["other", "afw-admins"], "admin"),
    ] {
        let jwt = idp.sign(&idp.claims(&groups), 1, KID_1);
        let me = call(&app, "GET", "/api/v1/me", Some(&jwt), None).await;
        assert_eq!(me.status, StatusCode::OK, "{groups:?}: {}", me.text());
        let body = me.json();
        assert_eq!(body["role"], role);
        assert_eq!(body["email"], "alice@example.org");
        assert_eq!(body["actor"]["kind"], "human");
        assert_eq!(body["actor"]["name"], "Alice");
    }
    // An OIDC admin can create a token: the audit names the human.
    let jwt = idp.sign(&idp.claims(&["afw-admins"]), 1, KID_1);
    let res = call_with(
        &app,
        "POST",
        "/api/v1/tokens",
        Some(&jwt),
        Some(json!({"name": "cli", "role": "viewer", "agent_id": null, "expires_at": null})),
        &[("x-afw-interface", "ui")],
    )
    .await;
    assert_eq!(res.status, StatusCode::CREATED, "{}", res.text());
    let audit = afw_api::audit::load(&pool, 1, 10).await.unwrap();
    assert_eq!(audit[0].actor.name, "Alice");
    assert_eq!(audit[0].interface, afw_core::events::Interface::Ui);
}

#[tokio::test]
async fn oidc_bypass_attempts_are_refused() {
    let pool = pool_or_skip!();
    let idp = FakeOidc::start().await;
    let app = app_with_oidc(&pool, &idp);
    let now = chrono::Utc::now().timestamp();
    let base = idp.claims(&["afw-admins"]);
    let with = |k: &str, v: serde_json::Value| {
        let mut c = base.clone();
        c[k] = v;
        c
    };
    let without = |k: &str| {
        let mut c = base.clone();
        c.as_object_mut().unwrap().remove(k);
        c
    };
    let unsigned = {
        use base64::Engine;
        let b64 = base64::engine::general_purpose::URL_SAFE_NO_PAD;
        format!(
            "{}.{}.",
            b64.encode(br#"{"alg":"none","typ":"JWT","kid":"key-1"}"#),
            b64.encode(serde_json::to_vec(&base).unwrap())
        )
    };
    // HS256 signed with the provider's public key material (algorithm confusion).
    let confused = {
        let mut header = jsonwebtoken::Header::new(jsonwebtoken::Algorithm::HS256);
        header.kid = Some(KID_1.into());
        let secret = rsa_jwk(1, KID_1)["n"].as_str().unwrap().to_owned();
        jsonwebtoken::encode(
            &header,
            &base,
            &jsonwebtoken::EncodingKey::from_secret(secret.as_bytes()),
        )
        .unwrap()
    };
    let cases = vec![
        (
            idp.sign(&with("exp", json!(now - 3600)), 1, KID_1),
            "expired",
        ),
        (
            idp.sign(&with("nbf", json!(now + 3600)), 1, KID_1),
            "not yet valid",
        ),
        (
            idp.sign(&with("aud", json!("another-client")), 1, KID_1),
            "wrong audience",
        ),
        (
            idp.sign(&with("iss", json!("https://evil.example")), 1, KID_1),
            "wrong issuer",
        ),
        (idp.sign(&without("exp"), 1, KID_1), "no expiry"),
        (idp.sign(&without("sub"), 1, KID_1), "no subject"),
        (idp.sign(&base, 2, KID_1), "signed by another key"),
        (idp.sign(&base, 2, "unknown-kid"), "unknown kid"),
        (unsigned, "alg none"),
        (confused, "HS256 with the public key"),
        ("a.b.c".to_owned(), "garbage"),
    ];
    for (jwt, why) in cases {
        let res = call(&app, "GET", "/api/v1/me", Some(&jwt), None).await;
        assert_eq!(res.status, StatusCode::UNAUTHORIZED, "{why}: {}", res.text());
    }
    // Authenticated but no mapped group: forbidden, never a default admin.
    let jwt = idp.sign(&idp.claims(&["unrelated"]), 1, KID_1);
    let res = call(&app, "GET", "/api/v1/me", Some(&jwt), None).await;
    assert_eq!(res.status, StatusCode::FORBIDDEN);
    let jwt = idp.sign(&without("groups"), 1, KID_1);
    let res = call(&app, "GET", "/api/v1/me", Some(&jwt), None).await;
    assert_eq!(res.status, StatusCode::FORBIDDEN);
    // An unknown kid triggers a bounded number of JWKS refreshes, not one per request.
    let hits = *idp.jwks_hits.lock().unwrap();
    for _ in 0..5 {
        let jwt = idp.sign(&base, 2, "unknown-kid");
        call(&app, "GET", "/api/v1/me", Some(&jwt), None).await;
    }
    assert!(*idp.jwks_hits.lock().unwrap() <= hits + 1);
}

#[tokio::test]
async fn oidc_key_rotation_is_picked_up() {
    let pool = pool_or_skip!();
    let idp = FakeOidc::start().await;
    let mut state = state(&pool);
    let mut settings = idp.settings();
    settings.audiences = vec!["afw-console".into(), "afw-api".into()];
    state.oidc = Some(Arc::new(OidcVerifier::new(settings)));
    let app = afw_api::router(state);
    let jwt = idp.sign(&idp.claims(&["afw-viewers"]), 1, KID_1);
    assert_eq!(
        call(&app, "GET", "/api/v1/me", Some(&jwt), None)
            .await
            .status,
        StatusCode::OK
    );
    // The provider rotates to key 2.
    *idp.jwks.lock().unwrap() = json!({"keys": [rsa_jwk(2, KID_2)]});
    let mut claims = idp.claims(&["afw-viewers"]);
    claims["aud"] = json!(["afw-api", "something-else"]);
    let jwt = idp.sign(&claims, 2, KID_2);
    let res = call(&app, "GET", "/api/v1/me", Some(&jwt), None).await;
    assert_eq!(res.status, StatusCode::OK, "{}", res.text());
}

#[tokio::test]
async fn oidc_public_configuration() {
    let pool = pool_or_skip!();
    let app = afw_api::router(state(&pool));
    let res = call(&app, "GET", "/api/v1/auth/oidc/config", None, None).await;
    assert_eq!(res.status, StatusCode::OK);
    assert_eq!(res.json()["enabled"], false);

    let idp = FakeOidc::start().await;
    let app = app_with_oidc(&pool, &idp);
    let res = call(&app, "GET", "/api/v1/auth/oidc/config", None, None).await;
    assert_eq!(res.status, StatusCode::OK, "{}", res.text());
    let body = res.json();
    assert_eq!(body["enabled"], true);
    assert_eq!(body["issuer"], idp.issuer.as_str());
    assert_eq!(body["client_id"], "afw-console");
    assert_eq!(
        body["authorization_endpoint"],
        format!("{}/authorize", idp.issuer)
    );
    assert!(!res.text().contains("secret"));
}
