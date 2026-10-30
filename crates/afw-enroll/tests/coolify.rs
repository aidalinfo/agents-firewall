//! Coolify enrollment against a fake Coolify v4 API (axum).

use std::sync::{Arc, Mutex};

use afw_enroll::{
    CoolifyClient, CoolifyKind, EnrollError, EnrollSpec, enroll_compose, enroll_coolify,
    unenroll_coolify,
};
use axum::{
    Json, Router,
    extract::{Path, State},
    http::{HeaderMap, Method, StatusCode},
    response::{IntoResponse, Response},
    routing::{any, get, patch},
};
use base64::Engine;
use serde_json::{Value, json};

const TOKEN: &str = "1|coolify-secret-token";
const COMPOSE: &str = "services:\n  bot:\n    image: alpine:3.20\n    ports: [\"80:80\"]\n";

#[derive(Default)]
struct Fake {
    compose: Option<String>,
    calls: Vec<String>,
    fail_get: Option<u16>,
    fail_patch: Option<u16>,
    restart_post_not_allowed: bool,
    restart_fails: bool,
    /// Simulates Coolify attaching its own network to every service on save.
    inject_network: bool,
    envs: Vec<Value>,
}

type Shared = Arc<Mutex<Fake>>;

fn authorized(h: &HeaderMap) -> bool {
    h.get("authorization").and_then(|v| v.to_str().ok()) == Some(&format!("Bearer {TOKEN}"))
}

async fn resource(
    State(st): State<Shared>,
    method: Method,
    Path((kind, uuid)): Path<(String, String)>,
    headers: HeaderMap,
    body: Option<Json<Value>>,
) -> Response {
    if !authorized(&headers) {
        return (
            StatusCode::UNAUTHORIZED,
            Json(json!({"message": "Unauthenticated."})),
        )
            .into_response();
    }
    let mut s = st.lock().unwrap();
    s.calls.push(format!("{method} /{kind}/{uuid}"));
    if uuid != "res1" {
        return (
            StatusCode::NOT_FOUND,
            Json(json!({"message": "Not found."})),
        )
            .into_response();
    }
    match method {
        Method::GET => {
            if let Some(code) = s.fail_get {
                return StatusCode::from_u16(code).unwrap().into_response();
            }
            let mut v = json!({"uuid": uuid, "name": "bots"});
            if let Some(c) = &s.compose {
                v["docker_compose_raw"] = json!(c);
            }
            Json(v).into_response()
        }
        Method::PATCH => {
            if let Some(code) = s.fail_patch {
                return (
                    StatusCode::from_u16(code).unwrap(),
                    Json(json!({"message": "The docker_compose_raw should be base64 encoded."})),
                )
                    .into_response();
            }
            let raw = body
                .and_then(|Json(b)| b["docker_compose_raw"].as_str().map(str::to_string))
                .unwrap_or_default();
            // Coolify requires base64.
            let Ok(decoded) = base64::engine::general_purpose::STANDARD.decode(&raw) else {
                return StatusCode::UNPROCESSABLE_ENTITY.into_response();
            };
            let mut text = String::from_utf8(decoded).unwrap();
            if s.inject_network && text.contains("afw-net-") {
                let mut doc: serde_yaml::Value = serde_yaml::from_str(&text).unwrap();
                for (_, svc) in doc["services"].as_mapping_mut().unwrap() {
                    if let Some(nets) = svc.get_mut("networks").and_then(|n| n.as_mapping_mut()) {
                        nets.insert("coolify".into(), serde_yaml::Value::Null);
                    }
                }
                text = serde_yaml::to_string(&doc).unwrap();
            }
            s.compose = Some(text);
            Json(json!({"uuid": uuid})).into_response()
        }
        _ => StatusCode::METHOD_NOT_ALLOWED.into_response(),
    }
}

async fn restart(
    State(st): State<Shared>,
    method: Method,
    Path((kind, uuid)): Path<(String, String)>,
    headers: HeaderMap,
) -> Response {
    if !authorized(&headers) {
        return StatusCode::UNAUTHORIZED.into_response();
    }
    let mut s = st.lock().unwrap();
    s.calls.push(format!("{method} /{kind}/{uuid}/restart"));
    if s.restart_fails {
        return (StatusCode::INTERNAL_SERVER_ERROR, "boom").into_response();
    }
    if method == Method::POST && s.restart_post_not_allowed {
        return StatusCode::METHOD_NOT_ALLOWED.into_response();
    }
    Json(json!({"message": "Restart request queued."})).into_response()
}

async fn envs(
    State(st): State<Shared>,
    Path((kind, uuid)): Path<(String, String)>,
    headers: HeaderMap,
    Json(body): Json<Value>,
) -> Response {
    if !authorized(&headers) {
        return StatusCode::UNAUTHORIZED.into_response();
    }
    let mut s = st.lock().unwrap();
    s.calls.push(format!("PATCH /{kind}/{uuid}/envs/bulk"));
    s.envs
        .extend(body["data"].as_array().cloned().unwrap_or_default());
    Json(json!({"message": "ok"})).into_response()
}

async fn serve(fake: Fake) -> (String, Shared) {
    let st: Shared = Arc::new(Mutex::new(fake));
    let app = Router::new()
        .route("/api/v1/{kind}/{uuid}", any(resource))
        .route("/api/v1/{kind}/{uuid}/restart", get(restart).post(restart))
        .route("/api/v1/{kind}/{uuid}/envs/bulk", patch(envs))
        .with_state(st.clone());
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();
    tokio::spawn(async move { axum::serve(listener, app).await.unwrap() });
    (format!("http://{addr}"), st)
}

fn spec() -> EnrollSpec {
    EnrollSpec {
        agent_name: "bot".into(),
        service: "bot".into(),
        gateway_ip: "10.80.0.2".parse().unwrap(),
        agent_ip: "10.80.0.30".parse().unwrap(),
        network: "afw-internal".into(),
        proxy_url: "http://10.80.0.2:3128".into(),
        ca_path_host: "/etc/afw/ca.crt".into(),
        hermes: None,
        netinit_image: "afw-netinit:local".into(),
    }
}

fn with_compose() -> Fake {
    Fake {
        compose: Some(COMPOSE.into()),
        ..Fake::default()
    }
}

#[tokio::test]
async fn enroll_reads_updates_then_restarts_service() {
    let (url, st) = serve(with_compose()).await;
    let client = CoolifyClient::new(&url, TOKEN).unwrap();
    let out = enroll_coolify(&client, CoolifyKind::Service, "res1", &spec())
        .await
        .unwrap();
    let s = st.lock().unwrap();
    assert_eq!(
        s.calls,
        vec![
            "GET /services/res1",
            "PATCH /services/res1",
            "GET /services/res1",
            "POST /services/res1/restart"
        ]
    );
    // What Coolify now stores is exactly the enrolled compose.
    assert_eq!(s.compose.as_deref(), Some(out.yaml.as_str()));
    assert_eq!(out.yaml, enroll_compose(COMPOSE, &spec()).unwrap().yaml);
}

#[tokio::test]
async fn unenroll_restores_the_original_in_coolify() {
    let (url, st) = serve(with_compose()).await;
    let client = CoolifyClient::new(format!("{url}/api/v1/"), TOKEN).unwrap();
    enroll_coolify(&client, CoolifyKind::Application, "res1", &spec())
        .await
        .unwrap();
    unenroll_coolify(&client, CoolifyKind::Application, "res1", "bot")
        .await
        .unwrap();
    let s = st.lock().unwrap();
    let back: serde_yaml::Value = serde_yaml::from_str(s.compose.as_deref().unwrap()).unwrap();
    let orig: serde_yaml::Value = serde_yaml::from_str(COMPOSE).unwrap();
    assert_eq!(back, orig);
    assert!(s.calls.iter().all(|c| c.contains("/applications/res1")));
    assert_eq!(s.calls.len(), 7);
}

#[tokio::test]
async fn missing_compose_is_a_clear_error_and_nothing_is_written() {
    let (url, st) = serve(Fake::default()).await;
    let client = CoolifyClient::new(&url, TOKEN).unwrap();
    let err = enroll_coolify(&client, CoolifyKind::Service, "res1", &spec())
        .await
        .unwrap_err();
    assert!(matches!(err, EnrollError::NoCompose(_)), "{err}");
    assert!(err.to_string().contains("read:sensitive"));
    assert_eq!(st.lock().unwrap().calls, vec!["GET /services/res1"]);
}

#[tokio::test]
async fn http_errors_stop_before_restart() {
    let (url, st) = serve(Fake {
        fail_patch: Some(422),
        ..with_compose()
    })
    .await;
    let client = CoolifyClient::new(&url, TOKEN).unwrap();
    let err = enroll_coolify(&client, CoolifyKind::Service, "res1", &spec())
        .await
        .unwrap_err();
    assert!(
        matches!(err, EnrollError::CoolifyStatus { status: 422, ref body, .. } if body.contains("base64")),
        "{err}"
    );
    assert!(
        !st.lock()
            .unwrap()
            .calls
            .iter()
            .any(|c| c.ends_with("restart"))
    );

    let err = enroll_coolify(&client, CoolifyKind::Service, "nope", &spec())
        .await
        .unwrap_err();
    assert!(
        matches!(err, EnrollError::CoolifyStatus { status: 404, .. }),
        "{err}"
    );
}

#[tokio::test]
async fn wrong_token_is_rejected_and_token_is_never_printed() {
    let (url, _st) = serve(with_compose()).await;
    let client = CoolifyClient::new(&url, "wrong").unwrap();
    let err = client.get_service("res1").await.unwrap_err();
    assert!(
        matches!(err, EnrollError::CoolifyStatus { status: 401, .. }),
        "{err}"
    );
    let good = CoolifyClient::new(&url, TOKEN).unwrap();
    assert!(!format!("{good:?}").contains("secret"));
}

#[tokio::test]
async fn already_enrolled_resource_is_not_rewritten() {
    // Enrolled with other parameters: no resume, clear error, nothing written.
    let other = EnrollSpec {
        agent_ip: "10.80.0.31".parse().unwrap(),
        ..spec()
    };
    let enrolled = enroll_compose(COMPOSE, &other).unwrap().yaml;
    let (url, st) = serve(Fake {
        compose: Some(enrolled),
        ..Fake::default()
    })
    .await;
    let client = CoolifyClient::new(&url, TOKEN).unwrap();
    let err = enroll_coolify(&client, CoolifyKind::Service, "res1", &spec())
        .await
        .unwrap_err();
    assert!(matches!(err, EnrollError::AlreadyEnrolled(_)));
    assert_eq!(st.lock().unwrap().calls.len(), 1);
}

#[tokio::test]
async fn restart_falls_back_to_get_on_older_coolify() {
    let (url, st) = serve(Fake {
        restart_post_not_allowed: true,
        ..with_compose()
    })
    .await;
    let client = CoolifyClient::new(&url, TOKEN).unwrap();
    client.restart(CoolifyKind::Service, "res1").await.unwrap();
    assert_eq!(
        st.lock().unwrap().calls,
        vec!["POST /services/res1/restart", "GET /services/res1/restart"]
    );
}

#[tokio::test]
async fn base64_compose_from_get_is_decoded_and_bad_uuid_refused() {
    let b64 = base64::engine::general_purpose::STANDARD.encode(COMPOSE);
    let (url, _st) = serve(Fake {
        compose: Some(b64),
        ..Fake::default()
    })
    .await;
    let client = CoolifyClient::new(&url, TOKEN).unwrap();
    let r = client.get_service("res1").await.unwrap();
    assert_eq!(r.docker_compose_raw.as_deref(), Some(COMPOSE));
    assert_eq!(r.name.as_deref(), Some("bots"));
    for bad in ["", "../x", "a/b", "a?b"] {
        assert!(matches!(
            client.get_application(bad).await.unwrap_err(),
            EnrollError::InvalidSpec(_)
        ));
    }
}

// ---------------------------------------------------------------- review #6 findings

#[tokio::test]
async fn coolify_network_injected_on_holder_is_rolled_back() {
    let (url, st) = serve(Fake {
        inject_network: true,
        ..with_compose()
    })
    .await;
    let client = CoolifyClient::new(&url, TOKEN).unwrap();
    let err = enroll_coolify(&client, CoolifyKind::Service, "res1", &spec())
        .await
        .unwrap_err();
    assert!(
        matches!(err, EnrollError::CoolifyRejected { ref reason, .. } if reason.contains("coolify")),
        "{err}"
    );
    let s = st.lock().unwrap();
    assert_eq!(s.compose.as_deref(), Some(COMPOSE), "original written back");
    assert!(!s.calls.iter().any(|c| c.ends_with("restart")));
}

#[tokio::test]
async fn failed_restart_writes_the_original_back_and_resume_restarts_only() {
    let (url, st) = serve(Fake {
        restart_fails: true,
        ..with_compose()
    })
    .await;
    let client = CoolifyClient::new(&url, TOKEN).unwrap();
    let err = enroll_coolify(&client, CoolifyKind::Service, "res1", &spec())
        .await
        .unwrap_err();
    assert!(
        matches!(err, EnrollError::CoolifyStatus { status: 500, .. }),
        "{err}"
    );
    assert_eq!(st.lock().unwrap().compose.as_deref(), Some(COMPOSE));

    // A resource left enrolled with the same parameters (rollback impossible, crash…)
    // is resumed: restart only, no rewrite.
    let enrolled = enroll_compose(COMPOSE, &spec()).unwrap().yaml;
    {
        let mut s = st.lock().unwrap();
        s.compose = Some(enrolled.clone());
        s.restart_fails = false;
        s.calls.clear();
    }
    let out = enroll_coolify(&client, CoolifyKind::Service, "res1", &spec())
        .await
        .unwrap();
    assert_eq!(out.yaml, enrolled);
    assert_eq!(
        st.lock().unwrap().calls,
        vec!["GET /services/res1", "POST /services/res1/restart"]
    );
}

#[tokio::test]
async fn agent_token_is_set_as_a_resource_variable() {
    let (url, st) = serve(with_compose()).await;
    let client = CoolifyClient::new(&url, TOKEN).unwrap();
    client
        .set_env(
            CoolifyKind::Service,
            "res1",
            "AFW_TOKEN_DANIEL",
            "afw_tok_123",
        )
        .await
        .unwrap();
    let s = st.lock().unwrap();
    assert_eq!(s.calls, vec!["PATCH /services/res1/envs/bulk"]);
    assert_eq!(s.envs[0]["key"], "AFW_TOKEN_DANIEL");
    assert_eq!(s.envs[0]["value"], "afw_tok_123");
}
