//! `afw` end to end, in-process, against the fake API (contract-shaped responses built from
//! the afw-core DTOs).

use std::path::{Path, PathBuf};

use afw_client::fake::{FakeApi, Reply};
use afw_core::api::{
    Approval, ApprovalStatus, Enrollment, Gateway, GatewayStatus, Install, InstallResult,
    InstallState, Me, Page, Revision, Role, Session, SessionState,
};
use afw_core::events::{
    Actor, ActorKind, DecisionRef, FlowEvent, Interface, Verdict,
};
use afw_core::policy::{
    Action, Agent, AgentKind, L4Proto, Layer, NetObject, NetObjectSpec, Rule, Track, Zone,
    ZoneMode,
};
use chrono::Utc;
use serde_json::{Value, json};
use uuid::Uuid;

struct Out {
    code: i32,
    out: String,
    err: String,
}

struct Env {
    dir: tempfile::TempDir,
}

impl Env {
    fn new() -> Self {
        Self {
            dir: tempfile::tempdir().unwrap(),
        }
    }
    fn config(&self) -> PathBuf {
        self.dir.path().join("afw/config.toml")
    }
    fn path(&self, name: &str) -> PathBuf {
        self.dir.path().join(name)
    }
}

async fn afw_full(env: &Env, url: Option<&str>, token: Option<&str>, args: &[&str], stdin: &str, docker: &str) -> Out {
    let mut full: Vec<std::ffi::OsString> = vec!["afw".into()];
    full.push("--config".into());
    full.push(env.config().into());
    if let Some(u) = url {
        full.push("--url".into());
        full.push(u.into());
    }
    full.extend(args.iter().map(Into::into));
    let mut out = Vec::new();
    let mut err = Vec::new();
    let mut input = stdin.as_bytes();
    let io = afw_cli::Io {
        out: &mut out,
        err: &mut err,
        stdin: &mut input,
        env_token: token.map(str::to_string),
        coolify_token: None,
        docker: docker.into(),
    };
    let code = afw_cli::run(full, io).await;
    Out {
        code,
        out: String::from_utf8(out).unwrap(),
        err: String::from_utf8(err).unwrap(),
    }
}

async fn afw(env: &Env, fake: &FakeApi, args: &[&str]) -> Out {
    afw_full(env, Some(&fake.url()), Some("tok-secret-123"), args, "", "docker").await
}

fn actor() -> Actor {
    Actor {
        kind: ActorKind::Human,
        id: "alice".into(),
        name: "Alice".into(),
    }
}

fn session(id: Uuid) -> Session {
    Session {
        id,
        owner: actor(),
        interface: Interface::Cli,
        state: SessionState::Open,
        opened_at: Utc::now(),
        closed_at: None,
        locks: vec![],
        changes: 0,
        approval_id: None,
    }
}

fn zone(name: &str) -> Zone {
    Zone {
        id: Uuid::new_v4(),
        name: name.into(),
        comment: String::new(),
        mode: ZoneMode::Enforce,
        delegated_to_mcp: false,
    }
}

fn gateway(name: &str) -> Gateway {
    Gateway {
        id: Uuid::new_v4(),
        name: name.into(),
        hostname: format!("{name}.local"),
        status: GatewayStatus::Online,
        version: Some("0.1.0".into()),
        desired_revision: Some(3),
        active_revision: Some(3),
        last_seen_at: Some(Utc::now()),
        registered_at: Utc::now(),
        ca_fingerprint: None,
        stats: None,
    }
}

fn no_current_session(fake: &FakeApi, id: Uuid) {
    fake.on(
        "GET",
        "/sessions/current",
        Reply::problem(404, "Not Found", "no open session"),
    );
    fake.on_json("POST", "/sessions", 201, &session(id));
}

// ---------------------------------------------------------------------------------------------
// Help snapshots and parsing

fn snapshot(name: &str, actual: &str) {
    let path = Path::new(env!("CARGO_MANIFEST_DIR"))
        .join("tests/snapshots")
        .join(format!("{name}.txt"));
    if std::env::var_os("AFW_UPDATE_SNAPSHOTS").is_some() {
        std::fs::write(&path, actual).unwrap();
        return;
    }
    let expected = std::fs::read_to_string(&path).unwrap_or_else(|_| {
        panic!(
            "missing snapshot {}: run with AFW_UPDATE_SNAPSHOTS=1",
            path.display()
        )
    });
    assert_eq!(actual, expected, "snapshot {name} differs (AFW_UPDATE_SNAPSHOTS=1 to update)");
}

#[tokio::test]
async fn help_snapshots() {
    let env = Env::new();
    let cases: &[(&str, &[&str])] = &[
        ("help", &["--help"]),
        ("help-objects", &["objects", "--help"]),
        ("help-objects-create", &["objects", "create", "--help"]),
        ("help-rules-create", &["rules", "create", "--help"]),
        ("help-session", &["session", "--help"]),
        ("help-allow", &["allow", "--help"]),
        ("help-install", &["install", "--help"]),
        ("help-logs", &["logs", "--help"]),
        ("help-logs-flows", &["logs", "flows", "--help"]),
        ("help-enroll", &["enroll", "--help"]),
        ("help-unenroll", &["unenroll", "--help"]),
        ("help-import", &["import", "egress-guard", "--help"]),
    ];
    for (name, args) in cases {
        let o = afw_full(&env, None, None, args, "", "docker").await;
        assert_eq!(o.code, 0, "{name}: {}", o.err);
        snapshot(name, &o.out);
    }
}

#[test]
fn clap_definitions_are_consistent() {
    use clap::CommandFactory;
    afw_cli::cli::Cli::command().debug_assert();
}

#[tokio::test]
async fn parsing_errors_exit_2() {
    let env = Env::new();
    for args in [
        &["rules", "create", "--zone", "a", "--baseline"][..],
        &["install", "3"][..],
        &["install", "3", "--all", "--gateway", "gw"][..],
        &["objects", "create", "--domain", "a.com", "--any"][..],
        &["logs", "flows", "--verdict", "maybe"][..],
        &["enroll", "bot"][..],
        &["nope"][..],
    ] {
        let o = afw_full(&env, None, None, args, "", "docker").await;
        assert_eq!(o.code, 2, "{args:?}: {}", o.err);
    }
}

#[tokio::test]
async fn missing_configuration_is_explained() {
    let env = Env::new();
    let o = afw_full(&env, None, None, &["zones", "list"], "", "docker").await;
    assert_eq!(o.code, 1);
    assert!(o.err.contains("afw login"), "{}", o.err);
}

// ---------------------------------------------------------------------------------------------
// Login and configuration

#[tokio::test]
async fn login_stores_token_0600_and_never_prints_it() {
    let env = Env::new();
    let fake = FakeApi::start().await;
    fake.on_json(
        "GET",
        "/me",
        200,
        &Me {
            actor: actor(),
            email: None,
            role: Role::Admin,
            agent_id: None,
            writable_zones: None,
        },
    );
    let o = afw_full(&env, None, None, &["login", "--url", &fake.url()], "tok-from-stdin-42\n", "docker").await;
    assert_eq!(o.code, 0, "{}", o.err);
    assert!(o.out.contains("Logged in"));
    assert!(!o.out.contains("tok-from-stdin-42") && !o.err.contains("tok-from-stdin-42"));
    assert_eq!(
        fake.requests_to("GET", "/me")[0].header("authorization"),
        Some("Bearer tok-from-stdin-42")
    );
    let text = std::fs::read_to_string(env.config()).unwrap();
    assert!(text.contains("tok-from-stdin-42"));
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        let mode = std::fs::metadata(env.config()).unwrap().permissions().mode();
        assert_eq!(mode & 0o777, 0o600);
    }
    for args in [&["config", "show"][..], &["--json", "config", "show"][..]] {
        let o = afw_full(&env, None, None, args, "", "docker").await;
        assert_eq!(o.code, 0);
        assert!(!o.out.contains("tok-from-stdin-42"), "{}", o.out);
    }
    // The stored configuration is used by the next commands.
    fake.on_json("GET", "/zones", 200, &Vec::<Zone>::new());
    let o = afw_full(&env, None, None, &["zones", "list"], "", "docker").await;
    assert_eq!(o.code, 0, "{}", o.err);
    assert_eq!(
        fake.requests_to("GET", "/zones")[0].header("x-afw-interface"),
        Some("cli")
    );
}

#[tokio::test]
async fn login_refused_token_writes_nothing() {
    let env = Env::new();
    let fake = FakeApi::start().await;
    fake.on("GET", "/me", Reply::problem(401, "Unauthorized", "invalid token"));
    let o = afw_full(&env, None, None, &["login", "--url", &fake.url()], "bad\n", "docker").await;
    assert_eq!(o.code, 1);
    assert!(o.err.contains("401") && o.err.contains("hint"), "{}", o.err);
    assert!(!env.config().exists());
}

// ---------------------------------------------------------------------------------------------
// Resources

#[tokio::test]
async fn objects_list_table_and_json() {
    let env = Env::new();
    let fake = FakeApi::start().await;
    let o = NetObject {
        id: Uuid::new_v4(),
        name: "github-api".into(),
        comment: String::new(),
        category: None,
        spec: NetObjectSpec::Domain {
            pattern: "api.github.com".into(),
        },
    };
    fake.on_json("GET", "/objects", 200, &vec![o.clone()]);
    let out = afw(&env, &fake, &["objects", "list"]).await;
    assert_eq!(out.code, 0, "{}", out.err);
    let lines: Vec<&str> = out.out.lines().collect();
    assert!(lines[0].starts_with("ID") && lines[0].contains("NAME") && lines[0].contains("VALUE"));
    assert!(lines[1].contains("github-api") && lines[1].contains("api.github.com"));
    let out = afw(&env, &fake, &["--json", "objects", "list"]).await;
    let v: Value = serde_json::from_str(&out.out).unwrap();
    assert_eq!(v, serde_json::to_value(vec![o]).unwrap());
}

#[tokio::test]
async fn create_opens_a_session_and_sends_a_valid_body() {
    let env = Env::new();
    let fake = FakeApi::start().await;
    let sid = Uuid::new_v4();
    no_current_session(&fake, sid);
    fake.on("POST", "/objects", Reply::json(201, &json!({})));
    let out = afw(
        &env,
        &fake,
        &["objects", "create", "--name", "pypi", "--domain", "*.pypi.org", "--category", "internal"],
    )
    .await;
    assert_eq!(out.code, 0, "{}", out.err);
    assert!(out.err.contains(&format!("Opened editing session {sid}")));
    let r = &fake.requests_to("POST", "/objects")[0];
    assert_eq!(r.header("x-afw-session"), Some(sid.to_string().as_str()));
    let body = r.json();
    assert_eq!(body["name"], "pypi");
    assert_eq!(body["spec"], json!({"type": "domain", "pattern": "*.pypi.org"}));
    assert_eq!(body["category"], "internal");
    serde_json::from_value::<NetObject>(body).unwrap();
}

#[tokio::test]
async fn invalid_body_is_refused_locally() {
    let env = Env::new();
    let fake = FakeApi::start().await;
    let out = afw(&env, &fake, &["objects", "create", "--name", "x"]).await;
    assert_eq!(out.code, 1);
    assert!(out.err.contains("--domain"), "{}", out.err);
    let out = afw(&env, &fake, &["objects", "create", "--name", "x", "--host", "not-an-ip"]).await;
    assert_eq!(out.code, 1);
    assert!(out.err.contains("invalid object"), "{}", out.err);
    assert!(fake.requests().is_empty(), "nothing sent to the API");
}

#[tokio::test]
async fn rule_create_resolves_names_and_appends_to_the_zone_layer() {
    let env = Env::new();
    let fake = FakeApi::start().await;
    let sid = Uuid::new_v4();
    let z = zone("clients");
    let dst = NetObject {
        id: Uuid::new_v4(),
        name: "github".into(),
        comment: String::new(),
        category: None,
        spec: NetObjectSpec::Domain {
            pattern: "github.com".into(),
        },
    };
    let existing = Rule {
        id: Uuid::new_v4(),
        name: "old".into(),
        layer: Layer::Zone { zone_id: z.id },
        section: None,
        position: 4,
        sources: vec![z.id],
        destinations: vec![],
        services: vec![],
        data_classes: vec![],
        action: Action::Deny,
        track: Track::Log,
        expires_at: None,
        comment: String::new(),
        enabled: true,
    };
    fake.on_json("GET", "/zones", 200, &vec![z.clone()]);
    fake.on_json("GET", "/objects", 200, &vec![dst.clone()]);
    fake.on_json("GET", "/rules", 200, &vec![existing]);
    fake.on_json("GET", "/sessions/current", 200, &session(sid));
    fake.on("POST", "/rules", Reply::json(201, &json!({})));
    let out = afw(
        &env,
        &fake,
        &[
            "rules", "create", "--name", "allow-github", "--zone", "clients", "--destination",
            "github", "--action", "accept", "--expires", "7d",
        ],
    )
    .await;
    assert_eq!(out.code, 0, "{}", out.err);
    let body = fake.requests_to("POST", "/rules")[0].json();
    let rule: Rule = serde_json::from_value(body).unwrap();
    assert_eq!(rule.layer, Layer::Zone { zone_id: z.id });
    assert_eq!(rule.sources, vec![z.id]);
    assert_eq!(rule.destinations, vec![dst.id]);
    assert_eq!(rule.position, 5);
    assert_eq!(rule.action, Action::Accept);
    assert!(rule.expires_at.unwrap() > Utc::now());
}

#[tokio::test]
async fn api_refusal_shows_problem_and_hint() {
    let env = Env::new();
    let fake = FakeApi::start().await;
    let z = zone("ops");
    fake.on_json("GET", "/sessions/current", 200, &session(Uuid::new_v4()));
    fake.on(
        "DELETE",
        &format!("/zones/{}", z.id),
        Reply::problem(403, "Forbidden", "zone ops applies to the caller"),
    );
    let out = afw(&env, &fake, &["zones", "delete", &z.id.to_string()]).await;
    assert_eq!(out.code, 1);
    assert!(out.err.contains("403") && out.err.contains("applies to the caller"), "{}", out.err);
    assert!(out.err.contains("hint"));
}

// ---------------------------------------------------------------------------------------------
// Allow, publish, install

#[tokio::test]
async fn allow_from_flow_prepares_rule_in_session() {
    let env = Env::new();
    let fake = FakeApi::start().await;
    let sid = Uuid::new_v4();
    no_current_session(&fake, sid);
    let z = zone("clients");
    let rule = Rule {
        id: Uuid::new_v4(),
        name: "Autorisé depuis le journal".into(),
        layer: Layer::Zone { zone_id: z.id },
        section: None,
        position: 1,
        sources: vec![z.id],
        destinations: vec![],
        services: vec![],
        data_classes: vec![],
        action: Action::Accept,
        track: Track::Detailed,
        expires_at: None,
        comment: String::new(),
        enabled: true,
    };
    let mut view = serde_json::to_value(&rule).unwrap();
    view["number"] = json!(9);
    view["hits"] = json!(0);
    fake.on_json(
        "POST",
        &format!("/sessions/{sid}/allow-from-log"),
        201,
        &json!({"rule": view, "created_object": null, "changes": []}),
    );
    let flow = Uuid::new_v4();
    let out = afw(
        &env,
        &fake,
        &["allow", &flow.to_string(), "--destination", "wildcard", "--expires-in-days", "30"],
    )
    .await;
    assert_eq!(out.code, 0, "{}", out.err);
    assert!(out.out.contains(&rule.id.to_string()) && out.out.contains(&sid.to_string()));
    assert_eq!(fake.requests_to("POST", "/sessions").len(), 1);
    assert_eq!(
        fake.requests_to("POST", &format!("/sessions/{sid}/allow-from-log"))[0].json(),
        json!({"flow_id": flow, "destination": "wildcard", "expires_in_days": 30})
    );
}

fn approval(sid: Uuid) -> Approval {
    Approval {
        id: Uuid::new_v4(),
        session_id: sid,
        requested_by: actor(),
        requested_at: Utc::now(),
        summary: "rule to *.com".into(),
        reason: "wide wildcard".into(),
        status: ApprovalStatus::Pending,
        decided_by: None,
        decided_at: None,
        comment: None,
    }
}

#[tokio::test]
async fn publish_reports_revision_or_pending_approval() {
    let env = Env::new();
    let fake = FakeApi::start().await;
    let sid = Uuid::new_v4();
    fake.on_json("GET", "/sessions/current", 200, &session(sid));
    let a = approval(sid);
    fake.on("POST", &format!("/sessions/{sid}/publish"), Reply::json(202, &a));
    fake.on(
        "POST",
        &format!("/sessions/{sid}/publish"),
        Reply::json(
            201,
            &Revision {
                number: 12,
                published_at: Utc::now(),
                published_by: actor(),
                interface: Interface::Cli,
                session_id: Some(sid),
                comment: "c".into(),
                sha256: "0".repeat(64),
            },
        ),
    );
    let out = afw(&env, &fake, &["session", "publish", "-m", "open pypi"]).await;
    assert_eq!(out.code, 0, "{}", out.err);
    assert!(out.out.contains("approval") && out.out.contains(&a.id.to_string()), "{}", out.out);
    let out = afw(&env, &fake, &["session", "publish", "-m", "open pypi"]).await;
    assert!(out.out.contains("Published revision 12"), "{}", out.out);
}

fn install(gw: Uuid, state: InstallState, id: Uuid) -> Install {
    Install {
        id,
        revision: 12,
        gateway_id: gw,
        requested_at: Utc::now(),
        requested_by: actor(),
        state,
        acked_at: None,
        error: (state == InstallState::Failed).then(|| "nft load failed".into()),
    }
}

#[tokio::test]
async fn install_all_waits_for_each_gateway() {
    let env = Env::new();
    let fake = FakeApi::start().await;
    let gw = gateway("gw-1");
    let iid = Uuid::new_v4();
    fake.on_json("GET", "/gateways", 200, &vec![gw.clone()]);
    fake.on_json(
        "POST",
        "/installs",
        202,
        &InstallResult {
            installs: vec![install(gw.id, InstallState::Pending, iid)],
        },
    );
    fake.on_json(
        "GET",
        "/installs",
        200,
        &Page {
            items: vec![install(gw.id, InstallState::Installed, iid)],
            next_cursor: None,
        },
    );
    let out = afw(&env, &fake, &["install", "12", "--all"]).await;
    assert_eq!(out.code, 0, "{}", out.err);
    assert!(out.out.contains("gw-1") && out.out.contains("installed"), "{}", out.out);
    assert_eq!(
        fake.requests_to("POST", "/installs")[0].json(),
        json!({"revision": 12, "gateways": []})
    );
    assert_eq!(
        fake.requests_to("GET", "/installs")[0].query_param("revision"),
        Some("12")
    );
}

#[tokio::test]
async fn install_failure_exits_non_zero() {
    let env = Env::new();
    let fake = FakeApi::start().await;
    let gw = gateway("gw-1");
    fake.on_json("GET", "/gateways", 200, &vec![gw.clone()]);
    fake.on_json(
        "POST",
        "/installs",
        202,
        &InstallResult {
            installs: vec![install(gw.id, InstallState::Failed, Uuid::new_v4())],
        },
    );
    let out = afw(&env, &fake, &["install", "12", "--gateway", "gw-1"]).await;
    assert_eq!(out.code, 1);
    assert!(out.err.contains("failed"), "{}", out.err);
    assert_eq!(
        fake.requests_to("POST", "/installs")[0].json(),
        json!({"revision": 12, "gateways": [gw.id]})
    );
}

// ---------------------------------------------------------------------------------------------
// Logs

#[tokio::test]
async fn logs_flows_sends_ef41_filters_and_prints_rows() {
    let env = Env::new();
    let fake = FakeApi::start().await;
    let agent = Agent {
        id: Uuid::new_v4(),
        name: "laurent-bot".into(),
        zone_id: Uuid::new_v4(),
        kind: AgentKind::DockerCompose,
        gateway_id: None,
        addresses: vec![],
        labels: Default::default(),
        hermes: false,
        mcp_admin: false,
    };
    let flow = FlowEvent {
        id: Uuid::new_v4(),
        gateway_id: Uuid::new_v4(),
        agent_id: Some(agent.id),
        zone_id: Some(agent.zone_id),
        src: "10.77.0.11:40000".parse().unwrap(),
        dst: "140.82.112.5:443".parse().unwrap(),
        protocol: L4Proto::Tcp,
        app: None,
        domain: Some("exfil.example".into()),
        sni: None,
        bytes_out: 10,
        bytes_in: 0,
        started_at: Utc::now(),
        ended_at: None,
        verdict: Verdict::Deny,
        decision: DecisionRef {
            rule_id: None,
            rule_number: None,
            rule_name: "default-deny".into(),
            revision: Some(3),
            layer: "implicit".into(),
            reason: "no rule matched".into(),
        },
        internal: false,
        llm_provider: false,
        tls_inspected: false,
        data_classes: vec![],
        observed: false,
    };
    // Flow list items as returned by the API: the flow plus display fields.
    let mut item = serde_json::to_value(&flow).unwrap();
    item["agent_name"] = json!("laurent-bot");
    item["zone_name"] = json!("clients");
    item["rule_label"] = json!("default-deny");
    fake.on_json("GET", "/agents", 200, &vec![agent.clone()]);
    fake.on_json(
        "GET",
        "/logs/flows",
        200,
        &json!({"items": [item], "next_cursor": "c2"}),
    );
    let out = afw(
        &env,
        &fake,
        &[
            "logs", "flows", "--agent", "laurent-bot", "--verdict", "deny", "--destination",
            "exfil.example", "--from", "2026-10-30T08:00:00Z", "-q", "upload", "--limit", "20",
        ],
    )
    .await;
    assert_eq!(out.code, 0, "{}", out.err);
    assert!(out.out.contains("exfil.example:443") && out.out.contains("laurent-bot"));
    assert!(out.out.contains("default-deny"));
    assert!(out.err.contains("--cursor c2"));
    let r = &fake.requests_to("GET", "/logs/flows")[0];
    assert_eq!(r.query_param("agent"), Some(agent.id.to_string().as_str()));
    assert_eq!(r.query_param("verdict"), Some("deny"));
    assert_eq!(r.query_param("destination"), Some("exfil.example"));
    assert_eq!(r.query_param("from"), Some("2026-10-30T08:00:00Z"));
    assert_eq!(r.query_param("q"), Some("upload"));
    assert_eq!(r.query_param("limit"), Some("20"));
}

// ---------------------------------------------------------------------------------------------
// Enrollment (compose fixture, no Docker)

fn fixture_copy(env: &Env) -> PathBuf {
    let src = Path::new(env!("CARGO_MANIFEST_DIR")).join("tests/fixtures/compose.yml");
    let dst = env.path("docker-compose.yml");
    std::fs::copy(src, &dst).unwrap();
    dst
}

fn enrollment(z: &Zone, gw: &Gateway, sid: Uuid, hermes: bool) -> Enrollment {
    Enrollment {
        agent: Agent {
            id: Uuid::new_v4(),
            name: "laurent-bot".into(),
            zone_id: z.id,
            kind: AgentKind::DockerCompose,
            gateway_id: Some(gw.id),
            addresses: vec![],
            labels: Default::default(),
            hermes,
            mcp_admin: false,
        },
        session_id: sid,
        plugin_token: hermes.then(|| "plugin-secret-xyz".into()),
    }
}

#[tokio::test]
async fn enroll_dry_run_touches_nothing() {
    let env = Env::new();
    let fake = FakeApi::start().await;
    let file = fixture_copy(&env);
    let before = std::fs::read_to_string(&file).unwrap();
    let out = afw(
        &env,
        &fake,
        &["enroll", "laurent-bot", "--zone", "clients", "--compose", file.to_str().unwrap(), "--ip", "10.77.0.11", "--dry-run"],
    )
    .await;
    assert_eq!(out.code, 0, "{}", out.err);
    assert!(out.out.contains("afw-net-laurent-bot"));
    assert_eq!(std::fs::read_to_string(&file).unwrap(), before);
    assert!(fake.requests().is_empty());
}

#[tokio::test]
async fn enroll_compose_then_unenroll_round_trip() {
    let env = Env::new();
    let fake = FakeApi::start().await;
    let file = fixture_copy(&env);
    let original: serde_yaml::Value =
        serde_yaml::from_str(&std::fs::read_to_string(&file).unwrap()).unwrap();
    let sid = Uuid::new_v4();
    let z = zone("clients");
    let gw = gateway("gw-1");
    let enr = enrollment(&z, &gw, sid, true);
    fake.on_json("GET", "/zones", 200, &vec![z.clone()]);
    fake.on_json("GET", "/gateways", 200, &vec![gw.clone()]);
    fake.on_json("GET", "/sessions/current", 200, &session(sid));
    fake.on_json("POST", "/enrollments", 201, &enr);
    let mut updated = enr.agent.clone();
    updated.addresses = vec!["10.77.0.11".parse().unwrap()];
    fake.on_json("PUT", &format!("/agents/{}", enr.agent.id), 200, &updated);
    let env_file = env.path(".env");

    let out = afw_full(
        &env,
        Some(&fake.url()),
        Some("tok"),
        &[
            "enroll", "laurent-bot", "--zone", "clients", "--compose", file.to_str().unwrap(),
            "--ip", "10.77.0.11", "--hermes", "--env-file", env_file.to_str().unwrap(), "--apply",
        ],
        "",
        "true",
    )
    .await;
    assert_eq!(out.code, 0, "{}", out.err);
    assert!(out.err.contains("Running: true compose -f"), "{}", out.err);
    assert!(!out.out.contains("plugin-secret-xyz"), "token written to the env file, not printed");
    let envs = std::fs::read_to_string(&env_file).unwrap();
    assert_eq!(envs, "AFW_TOKEN_LAURENT_BOT=plugin-secret-xyz\n");
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        assert_eq!(std::fs::metadata(&env_file).unwrap().permissions().mode() & 0o777, 0o600);
    }
    let enrolled = std::fs::read_to_string(&file).unwrap();
    assert!(enrolled.contains("afw-net-laurent-bot") && enrolled.contains("AFW_TOKEN_LAURENT_BOT"));
    assert!(!enrolled.contains("plugin-secret-xyz"), "secret never written in the compose file");
    let body = fake.requests_to("POST", "/enrollments")[0].json();
    assert_eq!(
        body,
        json!({"name": "laurent-bot", "zone_id": z.id, "kind": "docker_compose", "gateway_id": gw.id, "hermes": true})
    );
    let put = &fake.requests_to("PUT", &format!("/agents/{}", enr.agent.id))[0];
    assert_eq!(put.json()["addresses"], json!(["10.77.0.11"]));
    assert_eq!(put.header("x-afw-session"), Some(sid.to_string().as_str()));

    // Unenroll: exact inverse and agent deleted in the session.
    fake.on_json("GET", "/agents", 200, &vec![updated.clone()]);
    fake.on("DELETE", &format!("/agents/{}", updated.id), Reply::empty(204));
    let out = afw(&env, &fake, &["unenroll", "laurent-bot", "--compose", file.to_str().unwrap()]).await;
    assert_eq!(out.code, 0, "{}", out.err);
    let restored: serde_yaml::Value =
        serde_yaml::from_str(&std::fs::read_to_string(&file).unwrap()).unwrap();
    assert_eq!(restored, original);
    assert_eq!(fake.requests_to("DELETE", &format!("/agents/{}", updated.id)).len(), 1);
}

#[tokio::test]
async fn enroll_api_refusal_leaves_compose_untouched() {
    let env = Env::new();
    let fake = FakeApi::start().await;
    let file = fixture_copy(&env);
    let before = std::fs::read_to_string(&file).unwrap();
    let z = zone("clients");
    let gw = gateway("gw-1");
    fake.on_json("GET", "/zones", 200, &vec![z]);
    fake.on_json("GET", "/gateways", 200, &vec![gw]);
    fake.on_json("GET", "/sessions/current", 200, &session(Uuid::new_v4()));
    fake.on("POST", "/enrollments", Reply::problem(403, "Forbidden", "viewer"));
    let out = afw(
        &env,
        &fake,
        &["enroll", "laurent-bot", "--zone", "clients", "--compose", file.to_str().unwrap(), "--ip", "10.77.0.11"],
    )
    .await;
    assert_eq!(out.code, 1);
    assert_eq!(std::fs::read_to_string(&file).unwrap(), before);
}

#[tokio::test]
async fn import_without_feature_is_explained() {
    let env = Env::new();
    let fake = FakeApi::start().await;
    let f = env.path("eg.yaml");
    std::fs::write(&f, "allow: []\n").unwrap();
    let out = afw(&env, &fake, &["import", "egress-guard", f.to_str().unwrap(), "--zone", "clients"]).await;
    if cfg!(feature = "import") {
        return;
    }
    assert_eq!(out.code, 1);
    assert!(out.err.contains("--features import"), "{}", out.err);
}
