//! Contract tests of `docs/api/openapi.yaml` and `docs/api/gateway-openapi.yaml` (ADR 0008):
//! every expected path exists, every `$ref` resolves, and `components.schemas` equals the
//! schemas generated from afw-core. `AFW_UPDATE_SCHEMAS=1` regenerates `components.schemas`.

use std::collections::BTreeSet;
use std::path::PathBuf;

use afw_core::InstalledPolicy;
use afw_core::api::*;
use afw_core::events::*;
use afw_core::policy::*;
use afw_core::protocol::*;
use schemars::r#gen::{SchemaGenerator, SchemaSettings};
use serde_yaml::Value;

fn generator() -> SchemaGenerator {
    let mut settings = SchemaSettings::draft2019_09();
    settings.definitions_path = "#/components/schemas/".to_owned();
    settings.meta_schema = None;
    settings.into_generator()
}

/// Replaces boolean `true` schemas (e.g. `serde_json::Value`) by `{}`: equivalent in JSON
/// Schema, but OpenAPI tooling (openapi-typescript) expects schema objects.
fn objectify_true_schemas(v: &mut serde_json::Value) {
    use serde_json::Value as J;
    let fix = |x: &mut J| {
        if *x == J::Bool(true) {
            *x = J::Object(Default::default());
        }
    };
    match v {
        J::Object(m) => {
            for (k, val) in m.iter_mut() {
                match k.as_str() {
                    "properties" | "patternProperties" => {
                        if let J::Object(props) = val {
                            props.values_mut().for_each(fix);
                        }
                    }
                    "items" | "additionalProperties" => fix(val),
                    "anyOf" | "oneOf" | "allOf" => {
                        if let J::Array(a) = val {
                            a.iter_mut().for_each(fix);
                        }
                    }
                    _ => {}
                }
                objectify_true_schemas(val);
            }
        }
        J::Array(a) => a.iter_mut().for_each(objectify_true_schemas),
        _ => {}
    }
}

macro_rules! register {
    ($g:expr, $($t:ty),* $(,)?) => { $( $g.subschema_for::<$t>(); )* };
}

fn api_schemas() -> serde_json::Value {
    let mut g = generator();
    register!(
        g,
        NetObject,
        Service,
        DataClass,
        Zone,
        Agent,
        Rule,
        InspectionRule,
        PolicySettings,
        PolicyDocument,
        Problem,
        WhereUsed,
        MoveRuleRequest,
        Session,
        PublishRequest,
        AllowFromLogRequest,
        AllowFromLogResponse,
        Revision,
        RevisionDetail,
        RevisionDiff,
        VerifyReport,
        InstallRequest,
        InstallResult,
        Gateway,
        CreateRegistrationToken,
        RegistrationToken,
        GatewayCommand,
        FlowQuery,
        Page<Revision>,
        Page<Install>,
        Page<FlowEvent>,
        Page<DnsEvent>,
        Page<Capture>,
        Page<Alert>,
        Page<AuditEntry>,
        FlowDetail,
        Page<FlowListItem>,
        FlowStats,
        StatsBucket,
        MapPeriod,
        GatewayEvent,
        CaptureRequest,
        Capture,
        Alert,
        AlertChannel,
        InternalMap,
        AgentOverview,
        AuditEntry,
        AuditVerifyResult,
        Approval,
        ApprovalDecision,
        ApprovalStatus,
        Me,
        ApiToken,
        CreateApiToken,
        CreatedApiToken,
        IntentPolicy,
        ToolCallBatch,
        EnrollmentRequest,
        Enrollment,
        Verdict,
        Severity,
        RuleView,
        Rulebase,
        OpenSessionRequest,
        SessionChange,
    );
    let mut v = serde_json::to_value(g.take_definitions()).unwrap();
    objectify_true_schemas(&mut v);
    v
}

fn gateway_schemas() -> serde_json::Value {
    let mut g = generator();
    register!(
        g,
        Problem,
        RegisterRequest,
        RegisterResponse,
        InstalledPolicy,
        PolicyAck,
        EventBatch,
        Heartbeat,
        HeartbeatResponse,
    );
    let mut v = serde_json::to_value(g.take_definitions()).unwrap();
    objectify_true_schemas(&mut v);
    v
}

fn path(file: &str) -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .join("../../docs/api")
        .join(file)
}

/// Loads the document, syncs or checks `components.schemas`, returns the document.
fn load_and_sync(file: &str, schemas: serde_json::Value) -> Value {
    let p = path(file);
    let mut doc: Value = serde_yaml::from_str(&std::fs::read_to_string(&p).unwrap()).unwrap();
    let generated: Value = serde_yaml::to_value(&schemas).unwrap();
    if std::env::var_os("AFW_UPDATE_SCHEMAS").is_some() {
        doc["components"]["schemas"] = generated;
        std::fs::write(&p, serde_yaml::to_string(&doc).unwrap()).unwrap();
    } else {
        assert!(
            doc["components"]["schemas"] == generated,
            "{file}: components.schemas out of date, run \
             `AFW_UPDATE_SCHEMAS=1 scripts/cargo.sh test -p afw-api --test openapi`"
        );
    }
    doc
}

fn collect_refs(v: &Value, out: &mut BTreeSet<String>) {
    match v {
        Value::Mapping(m) => {
            for (k, val) in m {
                if k.as_str() == Some("$ref") {
                    out.insert(val.as_str().unwrap().to_owned());
                } else {
                    collect_refs(val, out);
                }
            }
        }
        Value::Sequence(s) => s.iter().for_each(|x| collect_refs(x, out)),
        _ => {}
    }
}

fn check_document(doc: &Value, expected: &[(&str, &[&str])]) {
    assert_eq!(doc["openapi"].as_str(), Some("3.1.0"));
    let paths = doc["paths"].as_mapping().expect("paths");
    for (p, methods) in expected {
        let item = paths
            .get(Value::from(*p))
            .unwrap_or_else(|| panic!("missing path {p}"));
        for m in *methods {
            let op = &item[*m];
            assert!(op.is_mapping(), "missing {m} {p}");
            assert!(op["operationId"].is_string(), "{m} {p}: operationId");
            assert!(
                op["responses"]["default"].is_mapping(),
                "{m} {p}: default problem response"
            );
        }
    }
    let mut refs = BTreeSet::new();
    collect_refs(doc, &mut refs);
    for r in refs {
        let mut node = doc;
        for part in r.strip_prefix("#/").expect("local ref").split('/') {
            node = &node[part];
        }
        assert!(!node.is_null(), "unresolved $ref {r}");
    }
}

const CRUD: &[&str] = &["get", "post"];
const ITEM: &[&str] = &["get", "put", "delete"];

#[test]
fn rest_contract_covers_every_resource() {
    let doc = load_and_sync("openapi.yaml", api_schemas());
    check_document(
        &doc,
        &[
            ("/objects", CRUD),
            ("/objects/{id}", ITEM),
            ("/objects/{id}/where-used", &["get"]),
            ("/services", CRUD),
            ("/services/{id}", ITEM),
            ("/data-classes", CRUD),
            ("/data-classes/{id}", ITEM),
            ("/zones", CRUD),
            ("/zones/{id}", ITEM),
            ("/agents", CRUD),
            ("/agents/{id}", ITEM),
            ("/agents/{id}/overview", &["get"]),
            ("/rules", CRUD),
            ("/rules/{id}", ITEM),
            ("/rules/{id}/move", &["post"]),
            ("/inspection-rules", CRUD),
            ("/inspection-rules/{id}", ITEM),
            ("/settings", &["get", "put"]),
            ("/sessions", CRUD),
            ("/sessions/current", &["get"]),
            ("/sessions/{id}", &["get"]),
            ("/sessions/{id}/discard", &["post"]),
            ("/sessions/{id}/publish", &["post"]),
            ("/sessions/{id}/allow-from-log", &["post"]),
            ("/sessions/{id}/import", &["post"]),
            ("/rulebase", &["get"]),
            ("/revisions", &["get"]),
            ("/revisions/{n}", &["get"]),
            ("/revisions/{n}/diff", &["get"]),
            ("/revisions/{n}/revert", &["post"]),
            ("/verify", &["get"]),
            ("/installs", CRUD),
            ("/gateways", &["get"]),
            ("/gateways/{id}", &["get", "delete"]),
            ("/gateways/registration-tokens", &["post"]),
            ("/gateways/{id}/commands", &["post"]),
            ("/logs/flows", &["get"]),
            ("/logs/flows/{id}", &["get"]),
            ("/logs/flows/stats", &["get"]),
            ("/logs/dns", &["get"]),
            ("/logs/stream", &["get"]),
            ("/captures", CRUD),
            ("/captures/{id}", &["get"]),
            ("/captures/{id}/download", &["get"]),
            ("/alerts", &["get"]),
            ("/alerts/{id}/ack", &["post"]),
            ("/alert-channels", CRUD),
            ("/alert-channels/{id}", ITEM),
            ("/internal-map", &["get"]),
            ("/audit", &["get"]),
            ("/audit/verify", &["get"]),
            ("/audit/export", &["get"]),
            ("/approvals", &["get"]),
            ("/approvals/{id}", &["get"]),
            ("/approvals/{id}/decision", &["post"]),
            ("/me", &["get"]),
            ("/tokens", CRUD),
            ("/tokens/{id}", &["delete"]),
            ("/intent-policy", &["get", "put"]),
            ("/ingest/tool-calls", &["post"]),
            ("/enrollments", &["post"]),
        ],
    );
    assert_eq!(
        doc["components"]["securitySchemes"]["bearer"]["scheme"].as_str(),
        Some("bearer")
    );
    assert!(
        doc["paths"]["/logs/stream"]["get"]["responses"]["200"]["content"]["text/event-stream"]
            .is_mapping()
    );
    assert!(
        doc["components"]["responses"]["Error"]["content"]["application/problem+json"].is_mapping()
    );
}

#[test]
fn gateway_contract_covers_the_protocol() {
    let doc = load_and_sync("gateway-openapi.yaml", gateway_schemas());
    check_document(
        &doc,
        &[
            ("/gw/v1/register", &["post"]),
            ("/gw/v1/policy", &["get"]),
            ("/gw/v1/policy/ack", &["post"]),
            ("/gw/v1/events", &["post"]),
            ("/gw/v1/heartbeat", &["post"]),
            ("/gw/v1/captures/{id}", &["post"]),
        ],
    );
    assert_eq!(
        doc["components"]["securitySchemes"]["mtls"]["type"].as_str(),
        Some("mutualTLS")
    );
    // Registration is the only call without a client certificate.
    assert_eq!(
        doc["paths"]["/gw/v1/register"]["post"]["security"],
        Value::Sequence(vec![])
    );
}
