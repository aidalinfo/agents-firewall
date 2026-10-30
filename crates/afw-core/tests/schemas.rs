//! JSON Schemas of the wire formats, generated from afw-core into `docs/schemas/`.
//! `AFW_UPDATE_SCHEMAS=1 cargo test -p afw-core` regenerates them; otherwise the test fails
//! when a committed schema differs from the code.

use std::path::PathBuf;

use afw_core::InstalledPolicy;
use afw_core::events::{AuditEntry, GatewayEvent, ToolCallEvent};
use schemars::schema::RootSchema;
use schemars::schema_for;

fn check(file: &str, schema: RootSchema) {
    let path = PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("../../docs/schemas").join(file);
    let generated = serde_json::to_string_pretty(&schema).unwrap() + "\n";
    if std::env::var_os("AFW_UPDATE_SCHEMAS").is_some() {
        std::fs::write(&path, &generated).unwrap();
        return;
    }
    let committed = std::fs::read_to_string(&path).unwrap_or_default();
    assert!(
        committed == generated,
        "{} is out of date: run `AFW_UPDATE_SCHEMAS=1 scripts/cargo.sh test -p afw-core`",
        path.display()
    );
}

#[test]
fn schemas_are_up_to_date() {
    check("installed-policy.schema.json", schema_for!(InstalledPolicy));
    check("gateway-event.schema.json", schema_for!(GatewayEvent));
    check("tool-call-event.schema.json", schema_for!(ToolCallEvent));
    check("audit-entry.schema.json", schema_for!(AuditEntry));
}
