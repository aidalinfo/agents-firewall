//! `afw` end to end against the REAL afw-api (PostgreSQL from `AFW_TEST_DATABASE_URL`; skipped
//! without it): session → object → rule → publish → revisions diff → audit with interface `cli`.

#[path = "common/real_api.rs"]
mod real_api;

use serde_json::Value;

struct Out {
    code: i32,
    out: String,
    err: String,
}

async fn afw(api: &real_api::RealApi, dir: &std::path::Path, args: &[&str]) -> Out {
    let mut full: Vec<std::ffi::OsString> = vec!["afw".into(), "--config".into()];
    full.push(dir.join("config.toml").into());
    full.push("--url".into());
    full.push(api.url.clone().into());
    full.extend(args.iter().map(Into::into));
    let (mut out, mut err) = (Vec::new(), Vec::new());
    let mut stdin: &[u8] = b"";
    let code = afw_cli::run(
        full,
        afw_cli::Io {
            out: &mut out,
            err: &mut err,
            stdin: &mut stdin,
            env_token: Some(api.admin_token.clone()),
            coolify_token: None,
            docker: "docker".into(),
        },
    )
    .await;
    let o = Out {
        code,
        out: String::from_utf8(out).unwrap(),
        err: String::from_utf8(err).unwrap(),
    };
    assert_eq!(o.code, 0, "afw {args:?} failed:\n{}\n{}", o.out, o.err);
    o
}

#[tokio::test]
async fn session_object_rule_publish_diff_audit() {
    let Some(api) = real_api::start().await else {
        eprintln!("AFW_TEST_DATABASE_URL not set: skipped");
        return;
    };
    let dir = tempfile::tempdir().unwrap();
    let d = dir.path();

    let me = afw(&api, d, &["me"]).await;
    assert!(me.out.contains("admin"), "{}", me.out);

    let o = afw(&api, d, &["session", "open", "--name", "l8-e2e"]).await;
    assert!(o.out.contains("Opened editing session"));
    afw(
        &api,
        d,
        &[
            "zones",
            "create",
            "--name",
            "clients",
            "--delegated-to-mcp",
            "true",
        ],
    )
    .await;
    afw(
        &api,
        d,
        &[
            "objects", "create", "--name", "pypi", "--domain", "pypi.org",
        ],
    )
    .await;
    afw(
        &api,
        d,
        &[
            "rules",
            "create",
            "--name",
            "allow-pypi",
            "--zone",
            "clients",
            "--destination",
            "pypi",
            "--action",
            "accept",
        ],
    )
    .await;
    let show = afw(&api, d, &["session", "show"]).await;
    assert!(show.out.contains("changes"), "{}", show.out);
    let rules = afw(&api, d, &["rules", "list"]).await;
    assert!(
        rules.out.contains("allow-pypi") && rules.out.contains("pypi"),
        "{}",
        rules.out
    );
    let p = afw(&api, d, &["session", "publish", "-m", "first policy"]).await;
    assert!(p.out.contains("Published revision 1"), "{}", p.out);

    // Second revision: one more object (session opened automatically).
    let c = afw(
        &api,
        d,
        &[
            "objects",
            "create",
            "--name",
            "github",
            "--domain",
            "github.com",
        ],
    )
    .await;
    assert!(c.err.contains("Opened editing session"), "{}", c.err);
    let p = afw(&api, d, &["session", "publish", "-m", "add github"]).await;
    assert!(p.out.contains("Published revision 2"), "{}", p.out);

    let diff = afw(&api, d, &["revisions", "diff", "2"]).await;
    assert!(
        diff.out.contains("github") && diff.out.contains("added"),
        "{}",
        diff.out
    );
    let list = afw(&api, d, &["revisions", "list"]).await;
    assert!(list.out.contains("add github") && list.out.contains("first policy"));
    afw(&api, d, &["rulebase"]).await;
    afw(&api, d, &["verify", "--revision", "2"]).await;
    afw(&api, d, &["status"]).await;
    let wu = afw(&api, d, &["where-used", "pypi"]).await;
    assert!(wu.out.contains("allow-pypi"), "{}", wu.out);

    let audit = afw(
        &api,
        d,
        &[
            "--json",
            "audit",
            "list",
            "--interface",
            "cli",
            "--limit",
            "1000",
        ],
    )
    .await;
    let page: Value = serde_json::from_str(&audit.out).unwrap();
    let items = page["items"].as_array().unwrap();
    assert!(!items.is_empty(), "no audit entry with interface cli");
    assert!(items.iter().all(|e| e["interface"] == "cli"));
    let actions: Vec<&str> = items.iter().filter_map(|e| e["action"].as_str()).collect();
    assert!(actions.iter().any(|a| a.contains("publish")), "{actions:?}");
    let v = afw(&api, d, &["audit", "verify"]).await;
    assert!(v.out.contains("intact"), "{}", v.out);
    let _ = api.pool;
}
