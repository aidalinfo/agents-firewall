//! Commands other than the policy resources CRUD and enrollment.

use std::collections::HashMap;
use std::io::{BufRead, BufReader, Read};
use std::path::PathBuf;
use std::time::{Duration, Instant};

use afw_client::{
    AfwClient, AlertQuery, AllowFromLog, AuditQuery, InstallQuery, MapQuery, PageQuery, PolicyKind,
    PublishOutcome, StreamQuery,
};
use afw_core::api::{
    ApprovalDecision, ApprovalStatus, CaptureRequest, CreateApiToken, CreateRegistrationToken,
    FlowQuery, InstallRequest, InstallState, Role,
};
use afw_core::events::{AuditEntry, GatewayEvent, Severity, Verdict};
use afw_core::policy::Track;
use afw_core::protocol::GatewayCommand;
use anyhow::{Context, Result, anyhow};
use futures::StreamExt;
use serde_json::{Value, json};
use uuid::Uuid;

use crate::Ctx;
use crate::cli::{
    AlertsCmd, AllowArgs, ApprovalsCmd, AuditCmd, CapturesCmd, GatewaysCmd, ImportCmd, InstallArgs,
    IntentPolicyCmd, LogFilter, LoginArgs, LogsCmd, MapArgs, Paging, Period, RevisionsCmd,
    SessionCmd, TokensCmd,
};
use crate::config::{self, Config};
use crate::output::{col, colf, kv, scalar, table, time_cell};
use crate::resources::Names;
use crate::util::{enum_word, opt_past, parse_future};

fn values<T: serde::Serialize>(items: &[T]) -> Result<Vec<Value>> {
    Ok(items
        .iter()
        .map(serde_json::to_value)
        .collect::<Result<_, _>>()?)
}

fn parse_enum<T: serde::de::DeserializeOwned>(what: &str, word: &str) -> Result<T> {
    serde_json::from_value(json!(enum_word(word))).map_err(|_| anyhow!("invalid {what} `{word}`"))
}

// ---------------------------------------------------------------------------------------------
// Login, configuration, identity

pub async fn login(ctx: &mut Ctx<'_>, a: LoginArgs, stdin: &mut dyn Read) -> Result<()> {
    let _ = a;
    let url = ctx
        .url_override()
        .or_else(|| ctx.config.url.clone())
        .ok_or_else(|| anyhow!("give the console URL: afw login --url https://<console>"))?;
    let token = match ctx.token_override() {
        Some(t) => t,
        None => {
            writeln!(ctx.err, "API token (read from stdin, never displayed):")?;
            let mut line = String::new();
            BufReader::new(stdin).read_line(&mut line)?;
            line
        }
    };
    let token = config::validate_token(&token)?;
    let ca_cert = ctx
        .ca_cert_override()
        .map(|p| std::path::absolute(&p).unwrap_or(p))
        .map(|p| p.display().to_string())
        .or_else(|| ctx.config.ca_cert.clone());
    let ca_pem = match &ca_cert {
        Some(p) => Some(std::fs::read(p).with_context(|| format!("cannot read {p}"))?),
        None => None,
    };
    let client = AfwClient::with_options(
        &url,
        token.clone(),
        afw_core::events::Interface::Cli,
        afw_client::ClientOptions {
            ca_cert_pem: ca_pem,
            timeout: None,
        },
    )?;
    let me = client.me().await?;
    let cfg = Config {
        url: Some(url.trim_end_matches('/').to_string()),
        token: Some(token),
        ca_cert,
    };
    cfg.save(&ctx.config_path)?;
    let role = scalar(Some(&serde_json::to_value(me.role)?));
    let msg = format!(
        "Logged in to {} as {} ({role}). Configuration saved to {}.",
        cfg.url.as_deref().unwrap_or_default(),
        me.actor.name,
        ctx.config_path.display()
    );
    ctx.say(&msg)
}

pub fn config_show(ctx: &mut Ctx<'_>) -> Result<()> {
    let c = ctx.config.clone();
    let path = ctx.config_path.display().to_string();
    if ctx.json {
        return ctx.print_json(&json!({
            "path": path,
            "url": c.url,
            "token_set": c.token.is_some(),
            "ca_cert": c.ca_cert,
        }));
    }
    kv(
        ctx.out,
        &[
            ("path", path),
            ("url", c.url.unwrap_or_else(|| "-".into())),
            (
                "token",
                if c.token.is_some() {
                    "set (hidden)"
                } else {
                    "not set"
                }
                .into(),
            ),
            ("ca_cert", c.ca_cert.unwrap_or_else(|| "-".into())),
        ],
    )?;
    Ok(())
}

pub async fn me(ctx: &mut Ctx<'_>) -> Result<()> {
    let c = ctx.client()?;
    let me = c.me().await?;
    if ctx.json {
        return ctx.print_json(&me);
    }
    let v = serde_json::to_value(&me)?;
    kv(
        ctx.out,
        &[
            ("name", scalar(v.pointer("/actor/name"))),
            ("id", scalar(v.pointer("/actor/id"))),
            ("kind", scalar(v.pointer("/actor/kind"))),
            ("role", scalar(v.get("role"))),
            ("email", scalar(v.get("email"))),
            ("agent", scalar(v.get("agent_id"))),
            ("writable zones", scalar(v.get("writable_zones"))),
        ],
    )?;
    Ok(())
}

pub async fn agent_overview(ctx: &mut Ctx<'_>, agent: &str) -> Result<()> {
    let c = ctx.client()?;
    let id = c.resolve(PolicyKind::Agents, agent).await?;
    let o = c.agent_overview(id).await?;
    if ctx.json {
        return ctx.print_json(&o);
    }
    let v = serde_json::to_value(&o)?;
    kv(
        ctx.out,
        &[
            ("agent", format!("{} ({})", o.agent.name, o.agent.id)),
            (
                "zone",
                format!("{} ({})", o.zone.name, scalar(v.pointer("/zone/mode"))),
            ),
            ("gateway", scalar(v.pointer("/gateway/name"))),
            ("last seen", time_cell(v.get("last_seen_at"))),
            ("flows (24h)", o.flows_24h.to_string()),
            ("denied (24h)", o.denied_24h.to_string()),
            (
                "bytes out/in (24h)",
                format!("{}/{}", o.bytes_out_24h, o.bytes_in_24h),
            ),
        ],
    )?;
    writeln!(ctx.out, "\nTop destinations:")?;
    table(
        ctx.out,
        &values(&o.top_destinations)?,
        &[
            col("DESTINATION", "/destination"),
            col("FLOWS", "/flows"),
            col("DENIED", "/denied"),
            col("OUT", "/bytes_out"),
            col("IN", "/bytes_in"),
            colf("LAST SEEN", |v| time_cell(v.get("last_seen_at"))),
        ],
    )?;
    writeln!(ctx.out, "\nRecent denials:")?;
    table(
        ctx.out,
        &values(&o.recent_denied)?,
        &flow_cols(Names::from_pairs([])),
    )?;
    writeln!(ctx.out, "\nRecent tool calls:")?;
    table(
        ctx.out,
        &values(&o.recent_tool_calls)?,
        &[
            colf("TIME", |v| time_cell(v.get("started_at"))),
            col("TOOL", "/tool"),
            col("STATUS", "/status"),
            col("ARGS", "/args_summary"),
        ],
    )?;
    writeln!(ctx.out, "\nAlerts:")?;
    table(ctx.out, &values(&o.alerts)?, &alert_event_cols())?;
    Ok(())
}

// ---------------------------------------------------------------------------------------------
// Sessions, verification, allow

pub async fn session(ctx: &mut Ctx<'_>, cmd: SessionCmd) -> Result<()> {
    let c = ctx.client()?;
    match cmd {
        SessionCmd::Open { name } => {
            let s = c.open_session(name.as_deref()).await?;
            if ctx.json {
                return ctx.print_json(&s);
            }
            ctx.say(&format!("Opened editing session {}.", s.id))
        }
        SessionCmd::List => {
            let items = c.list_sessions().await?;
            if ctx.json {
                return ctx.print_json(&items);
            }
            table(
                ctx.out,
                &values(&items)?,
                &[
                    col("ID", "/id"),
                    col("OWNER", "/owner/name"),
                    col("INTERFACE", "/interface"),
                    col("STATE", "/state"),
                    colf("OPENED", |v| time_cell(v.get("opened_at"))),
                    col("CHANGES", "/changes"),
                    col("APPROVAL", "/approval_id"),
                ],
            )?;
            Ok(())
        }
        SessionCmd::Show { id } => {
            let s = match id.or(c.session()) {
                Some(id) => c.get_session(id).await?,
                None => match c.current_session().await? {
                    Some(s) => s,
                    None => return ctx.say("No open session."),
                },
            };
            if ctx.json {
                return ctx.print_json(&s);
            }
            let v = serde_json::to_value(&s)?;
            kv(
                ctx.out,
                &[
                    ("id", s.id.to_string()),
                    ("owner", s.owner.name.clone()),
                    ("interface", scalar(v.get("interface"))),
                    ("state", scalar(v.get("state"))),
                    ("opened", time_cell(v.get("opened_at"))),
                    ("changes", s.changes.to_string()),
                    ("approval", scalar(v.get("approval_id"))),
                ],
            )?;
            if !s.locks.is_empty() {
                writeln!(ctx.out, "\nLocked resources:")?;
                table(
                    ctx.out,
                    &values(&s.locks)?,
                    &[col("KIND", "/kind"), col("NAME", "/name"), col("ID", "/id")],
                )?;
            }
            Ok(())
        }
        SessionCmd::Discard { id } => {
            let id = match id {
                Some(id) => id,
                None => c.ensure_session(false).await?,
            };
            let s = c.discard_session(id).await?;
            if ctx.json {
                return ctx.print_json(&s);
            }
            ctx.say(&format!("Discarded session {id}."))
        }
        SessionCmd::Publish { message, id } => {
            let id = match id {
                Some(id) => id,
                None => c.ensure_session(false).await?,
            };
            let outcome = c.publish_session(id, &message).await?;
            if ctx.json {
                return ctx.print_json(&outcome);
            }
            match outcome {
                PublishOutcome::Published { revision } => ctx.say(&format!(
                    "Published revision {}. Install it with: afw install {} --all",
                    revision.number, revision.number
                )),
                PublishOutcome::PendingApproval { approval } => ctx.say(&format!(
                    "Not published: this change needs a human approval (EF-52).\n\
                     Approval {} is pending: {} ({}).\n\
                     An administrator approves it with `afw approvals approve {}`; then publish again.",
                    approval.id, approval.summary, approval.reason, approval.id
                )),
            }
        }
    }
}

pub async fn status(ctx: &mut Ctx<'_>) -> Result<()> {
    let c = ctx.client()?;
    let st = c.policy_status().await?;
    if ctx.json {
        return ctx.print_json(&st);
    }
    let v = serde_json::to_value(&st)?;
    kv(
        ctx.out,
        &[
            ("latest revision", scalar(v.get("latest_revision"))),
            ("installed revision", scalar(v.get("installed_revision"))),
            (
                "gateways on it",
                format!("{}/{}", st.gateways_on_revision, st.gateways_total),
            ),
            ("pending installs", st.pending_installs.to_string()),
            ("p95 latency (ms)", scalar(v.get("p95_ms"))),
        ],
    )?;
    Ok(())
}

pub async fn verify(ctx: &mut Ctx<'_>, revision: Option<u64>) -> Result<i32> {
    let c = ctx.client()?;
    if revision.is_none() {
        // The draft of your session: send the session header when there is one.
        if c.session().is_none()
            && let Some(s) = c.open_session_of_caller().await?
        {
            c.set_session(Some(s.id));
        }
    }
    let r = c.verify(revision).await?;
    if ctx.json {
        ctx.print_json(&r)?;
        return Ok(0);
    }
    let target = match r.revision {
        Some(n) => format!("revision {n}"),
        None => "session draft".into(),
    };
    if r.findings.is_empty() {
        ctx.say(&format!("Verification of {target}: no finding."))?;
        return Ok(0);
    }
    let names = Names::load(&c, PolicyKind::Rules).await?;
    ctx.say(&format!(
        "Verification of {target}: {} finding(s).",
        r.findings.len()
    ))?;
    let n = names.clone();
    table(
        ctx.out,
        &values(&r.findings)?,
        &[
            col("FINDING", "/type"),
            colf("SUBJECT", move |v| {
                n.name(v.get("rule").or(v.get("id")).unwrap_or(&Value::Null))
            }),
            colf("DETAIL", move |v| match v.get("by") {
                Some(by) => format!("shadowed by {}", names.name(by)),
                None => String::new(),
            }),
        ],
    )?;
    Ok(0)
}

pub async fn allow(ctx: &mut Ctx<'_>, a: AllowArgs) -> Result<()> {
    let c = ctx.client()?;
    let session = ctx.session().await?;
    let track = a
        .track
        .as_deref()
        .map(|t| parse_enum::<Track>("track", t))
        .transpose()?;
    let out = c
        .allow_from_log(
            session,
            &AllowFromLog {
                flow_id: a.flow_id,
                destination: a.destination,
                expires_in_days: a.expires_in_days,
                track,
            },
        )
        .await?;
    if ctx.json {
        return ctx.print_json(&out);
    }
    let mut msg = format!(
        "Prepared rule {} ({}) in session {session} from flow {}.",
        out.rule.rule.name, out.rule.rule.id, a.flow_id
    );
    if let Some(o) = &out.created_object {
        msg.push_str(&format!("\nCreated object {} ({}).", o.name, o.id));
    }
    msg.push_str("\nReview it (afw rules show), then: afw session publish -m <comment>, afw install <revision> --all");
    ctx.say(&msg)
}

// ---------------------------------------------------------------------------------------------
// Revisions and installation

pub async fn revisions(ctx: &mut Ctx<'_>, cmd: RevisionsCmd) -> Result<()> {
    let c = ctx.client()?;
    match cmd {
        RevisionsCmd::List { limit, cursor } => {
            let page = c.list_revisions(&PageQuery { cursor, limit }).await?;
            if ctx.json {
                return ctx.print_json(&page);
            }
            table(
                ctx.out,
                &values(&page.items)?,
                &[
                    col("REVISION", "/number"),
                    colf("PUBLISHED", |v| time_cell(v.get("published_at"))),
                    col("BY", "/published_by/name"),
                    col("INTERFACE", "/interface"),
                    col("COMMENT", "/comment"),
                ],
            )?;
            next_cursor(ctx, page.next_cursor.as_deref())
        }
        RevisionsCmd::Show { revision } => {
            let r = c.get_revision(revision).await?;
            ctx.print_json(&r)
        }
        RevisionsCmd::Diff { revision, against } => {
            let d = c.diff_revision(revision, against).await?;
            if ctx.json {
                return ctx.print_json(&d);
            }
            ctx.say(&format!("Changes from revision {} to {}:", d.from, d.to))?;
            table(
                ctx.out,
                &values(&d.changes)?,
                &[
                    col("CHANGE", "/kind"),
                    col("RESOURCE", "/resource/kind"),
                    col("NAME", "/resource/name"),
                    col("ID", "/resource/id"),
                ],
            )?;
            Ok(())
        }
        RevisionsCmd::Revert { revision } => {
            let s = c.revert_to_revision(revision).await?;
            if ctx.json {
                return ctx.print_json(&s);
            }
            ctx.say(&format!(
                "Opened session {} with the content of revision {revision}. Publish it to roll back: afw session publish -m <comment>",
                s.id
            ))
        }
    }
}

fn next_cursor(ctx: &mut Ctx<'_>, cursor: Option<&str>) -> Result<()> {
    if let Some(c) = cursor {
        writeln!(ctx.err, "More results: --cursor {c}")?;
    }
    Ok(())
}

/// Poll interval while waiting for installations.
const INSTALL_POLL: Duration = Duration::from_millis(500);

pub async fn install(ctx: &mut Ctx<'_>, a: InstallArgs) -> Result<i32> {
    let c = ctx.client()?;
    let mut gateways = Vec::new();
    for g in &a.gateways {
        gateways.push(c.resolve_gateway(g).await?);
    }
    let res = c
        .install(&InstallRequest {
            revision: a.revision,
            gateways,
        })
        .await?;
    let ids: Vec<Uuid> = res.installs.iter().map(|i| i.id).collect();
    let mut installs = res.installs;
    let deadline = Instant::now() + Duration::from_secs(a.timeout);
    while !a.no_wait
        && installs.iter().any(|i| i.state == InstallState::Pending)
        && Instant::now() < deadline
    {
        tokio::time::sleep(INSTALL_POLL).await;
        let page = c
            .list_installs(&InstallQuery {
                revision: Some(a.revision),
                limit: Some(1000),
                ..Default::default()
            })
            .await?;
        let latest: HashMap<Uuid, _> = page
            .items
            .into_iter()
            .filter(|i| ids.contains(&i.id))
            .map(|i| (i.id, i))
            .collect();
        for i in installs.iter_mut() {
            if let Some(n) = latest.get(&i.id) {
                *i = n.clone();
            }
        }
    }
    let failed = installs
        .iter()
        .filter(|i| i.state == InstallState::Failed)
        .count();
    let pending = installs
        .iter()
        .filter(|i| i.state == InstallState::Pending)
        .count();
    if ctx.json {
        ctx.print_json(&installs)?;
    } else {
        let names = Names::from_pairs(
            c.list_gateways()
                .await
                .unwrap_or_default()
                .into_iter()
                .map(|g| (g.id.to_string(), g.name)),
        );
        table(
            ctx.out,
            &values(&installs)?,
            &[
                colf("GATEWAY", move |v| names.name(&v["gateway_id"])),
                col("REVISION", "/revision"),
                col("STATE", "/state"),
                colf("ACKED", |v| time_cell(v.get("acked_at"))),
                col("ERROR", "/error"),
            ],
        )?;
    }
    if a.no_wait {
        return Ok(0);
    }
    if failed > 0 {
        writeln!(
            ctx.err,
            "error: revision {} failed on {failed} gateway(s)",
            a.revision
        )?;
        return Ok(1);
    }
    if pending > 0 {
        writeln!(
            ctx.err,
            "error: {pending} gateway(s) did not confirm within {} s (offline gateways install on reconnection)",
            a.timeout
        )?;
        return Ok(1);
    }
    Ok(0)
}

// ---------------------------------------------------------------------------------------------
// Gateways

pub async fn gateways(ctx: &mut Ctx<'_>, cmd: GatewaysCmd) -> Result<()> {
    let c = ctx.client()?;
    match cmd {
        GatewaysCmd::List => {
            let items = c.list_gateways().await?;
            if ctx.json {
                return ctx.print_json(&items);
            }
            table(
                ctx.out,
                &values(&items)?,
                &[
                    col("ID", "/id"),
                    col("NAME", "/name"),
                    col("HOSTNAME", "/hostname"),
                    col("STATUS", "/status"),
                    col("DESIRED", "/desired_revision"),
                    col("ACTIVE", "/active_revision"),
                    colf("LAST SEEN", |v| time_cell(v.get("last_seen_at"))),
                    col("VERSION", "/version"),
                ],
            )?;
            Ok(())
        }
        GatewaysCmd::Show { gateway } => {
            let id = c.resolve_gateway(&gateway).await?;
            let g = c.get_gateway(id).await?;
            ctx.print_json(&g)
        }
        GatewaysCmd::Token { name } => {
            let t = c
                .create_registration_token(&CreateRegistrationToken { name })
                .await?;
            if ctx.json {
                return ctx.print_json(&t);
            }
            ctx.say(&format!(
                "Registration token (single use, expires {}):\n{}\nSet it as AFW_REGISTRATION_TOKEN on the gateway.",
                t.expires_at.format("%Y-%m-%d %H:%M:%S UTC"),
                t.token
            ))
        }
        GatewaysCmd::Command { gateway, command } => {
            let id = c.resolve_gateway(&gateway).await?;
            let cmd: GatewayCommand =
                serde_json::from_value(crate::resources::gateway_command(&command))
                    .map_err(|_| anyhow!("unknown command `{command}`"))?;
            c.send_gateway_command(id, &cmd).await?;
            ctx.say(&format!(
                "Command {command} queued for gateway {id} (sent with its next heartbeat)."
            ))
        }
        GatewaysCmd::Delete { gateway } => {
            let id = c.resolve_gateway(&gateway).await?;
            c.delete_gateway(id).await?;
            ctx.say(&format!(
                "Removed gateway {id}; its certificate is revoked."
            ))
        }
    }
}

// ---------------------------------------------------------------------------------------------
// Logs (EF-41)

async fn flow_query(
    c: &AfwClient,
    f: &LogFilter,
    period: &Period,
    q: Option<String>,
    paging: &Paging,
) -> Result<FlowQuery> {
    Ok(FlowQuery {
        agent: opt_resolve(c, PolicyKind::Agents, &f.agent).await?,
        zone: opt_resolve(c, PolicyKind::Zones, &f.zone).await?,
        destination: f.destination.clone(),
        verdict: f
            .verdict
            .as_deref()
            .map(|v| parse_enum::<Verdict>("verdict", v))
            .transpose()?,
        rule: opt_resolve(c, PolicyKind::Rules, &f.rule).await?,
        from: opt_past(&period.from)?,
        to: opt_past(&period.to)?,
        q,
        cursor: paging.cursor.clone(),
        limit: paging.limit,
    })
}

async fn opt_resolve(c: &AfwClient, kind: PolicyKind, s: &Option<String>) -> Result<Option<Uuid>> {
    match s {
        Some(s) => Ok(Some(c.resolve(kind, s).await?)),
        None => Ok(None),
    }
}

async fn agent_names(c: &AfwClient) -> std::rc::Rc<Names> {
    Names::from_pairs(
        c.list_raw(PolicyKind::Agents)
            .await
            .unwrap_or_default()
            .into_iter()
            .filter_map(|v| {
                Some((
                    v.get("id")?.as_str()?.to_string(),
                    v.get("name")?.as_str()?.to_string(),
                ))
            }),
    )
}

fn flow_dest(v: &Value) -> String {
    let host = v
        .get("domain")
        .and_then(Value::as_str)
        .or(v.get("sni").and_then(Value::as_str));
    match host {
        Some(h) => {
            let port = v["dst"]
                .as_str()
                .and_then(|d| d.rsplit_once(':').map(|(_, p)| p.to_string()))
                .unwrap_or_default();
            format!("{h}:{port}")
        }
        None => scalar(v.get("dst")),
    }
}

fn rule_cell(v: &Value) -> String {
    if let Some(l) = v.get("rule_label").and_then(Value::as_str) {
        return l.to_string();
    }
    let d = &v["decision"];
    match d.get("rule_number").and_then(Value::as_u64) {
        Some(n) => format!("#{n} {}", scalar(d.get("rule_name"))),
        None => scalar(d.get("rule_name")),
    }
}

fn flow_cols(agents: std::rc::Rc<Names>) -> Vec<crate::output::Col> {
    vec![
        colf("TIME", |v| time_cell(v.get("started_at"))),
        colf("VERDICT", |v| {
            let verdict = scalar(v.get("verdict"));
            if v["observed"].as_bool() == Some(true) {
                format!("{verdict} (observed)")
            } else {
                verdict
            }
        }),
        colf("AGENT", move |v| {
            match v.get("agent_name").and_then(Value::as_str) {
                Some(n) => n.to_string(),
                None => agents.name(&v["agent_id"]),
            }
        }),
        colf("DESTINATION", flow_dest),
        col("APP", "/app"),
        colf("RULE", rule_cell),
        colf("BYTES OUT/IN", |v| {
            format!(
                "{}/{}",
                scalar(v.get("bytes_out")),
                scalar(v.get("bytes_in"))
            )
        }),
        col("ID", "/id"),
    ]
}

fn alert_event_cols() -> Vec<crate::output::Col> {
    vec![
        colf("TIME", |v| time_cell(v.get("at"))),
        col("SEVERITY", "/severity"),
        col("KIND", "/kind"),
        col("SUMMARY", "/summary"),
        col("ID", "/id"),
    ]
}

pub async fn logs(ctx: &mut Ctx<'_>, cmd: LogsCmd) -> Result<()> {
    let c = ctx.client()?;
    match cmd {
        LogsCmd::Flows {
            filter,
            period,
            q,
            paging,
        } => {
            let query = flow_query(&c, &filter, &period, q, &paging).await?;
            let page = c.list_flows_raw(&query).await?;
            if ctx.json {
                return ctx.print_json(&page);
            }
            let agents = agent_names(&c).await;
            table(ctx.out, &page.items, &flow_cols(agents))?;
            next_cursor(ctx, page.next_cursor.as_deref())
        }
        LogsCmd::Dns {
            filter,
            period,
            q,
            paging,
        } => {
            let query = flow_query(&c, &filter, &period, q, &paging).await?;
            let page = c.list_dns(&query).await?;
            if ctx.json {
                return ctx.print_json(&page);
            }
            let agents = agent_names(&c).await;
            table(
                ctx.out,
                &values(&page.items)?,
                &[
                    colf("TIME", |v| time_cell(v.get("at"))),
                    col("VERDICT", "/verdict"),
                    colf("AGENT", move |v| agents.name(&v["agent_id"])),
                    col("QUERY", "/qname"),
                    col("TYPE", "/qtype"),
                    col("ANSWERS", "/answers"),
                    colf("RULE", rule_cell),
                    col("ID", "/id"),
                ],
            )?;
            next_cursor(ctx, page.next_cursor.as_deref())
        }
        LogsCmd::Stats {
            filter,
            period,
            q,
            bucket,
        } => {
            let query = flow_query(&c, &filter, &period, q, &Paging::default()).await?;
            let st = c.flow_stats(&query, bucket.as_deref()).await?;
            if ctx.json {
                return ctx.print_json(&st);
            }
            kv(
                ctx.out,
                &[
                    (
                        "period",
                        format!(
                            "{} .. {}",
                            time_cell(st.get("from")),
                            time_cell(st.get("to"))
                        ),
                    ),
                    ("bucket", scalar(st.get("bucket"))),
                    ("total", scalar(st.get("total"))),
                    ("allow", scalar(st.get("allow"))),
                    ("deny", scalar(st.get("deny"))),
                    ("observed", scalar(st.get("observed"))),
                ],
            )?;
            let points = st["points"].as_array().cloned().unwrap_or_default();
            writeln!(ctx.out)?;
            table(
                ctx.out,
                &points,
                &[
                    colf("TIME", |v| time_cell(v.get("at"))),
                    col("ALLOW", "/allow"),
                    col("DENY", "/deny"),
                    col("OBSERVED", "/observed"),
                ],
            )?;
            Ok(())
        }
        LogsCmd::Show { flow_id } => {
            let raw = c.get_flow_raw(flow_id).await?;
            if ctx.json {
                return ctx.print_json(&raw);
            }
            let d: afw_core::api::FlowDetail = serde_json::from_value(raw.clone())
                .map_err(|e| anyhow!("unexpected flow detail: {e}"))?;
            let f = serde_json::to_value(&d.flow)?;
            kv(
                ctx.out,
                &[
                    ("flow", d.flow.id.to_string()),
                    ("time", time_cell(f.get("started_at"))),
                    ("verdict", scalar(f.get("verdict"))),
                    ("agent", scalar(f.get("agent_id"))),
                    ("source", scalar(f.get("src"))),
                    ("destination", flow_dest(&f)),
                    ("address", scalar(f.get("dst"))),
                    (
                        "protocol",
                        format!("{} {}", scalar(f.get("protocol")), scalar(f.get("app"))),
                    ),
                    ("rule", rule_cell(&f)),
                    ("reason", scalar(f.pointer("/decision/reason"))),
                    ("revision", scalar(f.pointer("/decision/revision"))),
                    ("tls inspected", scalar(f.get("tls_inspected"))),
                    ("llm provider", scalar(f.get("llm_provider"))),
                    ("internal", scalar(f.get("internal"))),
                    ("data classes", scalar(f.get("data_classes"))),
                    (
                        "bytes out/in",
                        format!("{}/{}", d.flow.bytes_out, d.flow.bytes_in),
                    ),
                ],
            )?;
            if !d.http.is_empty() {
                writeln!(ctx.out, "\nHTTP exchanges:")?;
                table(
                    ctx.out,
                    &values(&d.http)?,
                    &[
                        colf("TIME", |v| time_cell(v.get("at"))),
                        col("METHOD", "/method"),
                        col("URL", "/url"),
                        col("STATUS", "/status"),
                        colf("FINDINGS", |v| {
                            v["findings"]
                                .as_array()
                                .map(|a| {
                                    a.iter()
                                        .map(|f| scalar(f.get("class")))
                                        .collect::<Vec<_>>()
                                        .join(",")
                                })
                                .unwrap_or_default()
                        }),
                    ],
                )?;
            }
            if let Some(t) = &d.tool_call {
                let confidence = d
                    .correlation
                    .as_ref()
                    .map(|c| {
                        scalar(Some(
                            &serde_json::to_value(c.confidence).unwrap_or_default(),
                        ))
                    })
                    .unwrap_or_else(|| "-".into());
                writeln!(ctx.out, "\nTool call ({confidence}):")?;
                kv(
                    ctx.out,
                    &[
                        ("tool", t.tool.clone()),
                        ("agent", t.agent.clone()),
                        ("conversation", t.conversation_id.clone()),
                        ("arguments", t.args_summary.clone()),
                        ("status", t.status.clone().unwrap_or_else(|| "-".into())),
                    ],
                )?;
            }
            if let Some(trace) = raw
                .get("trace")
                .and_then(Value::as_array)
                .filter(|t| !t.is_empty())
            {
                writeln!(ctx.out, "\nRule trace:")?;
                table(
                    ctx.out,
                    trace,
                    &[
                        col("RULE", "/rule_label"),
                        col("LAYER", "/layer"),
                        col("OUTCOME", "/outcome"),
                        col("REASON", "/reason"),
                    ],
                )?;
            }
            if let Some(m) = raw.get("agent_message").and_then(Value::as_str) {
                writeln!(
                    ctx.out,
                    "\nMessage received by the agent:\n{}",
                    crate::output::sanitize(m)
                )?;
            }
            if let Some(p) = raw.get("allow_proposal").filter(|p| p.is_object()) {
                let dests = p["destinations"]
                    .as_array()
                    .map(|a| {
                        a.iter()
                            .map(|d| {
                                format!("{} ({})", scalar(d.get("label")), scalar(d.get("kind")))
                            })
                            .collect::<Vec<_>>()
                            .join(", ")
                    })
                    .unwrap_or_default();
                writeln!(ctx.out, "\nAllow proposal:")?;
                kv(
                    ctx.out,
                    &[
                        ("zone", scalar(p.get("zone_name").or(p.get("zone_id")))),
                        ("destinations", dests),
                        ("service", scalar(p.pointer("/service/label"))),
                        ("rule number", scalar(p.get("rule_number"))),
                    ],
                )?;
            }
            if d.flow.verdict == Verdict::Deny || d.flow.observed {
                writeln!(
                    ctx.out,
                    "\nTo allow it: afw allow {} [--destination exact|wildcard|group]",
                    d.flow.id
                )?;
            }
            Ok(())
        }
        LogsCmd::Tail { filter } => {
            let q = StreamQuery {
                agent: opt_resolve(&c, PolicyKind::Agents, &filter.agent).await?,
                zone: opt_resolve(&c, PolicyKind::Zones, &filter.zone).await?,
                destination: filter.destination.clone(),
                verdict: filter
                    .verdict
                    .as_deref()
                    .map(|v| parse_enum::<Verdict>("verdict", v))
                    .transpose()?,
                rule: opt_resolve(&c, PolicyKind::Rules, &filter.rule).await?,
            };
            let agents = agent_names(&c).await;
            let mut stream = Box::pin(c.stream_logs(&q).await?);
            while let Some(item) = stream.next().await {
                match item {
                    Ok(ev) if ctx.json => {
                        writeln!(ctx.out, "{}", serde_json::to_string(&ev)?)?;
                    }
                    Ok(ev) => {
                        let line = event_line(&ev, &agents);
                        writeln!(ctx.out, "{}", crate::output::sanitize(&line))?;
                    }
                    Err(e) => writeln!(ctx.err, "warning: {e}")?,
                }
                ctx.out.flush()?;
            }
            Ok(())
        }
    }
}

fn event_line(ev: &GatewayEvent, agents: &Names) -> String {
    let v = serde_json::to_value(ev).unwrap_or_default();
    match ev {
        GatewayEvent::Flow(_) => format!(
            "{} flow  {:<5} {} -> {} {} [{}]",
            time_cell(v.get("started_at")),
            scalar(v.get("verdict")),
            agents.name(&v["agent_id"]),
            flow_dest(&v),
            scalar(v.get("app")),
            rule_cell(&v)
        ),
        GatewayEvent::Dns(_) => format!(
            "{} dns   {:<5} {} {} {}",
            time_cell(v.get("at")),
            scalar(v.get("verdict")),
            agents.name(&v["agent_id"]),
            scalar(v.get("qname")),
            scalar(v.get("qtype"))
        ),
        GatewayEvent::Http(_) => format!(
            "{} http  {} {} {} {}",
            time_cell(v.get("at")),
            agents.name(&v["agent_id"]),
            scalar(v.get("method")),
            scalar(v.get("url")),
            scalar(v.get("status"))
        ),
        GatewayEvent::Alert(_) => format!(
            "{} alert {} {} {}",
            time_cell(v.get("at")),
            scalar(v.get("severity")),
            scalar(v.get("kind")),
            scalar(v.get("summary"))
        ),
        GatewayEvent::RuleHits { hits } => format!("rule hits: {}", hits.len()),
    }
}

pub async fn internal_map(ctx: &mut Ctx<'_>, a: MapArgs) -> Result<()> {
    let c = ctx.client()?;
    let q = MapQuery {
        period: a.last.clone(),
        from: opt_past(&a.period.from)?,
        to: opt_past(&a.period.to)?,
        zone: opt_resolve(&c, PolicyKind::Zones, &a.zone).await?,
    };
    let m = c.internal_map(&q).await?;
    if ctx.json {
        return ctx.print_json(&m);
    }
    let labels = Names::from_pairs(m.nodes.iter().map(|n| (n.id.clone(), n.label.clone())));
    ctx.say("Nodes:")?;
    table(
        ctx.out,
        &values(&m.nodes)?,
        &[
            col("ID", "/id"),
            col("LABEL", "/label"),
            col("KIND", "/kind"),
            col("ADDRESS", "/address"),
        ],
    )?;
    ctx.say("\nEdges:")?;
    let (l1, l2) = (labels.clone(), labels);
    table(
        ctx.out,
        &values(&m.edges)?,
        &[
            colf("SOURCE", move |v| l1.name(&v["source"])),
            colf("TARGET", move |v| l2.name(&v["target"])),
            colf("PORT", |v| {
                format!("{}/{}", scalar(v.get("protocol")), scalar(v.get("port")))
            }),
            col("APP", "/app"),
            col("FLOWS", "/flows"),
            col("ALERTS", "/alerts"),
            col("NEW", "/new"),
            colf("LAST SEEN", |v| time_cell(v.get("last_seen_at"))),
        ],
    )?;
    Ok(())
}

// ---------------------------------------------------------------------------------------------
// Alerts, captures

pub async fn alerts(ctx: &mut Ctx<'_>, cmd: AlertsCmd) -> Result<()> {
    let c = ctx.client()?;
    match cmd {
        AlertsCmd::List {
            agent,
            severity,
            acknowledged,
            period,
            paging,
        } => {
            let q = AlertQuery {
                agent: opt_resolve(&c, PolicyKind::Agents, &agent).await?,
                severity: severity
                    .as_deref()
                    .map(|s| parse_enum::<Severity>("severity", s))
                    .transpose()?,
                acknowledged,
                from: opt_past(&period.from)?,
                to: opt_past(&period.to)?,
                cursor: paging.cursor,
                limit: paging.limit,
            };
            let page = c.list_alerts(&q).await?;
            if ctx.json {
                return ctx.print_json(&page);
            }
            let agents = agent_names(&c).await;
            table(
                ctx.out,
                &values(&page.items)?,
                &[
                    colf("TIME", |v| time_cell(v.pointer("/event/at"))),
                    col("SEVERITY", "/event/severity"),
                    col("KIND", "/event/kind"),
                    colf("AGENT", move |v| agents.name(&v["event"]["agent_id"])),
                    col("SUMMARY", "/event/summary"),
                    col("ACK", "/acknowledged"),
                    col("ID", "/event/id"),
                ],
            )?;
            next_cursor(ctx, page.next_cursor.as_deref())
        }
        AlertsCmd::Ack { id } => {
            let a = c.acknowledge_alert(id).await?;
            if ctx.json {
                return ctx.print_json(&a);
            }
            ctx.say(&format!("Acknowledged alert {id}."))
        }
    }
}

pub async fn captures(ctx: &mut Ctx<'_>, cmd: CapturesCmd) -> Result<()> {
    let c = ctx.client()?;
    match cmd {
        CapturesCmd::List { paging } => {
            let page = c
                .list_captures(&PageQuery {
                    cursor: paging.cursor,
                    limit: paging.limit,
                })
                .await?;
            if ctx.json {
                return ctx.print_json(&page);
            }
            let agents = agent_names(&c).await;
            table(
                ctx.out,
                &values(&page.items)?,
                &[
                    col("ID", "/id"),
                    colf("AGENT", move |v| agents.name(&v["agent_id"])),
                    colf("REQUESTED", |v| time_cell(v.get("requested_at"))),
                    col("DURATION", "/duration_secs"),
                    col("STATE", "/state"),
                    col("SIZE", "/size"),
                    col("ERROR", "/error"),
                ],
            )?;
            next_cursor(ctx, page.next_cursor.as_deref())
        }
        CapturesCmd::Start { agent, duration } => {
            let agent_id = c.resolve(PolicyKind::Agents, &agent).await?;
            let cap = c
                .start_capture(&CaptureRequest {
                    agent_id,
                    duration_secs: duration,
                })
                .await?;
            if ctx.json {
                return ctx.print_json(&cap);
            }
            ctx.say(&format!(
                "Capture {} started for {duration} s. Download it with: afw captures download {}",
                cap.id, cap.id
            ))
        }
        CapturesCmd::Show { id } => {
            let cap = c.get_capture(id).await?;
            ctx.print_json(&cap)
        }
        CapturesCmd::Download { id, output } => {
            let data = c.download_capture(id).await?;
            let path = output.unwrap_or_else(|| PathBuf::from(format!("capture-{id}.pcap")));
            // Captures may hold sensitive traffic: owner-only file.
            config::write_private(&path, &data)?;
            ctx.say(&format!(
                "Wrote {} bytes to {}.",
                data.len(),
                path.display()
            ))
        }
    }
}

// ---------------------------------------------------------------------------------------------
// Audit, approvals, tokens

pub async fn audit(ctx: &mut Ctx<'_>, cmd: AuditCmd) -> Result<i32> {
    let c = ctx.client()?;
    match cmd {
        AuditCmd::List {
            from_seq,
            actor,
            action,
            interface,
            period,
            paging,
        } => {
            let page = c
                .list_audit(&AuditQuery {
                    interface: interface
                        .as_deref()
                        .map(|i| parse_enum("interface", i))
                        .transpose()?,
                    from_seq,
                    actor,
                    action,
                    from: opt_past(&period.from)?,
                    to: opt_past(&period.to)?,
                    cursor: paging.cursor,
                    limit: paging.limit,
                })
                .await?;
            if ctx.json {
                ctx.print_json(&page)?;
                return Ok(0);
            }
            table(
                ctx.out,
                &values(&page.items)?,
                &[
                    col("SEQ", "/seq"),
                    colf("TIME", |v| time_cell(v.get("at"))),
                    col("ACTOR", "/actor/name"),
                    col("INTERFACE", "/interface"),
                    col("ACTION", "/action"),
                    col("TARGET", "/target"),
                    col("SESSION", "/session_id"),
                ],
            )?;
            next_cursor(ctx, page.next_cursor.as_deref())?;
            Ok(0)
        }
        AuditCmd::Verify => {
            let r = c.verify_audit().await?;
            if ctx.json {
                ctx.print_json(&r)?;
            } else if r.ok {
                ctx.say(&format!(
                    "Audit chain intact: {} entries checked, head seq {} hash {}.",
                    r.checked,
                    r.head_seq.map_or("-".into(), |s| s.to_string()),
                    r.head_hash.as_deref().unwrap_or("-")
                ))?;
            } else {
                writeln!(
                    ctx.err,
                    "error: audit chain BROKEN at seq {}",
                    r.broken_at.map_or("?".into(), |s| s.to_string())
                )?;
            }
            Ok(if r.ok { 0 } else { 1 })
        }
        AuditCmd::Export { from_seq, output } => {
            let data = c.export_audit(from_seq).await?;
            let mut entries = Vec::new();
            for (i, line) in data.split(|b| *b == b'\n').enumerate() {
                if line.iter().all(u8::is_ascii_whitespace) {
                    continue;
                }
                let e: AuditEntry = serde_json::from_slice(line)
                    .with_context(|| format!("export line {} is not an audit entry", i + 1))?;
                entries.push(e);
            }
            match &output {
                Some(p) => std::fs::write(p, &data)
                    .with_context(|| format!("cannot write {}", p.display()))?,
                None => ctx.out.write_all(&data)?,
            }
            let chain = afw_core::audit::verify_chain(&entries);
            let genesis_ok = from_seq.is_some()
                || entries
                    .first()
                    .is_none_or(|e| e.prev_hash == afw_core::audit::GENESIS_HASH);
            match (chain, genesis_ok) {
                (Ok(()), true) => {
                    writeln!(
                        ctx.err,
                        "Exported {} entries; hash chain verified locally.",
                        entries.len()
                    )?;
                    Ok(0)
                }
                (Err(e), _) => {
                    writeln!(ctx.err, "error: exported log fails local verification: {e}")?;
                    Ok(1)
                }
                (Ok(()), false) => {
                    writeln!(
                        ctx.err,
                        "error: the first exported entry does not start the chain"
                    )?;
                    Ok(1)
                }
            }
        }
    }
}

pub async fn approvals(ctx: &mut Ctx<'_>, cmd: ApprovalsCmd) -> Result<()> {
    let c = ctx.client()?;
    match cmd {
        ApprovalsCmd::List { status } => {
            let status = status
                .as_deref()
                .map(|s| parse_enum::<ApprovalStatus>("status", s))
                .transpose()?;
            let items = c.list_approvals(status).await?;
            if ctx.json {
                return ctx.print_json(&items);
            }
            table(
                ctx.out,
                &values(&items)?,
                &[
                    col("ID", "/id"),
                    colf("REQUESTED", |v| time_cell(v.get("requested_at"))),
                    col("BY", "/requested_by/name"),
                    col("STATUS", "/status"),
                    col("SUMMARY", "/summary"),
                    col("REASON", "/reason"),
                    col("SESSION", "/session_id"),
                ],
            )?;
            Ok(())
        }
        ApprovalsCmd::Show { id } => {
            let a = c.get_approval(id).await?;
            ctx.print_json(&a)
        }
        ApprovalsCmd::Approve { id, message } => decide(ctx, &c, id, true, message).await,
        ApprovalsCmd::Reject { id, message } => decide(ctx, &c, id, false, message).await,
    }
}

async fn decide(
    ctx: &mut Ctx<'_>,
    c: &AfwClient,
    id: Uuid,
    approve: bool,
    comment: Option<String>,
) -> Result<()> {
    let a = c
        .decide_approval(id, &ApprovalDecision { approve, comment })
        .await?;
    if ctx.json {
        return ctx.print_json(&a);
    }
    let status = scalar(Some(&serde_json::to_value(a.status)?));
    ctx.say(&format!("Approval {id}: {status}."))
}

pub async fn tokens(ctx: &mut Ctx<'_>, cmd: TokensCmd) -> Result<()> {
    let c = ctx.client()?;
    match cmd {
        TokensCmd::List => {
            let items = c.list_tokens().await?;
            if ctx.json {
                return ctx.print_json(&items);
            }
            table(
                ctx.out,
                &values(&items)?,
                &[
                    col("ID", "/id"),
                    col("NAME", "/name"),
                    col("ROLE", "/role"),
                    col("AGENT", "/agent_id"),
                    colf("CREATED", |v| time_cell(v.get("created_at"))),
                    colf("EXPIRES", |v| time_cell(v.get("expires_at"))),
                    colf("LAST USED", |v| time_cell(v.get("last_used_at"))),
                ],
            )?;
            Ok(())
        }
        TokensCmd::Create {
            name,
            role,
            agent,
            expires,
        } => {
            let role: Role = parse_enum("role", &role)?;
            let agent_id = opt_resolve(&c, PolicyKind::Agents, &agent).await?;
            let expires_at = expires.as_deref().map(parse_future).transpose()?;
            let t = c
                .create_token(&CreateApiToken {
                    name,
                    role,
                    agent_id,
                    expires_at,
                })
                .await?;
            if ctx.json {
                return ctx.print_json(&t);
            }
            ctx.say(&format!(
                "Created token {} ({}). Secret (shown once, store it now):\n{}",
                t.token.name, t.token.id, t.secret
            ))
        }
        TokensCmd::Revoke { id } => {
            c.revoke_token(id).await?;
            ctx.say(&format!("Revoked token {id}."))
        }
    }
}

// ---------------------------------------------------------------------------------------------
// Rule base, intent policy

pub async fn rulebase(ctx: &mut Ctx<'_>) -> Result<()> {
    let c = ctx.client()?;
    if c.session().is_none()
        && let Some(s) = c.open_session_of_caller().await?
    {
        c.set_session(Some(s.id));
    }
    let rb = c.get_rulebase().await?;
    if ctx.json {
        return ctx.print_json(&rb);
    }
    let names = Names::load(&c, PolicyKind::Rules).await?;
    let sections = |layer: &Value| layer["sections"].as_array().cloned().unwrap_or_default();
    let mut layers = vec![("Baseline".to_string(), sections(&rb["baseline"]), None)];
    for z in rb["zones"].as_array().cloned().unwrap_or_default() {
        layers.push((
            format!(
                "Zone {} ({})",
                scalar(z.pointer("/zone/name")),
                scalar(z.get("mode"))
            ),
            sections(&z),
            z.get("cleanup_number").cloned(),
        ));
    }
    for (title, secs, cleanup) in layers {
        writeln!(ctx.out, "{title}")?;
        for sec in secs {
            if let Some(n) = sec.get("name").and_then(Value::as_str) {
                writeln!(ctx.out, "  [{}]", crate::output::sanitize(n))?;
            }
            let rules = sec["rules"].as_array().cloned().unwrap_or_default();
            let (n1, n2, n3) = (names.clone(), names.clone(), names.clone());
            table(
                ctx.out,
                &rules,
                &[
                    col("NO", "/number"),
                    col("NAME", "/name"),
                    colf("SOURCES", move |v| n1.list(v.get("sources"), "all zones")),
                    colf("DESTINATIONS", move |v| {
                        n2.list(v.get("destinations"), "any")
                    }),
                    colf("SERVICES", move |v| n3.list(v.get("services"), "any")),
                    col("ACTION", "/action"),
                    col("HITS", "/hits"),
                    col("PENDING", "/pending_change"),
                    col("ID", "/id"),
                ],
            )?;
        }
        if let Some(n) = cleanup {
            writeln!(ctx.out, "{}  cleanup: deny everything", scalar(Some(&n)))?;
        }
        writeln!(ctx.out)?;
    }
    Ok(())
}

pub async fn intent_policy(ctx: &mut Ctx<'_>, cmd: IntentPolicyCmd) -> Result<()> {
    let c = ctx.client()?;
    match cmd {
        IntentPolicyCmd::Show => {
            let p = c.intent_policy().await?;
            if ctx.json {
                return ctx.print_json(&p);
            }
            ctx.say(&format!("Intent policy version {}:", p.version))?;
            table(
                ctx.out,
                &values(&p.action_classes)?,
                &[
                    col("ID", "/id"),
                    col("NAME", "/name"),
                    col("DECISION", "/decision"),
                    col("TOOLS", "/tools"),
                    col("PATTERNS", "/patterns"),
                ],
            )?;
            Ok(())
        }
        IntentPolicyCmd::Set { file } => {
            let text = crate::resources::read_input(&file)?;
            let mut v: Value = serde_yaml::from_str(&text)
                .with_context(|| format!("{} is not valid JSON or YAML", file.display()))?;
            if let Some(o) = v.as_object_mut() {
                o.entry("version").or_insert(json!(0));
            }
            let p: afw_core::api::IntentPolicy =
                serde_json::from_value(v).map_err(|e| anyhow!("invalid intent policy: {e}"))?;
            let saved = c.update_intent_policy(&p).await?;
            if ctx.json {
                return ctx.print_json(&saved);
            }
            ctx.say(&format!(
                "Intent policy saved as version {}.",
                saved.version
            ))
        }
    }
}

// ---------------------------------------------------------------------------------------------
// Import

pub async fn import(ctx: &mut Ctx<'_>, cmd: ImportCmd) -> Result<i32> {
    let ImportCmd::EgressGuard {
        file,
        zone,
        mode,
        downgrade,
        apply,
        force,
        intent_policy,
    } = cmd;
    let yaml = crate::resources::read_input(&file)?;
    let c = ctx.client()?;
    // The plan reuses what already exists: read the policy as your session sees it.
    if c.session().is_none()
        && let Some(s) = c.open_session_of_caller().await?
    {
        c.set_session(Some(s.id));
    }
    let existing = c.draft_document().await?;
    let mut opts = afw_import::ImportOptions::new(zone);
    opts.zone_mode = parse_enum("zone mode", &mode)?;
    opts.existing = Some(&existing);
    opts.downgrade = downgrade;
    let plan =
        afw_import::import(&yaml, &opts).map_err(|e| anyhow!("egress-guard import failed: {e}"))?;
    if ctx.json && !apply {
        ctx.print_json(&plan)?;
        return Ok(0);
    }
    if !ctx.json {
        write!(ctx.out, "{}", plan.report.to_markdown())?;
    }
    if !apply {
        writeln!(
            ctx.err,
            "Report only: rerun with --apply to merge the plan into your session."
        )?;
        return Ok(0);
    }
    if !plan.is_safe() && !force {
        writeln!(
            ctx.err,
            "error: the plan does not enforce every deny/gate of the source (see the blocking items of the report); \
             review it, then rerun with --force to apply anyway"
        )?;
        return Ok(1);
    }
    let session = ctx.session().await?;
    let s = c
        .import_document(session, &serde_json::to_value(plan.to_policy_fragment())?)
        .await?;
    let intent = if intent_policy {
        Some(c.update_intent_policy(&plan.intent_policy).await?)
    } else {
        None
    };
    if ctx.json {
        ctx.print_json(&json!({ "plan": plan, "session": s, "intent_policy": intent }))?;
        return Ok(0);
    }
    ctx.say(&format!(
        "Imported into session {} ({} pending changes). Review, then: afw session publish -m <comment>",
        s.id, s.changes
    ))?;
    if let Some(p) = intent {
        ctx.say(&format!("Intent policy replaced (version {}).", p.version))?;
    }
    Ok(0)
}
