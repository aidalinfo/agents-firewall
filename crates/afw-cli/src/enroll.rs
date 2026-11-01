//! `afw enroll` / `afw unenroll` (EF-60, EF-64): network transformation by `afw-enroll`, agent
//! creation by `POST /enrollments` in the caller's session.
//!
//! Order (ADR 0025): the local transformation runs first (it validates everything and fails
//! before any change); then the API creates the agent in the session; then the infrastructure
//! is changed (compose file written, Coolify updated, manifest written). If the infrastructure
//! step fails, the agent is removed from the session again (other pending changes are kept).

use std::net::IpAddr;
use std::path::{Path, PathBuf};

use afw_client::{AfwClient, PolicyKind, PublishOutcome};
use afw_core::api::EnrollmentRequest;
use afw_core::policy::AgentKind;
use afw_enroll::{
    CoolifyClient, CoolifyKind, EnrollSpec, EnrollWarning, HermesSpec, K8sSpec, docker_run_args,
    enroll_compose, enroll_coolify, k8s_manifests, netinit_run_args, patch_pod_template,
    unenroll_compose, unenroll_coolify, validate_agent_name,
};
use anyhow::{Context, Result, anyhow, bail};
use serde_json::json;
use uuid::Uuid;

use crate::Ctx;
use crate::cli::{EnrollArgs, UnenrollArgs};
use crate::config::write_private;

/// What the local transformation produced.
enum Prepared {
    Compose {
        path: PathBuf,
        yaml: String,
    },
    Coolify,
    K8s {
        yaml: String,
    },
    Container {
        netinit: Vec<String>,
        run: Vec<String>,
    },
}

fn token_env_name(agent: &str) -> String {
    let up: String = agent
        .chars()
        .map(|c| {
            if c.is_ascii_alphanumeric() {
                c.to_ascii_uppercase()
            } else {
                '_'
            }
        })
        .collect();
    format!("AFW_TOKEN_{up}")
}

fn console_url(ctx: &Ctx<'_>, a: &EnrollArgs) -> Option<String> {
    a.console_url
        .clone()
        .or_else(|| ctx.url_override())
        .or_else(|| ctx.config.url.clone())
}

fn parse_ip(what: &str, s: &str) -> Result<IpAddr> {
    s.parse()
        .map_err(|_| anyhow!("invalid {what} `{s}`: expected an IP address"))
}

fn spec(ctx: &Ctx<'_>, a: &EnrollArgs, agent: &str) -> Result<EnrollSpec> {
    let ip = a
        .ip
        .as_deref()
        .ok_or_else(|| anyhow!("--ip <address> is required: the agent's fixed address on the gateway network (e.g. 10.77.0.10)"))?;
    let gateway_ip = parse_ip("--gateway-ip", &a.gateway_ip)?;
    let proxy_url = a.proxy_url.clone().unwrap_or_else(|| match gateway_ip {
        IpAddr::V4(g) => format!("http://{g}:3128"),
        IpAddr::V6(g) => format!("http://[{g}]:3128"),
    });
    let hermes = if a.hermes {
        Some(HermesSpec {
            console_url: console_url(ctx, a)
                .ok_or_else(|| anyhow!("--hermes needs the console URL (--console-url)"))?,
            agent_token_env: a.token_env.clone().unwrap_or_else(|| token_env_name(agent)),
            plugin_dir_host: a.hermes_plugin_dir.clone(),
            plugin_dir_container: None,
        })
    } else {
        None
    };
    let s = EnrollSpec {
        agent_name: agent.to_string(),
        service: a.target.clone(),
        gateway_ip,
        agent_ip: parse_ip("--ip", ip)?,
        network: a.network.clone(),
        proxy_url,
        ca_path_host: a.ca_path.clone(),
        hermes,
        netinit_image: a.netinit_image.clone(),
    };
    s.validate()?;
    Ok(s)
}

fn print_warnings(ctx: &mut Ctx<'_>, warnings: &[EnrollWarning]) -> Result<()> {
    for w in warnings {
        writeln!(ctx.err, "warning: {w}")?;
    }
    Ok(())
}

fn shell_line(args: &[String]) -> String {
    args.iter()
        .map(|a| {
            if a.chars()
                .all(|c| c.is_ascii_alphanumeric() || "-_./:=,@".contains(c))
            {
                a.clone()
            } else {
                format!("'{}'", a.replace('\'', "'\\''"))
            }
        })
        .collect::<Vec<_>>()
        .join(" ")
}

pub async fn enroll(ctx: &mut Ctx<'_>, a: EnrollArgs) -> Result<()> {
    let agent = a.name.clone().unwrap_or_else(|| a.target.clone());
    validate_agent_name(&agent)?;
    let kind = if a.compose.is_some() {
        AgentKind::DockerCompose
    } else if a.coolify.is_some() {
        AgentKind::Coolify
    } else if a.k8s.is_some() {
        AgentKind::Kubernetes
    } else {
        AgentKind::Container
    };

    // 1. Local transformation: validates everything before any change.
    let mut warnings = Vec::new();
    let mut enroll_spec = None;
    let prepared = match kind {
        AgentKind::DockerCompose => {
            let path = a.compose.clone().expect("compose");
            let yaml = std::fs::read_to_string(&path)
                .with_context(|| format!("cannot read {}", path.display()))?;
            let s = spec(ctx, &a, &agent)?;
            let out = enroll_compose(&yaml, &s)?;
            warnings = out.warnings;
            enroll_spec = Some(s);
            Prepared::Compose {
                path: a.output.clone().unwrap_or(path),
                yaml: out.yaml,
            }
        }
        AgentKind::Coolify => {
            enroll_spec = Some(spec(ctx, &a, &agent)?);
            Prepared::Coolify
        }
        AgentKind::Kubernetes => {
            let path = a.k8s.clone().expect("k8s");
            let yaml = std::fs::read_to_string(&path)
                .with_context(|| format!("cannot read {}", path.display()))?;
            let namespace = a.namespace.clone().unwrap_or_else(|| {
                serde_yaml::from_str::<serde_yaml::Value>(&yaml)
                    .ok()
                    .and_then(|d| {
                        d.get("metadata")?
                            .get("namespace")?
                            .as_str()
                            .map(str::to_string)
                    })
                    .unwrap_or_else(|| "default".into())
            });
            let cluster_ip = parse_ip(
                "--gateway-cluster-ip",
                a.gateway_cluster_ip.as_deref().ok_or_else(|| {
                    anyhow!("--gateway-cluster-ip is required with --k8s (fixed ClusterIP of the gateway Service)")
                })?,
            )?;
            let url = console_url(ctx, &a)
                .ok_or_else(|| anyhow!("--k8s needs the console URL (--console-url)"))?;
            let ks = K8sSpec::new(
                namespace,
                a.gateway_image.clone(),
                cluster_ip,
                url,
                a.registration_secret.clone(),
            );
            let out = patch_pod_template(&yaml, &ks, &agent)?;
            warnings = out.warnings;
            let mut docs = Vec::new();
            if a.with_gateway {
                for m in k8s_manifests(&ks)? {
                    docs.push(serde_yaml::to_string(&m)?);
                }
            }
            docs.push(out.yaml);
            Prepared::K8s {
                yaml: docs.join("---\n"),
            }
        }
        AgentKind::Container => {
            let s = spec(ctx, &a, &agent)?;
            let p = Prepared::Container {
                netinit: netinit_run_args(&s),
                run: docker_run_args(&s),
            };
            enroll_spec = Some(s);
            p
        }
    };
    print_warnings(ctx, &warnings)?;

    if a.dry_run {
        match &prepared {
            Prepared::Compose { yaml, .. } | Prepared::K8s { yaml } => write!(ctx.out, "{yaml}")?,
            Prepared::Coolify => ctx.say(&format!(
                "Would enroll service {} of Coolify resource {} (compose file read from Coolify).",
                a.target,
                a.coolify.as_deref().unwrap_or_default()
            ))?,
            Prepared::Container { netinit, run } => {
                ctx.say(&format!("docker {}", shell_line(netinit)))?;
                ctx.say(&format!("docker run {} <image> [command]", shell_line(run)))?;
            }
        }
        return Ok(());
    }

    // 2. API: create the agent in the session.
    let c = ctx.client()?;
    ctx.session().await?;
    let zone_id = c.resolve(PolicyKind::Zones, &a.zone).await?;
    let gateway_id = match &a.gateway {
        Some(g) => c.resolve_gateway(g).await?,
        None => {
            let gws = c.list_gateways().await?;
            match gws.as_slice() {
                [g] => g.id,
                [] => bail!("no gateway is registered: register one first (afw gateways token)"),
                _ => bail!("several gateways are registered: choose one with --gateway"),
            }
        }
    };
    let enrollment = c
        .enroll(&EnrollmentRequest {
            name: agent.clone(),
            zone_id,
            kind,
            gateway_id,
            hermes: a.hermes,
        })
        .await?;
    c.set_session(Some(enrollment.session_id));
    let agent_id = enrollment.agent.id;
    if let Some(s) = &enroll_spec
        && !enrollment.agent.addresses.contains(&s.agent_ip)
    {
        let mut ag = enrollment.agent.clone();
        ag.addresses.push(s.agent_ip);
        c.update_agent(&ag).await?;
    }

    // 3. Infrastructure.
    let infra = apply_infra(ctx, &a, &prepared, enroll_spec.as_ref()).await;
    if let Err(e) = infra {
        // Undo the agent creation only (other changes of the session are kept).
        let undo = c.delete_agent(agent_id).await;
        let note = match undo {
            Ok(()) => "the agent was removed from the session again".to_string(),
            Err(u) => format!("removing the agent from the session failed too: {u}"),
        };
        return Err(e.context(format!("enrollment of {agent} failed ({note})")));
    }

    // 4. Hermes plugin token (shown once by the API).
    let mut token_shown = None;
    if let Some(token) = &enrollment.plugin_token {
        let var = enroll_spec
            .as_ref()
            .and_then(|s| s.hermes.as_ref())
            .map(|h| h.agent_token_env.clone())
            .unwrap_or_else(|| token_env_name(&agent));
        match &a.env_file {
            Some(f) => {
                set_env_line(f, &var, token)?;
                writeln!(
                    ctx.err,
                    "Hermes plugin token written to {} ({var}).",
                    f.display()
                )?;
            }
            None => token_shown = Some((var, token.clone())),
        }
    }

    // 5. Publish on request.
    let session = enrollment.session_id;
    let published = match &a.publish {
        Some(comment) => Some(c.publish_session(session, comment).await?),
        None => None,
    };

    if ctx.json {
        return ctx.print_json(&json!({
            "agent": enrollment.agent,
            "session_id": session,
            "plugin_token": token_shown.as_ref().map(|(_, t)| t),
            "published": published,
            "warnings": warnings.iter().map(ToString::to_string).collect::<Vec<_>>(),
        }));
    }
    ctx.say(&format!(
        "Enrolled {agent} ({agent_id}) in zone {} on gateway {gateway_id}, session {session}.",
        a.zone
    ))?;
    if let Some((var, token)) = token_shown {
        ctx.say(&format!(
            "Hermes plugin token (shown once): export {var}={token}\n(or rerun with --env-file to write it to a .env file)"
        ))?;
    }
    after_publish(ctx, published)
}

fn after_publish(ctx: &mut Ctx<'_>, published: Option<PublishOutcome>) -> Result<()> {
    match published {
        None => {
            ctx.say("Next: afw session publish -m <comment>, then afw install <revision> --all")
        }
        Some(PublishOutcome::Published { revision }) => ctx.say(&format!(
            "Published revision {}. Next: afw install {} --all",
            revision.number, revision.number
        )),
        Some(PublishOutcome::PendingApproval { approval }) => ctx.say(&format!(
            "Publication waits for approval {} ({}).",
            approval.id, approval.reason
        )),
    }
}

async fn apply_infra(
    ctx: &mut Ctx<'_>,
    a: &EnrollArgs,
    prepared: &Prepared,
    spec: Option<&EnrollSpec>,
) -> Result<()> {
    match prepared {
        Prepared::Compose { path, yaml } => {
            write_atomic(path, yaml.as_bytes())?;
            writeln!(ctx.err, "Wrote {}.", path.display())?;
            if a.apply {
                docker_compose_up(ctx, path)?;
            }
        }
        Prepared::Coolify => {
            let client = coolify_client(ctx, a.coolify_url.as_deref())?;
            let ck = if a.coolify_service {
                CoolifyKind::Service
            } else {
                CoolifyKind::Application
            };
            let uuid = a.coolify.as_deref().expect("coolify");
            let out = enroll_coolify(&client, ck, uuid, spec.expect("spec")).await?;
            print_warnings(ctx, &out.warnings)?;
            writeln!(ctx.err, "Coolify resource {uuid} updated and restarted.")?;
        }
        Prepared::K8s { yaml } => match &a.output {
            Some(p) => {
                write_atomic(p, yaml.as_bytes())?;
                writeln!(
                    ctx.err,
                    "Wrote {} (apply it with kubectl apply -f).",
                    p.display()
                )?;
            }
            None => write!(ctx.out, "{yaml}")?,
        },
        Prepared::Container { netinit, run } => {
            ctx.say("Start the agent with:")?;
            ctx.say(&format!("  docker {}", shell_line(netinit)))?;
            ctx.say(&format!(
                "  docker run {} <image> [command]",
                shell_line(run)
            ))?;
        }
    }
    Ok(())
}

fn coolify_client(ctx: &Ctx<'_>, url: Option<&str>) -> Result<CoolifyClient> {
    let url = url.ok_or_else(|| anyhow!("--coolify-url (or AFW_COOLIFY_URL) is required"))?;
    let token = ctx.coolify_token.clone().ok_or_else(|| {
        anyhow!("set AFW_COOLIFY_TOKEN (Coolify API token with read:sensitive and write)")
    })?;
    Ok(CoolifyClient::new(url, token)?)
}

fn docker_compose_up(ctx: &mut Ctx<'_>, file: &Path) -> Result<()> {
    let args = [
        "compose".to_string(),
        "-f".into(),
        file.display().to_string(),
        "up".into(),
        "-d".into(),
    ];
    writeln!(ctx.err, "Running: {} {}", ctx.docker, shell_line(&args))?;
    let status = std::process::Command::new(&ctx.docker)
        .args(&args)
        .status()
        .with_context(|| format!("cannot run {}", ctx.docker))?;
    if !status.success() {
        bail!("`{} compose up -d` failed ({status})", ctx.docker);
    }
    Ok(())
}

fn write_atomic(path: &Path, data: &[u8]) -> Result<()> {
    crate::config::write_atomic(path, data, None)
}

/// Sets `VAR=value` in a .env file (other lines kept), mode 0600.
fn set_env_line(path: &Path, var: &str, value: &str) -> Result<()> {
    let existing = std::fs::read_to_string(path).unwrap_or_default();
    let mut lines: Vec<String> = existing
        .lines()
        .filter(|l| !l.trim_start().starts_with(&format!("{var}=")))
        .map(str::to_string)
        .collect();
    lines.push(format!("{var}={value}"));
    write_private(path, format!("{}\n", lines.join("\n")).as_bytes())
}

pub async fn unenroll(ctx: &mut Ctx<'_>, a: UnenrollArgs) -> Result<()> {
    validate_agent_name(&a.agent)?;
    if let Some(path) = &a.compose {
        let yaml = std::fs::read_to_string(path)
            .with_context(|| format!("cannot read {}", path.display()))?;
        let restored = unenroll_compose(&yaml, &a.agent)?;
        write_atomic(path, restored.as_bytes())?;
        writeln!(ctx.err, "Restored {}.", path.display())?;
        if a.apply {
            docker_compose_up(ctx, path)?;
        }
    } else if let Some(uuid) = &a.coolify {
        let client = coolify_client(ctx, a.coolify_url.as_deref())?;
        let ck = if a.coolify_service {
            CoolifyKind::Service
        } else {
            CoolifyKind::Application
        };
        unenroll_coolify(&client, ck, uuid, &a.agent).await?;
        writeln!(ctx.err, "Coolify resource {uuid} restored and restarted.")?;
    }
    if a.keep_agent {
        return ctx.say(&format!(
            "Unenrolled {} (agent kept in the policy).",
            a.agent
        ));
    }
    let c: AfwClient = ctx.client()?;
    let session = ctx.session().await?;
    let id: Uuid = c.resolve(PolicyKind::Agents, &a.agent).await?;
    c.delete_agent(id).await?;
    let published = match &a.publish {
        Some(comment) => Some(c.publish_session(session, comment).await?),
        None => None,
    };
    if ctx.json {
        return ctx.print_json(
            &json!({"deleted_agent": id, "session_id": session, "published": published}),
        );
    }
    ctx.say(&format!(
        "Unenrolled {} and deleted agent {id} in session {session}.",
        a.agent
    ))?;
    after_publish(ctx, published)
}
