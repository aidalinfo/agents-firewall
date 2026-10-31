//! `afw` command-line interface (lot L8): library part, so the commands can be tested
//! in-process against a fake API. The binary (`main.rs`) only wires stdio and the process
//! environment.

pub mod cli;
mod commands;
pub mod config;
mod enroll;
pub mod output;
mod resources;
pub mod util;

use std::ffi::OsString;
use std::io::{Read, Write};
use std::path::PathBuf;

use afw_client::{AfwClient, ClientError, ClientOptions, PolicyKind};
use afw_core::events::Interface;
use anyhow::{Context, Result, anyhow};
use clap::Parser;
use uuid::Uuid;

use crate::cli::{
    AgentsCmd, AlertChannelsCmd, Cli, Command, ConfigCmd, DataClassesCmd, InspectionRulesCmd,
    ObjectsCmd, RulesCmd, ServicesCmd, ZonesCmd,
};
use crate::config::Config;
use crate::resources::KindArgs;

/// Process environment and streams, injectable for tests.
pub struct Io<'a> {
    pub out: &'a mut dyn Write,
    pub err: &'a mut dyn Write,
    pub stdin: &'a mut dyn Read,
    /// `AFW_TOKEN`.
    pub env_token: Option<String>,
    /// `AFW_COOLIFY_TOKEN`.
    pub coolify_token: Option<String>,
    /// Docker executable used by `--apply` (`AFW_DOCKER`, default `docker`).
    pub docker: String,
}

/// Execution context of a command.
pub struct Ctx<'a> {
    pub out: &'a mut dyn Write,
    pub err: &'a mut dyn Write,
    pub json: bool,
    pub config: Config,
    pub config_path: PathBuf,
    url: Option<String>,
    ca_cert: Option<PathBuf>,
    session: Option<Uuid>,
    token: Option<String>,
    client: Option<AfwClient>,
    pub coolify_token: Option<String>,
    pub docker: String,
}

impl Ctx<'_> {
    /// The API client (built on first use from flags, environment and configuration).
    pub fn client(&mut self) -> Result<AfwClient> {
        if let Some(c) = &self.client {
            return Ok(c.clone());
        }
        let url = self
            .url
            .clone()
            .or_else(|| self.config.url.clone())
            .ok_or_else(|| anyhow!("no console URL: run `afw login --url <url>` or set AFW_URL"))?;
        let token = self
            .token
            .clone()
            .or_else(|| self.config.token.clone())
            .ok_or_else(|| anyhow!("no API token: run `afw login` or set AFW_TOKEN"))?;
        let ca = self
            .ca_cert
            .clone()
            .or_else(|| self.config.ca_cert.clone().map(PathBuf::from));
        let ca_cert_pem = match ca {
            Some(p) => Some(
                std::fs::read(&p).with_context(|| format!("cannot read CA certificate {}", p.display()))?,
            ),
            None => None,
        };
        let c = AfwClient::with_options(
            &url,
            token,
            Interface::Cli,
            ClientOptions {
                ca_cert_pem,
                timeout: None,
            },
        )?;
        c.set_session(self.session);
        self.client = Some(c.clone());
        Ok(c)
    }

    /// The editing session for a change: `--session`, else your open session, else a new one.
    pub async fn session(&mut self) -> Result<Uuid> {
        let c = self.client()?;
        if let Some(s) = c.session() {
            return Ok(s);
        }
        if let Some(s) = c.current_session().await? {
            c.set_session(Some(s.id));
            return Ok(s.id);
        }
        let s = c.open_session(None).await?;
        writeln!(self.err, "Opened editing session {}.", s.id)?;
        Ok(s.id)
    }

    pub fn url_override(&self) -> Option<String> {
        self.url.clone()
    }

    pub fn ca_cert_override(&self) -> Option<PathBuf> {
        self.ca_cert.clone()
    }

    pub fn token_override(&self) -> Option<String> {
        self.token.clone()
    }

    pub fn print_json(&mut self, v: &impl serde::Serialize) -> Result<()> {
        output::json(self.out, v)?;
        Ok(())
    }

    pub fn say(&mut self, line: &str) -> Result<()> {
        writeln!(self.out, "{line}")?;
        Ok(())
    }
}

/// Runs `afw` with `args` (including the program name); returns the exit code.
pub async fn run(args: impl IntoIterator<Item = OsString>, io: Io<'_>) -> i32 {
    let cli = match Cli::try_parse_from(args) {
        Ok(c) => c,
        Err(e) => {
            let code = e.exit_code();
            let text = e.render().to_string();
            let _ = if code == 0 {
                write!(io.out, "{text}")
            } else {
                write!(io.err, "{text}")
            };
            return code;
        }
    };
    let Io {
        out,
        err,
        stdin,
        env_token,
        coolify_token,
        docker,
    } = io;
    let config_path = match cli.config.clone().or_else(config::default_path) {
        Some(p) => p,
        None => {
            let _ = writeln!(err, "error: cannot locate the configuration file: set AFW_CONFIG or HOME");
            return 1;
        }
    };
    let config = match Config::load(&config_path) {
        Ok(c) => c,
        Err(e) => {
            let _ = writeln!(err, "error: {e:#}");
            return 1;
        }
    };
    if config.token.is_some()
        && let Some(w) = config::check_permissions(&config_path)
    {
        let _ = writeln!(err, "{w}");
    }
    let mut ctx = Ctx {
        out,
        err,
        json: cli.json,
        config,
        config_path,
        url: cli.url.clone(),
        ca_cert: cli.ca_cert.clone(),
        session: cli.session,
        token: env_token.filter(|t| !t.trim().is_empty()),
        client: None,
        coolify_token,
        docker,
    };
    match dispatch(&mut ctx, cli.command, stdin).await {
        Ok(code) => code,
        Err(e) => {
            let _ = writeln!(ctx.err, "error: {}", error_text(&e));
            1
        }
    }
}

/// Error message, with a hint for the API refusals an operator meets most.
pub fn error_text(e: &anyhow::Error) -> String {
    let mut s = format!("{e:#}");
    if let Some(ce) = e.downcast_ref::<ClientError>() {
        match ce.status() {
            Some(401) => s.push_str("\nhint: the token is missing, invalid or expired (`afw login`)."),
            Some(403) => s.push_str("\nhint: your role or delegation does not allow this action."),
            Some(423) => s.push_str("\nhint: another session holds a lock on this resource."),
            _ => {}
        }
    }
    s
}

macro_rules! crud {
    ($ctx:expr, $cmd:expr, $enum:ident, $kind:expr, $variant:ident $(, $extra:pat => $body:expr)*) => {
        match $cmd {
            $enum::List => resources::list($ctx, $kind).await,
            $enum::Show { id } => resources::show($ctx, $kind, &id).await,
            $enum::Create { file, args } => {
                resources::create($ctx, $kind, &file, KindArgs::$variant(args)).await
            }
            $enum::Update { id, file, args } => {
                resources::update($ctx, $kind, &id, &file, KindArgs::$variant(args)).await
            }
            $enum::Delete { id } => resources::delete($ctx, $kind, &id).await,
            $($extra => $body,)*
        }
    };
}

async fn dispatch(ctx: &mut Ctx<'_>, cmd: Command, stdin: &mut dyn Read) -> Result<i32> {
    let r = match cmd {
        Command::Login(a) => commands::login(ctx, a, stdin).await,
        Command::Config(ConfigCmd::Path) => {
            let p = ctx.config_path.display().to_string();
            ctx.say(&p)
        }
        Command::Config(ConfigCmd::Show) => commands::config_show(ctx),
        Command::Me => commands::me(ctx).await,
        Command::Objects(c) => crud!(ctx, c, ObjectsCmd, PolicyKind::Objects, Object),
        Command::Services(c) => crud!(ctx, c, ServicesCmd, PolicyKind::Services, Service),
        Command::DataClasses(c) => {
            crud!(ctx, c, DataClassesCmd, PolicyKind::DataClasses, DataClass)
        }
        Command::Zones(c) => crud!(ctx, c, ZonesCmd, PolicyKind::Zones, Zone),
        Command::Agents(c) => crud!(ctx, c, AgentsCmd, PolicyKind::Agents, Agent,
            AgentsCmd::Overview { agent } => commands::agent_overview(ctx, &agent).await),
        Command::Rules(c) => crud!(ctx, c, RulesCmd, PolicyKind::Rules, Rule,
            RulesCmd::Move { rule, position, zone, baseline, section } =>
                resources::move_rule(ctx, &rule, position, zone.as_deref(), baseline, section).await),
        Command::Rulebase => commands::rulebase(ctx).await,
        Command::IntentPolicy(c) => commands::intent_policy(ctx, c).await,
        Command::InspectionRules(c) => crud!(
            ctx,
            c,
            InspectionRulesCmd,
            PolicyKind::InspectionRules,
            Inspection
        ),
        Command::AlertChannels(c) => match c {
            AlertChannelsCmd::List => resources::channels_list(ctx).await,
            AlertChannelsCmd::Show { id } => resources::channels_show(ctx, &id).await,
            AlertChannelsCmd::Create { file, args } => {
                resources::channels_save(ctx, None, &file, &args).await
            }
            AlertChannelsCmd::Update { id, file, args } => {
                resources::channels_save(ctx, Some(&id), &file, &args).await
            }
            AlertChannelsCmd::Delete { id } => resources::channels_delete(ctx, &id).await,
        },
        Command::WhereUsed { object } => resources::where_used(ctx, &object).await,
        Command::Session(c) => commands::session(ctx, c).await,
        Command::Status => commands::status(ctx).await,
        Command::Verify { revision } => return commands::verify(ctx, revision).await,
        Command::Allow(a) => commands::allow(ctx, a).await,
        Command::Revisions(c) => commands::revisions(ctx, c).await,
        Command::Install(a) => return commands::install(ctx, a).await,
        Command::Gateways(c) => commands::gateways(ctx, c).await,
        Command::Logs(c) => commands::logs(ctx, c).await,
        Command::InternalMap(a) => commands::internal_map(ctx, a).await,
        Command::Alerts(c) => commands::alerts(ctx, c).await,
        Command::Captures(c) => commands::captures(ctx, c).await,
        Command::Audit(c) => return commands::audit(ctx, c).await,
        Command::Approvals(c) => commands::approvals(ctx, c).await,
        Command::Tokens(c) => commands::tokens(ctx, c).await,
        Command::Enroll(a) => enroll::enroll(ctx, *a).await,
        Command::Unenroll(a) => enroll::unenroll(ctx, a).await,
        Command::Import(c) => return commands::import(ctx, c).await,
    };
    r.map(|()| 0)
}
