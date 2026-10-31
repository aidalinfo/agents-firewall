//! Command-line definitions (clap derive).

use std::path::PathBuf;

use clap::{Args, Parser, Subcommand, ValueEnum};

/// agents-firewall command-line interface: everything the console does, enrollment included.
///
/// Configuration: ~/.config/afw/config.toml (written by `afw login`), overridden by
/// AFW_URL, AFW_TOKEN and AFW_CA_CERT. Policy changes happen in your editing session, opened
/// automatically on the first change; publish it with `afw session publish -m <comment>`.
#[derive(Parser, Debug)]
#[command(name = "afw", version, propagate_version = true, max_term_width = 100)]
pub struct Cli {
    /// Print JSON instead of tables.
    #[arg(long, global = true)]
    pub json: bool,
    /// Configuration file [default: ~/.config/afw/config.toml].
    #[arg(long, global = true, env = "AFW_CONFIG", value_name = "FILE")]
    pub config: Option<PathBuf>,
    /// Console URL (overrides the configuration).
    #[arg(long, global = true, env = "AFW_URL", value_name = "URL")]
    pub url: Option<String>,
    /// Extra trusted CA certificate, PEM (overrides the configuration).
    #[arg(long, global = true, env = "AFW_CA_CERT", value_name = "FILE")]
    pub ca_cert: Option<PathBuf>,
    /// Editing session to use (default: your open session).
    #[arg(long, global = true, env = "AFW_SESSION", value_name = "ID")]
    pub session: Option<uuid::Uuid>,
    #[command(subcommand)]
    pub command: Command,
}

#[derive(Subcommand, Debug)]
pub enum Command {
    /// Save the console URL and an API token (read from stdin), after checking them.
    Login(LoginArgs),
    /// Show the configuration (the token is never printed).
    #[command(subcommand)]
    Config(ConfigCmd),
    /// Show who the token belongs to (role, writable zones).
    Me,
    /// Network objects (destinations).
    #[command(subcommand)]
    Objects(ObjectsCmd),
    /// Services (protocol, ports, application match).
    #[command(subcommand)]
    Services(ServicesCmd),
    /// Data classes (DLP detectors).
    #[command(subcommand, name = "data-classes")]
    DataClasses(DataClassesCmd),
    /// Zones (VLAN-like groups of agents) and their mode.
    #[command(subcommand)]
    Zones(ZonesCmd),
    /// Agents: list, change zone, agent view.
    #[command(subcommand)]
    Agents(AgentsCmd),
    /// Rule base: create, update, move, delete.
    #[command(subcommand)]
    Rules(RulesCmd),
    /// Whole rule base by layer and section (baseline, then zones), with numbers and hits.
    Rulebase,
    /// TLS inspection rules.
    #[command(subcommand, name = "inspection-rules")]
    InspectionRules(InspectionRulesCmd),
    /// Rules, groups and inspection rules referencing an object.
    #[command(name = "where-used")]
    WhereUsed {
        /// Object name or id.
        object: String,
    },
    /// Editing sessions: open, show, discard, publish.
    #[command(subcommand)]
    Session(SessionCmd),
    /// Published and installed revisions, gateways up to date.
    Status,
    /// Pre-install verification: shadowed rules, unused objects, expired rules.
    Verify {
        /// Revision to verify (default: your session draft).
        #[arg(long)]
        revision: Option<u64>,
    },
    /// Prepare an accept rule in your session from a denied flow of the log.
    Allow(AllowArgs),
    /// Published revisions: history, detail, differences, rollback.
    #[command(subcommand)]
    Revisions(RevisionsCmd),
    /// Install a revision on gateways and wait for each gateway's result.
    Install(InstallArgs),
    /// Gateways, registration tokens, commands.
    #[command(subcommand)]
    Gateways(GatewaysCmd),
    /// Traffic log: flows, flow detail, DNS, live tail.
    #[command(subcommand)]
    Logs(LogsCmd),
    /// Internal flows map (agents and internal hosts).
    #[command(name = "internal-map")]
    InternalMap(MapArgs),
    /// Alerts.
    #[command(subcommand)]
    Alerts(AlertsCmd),
    /// Alert channels (webhook, Teams, Pulse Chat).
    #[command(subcommand, name = "alert-channels")]
    AlertChannels(AlertChannelsCmd),
    /// Packet captures.
    #[command(subcommand)]
    Captures(CapturesCmd),
    /// Hash-chained audit log.
    #[command(subcommand)]
    Audit(AuditCmd),
    /// Approvals of widening changes requested by the MCP agent.
    #[command(subcommand)]
    Approvals(ApprovalsCmd),
    /// API tokens.
    #[command(subcommand)]
    Tokens(TokensCmd),
    /// Hermes intent policy (action classes evaluated by the plugin).
    #[command(subcommand, name = "intent-policy")]
    IntentPolicy(IntentPolicyCmd),
    /// Enroll a container agent behind its gateway and create the agent in a zone.
    Enroll(Box<EnrollArgs>),
    /// Undo an enrollment and delete the agent.
    Unenroll(UnenrollArgs),
    /// Import a policy from another tool.
    #[command(subcommand)]
    Import(ImportCmd),
}

/// `afw login --url <console> [--ca-cert <pem>]`: the global flags give the URL and CA.
#[derive(Args, Debug)]
pub struct LoginArgs {}

#[derive(Subcommand, Debug)]
pub enum ConfigCmd {
    /// Print the configuration (token masked).
    Show,
    /// Print the configuration file path.
    Path,
}

// ---------------------------------------------------------------------------------------------
// Policy resources

/// Creation/update input: a JSON or YAML file (`-` for stdin), completed or overridden by flags.
#[derive(Args, Debug, Clone, Default)]
pub struct FileArg {
    /// JSON or YAML body (`-` = stdin); flags override its fields.
    #[arg(short = 'f', long = "file", value_name = "FILE")]
    pub file: Option<PathBuf>,
}

macro_rules! resource_cmd {
    ($name:ident, $args:ty, $what:literal $(, $($extra:tt)*)?) => {
        #[derive(Subcommand, Debug)]
        pub enum $name {
            #[doc = concat!("List ", $what, "s.")]
            List,
            #[doc = concat!("Show a ", $what, " (name or id).")]
            Show { id: String },
            #[doc = concat!("Create a ", $what, " in your session.")]
            Create {
                #[command(flatten)]
                file: FileArg,
                #[command(flatten)]
                args: $args,
            },
            #[doc = concat!("Update a ", $what, " in your session (only the given fields change).")]
            Update {
                id: String,
                #[command(flatten)]
                file: FileArg,
                #[command(flatten)]
                args: $args,
            },
            #[doc = concat!("Delete a ", $what, " in your session.")]
            Delete { id: String },
            $($($extra)*)?
        }
    };
}

resource_cmd!(ObjectsCmd, ObjectArgs, "object");
resource_cmd!(ServicesCmd, ServiceArgs, "service");
resource_cmd!(DataClassesCmd, DataClassArgs, "data class");
resource_cmd!(ZonesCmd, ZoneArgs, "zone");
resource_cmd!(InspectionRulesCmd, InspectionArgs, "inspection rule");
resource_cmd!(AgentsCmd, AgentArgs, "agent",
    /// Agent view: zone, gateway, counters, top destinations, recent denials and tool calls.
    Overview { agent: String },
);
resource_cmd!(RulesCmd, RuleArgs, "rule",
    /// Move a rule (position, layer, section).
    Move {
        rule: String,
        /// New position in the layer (1 = first).
        #[arg(long)]
        position: u32,
        /// Move to this zone's layer.
        #[arg(long, conflicts_with = "baseline")]
        zone: Option<String>,
        /// Move to the baseline layer.
        #[arg(long)]
        baseline: bool,
        /// New section.
        #[arg(long)]
        section: Option<String>,
    },
);

#[derive(Args, Debug, Clone, Default)]
pub struct ObjectArgs {
    #[arg(long)]
    pub name: Option<String>,
    #[arg(long)]
    pub comment: Option<String>,
    /// Destination category (`none` clears it).
    #[arg(long, value_enum)]
    pub category: Option<CategoryArg>,
    /// Domain or wildcard (`*.example.com` matches sub-domains only).
    #[arg(long, group = "spec")]
    pub domain: Option<String>,
    /// Host IP address.
    #[arg(long, group = "spec")]
    pub host: Option<String>,
    /// Network (CIDR).
    #[arg(long, group = "spec")]
    pub network: Option<String>,
    /// Inclusive address range START-END.
    #[arg(long, group = "spec")]
    pub range: Option<String>,
    /// Group of objects (names or ids, comma separated).
    #[arg(long, group = "spec", value_delimiter = ',')]
    pub group: Option<Vec<String>>,
    /// Any destination.
    #[arg(long, group = "spec")]
    pub any: bool,
}

#[derive(ValueEnum, Clone, Copy, Debug, PartialEq, Eq)]
pub enum CategoryArg {
    LlmProvider,
    CloudMetadata,
    Internal,
    None,
}

#[derive(Args, Debug, Clone, Default)]
pub struct ServiceArgs {
    #[arg(long)]
    pub name: Option<String>,
    #[arg(long)]
    pub comment: Option<String>,
    #[arg(long, value_parser = ["tcp", "udp", "any"])]
    pub protocol: Option<String>,
    /// Port or range (`443`, `8000-8100`); repeatable; replaces the list.
    #[arg(long = "port")]
    pub ports: Vec<String>,
    /// Application protocol match.
    #[arg(long, value_parser = ["http", "https", "dns", "ssh", "tls", "other"])]
    pub app: Option<String>,
    /// HTTP method (with --app http/https); repeatable.
    #[arg(long = "method")]
    pub methods: Vec<String>,
    /// HTTP path prefix (with --app http/https); repeatable.
    #[arg(long = "path-prefix")]
    pub path_prefixes: Vec<String>,
}

#[derive(Args, Debug, Clone, Default)]
pub struct DataClassArgs {
    #[arg(long)]
    pub name: Option<String>,
    #[arg(long)]
    pub comment: Option<String>,
    #[arg(long, value_parser = ["secret", "infra", "commercial", "personal", "custom"])]
    pub category: Option<String>,
    /// Built-in detector id (e.g. aws_access_key); repeatable.
    #[arg(long = "builtin")]
    pub builtins: Vec<String>,
    /// Regex detector NAME=PATTERN; repeatable.
    #[arg(long = "regex")]
    pub regexes: Vec<String>,
}

#[derive(Args, Debug, Clone, Default)]
pub struct ZoneArgs {
    #[arg(long)]
    pub name: Option<String>,
    #[arg(long)]
    pub comment: Option<String>,
    /// `observe` logs denials but lets flows through.
    #[arg(long, value_parser = ["enforce", "observe"])]
    pub mode: Option<String>,
    /// Delegate the zone to the MCP agent.
    #[arg(long = "delegated-to-mcp")]
    pub delegated_to_mcp: Option<bool>,
}

#[derive(Args, Debug, Clone, Default)]
pub struct AgentArgs {
    #[arg(long)]
    pub name: Option<String>,
    /// Zone (name or id): changing it moves the agent.
    #[arg(long)]
    pub zone: Option<String>,
    #[arg(long, value_parser = ["docker_compose", "coolify", "kubernetes", "container"])]
    pub kind: Option<String>,
    /// Gateway (name or id).
    #[arg(long)]
    pub gateway: Option<String>,
    /// Source address on the gateway's internal network; repeatable; replaces the list.
    #[arg(long = "address")]
    pub addresses: Vec<String>,
    /// Label KEY=VALUE; repeatable; replaces the labels.
    #[arg(long = "label")]
    pub labels: Vec<String>,
    #[arg(long)]
    pub hermes: Option<bool>,
    /// Approved administration agent (MCP).
    #[arg(long = "mcp-admin")]
    pub mcp_admin: Option<bool>,
}

#[derive(Args, Debug, Clone, Default)]
pub struct RuleArgs {
    #[arg(long)]
    pub name: Option<String>,
    /// Zone layer of the rule (name or id); also its default source.
    #[arg(long, conflicts_with = "baseline")]
    pub zone: Option<String>,
    /// Baseline layer (shared by every zone).
    #[arg(long)]
    pub baseline: bool,
    #[arg(long)]
    pub section: Option<String>,
    /// Position in the layer (default: last).
    #[arg(long)]
    pub position: Option<u32>,
    /// Source zone (name or id); repeatable; replaces the list.
    #[arg(long = "source")]
    pub sources: Vec<String>,
    /// Destination object (name or id); repeatable; replaces the list (none = any).
    #[arg(long = "destination")]
    pub destinations: Vec<String>,
    /// Service (name or id); repeatable; replaces the list (none = any).
    #[arg(long = "service")]
    pub services: Vec<String>,
    /// Data class (name or id); repeatable; replaces the list.
    #[arg(long = "data-class")]
    pub data_classes: Vec<String>,
    #[arg(long, value_parser = ["accept", "deny"])]
    pub action: Option<String>,
    #[arg(long, value_parser = ["none", "log", "detailed", "capture"])]
    pub track: Option<String>,
    /// Expiry: RFC 3339 time, duration from now (`7d`, `12h`) or `never`.
    #[arg(long)]
    pub expires: Option<String>,
    #[arg(long)]
    pub comment: Option<String>,
    #[arg(long)]
    pub enabled: Option<bool>,
}

#[derive(Args, Debug, Clone, Default)]
pub struct InspectionArgs {
    #[arg(long)]
    pub name: Option<String>,
    /// Position (default: last).
    #[arg(long)]
    pub position: Option<u32>,
    /// Zone (name or id); repeatable; replaces the list (none = all zones).
    #[arg(long = "zone")]
    pub zones: Vec<String>,
    /// Destination object (name or id); repeatable; replaces the list (none = any).
    #[arg(long = "destination")]
    pub destinations: Vec<String>,
    #[arg(long, value_parser = ["inspect", "bypass"])]
    pub action: Option<String>,
}

#[derive(Args, Debug, Clone, Default)]
pub struct AlertChannelArgs {
    #[arg(long)]
    pub name: Option<String>,
    #[arg(long, value_parser = ["webhook", "teams", "pulse_chat"])]
    pub kind: Option<String>,
    /// Target URL.
    #[arg(long = "target-url")]
    pub target_url: Option<String>,
    #[arg(long = "min-severity", value_parser = ["info", "warning", "critical"])]
    pub min_severity: Option<String>,
    #[arg(long)]
    pub enabled: Option<bool>,
}

resource_cmd!(AlertChannelsCmd, AlertChannelArgs, "alert channel");

// ---------------------------------------------------------------------------------------------
// Sessions, revisions, install

#[derive(Subcommand, Debug)]
pub enum SessionCmd {
    /// Open an editing session.
    Open {
        #[arg(long)]
        name: Option<String>,
    },
    /// Show a session (default: yours) with its locks and pending changes.
    Show { id: Option<uuid::Uuid> },
    /// List open sessions.
    List,
    /// Discard a session (default: yours) and release its locks.
    Discard { id: Option<uuid::Uuid> },
    /// Publish a session (default: yours) as a new revision.
    Publish {
        /// Revision comment.
        #[arg(short = 'm', long = "message")]
        message: String,
        id: Option<uuid::Uuid>,
    },
}

#[derive(Args, Debug)]
pub struct AllowArgs {
    /// Id of the denied flow (see `afw logs flows --verdict deny`).
    pub flow_id: uuid::Uuid,
    /// Destination of the rule.
    #[arg(long, value_parser = ["exact", "wildcard", "group"])]
    pub destination: Option<String>,
    /// Rule expiry, in days.
    #[arg(long = "expires-in-days")]
    pub expires_in_days: Option<u32>,
    #[arg(long, value_parser = ["none", "log", "detailed", "capture"])]
    pub track: Option<String>,
}

#[derive(Subcommand, Debug)]
pub enum RevisionsCmd {
    /// List revisions (newest first).
    List {
        #[arg(long)]
        limit: Option<u32>,
        #[arg(long)]
        cursor: Option<String>,
    },
    /// Show a revision and its full policy document.
    Show { revision: u64 },
    /// Differences between a revision and another one (default: the previous one).
    Diff {
        revision: u64,
        #[arg(long)]
        against: Option<u64>,
    },
    /// Open a session whose content is this revision (rollback); publish it to apply.
    Revert { revision: u64 },
}

#[derive(Args, Debug)]
pub struct InstallArgs {
    /// Revision to install.
    pub revision: u64,
    /// Gateway (name or id); repeatable.
    #[arg(long = "gateway", required_unless_present = "all", conflicts_with = "all")]
    pub gateways: Vec<String>,
    /// Every gateway.
    #[arg(long)]
    pub all: bool,
    /// Do not wait for the gateways' results.
    #[arg(long = "no-wait")]
    pub no_wait: bool,
    /// Maximum wait, in seconds.
    #[arg(long, default_value_t = 120)]
    pub timeout: u64,
}

#[derive(Subcommand, Debug)]
pub enum GatewaysCmd {
    /// List gateways (status, desired and active revisions).
    List,
    /// Show a gateway.
    Show { gateway: String },
    /// Create a one-time registration token (valid 15 minutes).
    Token {
        /// Expected gateway name (informative).
        #[arg(long)]
        name: Option<String>,
    },
    /// Queue a command, delivered with the gateway's next heartbeat.
    Command {
        gateway: String,
        #[arg(value_parser = ["reinstall", "self-test"])]
        command: String,
    },
    /// Remove a gateway (revokes its certificate).
    Delete { gateway: String },
}

// ---------------------------------------------------------------------------------------------
// Logs

/// Log filters (EF-41). Times: RFC 3339 or a duration ago (`15m`, `2h`, `7d`).
#[derive(Args, Debug, Clone, Default)]
pub struct LogFilter {
    /// Agent (name or id).
    #[arg(long)]
    pub agent: Option<String>,
    /// Zone (name or id).
    #[arg(long)]
    pub zone: Option<String>,
    /// Destination domain, IP or CIDR.
    #[arg(long)]
    pub destination: Option<String>,
    #[arg(long, value_parser = ["allow", "deny"])]
    pub verdict: Option<String>,
    /// Rule (name or id).
    #[arg(long)]
    pub rule: Option<String>,
}

#[derive(Args, Debug, Clone, Default)]
pub struct Period {
    /// Start: RFC 3339 or a duration ago (`2h`).
    #[arg(long)]
    pub from: Option<String>,
    /// End: RFC 3339 or a duration ago.
    #[arg(long)]
    pub to: Option<String>,
}

#[derive(Args, Debug, Clone, Default)]
pub struct Paging {
    /// Page size (max 1000).
    #[arg(long)]
    pub limit: Option<u32>,
    /// `next_cursor` of the previous page.
    #[arg(long)]
    pub cursor: Option<String>,
}

#[derive(Subcommand, Debug)]
pub enum LogsCmd {
    /// Search flows (newest first).
    Flows {
        #[command(flatten)]
        filter: LogFilter,
        #[command(flatten)]
        period: Period,
        /// Free text search.
        #[arg(short = 'q', long = "search")]
        q: Option<String>,
        #[command(flatten)]
        paging: Paging,
    },
    /// Flow counts over time (allowed, denied, observed).
    Stats {
        #[command(flatten)]
        filter: LogFilter,
        #[command(flatten)]
        period: Period,
        #[arg(short = 'q', long = "search")]
        q: Option<String>,
        /// Histogram bucket.
        #[arg(long, value_parser = ["1m", "5m", "1h"])]
        bucket: Option<String>,
    },
    /// Flow detail: HTTP exchanges, rule trace, correlated tool call, allow proposal.
    Show { flow_id: uuid::Uuid },
    /// Search DNS queries.
    Dns {
        #[command(flatten)]
        filter: LogFilter,
        #[command(flatten)]
        period: Period,
        #[arg(short = 'q', long = "search")]
        q: Option<String>,
        #[command(flatten)]
        paging: Paging,
    },
    /// Follow live events (Ctrl-C to stop).
    Tail {
        #[command(flatten)]
        filter: LogFilter,
    },
}

#[derive(Args, Debug)]
pub struct MapArgs {
    /// Period shortcut (`--from`/`--to` take precedence).
    #[arg(long = "period", value_parser = ["1h", "24h", "7d"])]
    pub last: Option<String>,
    #[command(flatten)]
    pub period: Period,
    /// Zone (name or id).
    #[arg(long)]
    pub zone: Option<String>,
}

#[derive(Subcommand, Debug)]
pub enum AlertsCmd {
    /// List alerts (newest first).
    List {
        /// Agent (name or id).
        #[arg(long)]
        agent: Option<String>,
        #[arg(long, value_parser = ["info", "warning", "critical"])]
        severity: Option<String>,
        /// Only acknowledged (`true`) or unacknowledged (`false`) alerts.
        #[arg(long)]
        acknowledged: Option<bool>,
        #[command(flatten)]
        period: Period,
        #[command(flatten)]
        paging: Paging,
    },
    /// Acknowledge an alert.
    Ack { id: uuid::Uuid },
}

#[derive(Subcommand, Debug)]
pub enum CapturesCmd {
    /// List captures.
    List {
        #[command(flatten)]
        paging: Paging,
    },
    /// Start a packet capture of an agent's traffic.
    Start {
        /// Agent (name or id).
        agent: String,
        /// Duration in seconds.
        #[arg(long, default_value_t = 60)]
        duration: u32,
    },
    /// Show a capture.
    Show { id: uuid::Uuid },
    /// Download the pcap file.
    Download {
        id: uuid::Uuid,
        /// Output file [default: capture-<id>.pcap].
        #[arg(short = 'o', long = "output")]
        output: Option<PathBuf>,
    },
}

#[derive(Subcommand, Debug)]
pub enum AuditCmd {
    /// List audit entries (ascending sequence).
    List {
        #[arg(long = "from-seq")]
        from_seq: Option<i64>,
        /// Actor id or name.
        #[arg(long)]
        actor: Option<String>,
        /// Action (e.g. `session.publish`).
        #[arg(long)]
        action: Option<String>,
        /// Interface the change was made from.
        #[arg(long, value_parser = ["ui", "cli", "mcp", "api", "system"])]
        interface: Option<String>,
        #[command(flatten)]
        period: Period,
        #[command(flatten)]
        paging: Paging,
    },
    /// Verify the hash chain on the server.
    Verify,
    /// Export the log as JSON lines and check the chain locally.
    Export {
        #[arg(long = "from-seq")]
        from_seq: Option<i64>,
        /// Output file [default: stdout].
        #[arg(short = 'o', long = "output")]
        output: Option<PathBuf>,
    },
}

#[derive(Subcommand, Debug)]
pub enum ApprovalsCmd {
    /// List approvals.
    List {
        #[arg(long, value_parser = ["pending", "approved", "rejected"])]
        status: Option<String>,
    },
    /// Show an approval.
    Show { id: uuid::Uuid },
    /// Approve (an administrator other than the requester).
    Approve {
        id: uuid::Uuid,
        #[arg(short = 'm', long = "message")]
        message: Option<String>,
    },
    /// Reject.
    Reject {
        id: uuid::Uuid,
        #[arg(short = 'm', long = "message")]
        message: Option<String>,
    },
}

#[derive(Subcommand, Debug)]
pub enum TokensCmd {
    /// List API tokens.
    List,
    /// Create an API token; its secret is printed once.
    Create {
        #[arg(long)]
        name: String,
        #[arg(long, value_parser = ["admin", "auditor", "viewer", "mcp_agent", "agent_plugin"])]
        role: String,
        /// Agent bound to the token (mcp_agent, agent_plugin).
        #[arg(long)]
        agent: Option<String>,
        /// Expiry: RFC 3339 time or a duration from now (`90d`).
        #[arg(long)]
        expires: Option<String>,
    },
    /// Revoke an API token.
    Revoke { id: uuid::Uuid },
}

#[derive(Subcommand, Debug)]
pub enum IntentPolicyCmd {
    /// Show the current intent policy.
    Show,
    /// Replace the intent policy (the server assigns the next version).
    Set {
        /// JSON or YAML file (`-` = stdin) with `action_classes`.
        #[arg(short = 'f', long = "file")]
        file: PathBuf,
    },
}

// ---------------------------------------------------------------------------------------------
// Enrollment and import

#[derive(Args, Debug, Clone)]
pub struct EnrollArgs {
    /// Container, compose service or workload of the agent.
    pub target: String,
    /// Agent name [default: the target].
    #[arg(long)]
    pub name: Option<String>,
    /// Zone of the agent (name or id).
    #[arg(long)]
    pub zone: String,
    /// Gateway (name or id) [default: the only gateway].
    #[arg(long)]
    pub gateway: Option<String>,
    /// Docker Compose file to transform.
    #[arg(long, value_name = "FILE", group = "target_kind")]
    pub compose: Option<PathBuf>,
    /// Coolify application (or service, with --coolify-service) UUID.
    #[arg(long, value_name = "UUID", group = "target_kind")]
    pub coolify: Option<String>,
    /// Kubernetes workload manifest to patch.
    #[arg(long, value_name = "FILE", group = "target_kind")]
    pub k8s: Option<PathBuf>,
    /// Hermes agent: mount the plugin and create its token.
    #[arg(long)]
    pub hermes: bool,
    /// Agent address on the gateway's internal network (its identity).
    #[arg(long, value_name = "IP")]
    pub ip: Option<String>,
    /// Gateway address on the internal network.
    #[arg(long = "gateway-ip", default_value = "10.77.0.2")]
    pub gateway_ip: String,
    /// Internal network of the gateway.
    #[arg(long, default_value = "afw-internal")]
    pub network: String,
    /// Explicit proxy URL [default: http://<gateway-ip>:3128].
    #[arg(long = "proxy-url")]
    pub proxy_url: Option<String>,
    /// Host path of the gateway inspection CA certificate.
    #[arg(long = "ca-path", default_value = "/etc/agents-firewall/gateway.crt")]
    pub ca_path: String,
    /// Image of the afw-net-<agent> network container.
    #[arg(long = "netinit-image", default_value = afw_enroll::DEFAULT_NETINIT_IMAGE)]
    pub netinit_image: String,
    /// Console URL used by the Hermes plugin [default: the configured URL].
    #[arg(long = "console-url")]
    pub console_url: Option<String>,
    /// Host directory of the Hermes plugin.
    #[arg(long = "hermes-plugin-dir", default_value = "./integrations/hermes")]
    pub hermes_plugin_dir: String,
    /// Environment variable holding the Hermes plugin token [default: AFW_TOKEN_<AGENT>].
    #[arg(long = "token-env")]
    pub token_env: Option<String>,
    /// File (.env) where the Hermes plugin token is written (mode 0600) instead of printed.
    #[arg(long = "env-file", value_name = "FILE")]
    pub env_file: Option<PathBuf>,
    /// Coolify: the UUID is a service, not an application.
    #[arg(long = "coolify-service")]
    pub coolify_service: bool,
    /// Coolify URL.
    #[arg(long = "coolify-url", env = "AFW_COOLIFY_URL")]
    pub coolify_url: Option<String>,
    /// Kubernetes: namespace of the agents [default: the workload's, else `default`].
    #[arg(long)]
    pub namespace: Option<String>,
    /// Kubernetes: fixed ClusterIP of the gateway Service.
    #[arg(long = "gateway-cluster-ip")]
    pub gateway_cluster_ip: Option<String>,
    /// Kubernetes: gateway image.
    #[arg(long = "gateway-image", default_value = "afw-gateway:local")]
    pub gateway_image: String,
    /// Kubernetes: Secret holding the gateway registration token.
    #[arg(long = "registration-secret", default_value = "afw-gateway-registration")]
    pub registration_secret: String,
    /// Kubernetes: also output the gateway manifests of the namespace.
    #[arg(long = "with-gateway")]
    pub with_gateway: bool,
    /// Output file of the transformed manifest [default: compose file in place, k8s to stdout].
    #[arg(short = 'o', long = "output")]
    pub output: Option<PathBuf>,
    /// Docker Compose: run `docker compose up -d` afterwards.
    #[arg(long)]
    pub apply: bool,
    /// Publish the session right away with this comment.
    #[arg(long, value_name = "COMMENT")]
    pub publish: Option<String>,
    /// Show the transformation without calling the API nor writing anything.
    #[arg(long = "dry-run")]
    pub dry_run: bool,
}

#[derive(Args, Debug, Clone)]
pub struct UnenrollArgs {
    /// Agent name.
    pub agent: String,
    /// Docker Compose file to restore.
    #[arg(long, value_name = "FILE", group = "target_kind")]
    pub compose: Option<PathBuf>,
    /// Coolify application (or service, with --coolify-service) UUID.
    #[arg(long, value_name = "UUID", group = "target_kind")]
    pub coolify: Option<String>,
    #[arg(long = "coolify-service")]
    pub coolify_service: bool,
    #[arg(long = "coolify-url", env = "AFW_COOLIFY_URL")]
    pub coolify_url: Option<String>,
    /// Docker Compose: run `docker compose up -d` afterwards.
    #[arg(long)]
    pub apply: bool,
    /// Keep the agent in the policy (only undo the network changes).
    #[arg(long = "keep-agent")]
    pub keep_agent: bool,
    /// Publish the session right away with this comment.
    #[arg(long, value_name = "COMMENT")]
    pub publish: Option<String>,
}

#[derive(Subcommand, Debug)]
pub enum ImportCmd {
    /// Import an egress-guard policy (objects, services, data classes, zone, rules, intent
    /// policy). Without --apply, only prints the import report.
    #[command(name = "egress-guard")]
    EgressGuard {
        /// egress-guard YAML file (`-` = stdin).
        file: PathBuf,
        /// Zone receiving the imported rules (created when missing).
        #[arg(long)]
        zone: String,
        /// Mode of a created zone.
        #[arg(long, value_parser = ["observe", "enforce"], default_value = "observe")]
        mode: String,
        /// Allow changing the mode of an existing zone.
        #[arg(long)]
        downgrade: bool,
        /// Merge the plan into your editing session.
        #[arg(long)]
        apply: bool,
        /// Apply even when a deny/gate of the source is not enforced by the plan.
        #[arg(long, requires = "apply")]
        force: bool,
        /// Also replace the whole Hermes intent policy with the imported one.
        #[arg(long = "intent-policy", requires = "apply")]
        intent_policy: bool,
    },
}
