//! Administration MCP server (lot L9): exposes to the single approved agent the operations of
//! the `afw` CLI, through `afw-client` with `Interface::Mcp` and an `mcp_agent` token.
//! No authorization is decided here (EF-51/52): the API is the authority, its refusals are
//! returned as readable tool errors.

pub mod tools;

use std::borrow::Cow;
use std::sync::Arc;

use afw_client::AfwClient;
use axum::extract::Request;
use axum::http::StatusCode;
use axum::middleware::Next;
use axum::response::{IntoResponse, Response};
use rmcp::model::{
    CallToolRequestParam, CallToolResult, Content, Implementation, ListToolsResult,
    PaginatedRequestParam, ServerCapabilities, ServerInfo, Tool, ToolAnnotations,
};
use rmcp::service::RequestContext;
use rmcp::transport::streamable_http_server::session::local::LocalSessionManager;
use rmcp::transport::{StreamableHttpServerConfig, StreamableHttpService};
use rmcp::{ErrorData as McpError, RoleServer, ServerHandler};

/// Server instructions sent to the MCP client at initialization.
pub const INSTRUCTIONS: &str = "Administration of the agents-firewall egress firewall. Read the log \
(search_flows, get_flow), prepare changes in an editing session (create_resource, allow_from_log…), \
then publish_session and install_revision. You act on behalf of the approved administration agent: \
you can only change zones delegated to you and NEVER your own zone, rules whose source is your zone, \
the baseline, nor agents moving into or out of your zone (403). Widening changes wait for a human \
approval (publish_session answers PENDING HUMAN APPROVAL). Every call is audited with interface `mcp`.";

/// The MCP server: one API client shared by every tool call.
#[derive(Clone)]
pub struct AfwMcp {
    client: AfwClient,
}

impl AfwMcp {
    /// `client` should be built with `Interface::Mcp` and the `mcp_agent` token.
    pub fn new(client: AfwClient) -> Self {
        Self { client }
    }

    /// The tools, as listed to MCP clients.
    pub fn tool_list() -> Vec<Tool> {
        tools::tools()
            .into_iter()
            .map(|t| {
                let schema = match t.schema {
                    serde_json::Value::Object(m) => m,
                    _ => serde_json::Map::new(),
                };
                Tool::new(t.name, t.description, Arc::new(schema)).annotate(ToolAnnotations {
                    read_only_hint: Some(!t.write),
                    destructive_hint: Some(t.write),
                    open_world_hint: Some(false),
                    ..Default::default()
                })
            })
            .collect()
    }

    /// Runs a tool (used by `call_tool`, and directly by tests).
    pub async fn call(
        &self,
        name: &str,
        arguments: Option<serde_json::Map<String, serde_json::Value>>,
    ) -> CallToolResult {
        let out = tools::call(&self.client, name, arguments.unwrap_or_default()).await;
        if out.is_error {
            CallToolResult::error(vec![Content::text(out.text)])
        } else {
            CallToolResult::success(vec![Content::text(out.text)])
        }
    }
}

impl ServerHandler for AfwMcp {
    fn get_info(&self) -> ServerInfo {
        ServerInfo {
            capabilities: ServerCapabilities::builder().enable_tools().build(),
            server_info: Implementation {
                name: "afw-mcp".into(),
                title: Some("agents-firewall administration".into()),
                version: env!("CARGO_PKG_VERSION").into(),
                icons: None,
                website_url: None,
            },
            instructions: Some(INSTRUCTIONS.into()),
            ..Default::default()
        }
    }

    async fn list_tools(
        &self,
        _request: Option<PaginatedRequestParam>,
        _context: RequestContext<RoleServer>,
    ) -> Result<ListToolsResult, McpError> {
        Ok(ListToolsResult {
            tools: Self::tool_list(),
            next_cursor: None,
        })
    }

    async fn call_tool(
        &self,
        request: CallToolRequestParam,
        _context: RequestContext<RoleServer>,
    ) -> Result<CallToolResult, McpError> {
        let name: Cow<'static, str> = request.name;
        if !tools::tools().iter().any(|t| t.name == name) {
            return Err(McpError::invalid_params(
                format!("unknown tool `{name}`"),
                None,
            ));
        }
        Ok(self.call(&name, request.arguments).await)
    }
}

/// HTTP transport settings.
#[derive(Clone, Debug)]
pub struct HttpOptions {
    /// Bearer token clients must send (anyone reaching the endpoint acts as the agent).
    pub listen_token: String,
    /// Listening address: `Host` must name it (or `localhost` on its port).
    pub listen: std::net::SocketAddr,
    /// Extra accepted `Host` values (`name` or `name:port`), e.g. behind a reverse proxy.
    pub allowed_hosts: Vec<String>,
}

impl HttpOptions {
    /// Accepted `Host` header values (lower case).
    fn hosts(&self) -> Vec<String> {
        let port = self.listen.port();
        let mut h = vec![
            self.listen.to_string(),
            format!("localhost:{port}"),
            format!("127.0.0.1:{port}"),
            format!("[::1]:{port}"),
        ];
        if self.listen.ip().is_unspecified() {
            // 0.0.0.0 / [::]: the Host is then whatever name or address the client used; only
            // the explicitly allowed ones are accepted.
            h.truncate(4);
        }
        h.extend(self.allowed_hosts.iter().map(|s| s.to_ascii_lowercase()));
        h
    }
}

/// HTTP router (streamable HTTP transport on `/mcp`), protected by:
/// - a listen token (bearer): anyone reaching this endpoint would otherwise act as the agent;
/// - `Host` and `Origin` checks (DNS rebinding, cross-site requests from a browser): `Host` must
///   be the listening address, `localhost` on its port, or an allowed host; an `Origin` header,
///   when present, must be `http(s)://<one of those hosts>`; otherwise 403.
pub fn http_router(server: AfwMcp, opts: HttpOptions) -> axum::Router {
    let service = StreamableHttpService::new(
        move || Ok(server.clone()),
        Arc::new(LocalSessionManager::default()),
        StreamableHttpServerConfig::default(),
    );
    let token = Arc::new(opts.listen_token.clone());
    let hosts = Arc::new(opts.hosts());
    axum::Router::new()
        .nest_service("/mcp", service)
        .layer(axum::middleware::from_fn(
            move |req: Request, next: Next| {
                let token = token.clone();
                let hosts = hosts.clone();
                async move {
                    if !host_and_origin_ok(&hosts, &req) {
                        return (StatusCode::FORBIDDEN, "host or origin not allowed\n")
                            .into_response();
                    }
                    check_bearer(&token, req, next).await
                }
            },
        ))
}

fn host_and_origin_ok(hosts: &[String], req: &Request) -> bool {
    let header = |name| {
        req.headers()
            .get(name)
            .and_then(|v| v.to_str().ok())
            .map(str::to_ascii_lowercase)
    };
    let host = header(axum::http::header::HOST).or_else(|| {
        req.uri()
            .authority()
            .map(|a| a.as_str().to_ascii_lowercase())
    });
    let Some(host) = host else { return false };
    if !hosts.contains(&host) {
        return false;
    }
    match header(axum::http::header::ORIGIN) {
        None => true,
        Some(origin) => {
            let rest = origin
                .strip_prefix("http://")
                .or_else(|| origin.strip_prefix("https://"));
            rest.is_some_and(|r| hosts.iter().any(|h| h == r.trim_end_matches('/')))
        }
    }
}

async fn check_bearer(token: &str, req: Request, next: Next) -> Response {
    let given = req
        .headers()
        .get(axum::http::header::AUTHORIZATION)
        .and_then(|v| v.to_str().ok())
        .and_then(|v| v.strip_prefix("Bearer "))
        .unwrap_or("");
    if constant_time_eq(given.as_bytes(), token.as_bytes()) {
        next.run(req).await
    } else {
        (
            StatusCode::UNAUTHORIZED,
            "missing or invalid bearer token\n",
        )
            .into_response()
    }
}

fn constant_time_eq(a: &[u8], b: &[u8]) -> bool {
    if a.len() != b.len() || b.is_empty() {
        return false;
    }
    a.iter().zip(b).fold(0u8, |acc, (x, y)| acc | (x ^ y)) == 0
}
