-- Authentication (lot L0 base, extended by lot L7c): API tokens.
-- The MCP agent's own zone and delegated zones are NOT stored here: they are computed on each
-- request from the current policy (`Agent.zone_id`, `Zone.delegated_to_mcp`), single source.
CREATE TABLE api_tokens (
    id           uuid PRIMARY KEY DEFAULT gen_random_uuid(),
    name         text NOT NULL,
    token_sha256 text NOT NULL UNIQUE,
    role         text NOT NULL,
    actor_kind   text NOT NULL,
    actor_name   text NOT NULL,
    agent_id     uuid NULL,
    created_at   timestamptz NOT NULL DEFAULT now(),
    created_by   jsonb NOT NULL,
    expires_at   timestamptz NULL,
    last_used_at timestamptz NULL,
    revoked_at   timestamptz NULL
);

-- A single active `mcp_agent` token at a time (EF-51).
CREATE UNIQUE INDEX api_tokens_single_mcp_agent ON api_tokens (role)
    WHERE role = 'mcp_agent' AND revoked_at IS NULL;
