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

-- Gateways (lot L7c). `desired_revision` is written by the policy module (installs, lot L7a);
-- the other state columns come from the gateway heartbeat.
CREATE TABLE gateways (
    id               uuid PRIMARY KEY,
    name             text NOT NULL,
    hostname         text NOT NULL,
    -- SHA-256 (hex) of the DER client certificate issued at registration: pinned, so only that
    -- certificate authenticates the gateway, and removing the row revokes it.
    cert_sha256      text NOT NULL,
    registered_at    timestamptz NOT NULL DEFAULT now(),
    deleted_at       timestamptz NULL,
    last_seen_at     timestamptz NULL,
    version          text NULL,
    active_revision  bigint NULL,
    desired_revision bigint NULL,
    ca_fingerprint   text NULL,
    stats            jsonb NULL
);
CREATE UNIQUE INDEX gateways_active_name ON gateways (name) WHERE deleted_at IS NULL;

-- One-time registration tokens (15 minutes), stored hashed.
CREATE TABLE gateway_registration_tokens (
    id           uuid PRIMARY KEY DEFAULT gen_random_uuid(),
    token_sha256 text NOT NULL UNIQUE,
    name         text NULL,
    created_at   timestamptz NOT NULL DEFAULT now(),
    created_by   jsonb NOT NULL,
    expires_at   timestamptz NOT NULL,
    used_at      timestamptz NULL,
    gateway_id   uuid NULL REFERENCES gateways (id)
);

-- Commands queued by administrators, delivered once with the next heartbeat.
CREATE TABLE gateway_commands (
    id           uuid PRIMARY KEY DEFAULT gen_random_uuid(),
    gateway_id   uuid NOT NULL REFERENCES gateways (id),
    command      jsonb NOT NULL,
    created_at   timestamptz NOT NULL DEFAULT now(),
    created_by   jsonb NOT NULL,
    delivered_at timestamptz NULL
);
CREATE INDEX gateway_commands_pending ON gateway_commands (gateway_id, created_at)
    WHERE delivered_at IS NULL;

-- Event batches reserved or ingested (`EventBatch.batch_id` idempotency key, per gateway). A
-- reservation is taken before ingestion and removed if ingestion fails.
CREATE TABLE gateway_event_batches (
    gateway_id  uuid NOT NULL REFERENCES gateways (id),
    batch_id    uuid NOT NULL,
    received_at timestamptz NOT NULL DEFAULT now(),
    PRIMARY KEY (gateway_id, batch_id)
);
