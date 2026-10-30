-- Logs (lot L7b, ADR 0006, ADR 0007, ADR 0021).
-- Events tables (flows, dns_events, http_events, tool_calls) are used by the PostgreSQL
-- LogStore (AFW_LOG_STORE=postgres, default). The console state tables (alerts, alert_channels,
-- captures, rule_hits, agent_destinations, ingested_batches) are always in PostgreSQL.
-- Each event keeps its full JSON in `event`; the other columns exist for filtering.

CREATE TABLE flows (
    id           uuid PRIMARY KEY,
    gateway_id   uuid NOT NULL,
    agent_id     uuid NULL,
    zone_id      uuid NULL,
    src_ip       inet NOT NULL,
    dst_ip       inet NOT NULL,
    dst_port     integer NOT NULL,
    protocol     text NOT NULL,
    app          text NULL,
    dest         text NOT NULL,          -- domain, else SNI, else destination IP (lowercase)
    domain       text NULL,
    sni          text NULL,
    search       text NOT NULL,          -- lowercase "domain sni dst_ip" for free text search
    started_at   timestamptz NOT NULL,
    verdict      text NOT NULL,
    rule_id      uuid NULL,
    internal     boolean NOT NULL,
    observed     boolean NOT NULL,
    bytes_out    bigint NOT NULL,
    bytes_in     bigint NOT NULL,
    event        jsonb NOT NULL,
    tool_call_id uuid NULL,              -- materialized correlation (ADR 0007)
    confidence   text NULL,
    ingested_at  timestamptz NOT NULL DEFAULT now()
);
CREATE INDEX flows_time ON flows (started_at DESC, id DESC);
CREATE INDEX flows_agent_time ON flows (agent_id, started_at DESC);
CREATE INDEX flows_zone_time ON flows (zone_id, started_at DESC);
CREATE INDEX flows_verdict_time ON flows (verdict, started_at DESC);
CREATE INDEX flows_rule_time ON flows (rule_id, started_at DESC);
CREATE INDEX flows_internal_time ON flows (started_at DESC) WHERE internal;
CREATE INDEX flows_dest ON flows (dest);

CREATE TABLE dns_events (
    id         uuid PRIMARY KEY,
    gateway_id uuid NOT NULL,
    agent_id   uuid NULL,
    zone_id    uuid NULL,
    at         timestamptz NOT NULL,
    qname      text NOT NULL,            -- lowercase, without the trailing dot
    answer_ips inet[] NOT NULL,
    verdict    text NOT NULL,
    rule_id    uuid NULL,
    event      jsonb NOT NULL
);
CREATE INDEX dns_time ON dns_events (at DESC, id DESC);
CREATE INDEX dns_agent_time ON dns_events (agent_id, at DESC);

-- HTTP exchanges: metadata in clear (headers and bodies stripped from `event`), contents
-- (headers + bodies) sealed with AES-256-GCM in `content` (NULL when no AFW_DATA_KEY).
CREATE TABLE http_events (
    id         uuid PRIMARY KEY,
    flow_id    uuid NOT NULL,
    gateway_id uuid NOT NULL,
    agent_id   uuid NULL,
    at         timestamptz NOT NULL,
    url        text NOT NULL,
    event      jsonb NOT NULL,
    content    bytea NULL
);
CREATE INDEX http_flow ON http_events (flow_id);
CREATE INDEX http_time ON http_events (at);

-- Tool calls reported by the Hermes plugin; `agent_id` is the agent of the plugin token.
CREATE TABLE tool_calls (
    id              uuid PRIMARY KEY,
    agent_id        uuid NOT NULL,
    agent           text NOT NULL,
    conversation_id text NOT NULL,
    tool            text NOT NULL,
    args_summary    text NOT NULL,
    started_at      timestamptz NOT NULL,
    ended_at        timestamptz NULL,
    status          text NULL,
    received_at     timestamptz NOT NULL DEFAULT now()
);
CREATE INDEX tool_calls_agent_time ON tool_calls (agent_id, started_at DESC);

CREATE TABLE alerts (
    id              uuid PRIMARY KEY,
    at              timestamptz NOT NULL,
    kind            text NOT NULL,
    severity        text NOT NULL,
    agent_id        uuid NULL,
    gateway_id      uuid NULL,
    source          text NOT NULL,       -- gateway | console
    event           jsonb NOT NULL,
    acknowledged    boolean NOT NULL DEFAULT false,
    acknowledged_by jsonb NULL,
    acknowledged_at timestamptz NULL
);
CREATE INDEX alerts_time ON alerts (at DESC, id DESC);
CREATE INDEX alerts_agent_kind ON alerts (agent_id, kind, at DESC);

CREATE TABLE alert_channels (
    id           uuid PRIMARY KEY,
    name         text NOT NULL,
    kind         text NOT NULL,
    url          text NOT NULL,
    min_severity text NOT NULL,
    enabled      boolean NOT NULL,
    created_at   timestamptz NOT NULL DEFAULT now()
);

-- pcap captures; `data` is sealed with AES-256-GCM (never stored in clear).
CREATE TABLE captures (
    id            uuid PRIMARY KEY,
    agent_id      uuid NOT NULL,
    gateway_id    uuid NOT NULL,
    requested_at  timestamptz NOT NULL,
    requested_by  jsonb NOT NULL,
    duration_secs integer NOT NULL,
    state         text NOT NULL,
    size          bigint NULL,
    error         text NULL,
    dispatched_at timestamptz NULL,
    completed_at  timestamptz NULL,
    data          bytea NULL
);
CREATE INDEX captures_time ON captures (requested_at DESC, id DESC);
CREATE INDEX captures_pending ON captures (gateway_id) WHERE state = 'pending';

-- Rule hit counters, aggregated per gateway and revision.
CREATE TABLE rule_hits (
    rule_id     uuid NOT NULL,
    gateway_id  uuid NOT NULL,
    revision    bigint NOT NULL,
    hits        bigint NOT NULL,
    last_hit_at timestamptz NOT NULL,
    PRIMARY KEY (rule_id, gateway_id, revision)
);

-- Destinations already seen per agent ("never seen destination" alert).
CREATE TABLE agent_destinations (
    agent_id      uuid NOT NULL,
    destination   text NOT NULL,
    first_seen_at timestamptz NOT NULL,
    last_seen_at  timestamptz NOT NULL,
    PRIMARY KEY (agent_id, destination)
);

-- Idempotency of gateway event batches (EventBatch.batch_id).
CREATE TABLE ingested_batches (
    gateway_id  uuid NOT NULL,
    batch_id    uuid NOT NULL,
    ingested_at timestamptz NOT NULL DEFAULT now(),
    PRIMARY KEY (gateway_id, batch_id)
);
