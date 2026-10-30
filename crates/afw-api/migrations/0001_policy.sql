-- Policy model (lot L7a, ADR 0020): published revisions, editing sessions with their pending
-- changes and locks, approvals (EF-52), installations per gateway.

-- Published revisions: the complete document (single source of the published state).
CREATE TABLE revisions (
    number       bigint PRIMARY KEY CHECK (number > 0),
    document     jsonb NOT NULL,
    sha256       text NOT NULL,
    published_by jsonb NOT NULL,
    interface    text NOT NULL,
    session_id   uuid NULL,
    comment      text NOT NULL,
    published_at timestamptz NOT NULL,
    -- Readable differences against the previous revision (afw_core::api::Change list).
    diff         jsonb NOT NULL
);

CREATE TABLE policy_sessions (
    id                 uuid PRIMARY KEY,
    owner              jsonb NOT NULL,
    -- Stable caller identity ("<actor kind>:<actor id>").
    owner_key          text NOT NULL,
    interface          text NOT NULL,
    name               text NULL,
    state              text NOT NULL CHECK (state IN ('open', 'published', 'discarded')),
    opened_at          timestamptz NOT NULL,
    closed_at          timestamptz NULL,
    approval_id        uuid NULL,
    published_revision bigint NULL REFERENCES revisions (number),
    -- Last published revision when the session was opened.
    base_revision      bigint NULL
);

-- At most one open session per caller.
CREATE UNIQUE INDEX policy_sessions_one_open ON policy_sessions (owner_key) WHERE state = 'open';

-- Draft of a session: the full state of each changed entity ("after"; NULL = deleted).
CREATE TABLE policy_session_changes (
    session_id uuid NOT NULL REFERENCES policy_sessions (id) ON DELETE CASCADE,
    kind       text NOT NULL,
    entity_id  uuid NOT NULL,
    op         text NOT NULL CHECK (op IN ('create', 'update', 'delete')),
    after      jsonb NULL,
    seq        bigserial NOT NULL,
    PRIMARY KEY (session_id, kind, entity_id)
);

-- An entity changed in an open session is locked for the other sessions.
CREATE TABLE policy_locks (
    kind       text NOT NULL,
    entity_id  uuid NOT NULL,
    session_id uuid NOT NULL REFERENCES policy_sessions (id) ON DELETE CASCADE,
    locked_at  timestamptz NOT NULL DEFAULT now(),
    PRIMARY KEY (kind, entity_id)
);

CREATE TABLE approvals (
    id               uuid PRIMARY KEY,
    session_id       uuid NOT NULL REFERENCES policy_sessions (id),
    requested_by     jsonb NOT NULL,
    requested_by_key text NOT NULL,
    requested_at     timestamptz NOT NULL,
    summary          text NOT NULL,
    reason           text NOT NULL,
    -- Fingerprint of the draft the approval applies to: any later edit needs a new approval.
    draft_sha256     text NOT NULL,
    status           text NOT NULL CHECK (status IN ('pending', 'approved', 'rejected')),
    decided_by       jsonb NULL,
    decided_at       timestamptz NULL,
    comment          text NULL
);

CREATE INDEX approvals_session ON approvals (session_id);

CREATE TABLE installs (
    id           uuid PRIMARY KEY,
    revision     bigint NOT NULL REFERENCES revisions (number),
    gateway_id   uuid NOT NULL,
    requested_by jsonb NOT NULL,
    requested_at timestamptz NOT NULL,
    state        text NOT NULL CHECK (state IN ('pending', 'installed', 'failed')),
    error        text NULL,
    acked_at     timestamptz NULL
);

CREATE INDEX installs_gateway ON installs (gateway_id, requested_at DESC);

-- Desired / active revision per gateway (read by the gateway protocol, lot L7c).
CREATE TABLE gateway_policy_state (
    gateway_id       uuid PRIMARY KEY,
    desired_revision bigint NOT NULL REFERENCES revisions (number),
    rollback         boolean NOT NULL,
    active_revision  bigint NULL,
    updated_at       timestamptz NOT NULL DEFAULT now()
);

-- Hermes intent policy (ADR 0015), versioned; no row = the plugin's built-in policy (version 0).
CREATE TABLE intent_policy (
    version    bigint PRIMARY KEY CHECK (version > 0),
    document   jsonb NOT NULL,
    updated_by jsonb NOT NULL,
    interface  text NOT NULL,
    updated_at timestamptz NOT NULL DEFAULT now()
);

-- Group of each zone receiving the destinations allowed from the log (`allow-from-log`
-- `destination: group`), found by id rather than by name.
CREATE TABLE allow_log_groups (
    zone_id  uuid PRIMARY KEY,
    group_id uuid NOT NULL
);
