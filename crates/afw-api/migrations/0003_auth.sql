-- Authentication (lot L0 base, extended by lot L7c): API tokens.
CREATE TABLE api_tokens (
    id              uuid PRIMARY KEY DEFAULT gen_random_uuid(),
    name            text NOT NULL,
    token_sha256    text NOT NULL UNIQUE,
    role            text NOT NULL,
    actor_kind      text NOT NULL,
    actor_name      text NOT NULL,
    agent_id        uuid NULL,
    delegated_zones uuid[] NOT NULL DEFAULT '{}',
    own_zone        uuid NULL,
    created_at      timestamptz NOT NULL DEFAULT now(),
    revoked_at      timestamptz NULL
);
