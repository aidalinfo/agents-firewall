-- Hash-chained, append-only audit log (afw_core::events::AuditEntry).
CREATE TABLE audit_log (
    seq        bigserial PRIMARY KEY,
    at         timestamptz NOT NULL,
    actor      jsonb NOT NULL,
    interface  text NOT NULL,
    session_id uuid NULL,
    action     text NOT NULL,
    target     text NOT NULL,
    diff       jsonb NOT NULL,
    prev_hash  text NOT NULL,
    hash       text NOT NULL UNIQUE
);

-- Append-only: updates, deletes and truncation are refused.
CREATE FUNCTION audit_log_append_only() RETURNS trigger LANGUAGE plpgsql AS $$
BEGIN
    RAISE EXCEPTION 'audit_log is append-only';
END;
$$;
CREATE TRIGGER audit_log_no_update_delete BEFORE UPDATE OR DELETE ON audit_log
    FOR EACH ROW EXECUTE FUNCTION audit_log_append_only();
CREATE TRIGGER audit_log_no_truncate BEFORE TRUNCATE ON audit_log
    FOR EACH STATEMENT EXECUTE FUNCTION audit_log_append_only();
