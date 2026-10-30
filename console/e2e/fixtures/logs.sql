-- Demonstration logs for the console e2e stack (lot L3b). Gateway events normally arrive over
-- mutual TLS (POST /gw/v1/events) from a registered gateway; this fixture writes the same rows
-- the PostgreSQL LogStore writes, for the agents of demo/policy/demo-policy.json.
-- Idempotent (fixed ids, ON CONFLICT DO NOTHING); timestamps are relative to now().

INSERT INTO gateways (id, name, hostname, cert_sha256, registered_at, last_seen_at, version, active_revision, desired_revision, ca_fingerprint, stats)
VALUES
  ('00000000-0000-4000-8000-0000000000a1', 'gw-demo-01', 'demo-01.interne.lan', 'e2e-fixture-not-a-certificate',
   now() - interval '3 days', now(), '0.1.0', 1, 1, NULL,
   '{"uptime_secs": 259200, "active_flows": 4, "flows_total": 1840, "denied_total": 37, "bytes_in": 18400000, "bytes_out": 4100000, "events_queued": 0, "events_dropped": 0}'),
  ('00000000-0000-4000-8000-0000000000a2', 'gw-demo-02', 'demo-02.interne.lan', 'e2e-fixture-not-a-certificate-2',
   now() - interval '2 days', now() - interval '30 minutes', '0.1.0', 1, 1, NULL, NULL)
ON CONFLICT DO NOTHING;

CREATE FUNCTION pg_temp.flow(
  p_id uuid, p_agent uuid, p_zone uuid, p_src text, p_dst_ip text, p_port int, p_app text, p_domain text,
  p_minutes numeric, p_verdict text, p_rule uuid, p_rule_number int, p_rule_name text, p_layer text,
  p_internal boolean, p_observed boolean, p_llm boolean, p_out bigint, p_tool uuid
) RETURNS void LANGUAGE plpgsql AS $$
DECLARE
  started timestamptz := now() - make_interval(secs => p_minutes * 60);
  ev jsonb;
BEGIN
  ev := jsonb_build_object(
    'id', p_id, 'gateway_id', '00000000-0000-4000-8000-0000000000a1', 'agent_id', p_agent, 'zone_id', p_zone,
    'src', p_src || ':' || (40000 + (p_minutes * 37)::int % 20000), 'dst', p_dst_ip || ':' || p_port,
    'protocol', 'tcp', 'app', p_app, 'domain', p_domain, 'sni', CASE WHEN p_app = 'https' THEN p_domain END,
    'bytes_out', p_out, 'bytes_in', p_out / 2 + 300,
    'started_at', to_char(started AT TIME ZONE 'UTC', 'YYYY-MM-DD"T"HH24:MI:SS.MS"Z"'),
    'ended_at', to_char((started + interval '180 milliseconds') AT TIME ZONE 'UTC', 'YYYY-MM-DD"T"HH24:MI:SS.MS"Z"'),
    'verdict', p_verdict,
    'decision', jsonb_build_object('rule_id', p_rule, 'rule_number', p_rule_number, 'rule_name', p_rule_name,
                                   'layer', p_layer, 'reason', CASE WHEN p_rule IS NULL THEN 'no rule matched' ELSE 'matched' END,
                                   'revision', 1),
    'internal', p_internal, 'llm_provider', p_llm, 'observed', p_observed,
    'tls_inspected', p_app = 'https' AND NOT p_llm, 'data_classes', '[]'::jsonb);
  INSERT INTO flows (id, gateway_id, agent_id, zone_id, src_ip, dst_ip, dst_port, protocol, app, dest, domain, sni,
                     search, started_at, verdict, rule_id, internal, observed, bytes_out, bytes_in, event, tool_call_id, confidence)
  VALUES (p_id, '00000000-0000-4000-8000-0000000000a1', p_agent, p_zone, p_src::inet, p_dst_ip::inet, p_port, 'tcp', p_app,
          lower(coalesce(p_domain, p_dst_ip)), p_domain, CASE WHEN p_app = 'https' THEN p_domain END,
          lower(concat_ws(' ', p_domain, p_domain, p_dst_ip)), started, p_verdict, p_rule, p_internal, p_observed,
          p_out, p_out / 2 + 300, ev, p_tool, CASE WHEN p_tool IS NULL THEN NULL ELSE 'certain' END)
  ON CONFLICT DO NOTHING;
END $$;

-- Tool call of daniel-bot behind the denied upload (correlated, ADR 0007).
INSERT INTO tool_calls (id, agent_id, agent, conversation_id, tool, args_summary, started_at, ended_at, status)
VALUES ('00000000-0000-4000-8000-0000000000c1', '00000000-0000-4000-8000-000000000501', 'daniel-bot', 'conv-rapport-q3',
        'upload_file', 'path: rapport-q3.pdf', now() - interval '61 seconds', now() - interval '60 seconds', 'error')
ON CONFLICT DO NOTHING;

-- daniel-bot (zone internes): the denied upload replayed by the e2e test (« refus → Autoriser »).
SELECT pg_temp.flow('00000000-0000-4000-8000-00000000f001', '00000000-0000-4000-8000-000000000501', '00000000-0000-4000-8000-000000000401',
  '10.77.0.10', '203.0.113.40', 443, 'https', 'upload.fichiers-partage.example', 1, 'deny', NULL, NULL, 'default-deny', 'implicit',
  false, false, false, 412, '00000000-0000-4000-8000-0000000000c1');
-- Allowed traffic of the demo agents over the last hour.
SELECT pg_temp.flow(('00000000-0000-4000-8000-0000000' || lpad(to_hex(4096 + i), 5, '0'))::uuid,
  CASE i % 3 WHEN 0 THEN '00000000-0000-4000-8000-000000000501'::uuid WHEN 1 THEN '00000000-0000-4000-8000-000000000502'::uuid ELSE '00000000-0000-4000-8000-000000000503'::uuid END,
  CASE i % 3 WHEN 2 THEN '00000000-0000-4000-8000-000000000402'::uuid ELSE '00000000-0000-4000-8000-000000000401'::uuid END,
  CASE i % 3 WHEN 0 THEN '10.77.0.10' WHEN 1 THEN '10.77.0.11' ELSE '10.77.0.12' END,
  CASE i % 4 WHEN 0 THEN '160.79.104.10' WHEN 1 THEN '140.82.121.6' ELSE '198.51.100.20' END, 443, 'https',
  CASE i % 4 WHEN 0 THEN 'api.anthropic.com' WHEN 1 THEN CASE i % 3 WHEN 2 THEN 'allowed.example' ELSE 'api.github.com' END ELSE 'allowed.example' END,
  (i * 7) % 60 + 2, 'allow',
  CASE i % 4 WHEN 0 THEN '00000000-0000-4000-8000-000000000604'::uuid WHEN 1 THEN CASE i % 3 WHEN 2 THEN '00000000-0000-4000-8000-000000000621'::uuid ELSE '00000000-0000-4000-8000-000000000611'::uuid END
       ELSE CASE i % 3 WHEN 2 THEN '00000000-0000-4000-8000-000000000621'::uuid ELSE '00000000-0000-4000-8000-000000000612'::uuid END END,
  CASE i % 4 WHEN 0 THEN 5 WHEN 1 THEN CASE i % 3 WHEN 2 THEN 6 ELSE 7 END ELSE CASE i % 3 WHEN 2 THEN 6 ELSE 8 END END,
  CASE i % 4 WHEN 0 THEN 'Fournisseurs LLM' WHEN 1 THEN CASE i % 3 WHEN 2 THEN 'API autorisée' ELSE 'GitHub API' END ELSE 'API autorisée' END,
  CASE i % 4 WHEN 0 THEN 'baseline' ELSE 'zone' END,
  false, false, i % 4 = 0, 800 + (i * 113) % 9000, NULL)
FROM generate_series(1, 90) AS i;
-- Other denials: cloud metadata (baseline) and an internal SSH attempt.
SELECT pg_temp.flow('00000000-0000-4000-8000-00000000f002', '00000000-0000-4000-8000-000000000503', '00000000-0000-4000-8000-000000000402',
  '10.77.0.12', '169.254.169.254', 80, 'http', NULL, 6, 'deny', '00000000-0000-4000-8000-000000000601', 1, 'Métadonnées cloud', 'baseline',
  false, false, false, 312, NULL);
SELECT pg_temp.flow('00000000-0000-4000-8000-00000000f003', '00000000-0000-4000-8000-000000000502', '00000000-0000-4000-8000-000000000401',
  '10.77.0.11', '10.78.0.31', 22, 'ssh', NULL, 18, 'deny', NULL, NULL, 'default-deny', 'implicit',
  true, false, false, 0, NULL);

-- HTTP exchange of the denied upload (metadata only: contents are sealed and absent here).
INSERT INTO http_events (id, flow_id, gateway_id, agent_id, at, url, event, content)
VALUES ('00000000-0000-4000-8000-0000000000d1', '00000000-0000-4000-8000-00000000f001', '00000000-0000-4000-8000-0000000000a1',
        '00000000-0000-4000-8000-000000000501', now() - interval '60 seconds', 'https://upload.fichiers-partage.example/v1/files/rapport-q3.pdf',
        jsonb_build_object('id', '00000000-0000-4000-8000-0000000000d1', 'flow_id', '00000000-0000-4000-8000-00000000f001',
          'gateway_id', '00000000-0000-4000-8000-0000000000a1', 'agent_id', '00000000-0000-4000-8000-000000000501',
          'at', to_char((now() - interval '60 seconds') AT TIME ZONE 'UTC', 'YYYY-MM-DD"T"HH24:MI:SS.MS"Z"'),
          'method', 'PUT', 'url', 'https://upload.fichiers-partage.example/v1/files/rapport-q3.pdf',
          'host', 'upload.fichiers-partage.example', 'request_headers', '[]'::jsonb, 'response_headers', '[]'::jsonb,
          'status', 403, 'findings', '[]'::jsonb, 'websocket', false), NULL)
ON CONFLICT DO NOTHING;

INSERT INTO alerts (id, at, kind, severity, agent_id, gateway_id, source, event)
VALUES ('00000000-0000-4000-8000-0000000000e1', now() - interval '6 minutes', 'cloud_metadata', 'critical',
        '00000000-0000-4000-8000-000000000503', '00000000-0000-4000-8000-0000000000a1', 'gateway',
        jsonb_build_object('id', '00000000-0000-4000-8000-0000000000e1',
          'at', to_char((now() - interval '6 minutes') AT TIME ZONE 'UTC', 'YYYY-MM-DD"T"HH24:MI:SS.MS"Z"'),
          'kind', 'cloud_metadata', 'severity', 'critical', 'agent_id', '00000000-0000-4000-8000-000000000503',
          'summary', 'acme-bot a tenté de joindre 169.254.169.254 (métadonnées cloud)', 'details', '{}'::jsonb))
ON CONFLICT DO NOTHING;
