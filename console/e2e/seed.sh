#!/usr/bin/env bash
# Seeds the e2e stack with demonstration data, through the public API where it exists:
#   1. imports demo/policy/demo-policy.json into a session and publishes it (revision 1);
#   2. inserts gateways, flows, HTTP exchanges, tool calls and alerts with fixtures/logs.sql
#      (gateway events normally arrive over mTLS from a real gateway: out of scope here).
# Usage: seed.sh <api base url> <admin token> <psql command…>
set -euo pipefail
api="$1"; token="$2"; shift 2
here="$(cd "$(dirname "$0")" && pwd)"
policy="$here/../../demo/policy/demo-policy.json"

call() { # method path [body]
  curl -fsS -X "$1" "$api/api/v1$2" -H "authorization: Bearer $token" -H 'content-type: application/json' \
    -H 'x-afw-interface: api' ${3:+--data-binary "$3"}
}

if [ "$(call GET /revisions | grep -c '"number"')" -eq 0 ]; then
  session=$(call POST /sessions "{\"name\":\"Import de la politique de démonstration\"}" | python3 -c "import json,sys; print(json.load(sys.stdin)[\"id\"])")
  call POST "/sessions/$session/import" "@$policy" > /dev/null
  call POST "/sessions/$session/publish" '{"comment":"Politique de démonstration"}' > /dev/null
  echo "seed: demo policy published"
fi
"$@" < "$here/fixtures/logs.sql"
echo "seed: logs inserted"
