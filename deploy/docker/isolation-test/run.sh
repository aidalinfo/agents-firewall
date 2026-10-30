#!/usr/bin/env bash
# Real network isolation test (ENF-07): proves that an enrolled agent cannot leave without the
# gateway, even when it ignores proxy settings. Needs Docker with Compose v2.
#   deploy/docker/isolation-test/run.sh          # build, run every check, tear down
#   KEEP=1 deploy/docker/isolation-test/run.sh   # leave the stack up for inspection
set -uo pipefail
cd "$(dirname "$0")"
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
check "agent: proxy ignored, denied domain -> explicit 403" ok \
  agent sh -c "out=\$(curl -s -m 8 --noproxy '*' -w ' %{http_code}' http://denied.example/); echo \"\$out\"; case \"\$out\" in *'blocked by agents-firewall: denied.example not allowed for test-bot (rule default-deny)'*403) exit 0;; *) exit 1;; esac"
check "agent: proxy ignored, allowed domain -> 200" ok \
  agent sh -c "out=\$(curl -s -m 8 --noproxy '*' -w ' %{http_code}' http://allowed.example/); echo \"\$out\"; case \"\$out\" in *hello-from-web*200) exit 0;; *) exit 1;; esac"
check "agent: HTTPS to a denied domain -> explicit 403 over inspected TLS" ok \
  agent sh -c "out=\$(curl -s -m 8 --noproxy '*' --resolve denied.example:443:198.18.99.20 -w ' %{http_code}' https://denied.example/); echo \"\$out\"; case \"\$out\" in *'blocked by agents-firewall'*403) exit 0;; *) exit 1;; esac"
check "agent: nc to an arbitrary external TCP port is refused" ko \
  agent sh -c "printf 'ping\n' | nc -w 5 198.18.99.20 4444 | grep -q ping"
check "agent: dig @8.8.8.8 for a denied name gets no answer (REFUSED)" ok \
  agent sh -c "out=\$(dig +tries=1 +time=4 @8.8.8.8 denied.example A); echo \"\$out\" | grep -E 'status|ANSWER:'; echo \"\$out\" | grep -q 'status: REFUSED' && echo \"\$out\" | grep -q 'ANSWER: 0'"
check "agent: dig for an allowed name is answered by the gateway's resolver" ok \
  agent sh -c "dig +short +tries=1 +time=4 @8.8.8.8 allowed.example A | grep -x 198.18.99.20"
check "agent: cannot change its route (no NET_ADMIN)" ko \
  agent ip route replace default via 10.99.0.20
check "agent: the only path out is the gateway" ok \
  agent sh -c "ip route get 198.18.99.20 | tee /dev/stderr | grep -q 'via 10.99.0.2'"

echo "== stopping the gateway"
dc stop gateway >/dev/null
check "gateway down: no network at all (fail closed)" ko \
  agent curl -s -m 6 --noproxy '*' http://allowed.example/
check "gateway down: no DNS" ko \
  agent dig +short +tries=1 +time=3 @8.8.8.8 allowed.example A

echo "== result: $pass passed, $fail failed"
[ "$fail" -eq 0 ]
