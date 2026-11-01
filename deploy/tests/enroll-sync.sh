#!/usr/bin/env bash
# afw-enroll is the source of truth of the enrolled format (ADR 0023): this test regenerates, with the
# afw-enroll crate, (1) the netinit body of deploy/docker/netinit.sh (afw_enroll::netinit_script) and
# (2) demo/docker-compose.agents.yml (afw_enroll::enroll_compose of demo/agents.base.yml), and fails if
# the committed files differ. `--write` updates them.
# shellcheck source=deploy/tests/common.sh
. "$(dirname "$0")/common.sh"
cd "$ROOT"
write=0; [ "${1:-}" = --write ] && write=1
gen() { AFW_DOCKER_ARGS="-e CARGO_TARGET_DIR=/w/target/demo-enroll" scripts/cargo.sh run -q \
  --manifest-path deploy/tools/demo-enroll/Cargo.toml -- "$@"; }
tmp="$(mktemp -d)"; trap 'rm -rf "$tmp"' EXIT

section "generate with afw-enroll"
gen netinit >"$tmp/script.sh" 2>"$tmp/err" || { cat "$tmp/err"; ko "netinit_script generation"; finish; }
gen compose demo/agents.base.yml >"$tmp/agents.yml" 2>"$tmp/err" || { cat "$tmp/err"; ko "enroll_compose generation"; finish; }
ok "generated netinit_script and the enrolled agents"

# The image runs the same script with the addresses taken from the environment.
sed -e "s/^GW='[^']*'\$/GW=\"\$AFW_GATEWAY_IP\"/" -e "s/^ME='[^']*'\$/ME=\"\$AFW_AGENT_IP\"/" "$tmp/script.sh" >"$tmp/body.sh"
grep -q '^GW="\$AFW_GATEWAY_IP"$' "$tmp/body.sh" && grep -q '^ME="\$AFW_AGENT_IP"$' "$tmp/body.sh" ||
  { ko "netinit_script no longer starts with GW='…' / ME='…' (update this test)"; finish; }
begin='# --- BEGIN afw_enroll::netinit_script (generated, do not edit) ---'
end='# --- END afw_enroll::netinit_script ---'
current_body() { awk -v b="$begin" -v e="$end" '$0 == e {p = 0} p {print} $0 == b {p = 1}' deploy/docker/netinit.sh; }

if [ "$write" = 1 ]; then
  { awk -v b="$begin" '{print} $0 == b {exit}' deploy/docker/netinit.sh; cat "$tmp/body.sh"; echo "$end"; } >"$tmp/netinit.sh"
  cat "$tmp/netinit.sh" >deploy/docker/netinit.sh
  cp "$tmp/agents.yml" demo/docker-compose.agents.yml
  ok "deploy/docker/netinit.sh and demo/docker-compose.agents.yml updated"
fi

section "compare with the committed files"
check "deploy/docker/netinit.sh runs afw_enroll::netinit_script verbatim" diff -u "$tmp/body.sh" <(current_body)
check "demo/docker-compose.agents.yml is the afw-enroll output" diff -u "$tmp/agents.yml" demo/docker-compose.agents.yml
finish
