#!/usr/bin/env bash
# Starts the local acceptance environment: builds the images locally (never pushed), starts the stack in
# order, registers the gateway with a one-time token, loads and installs the demo policy, starts the agents.
# Usage: demo/up.sh [--no-build] [--partial]
#   --partial  start whatever can be built (missing product images are listed, not fatal)
# shellcheck source=demo/lib.sh
. "$(dirname "$0")/lib.sh"

build=1; partial="${AFW_DEMO_PARTIAL:-0}"
for a in "$@"; do
  case "$a" in
    --no-build) build=0 ;;
    --partial) partial=1 ;;
    -h | --help) sed -n '2,6p' "$0"; exit 0 ;;
    *) die "unknown option $a" ;;
  esac
done
command -v docker >/dev/null || die "docker is required"
docker compose version >/dev/null 2>&1 || die "docker compose v2 is required"
command -v curl >/dev/null || die "curl is required"

# Markers of a previous run are stale if the volumes were deleted behind our back.
if ! docker volume inspect "${DEMO_PROJECT}_postgres-data" >/dev/null 2>&1; then
  rm -f "$STATE_DIR/gateway-registered" "$STATE_DIR/policy-installed" "$STATE_DIR/demo.env" "$STATE_DIR/ids.json"
fi

# --- 1. images ---------------------------------------------------------------------------------------
# service:image:source that must exist for the image to be buildable
IMAGES="demo-pki:afw-demo-tools:local:demo/tools/Dockerfile
afw-net-laurent-bot:afw-netinit:local:deploy/docker/Dockerfile.netinit
afw-api:afw-api:local:crates/afw-api/src/main.rs
gateway:afw-gateway:local:deploy/docker/Dockerfile.gateway
console:afw-console:local:console/Dockerfile
daniel-bot:afw-hermes-demo:local:integrations/hermes/demo/Dockerfile.demo"
missing=""
while IFS=: read -r svc img tag src; do
  if [ ! -e "$ROOT/$src" ]; then
    image_exists "$img:$tag" && { warn "$src missing, using existing image $img:$tag"; continue; }
    missing="$missing $img:$tag($src)"; continue
  fi
  if [ "$build" = 1 ]; then step "build $img:$tag"; dc build "$svc" >&2 || die "build of $img:$tag failed"; fi
done <<<"$IMAGES"
if [ "$build" = 1 ] && [ -e "$ROOT/crates/afw-cli/src/main.rs" ]; then
  step "build $AFW_CLI_IMAGE"
  docker build -q -t "$AFW_CLI_IMAGE" -f "$ROOT/deploy/docker/Dockerfile.cli" "$ROOT" >/dev/null || warn "CLI image build failed (scenarios fall back to curl)"
fi
if [ -n "$missing" ]; then
  warn "images that cannot be built yet (lots not merged):$missing"
  [ "$partial" = 1 ] || die "re-run with --partial to start the rest of the demo"
fi
have() { image_exists "$1"; }

# --- 2. control plane and simulated world ----------------------------------------------------------
world="demo-pki demo-dns fake-llm exfil allowed-api s3 internal-db"
step "start the simulated world: $world"
# shellcheck disable=SC2086
dc up -d --no-build --wait $world >&2
if have afw-api:local; then
  svcs="postgres afw-api"; have afw-console:local && svcs="$svcs console"
  step "start the control plane: $svcs"
  # shellcheck disable=SC2086
  dc up -d --no-build --wait $svcs >&2
  wait_api 120 || die "API not healthy on $AFW_API_URL"
else
  warn "no API image: control plane not started"
fi

# --- 3. gateway registration (one-time token, ENF-03) ----------------------------------------------
if have afw-gateway:local && api_healthy; then
  if [ ! -f "$STATE_DIR/gateway-registered" ]; then
    step "create a one-time registration token for demo-gw"
    AFW_GATEWAY_TOKEN="$(gateway_registration_token demo-gw)" || die "cannot create a registration token"
    export AFW_GATEWAY_TOKEN
  fi
  step "start the gateway"
  dc up -d --no-build gateway >&2
  for _ in $(seq 1 90); do
    gateways_json 2>/dev/null | jqx -e -s 'any(.[]; .name == "demo-gw" and .status == "online")' >/dev/null 2>&1 && break
    sleep 1
  done
  gateways_json | jqx -e -s 'any(.[]; .name == "demo-gw" and .status == "online")' >/dev/null 2>&1 ||
    die "gateway demo-gw is not online (docker compose -p $DEMO_PROJECT logs gateway)"
  touch "$STATE_DIR/gateway-registered"
else
  warn "gateway not started (no image or no API)"
fi

# --- 4. demo policy ---------------------------------------------------------------------------------
if api_healthy && [ ! -f "$STATE_DIR/policy-installed" ]; then
  step "load the demo policy (demo/policy/demo-policy.json)"
  session_open
  load_policy "$DEMO_DIR/policy/demo-policy.json"
  rev1="$(publish "Démo : politique initiale (zone clients en observation)")"
  info "published revision $rev1"
  install "$rev1"
  have afw-gateway:local && { wait_installed "$rev1" 90 || die "revision $rev1 not installed"; }
  # The clients zone starts in Observe (EF-12) and is switched to Enforce once its traffic is known.
  session_open
  set_zone_mode "$(did 402)" enforce
  rev2="$(publish "Démo : zone clients en application")"
  install "$rev2"
  have afw-gateway:local && { wait_installed "$rev2" 90 || die "revision $rev2 not installed"; }
  info "installed revision $rev2"
  touch "$STATE_DIR/policy-installed"
fi

# --- 5. agents ---------------------------------------------------------------------------------------
if api_healthy && [ ! -s "$STATE_DIR/demo.env" ]; then
  step "create the Hermes plugin token of daniel-bot"
  if tok="$(agent_plugin_token "$(agent_id daniel-bot)")" && [ -n "$tok" ]; then
    printf 'AFW_AGENT_TOKEN=%s\n' "$tok" >"$STATE_DIR/demo.env"; chmod 600 "$STATE_DIR/demo.env"
  else
    warn "no plugin token for daniel-bot (enrollments API): tool calls will not be correlated"
  fi
fi
agents="afw-net-laurent-bot laurent-bot afw-net-acme-bot acme-bot"
have afw-hermes-demo:local && agents="afw-net-daniel-bot daniel-bot $agents"
step "start the agents: $agents"
# shellcheck disable=SC2086
dc up -d --no-build $agents >&2 ||
  die "agents not started: their afw-net container waits for the gateway CA (docker compose -p $DEMO_PROJECT logs gateway afw-net-laurent-bot)"

if have afw-gateway:local; then
  for _ in $(seq 1 30); do agent_sh laurent-bot 'test -s /afw-ca/bundle.pem' 2>/dev/null && break; sleep 1; done
  agent_sh laurent-bot 'test -s /afw-ca/bundle.pem' 2>/dev/null ||
    warn "no CA bundle in the agents: the gateway did not export its inspection CA (/var/lib/afw/public/inspection-ca.crt)"
fi

cat >&2 <<INFO

agents-firewall demo is up.
  Console     http://localhost:3000   (token: $AFW_DEMO_ADMIN_TOKEN)
  API         $AFW_API_URL$API
  Scenarios   demo/scenarios/run-all.sh   (results in demo/.state/results.md)
  Stop        demo/down.sh [--purge]
INFO
