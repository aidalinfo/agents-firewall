#!/usr/bin/env bash
# Stops the demo. --purge also deletes volumes (database, gateway identity, PKI) and demo/.state.
# shellcheck source=demo/lib.sh
. "$(dirname "$0")/lib.sh"
purge=0
for a in "$@"; do
  case "$a" in
    --purge) purge=1 ;;
    -h | --help) sed -n '2p' "$0"; exit 0 ;;
    *) die "unknown option $a" ;;
  esac
done
# Agents enrolled by scenario 11 live in their own compose project.
if [ -f "$STATE_DIR/s11/docker-compose.yml" ]; then
  docker compose -p afw-demo-s11 -f "$STATE_DIR/s11/docker-compose.yml" down --remove-orphans >&2 || true
fi
if [ "$purge" = 1 ]; then
  dc --profile tools down -v --remove-orphans >&2
  rm -rf "$STATE_DIR"
  info "demo stopped, volumes and demo/.state deleted"
else
  dc --profile tools down --remove-orphans >&2
  info "demo stopped (volumes kept; demo/down.sh --purge to reset)"
fi
