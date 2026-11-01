#!/usr/bin/env bash
# Entry point of the deployment tests: static checks, netinit bypass tests, inbound ports of an enrolled agent,
# demo world.
# Usage: deploy/tests/run.sh [static|enroll|netinit|ingress|world|images|all]   (default: all but images)
set -euo pipefail
here="$(cd "$(dirname "$0")" && pwd)"
what="${1:-all}"
rc=0
run() { echo; echo "######## $1"; "$here/$1.sh" || rc=1; }
case "$what" in
  static) run static ;;
  netinit) run netinit ;;
  ingress) run ingress ;;
  world) run demo-world ;;
  images) run images ;;
  enroll) run enroll-sync ;;
  all) run static; run enroll-sync; run netinit; run ingress; run demo-world ;;
  *) echo "usage: $0 [static|enroll|netinit|ingress|world|images|all]"; exit 2 ;;
esac
exit "$rc"
