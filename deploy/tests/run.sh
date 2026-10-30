#!/usr/bin/env bash
# Entry point of the deployment tests: static checks, netinit bypass tests, demo world.
# Usage: deploy/tests/run.sh [static|netinit|world|images|all]   (default: all but images)
set -euo pipefail
here="$(cd "$(dirname "$0")" && pwd)"
what="${1:-all}"
rc=0
run() { echo; echo "######## $1"; "$here/$1.sh" || rc=1; }
case "$what" in
  static) run static ;;
  netinit) run netinit ;;
  world) run demo-world ;;
  images) run images ;;
  all) run static; run netinit; run demo-world ;;
  *) echo "usage: $0 [static|netinit|world|images|all]"; exit 2 ;;
esac
exit "$rc"
