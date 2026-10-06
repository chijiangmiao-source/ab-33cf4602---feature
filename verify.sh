#!/usr/bin/env bash
# One-shot verification: build the image, run the lock-rule unit tests and
# the commit/reject HTTP smoke inside Docker Compose, then exit with the
# verify container's status code.
set -uo pipefail
cd "$(dirname "$0")"

cleanup() {
  docker compose down -v --remove-orphans >/dev/null 2>&1 || true
}
trap cleanup EXIT

docker compose up --build --exit-code-from verify verify
exit $?
