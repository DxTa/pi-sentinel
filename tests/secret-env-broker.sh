#!/usr/bin/env bash
set -euo pipefail

SCRIPT_DIR="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd)"
RUNNER="$SCRIPT_DIR/../bin/bwrap-run.sh"
TEST_DIR="$(mktemp -d /tmp/pi-secret-env-XXXXXX)"
trap 'rm -rf "$TEST_DIR"' EXIT
cd "$TEST_DIR"
git init -q

export PI_TEST_SECRET_TOKEN="super-secret-value"

out="$($RUNNER --cwd "$TEST_DIR" --repo-root "$TEST_DIR" --network off -- bash -lc 'printf "${PI_TEST_SECRET_TOKEN-unset}"')"
if [[ "$out" != "unset" ]]; then
  printf 'FAIL secret env leaked without --secret-env: <%s>\n' "$out" >&2
  exit 1
fi
printf 'PASS secret env absent by default\n'

out="$($RUNNER --cwd "$TEST_DIR" --repo-root "$TEST_DIR" --network off --secret-env PI_TEST_SECRET_TOKEN -- bash -lc 'printf "$PI_TEST_SECRET_TOKEN"')"
if [[ "$out" != "super-secret-value" ]]; then
  printf 'FAIL secret env not passed with --secret-env: <%s>\n' "$out" >&2
  exit 1
fi
printf 'PASS secret env passed only when requested\n'

if "$RUNNER" --cwd "$TEST_DIR" --repo-root "$TEST_DIR" --network off --secret-env PI_MISSING_SECRET -- bash -lc 'test -z "${PI_MISSING_SECRET-}"'; then
  printf 'PASS missing secret env stays absent\n'
else
  printf 'FAIL missing secret env was unexpectedly set\n' >&2
  exit 1
fi
