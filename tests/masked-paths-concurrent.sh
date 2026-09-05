#!/usr/bin/env bash
set -euo pipefail

SCRIPT_DIR="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd)"
RUNNER="$SCRIPT_DIR/../bin/bwrap-run.sh"
TEST_DIR="$(mktemp -d /tmp/pi-mask-concurrent-XXXXXX)"
trap 'rm -rf "$TEST_DIR"' EXIT

cd "$TEST_DIR"
git init -q
printf 'SECRET=one\n' > .env

run_one() {
  "$RUNNER" --cwd "$TEST_DIR" --repo-root "$TEST_DIR" --network off \
    --masked-paths '**/.env' -- bash -lc 'cat .env >/dev/null; sleep 2; cat .env'
}

pids=()
for _ in $(seq 1 8); do
  run_one >"$TEST_DIR/out.$_" 2>"$TEST_DIR/err.$_" &
  pids+=("$!")
done

for pid in "${pids[@]}"; do
  wait "$pid"
done

for _ in $(seq 1 8); do
  actual="$(cat "$TEST_DIR/out.$_")"
  if [[ "$actual" != "(masked)" ]]; then
    printf 'FAIL concurrent run %s expected masked output, got <%s>\n' "$_" "$actual" >&2
    printf 'stderr: %s\n' "$(cat "$TEST_DIR/err.$_")" >&2
    exit 1
  fi
  if [[ -s "$TEST_DIR/err.$_" ]]; then
    printf 'FAIL concurrent run %s stderr not empty: %s\n' "$_" "$(cat "$TEST_DIR/err.$_")" >&2
    exit 1
  fi
done

printf 'PASS concurrent placeholder runs do not delete each other\n'
