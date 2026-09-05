#!/usr/bin/env bash
set -euo pipefail

SCRIPT_DIR="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd)"
RUNNER="$SCRIPT_DIR/../bin/bwrap-run.sh"
TEST_DIR="$(mktemp -d /tmp/pi-mask-int-XXXXXX)"
trap 'rm -rf "$TEST_DIR"' EXIT

cd "$TEST_DIR"
git init -q
printf 'SECRET_KEY=topsecret123\n' > .env
printf 'CERT_SECRET=hidden\n' > certfile.pem
printf 'KEY_SECRET=hidden\n' > keyfile.key
mkdir -p src
printf "console.log('safe')\n" > src/index.js
FAKE_HOME="$TEST_DIR/fake-home"
mkdir -p "$FAKE_HOME/.ssh"
printf 'SSH_PRIVATE_KEY_SECRET\n' > "$FAKE_HOME/.ssh/id_test"

run_sandbox() {
  "$RUNNER" --cwd "$TEST_DIR" --repo-root "$TEST_DIR" --network off \
    --masked-paths '**/.env,**/*.pem,**/*.key,~/.ssh/*' -- "$@"
}

assert_eq() {
  local name="$1" expected="$2" actual="$3"
  if [[ "$actual" != "$expected" ]]; then
    printf 'FAIL %s\nexpected: <%s>\nactual: <%s>\n' "$name" "$expected" "$actual" >&2
    exit 1
  fi
  printf 'PASS %s\n' "$name"
}

assert_contains() {
  local name="$1" needle="$2" haystack="$3"
  if [[ "$haystack" != *"$needle"* ]]; then
    printf 'FAIL %s\nmissing: <%s>\noutput: <%s>\n' "$name" "$needle" "$haystack" >&2
    exit 1
  fi
  printf 'PASS %s\n' "$name"
}

out="$(run_sandbox cat .env)"
assert_eq 'cat .env masked' '(masked)' "$out"

out="$(run_sandbox cat certfile.pem)"
assert_eq 'cat certfile.pem masked' '(masked)' "$out"

out="$(run_sandbox cat keyfile.key)"
assert_eq 'cat keyfile.key masked' '(masked)' "$out"

out="$(run_sandbox cat src/index.js)"
assert_eq 'cat non-masked file real content' "console.log('safe')" "$out"

out="$(run_sandbox wc -c .env | awk '{print $1}')"
assert_eq 'masked file byte count' '9' "$out"

out="$(run_sandbox ls -la)"
assert_contains 'ls lists .env' '.env' "$out"
assert_contains 'ls lists certfile.pem' 'certfile.pem' "$out"
assert_contains 'ls lists keyfile.key' 'keyfile.key' "$out"

out="$(run_sandbox find . -name '.env')"
assert_eq 'find sees .env filename' './.env' "$out"

if run_sandbox grep -r 'SECRET_KEY' . >/tmp/pi-mask-grep-secret.out 2>&1; then
  printf 'FAIL grep secret should not match masked .env\noutput: <%s>\n' "$(cat /tmp/pi-mask-grep-secret.out)" >&2
  exit 1
else
  if [[ -s /tmp/pi-mask-grep-secret.out ]]; then
    printf 'FAIL grep secret produced output despite non-match\noutput: <%s>\n' "$(cat /tmp/pi-mask-grep-secret.out)" >&2
    exit 1
  fi
  printf 'PASS grep does not expose secret content\n'
fi

out="$(run_sandbox grep -r '(masked)' . || true)"
assert_contains 'grep can indicate masked files' '.env:(masked)' "$out"
assert_contains 'grep can indicate masked pem' 'certfile.pem:(masked)' "$out"
assert_contains 'grep can indicate masked key' 'keyfile.key:(masked)' "$out"

out="$(HOME="$FAKE_HOME" run_sandbox cat "$FAKE_HOME/.ssh/id_test")"
assert_eq 'home-level masked path outside repo is masked' '(masked)' "$out"

out="$($RUNNER --cwd "$TEST_DIR" --repo-root "$TEST_DIR" --network off \
  --masked-paths '**/.env,**/*.pem,**/*.key' \
  --approved-unmask-path "$TEST_DIR/.env" --ro-bind "$TEST_DIR/.env" \
  -- cat .env)"
assert_eq 'approved unmask shows real content' 'SECRET_KEY=topsecret123' "$out"

PLACEHOLDER_ROOT="$HOME/.pi/agent/tmp/pi-mask-placeholders"
rm -rf "$PLACEHOLDER_ROOT" 2>/dev/null || true
run_sandbox true
if find "$PLACEHOLDER_ROOT" -mindepth 1 -maxdepth 1 -type d -print -quit 2>/dev/null | grep -q .; then
  printf 'FAIL placeholder directory leaked\n%s\n' "$(find "$PLACEHOLDER_ROOT" -mindepth 1 -maxdepth 1 -type d -print 2>/dev/null)" >&2
  exit 1
else
  printf 'PASS placeholder cleanup after normal exit\n'
fi

printf 'ALL MASKED PATH TESTS PASSED\n'
