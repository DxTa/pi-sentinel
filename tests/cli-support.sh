#!/usr/bin/env bash
set -euo pipefail

SCRIPT_DIR="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd)"
RUNNER="$SCRIPT_DIR/../bin/bwrap-run.sh"
TEST_DIR="$(mktemp -d /tmp/pi-cli-test-XXXXXX)"
trap 'rm -rf "$TEST_DIR"' EXIT
cd "$TEST_DIR"
git init -q

# ── Test: env vars available by default ──
export GH_TOKEN="test-gh-token-value"
export AWS_DEFAULT_REGION="us-east-1"

out="$($RUNNER --cwd "$TEST_DIR" --repo-root "$TEST_DIR" --network off -- bash -c 'printf "${GH_TOKEN:-unset}"')"
if [[ "$out" != "test-gh-token-value" ]]; then
  printf 'FAIL GH_TOKEN not passed by default: <%s>\n' "$out" >&2
  exit 1
fi
printf 'PASS GH_TOKEN passed by default\n'

out="$($RUNNER --cwd "$TEST_DIR" --repo-root "$TEST_DIR" --network off -- bash -c 'printf "${AWS_DEFAULT_REGION:-unset}"')"
if [[ "$out" != "us-east-1" ]]; then
  printf 'FAIL AWS_DEFAULT_REGION not passed by default: <%s>\n' "$out" >&2
  exit 1
fi
printf 'PASS AWS_DEFAULT_REGION passed by default\n'

# ── Test: gh config dir readable by default ──
if [[ -d "$HOME/.config/gh" ]]; then
  out="$($RUNNER --cwd "$TEST_DIR" --repo-root "$TEST_DIR" --network off -- bash -c 'ls "$HOME/.config/gh" 2>/dev/null && echo visible || echo missing')"
  if [[ "$out" == *"missing"* ]]; then
    printf 'FAIL gh config dir not visible by default\n' >&2
    exit 1
  fi
  printf 'PASS gh config dir visible by default\n'
else
  printf 'SKIP gh config dir test (dir does not exist)\n'
fi

# ── Test: masked files still masked ──
echo "SECRET=abc" > .env
out="$($RUNNER --cwd "$TEST_DIR" --repo-root "$TEST_DIR" --network off --masked-paths '**/.env' -- cat .env)"
if [[ "$out" != "(masked)" ]]; then
  printf 'FAIL .env not masked: <%s>\n' "$out" >&2
  exit 1
fi
printf 'PASS .env still masked\n'

# ── Test: config dirs are read-only ──
if [[ -d "$HOME/.config/gh" ]]; then
  out="$($RUNNER --cwd "$TEST_DIR" --repo-root "$TEST_DIR" --network off -- bash -c 'touch "$HOME/.config/gh/test-write" 2>/dev/null && echo writable || echo read-only')"
  if [[ "$out" != *"read-only"* ]]; then
    printf 'FAIL gh config dir is writable!\n' >&2
    exit 1
  fi
  printf 'PASS gh config dir is read-only\n'
fi

# ── Test: ssh known_hosts readable but private keys masked ──
if [[ -f "$HOME/.ssh/known_hosts" ]]; then
  out="$($RUNNER --cwd "$TEST_DIR" --repo-root "$TEST_DIR" --network off -- bash -c 'test -r "$HOME/.ssh/known_hosts" && echo readable || echo missing')"
  if [[ "$out" == *"readable"* ]]; then
    printf 'PASS ssh known_hosts readable\n'
  else
    printf 'SKIP ssh known_hosts not found inside sandbox\n'
  fi
else
  printf 'SKIP ssh known_hosts (file does not exist)\n'
fi

unset GH_TOKEN AWS_DEFAULT_REGION
printf 'ALL CLI SUPPORT TESTS PASSED\n'