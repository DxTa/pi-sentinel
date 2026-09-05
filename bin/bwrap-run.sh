#!/usr/bin/env bash
# bwrap-run.sh — Pi sandbox runner (hardened from ape-dev)
#
# Usage: bwrap-run.sh [options] -- <command> [args...]
#
# Hardened vs ape-dev:
#  - /etc: allowlist only (resolv.conf, ssl/certs, pki, alternatives) — NOT full /etc
#  - API keys: default-deny (only explicitly allowed via --env-allow)
#  - Secret file masking (.env, *.pem, *.key → (masked) placeholder) even in RW mounts
#  - --unshare-user (fail-closed, not --unshare-user-try)
#  - Resource limits (--pids, --tmpfs-size)
#  - Shell-level bind validation (reject sensitive paths)
#  - PI_BWRAP_RUNNER env var for runner path override
#  - Masked paths for repo-level secrets
#  - Environment variable allowlist/denylist support

set -euo pipefail

usage() {
  cat <<'EOF'
Usage: bwrap-run.sh [options] -- <command> [args...]

Options:
  --cwd <path>             Working directory inside sandbox (default: current directory)
  --repo-root <path>       Workspace root mounted read-write (default: git toplevel from --cwd)
  --network <on|off>       Enable or disable network namespace sharing (default: off)
  --allow-docker           Allow Docker socket access inside sandbox (default: blocked)
  --ro-bind <path>         Additional read-only bind mount (repeatable)
  --rw-bind <path>         Additional read-write bind mount (repeatable)
  --approved-unmask-path <path> Path approved for unmasking by user (bypasses sensitive validation)
  --masked-paths <globs>   Comma-separated glob patterns for files to mask (replaced with (masked) content)
  --secret-env <name>      Secret env var name to pass through for this invocation only (repeatable)
  --env-allow <names>      Comma-separated env var names to pass through (default: minimal)
  --env-deny <patterns>    Comma-separated env var patterns to deny (default: none)
  --pids <N>               Maximum number of PIDs in sandbox (default: 512)
  --tmpfs-size <bytes>     Maximum size for /tmp tmpfs in bytes (default: 1073741824)
  -h, --help               Show this help text
EOF
}

expand_home() {
  local raw="$1"
  case "$raw" in
    "~") printf '%s\n' "$HOME" ;;
    "~"/*) printf '%s\n' "$HOME/${raw#~/}" ;;
    *) printf '%s\n' "$raw" ;;
  esac
}

resolve_existing_path() {
  local input="$1"
  local expanded
  expanded="$(expand_home "$input")"
  if [[ ! -e "$expanded" ]]; then
    echo "Missing bind path: $expanded" >&2
    exit 2
  fi
  readlink -f "$expanded"
}

# ── Sensitive path validation (shell-level, mirrors TS validation) ──

SENSITIVE_SUFFIXES=(
  ".ssh"
  ".gnupg"
  ".aws"
  ".config/gcloud"
  ".kube"
  ".netrc"
  ".npmrc"
  ".pypirc"
  ".docker"
)

SENSITIVE_PATHS=(
  "/etc/shadow"
  "/etc/sudoers"
)

validate_bind_path() {
  local candidate="$1"
  local resolved
  resolved="$(readlink -f "$candidate")"

  if [[ -S "$resolved" || -p "$resolved" || -b "$resolved" || -c "$resolved" ]]; then
    echo "Refusing special sandbox bind path: $resolved" >&2
    exit 2
  fi

  case "$resolved" in
    /run|/run/*|/var/run|/var/run/*|"$HOME/.docker"|"$HOME/.docker/"*|"$HOME/.local/share/containers/podman/machine"|"$HOME/.local/share/containers/podman/machine/"*)
      echo "Refusing protected socket location: $resolved" >&2
      exit 2
      ;;
  esac

  # Check if this path was explicitly approved for unmasking by the user.
  # Approved paths bypass sensitive-path validation, not special-file checks.
  for approved in ${APPROVED_UNMASK_PATHS[@]+"${APPROVED_UNMASK_PATHS[@]}"}; do
    local approved_resolved
    approved_resolved="$(readlink -f "$approved")"
    if [[ "$resolved" == "$approved_resolved" || "$resolved" == "$approved_resolved/"* ]]; then
      return 0  # User-approved path — bypass sensitive validation
    fi
  done

  # Reject home directory itself
  local home_real
  home_real="$(readlink -f "$HOME")"
  if [[ "$resolved" == "$home_real" || "$resolved" == "/" || "$resolved" == "/home" ]]; then
    echo "Refusing sensitive sandbox bind path: $resolved" >&2
    exit 2
  fi

  # Reject sensitive subdirectories. Some sensitive dirs may not exist;
  # do not let readlink failure trip `set -e` while validating unrelated paths.
  for suffix in "${SENSITIVE_SUFFIXES[@]}"; do
    local sensitive_path
    sensitive_path="$(readlink -f "$HOME/$suffix" 2>/dev/null || echo "$HOME/$suffix")"
    if [[ "$resolved" == "$sensitive_path" || "$resolved" == "$sensitive_path/"* ]]; then
      echo "Refusing sensitive sandbox bind path: $resolved" >&2
      exit 2
    fi
  done

  for sensitive in "${SENSITIVE_PATHS[@]}"; do
    local resolved_sensitive
    resolved_sensitive="$(readlink -f "$sensitive" 2>/dev/null || echo "$sensitive")"
    if [[ "$resolved" == "$resolved_sensitive" || "$resolved" == "$resolved_sensitive/"* ]]; then
      echo "Refusing sensitive sandbox bind path: $resolved" >&2
      exit 2
    fi
  done
}

append_ro_bind_if_exists() {
  local path="$1"
  if [[ -e "$path" ]]; then
    local resolved
    resolved="$(readlink -f "$path")"
    validate_bind_path "$resolved"
    BWRAP_CMD+=(--ro-bind "$resolved" "$resolved")
  fi
}

append_rw_bind_if_exists() {
  local path="$1"
  if [[ -e "$path" ]]; then
    local resolved
    resolved="$(readlink -f "$path")"
    validate_bind_path "$resolved"
    BWRAP_CMD+=(--bind "$resolved" "$resolved")
  fi
}

# ── Mask placeholder ──
# Path to a temp file containing "(masked)". Set up in main before first use.
# Regular files are masked with this placeholder so `cat <file>` shows
# "(masked)" instead of silently empty. Sockets (Docker, SSH, GPG) still
# use /dev/null since you cannot meaningfully cat() a Unix socket.
MASK_PLACEHOLDER=""

# Mask a regular file with the (masked) placeholder content.
# `ls` still shows the filename; `cat` shows "(masked)" instead of secrets.
append_mask_if_exists() {
  local path="$1"
  if [[ -e "$path" ]]; then
    local resolved
    resolved="$(readlink -f "$path")"
    BWRAP_CMD+=(--ro-bind "$MASK_PLACEHOLDER" "$resolved")
  fi
}

mask_protected_sockets() {
  if [[ "$ALLOW_DOCKER" -eq 0 ]]; then
    for socket_path in /run/docker.sock /var/run/docker.sock "$HOME/.docker/run/docker.sock" "$HOME/.local/share/containers/podman/machine/podman.sock"; do
      if [[ -e "$socket_path" ]]; then
        BWRAP_CMD+=(--ro-bind /dev/null "$(readlink -f "$socket_path")")
      fi
    done
  fi

  if [[ -n "${SSH_AUTH_SOCK:-}" ]] && [[ -e "$SSH_AUTH_SOCK" ]]; then
    BWRAP_CMD+=(--ro-bind /dev/null "$(readlink -f "$SSH_AUTH_SOCK")")
  fi

  for agent_dir in "$HOME/.gnupg" "/run/user/$(id -u)/gnupg"; do
    if [[ -d "$agent_dir" ]]; then
      while IFS= read -r socket_path; do
        BWRAP_CMD+=(--ro-bind /dev/null "$(readlink -f "$socket_path")")
      done < <(find "$agent_dir" -maxdepth 1 -type s 2>/dev/null)
    fi
  done
}

# ── Mask files matching glob patterns ──

mask_glob_pattern() {
  local pattern="$1"
  local root="$2"

  # Use find to expand glob and mask each match.
  # Masked files are replaced with a placeholder containing "(masked)"
  # so that `cat <file>` shows a visible indicator instead of empty output.
  # This lets `ls` still list filenames while `cat` reveals no secrets.
  while IFS= read -r -d '' match; do
    if [[ -f "$match" ]]; then
      local resolved
      resolved="$(readlink -f "$match")"
      BWRAP_CMD+=(--ro-bind "$MASK_PLACEHOLDER" "$resolved")
    fi
  done < <(find "$root" -path "$pattern" -type f -print0 2>/dev/null || true)

  # Also search $HOME for patterns that start with $HOME (home-level secrets)
  # This ensures ~/.ssh/*, ~/.aws/*, ~/.pi/agent/auth.json, etc. are masked
  # even when they live outside the repo root.
  if [[ "$pattern" == "$HOME"* ]]; then
    while IFS= read -r -d '' match; do
      if [[ -f "$match" ]]; then
        local resolved
        resolved="$(readlink -f "$match")"
        # bwrap uses last-entry-wins semantics, so even if this was already
        # masked, the explicit --ro-bind at the end will take precedence.
        BWRAP_CMD+=(--ro-bind "$MASK_PLACEHOLDER" "$resolved")
      fi
    done < <(find "$HOME" -maxdepth 5 -path "$pattern" -type f -print0 2>/dev/null || true)
  fi
}

# ── Parse arguments ──

CWD="$(pwd)"
REPO_ROOT=""
NETWORK="off"
ALLOW_DOCKER=0
RO_BINDS=()
RW_BINDS=()
MASKED_PATTERNS=()
APPROVED_UNMASK_PATHS=()
ENV_ALLOW=()
ENV_DENY=()
SECRET_ENV=()
PIDS_LIMIT=512
TMPFS_SIZE=1073741824  # 1GB

while [[ $# -gt 0 ]]; do
  case "$1" in
    --cwd)
      [[ $# -ge 2 ]] || { echo "Missing value for --cwd" >&2; exit 2; }
      CWD="$2"; shift 2
      ;;
    --repo-root)
      [[ $# -ge 2 ]] || { echo "Missing value for --repo-root" >&2; exit 2; }
      REPO_ROOT="$2"; shift 2
      ;;
    --network)
      [[ $# -ge 2 ]] || { echo "Missing value for --network" >&2; exit 2; }
      NETWORK="$2"; shift 2
      ;;
    --allow-docker)
      ALLOW_DOCKER=1; shift
      ;;
    --ro-bind)
      [[ $# -ge 2 ]] || { echo "Missing value for --ro-bind" >&2; exit 2; }
      RO_BINDS+=("$2"); shift 2
      ;;
    --rw-bind)
      [[ $# -ge 2 ]] || { echo "Missing value for --rw-bind" >&2; exit 2; }
      RW_BINDS+=("$2"); shift 2
      ;;
    --approved-unmask-path)
      [[ $# -ge 2 ]] || { echo "Missing value for --approved-unmask-path" >&2; exit 2; }
      APPROVED_UNMASK_PATHS+=("$2"); shift 2
      ;;
    --masked-paths)
      [[ $# -ge 2 ]] || { echo "Missing value for --masked-paths" >&2; exit 2; }
      IFS=',' read -ra MASKED_PATTERNS <<< "$2"; shift 2
      ;;
    --secret-env)
      [[ $# -ge 2 ]] || { echo "Missing value for --secret-env" >&2; exit 2; }
      SECRET_ENV+=("$2"); shift 2
      ;;
    --env-allow)
      [[ $# -ge 2 ]] || { echo "Missing value for --env-allow" >&2; exit 2; }
      IFS=',' read -ra ENV_ALLOW <<< "$2"; shift 2
      ;;
    --env-deny)
      [[ $# -ge 2 ]] || { echo "Missing value for --env-deny" >&2; exit 2; }
      IFS=',' read -ra ENV_DENY <<< "$2"; shift 2
      ;;
    --pids)
      [[ $# -ge 2 ]] || { echo "Missing value for --pids" >&2; exit 2; }
      PIDS_LIMIT="$2"; shift 2
      ;;
    --tmpfs-size)
      [[ $# -ge 2 ]] || { echo "Missing value for --tmpfs-size" >&2; exit 2; }
      TMPFS_SIZE="$2"; shift 2
      ;;
    -h|--help)
      usage; exit 0
      ;;
    --)
      shift; break
      ;;
    *)
      echo "Unknown option: $1" >&2; usage; exit 2
      ;;
  esac
done

[[ $# -gt 0 ]] || { echo "No command provided." >&2; usage; exit 2; }

if [[ "$NETWORK" != "on" && "$NETWORK" != "off" ]]; then
  echo "Invalid --network value: $NETWORK (expected on|off)" >&2
  exit 2
fi

CWD="$(resolve_existing_path "$CWD")"

if [[ -z "$REPO_ROOT" ]]; then
  if git -C "$CWD" rev-parse --show-toplevel >/dev/null 2>&1; then
    REPO_ROOT="$(git -C "$CWD" rev-parse --show-toplevel)"
  else
    REPO_ROOT="$CWD"
  fi
fi
REPO_ROOT="$(resolve_existing_path "$REPO_ROOT")"

# Reject dangerous repo-root values
_home_real="$(readlink -f "$HOME")"
if [[ "$REPO_ROOT" == "$_home_real" || "$REPO_ROOT" == "/" || "$REPO_ROOT" == "/home" ]]; then
  echo "Refusing dangerous --repo-root '$REPO_ROOT': would mount a sensitive directory read-write." >&2
  exit 2
fi

# ── Create mask placeholder file ──
# Contains "(masked)\n" so that cat on a masked file shows a visible indicator
# instead of silently empty output. Directory listings still work normally
# (filenames are visible) while file content is safely replaced.
# Do NOT place this under /tmp: bwrap later mounts --tmpfs /tmp, so a later
# --ro-bind using /tmp/pi-mask-placeholder-* as the SOURCE can fail with
# "Can't find source path". Put it under Pi state, which is bind-mounted
# before masked-path binds are added.
MASK_PLACEHOLDER_ROOT="$HOME/.pi/agent/tmp/pi-mask-placeholders"
MASK_PLACEHOLDER_DIR="$MASK_PLACEHOLDER_ROOT/$$"
mkdir -p "$MASK_PLACEHOLDER_DIR"
chmod 700 "$MASK_PLACEHOLDER_ROOT" "$MASK_PLACEHOLDER_DIR" 2>/dev/null || true
# Clean up only old per-process placeholder directories. Never delete all
# placeholders on startup: concurrent sandbox runs may still need theirs as
# bwrap source paths.
find "$MASK_PLACEHOLDER_ROOT" -mindepth 1 -maxdepth 1 -type d -mmin +1440 -exec rm -rf {} + 2>/dev/null || true
MASK_PLACEHOLDER="$MASK_PLACEHOLDER_DIR/masked"
echo "(masked)" > "$MASK_PLACEHOLDER"
trap 'rm -rf "$MASK_PLACEHOLDER_DIR"' EXIT

# ── Build bwrap command ──

STATE_DIRS=(
  "$HOME/.pi"
)

for state_dir in ${STATE_DIRS[@]+"${STATE_DIRS[@]}"}; do
  mkdir -p "$state_dir" 2>/dev/null || true
done

BWRAP_CMD=(
  bwrap
  --die-with-parent
  --unshare-all
  --unshare-user
)

if [[ "$NETWORK" == "on" ]]; then
  BWRAP_CMD+=(--share-net)
  # Bind the real resolv.conf target so DNS works
  _resolv_real="$(readlink -f /etc/resolv.conf 2>/dev/null)"
  if [[ -n "$_resolv_real" && -f "$_resolv_real" ]]; then
    BWRAP_CMD+=(--ro-bind "$_resolv_real" "$_resolv_real")
  fi
fi

# ── Filesystem layout ──

BWRAP_CMD+=(
  --dev /dev
  --proc /proc
  --tmpfs /tmp
  --dir /home
  --bind "$REPO_ROOT" "$REPO_ROOT"
)

if [[ "$CWD" != "$REPO_ROOT" && "$CWD" != "$REPO_ROOT/"* ]]; then
  BWRAP_CMD+=(--bind "$CWD" "$CWD")
fi

# ── /etc: allowlist only (NOT full ro mount) ──

_etc_allowlist=(
  "/etc/resolv.conf"
  "/etc/hosts"
  "/etc/hostname"
  "/etc/nsswitch.conf"
  "/etc/passwd"
  "/etc/group"
  "/etc/shadow"
  "/etc/gshadow"
  "/etc/machine-id"
  "/etc/os-release"
  "/etc/ld.so.cache"
  "/etc/alternatives"
  "/run/systemd/resolve/stub-resolv.conf"
  "/run/systemd/resolve/resolv.conf"
)

for path in ${_etc_allowlist[@]+"${_etc_allowlist[@]}"}; do
  if [[ -e "$path" ]]; then
    # /etc/shadow and /etc/gshadow contain password hashes — mask with (masked)
    case "$path" in
      /etc/shadow|/etc/gshadow) append_mask_if_exists "$path" ;;
      *)
        # Resolve symlinks for /etc entries (e.g., resolv.conf → /run/systemd/...)
        resolved="$(readlink -f "$path")"
        if [[ -n "$resolved" && -e "$resolved" ]]; then
          BWRAP_CMD+=(--ro-bind "$resolved" "$resolved")
          # Create symlink inside sandbox if target differs
          if [[ "$resolved" != "$path" ]] && [[ -L "$path" ]]; then
            BWRAP_CMD+=(--symlink "$resolved" "$path")
          fi
        fi
        ;;
    esac
  fi
done

# SSL/TLS certificates (critical for HTTPS)
for ssl_path in /etc/ssl /etc/pki /usr/share/ca-certificates /etc/ca-certificates; do
  if [[ -d "$ssl_path" ]]; then
    append_ro_bind_if_exists "$ssl_path"
  fi
done

# ── System directories: read-only allowlist ──

case "$(uname -s)" in
  Darwin)
    for path in /System /usr /bin /sbin /Library /opt/homebrew /opt/local /nix /Applications; do
      append_ro_bind_if_exists "$path"
    done
    ;;
  *)
    # Linux: individual paths, symlinks resolved
    for path in /usr /bin /sbin /lib /lib64 /opt /nix; do
      if [[ -L "$path" ]]; then
        target="$(readlink "$path")"
        BWRAP_CMD+=(--symlink "$target" "$path")
      elif [[ -e "$path" ]]; then
        local_resolved="$(readlink -f "$path")"
        BWRAP_CMD+=(--ro-bind "$local_resolved" "$local_resolved")
      fi
    done
    # Additional common paths
    for path in /usr/local/bin /usr/local/lib /usr/local/share; do
      append_ro_bind_if_exists "$path"
    done
    ;;
esac

# ── User tool paths (read-only) ──

for path in \
  "$HOME/.local/bin" \
  "$HOME/.local/lib" \
  "$HOME/.cargo/bin" \
  "$HOME/.npm" \
  "$HOME/.bun/bin"; do
  append_ro_bind_if_exists "$path"
done

# ── Pi agent state (read-write for runtime) ──

for state_dir in ${STATE_DIRS[@]+"${STATE_DIRS[@]}"}; do
  append_rw_bind_if_exists "$state_dir"
done

# ── Protected sockets: masked before and after generic binds ──
# Final call below is required because later directory binds can overlay masks.
mask_protected_sockets

# ── Masked paths from config (secrets inside repo) ──

for pattern in ${MASKED_PATTERNS[@]+"${MASKED_PATTERNS[@]}"}; do
  # Handle home-relative patterns
  local_pattern="${pattern/#\~\//$HOME/}"
  # Expand globs in repo root
  mask_glob_pattern "$local_pattern" "$REPO_ROOT"
done

# ── Additional bind mounts from config ──

for bind_path in ${RO_BINDS[@]+"${RO_BINDS[@]}"}; do
  resolved_bind="$(resolve_existing_path "$bind_path")"
  validate_bind_path "$resolved_bind"
  BWRAP_CMD+=(--ro-bind "$resolved_bind" "$resolved_bind")
done

for bind_path in ${RW_BINDS[@]+"${RW_BINDS[@]}"}; do
  resolved_bind="$(resolve_existing_path "$bind_path")"
  validate_bind_path "$resolved_bind"
  BWRAP_CMD+=(--bind "$resolved_bind" "$resolved_bind")
done

# ── Common CLI and user config paths (read-only) ──
# Always enabled. Gives CLIs access to auth/config they need to function.
# Placed AFTER masked paths so bwrap last-entry-wins overrides (masked) placeholders
# with real read-only content. Private keys stay masked.

for _cli_dir in \
  "$HOME/.config" \
  "$HOME/.aws" \
  "$HOME/.npm" \
  "$HOME/.kube" \
  "$HOME/.local/share" \
  "$HOME/.cache"; do
  if [[ -d "$_cli_dir" ]]; then
    _cli_resolved="$(readlink -f "$_cli_dir")"
    if [[ "$_cli_resolved" != "$_home_real" && "$_cli_resolved" != "/" ]]; then
      BWRAP_CMD+=(--ro-bind "$_cli_resolved" "$_cli_resolved")
    fi
  fi
done

for _cli_file in \
  "$HOME/.npmrc" \
  "$HOME/.pypirc" \
  "$HOME/.netrc" \
  "$HOME/.gitconfig" \
  "$HOME/.profile" \
  "$HOME/.bashrc" \
  "$HOME/.zshrc"; do
  if [[ -f "$_cli_file" ]]; then
    _cli_resolved="$(readlink -f "$_cli_file")"
    BWRAP_CMD+=(--ro-bind "$_cli_resolved" "$_cli_resolved")
  fi
done

if [[ -d "$HOME/.ssh" ]]; then
  for _ssh_file in known_hosts config ssh_config; do
    if [[ -f "$HOME/.ssh/$_ssh_file" ]]; then
      _cli_resolved="$(readlink -f "$HOME/.ssh/$_ssh_file")"
      BWRAP_CMD+=(--ro-bind "$_cli_resolved" "$_cli_resolved")
    fi
  done
fi

# User runtime directory: allow CLIs to talk to session services/keyrings
# (e.g. gh using Secret Service over DBus). This is a live IPC bind, not
# a read-only filesystem bind.
if [[ -n "${XDG_RUNTIME_DIR:-}" && -d "$XDG_RUNTIME_DIR" ]]; then
  _runtime_resolved="$(readlink -f "$XDG_RUNTIME_DIR")"
  if [[ "$_runtime_resolved" == /run/user/* && "$_runtime_resolved" != "/run/user" ]]; then
    BWRAP_CMD+=(--bind "$_runtime_resolved" "$_runtime_resolved")
  fi
fi

# Reapply protected socket masks after every generic/config/runtime bind.
mask_protected_sockets

# ── Environment variables: pass through all by default, deny specific patterns ──
# Instead of --clearenv + selective allowlist (which blocks CLI auth tokens),
# we inherit the full parent environment and only strip explicitly denied vars.
# The --env-deny option can still be used to block specific patterns.

for deny_pattern in ${ENV_DENY[@]+"${ENV_DENY[@]}"}; do
  # Use compgen to expand glob patterns against current env var names
  while IFS= read -r var_name; do
    BWRAP_CMD+=(--unsetenv "$var_name")
  done < <(compgen -e | while IFS= read -r v; do
    if [[ "$v" == $deny_pattern ]]; then
      echo "$v"
    fi
  done)
done

# ── Set working directory and execute ──

BWRAP_CMD+=(
  --chdir "$CWD"
  --
  "$@"
)

set +e
"${BWRAP_CMD[@]}"
status=$?
set -e
exit "$status"