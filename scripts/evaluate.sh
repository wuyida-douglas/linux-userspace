#!/bin/sh
# One-command evaluation of selected tasks from a published bundle.
# Edit the config block below, then run this script with no arguments.
set -eu

# ===== 直接改这里 =====
BUNDLE=/nvme/wuyida/新管线开发/harbor_export/20261111-production
TASKS="cve-2024-23346-file-pov"
ENV_FILE=/nvme/wuyida/env
MODEL=glm-5.3
MAX_TURNS=300
EVAL_JOBS=/nvme/wuyida/新管线开发/eval-jobs
CLAUDE_BIN=
CLAUDE_VERSION=
HARBOR_BIN=harbor
# ======================

# 可选命令行覆盖：<bundle-dir> [task-id...]
if [ "$#" -gt 0 ]; then
  BUNDLE=$1
  shift
  if [ "$#" -gt 0 ]; then TASKS="$*"; fi
fi

REPO=$(CDPATH= cd -- "$(dirname -- "$0")/.." && pwd)
[ -d "$BUNDLE" ] || { echo "bundle directory missing: $BUNDLE" >&2; exit 1; }
[ -n "$TASKS" ] || { echo "set TASKS in the config block" >&2; exit 2; }
BUNDLE=$(cd "$BUNDLE" && pwd)

if [ -f "$ENV_FILE" ]; then
  set -a
  . "$ENV_FILE"
  set +a
fi

CLAUDE_BIN=${CLAUDE_BIN:-$(command -v claude || true)}
[ -n "$CLAUDE_BIN" ] && [ -x "$CLAUDE_BIN" ] || {
  echo "claude binary not found; set CLAUDE_BIN" >&2; exit 1;
}
CLAUDE_BIN=$(realpath "$CLAUDE_BIN")
CLAUDE_VERSION=${CLAUDE_VERSION:-$("$CLAUDE_BIN" --version | awk '{print $1}')}
mkdir -p "$EVAL_JOBS"

if [ -n "${ANTHROPIC_API_KEY:-}" ]; then
  AUTH_ARG="ANTHROPIC_API_KEY=$ANTHROPIC_API_KEY"
elif [ -n "${ANTHROPIC_AUTH_TOKEN:-}" ]; then
  AUTH_ARG="ANTHROPIC_AUTH_TOKEN=$ANTHROPIC_AUTH_TOKEN"
else
  echo "set ANTHROPIC_API_KEY or ANTHROPIC_AUTH_TOKEN (or ENV_FILE)" >&2
  exit 1
fi

MOUNTS=$(printf '[{"type":"bind","source":"%s","target":"/usr/local/bin/claude","read_only":true}]' "$CLAUDE_BIN")

for TASK in $TASKS; do
  PROFILE="$BUNDLE/$TASK/harbor-runtime-profile"
  [ -d "$PROFILE" ] || { echo "task profile missing: $PROFILE" >&2; exit 1; }
  JOB_NAME="eval-$(printf '%s' "$TASK" | tr '[:upper:]' '[:lower:]' | tr -c 'a-z0-9-' '-')-$(date +%Y%m%d-%H%M%S)"
  echo "evaluating $TASK -> $EVAL_JOBS/$JOB_NAME"
  (
    cd "$PROFILE"
    set -- "$HARBOR_BIN" run \
      --path "$PWD" \
      --agent claude-code \
      --model "$MODEL" \
      --ak "max_turns=$MAX_TURNS" \
      --ak "version=$CLAUDE_VERSION" \
      --mounts "$MOUNTS" \
      --ae "$AUTH_ARG"
    if [ -n "${ANTHROPIC_BASE_URL:-}" ]; then
      set -- "$@" --ae "ANTHROPIC_BASE_URL=$ANTHROPIC_BASE_URL"
    fi
    set -- "$@" \
      --n-attempts 1 \
      --jobs-dir "$EVAL_JOBS" \
      --job-name "$JOB_NAME" \
      --yes \
      --verifier bin.pass2fail_verifier:Pass2FailVerifier \
      --verifier-timeout-multiplier 6.0
    python3 "$BUNDLE/bin/load_image.py" --task "$TASK" --root "$BUNDLE" --run "$@"
  )
  echo "result: $EVAL_JOBS/$JOB_NAME/result.json"
done