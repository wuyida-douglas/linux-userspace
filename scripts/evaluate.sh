#!/bin/sh
# One-command evaluation of selected tasks from a published bundle.
# Usage: scripts/evaluate.sh <bundle-dir> <task-id> [task-id...]
set -eu
cd "$(dirname "$0")/.."
ROOT=$PWD

BUNDLE=${1:?usage: scripts/evaluate.sh <bundle-dir> <task-id> [task-id...]}
shift
[ "$#" -gt 0 ] || { echo "select at least one task id" >&2; exit 2; }
[ -d "$BUNDLE" ] || { echo "bundle directory missing: $BUNDLE" >&2; exit 1; }
BUNDLE=$(cd "$BUNDLE" && pwd)

ENV_FILE=${ENV_FILE:-/nvme/wuyida/env}
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
MODEL=${MODEL:-glm-5.3}
MAX_TURNS=${MAX_TURNS:-300}
HARBOR_BIN=${HARBOR_BIN:-harbor}
EVAL_JOBS=${EVAL_JOBS:-$ROOT/eval-jobs}
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

for TASK in "$@"; do
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