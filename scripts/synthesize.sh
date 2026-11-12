#!/bin/sh
# One-command resumable synthesis.
# Edit the config block below, then run this script with no arguments.
#
# MODE=all          synthesize every task in selection.jsonl
# MODE=tasks-file   synthesize only the ids listed in TASKS_FILE
# RETRY_FAILED=1    archive failed/error/timeout attempts and rerun them
set -eu

# ===== 直接改这里 =====
SAMPLE=/nvme/wuyida/新管线开发/samples/batch-01
RESULTS=/nvme/wuyida/新管线开发/results/batch-01
ENV_FILE=/nvme/wuyida/env
MODE=all
CONCURRENCY=80
WAVE_SIZE=0
RETRY_FAILED=0
RETRY_ROUNDS=1
DRY_RUN=0
EXPECT_BATCH=1
# ======================

REPO=$(CDPATH= cd -- "$(dirname -- "$0")/.." && pwd)
export ANTHROPIC_MODEL="${ANTHROPIC_MODEL:-deepseek-v4.1-flash-1017}"
export PYTHONPATH="$REPO${PYTHONPATH:+:$PYTHONPATH}"

# 带参数时保持旧的显式调用方式：所有参数原样交给 synthesize_batch.py。
if [ "$#" -gt 0 ]; then
  exec "$REPO/.venv/bin/python" -m pipeline.synthesize_batch "$@"
fi

[ -d "$SAMPLE" ] || { echo "sample directory missing: $SAMPLE" >&2; exit 1; }
[ -f "$SAMPLE/selection.jsonl" ] || { echo "sample has no selection.jsonl: $SAMPLE" >&2; exit 1; }
[ -f "$ENV_FILE" ] || { echo "model env file missing: $ENV_FILE" >&2; exit 1; }

case "$CONCURRENCY" in
  ''|*[!0-9]*) echo "CONCURRENCY must be an integer in 1..80" >&2; exit 2 ;;
esac
case "$WAVE_SIZE" in
  ''|*[!0-9]*) echo "WAVE_SIZE must be an integer in 0..100000" >&2; exit 2 ;;
esac
if [ "$CONCURRENCY" -lt 1 ] || [ "$CONCURRENCY" -gt 80 ]; then
  echo "CONCURRENCY must be in 1..80" >&2
  exit 2
fi
if [ "$WAVE_SIZE" -gt 100000 ]; then
  echo "WAVE_SIZE must be in 0..100000 (0 = continuous scheduling)" >&2
  exit 2
fi
case "$RETRY_FAILED" in 0|1) ;; *) echo "RETRY_FAILED must be 0 or 1" >&2; exit 2 ;; esac
case "$DRY_RUN" in 0|1) ;; *) echo "DRY_RUN must be 0 or 1" >&2; exit 2 ;; esac

case "$MODE" in
  all)
    set -- --all
    ;;
  tasks-file)
    [ -f "$TASKS_FILE" ] || { echo "tasks file missing: $TASKS_FILE" >&2; exit 1; }
    set -- --tasks-file "$TASKS_FILE"
    ;;
  *)
    echo "MODE must be all or tasks-file" >&2
    exit 2
    ;;
esac
set -- --sample "$SAMPLE" --results "$RESULTS" --env-file "$ENV_FILE" \
       --concurrency "$CONCURRENCY" --wave-size "$WAVE_SIZE" "$@"
if [ "$RETRY_FAILED" = "1" ]; then
  set -- "$@" --retry-failed --retry-rounds "$RETRY_ROUNDS"
fi
if [ "$DRY_RUN" = "1" ]; then
  set -- "$@" --dry-run
fi
if [ -n "${EXPECT_BATCH:-}" ]; then
  set -- "$@" --expect-batch "$EXPECT_BATCH"
fi

echo "synthesizing sample=$SAMPLE results=$RESULTS mode=$MODE concurrency=$CONCURRENCY wave_size=$WAVE_SIZE retry_failed=$RETRY_FAILED"
exec "$REPO/.venv/bin/python" -m pipeline.synthesize_batch "$@"