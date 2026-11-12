#!/bin/sh
# One-command input preparation for one frozen-pool batch.
# Edit the config block below, then run this script with no arguments.
set -eu

# ===== 直接改这里 =====
BATCH=1
OUTPUT=/nvme/wuyida/新管线开发/samples/batch-01
WORKERS=30
# ======================

# 可选命令行覆盖（一般不用）
BATCH=${1:-$BATCH}
OUTPUT=${2:-$OUTPUT}
WORKERS=${3:-$WORKERS}

REPO=$(CDPATH= cd -- "$(dirname -- "$0")/.." && pwd)
POOL=$REPO/data/frozen-pool-20261109/candidates-kept-available-20261109.jsonl

case "$BATCH" in
  ''|*[!0-9]*) echo "batch must be a positive integer" >&2; exit 2 ;;
esac
if [ "$BATCH" -lt 1 ]; then
  echo "batch must be >= 1" >&2
  exit 2
fi
case "$WORKERS" in
  ''|*[!0-9]*) echo "workers must be an integer in 1..30" >&2; exit 2 ;;
esac
if [ "$WORKERS" -lt 1 ] || [ "$WORKERS" -gt 30 ]; then
  echo "workers must be in 1..30" >&2
  exit 2
fi
[ -f "$POOL" ] || { echo "frozen pool missing: $POOL" >&2; exit 1; }

echo "preparing batch=$BATCH -> $OUTPUT (workers=$WORKERS)"
export PYTHONPATH="$REPO${PYTHONPATH:+:$PYTHONPATH}"
exec "$REPO/.venv/bin/python" -m pipeline.prepare \
  --input "$POOL" \
  --output "$OUTPUT" \
  --batch "$BATCH" --workers "$WORKERS"