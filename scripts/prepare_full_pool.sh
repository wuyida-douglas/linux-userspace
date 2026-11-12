#!/bin/sh
# One-command input preparation for the complete frozen candidate pool.
# Prefer scripts/prepare_batch.sh for production: it downloads one batch at a
# time so source trees can be deleted after synthesis/upload.
# Edit the config block below, then run this script with no arguments.
set -eu

# ===== 直接改这里 =====
OUTPUT=/nvme/wuyida/新管线开发/samples/full-20261109
WORKERS=30
# ======================

# 可选命令行覆盖（一般不用）
OUTPUT=${1:-$OUTPUT}
WORKERS=${2:-$WORKERS}

REPO=$(CDPATH= cd -- "$(dirname -- "$0")/.." && pwd)
POOL=$REPO/data/frozen-pool-20261109/candidates-kept-available-20261109.jsonl

case "$WORKERS" in
  ''|*[!0-9]*) echo "workers must be an integer in 1..30" >&2; exit 2 ;;
esac
if [ "$WORKERS" -lt 1 ] || [ "$WORKERS" -gt 30 ]; then
  echo "workers must be in 1..30" >&2
  exit 2
fi
[ -f "$POOL" ] || { echo "frozen pool missing: $POOL" >&2; exit 1; }

echo "preparing full frozen pool -> $OUTPUT (workers=$WORKERS)"
export PYTHONPATH="$REPO${PYTHONPATH:+:$PYTHONPATH}"
exec "$REPO/.venv/bin/python" -m pipeline.prepare \
  --input "$POOL" \
  --output "$OUTPUT" \
  --all --workers "$WORKERS"