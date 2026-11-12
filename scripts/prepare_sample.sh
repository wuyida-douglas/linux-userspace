#!/bin/sh
# One-command input preparation for a fixed random sample.
# Edit the config block below, then run this script with no arguments.
set -eu

# ===== 直接改这里 =====
OUTPUT=/nvme/wuyida/新管线开发/samples/my100
COUNT=100
SEED=42
WORKERS=4
# ======================

# 可选命令行覆盖（一般不用）：<输出目录> [数量] [seed] [workers]
OUTPUT=${1:-$OUTPUT}
COUNT=${2:-$COUNT}
SEED=${3:-$SEED}
WORKERS=${4:-$WORKERS}

REPO=$(CDPATH= cd -- "$(dirname -- "$0")/.." && pwd)
POOL=$REPO/data/frozen-pool-20261109/candidates-kept-available-20261109.jsonl

case "$COUNT" in
  ''|*[!0-9]*) echo "count must be a positive integer" >&2; exit 2 ;;
esac
case "$WORKERS" in
  ''|*[!0-9]*) echo "workers must be an integer in 1..30" >&2; exit 2 ;;
esac
if [ "$COUNT" -lt 1 ] || [ "$WORKERS" -lt 1 ] || [ "$WORKERS" -gt 30 ]; then
  echo "count must be >=1 and workers must be in 1..30" >&2
  exit 2
fi
[ -f "$POOL" ] || { echo "frozen pool missing: $POOL" >&2; exit 1; }

echo "preparing sample=$OUTPUT count=$COUNT seed=$SEED workers=$WORKERS"
export PYTHONPATH="$REPO${PYTHONPATH:+:$PYTHONPATH}"
exec "$REPO/.venv/bin/python" -m pipeline.prepare \
  --input "$POOL" \
  --output "$OUTPUT" \
  --count "$COUNT" --seed "$SEED" --workers "$WORKERS"