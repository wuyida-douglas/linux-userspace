#!/bin/sh
# One-command input preparation for a fixed random sample.
# Usage: scripts/prepare_sample.sh <sample-dir> [count] [seed] [workers]
set -eu
cd "$(dirname "$0")/.."

SAMPLE=${1:?usage: scripts/prepare_sample.sh <sample-dir> [count] [seed] [workers]}
COUNT=${2:-100}
SEED=${3:-$(date +%Y%m%d)}
WORKERS=${4:-${WORKERS:-4}}
POOL=data/frozen-pool-20261109/candidates-kept-available-20261109.jsonl

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

echo "preparing sample=$SAMPLE count=$COUNT seed=$SEED workers=$WORKERS"
exec .venv/bin/python -m pipeline.prepare \
  --input "$POOL" \
  --output "$SAMPLE" \
  --count "$COUNT" --seed "$SEED" --workers "$WORKERS"