#!/bin/sh
# One-command scale-up input preparation: the complete frozen candidate pool.
# Usage: scripts/prepare_full_pool.sh [output-dir] [workers]
set -eu
cd "$(dirname "$0")/.."

OUTPUT=${1:-"samples/full-$(date +%Y%m%d)"}
WORKERS=${2:-${WORKERS:-30}}

case "$WORKERS" in
  ''|*[!0-9]*) echo "workers must be an integer in 1..30" >&2; exit 2 ;;
esac
if [ "$WORKERS" -lt 1 ] || [ "$WORKERS" -gt 30 ]; then
  echo "workers must be an integer in 1..30" >&2
  exit 2
fi

echo "preparing full frozen pool -> $OUTPUT (workers=$WORKERS)"
exec .venv/bin/python -m pipeline.prepare \
  --input data/frozen-pool-20261109/candidates-kept-available-20261109.jsonl \
  --output "$OUTPUT" \
  --all --workers "$WORKERS"