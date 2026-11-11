#!/bin/sh
# One-command synthesis for selected tasks from a prepared sample.
# Usage: scripts/synthesize.sh <sample-dir> <results-dir> <env-file> <task-id...>
set -eu
cd "$(dirname "$0")/.."

SAMPLE=${1:?usage: scripts/synthesize.sh <sample-dir> <results-dir> <env-file> <task-id...>}
RESULTS=${2:?usage: scripts/synthesize.sh <sample-dir> <results-dir> <env-file> <task-id...>}
ENV_FILE=${3:?usage: scripts/synthesize.sh <sample-dir> <results-dir> <env-file> <task-id...>}
shift 3

[ "$#" -gt 0 ] || { echo "select at least one task id from $SAMPLE/selection.jsonl" >&2; exit 2; }
[ -d "$SAMPLE" ] || { echo "sample directory missing: $SAMPLE" >&2; exit 1; }
[ -f "$SAMPLE/selection.jsonl" ] || { echo "sample has no selection.jsonl: $SAMPLE" >&2; exit 1; }
[ -f "$ENV_FILE" ] || { echo "model env file missing: $ENV_FILE" >&2; exit 1; }

TASKS=$#
CONCURRENCY=${CONCURRENCY:-$TASKS}
case "$CONCURRENCY" in
  ''|*[!0-9]*) echo "concurrency must be a positive integer" >&2; exit 2 ;;
esac
if [ "$CONCURRENCY" -lt 1 ] || [ "$CONCURRENCY" -gt 40 ]; then
  echo "concurrency must be in 1..40" >&2
  exit 2
fi

echo "synthesizing $TASKS task(s) from $SAMPLE -> $RESULTS (concurrency=$CONCURRENCY)"
exec .venv/bin/python -m pipeline.supervise \
  --sample "$SAMPLE" \
  --results "$RESULTS" \
  --env-file "$ENV_FILE" \
  --batch-size "$TASKS" --concurrency "$CONCURRENCY" \
  --only "$@"