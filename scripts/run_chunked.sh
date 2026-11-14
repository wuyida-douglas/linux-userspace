#!/bin/bash
# Run a batch in fixed-size chunks, cleaning both daemons between chunks.
#
#   scripts/run_chunked.sh <sample-dir> <results-root> <published-root> \
#       [tasks-file] [chunk-size] [concurrency-per-daemon]
#
# Every chunk is one start_dual.sh run (shared queue, two daemons). When both
# coordinators exit, the script performs a full sweep on both daemons -- all
# containers, every unused image, the build cache, volumes and old temp dirs --
# and only then starts the next chunk. That keeps the aggressive cleanup
# (which would break a running acceptance) inside a safe window, so no human
# has to watch the disk.
#
# Results and publications are shared across chunks:
#   <results-root>-a / <results-root>-b
#   <published-root>_1 / <published-root>_2
set -eu

SAMPLE=$(CDPATH= cd -- "${1:?usage: run_chunked.sh <sample-dir> <results-root> <published-root> [tasks-file] [chunk] [concurrency]}" && pwd)
RESULTS=${2:?}
PUBLISHED=${3:?}
TASKS_FILE=${4:-$SAMPLE/fresh-todo.txt}
CHUNK=${5:-500}
CONCURRENCY=${6:-70}
REPO=$(CDPATH= cd -- "$(dirname -- "$0")/.." && pwd)
cd "$REPO"

[ -f "$TASKS_FILE" ] || { echo "tasks file missing: $TASKS_FILE" >&2; exit 1; }
SPLIT_DIR="$RESULTS/chunks"
mkdir -p "$SPLIT_DIR"
rm -f "$SPLIT_DIR"/part-*
split -d -a 3 -l "$CHUNK" "$TASKS_FILE" "$SPLIT_DIR/part-"
echo "chunks: $(ls "$SPLIT_DIR"/part-* | wc -l) x <=$CHUNK tasks"

wait_for_coordinators() {
  while pgrep -f "pipeline[.]synthesize_batch .*--results $REPO/$RESULTS-[ab]( |$)" >/dev/null; do
    sleep 60
  done
}

clean_daemon() {
  local label=$1 results=$2 host=${3:-}
  echo "[$label] full sweep"
  if [ -n "$host" ]; then
    DOCKER_HOST=$host .venv/bin/python -m pipeline.resource_cleanup \
      --results "$results" --batch-end --batch-end-cache-until=1h || true
  else
    .venv/bin/python -m pipeline.resource_cleanup \
      --results "$results" --batch-end --batch-end-cache-until=1h || true
  fi
}

for part in "$SPLIT_DIR"/part-*; do
  round=$(basename "$part")
  echo "=== $round ($(wc -l < "$part") tasks, $CONCURRENCY per daemon) ==="
  rm -rf "$RESULTS-claims"
  scripts/start_dual.sh "$SAMPLE" "$RESULTS" "$PUBLISHED" "$part" "$CONCURRENCY"
  wait_for_coordinators
  echo "[$round] both coordinators finished"
  clean_daemon a "$RESULTS-a"
  clean_daemon b "$RESULTS-b" "unix:///run/docker2.sock"
done
rm -rf "$RESULTS-claims" "$SPLIT_DIR"
echo "all chunks finished; merge ${PUBLISHED}_2 into ${PUBLISHED}_1 before delivery"