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
START_PART=${7:-}
REPO=$(CDPATH= cd -- "$(dirname -- "$0")/.." && pwd)
cd "$REPO"

[ -f "$TASKS_FILE" ] || { echo "tasks file missing: $TASKS_FILE" >&2; exit 1; }
SPLIT_DIR="$RESULTS/chunks"
mkdir -p "$SPLIT_DIR"
# Splitting is destructive for a recovery run: a restart after a crash must
# keep the part files (and any interrupted tasks appended to them) instead of
# rebuilding them from the task file.
if [ -z "$(ls -A "$SPLIT_DIR" 2>/dev/null)" ]; then
  split -d -a 3 -l "$CHUNK" "$TASKS_FILE" "$SPLIT_DIR/part-"
fi
echo "chunks: $(ls "$SPLIT_DIR"/part-* | wc -l) x <=$CHUNK tasks"

wait_for_coordinators() {
  # --results is passed relative to the repository root.
  local pa="pipeline[.]synthesize_batch .*--results ([^ ]*/)?$RESULTS-a( |$)"
  local pb="pipeline[.]synthesize_batch .*--results ([^ ]*/)?$RESULTS-b( |$)"
  local waited=0
  # Never redirect pgrep to /dev/null: when a task container leaves /dev/null
  # at 0644 the redirection itself fails, pgrep never runs, and the whole chunk
  # is declared finished while 145 workers are still running. That started a
  # full sweep over a live batch on 2026-11-14. Command substitution cannot
  # fail that way.
  alive() {
    [ -n "$(pgrep -f "$1" 2>&1 || true)" ]
  }
  # They are backgrounded by start_dual.sh; wait until both have exec'd.
  while ! { alive "$pa" && alive "$pb"; }; do
    waited=$((waited + 2))
    if [ "$waited" -ge 180 ]; then
      echo "coordinators did not appear within 180s" >&2
      return 1
    fi
    sleep 2
  done
  while alive "$pa" || alive "$pb"; do
    sleep 60
  done
  # A supervisor can exit while its workers still run. A sweep at that moment
  # deletes their containers and images, so wait for the workers too.
  local worker_pa="pipeline[.]run .*--results ([^ ]*/)?$RESULTS-a( |$)"
  local worker_pb="pipeline[.]run .*--results ([^ ]*/)?$RESULTS-b( |$)"
  local guard=0
  while alive "$worker_pa" || alive "$worker_pb"; do
    guard=$((guard + 1))
    if [ "$guard" -ge 20 ]; then
      echo "[$round] workers still running after 10 minutes" >&2
      return 2
    fi
    echo "[$round] waiting for live workers before the sweep"
    sleep 30
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
  if [ -n "$START_PART" ] && [ "$round" \< "$START_PART" ]; then
    echo "skip $round (before $START_PART)"
    continue
  fi
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