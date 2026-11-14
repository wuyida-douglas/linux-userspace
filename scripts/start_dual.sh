#!/bin/bash
# Run one batch across two docker daemons from a shared task queue.
#
#   scripts/start_dual.sh <sample-dir> <results-root> <published-root> \
#       [tasks-file] [concurrency-per-daemon]
#
# Both coordinators read the SAME task list and claim tasks through
# PIPELINE_CLAIM_DIR: the first supervisor to create <task>.json runs that
# task on its daemon. The split therefore adjusts itself -- if daemon A is
# faster it simply claims more of the list, and vice versa.
#
# Results and publications stay separate per daemon:
#   <results-root>-a / <results-root>-b
#   <published-root>_1 / <published-root>_2
# Merge the two published roots after both finish (task ids are disjoint).
#
# Daemon A is the system default socket; daemon B is docker-d2
# (unix:///run/docker2.sock, data-root /nvme/docker2, containerd2).
# Each coordinator runs its own housekeeping, so both daemons are swept.
set -eu

SAMPLE=$(CDPATH= cd -- "${1:?usage: start_dual.sh <sample-dir> <results-root> <published-root> [tasks-file] [concurrency]}" && pwd)
RESULTS=${2:?}
PUBLISHED=${3:?}
TASKS_FILE=${4:-$SAMPLE/fresh-todo.txt}
CONCURRENCY=${5:-40}
REPO=$(CDPATH= cd -- "$(dirname -- "$0")/.." && pwd)
SOCKET_B=/run/docker2.sock
CLAIMS="$RESULTS-claims"

[ -f "$TASKS_FILE" ] || { echo "tasks file missing: $TASKS_FILE" >&2; exit 1; }
[ -S "$SOCKET_B" ] || { echo "second daemon socket missing: $SOCKET_B" >&2; exit 1; }
cd "$REPO"

EXPECT=$(python3 -c "import json;print(json.load(open('$SAMPLE/sample.json')).get('batch',1))")
mkdir -p "$RESULTS-a/logs" "$RESULTS-b/logs" "$CLAIMS" "${PUBLISHED}_1" "${PUBLISHED}_2"

start() {
  local label=$1 results=$2 published=$3 peer=$4
  .venv/bin/python -m pipeline.synthesize_batch \
    --sample "$SAMPLE" --results "$results" --env-file /nvme/wuyida/env \
    --tasks-file "$TASKS_FILE" --concurrency "$CONCURRENCY" --wave-size 0 \
    --expect-batch "$EXPECT" --published-root "$published" \
    > "$results/logs/coordinator-$label-$(date -u +%Y%m%d-%H%M%S).log" 2>&1 &
  echo "$label: coordinator pid=$! results=$results published=$published peer=$peer"
}

TMPDIR=/nvme/wuyida/tmp \
ANTHROPIC_MODEL=deepseek-v4.1-flash-1017 \
PIPELINE_FAILURES_TERMINAL=1 \
PIPELINE_BUILD_CACHE_PRUNE_MIN_FREE_GB=1200 \
PIPELINE_BUILD_CACHE_PRUNE_UNTIL=3h \
PIPELINE_DATA_DISK=/nvme \
PIPELINE_CLAIM_DIR="$CLAIMS" \
PIPELINE_PEER_RESULTS="$REPO/$RESULTS-b" \
start a "$RESULTS-a" "${PUBLISHED}_1" "$RESULTS-b"

DOCKER_HOST=unix://$SOCKET_B \
PIPELINE_IPAM_FACTORY_POOL=10.96.0.0/12 \
PIPELINE_IPAM_HARBOR_POOL=10.128.0.0/12 \
TMPDIR=/nvme/wuyida/tmp \
ANTHROPIC_MODEL=deepseek-v4.1-flash-1017 \
PIPELINE_FAILURES_TERMINAL=1 \
PIPELINE_BUILD_CACHE_PRUNE_MIN_FREE_GB=1200 \
PIPELINE_BUILD_CACHE_PRUNE_UNTIL=3h \
PIPELINE_DATA_DISK=/nvme \
PIPELINE_CLAIM_DIR="$CLAIMS" \
PIPELINE_PEER_RESULTS="$REPO/$RESULTS-a" \
start b "$RESULTS-b" "${PUBLISHED}_2" "$RESULTS-a"