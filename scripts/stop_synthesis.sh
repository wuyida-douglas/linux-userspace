#!/bin/sh
# Stop synthesis for one results directory.
# Edit the config block below, then run this script with no arguments.
#
# STOP_WORKERS=0: stop the coordinator/supervisor but let already-started
#                 pipeline.run workers finish their current task.
# STOP_WORKERS=1: also terminate pipeline.run workers (hard stop).
set -eu

# ===== 直接改这里 =====
RESULTS=/nvme/wuyida/新管线开发/results/batch-01
STOP_WORKERS=0
# ======================

RESULTS=${1:-$RESULTS}
STOP_WORKERS=${2:-$STOP_WORKERS}

kill_matching() {
  pattern=$1
  pids=$(pgrep -f "$pattern" || true)
  if [ -n "$pids" ]; then
    echo "  TERM $pids  ($pattern)"
    # shellcheck disable=SC2086
    kill -TERM $pids 2>/dev/null || true
  fi
}

echo "stopping synthesis for $RESULTS (STOP_WORKERS=$STOP_WORKERS)"
kill_matching "pipeline[.]synthesize_batch .*--results $RESULTS"
kill_matching "pipeline[.]supervise .*--results $RESULTS"
if [ "$STOP_WORKERS" = "1" ]; then
  kill_matching "pipeline[.]run .*--results $RESULTS"
else
  echo "  leaving live pipeline.run workers alone; rerun the same command to adopt them"
fi

sleep 1
echo "remaining processes:"
pgrep -af "pipeline[.](synthesize_batch|supervise|run) .*--results $RESULTS" || echo "  none"