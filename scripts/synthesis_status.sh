#!/bin/sh
# Show how many tasks are in each synthesis stage and how many workers are live.
# Edit the config block below, then run this script with no arguments.
set -eu

# ===== 直接改这里 =====
SAMPLE=/nvme/wuyida/新管线开发/samples/batch-01
RESULTS=/nvme/wuyida/新管线开发/results/batch-01
TASKS_FILE=/nvme/wuyida/新管线开发/samples/batch-01/todo.txt
# TASKS_FILE=   # 留空 = 统计整个 selection.jsonl
# ======================

REPO=$(CDPATH= cd -- "$(dirname -- "$0")/.." && pwd)
export PYTHONPATH="$REPO${PYTHONPATH:+:$PYTHONPATH}"
if [ -n "$TASKS_FILE" ]; then
  exec "$REPO/.venv/bin/python" -m pipeline.synthesis_status \
    --sample "$SAMPLE" \
    --results "$RESULTS" \
    --tasks-file "$TASKS_FILE"
else
  exec "$REPO/.venv/bin/python" -m pipeline.synthesis_status \
    --sample "$SAMPLE" \
    --results "$RESULTS"
fi