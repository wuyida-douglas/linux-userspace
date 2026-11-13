#!/bin/bash
# Keep dead Compose networks bounded while a batch is running.
# The running coordinator was started before prune_idle_networks() existed,
# so this loop does the job its housekeeping will do from the next start on.
cd /nvme/wuyida/新管线开发 || exit 1
while true; do
  .venv/bin/python -c "
import sys; sys.path.insert(0, '.')
from pathlib import Path
from pipeline.resource_cleanup import prune_idle_networks
print(prune_idle_networks(Path('results/batch-01'), 1.0), flush=True)
" >> results/batch-01/logs/network-prune.log 2>&1
  sleep 1200
done
