#!/usr/bin/env python3
"""One deterministic monitoring tick for a running synthesis batch.

Prints a compact report and stores the previous snapshot so the next tick can
show deltas. Read-only: it never changes a task record or the supervisor state.

Definitions (kept here so the monitoring loop cannot drift):

* cohort: task ids listed in ``--fresh-file`` (the tasks this run owns);
* rate A: passed / (passed + rejected-not_suitable + failed + error), only over
  the cohort's terminal records;
* rate B: same, but terminal ``error`` records whose message comes from the
  per-task image cleanup loop (``failed to rebuild`` / ``is missing`` /
  ``shared image archive differs``) are left out of the denominator; it is a
  diagnostic of model quality, not the official acceptance rate;
* concurrency: distinct task ids with a live ``pipeline.run`` process, and the
  alive pids recorded in ``supervisor-state.json`` (the larger is the truth;
  a single ``pgrep -c`` sample undercounts during scheduling bursts).
"""
from __future__ import annotations

import argparse
import json
import os
import shutil
import subprocess
import time
from pathlib import Path

TERMINAL = ("passed", "rejected", "failed", "error", "timeout")
IN_PROGRESS = ("routing", "synthesizing", "reviewing", "harbor", "preparing")
IMAGE_LOOP_MARKERS = ("failed to rebuild", "is missing", "shared image archive differs")


def load(path: Path) -> dict:
    try:
        return json.loads(path.read_text(encoding="utf-8"))
    except (OSError, ValueError):
        return {}


def alive(pid) -> bool:
    try:
        os.kill(int(pid), 0)
        return True
    except Exception:
        return False


def live_task_ids(results: Path) -> set[str]:
    out = subprocess.run(["ps", "-eo", "args="], capture_output=True, text=True).stdout
    ids = set()
    for line in out.splitlines():
        if "pipeline.run" not in line or "--only" not in line:
            continue
        parts = line.split()
        try:
            ids.add(parts[parts.index("--only") + 1])
        except (ValueError, IndexError):
            continue
    return ids


def counts(results: Path, fresh: set[str], since: float = 0.0) -> dict:
    status = {}
    passed = failed = error = rejected_ns = rejected_other = image_loop = 0
    in_progress = {}
    latest = 0.0
    for record_path in results.glob("*/result.json"):
        task = record_path.parent.name
        if fresh and task not in fresh:
            continue
        record = load(record_path)
        state = str(record.get("status") or "")
        if state in IN_PROGRESS:
            in_progress[state] = in_progress.get(state, 0) + 1
            continue
        if state not in TERMINAL:
            continue
        mtime = record_path.stat().st_mtime
        if since and mtime < since:
            continue
        latest = max(latest, mtime)
        if state == "passed":
            passed += 1
        elif state == "rejected":
            if record.get("failure_class") == "not_suitable":
                rejected_ns += 1
            else:
                rejected_other += 1
        elif state in ("failed",):
            failed += 1
        else:
            error += 1
            if any(marker in str(record.get("error") or "") for marker in IMAGE_LOOP_MARKERS):
                image_loop += 1
        status[state] = status.get(state, 0) + 1
    denominator = passed + rejected_other + failed + error
    den_no_image = denominator - image_loop
    return {
        "status": status,
        "in_progress": in_progress,
        "passed": passed,
        "failed": failed,
        "error": error,
        "rejected_not_suitable": rejected_ns,
        "image_loop": image_loop,
        "denominator": denominator,
        "rate_a": round(passed / denominator * 100, 1) if denominator else 0.0,
        "denominator_no_image": den_no_image,
        "rate_b": round(passed / den_no_image * 100, 1) if den_no_image else 0.0,
        "latest_terminal_age_sec": int(time.time() - latest) if latest else None,
    }


def disk(results: Path) -> dict:
    info = {}
    for label, path in (("root", "/"), ("nvme", "/nvme")):
        try:
            usage = shutil.disk_usage(path)
            info[f"{label}_free_g"] = round(usage.free / 1024 ** 3, 1)
        except OSError:
            pass
    try:
        info["volumes"] = len(subprocess.run(["docker", "volume", "ls", "-q"],
                                             capture_output=True, text=True).stdout.split())
    except Exception:
        pass
    return info


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--results", type=Path, required=True)
    parser.add_argument("--fresh-file", type=Path, default=None)
    parser.add_argument("--no-disk", action="store_true", help="skip df/docker probes")
    parser.add_argument("--json", action="store_true")
    parser.add_argument("--since", default=None,
                        help="count only terminal records updated after this UTC time "
                             "(default: the first tick's time, stored in the snapshot)")
    args = parser.parse_args()
    results = args.results.resolve()
    fresh = set()
    if args.fresh_file and args.fresh_file.is_file():
        fresh = {line.strip() for line in args.fresh_file.read_text().splitlines() if line.strip()}
    snapshot_path = results / ".monitor-snapshot.json"
    previous = load(snapshot_path)
    if args.since:
        since = time.mktime(time.strptime(args.since[:19], "%Y-%m-%dT%H:%M"))
    elif previous.get("run_start"):
        since = time.mktime(time.strptime(previous["run_start"][:19], "%Y-%m-%dT%H:%M"))
    else:
        since = time.time()
    tick = counts(results, fresh, since)
    state = load(results / "supervisor-state.json")
    alive_pids = sum(1 for child in (state.get("children") or {}).values()
                     if child.get("pid") and alive(child["pid"]))
    tick["concurrency_alive_state"] = alive_pids
    tick["concurrency_live_ps"] = len(live_task_ids(results))
    if not args.no_disk:
        tick.update(disk(results))
    tick["checked_at"] = time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime())
    delta = {}
    for key in ("passed", "denominator", "rate_a", "rate_b"):
        if key in previous:
            delta[key] = round(tick[key] - previous[key], 1) if isinstance(tick[key], float) \
                else tick[key] - previous[key]
    tick["delta_since_last_tick"] = delta
    try:
        snapshot_path.write_text(json.dumps({
            **{k: tick[k] for k in ("passed", "denominator", "rate_a", "rate_b", "checked_at")},
            "run_start": previous.get("run_start") or time.strftime(
                "%Y-%m-%dT%H:%M:%SZ", time.gmtime(since)),
        }, indent=2) + "\n", encoding="utf-8")
    except OSError:
        pass
    if args.json:
        print(json.dumps(tick, ensure_ascii=False, indent=2))
        return 0
    print(f"passed {tick['passed']}  A={tick['rate_a']}% ({tick['passed']}/{tick['denominator']})"
          f"  B={tick['rate_b']}% ({tick['passed']}/{tick['denominator_no_image']})")
    print(f"in_progress {tick['in_progress']}  latest_terminal_age {tick['latest_terminal_age_sec']}s")
    print(f"concurrency state_alive={alive_pids} live_ps={tick['concurrency_live_ps']}")
    if not args.no_disk:
        print(f"disk root_free={tick.get('root_free_g')}G nvme_free={tick.get('nvme_free_g')}G"
              f" volumes={tick.get('volumes')}")
    if delta:
        print(f"delta {delta}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())