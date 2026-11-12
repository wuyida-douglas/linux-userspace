#!/usr/bin/env python3
"""Requeue tasks whose Harbor acceptance died from infrastructure, not grading.

A task that reaches Harbor has a frozen, reviewed delivery. When the outer
``harbor run`` process is killed by its wall-clock timeout, or when Harbor
itself raises a trial-level infrastructure error (environment start timeout,
verifier environment timeout), nothing about the task is wrong: acceptance
just needs another attempt. Writing the record back as ``status=harbor`` lets
the running supervisor match its interrupted final-acceptance branch and
relaunch the task with ``--resume`` (acceptance only, no synthesis, no review
vote), without restarting the supervisor.

Genuine grading outcomes (reward 0 with a completed trial) never match: the
record then is ``failed/harbor_failed`` without an exception, not ``error``.

The original record is preserved under ``retry-evidence/`` first. Each task
gets at most ``MAX_REQUEUES`` attempts so a task whose verifier genuinely
cannot run does not cycle forever. The script is idempotent: a task already
flipped has no ``error`` record to match.
"""
from __future__ import annotations

import argparse
import json
import os
import time
from pathlib import Path

MAX_REQUEUES = 3
TRIGGERS = ("TimeoutExpired", "Harbor trial failed")


def job_finished_with_zero_reward(error: str) -> bool:
    """True when the referenced Harbor job completed without an exception.

    A completed trial with reward 0 is a grading verdict (harbor_failed), not
    an infrastructure failure. Requeueing it just replays the same delivery,
    and after per-task cleanup the images are gone, so every retry would fail
    at export instead.
    """
    marker = "harbor/jobs/"
    if marker not in error:
        return False
    tail = error.split(marker, 1)[1]
    job_name = tail.split(":", 1)[0].split()[0].rstrip("/")
    root = Path(error.split(marker, 1)[0] + marker)
    job = root / job_name / "result.json"
    try:
        stats = json.loads(job.read_text(encoding="utf-8")).get("stats") or {}
    except (OSError, ValueError):
        return False
    return (stats.get("n_errored_trials") or 0) == 0 and (stats.get("n_completed_trials") or 0) == 1


def load(path: Path) -> dict:
    try:
        return json.loads(path.read_text(encoding="utf-8"))
    except Exception:
        return {}


def previous_requeues(task: Path) -> int:
    return len(list((task / "retry-evidence").glob("harbor-requeue-*.json")))


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("results", type=Path)
    parser.add_argument("--only", nargs="*", help="explicit task ids (manual retry only)")
    parser.add_argument("--dry-run", action="store_true")
    args = parser.parse_args()
    results = args.results.resolve()
    flipped: list[str] = []
    wanted = set(args.only or [])
    for record_path in sorted(results.glob("*/result.json")):
        if wanted and record_path.parent.name not in wanted:
            continue
        record = load(record_path)
        if record.get("status") != "error":
            continue
        error = str(record.get("error") or "")
        if not any(token in error for token in TRIGGERS):
            continue
        if job_finished_with_zero_reward(error):
            continue
        task = record_path.parent
        if not (task / "workspace/delivery").is_dir():
            continue
        review = load(task / "workspace/review.json")
        if review.get("passed") is not True:
            continue
        if not (task / "harbor").is_dir():
            continue
        count = previous_requeues(task)
        if count >= MAX_REQUEUES:
            continue
        if args.dry_run:
            flipped.append(task.name)
            continue
        evidence = task / "retry-evidence"
        evidence.mkdir(exist_ok=True)
        (evidence / f"harbor-requeue-{count + 1}.json").write_text(
            json.dumps(record, ensure_ascii=False, indent=2) + "\n", encoding="utf-8")
        new = {"task_id": task.name,
               "instance_id": record.get("instance_id"),
               "status": "harbor",
               "started_at": record.get("started_at"),
               "requeued_after": "harbor infrastructure failure; acceptance needs another attempt",
               "requeued_at": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime())}
        temporary = record_path.with_suffix(".tmp")
        temporary.write_text(json.dumps(new, ensure_ascii=False, indent=2) + "\n",
                             encoding="utf-8")
        os.replace(temporary, record_path)
        flipped.append(task.name)
    for name in flipped:
        print(("would requeue " if args.dry_run else "requeued ") + name)
    print(f"{len(flipped)} task(s)")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())