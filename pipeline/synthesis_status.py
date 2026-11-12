#!/usr/bin/env python3
"""Report synthesis progress by stage and live worker count.

The target list comes from ``selection.jsonl`` (all tasks) or an optional
``--tasks-file`` subset. Stage counts come from each task's ``result.json``;
live counts come from ``/proc`` command lines for ``pipeline.run`` workers that
belong to the same results directory.
"""
from __future__ import annotations

import argparse
import json
from collections import Counter
from pathlib import Path
from typing import Any

from .common import timestamp
from .synthesize_batch import resolve_targets, selection_rows, task_file_tokens

IN_FLIGHT = {"preparing", "routing", "synthesizing", "reviewing", "harbor"}
TERMINAL = {"passed", "failed", "rejected", "error", "timeout"}
STAGES = ["preparing", "routing", "synthesizing", "reviewing", "harbor", "routed",
          "passed", "failed", "rejected", "error", "timeout", "duplicate", "missing"]


def load_json(path: Path, default: Any = None) -> Any:
    try:
        return json.loads(path.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError):
        return {} if default is None else default


def command_args(pid_dir: Path) -> list[str]:
    try:
        raw = (pid_dir / "cmdline").read_bytes()
    except OSError:
        return []
    return [part.decode("utf-8", "replace") for part in raw.split(b"\0") if part]


def flag_value(args: list[str], flag: str) -> str | None:
    try:
        return args[args.index(flag) + 1]
    except (ValueError, IndexError):
        return None


def parent_pid(proc_root: Path, pid: int) -> int:
    try:
        stat = (proc_root / str(pid) / "stat").read_text(encoding="utf-8")
        return int(stat.rsplit(")", 1)[1].split()[1])
    except (OSError, ValueError, IndexError):
        return 0


def is_module(args: list[str], module: str) -> bool:
    return args[1:3] == ["-m", module]


def scan(results: Path, proc_root: Path = Path("/proc")) -> tuple[list[int], list[int], dict[str, list[int]]]:
    """Find the coordinator, supervisor and live pipeline.run workers."""
    results = results.resolve()
    coordinators: list[int] = []
    supervisors: list[int] = []
    workers: dict[str, list[int]] = {}
    for entry in proc_root.iterdir():
        if not entry.name.isdigit():
            continue
        args = command_args(entry)
        if not args:
            continue
        value = flag_value(args, "--results")
        if value is None or Path(value).resolve() != results:
            continue
        pid = int(entry.name)
        if is_module(args, "pipeline.synthesize_batch"):
            coordinators.append(pid)
        elif is_module(args, "pipeline.supervise"):
            supervisors.append(pid)
        elif is_module(args, "pipeline.run"):
            # harbor.py forks a short-lived multiprocessing child for one
            # acceptance check. It inherits the worker's cmdline but is not a
            # second synthesis worker.
            parent = parent_pid(proc_root, pid)
            if parent > 1 and is_module(command_args(proc_root / str(parent)), "pipeline.run"):
                continue
            task = flag_value(args, "--only")
            if task:
                workers.setdefault(task, []).append(pid)
    return coordinators, supervisors, workers


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--sample", type=Path, required=True)
    parser.add_argument("--results", type=Path, required=True)
    parser.add_argument("--tasks-file", type=Path,
                        help="count only the ids in this file; default: all selection.jsonl")
    parser.add_argument("--json", action="store_true", help="machine-readable output")
    args = parser.parse_args()
    sample = args.sample.resolve()
    results = args.results.resolve()
    rows = selection_rows(sample)
    if args.tasks_file is not None:
        targets = resolve_targets(task_file_tokens(args.tasks_file.resolve()), rows, results)
    else:
        targets = [row["task_id"] for row in rows]

    coordinators, supervisors, workers = scan(results)
    counts: Counter[str] = Counter()
    live_counts: Counter[str] = Counter()
    stale_counts: Counter[str] = Counter()
    for task in targets:
        record = load_json(results / task / "result.json", {})
        status = str(record.get("status") or "missing") if isinstance(record, dict) else "missing"
        counts[status] += 1
        if task in workers:
            live_counts[status] += 1
        elif status in IN_FLIGHT:
            stale_counts[status] += 1

    live_tasks = set(workers) & set(targets)
    live_pids = sum(len(pids) for task, pids in workers.items() if task in set(targets))
    extra_workers = sorted(set(workers) - set(targets))
    terminal = sum(counts[status] for status in TERMINAL)
    stale = sum(stale_counts.values())
    always = {"preparing", "routing", "synthesizing", "reviewing", "harbor"}
    stages = [stage for stage in STAGES if counts.get(stage) or stage in always]
    stages += sorted(set(counts) - set(stages))
    summary = {
        "time": timestamp(),
        "sample": str(sample),
        "results": str(results),
        "target": len(targets),
        "terminal": terminal,
        "remaining": len(targets) - terminal,
        "live_tasks": len(live_tasks),
        "live_pids": live_pids,
        "stale": stale,
        "coordinators": coordinators,
        "supervisors": supervisors,
        "stages": {stage: {"tasks": counts.get(stage, 0),
                           "live": live_counts.get(stage, 0),
                           "stale": stale_counts.get(stage, 0)}
                   for stage in stages},
    }
    if args.json:
        print(json.dumps(summary, ensure_ascii=False))
        return 0

    print(f"synthesis status @ {summary['time']}")
    print(f"sample={sample}")
    print(f"results={results}")
    print(f"coordinator: {'running pid=' + ','.join(map(str, coordinators)) if coordinators else 'stopped'}")
    print(f"supervisor:  {'running pid=' + ','.join(map(str, supervisors)) if supervisors else 'stopped'}")
    print(f"workers:     {live_pids} process(es) for {len(live_tasks)} target task(s)")
    if not coordinators and not supervisors and live_pids:
        print("note: coordinator/supervisor stopped; live workers finish current tasks "
              "and are adopted when the same command is rerun")
    if extra_workers:
        print(f"note: {len(extra_workers)} live worker task(s) are outside the target list")
    print()
    print(f"{'stage':<14} {'tasks':>6} {'live':>6} {'stale':>6}")
    for stage in stages:
        print(f"{stage:<14} {counts.get(stage, 0):>6} {live_counts.get(stage, 0):>6} "
              f"{stale_counts.get(stage, 0):>6}")
    print()
    print(f"target={len(targets)} terminal={terminal} remaining={len(targets) - terminal} "
          f"live_tasks={len(live_tasks)} stale={stale}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())