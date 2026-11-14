#!/usr/bin/env python3
"""Collect per-stage SFT conversations from a results directory.

Each stage writes one ``sft.jsonl`` (Qwen/OpenAI-style messages) under
``results/<batch>/<task>/<stage>/``. A retried task overwrites the same file,
so a task contributes at most one conversation per stage; earlier attempts are
not archived. This tool gathers them into a single JSONL and can filter by the
task's final status.

    python3 scripts/export_sft.py --results results/batch-01 --out sft-batch-01.jsonl
    python3 scripts/export_sft.py --results results/batch-01 --status passed \
        --stages synthesis --out sft-passed-synthesis.jsonl
"""
from __future__ import annotations

import argparse
import json
from pathlib import Path

STAGES = ("route", "synthesis", "review")
TERMINAL = ("passed", "failed", "error", "rejected", "timeout")


def task_status(results: Path, task: str) -> str:
    try:
        return str(json.loads((results / task / "result.json").read_text()).get("status") or "")
    except (OSError, ValueError):
        return ""


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--results", type=Path, required=True)
    parser.add_argument("--out", type=Path, required=True)
    parser.add_argument("--stages", nargs="*", default=list(STAGES))
    parser.add_argument("--status", nargs="*", default=None,
                        help="only tasks whose result.json status is in this list")
    parser.add_argument("--tasks-file", type=Path, default=None,
                        help="only these task ids (one per line)")
    args = parser.parse_args()
    results: Path = args.results.resolve()
    wanted = None
    if args.tasks_file and args.tasks_file.is_file():
        wanted = {line.strip() for line in args.tasks_file.read_text().splitlines() if line.strip()}
    seen: set[tuple[str, str]] = set()
    written = skipped_status = 0
    counts = {stage: 0 for stage in args.stages}
    args.out.parent.mkdir(parents=True, exist_ok=True)
    with args.out.open("w", encoding="utf-8") as handle:
        for stage in args.stages:
            for path in sorted(results.glob(f"*/{stage}/sft.jsonl")):
                task = path.parent.parent.name
                if wanted is not None and task not in wanted:
                    continue
                status = task_status(results, task)
                if args.status and status not in args.status:
                    skipped_status += 1
                    continue
                key = (task, stage)
                if key in seen:
                    continue
                seen.add(key)
                try:
                    payload = json.loads(path.read_text(encoding="utf-8"))
                except (OSError, ValueError):
                    continue
                metadata = payload.setdefault("metadata", {})
                metadata["source_path"] = str(path.relative_to(results))
                metadata["task_status"] = status or "unknown"
                handle.write(json.dumps(payload, ensure_ascii=False) + "\n")
                written += 1
                counts[stage] += 1
    print(f"wrote {written} conversations to {args.out}")
    print("by stage:", counts, "skipped_by_status:", skipped_status)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())