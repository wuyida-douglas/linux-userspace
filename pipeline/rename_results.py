#!/usr/bin/env python3
"""Rename completed task directories to canonical-id + route-branch names.

The sample/selection task id remains the internal identity used by
``--only`` and ``result.json.task_id``. This tool only changes the visible
result directory name after a batch is terminal, for example:

    linux-002-osv-2020-2098-unetworking-uwebsockets
        -> osv-2020-2098-file-pov

It is deliberately post-batch: renaming while a supervisor is polling
``<results>/<task_id>/result.json`` would make the worker disappear.
"""
from __future__ import annotations

import argparse
import json
from pathlib import Path

from .common import display_task_id, timestamp, write_json


def load(path: Path) -> dict:
    try:
        return json.loads(path.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError):
        return {}


def rename_batch(batch: Path, *, dry_run: bool = False) -> dict[str, str]:
    mapping: dict[str, str] = {}
    used: dict[str, str] = {}
    for task_dir in sorted(path for path in batch.iterdir() if path.is_dir()):
        route_path = task_dir / "workspace/route.json"
        if not route_path.is_file():
            continue
        route = load(route_path)
        result = load(task_dir / "result.json")
        branch = route.get("branch") or "UNROUTED"
        instance = route.get("instance_id") or result.get("instance_id") or task_dir.name
        base = display_task_id(instance, branch, route.get("host_type"))
        name = base
        suffix = 2
        while name in used and used[name] != task_dir.name:
            name = f"{base}-{suffix}"
            suffix += 1
        used[name] = task_dir.name
        if name == task_dir.name:
            continue
        target = batch / name
        if target.exists():
            raise FileExistsError(f"cannot rename {task_dir} -> {target}: target exists")
        mapping[task_dir.name] = name
        if not dry_run:
            task_dir.rename(target)
            result["folder_name"] = name
            write_json(target / "result.json", result)
    if not dry_run:
        previous = load(batch / "renames.json").get("mapping", {})
        if mapping or previous:
            previous.update(mapping)
            write_json(batch / "renames.json", {
                "schema_version": 1,
                "generated_at": timestamp(),
                "mapping": previous,
            })
    return mapping


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("results", nargs="+", type=Path,
                        help="run directory, or a batch-* directory")
    parser.add_argument("--dry-run", action="store_true")
    args = parser.parse_args()
    for root in args.results:
        batches = sorted(path for path in root.glob("batch-*") if path.is_dir()) if root.is_dir() else []
        if not batches:
            batches = [root] if root.is_dir() else []
        for batch in batches:
            mapping = rename_batch(batch, dry_run=args.dry_run)
            if mapping:
                print(f"{batch}: {len(mapping)} renamed"
                      + (" (dry-run)" if args.dry_run else ""))
                for old, new in mapping.items():
                    print(f"  {old} -> {new}")
            else:
                print(f"{batch}: no renames")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())