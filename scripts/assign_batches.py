#!/usr/bin/env python3
"""Assign the per-row ``batch`` partition to a frozen candidate pool.

Rows keep their original file order. Batch numbers are 1-based natural
numbers and every batch holds ``--batch-size`` rows except the last. The
rewrite is atomic, so an interrupted run leaves the input untouched.

Use this after regenerating the available-candidate pool (for example after
``filter_pool_by_s3.py``) and update ``APPROVED_POOL_SHA256`` in
``pipeline/prepare.py`` to the printed digest.
"""
from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))

from pipeline.common import read_jsonl, sha256, write_jsonl  # noqa: E402


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--input", type=Path, required=True)
    parser.add_argument("--output", type=Path,
                        help="output path (default: rewrite --input atomically)")
    parser.add_argument("--batch-size", type=int, default=2000)
    args = parser.parse_args()
    if args.batch_size < 1:
        parser.error("--batch-size must be positive")
    rows = list(read_jsonl(args.input))
    if not rows:
        parser.error("input pool is empty")
    instance_ids = [row.get("instance_id") for row in rows]
    if any(not isinstance(value, str) or not value for value in instance_ids):
        parser.error("every row needs a non-empty instance_id")
    if len(set(instance_ids)) != len(instance_ids):
        parser.error("input pool contains duplicate instance_id values")
    for index, row in enumerate(rows):
        row["batch"] = index // args.batch_size + 1
    output = args.output or args.input
    write_jsonl(output, rows)
    print(json.dumps({
        "rows": len(rows), "batch_size": args.batch_size,
        "batches": rows[-1]["batch"], "output": str(output),
        "sha256": sha256(output),
    }, ensure_ascii=False))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())