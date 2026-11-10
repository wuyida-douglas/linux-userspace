#!/usr/bin/env python3
"""Remove pool rows whose source snapshot is confirmed absent from the S3 mirror.

A row is confirmed absent only when neither the bare ``osv_<CVE>`` /
``cvelist_<CVE>`` directory nor an ecosystem alias directory (for example
``osv_UBUNTU-CVE-...``) contains a candidate matching the row. Exact-path rows
are kept without a full byte-level download; this tool removes the systematic
no-snapshot gap, not transient transfer errors.
"""
from __future__ import annotations

import argparse
import concurrent.futures
import hashlib
import json
import re
import subprocess
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))

from pipeline.common import read_jsonl, sha256, timestamp, write_json, write_jsonl  # noqa: E402
from pipeline.prepare import DEFAULT_REMOTE, s3_canonical_id, select_candidate  # noqa: E402

ALIAS_RE = re.compile(r"^osv_[A-Za-z0-9_.]+-(CVE-\d{4}-\d+)$", re.I)


def s3_dirs(remote: str, listing: Path | None) -> list[str]:
    if listing is not None:
        return [line.strip().rstrip("/") for line in listing.read_text(encoding="utf-8").splitlines()
                if line.strip()]
    result = subprocess.run(
        ["rclone", "lsf", remote, "--dirs-only", "--max-depth", "1"],
        capture_output=True, text=True, check=True, timeout=180)
    return [line.strip().rstrip("/") for line in result.stdout.splitlines() if line.strip()]


def alias_map(dirs: list[str]) -> dict[str, list[str]]:
    aliases: dict[str, list[str]] = {}
    for name in dirs:
        match = ALIAS_RE.match(name)
        if match:
            aliases.setdefault(match.group(1).upper(), []).append(name)
    return aliases


def fetch_meta(remote: str, directory: str) -> list[dict] | None:
    try:
        result = subprocess.run(
            ["rclone", "cat", f"{remote}/{directory}/meta.json"],
            capture_output=True, text=True, check=True, timeout=60)
        meta = json.loads(result.stdout)
    except (OSError, subprocess.SubprocessError, json.JSONDecodeError):
        return None
    return (meta.get("code") or {}).get("candidates") or meta.get("candidates") or []


def candidate_matches(candidates: list[dict], row: dict) -> bool:
    wanted = row.get("candidate_id")
    if wanted and any(x.get("candidate_id") == wanted for x in candidates):
        return True
    # Reuse the exact same fallback as prepare.py without mutating the row.
    probe = {"candidate_id": wanted or "", "repo": row.get("repo")}
    return select_candidate({"code": {"candidates": candidates}}, probe) is not None


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--input", type=Path, required=True)
    parser.add_argument("--output", type=Path, required=True)
    parser.add_argument("--removed", type=Path, required=True)
    parser.add_argument("--report", type=Path, required=True)
    parser.add_argument("--remote", default=DEFAULT_REMOTE)
    parser.add_argument("--s3-listing", type=Path,
                        help="cached `rclone lsf --dirs-only --max-depth 1` output")
    parser.add_argument("--workers", type=int, default=20)
    args = parser.parse_args()
    rows = list(read_jsonl(args.input))
    dirs = s3_dirs(args.remote, args.s3_listing)
    dir_set = set(dirs)
    aliases = alias_map(dirs)

    def candidate_for(row: dict) -> dict:
        return (row.get("code") or {}).get("candidates", [{}])[0]

    def bare_norm(row: dict) -> str:
        return s3_canonical_id(row["canonical_id"])

    alias_rows = [row for row in rows
                  if not (f"osv_{bare_norm(row)}" in dir_set or
                          f"cvelist_{bare_norm(row)}" in dir_set)
                  and aliases.get(row["canonical_id"].upper())]
    needed = sorted({d for row in alias_rows
                     for d in aliases.get(row["canonical_id"].upper(), [])})
    metas: dict[str, list[dict] | None] = {}
    with concurrent.futures.ThreadPoolExecutor(max_workers=max(1, args.workers)) as pool:
        for directory, candidates in zip(needed, pool.map(lambda d: fetch_meta(args.remote, d), needed)):
            metas[directory] = candidates

    kept, removed = [], []
    for row in rows:
        candidate = candidate_for(row)
        probe = {**row, "candidate_id": candidate.get("candidate_id")}
        norm = bare_norm(row)
        if f"osv_{norm}" in dir_set or f"cvelist_{norm}" in dir_set:
            kept.append(row)
            continue
        alias_dirs = aliases.get(row["canonical_id"].upper(), [])
        if not alias_dirs:
            removed.append({"instance_id": row["instance_id"], "canonical_id": row["canonical_id"],
                            "reason": "no exact or alias S3 directory"})
            continue
        matched = [d for d in alias_dirs if metas.get(d) and candidate_matches(metas[d], probe)]
        if matched:
            kept.append(row)
        else:
            removed.append({"instance_id": row["instance_id"], "canonical_id": row["canonical_id"],
                            "reason": "alias S3 directories exist but none contains the candidate"})

    args.output.parent.mkdir(parents=True, exist_ok=True)
    temporary = args.output.with_suffix(args.output.suffix + ".tmp")
    write_jsonl(temporary, kept)
    temporary.replace(args.output)
    args.removed.parent.mkdir(parents=True, exist_ok=True)
    write_jsonl(args.removed, removed)
    reasons: dict[str, int] = {}
    for item in removed:
        reasons[item["reason"]] = reasons.get(item["reason"], 0) + 1
    cve_ids = {match.group(1).upper() for name in dirs
               if (match := re.search(r"(CVE-\d{4}-\d+)", name, re.I))}
    alias_removed = reasons.get("alias S3 directories exist but none contains the candidate", 0)
    write_json(args.report, {
        "schema_version": 1,
        "created_at": timestamp(),
        "source": {"path": str(args.input), "sha256": sha256(args.input), "rows": len(rows)},
        "s3": {"remote": args.remote, "top_level_dirs": len(dirs),
               "unique_cve_ids": len(cve_ids)},
        "kept": {"path": str(args.output), "sha256": sha256(args.output), "rows": len(kept)},
        "removed": {"path": str(args.removed), "rows": len(removed), "reasons": reasons},
        "alias": {"directories": len(needed), "rows_with_alias_dirs": len(alias_rows),
                  "rows_recovered": len(alias_rows) - alias_removed},
    })
    print(json.dumps({"kept": len(kept), "removed": len(removed), "reasons": reasons},
                     ensure_ascii=False))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())