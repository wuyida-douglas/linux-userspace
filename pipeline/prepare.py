#!/usr/bin/env python3
"""Sample instances and download only their vulnerable prefix and fix.diff.

The original sample retains every availability failure. An explicit top-up
sample excludes those instances and continues the seeded random stream until
it has the requested number of complete inputs. Both histories are preserved.
"""
from __future__ import annotations

import argparse
import concurrent.futures
import json
import os
import random
import re
import shutil
import subprocess
import tempfile
from pathlib import Path
from typing import Any

from .common import ID_RE, inventory, read_jsonl, repository_key, task_id, timestamp, write_json, write_jsonl

DEFAULT_INPUT = Path(__file__).resolve().parents[1] / "data/remaining-38901.instances.jsonl"
DEFAULT_REMOTE = "p_huawei_hdd1:private-data-3/DataWheel/en-code-osv-nvd/file"


def sample(path: Path, count: int, seed: int) -> list[dict[str, Any]]:
    rows = list(read_jsonl(path))
    if not 1 <= count <= len(rows):
        raise ValueError(f"count must be 1..{len(rows)}")
    chosen = random.Random(seed).sample(rows, count)
    return [sample_from_row(row, index) for index, row in enumerate(chosen, 1)]


def sample_from_row(row: dict[str, Any], index: int) -> dict[str, Any]:
    candidates = (row.get("code") or {}).get("candidates") or []
    candidate = candidates[0] if candidates else {}
    return {
        "sample_id": index,
        "task_id": task_id(row, index),
        "instance_id": row["instance_id"],
        "canonical_id": row["canonical_id"],
        "source_hint": (row.get("sources") or [None])[0],
        "candidate_id": candidate.get("candidate_id"),
        "repo": row.get("repo"),
        "vulnerability": row.get("vulnerability"),
        "code": row.get("code"),
        "old_tags": row.get("old_tags"),
    }


def sample(path: Path, count: int, seed: int, exclude: set[str] | None = None) -> list[dict[str, Any]]:
    rows = list(read_jsonl(path))
    exclude = exclude or set()
    rows = [row for row in rows if row["instance_id"] not in exclude]
    if not 1 <= count <= len(rows):
        raise ValueError(f"count must be 1..{len(rows)} after exclusions")
    chosen = random.Random(seed).sample(rows, count)
    return [sample_from_row(row, index) for index, row in enumerate(chosen, 1)]


def complete_instances(path: Path) -> set[str]:
    return {row["instance_id"] for row in read_jsonl(path)
            if row.get("status") == "complete" and row.get("integrity_ok") is not False}


def safe_prepare(row: dict[str, Any], destination: Path, remote: str) -> dict[str, Any]:
    try:
        return prepare_one(row, destination, remote)
    except (OSError, ValueError, RuntimeError, subprocess.SubprocessError,
            json.JSONDecodeError) as exc:
        return {key: row[key] for key in ("sample_id", "task_id", "instance_id", "canonical_id")} | {
            "status": "error", "error": f"{type(exc).__name__}: {exc}"}


def top_up(source: Path, original: Path, destination: Path, count: int,
           seed: int, workers: int, remote: str) -> int:
    """Continue a random stream until count usable inputs, not count attempts."""
    if count < 1 or workers < 1:
        raise ValueError("top-up count and workers must be positive")
    destination.mkdir(parents=True, exist_ok=True)
    selection = destination / "selection.jsonl"
    report_path = original / "download-report.json"
    if report_path.is_file():
        report = json.loads(report_path.read_text(encoding="utf-8"))
        original_rows = {row["instance_id"]: row for row in report["tasks"]}
    else:
        # A sample-only manifest is a valid starting point. Missing downloads
        # are resolved in this invocation instead of requiring a dummy report.
        original_rows = {row["instance_id"]: row | {"status": "pending"}
                         for row in read_jsonl(original / "selection.jsonl")}
    catalog = {row["instance_id"]: row for row in read_jsonl(source)}
    if selection.exists():
        rows = list(read_jsonl(selection))
        if len(rows) > count:
            raise ValueError(f"existing top-up selection has {len(rows)} rows, requested {count}; trim explicitly")
        selected_ids = {row["instance_id"] for row in rows}
        rows = [row for row in rows
                if (destination / "tasks" / row["task_id"] / "input/manifest.json").is_file()]
        # A finalized sample is immutable. A reordered prefix may only be
        # written for an explicitly interrupted download before its marker.
        if len(rows) != len(selected_ids) and (destination / "sample.json").is_file():
            previous_sample = json.loads((destination / "sample.json").read_text(encoding="utf-8"))
            if previous_sample.get("completed_at"):
                raise ValueError("finalized selection has missing task inputs; refusing to renumber")
        write_jsonl(selection, rows)
    else:
        rows = [row for row in read_jsonl(original / "selection.jsonl")
                if original_rows.get(row["instance_id"], {}).get("status") == "complete"]
        write_jsonl(selection, rows)
    # With a sample-only source, statuses in the original selection are just
    # placeholders. The retained, manifest-backed rows are the real baseline.
    original_complete = sum(row["instance_id"] in original_rows for row in rows)
    write_json(destination / "sample.json", {
        "seed": seed, "count": count, "source": str(source), "original_sample": str(original),
        "original_complete": original_complete,
        "strategy": "exclude-original-failures-then-seeded-top-up",
        "created_at": timestamp()})
    excluded = set(original_rows)
    history_path = destination / "download-history.jsonl"
    rejected_path = destination / "rejected-instances.jsonl"
    history = list(read_jsonl(history_path)) if history_path.exists() else list(original_rows.values())
    rejected = list(read_jsonl(rejected_path)) if rejected_path.exists() else [
        row for row in original_rows.values() if row.get("status") != "complete"]
    # An interrupted round may have committed task directories before its
    # terminal history was flushed. Recover provenance from those manifests.
    destination.joinpath("tasks").mkdir(exist_ok=True)
    known = {row["instance_id"] for row in history}
    for task_path in sorted((destination / "tasks").iterdir()):
        if not task_path.is_dir() or task_path.is_symlink():
            continue
        manifest_path = task_path / "input/manifest.json"
        if not manifest_path.is_file():
            continue
        manifest = json.loads(manifest_path.read_text(encoding="utf-8"))
        instance_id = manifest["instance_id"]
        if instance_id in known or instance_id in original_rows:
            continue
        row = {"sample_id": 0, "task_id": task_path.name, "instance_id": instance_id,
               "canonical_id": instance_id.split("::", 1)[0], "status": manifest["status"],
               "errors": manifest.get("errors", []), "file_count": manifest["file_count"],
               "total_bytes": manifest["total_bytes"]}
        history.append(row)
        known.add(instance_id)
    write_jsonl(history_path, history)
    write_jsonl(rejected_path, rejected)
    excluded.update(row["instance_id"] for row in history)
    excluded.update(row["instance_id"] for row in rejected)
    destination.joinpath("tasks").mkdir(exist_ok=True)
    for row in rows:
        target = destination / "tasks" / row["task_id"]
        if target.exists():
            continue
        source_task = original / "tasks" / row["task_id"]
        if source_task.exists():
            os.symlink(os.path.relpath(source_task, target.parent), target, target_is_directory=True)
            continue
        # Recover a committed download from an interrupted round even when its
        # randomly assigned sample position changed on resume.
        previous = next((item for item in reversed(history)
                         if item.get("instance_id") == row["instance_id"]
                         and item.get("status") == "complete"
                         and (destination / "tasks" / item["task_id"] / "input/manifest.json").is_file()), None)
        if previous is not None:
            os.rename(destination / "tasks" / previous["task_id"], target)
            task_path = target / "task.json"
            task = json.loads(task_path.read_text(encoding="utf-8"))
            task["task_id"] = row["task_id"]
            write_json(task_path, task)
    # Resume repairable partial caches before spending bandwidth on new draws.
    attempted_repair = {item["instance_id"] for item in history if item.get("repaired")}
    partials_by_instance = {}
    for item in history:
        if (item.get("status") == "partial" and item.get("errors") == ["fix.diff is missing"]
                and item["instance_id"] not in attempted_repair
                and (destination / "tasks" / item["task_id"] / "input/manifest.json").is_file()):
            partials_by_instance[item["instance_id"]] = item
    partials = list(partials_by_instance.values())
    with concurrent.futures.ThreadPoolExecutor(max_workers=workers) as pool:
        repaired = list(pool.map(lambda row: safe_prepare(row, destination / "tasks", remote), partials))
    for original_record, record in zip(partials, repaired):
        print(f"repair {record['status']} {record['canonical_id']}", flush=True)
        history.append(record)
        excluded.add(record["instance_id"])
        if record["status"] != "complete":
            continue
        if record["instance_id"] in {row["instance_id"] for row in rows}:
            continue
        if len(rows) >= count:
            # A prior interrupted run may have recovered more candidates than
            # requested. Keep their valid caches, but not in this sample.
            continue
        source_task = destination / "tasks" / original_record["task_id"]
        task_path = source_task / "task.json"
        task = json.loads(task_path.read_text(encoding="utf-8"))
        task["input_status"] = "complete"
        write_json(task_path, task)
        next_id = len(rows) + 1
        candidate = sample_from_row(catalog[record["instance_id"]], next_id)
        os.rename(source_task, destination / "tasks" / candidate["task_id"])
        task_path = destination / "tasks" / candidate["task_id"] / "task.json"
        task = json.loads(task_path.read_text(encoding="utf-8"))
        task["task_id"] = candidate["task_id"]
        write_json(task_path, task)
        rows.append(candidate)
        write_jsonl(selection, rows)
    write_jsonl(history_path, history)
    next_id = len(rows) + 1
    # A resumed top-up may have repaired some of its existing incomplete
    # cache before drawing anything. Continue past historical download IDs;
    # len(rows) is not the number of random draws already attempted.
    round_number = max((int(match.group(1)) for row in history
                        if (match := re.match(r"download-(\d+)-\d+$", str(row.get("task_id", ""))))),
                       default=0)
    while len(rows) < count:
        round_number += 1
        wanted = count - len(rows)
        candidates = sample(source, wanted, seed + 1000 + round_number, excluded)
        for candidate in candidates:
            # Download directories use round-local names; sample_id/task_id
            # are assigned only after their manifest proves a complete input.
            candidate["task_id"] = f"download-{round_number:03d}-{candidate['sample_id']:03d}"
        excluded.update(row["instance_id"] for row in candidates)
        print(f"top-up round {round_number}: {len(rows)} complete; checking {len(candidates)}", flush=True)
        with concurrent.futures.ThreadPoolExecutor(max_workers=workers) as pool:
            records = list(pool.map(lambda row: safe_prepare(row, destination / "tasks", remote), candidates))
        for candidate, record in zip(candidates, records):
            print(f"[{record['sample_id']:03d}] {record['status']} {record['canonical_id']}", flush=True)
            previous_history = list(read_jsonl(history_path))
            write_jsonl(history_path, previous_history + [record])
            if record["status"] != "complete":
                rejected = list(read_jsonl(rejected_path))
                write_jsonl(rejected_path, rejected + [candidate | {"download_error": record.get("error")}])
                continue
            candidate["sample_id"] = next_id
            candidate["task_id"] = task_id(candidate, next_id)
            os.rename(destination / "tasks" / record["task_id"], destination / "tasks" / candidate["task_id"])
            task_path = destination / "tasks" / candidate["task_id"] / "task.json"
            task = json.loads(task_path.read_text(encoding="utf-8"))
            task["task_id"] = candidate["task_id"]
            write_json(task_path, task)
            record.update(sample_id=next_id, task_id=candidate["task_id"])
            rows.append(candidate)
            write_jsonl(selection, rows)
            write_jsonl(destination / "completed-selection.jsonl", rows)
            next_id += 1
            if len(rows) == count:
                break
    write_json(destination / "sample.json", {
        "seed": seed, "count": len(rows), "source": str(source), "original_sample": str(original),
        "original_complete": original_complete,
        "rounds": round_number, "strategy": "exclude-original-failures-then-seeded-top-up",
        "completed_at": timestamp()})
    print(json.dumps({"complete": len(rows), "rounds": round_number}))
    return 0


def copy(remote: str, destination: Path, *, directory: bool = False) -> None:
    destination.parent.mkdir(parents=True, exist_ok=True)
    command = ["rclone", "copy" if directory else "copyto", remote, str(destination),
               "--contimeout", "20s", "--timeout", "120s", "--retries", "2"]
    if directory:
        # S3 rejects some valid repository filenames (e.g. a trailing dot) during
        # rclone's server-side directory recursion. List first, then exact copyto.
        listing = subprocess.run(["rclone", "lsf", remote, "--recursive", "--files-only"],
                                 capture_output=True, text=True, check=True, timeout=90)
        names = [name for name in listing.stdout.splitlines()
                 if name and not any(part == ".git" for part in Path(name).parts)]
        special = [name for name in names if any(part.endswith(".") for part in Path(name).parts)]
        special_names = set(special)
        names = [name for name in names if name not in special_names]
        # Recursive copy rejects these valid object names. Exact copyto does
        # not enumerate their parent, so preserve the revision byte-for-byte.
        for name in special:
            copy(f"{remote}/{name}", destination / name)
        with tempfile.NamedTemporaryFile("w", encoding="utf-8", prefix="rclone-files-") as manifest:
            manifest.write("\n".join(names) + "\n")
            manifest.flush()
            # Keep the exact listing (needed for trailing-dot safety), but use
            # rclone's concurrent transfers instead of one S3 request per file.
            subprocess.run(["rclone", "copy", remote, str(destination),
                            "--files-from", manifest.name,
                            "--transfers", "8", "--checkers", "8", "--stats", "60s",
                            "--contimeout", "20s", "--timeout", "120s", "--retries", "2"],
                           check=True, timeout=600)
        return
    try:
        subprocess.run(command, check=True, stdout=subprocess.DEVNULL,
                       stderr=subprocess.PIPE, text=True, timeout=3600)
    except subprocess.CalledProcessError as exc:
        probe = subprocess.run(["rclone", "lsf", remote, "--max-depth", "1"],
                               capture_output=True, text=True, timeout=120)
        if probe.returncode == 0:
            detail = "remote prefix exists but copy failed"
        else:
            detail = (probe.stderr or probe.stdout).strip()[-1000:]
        raise RuntimeError(f"rclone copy failed for {remote}: {detail}; {(exc.stderr or '')[-800:]}") from exc


def prepare_one(row: dict[str, Any], destination: Path, remote: str) -> dict[str, Any]:
    record = {key: row[key] for key in ("sample_id", "task_id", "instance_id", "canonical_id")}
    task = destination / row["task_id"]
    if (task / "input/manifest.json").is_file():
        manifest = json.loads((task / "input/manifest.json").read_text(encoding="utf-8"))
        current = inventory(task / "input", {"manifest.json"})["files"]
        manifest_files = manifest.get("files", manifest)
        integrity_ok = (current.keys() == manifest_files.keys()
                        and all(current[key] == manifest_files[key] for key in current))
        record.update(status=manifest["status"] if integrity_ok else "error", cached=True,
                      file_count=manifest["file_count"], total_bytes=manifest["total_bytes"],
                      integrity_ok=integrity_ok)
        if not integrity_ok:
            record["error"] = "cached input differs from its manifest"
            return record
        if manifest["status"] == "partial" and "fix.diff" in manifest_files and integrity_ok:
            patch = task / "input/fix.diff"
            if patch.stat().st_size > 0 and re.search(r"^diff --git a/.+ b/.+$",
                    patch.read_text(encoding="utf-8", errors="strict"), re.MULTILINE):
                updated = manifest | {"status": "complete", "errors": []}
                write_json(task / "input/manifest.json", updated)
                task_path = task / "task.json"
                task_value = json.loads(task_path.read_text(encoding="utf-8"))
                task_value["input_status"] = "complete"
                write_json(task_path, task_value)
                record.update(status="complete", recovered_late_patch=True)
                return record
        if manifest["status"] == "partial" and manifest.get("errors") == ["fix.diff is missing"]:
            # Reuse the saved source provenance; alternate crawls may disagree.
            meta = json.loads((task / "input/meta.json").read_text(encoding="utf-8"))
            selected = meta["candidate"]
            provenance = [meta.get("source"), row.get("source_hint"), "osv", "cvelist"]
            repaired = False
            for source in dict.fromkeys(x for x in provenance if x in {"osv", "cvelist"}):
                try:
                    base = f"{remote}/{source}_{row['canonical_id']}/candidates/{selected['candidate_id']}"
                    copy(base + "/fix.diff", task / "input/fix.diff")
                    repaired = True
                    break
                except RuntimeError:
                    continue
            if not repaired or not (task / "input/fix.diff").is_file():
                raise RuntimeError("cached source is valid but fix.diff could not be retrieved")
            updated = {"schema_version": 1, "instance_id": row["instance_id"],
                       "status": "complete", "source_file_count": manifest["source_file_count"],
                       "errors": [], **inventory(task / "input", {"manifest.json"})}
            write_json(task / "input/manifest.json", updated)
            write_json(task / "task.json", {"task_id": row["task_id"],
                                            "instance_id": row["instance_id"], "input_status": "complete"})
            record.update(status="complete", repaired=True, cached=False,
                          file_count=updated["file_count"], total_bytes=updated["total_bytes"])
        return record
    staging = Path(tempfile.mkdtemp(prefix=".staging-", dir=destination))
    errors: list[str] = []
    try:
        selected = None
        source = None
        metadata_errors: list[str] = []
        # The catalog records provenance order. Probe only exact objects for
        # this CVE, never an entire bucket or all source snapshots.
        for name in ["osv", row.get("source_hint"), "cvelist"]:
            if name not in {"osv", "cvelist"}:
                continue
            try:
                base = f"{remote}/{name}_{row['canonical_id']}"
                copy(base + "/meta.json", staging / "meta.json")
                meta_path = staging / "meta.json"
                if meta_path.stat().st_size == 0:
                    raise ValueError("S3 metadata object is empty or absent")
                meta = json.loads(meta_path.read_text(encoding="utf-8"))
                candidates = meta.get("code", {}).get("candidates") or meta.get("candidates") or []
                selected = next((x for x in candidates if x.get("candidate_id") == row["candidate_id"]), None)
                # The catalog and a later S3 crawl may use different commit
                # identifiers. Prefer an exact match, never mix repositories.
                if selected is None:
                    selected = next((x for x in candidates
                                     if repository_key(x.get("repo") or (x.get("prefix") or {}).get("repo")
                                                       or (x.get("fix") or {}).get("repo")) == repository_key(row["repo"])
                                     and (x.get("prefix") or {}).get("revision")
                                     and (x.get("fix") or {}).get("revision")), None)
                if selected and ID_RE.fullmatch(selected["candidate_id"]):
                    source = name
                    break
            except (subprocess.CalledProcessError, subprocess.SubprocessError, OSError, ValueError,
                    RuntimeError,
                    json.JSONDecodeError, KeyError, TypeError) as exc:
                metadata_errors.append(f"{name}: {type(exc).__name__}: {exc}")
                continue
        if selected is None or source is None:
            raise ValueError("no usable source snapshot for the selected instance; " +
                             " | ".join(metadata_errors))
        candidate_id = selected["candidate_id"]
        base = f"{remote}/{source}_{row['canonical_id']}/candidates/{candidate_id}"
        prefix = staging / "prefix"
        copy(base + "/prefix", prefix, directory=True)
        if not any(path.is_file() for path in prefix.rglob("*")):
            raise ValueError("empty prefix source")
        try:
            copy(base + "/fix.diff", staging / "fix.diff")
        except (subprocess.CalledProcessError, subprocess.TimeoutExpired, RuntimeError):
            errors.append("fix.diff is missing")
        source_files = 0
        for path in prefix.rglob("*"):
            if path.is_symlink():
                target = path.resolve(strict=False)
                if path.readlink().is_absolute() or not target.is_relative_to(prefix.resolve()):
                    raise ValueError(f"unsafe source symlink: {path.relative_to(prefix)}")
            elif path.is_file():
                source_files += 1
        public = {
            "instance_id": row["instance_id"], "cve": row["canonical_id"],
            "repo": row["repo"], "candidate_id": candidate_id,
            "catalog_candidate_id": row.get("candidate_id"),
            "candidate_selection": "exact" if candidate_id == row.get("candidate_id") else "same-upstream-snapshot-fallback",
            "source": source, "vulnerability": row["vulnerability"],
            "candidate": selected, "old_tags": row["old_tags"],
        }
        input_dir = staging / "input"
        input_dir.mkdir()
        os.replace(prefix, input_dir / "src")
        (input_dir / "meta.json").write_text(json.dumps(public, ensure_ascii=False, indent=2) + "\n",
                                             encoding="utf-8")
        if (staging / "fix.diff").is_file():
            os.replace(staging / "fix.diff", input_dir / "fix.diff")
        if not (staging / "fix.diff").is_file():
            errors.append("fix.diff is missing")
        status = "partial" if errors else "complete"
        manifest = {"schema_version": 1, "instance_id": row["instance_id"], "status": status,
                    "source_file_count": source_files, "errors": errors,
                    **inventory(input_dir)}
        write_json(input_dir / "manifest.json", manifest)
        write_json(staging / "task.json", {"task_id": row["task_id"], "instance_id": row["instance_id"],
                                           "input_status": status})
        if task.exists():
            raise FileExistsError(f"refusing to overwrite an existing task without a valid manifest: {task}")
        os.replace(staging, task)
        record.update(status=status, source=source, candidate_id=candidate_id,
                      source_file_count=source_files, errors=errors,
                      file_count=manifest["file_count"], total_bytes=manifest["total_bytes"])
        return record
    except (OSError, ValueError, RuntimeError, subprocess.SubprocessError, json.JSONDecodeError) as exc:
        record.update(status="error", error=f"{type(exc).__name__}: {exc}", errors=errors)
        return record
    finally:
        shutil.rmtree(staging, ignore_errors=True)


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--input", type=Path, default=DEFAULT_INPUT)
    parser.add_argument("--output", type=Path, required=True)
    parser.add_argument("--count", type=int, default=100)
    parser.add_argument("--seed", type=int, default=20261103)
    parser.add_argument("--workers", type=int, default=4)
    parser.add_argument("--sample-only", action="store_true")
    parser.add_argument("--remote", default=DEFAULT_REMOTE)
    parser.add_argument("--only", nargs="+")
    parser.add_argument("--top-up-from", type=Path,
                        help="preserve complete inputs from this sample and top up to --count")
    args = parser.parse_args()
    if args.top_up_from:
        if args.only or args.sample_only:
            parser.error("--top-up-from cannot be combined with --only or --sample-only")
        if not 1 <= args.workers <= 20:
            parser.error("workers must be 1..20")
        return top_up(args.input, args.top_up_from, args.output, args.count,
                      args.seed, args.workers, args.remote)
    args.output.mkdir(parents=True, exist_ok=True)
    selection = args.output / "selection.jsonl"
    if selection.exists():
        rows = list(read_jsonl(selection))
        if len(rows) != args.count:
            raise ValueError("existing selection has a different count; choose another output directory")
    elif args.only:
        raise ValueError("cannot repair a partial selection before the fixed sample is created")
    else:
        rows = sample(args.input, args.count, args.seed)
        write_jsonl(selection, rows)
        write_json(args.output / "sample.json", {"seed": args.seed, "count": len(rows),
                                                 "input": str(args.input), "created_at": timestamp()})
    if args.only:
        wanted = set(args.only)
        rows = [row for row in rows if row["task_id"] in wanted or row["canonical_id"] in wanted]
    if args.sample_only:
        print(json.dumps({"sampled": len(rows), "selection": str(selection)}))
        return 0
    if not 1 <= args.workers <= 20:
        parser.error("workers must be 1..20")
    (args.output / "tasks").mkdir(exist_ok=True)
    def prepare_record(row: dict[str, Any]) -> dict[str, Any]:
        try:
            return prepare_one(row, args.output / "tasks", args.remote)
        except (OSError, ValueError, RuntimeError, subprocess.SubprocessError,
                json.JSONDecodeError) as exc:
            # One corrupt object or an unwritable cache must not erase the
            # records of all other fixed-sample tasks in this batch.
            return {key: row[key] for key in ("sample_id", "task_id", "instance_id", "canonical_id")} | {
                "status": "error", "error": f"{type(exc).__name__}: {exc}"}

    with concurrent.futures.ThreadPoolExecutor(max_workers=args.workers) as pool:
        records = list(pool.map(prepare_record, rows))
    counts: dict[str, int] = {}
    for record in records:
        counts[record["status"]] = counts.get(record["status"], 0) + 1
        print(f"[{record['sample_id']:03d}] {record['status']} {record['canonical_id']}", flush=True)
    write_json(args.output / "download-report.json", {"selected": len(rows), "counts": counts,
                                                      "tasks": records})
    history_path = args.output / "download-history.jsonl"
    previous = list(read_jsonl(history_path)) if history_path.exists() else []
    merged = {row["task_id"]: row for row in previous}
    merged.update({row["task_id"]: row for row in records})
    write_jsonl(history_path, [merged[task_id] for task_id in sorted(merged)])
    print(json.dumps(counts, ensure_ascii=False))
    return 0 if counts.get("complete", 0) == len(rows) else 1


if __name__ == "__main__":
    raise SystemExit(main())
