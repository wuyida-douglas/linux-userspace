#!/usr/bin/env python3
"""Sample instances and download only their vulnerable prefix and fix.diff.

The original sample retains every availability failure. A cached source with a
subsequently recovered genuine fix.diff is recorded as recovered_late_patch;
it does not change the selected instance or claim first-download completeness.
An explicit top-up sample excludes those instances and continues the seeded
random stream until it has the requested number of complete inputs. Both
histories are preserved; top-up is never the default for a fixed production
sample.
"""
from __future__ import annotations

import argparse
import base64
import concurrent.futures
import email.utils
import hashlib
import hmac
import json
import os
import random
import re
import shutil
import subprocess
import sys
import tempfile
import urllib.error
import urllib.parse
import urllib.request
from pathlib import Path
from typing import Any

from .common import ID_RE, inventory, read_jsonl, repository_key, sha256, task_id, timestamp, write_json, write_jsonl

DEFAULT_INPUT = Path(__file__).resolve().parents[1] / (
    "data/frozen-pool-20261109/candidates-kept-available-20261109.jsonl")
# The frozen 23,873-row labeling output is kept at candidates-kept.jsonl for
# audit. This default is that pool minus rows with no source snapshot under any
# exact or ecosystem-alias S3 directory (see pool-availability-20261109.json).
APPROVED_POOL_SHA256 = "565bdf5914152b3a4f2a00f44c09cc85a38f1b85ae8d42bb833a72c38579e941"
APPROVED_POOL_SIZE = 22138
DEFAULT_REMOTE = "p_huawei_hdd1:private-data-3/DataWheel/en-code-osv-nvd/file"


def sample(path: Path, count: int, seed: int) -> list[dict[str, Any]]:
    rows = list(read_jsonl(path))
    if not 1 <= count <= len(rows):
        raise ValueError(f"count must be 1..{len(rows)}")
    chosen = random.Random(seed).sample(rows, count)
    return [sample_from_row(row, index) for index, row in enumerate(chosen, 1)]


def s3_canonical_id(value: str) -> str:
    """Match the mirror's object naming for advisory identifiers.

    The S3 crawl stores GHSA ids with an uppercase ``GHSA-`` prefix and a
    lowercase suffix, while the catalog keeps the whole id uppercase.
    """
    if value.upper().startswith("GHSA-"):
        return "GHSA-" + value[5:].lower()
    return value


def s3_alias_index(remote: str) -> dict[str, list[str]]:
    """Map a CVE to the mirror's ecosystem-specific OSV directories.

    Ubuntu, CURL and a few other sources publish CVE records under names such
    as ``osv_UBUNTU-CVE-2022-37315``. The frozen catalog only carries the bare
    CVE id, so without this index those snapshots look absent.
    """
    try:
        listing = subprocess.run(
            ["rclone", "lsf", remote, "--dirs-only", "--max-depth", "1"],
            capture_output=True, text=True, check=True, timeout=180)
    except (OSError, subprocess.SubprocessError) as exc:
        print(f"warning: cannot build S3 alias index: {exc}", file=sys.stderr)
        return {}
    aliases: dict[str, list[str]] = {}
    for line in listing.stdout.splitlines():
        name = line.strip().rstrip("/")
        match = re.match(r"^osv_[A-Za-z0-9_.]+-(CVE-\d{4}-\d+)$", name, re.I)
        if match:
            aliases.setdefault(match.group(1).upper(), []).append(name)
    return aliases


def select_candidate(meta: dict[str, Any], row: dict[str, Any]) -> dict[str, Any] | None:
    """Prefer the exact catalog candidate, then the same upstream repository."""
    candidates = meta.get("code", {}).get("candidates") or meta.get("candidates") or []
    selected = next((x for x in candidates if x.get("candidate_id") == row["candidate_id"]), None)
    if selected is None:
        selected = next((x for x in candidates
                         if repository_key(x.get("repo") or (x.get("prefix") or {}).get("repo")
                                           or (x.get("fix") or {}).get("repo")) == repository_key(row["repo"])
                         and (x.get("prefix") or {}).get("revision")
                         and (x.get("fix") or {}).get("revision")), None)
    return selected if selected and ID_RE.fullmatch(selected["candidate_id"]) else None


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


def sample_all(path: Path) -> list[dict[str, Any]]:
    """Use the frozen pool in its original order; no random sampling."""
    rows = list(read_jsonl(path))
    if not rows:
        raise ValueError("candidate pool is empty")
    return [sample_from_row(row, index) for index, row in enumerate(rows, 1)]


def complete_instances(path: Path) -> set[str]:
    return {row["instance_id"] for row in read_jsonl(path)
            if row.get("status") == "complete" and row.get("integrity_ok") is not False}


def safe_prepare(row: dict[str, Any], destination: Path, remote: str,
                 aliases: dict[str, list[str]] | None = None) -> dict[str, Any]:
    try:
        return prepare_one(row, destination, remote, aliases=aliases)
    except (OSError, ValueError, RuntimeError, subprocess.SubprocessError,
            json.JSONDecodeError) as exc:
        return {key: row[key] for key in ("sample_id", "task_id", "instance_id", "canonical_id")} | {
            "status": "error", "error": f"{type(exc).__name__}: {exc}"}


def top_up(source: Path, original: Path, destination: Path, count: int,
           seed: int, workers: int, remote: str, *,
           aliases: dict[str, list[str]] | None = None,
           retain_original: bool = True) -> int:
    """Top up complete inputs, or explicitly sample only disjoint new instances."""
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
                if retain_original and original_rows.get(row["instance_id"], {}).get("status") == "complete"]
        write_jsonl(selection, rows)
    # With a sample-only source, statuses in the original selection are just
    # placeholders. The retained, manifest-backed rows are the real baseline.
    original_complete = sum(row["instance_id"] in original_rows for row in rows)
    write_json(destination / "sample.json", {
        "seed": seed, "count": count, "source": str(source), "original_sample": str(original),
        "original_complete": original_complete, "retain_original": retain_original,
        "excluded_original_instances": len(original_rows),
        "strategy": "retain-complete-originals" if retain_original else "disjoint-new-instances-only",
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
        repaired = list(pool.map(lambda row: safe_prepare(row, destination / "tasks", remote, aliases), partials))
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
            records = list(pool.map(lambda row: safe_prepare(row, destination / "tasks", remote, aliases), candidates))
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
        "original_complete": original_complete, "retain_original": retain_original,
        "excluded_original_instances": len(original_rows),
        "rounds": round_number,
        "strategy": "retain-complete-originals" if retain_original else "disjoint-new-instances-only",
        "completed_at": timestamp()})
    print(json.dumps({"complete": len(rows), "rounds": round_number}))
    return 0


def remote_object_sizes(remote: str) -> dict[str, int]:
    """Record every remote file size before trusting a bulk-copy exit code."""
    listing = subprocess.run(["rclone", "lsf", remote, "--recursive", "--files-only",
                              "--format", "ps", "--separator", "\t"],
                             capture_output=True, text=True, check=True, timeout=180)
    result = {}
    for line in listing.stdout.splitlines():
        name, size = line.rsplit("\t", 1)
        if name and not any(part == ".git" for part in Path(name).parts):
            result[name] = int(size)
    return result


def direct_object_copy(remote: str, destination: Path, expected_size: int | None = None) -> None:
    """Use a small S3 GET when this rclone build stops after HEAD.

    Credentials are read by rclone and never placed on argv. Object names are
    quoted from the already validated rclone key, and the exact Content-Length
    is checked before an atomic local rename.
    """
    name, key = remote.split(":", 1)
    if not name or not key or key.startswith("/"):
        raise ValueError("direct object fallback requires an S3 remote and object key")
    config = json.loads(subprocess.run(["rclone", "config", "dump"],
                                       check=True, capture_output=True, text=True,
                                       timeout=30).stdout)[name]
    if config.get("type") != "s3" or not config.get("endpoint"):
        raise RuntimeError("direct object fallback is only implemented for configured S3 remotes")
    if expected_size is None:
        metadata = json.loads(subprocess.run(["rclone", "lsjson", remote, "--stat"],
                                             check=True, capture_output=True, text=True,
                                             timeout=120).stdout)
        if metadata.get("IsDir") is not False:
            raise ValueError("direct object fallback requires a regular remote object")
        expected_size = int(metadata["Size"])
    date = email.utils.formatdate(usegmt=True)
    signature = base64.b64encode(hmac.new(
        config["secret_access_key"].encode(),
        f"GET\n\n\n{date}\n/{key}".encode(), hashlib.sha1).digest()).decode()
    url = config["endpoint"].rstrip("/") + "/" + urllib.parse.quote(key, safe="/")
    request = urllib.request.Request(url, headers={
        "Date": date, "Authorization": "AWS " + config["access_key_id"] + ":" + signature})
    destination.parent.mkdir(parents=True, exist_ok=True)
    temporary = destination.with_name(destination.name + ".download")
    try:
        with urllib.request.urlopen(request, timeout=120) as response, temporary.open("wb") as output:
            length = response.headers.get("Content-Length")
            if length is not None and int(length) != expected_size:
                raise RuntimeError(f"S3 Content-Length mismatch for {remote}: {length} != {expected_size}")
            written = 0
            while chunk := response.read(1024 * 1024):
                output.write(chunk)
                written += len(chunk)
            if written != expected_size:
                raise RuntimeError(f"S3 object size mismatch for {remote}: {written} != {expected_size}")
        os.replace(temporary, destination)
    except (OSError, urllib.error.URLError) as exc:
        raise RuntimeError(f"S3 direct object copy failed for {remote}: {exc}") from exc
    finally:
        temporary.unlink(missing_ok=True)


def copy(remote: str, destination: Path, *, directory: bool = False) -> None:
    destination.parent.mkdir(parents=True, exist_ok=True)
    if directory:
        command = ["rclone", "copy", remote, str(destination)]
    else:
        if "/" not in remote:
            raise ValueError("a single remote object must include its parent")
        # This rclone/S3 combination can return success from copyto without
        # creating the local file. Copy the exact object by its basename and
        # verify the resulting file instead of trusting that exit status.
        parent, name = remote.rsplit("/", 1)
        if not name or any(part in {".", ".."} for part in Path(name).parts):
            raise ValueError("unsafe remote object name")
        probe = subprocess.run(["rclone", "lsf", remote, "--max-depth", "1"],
                               capture_output=True, text=True, timeout=120)
        if probe.returncode != 0 or name not in probe.stdout.splitlines():
            raise RuntimeError(f"remote object is unavailable: {remote}; "
                               f"{(probe.stderr or probe.stdout).strip()[-800:]}")
        command = ["rclone", "copy", parent, str(destination.parent), "--include", name]
    command += ["--contimeout", "20s", "--timeout", "120s", "--retries", "2"]
    if directory:
        # S3 rejects some valid repository filenames (e.g. a trailing dot) during
        # rclone's server-side directory recursion. List first, then exact copyto.
        sizes = remote_object_sizes(remote)
        names = list(sizes)
        special = [name for name in names if any(part.endswith(".") for part in Path(name).parts)]
        special_names = set(special)
        names = [name for name in names if name not in special_names]
        # Recursive copy rejects these valid object names. Exact copyto does
        # not enumerate their parent, so preserve the revision byte-for-byte.
        for name in special:
            direct_object_copy(f"{remote}/{name}", destination / name, sizes[name])
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
        mismatches = []
        for name, size in sizes.items():
            local = destination / name
            if not local.is_file() or local.is_symlink() or local.stat().st_size != size:
                mismatches.append(name)
        if mismatches:
            raise RuntimeError(f"rclone omitted or truncated {len(mismatches)} objects: {mismatches[:8]}")
        return
    direct_object_copy(remote, destination)


def prepare_one(row: dict[str, Any], destination: Path, remote: str,
                aliases: dict[str, list[str]] | None = None) -> dict[str, Any]:
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
            provenance = [meta.get("source_path"), meta.get("source"), row.get("source_hint"),
                          "osv", "cvelist"]
            repaired = False
            for directory in dict.fromkeys(x for x in provenance if x):
                if directory in {"osv", "cvelist"}:
                    directory = f"{directory}_{s3_canonical_id(row['canonical_id'])}"
                try:
                    base = f"{remote}/{directory}/candidates/{selected['candidate_id']}"
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
    destination.mkdir(parents=True, exist_ok=True)
    staging = Path(tempfile.mkdtemp(prefix=".staging-", dir=destination))
    errors: list[str] = []
    try:
        selected = None
        source = None
        source_base = None
        metadata_errors: list[str] = []
        # The catalog records provenance order. Probe exact objects first,
        # then ecosystem-specific OSV aliases (for example UBUNTU-CVE-*).
        probes = []
        for name in ["osv", row.get("source_hint"), "cvelist"]:
            if name in {"osv", "cvelist"}:
                probes.append(f"{remote}/{name}_{s3_canonical_id(row['canonical_id'])}")
        probes.extend(f"{remote}/{name}"
                      for name in (aliases or {}).get(row["canonical_id"].upper(), []))
        for base in dict.fromkeys(probes):
            try:
                copy(base + "/meta.json", staging / "meta.json")
                meta_path = staging / "meta.json"
                if meta_path.stat().st_size == 0:
                    raise ValueError("S3 metadata object is empty or absent")
                meta = json.loads(meta_path.read_text(encoding="utf-8"))
                selected = select_candidate(meta, row)
                if selected:
                    source = base.rsplit("/", 1)[-1].split("_", 1)[0]
                    source_base = base
                    break
            except (subprocess.CalledProcessError, subprocess.SubprocessError, OSError, ValueError,
                    RuntimeError,
                    json.JSONDecodeError, KeyError, TypeError) as exc:
                metadata_errors.append(f"{base.rsplit('/', 1)[-1]}: {type(exc).__name__}: {exc}")
                continue
        if selected is None or source is None or source_base is None:
            raise ValueError("no usable source snapshot for the selected instance; " +
                             " | ".join(metadata_errors))
        candidate_id = selected["candidate_id"]
        base = f"{source_base}/candidates/{candidate_id}"
        prefix = staging / "prefix"
        copy(base + "/prefix", prefix, directory=True)
        if not any(path.is_file() for path in prefix.rglob("*")):
            raise ValueError("empty prefix source")
        try:
            copy(base + "/fix.diff", staging / "fix.diff")
        except (subprocess.CalledProcessError, subprocess.TimeoutExpired, RuntimeError) as exc:
            # A missing object and a corrupt/truncated read are different
            # availability evidence. Never collapse both into a fake absence.
            if "remote object is unavailable:" in str(exc) or "not found" in str(exc).lower():
                errors.append("fix.diff is missing")
            else:
                raise RuntimeError(f"fix.diff download failed for {base}: {exc}") from exc
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
            "source": source, "source_path": source_base.rsplit("/", 1)[-1],
            "vulnerability": row["vulnerability"],
            "candidate": selected, "old_tags": row["old_tags"],
        }
        input_dir = staging / "input"
        input_dir.mkdir()
        os.replace(prefix, input_dir / "src")
        (input_dir / "meta.json").write_text(json.dumps(public, ensure_ascii=False, indent=2) + "\n",
                                             encoding="utf-8")
        if (staging / "fix.diff").is_file():
            os.replace(staging / "fix.diff", input_dir / "fix.diff")
        patch = input_dir / "fix.diff"
        if not patch.is_file():
            errors.append("fix.diff is missing")
        elif not re.search(rb"^diff --git a/.+ b/.+$", patch.read_bytes(), re.MULTILINE):
            raise ValueError("downloaded fix.diff is not a Git diff with source paths")
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
    size = parser.add_mutually_exclusive_group()
    size.add_argument("--count", type=int, default=None,
                      help="random sample size (default 100 when --all is absent)")
    size.add_argument("--all", action="store_true",
                      help="prepare the complete frozen candidate pool in pool order")
    parser.add_argument("--seed", type=int, default=20261103)
    parser.add_argument("--workers", type=int, default=4)
    parser.add_argument("--sample-only", action="store_true")
    parser.add_argument("--remote", default=DEFAULT_REMOTE)
    parser.add_argument("--only", nargs="+")
    parser.add_argument("--exclude-original", action="store_true",
                        help="top up entirely from new instances; exclude every original task")
    parser.add_argument("--top-up-from", type=Path,
                        help="preserve complete inputs from this sample and top up to --count")
    args = parser.parse_args()
    # The approved pool is a frozen provenance boundary, not a filename
    # hint. Historical regex subsets must fail before any S3 call.
    if sha256(args.input) != APPROVED_POOL_SHA256:
        parser.error(f"input is not the approved {APPROVED_POOL_SIZE:,} kept-candidate pool")
    pool_rows = list(read_jsonl(args.input))
    if len(pool_rows) != APPROVED_POOL_SIZE or len({row["instance_id"] for row in pool_rows}) != APPROVED_POOL_SIZE \
            or any((row.get("metadata_label") or {}).get("label") != "keep" for row in pool_rows):
        parser.error(f"candidate pool must contain exactly {APPROVED_POOL_SIZE:,} unique keep labels")
    aliases = {} if args.sample_only else s3_alias_index(args.remote)
    if args.top_up_from:
        if args.all:
            parser.error("--top-up-from cannot be combined with --all")
        if args.only or args.sample_only:
            parser.error("--top-up-from cannot be combined with --only or --sample-only")
        if not 1 <= args.workers <= 30:
            parser.error("workers must be 1..30")
        return top_up(args.input, args.top_up_from, args.output,
                      args.count if args.count is not None else 100,
                      args.seed, args.workers, args.remote, aliases=aliases,
                      retain_original=not args.exclude_original)
    args.output.mkdir(parents=True, exist_ok=True)
    selection = args.output / "selection.jsonl"
    count = args.count if args.count is not None else 100
    if args.all:
        policy = "all(frozen_pool_order)"
        expected = APPROVED_POOL_SIZE
    else:
        policy = "random.Random(seed).sample(frozen_pool_order, count)"
        expected = count
    if selection.exists():
        rows = list(read_jsonl(selection))
        if len(rows) != expected:
            raise ValueError(
                f"existing selection has {len(rows)} rows, expected {expected}; "
                "choose another output directory or use the matching --all/--count mode")
        if args.all:
            existing = [row["instance_id"] for row in rows]
            frozen = [row["instance_id"] for row in pool_rows]
            if existing != frozen:
                raise ValueError("existing full selection differs from the frozen pool order; use a new output directory")
    elif args.only:
        raise ValueError("cannot repair a partial selection before the fixed sample is created")
    else:
        rows = sample_all(args.input) if args.all else sample(args.input, count, args.seed)
        write_jsonl(selection, rows)
        write_json(args.output / "sample.json", {"seed": args.seed, "count": len(rows),
                                                 "input": str(args.input), "input_sha256": APPROVED_POOL_SHA256,
                                                 "input_count": APPROVED_POOL_SIZE,
                                                 "label_policy": "metadata_label.label == keep; no additional filters",
                                                 "sampling_policy": policy,
                                                 "created_at": timestamp()})
    if args.only:
        wanted = set(args.only)
        rows = [row for row in rows if row["task_id"] in wanted or row["canonical_id"] in wanted]
    if args.sample_only:
        print(json.dumps({"sampled": len(rows), "selection": str(selection)}))
        return 0
    if not 1 <= args.workers <= 30:
        parser.error("workers must be 1..30")
    (args.output / "tasks").mkdir(exist_ok=True)
    def prepare_record(row: dict[str, Any]) -> dict[str, Any]:
        try:
            return prepare_one(row, args.output / "tasks", args.remote, aliases=aliases)
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
