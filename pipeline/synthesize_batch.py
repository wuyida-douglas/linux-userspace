#!/usr/bin/env python3
"""Run one prepared sample through the supervisor in bounded, resumable waves.

Two selection modes:

``--all``
    Every task in the sample's ``selection.jsonl``. This is the 2,000-task
    batch mode.
``--tasks-file FILE``
    Only the task ids listed in FILE. The file may be plain text (one id per
    line) or JSONL/JSON with ``task_id`` or ``instance_id`` fields.

The supervisor accepts the whole selected batch in one continuous invocation;
this coordinator still supports bounded waves for recovery. Re-running the same command resumes: the
supervisor skips terminal results and restarts interrupted routes/synthesis
from their preserved state. ``--retry-failed`` archives failed/error attempts
(evidence stays under ``results/.attempts/``), removes them from the
supervisor state, and runs them again for up to ``--retry-rounds`` rounds.
"""
from __future__ import annotations

import argparse
import fcntl
import hashlib
import json
import os
import re
import subprocess
import sys
import time
from contextlib import contextmanager
from pathlib import Path
from typing import Any, Iterable

from .common import ROOT, read_jsonl, timestamp, write_json

MAX_CONCURRENCY = 80
MAX_BATCH = 100000
RETRY_STATUSES = {"failed", "error", "timeout"}
ACCEPTABLE_STATUSES = {"passed", "rejected", "skipped"}


def load_json(path: Path, default: Any = None) -> Any:
    try:
        return json.loads(path.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError):
        return {} if default is None else default


def worker_alive(pid: object) -> bool:
    if not pid:
        return False
    try:
        stat = Path(f"/proc/{int(pid)}/stat").read_text(encoding="utf-8")
        return stat.rsplit(")", 1)[1].split()[0] != "Z"
    except (OSError, ValueError, IndexError):
        return False


def selection_rows(sample: Path) -> list[dict[str, Any]]:
    path = sample / "selection.jsonl"
    if not path.is_file():
        raise SystemExit(f"sample has no selection.jsonl: {sample}")
    rows = list(read_jsonl(path))
    ids = [row.get("task_id") for row in rows]
    if any(not isinstance(value, str) or not value for value in ids):
        raise SystemExit(f"{path}: every row needs a non-empty task_id")
    if len(set(ids)) != len(ids):
        raise SystemExit(f"{path}: duplicate task_id values")
    return rows


def display_names(results: Path) -> dict[str, set[str]]:
    data = load_json(results / "display-names.json", {})
    mapping = data.get("mapping") if isinstance(data, dict) else None
    if not isinstance(mapping, dict):
        return {}
    result: dict[str, set[str]] = {}
    for task, value in mapping.items():
        if isinstance(value, str) and value:
            result.setdefault(value, set()).add(task)
    return result


def task_file_tokens(path: Path) -> list[str]:
    if not path.is_file():
        raise SystemExit(f"task list file missing: {path}")
    text = path.read_text(encoding="utf-8")
    stripped = text.strip()
    lines = [line for line in text.splitlines() if line.strip()]
    tokens: list[str] = []
    if path.suffix == ".jsonl" or (lines and lines[0].lstrip().startswith("{")):
        for number, line in enumerate(text.splitlines(), 1):
            if not line.strip():
                continue
            try:
                value = json.loads(line)
            except json.JSONDecodeError as exc:
                raise SystemExit(f"{path}:{number}: invalid JSON: {exc}") from exc
            tokens.append(token_from_value(value, path, number))
    elif stripped.startswith("["):
        try:
            value = json.loads(stripped)
        except json.JSONDecodeError as exc:
            raise SystemExit(f"{path}: invalid JSON: {exc}") from exc
        if not isinstance(value, list):
            raise SystemExit(f"{path}: expected a JSON array")
        for index, item in enumerate(value, 1):
            tokens.append(token_from_value(item, path, index))
    else:
        for line in text.splitlines():
            line = line.split("#", 1)[0].strip()
            if not line:
                continue
            tokens.extend(token for token in re.split(r"[,\s]+", line) if token)
    return tokens


def token_from_value(value: Any, path: Path, number: int) -> str:
    if isinstance(value, dict):
        token = value.get("task_id") or value.get("instance_id")
        if not isinstance(token, str) or not token:
            raise SystemExit(f"{path}:{number}: object needs task_id or instance_id")
        return token
    if isinstance(value, str) and value.strip():
        return value.strip()
    raise SystemExit(f"{path}:{number}: expected a task id string")


def _index(pairs: Iterable[tuple[Any, str]]) -> dict[str, set[str]]:
    result: dict[str, set[str]] = {}
    for key, task in pairs:
        if isinstance(key, str) and key:
            result.setdefault(key, set()).add(task)
    return result


def _lower_index(index: dict[str, set[str]]) -> dict[str, set[str]]:
    result: dict[str, set[str]] = {}
    for key, tasks in index.items():
        result.setdefault(key.lower(), set()).update(tasks)
    return result


def resolve_targets(tokens: list[str], rows: list[dict[str, Any]],
                    results: Path) -> list[str]:
    known = {row["task_id"] for row in rows}
    display = {name: tasks & known for name, tasks in display_names(results).items()}
    indexes = [
        _index((row["task_id"], row["task_id"]) for row in rows),
        _index((row.get("instance_id"), row["task_id"]) for row in rows),
        _index((row.get("canonical_id"), row["task_id"]) for row in rows),
        {name: tasks for name, tasks in display.items() if tasks},
    ]
    lower_indexes = [_lower_index(index) for index in indexes]

    chosen: set[str] = set()
    unknown: list[str] = []
    ambiguous: list[str] = []
    for token in tokens:
        matches: set[str] = set()
        for exact, lower in zip(indexes, lower_indexes):
            if token in exact:
                matches = exact[token]
                break
            if token.lower() in lower:
                matches = lower[token.lower()]
                break
        if not matches:
            unknown.append(token)
        elif len(matches) > 1:
            ambiguous.append(token)
        else:
            chosen.update(matches)
    if unknown:
        raise SystemExit(f"task list contains unknown ids: {', '.join(sorted(set(unknown))[:20])}")
    if ambiguous:
        raise SystemExit(f"task list contains ambiguous ids: {', '.join(sorted(set(ambiguous))[:20])}")
    return [row["task_id"] for row in rows if row["task_id"] in chosen]


def resolve_paths(args: argparse.Namespace) -> None:
    args.sample = args.sample.resolve()
    args.results = args.results.resolve()
    args.env_file = args.env_file.resolve()
    if args.tasks_file is not None:
        args.tasks_file = args.tasks_file.resolve()
    if args.published_root is not None:
        args.published_root = args.published_root.resolve()
    if not args.sample.is_dir():
        raise SystemExit(f"sample directory missing: {args.sample}")
    if not args.env_file.is_file():
        raise SystemExit(f"model env file missing: {args.env_file}")
    if args.wave_size < 0 or args.wave_size > MAX_BATCH:
        raise SystemExit(f"--wave-size must be 0..{MAX_BATCH} "
                         "(0 = one continuous supervisor batch)")
    if args.concurrency < 1 or args.concurrency > MAX_CONCURRENCY:
        raise SystemExit(f"--concurrency must be 1..{MAX_CONCURRENCY}")
    if args.retry_failed:
        raise SystemExit("--retry-failed is disabled: failed/error are terminal; "
                         "re-run a specific task manually if you really need it")
    if args.retry_rounds < 0:
        raise SystemExit("--retry-rounds must be >= 0")


def waves(tasks: list[str], size: int) -> Iterable[list[str]]:
    for index in range(0, len(tasks), size):
        yield tasks[index:index + size]


def batch_count(tasks: list[str], wave_size: int) -> int:
    if not tasks:
        return 0
    if wave_size <= 0 or wave_size >= len(tasks):
        return 1
    return (len(tasks) + wave_size - 1) // wave_size


def task_status(results: Path, task: str) -> str:
    record = load_json(results / task / "result.json", {})
    return str(record.get("status") or "missing") if isinstance(record, dict) else "missing"


def status_counts(results: Path, tasks: list[str]) -> dict[str, int]:
    counts: dict[str, int] = {}
    for task in tasks:
        status = task_status(results, task)
        counts[status] = counts.get(status, 0) + 1
    return counts


def failures(results: Path, tasks: list[str]) -> list[dict[str, Any]]:
    result = []
    for task in tasks:
        record = load_json(results / task / "result.json", {})
        record = record if isinstance(record, dict) else {}
        status = str(record.get("status") or "missing")
        if status in ACCEPTABLE_STATUSES:
            continue
        result.append({"task_id": task, "status": status,
                       "failure_class": record.get("failure_class"),
                       "error": str(record.get("error", ""))[:500]})
    return result


@contextmanager
def coordinator_lock(results: Path):
    results.mkdir(parents=True, exist_ok=True)
    with (results / ".synthesize.lock").open("a+") as handle:
        try:
            fcntl.flock(handle, fcntl.LOCK_EX | fcntl.LOCK_NB)
        except BlockingIOError as exc:
            raise SystemExit(f"another synthesize coordinator already owns {results}") from exc
        try:
            yield
        finally:
            fcntl.flock(handle, fcntl.LOCK_UN)


def wait_for_supervisor_lock(results: Path, poll: float = 10.0) -> None:
    """Let an older supervisor finish before starting another wave."""
    results.mkdir(parents=True, exist_ok=True)
    announced = False
    while True:
        with (results / ".supervisor.lock").open("a+") as handle:
            try:
                fcntl.flock(handle, fcntl.LOCK_EX | fcntl.LOCK_NB)
            except BlockingIOError:
                if not announced:
                    print(f"another supervisor owns {results}; waiting for it to finish", flush=True)
                    announced = True
                time.sleep(poll)
                continue
            fcntl.flock(handle, fcntl.LOCK_UN)
            return


def receipt_for(results: Path, wave: list[str], batch_number: int) -> Path:
    payload = {"schema_version": 1, "batch": batch_number, "fresh": wave,
               "carried": [], "observed_only": []}
    digest = hashlib.sha256(json.dumps(payload, sort_keys=True).encode()).hexdigest()[:16]
    path = results / ".synthesize-receipts" / f"wave-{digest}.json"
    if path.is_file():
        current = load_json(path, {})
        if current != payload:
            raise SystemExit(f"batch receipt collision: {path}")
    else:
        write_json(path, payload)
    return path


def _housekeeping_loop(stop, results_root: Path, interval_sec: int = 30 * 60) -> None:
    """Periodic cleanup while the supervisor keeps the queue full.

    Anonymous volumes, old pip/build unpack directories and dead Compose
    networks are reclaimed every cycle. The network sweep matters most: a
    leaked network keeps its subnet reserved, and the IPAM bulk inspect walks
    every network under a host-wide lock on each Compose start (892 networks
    once cost 11s per start, which queued every acceptance behind it).
    Build cache is bounded too, because every task
    builds its own images once and the cache otherwise grows ~130GB/h until the
    disk is full. The cache prune holds the containerd content-store lock for
    minutes, so it runs only when the data disk drops below
    ``PIPELINE_BUILD_CACHE_PRUNE_MIN_FREE_GB`` (default 1500) and only drops
    entries idle longer than ``PIPELINE_BUILD_CACHE_PRUNE_UNTIL`` (default 6h),
    i.e. layers no running task can still need.
    """
    from .resource_cleanup import (data_disk_free_gb, prune_build_cache,
                                   prune_idle_networks, prune_idle_volumes,
                                   prune_stale_images, prune_temp_leftovers,
                                   prune_unused_volumes)
    until = os.environ.get("PIPELINE_BUILD_CACHE_PRUNE_UNTIL", "6h")
    try:
        min_free = float(os.environ.get("PIPELINE_BUILD_CACHE_PRUNE_MIN_FREE_GB", "1500"))
    except ValueError:
        min_free = 1500.0
    # First sweep shortly after start (networks and stale volumes are already
    # there from the previous run), then every 30 minutes: leaked Compose
    # networks and volumes accumulate faster than a three-hour cadence can
    # contain, and every allocation pays for the networks that remain.
    delay = 300
    while not stop.wait(delay):
        delay = interval_sec
        try:
            prune_unused_volumes()
            prune_temp_leftovers(24)
        except Exception:
            pass
        try:
            # Dead Compose networks fragment docker's address pools and make
            # every IPAM allocation walk them under a host-wide lock.
            prune_idle_networks(results_root)
        except Exception:
            pass
        try:
            # Named volumes survive a killed trial; agents also build probe
            # images under tags no task declares, so sweep old unused images.
            prune_idle_volumes(results_root)
            prune_stale_images(float(os.environ.get("PIPELINE_IMAGE_GC_HOURS", "12")))
        except Exception:
            pass
        try:
            if min_free > 0 and data_disk_free_gb() >= min_free:
                continue
            prune_build_cache(until)
        except Exception:
            pass


def run_wave(args: argparse.Namespace, wave: list[str], number: int,
             batch_number: int, published_root: Path | None,
             label: str = "initial") -> int:
    if not wave:
        return 0
    wait_for_supervisor_lock(args.results)
    receipt = receipt_for(args.results, wave, batch_number)
    command = [sys.executable, "-m", "pipeline.supervise",
               "--sample", str(args.sample), "--results", str(args.results),
               "--env-file", str(args.env_file),
               "--only", *wave,
               "--batch-size", str(len(wave)),
               "--concurrency", str(args.concurrency),
               "--max-turns", str(args.max_turns),
               "--timeout", str(args.timeout),
               "--review-turns", str(args.review_turns),
               "--review-timeout", str(args.review_timeout),
               "--verify-timeout", str(args.verify_timeout),
               "--batch-selection", str(receipt),
               "--batch-number", str(batch_number)]
    if published_root is not None:
        command += ["--published-root", str(published_root)]
    log_path = args.results / "logs" / f"synthesize-{label}-batch-{number:04d}.log"
    log_path.parent.mkdir(parents=True, exist_ok=True)
    import threading
    stop = threading.Event()
    housekeeping = threading.Thread(target=_housekeeping_loop, args=(stop, args.results), daemon=True)
    housekeeping.start()
    with log_path.open("a", encoding="utf-8") as log:
        log.write(f"\n[{timestamp()}] wave {number}: {len(wave)} task(s)\n")
        log.flush()
        try:
            completed = subprocess.run(command, cwd=ROOT, stdout=log, stderr=subprocess.STDOUT)
        finally:
            stop.set()
    if completed.returncode != 0:
        raise SystemExit(f"supervisor wave {number} exited {completed.returncode}; see {log_path}")
    return 0


def run_round(args: argparse.Namespace, tasks: list[str], label: str,
              batch_number: int, published_root: Path | None) -> None:
    if not tasks:
        return
    # WAVE_SIZE=0 (default) keeps one supervisor alive for the whole target.
    # The supervisor already fills freed concurrency slots continuously, so
    # there is no wave barrier and no head-of-line blocking.
    if args.wave_size <= 0 or args.wave_size >= len(tasks):
        if not args.force and all(task_status(args.results, task) in ACCEPTABLE_STATUSES
                                  for task in tasks):
            print(f"[{label}] already settled, skipping", flush=True)
            return
        print(f"[{label}] continuous batch: {len(tasks)} task(s)", flush=True)
        run_wave(args, tasks, 1, batch_number, published_root, label=label)
        return
    # Legacy bounded-wave mode, retained for deliberately small supervisor
    # state/restart granularity.
    chunks = list(waves(tasks, args.wave_size))
    for index, wave in enumerate(chunks, 1):
        if not wave:
            continue
        if not args.force and all(task_status(args.results, task) in ACCEPTABLE_STATUSES
                                  for task in wave):
            print(f"[{label}] wave {index}/{len(chunks)}: already settled, skipping", flush=True)
            continue
        print(f"[{label}] wave {index}/{len(chunks)}: {len(wave)} task(s)", flush=True)
        run_wave(args, wave, index, batch_number, published_root, label=label)


def retryable_failures(sample: Path, results: Path, tasks: list[str]) -> list[str]:
    retry = []
    for task in tasks:
        record = load_json(results / task / "result.json", {})
        status = str(record.get("status") or "") if isinstance(record, dict) else ""
        if status not in RETRY_STATUSES:
            continue
        if isinstance(record, dict) and record.get("failure_class") == "input_unavailable":
            continue
        if not (sample / "tasks" / task / "input/manifest.json").is_file():
            continue
        retry.append(task)
    return retry


def archive_failed_tasks(sample: Path, results: Path, tasks: list[str]) -> list[str]:
    """Archive failed attempts and clear their supervisor state for a fresh run."""
    archived: list[str] = []
    results.mkdir(parents=True, exist_ok=True)
    with (results / ".supervisor.lock").open("a+") as lock:
        fcntl.flock(lock, fcntl.LOCK_EX)
        state_path = results / "supervisor-state.json"
        state = load_json(state_path, {"schema_version": 1, "children": {}})
        if not isinstance(state, dict):
            state = {"schema_version": 1, "children": {}}
        children = state.get("children")
        if not isinstance(children, dict):
            children = state["children"] = {}
        stamp = timestamp().replace(":", "-")
        for task in tasks:
            record = load_json(results / task / "result.json", {})
            status = str(record.get("status") or "") if isinstance(record, dict) else ""
            if status not in RETRY_STATUSES:
                continue
            if isinstance(record, dict) and record.get("failure_class") == "input_unavailable":
                continue
            if not (sample / "tasks" / task / "input/manifest.json").is_file():
                continue
            if worker_alive((children.get(task) or {}).get("pid")):
                continue
            source = results / task
            if source.exists():
                target = results / ".attempts" / task / stamp
                suffix = 1
                while target.exists():
                    target = results / ".attempts" / task / f"{stamp}-{suffix}"
                    suffix += 1
                target.parent.mkdir(parents=True, exist_ok=True)
                os.rename(source, target)
            children.pop(task, None)
            for key in ("scheduled", "final_tasks", "observed_only", "batch_members"):
                value = state.get(key)
                if isinstance(value, list):
                    state[key] = [item for item in value if item != task]
            launches = state.get("initial_launches")
            if isinstance(launches, dict):
                launches.pop(task, None)
            archived.append(task)
        state["updated_at"] = timestamp()
        write_json(state_path, state)
        fcntl.flock(lock, fcntl.LOCK_UN)
    return archived


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--sample", type=Path, required=True)
    parser.add_argument("--results", type=Path, required=True)
    parser.add_argument("--env-file", type=Path, default=Path("/nvme/wuyida/env"))
    mode = parser.add_mutually_exclusive_group(required=True)
    mode.add_argument("--all", action="store_true",
                      help="synthesize every task in the sample's selection.jsonl")
    mode.add_argument("--tasks-file", type=Path,
                      help="synthesize only the task ids listed in this file")
    parser.add_argument("--wave-size", type=int, default=0,
                        help=f"0 = one continuous supervisor batch (default); "
                             f"positive N = legacy bounded waves of N (max {MAX_BATCH})")
    parser.add_argument("--concurrency", type=int, default=MAX_CONCURRENCY)
    parser.add_argument("--max-turns", type=int, default=400)
    parser.add_argument("--timeout", type=int, default=18000)
    parser.add_argument("--review-turns", type=int, default=140)
    parser.add_argument("--review-timeout", type=int, default=5400)
    parser.add_argument("--verify-timeout", type=int, default=1800)
    parser.add_argument("--published-root", type=Path)
    parser.add_argument("--expect-batch", type=int,
                        help="fail unless sample.json records this batch number")
    parser.add_argument("--no-prune-cache", action="store_true",
                        help="keep the Docker build cache after the batch (default: prune idle cache)")
    parser.add_argument("--retry-failed", action="store_true",
                        help="disabled: failures are terminal")
    parser.add_argument("--retry-rounds", type=int, default=1,
                        help="bounded retry rounds after the first pass (default: 1)")
    parser.add_argument("--force", action="store_true",
                        help="run waves even when every task is already passed/rejected")
    parser.add_argument("--dry-run", action="store_true",
                        help="print the target waves and current statuses without running")
    args = parser.parse_args()
    resolve_paths(args)
    rows = selection_rows(args.sample)
    info = load_json(args.sample / "sample.json", {})
    batch_number = info.get("batch") if isinstance(info, dict) else None
    if not isinstance(batch_number, int) or batch_number < 1:
        batch_number = 1
    if args.expect_batch is not None and batch_number != args.expect_batch:
        raise SystemExit(f"{args.sample}/sample.json records batch {batch_number}, "
                         f"expected {args.expect_batch}")
    if args.tasks_file is not None:
        target = resolve_targets(task_file_tokens(args.tasks_file), rows, args.results)
        mode_label = f"tasks-file={args.tasks_file}"
    else:
        target = [row["task_id"] for row in rows]
        mode_label = "all"
    if not target:
        raise SystemExit("no tasks selected")
    if args.published_root is None:
        from .run import reported_published_root
        args.published_root = reported_published_root()
    print(f"sample={args.sample} results={args.results} batch={batch_number} "
          f"mode={mode_label} tasks={len(target)} batches={batch_count(target, args.wave_size)} "
          f"env={args.env_file}", flush=True)
    if args.dry_run:
        print(json.dumps({"counts": status_counts(args.results, target),
                          "retryable": retryable_failures(args.sample, args.results, target)},
                         ensure_ascii=False), flush=True)
        if args.wave_size <= 0 or args.wave_size >= len(target):
            print(f"batch 0001 ({len(target)}): {' '.join(target)}", flush=True)
        else:
            for index, wave in enumerate(waves(target, args.wave_size), 1):
                print(f"wave {index:04d} ({len(wave)}): {' '.join(wave)}", flush=True)
        return 0

    with coordinator_lock(args.results):
        run_round(args, target, "initial", batch_number, args.published_root)
        rounds = 0
        if args.retry_failed:
            for round_index in range(1, args.retry_rounds + 1):
                failed = retryable_failures(args.sample, args.results, target)
                if not failed:
                    break
                failed_set = set(failed)
                ordered = [task for task in target if task in failed_set]
                archived = archive_failed_tasks(args.sample, args.results, ordered)
                if not archived:
                    print("no failed task can be retried (missing input or live worker)", flush=True)
                    break
                print(f"retry round {round_index}: {len(archived)} task(s)", flush=True)
                run_round(args, archived, f"retry-{round_index}", batch_number,
                          args.published_root)
                rounds = round_index
        counts = status_counts(args.results, target)
        failures_list = failures(args.results, target)
        summary = {
            "schema_version": 1,
            "sample": str(args.sample),
            "results": str(args.results),
            "batch": batch_number,
            "mode": mode_label,
            "target": len(target),
            "batches": batch_count(target, args.wave_size),
            "wave_size": args.wave_size,
            "concurrency": args.concurrency,
            "retry_failed": args.retry_failed,
            "retry_rounds": rounds,
            "counts": counts,
            "failures": failures_list,
            "finished_at": timestamp(),
        }
        write_json(args.results / "synthesis-summary.json", summary)
        print(json.dumps({"counts": counts, "failures": len(failures_list),
                          "summary": str(args.results / "synthesis-summary.json")},
                         ensure_ascii=False), flush=True)
        for item in failures_list[:20]:
            print(f"  {item['task_id']}: {item['status']} {item['failure_class'] or ''} "
                  f"{item['error']}", flush=True)
        if len(failures_list) > 20:
            print(f"  ... {len(failures_list) - 20} more in synthesis-summary.json", flush=True)
        # Build cache only helps rebuilds inside a task. Once the batch has no
        # live worker the cache is dead weight, and this is the only window
        # where pruning cannot collide with an acceptance on the daemon.
        if not args.no_prune_cache:
            from .resource_cleanup import (prune_build_cache, prune_temp_leftovers,
                                           prune_unused_volumes)
            pruned = prune_build_cache("1h")
            volumes = prune_unused_volumes()
            temp = prune_temp_leftovers(24)
            summary["build_cache_prune"] = pruned
            summary["volume_prune"] = volumes
            summary["temp_prune"] = temp
            write_json(args.results / "synthesis-summary.json", summary)
            print(f"build cache pruned: {pruned.get('returncode', pruned)}", flush=True)
            print(f"volumes pruned: {volumes.get('returncode', volumes)}", flush=True)
            print(f"temp leftovers removed: {len(temp.get('removed', []))}", flush=True)
        return 0 if all(status in ACCEPTABLE_STATUSES for status in counts) else 1


if __name__ == "__main__":
    try:
        raise SystemExit(main())
    except KeyboardInterrupt:
        print("\ninterrupted; rerun the same command to resume", file=sys.stderr)
        raise SystemExit(130)