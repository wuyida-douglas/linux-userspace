#!/usr/bin/env python3
"""Bounded, resumable scheduling and monitoring for routed synthesis batches.

Routing and synthesis each occupy a worker. Existing processes are never
killed, renumbered, or silently rerun. Harbor exports remain serialized by
run.py's Docker lock so acceptance does not contend with factory builds.
"""
from __future__ import annotations

import argparse
import json
import os
import shlex
import shutil
import subprocess
import sys
import threading
import time
from pathlib import Path

from .common import display_task_id, read_jsonl, timestamp, write_json
from .run import route as validate_route, reported_published_root


def gold_writable_path_evidence(root: Path, task: str, record: dict) -> str | None:
    """Identify only a proven reference-submission path/protocol defect."""
    def inspect(harbor_root: Path, harbor: dict) -> str | None:
        report = (harbor.get("differential_from_final_bundle") or {}).get("report") or {}
        if ((harbor.get("gold") or {}).get("reward") != 0.0
                or report.get("status") not in {"this_bug", "infra_error"}
                or (report.get("vulnerable") or {}).get("oracle", {}).get("returncode") != 1
                or (report.get("fixed") or {}).get("oracle", {}).get("returncode") != 0):
            return None
        paths = sorted(harbor_root.glob("jobs/*gold/*/verifier/evidence.json"))
        evidence = load(paths[-1] if paths else Path("/nonexistent"), {})
        output = (((evidence.get("vulnerable") or {}).get("submission_result") or {})
                  .get("output", ""))
        fixed_output = (((report.get("fixed") or {}).get("submission_result") or {})
                        .get("output", ""))
        if "Read-only file system" in output and "Read-only file system" in fixed_output:
            return "writable_gold_log_path"
        if "Permission denied" in output:
            return "writable_gold_submission_directory"
        return None
    defect = inspect(root / task / "harbor", record.get("harbor") or {})
    if defect is not None:
        return defect
    # A transient later error must not erase a concrete archived delivery defect.
    archives = sorted((root / task / "infrastructure-attempts").glob("*/result.json"),
                      key=lambda path: path.stat().st_mtime_ns)
    for path in reversed(archives):
        defect = inspect(path.parent, load(path, {}).get("harbor") or {})
        if defect is not None:
            return defect
    return None


def atomic_json(path: Path, value: dict) -> None:
    temporary = path.with_name(path.name + f".{os.getpid()}.{threading.get_ident()}.tmp")
    write_json(temporary, value)
    os.replace(temporary, path)


def load(path: Path, default):
    try:
        return json.loads(path.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError):
        return default


def worker_alive(pid: object) -> bool:
    """A zombie is exited work, not a live task holding a concurrency slot."""
    if not pid:
        return False
    try:
        stat = Path(f"/proc/{int(pid)}/stat").read_text(encoding="utf-8")
        return stat.rsplit(")", 1)[1].split()[0] != "Z"
    except (OSError, ValueError, IndexError):
        return False


def strictly_accepted(record: dict) -> bool:
    harbor = record.get("harbor") or {}
    review_ok = (record.get("review") or {}).get("passed") is True
    runs = harbor.get("acceptance_runs")
    if runs is not None:
        return (record.get("status") == "passed" and review_ok
                and harbor.get("status") == "passed"
                and isinstance(runs, list) and len(runs) == 2
                and all(isinstance(run, dict) and run.get("reward") == 1.0 for run in runs))
    # Historical records used one Harbor gold, one null and a factory
    # differential. Keep reading them for resume/audit; new acceptance never
    # writes these fields.
    differential = harbor.get("differential_from_final_bundle") or {}
    report = differential.get("report") or {}
    vulnerable = report.get("vulnerable") or {}
    fixed = report.get("fixed") or {}
    protocol_ok = (
        vulnerable.get("triggered") is True
        and (vulnerable.get("health") or {}).get("returncode") == 0
        and fixed.get("triggered") is False
        and (fixed.get("solution") or {}).get("returncode") == 0
        and (fixed.get("patched_health") or {}).get("returncode") == 0)
    return (record.get("status") == "passed" and review_ok
            and (harbor.get("gold") or {}).get("reward") == 1.0
            and (harbor.get("null") or {}).get("reward") == 0.0
            and differential.get("status") == "passed"
            and report.get("success") is True and protocol_ok)


def latest_turn(path: Path) -> int:
    result = 0
    candidates = [path, *sorted(path.parent.glob(path.stem + "-[0-9][0-9].jsonl"))]
    for trajectory in candidates:
        try:
            with trajectory.open(encoding="utf-8") as handle:
                for line in handle:
                    try:
                        result = max(result, int(json.loads(line).get("turn", 0)))
                    except json.JSONDecodeError:
                        pass
        except OSError:
            pass
    return result


TERMINAL_RESULT_STATUSES = {"passed", "failed", "rejected", "error", "timeout"}


def write_display_index(results: Path) -> dict[str, str]:
    """Write canonical display names without renaming result directories.

    Result directories stay keyed by the internal selection id so a worker or
    supervisor can always find them. This index is the human/export-facing
    name map (canonical advisory id + route branch), and it never invalidates
    paths stored in result.json or acceptance.json.
    """
    statuses = [load(path, {}).get("status") for path in results.glob("*/result.json")]
    if not statuses or any(status not in TERMINAL_RESULT_STATUSES for status in statuses):
        return {}
    mapping: dict[str, str] = {}
    for result_path in sorted(results.glob("*/result.json")):
        result = load(result_path, {})
        route = load(result_path.parent / "workspace/route.json", {})
        branch = route.get("branch")
        if not branch:
            continue
        instance = route.get("instance_id") or result.get("instance_id") or result_path.parent.name
        mapping[result_path.parent.name] = display_task_id(
            instance, branch, route.get("host_type"))
    if mapping:
        write_json(results / "display-names.json", {
            "schema_version": 1, "mapping": mapping})
        print(f"wrote display names for {len(mapping)} result directories", flush=True)
    return mapping


def pipeline_worker_command(pid: int, proc_root: Path = Path("/proc")) -> list[str] | None:
    """Read the real module entrypoint; ps truncates .venv executable names.

    The argv prefix matters: a supervisor's --only list can contain text that
    looks like another command, but it is not a pipeline.run worker.
    """
    try:
        raw = (proc_root / str(pid) / "cmdline").read_bytes().split(b"\0")
        command = [part.decode(errors="surrogateescape") for part in raw if part]
        if command[1:3] != ["-m", "pipeline.run"]:
            return None
        parent = (proc_root / str(pid) / "stat").read_text().rsplit(")", 1)[1].split()[1]
        if int(parent) > 1:
            raw_parent = (proc_root / parent / "cmdline").read_bytes().split(b"\0")
            parent_command = [part.decode(errors="surrogateescape") for part in raw_parent if part]
            if parent_command[1:3] == ["-m", "pipeline.run"]:
                return None
        return command
    except (OSError, ValueError, IndexError):
        return None


def worker_start_error(task: Path) -> str | None:
    """Return an import-time failure after the latest launch, not a task verdict.

    A fresh interpreter can fail before run_one writes its result. In that case
    the old terminal result is still authoritative and must not consume a
    delivery repair that never started. Ordinary exceptions handled by run_one
    are deliberately excluded: they are recorded in the fresh result instead.
    """
    try:
        lines = (task / "supervisor.log").read_text(encoding="utf-8", errors="replace").splitlines()
    except OSError:
        return None
    launches = [index for index, line in enumerate(lines)
                if line.startswith("[") and " launch: " in line]
    if not launches:
        return None
    output = lines[launches[-1] + 1:]
    if not any(line.startswith("Traceback (most recent call last):") for line in output):
        return None
    for line in reversed(output):
        if line.startswith(("ModuleNotFoundError:", "ImportError:", "SyntaxError:")):
            return line
    return None


def prioritize_candidates(candidates: list[str], children: dict,
                          selected: list[dict]) -> None:
    """Preserve sample order within Harbor resumes and new work."""
    order = {row["task_id"]: index for index, row in enumerate(selected)}
    candidates.sort(key=lambda task: (
        0 if children.get(task, {}).get("repair_priority") else 1,
        order[task]))


def carry_workspaces(sources: list[Path], results: Path, selected_ids: set[str] | None,
                     recovery_plans: dict[str, dict] | None = None) -> set[str]:
    """Carry frozen evidence into a new sample; never mutate the old attempt.

    The carry manifest is its allowlist: --only may narrow it, never add an
    arbitrary old failure as a retry vote. The actual recovery reason and
    original result remain available for the batch-level attribution pass.
    """
    carried = set()
    for source in sources:
        task = source.resolve().name
        if selected_ids is not None and task not in selected_ids:
            raise ValueError(f"carried task is not in --only: {task}")
        plan = (recovery_plans or {}).get(task, {})
        mode = plan.get("mode", "review")
        if recovery_plans is not None:
            if plan.get("schema_version") != 1 or plan.get("task_id") != task \
                    or mode not in {"route", "route_handoff", "synthesis", "review", "harbor"}:
                raise ValueError(f"unsupported carried recovery mode for {task}: {mode}")
        if not (source / "result.json").is_file():
            raise ValueError(f"carried task lacks a frozen result: {source}")
        if mode in {"review", "harbor"}:
            if not (source / "workspace/route.json").is_file():
                raise ValueError(f"carried task lacks a frozen route: {source}")
            if not (source / "synthesis/result.json").is_file() \
                    or not (source / "workspace/delivery").is_dir():
                raise ValueError(f"carried task lacks a completed delivery: {source}")
        elif mode == "synthesis":
            if not (source / "workspace/route.json").is_file() \
                    or not (source / "workspace/input").is_dir():
                raise ValueError(f"carried synthesis lacks a frozen route or input: {source}")
        elif mode == "route_handoff":
            if not (source / "route/trajectory.jsonl").is_file() \
                    or not (source / "workspace/input").is_dir():
                raise ValueError(f"carried route handoff lacks a trajectory or input: {source}")
        elif mode == "route":
            if not (source / "workspace/input").is_dir() \
                    or not ((source / "workspace/route.json").is_file()
                            or (source / "route/trajectory.jsonl").is_file()):
                raise ValueError(f"carried route lacks input and route evidence: {source}")
        destination = results / task
        staged_plan = load(destination / "carry-recovery.json", {}) if destination.is_dir() else {}
        if destination.exists() and (recovery_plans is None or staged_plan != plan):
            raise ValueError(f"refusing to overwrite an existing task during carry: {task}")
        # Copy rather than symlink: reviewer cleanup, archived Harbor output,
        # or a delivery repair must never alter the original evidence tree.
        shutil.copytree(
            source, destination, symlinks=True, dirs_exist_ok=bool(staged_plan),
            ignore=shutil.ignore_patterns(
                ".agent-tmp", ".agent-config", ".agent-home",
                "cli-debug.log", "latest", "__pycache__", ".pytest_cache",
                "*.pyc", ".agent-guard.log", "harbor"))
        if recovery_plans is not None:
            atomic_json(destination / "carry-recovery.json", plan)
        source_result = load(source / "result.json", {})
        source_route = load(source / "workspace/route.json", {})
        instance_id = source_result.get("instance_id") or source_route.get("instance_id")
        if not isinstance(instance_id, str) or not instance_id:
            raise ValueError(f"carried task lacks a verifiable instance identity: {source}")
        (results / task / "carry-provenance.json").write_text(json.dumps({
            "schema_version": 1, "source": str(source.resolve()),
            "carried_at": timestamp(), "same_instance_continuation": True,
            "instance_id": instance_id,
        "source_sample": str(load(source / "supervisor-state.json", {}).get("sample", "")),
        }, indent=2) + "\n", encoding="utf-8")
        state_path = results / "supervisor-state.json"
        state = load(state_path, {"schema_version": 1, "children": {}})
        child = state.setdefault("children", {}).setdefault(task, {})
        # PID, owner and consumed retry markers belong to the original result
        # directory, never to its copied workspace. The preserved result and
        # retry-evidence remain the sole record of the previous attempt.
        for key in ("pid", "external_worker", "worker_results", "recovery_requested",
                    "recovery_merged", "recovery_merged_at", "retry_count", "retry_reason",
                    "previous_status", "review_incomplete_retry_count", "delivery_retry_count",
                    "harbor_retry_count", "harbor_exception_retry_count", "review_retry_count",
                    "retry_blocked", "acceptance_resume_requested", "manual_correction",
                    "route_budget_recovery_count", "carry_recovery_dispatched", "bounded_recovery_launched",
                    "review_launched", "delivery_launched", "harbor_launched", "final_status"):
            child.pop(key, None)
        child["carried_recovery"] = True
        # A carried result can predate the identity field. Reconcile its
        # verified route identity before checking the explicit recovery plan.
        if not source_result.get("instance_id"):
            source_result["instance_id"] = instance_id
            atomic_json(results / task / "result.json", source_result)
        atomic_json(state_path, state)
        carried.add(task)
    return carried


def launch(task: str, sample: Path, results: Path,
           turns: int, timeout: int,
           resume_harbor: bool = False,
           published_root: Path | None = None, review_turns: int = 140,
           review_timeout: int = 5400, verify_timeout: int = 1800,
           review_delivery: bool = False,
           continue_synthesis: bool = False,
           workspace_from: Path | None = None,
           route_from: Path | None = None,
           route_handoff: Path | None = None,
           concurrency: int = 30) -> subprocess.Popen:
    """Launch one new task or resume only its frozen route/synthesis/review tail."""
    command = [sys.executable, "-m", "pipeline.run", "--sample", str(sample),
               "--results", str(results), "--only", task, "--concurrency", str(concurrency),
               "--max-turns", str(turns), "--route-turns", "60",
               "--timeout", str(timeout), "--review-turns", str(review_turns),
               "--review-timeout", str(review_timeout), "--verify-timeout", str(verify_timeout)]
    if published_root is not None:
        command += ["--published-root", str(published_root)]
    if review_delivery:
        command.append("--review-delivery")
    elif resume_harbor:
        command.append("--resume")
    elif continue_synthesis:
        command.append("--continue-synthesis")
        if workspace_from is not None:
            command += ["--workspace-from", str(workspace_from)]
    elif route_handoff is not None:
        command += ["--route-handoff-from", str(route_handoff)]
    elif route_from is not None:
        command += ["--route-from", str(route_from)]
    log = results / task / "supervisor.log"
    log.parent.mkdir(parents=True, exist_ok=True)
    with log.open("a", encoding="utf-8") as output:
        output.write(f"\n[{timestamp()}] launch: {shlex.join(command)}\n")
        output.flush()
        return subprocess.Popen(command, cwd=Path(__file__).resolve().parents[1],
                                stdout=output, stderr=subprocess.STDOUT,
                                start_new_session=True)


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--sample", type=Path, required=True)
    parser.add_argument("--results", type=Path, required=True)
    parser.add_argument("--concurrency", type=int, default=20)
    parser.add_argument("--max-turns", type=int, default=400)
    parser.add_argument("--timeout", type=int, default=18000)
    parser.add_argument("--review-turns", type=int, default=140)
    parser.add_argument("--review-timeout", type=int, default=5400)
    parser.add_argument("--verify-timeout", type=int, default=1800)
    parser.add_argument("--published-root", type=Path, default=reported_published_root())
    parser.add_argument("--route-only", action="store_true")
    parser.add_argument("--from-pilot", type=Path)
    parser.add_argument("--recovery-results", type=Path,
                        help="another live result directory whose workers count toward the shared limit")
    parser.add_argument("--retry-results", type=Path,
                        help="isolated output for this supervisor's bounded retries, merged into --results")
    parser.add_argument("--only", nargs="*")
    parser.add_argument("--batch-size", type=int, default=30,
                        help="fresh tasks per batch; wait for the full batch before the next batch")
    parser.add_argument("--carry-results", type=Path, nargs="*",
                        help="frozen task results to recover in this sample without modifying their source")
    parser.add_argument("--batch-selection", type=Path,
                        help="immutable fresh/carried receipt; observed-only sessions cannot be relaunched")
    parser.add_argument("--batch-number", type=int, help="stable attribution number from the batch coordinator")
    parser.add_argument("--once", action="store_true", help="schedule available work and return")
    args = parser.parse_args()
    if not 1 <= args.batch_size <= 40:
        parser.error("--batch-size must be 1..40")
    state_sample = load(args.results / "supervisor-state.json", {}).get("sample")
    if state_sample and Path(state_sample).resolve() != args.sample.resolve():
        parser.error("this results directory belongs to a different sample; choose a new results directory")
    if not 1 <= args.concurrency <= 40:
        parser.error("concurrency must be 1..40")
    selected_ids = set(args.only) if args.only else None
    if args.batch_selection and args.results not in args.batch_selection.parents:
        parser.error("--batch-selection must belong to this results directory")
    selection_receipt = load(args.batch_selection, {}) if args.batch_selection else {}
    if args.batch_number is not None and selection_receipt.get("batch") != args.batch_number:
        parser.error("--batch-number must match the frozen selection receipt")
    batch_number = args.batch_number or 1
    observed_ids = set(selection_receipt.get("observed_only", []))
    official_ids = set(selection_receipt.get("fresh", [])) | set(selection_receipt.get("carried", []))
    if selection_receipt:
        if selected_ids != official_ids | observed_ids or official_ids & observed_ids:
            parser.error("--only must exactly match the batch receipt and disjoint observed-only IDs")
        if len(selection_receipt.get("fresh", [])) > args.batch_size:
            parser.error("the batch receipt exceeds the fresh-task limit")
    carried_ids = carry_workspaces(args.carry_results or [], args.results, selected_ids)
    if carried_ids:
        for task in carried_ids:
            plan = load(args.results / task / "carry-recovery.json", {})
            if plan.get("mode") not in {None, "review", "harbor"}:
                raise ValueError(f"manual route/synthesis recovery is not supervised: {task}")
        if len(args.carry_results) != len(carried_ids):
            raise ValueError("carry-results must identify distinct tasks")
        (args.results / "carry-manifest.json").write_text(json.dumps({
            "schema_version": 1, "tasks": sorted(carried_ids),
            "sources": [str(source.resolve()) for source in args.carry_results],
            "fresh_batch_limit": args.batch_size,
        }, indent=2) + "\n", encoding="utf-8")
    controller_lock_path = args.results / ".supervisor.lock"
    args.results.mkdir(parents=True, exist_ok=True)
    import fcntl
    controller_lock = controller_lock_path.open("a+")
    try:
        fcntl.flock(controller_lock, fcntl.LOCK_EX | fcntl.LOCK_NB)
    except BlockingIOError:
        controller_lock.close()
        parser.error("another supervisor already owns this results directory")
    # Keep the lock descriptor alive for the entire scheduling loop.
    if args.retry_results is not None:
        if args.retry_results.resolve() == args.results.resolve():
            parser.error("--retry-results must be separate from --results")
        if args.recovery_results is not None \
                and args.retry_results.resolve() == args.recovery_results.resolve():
            parser.error("--retry-results and --recovery-results must be separate")
        args.retry_results.mkdir(parents=True, exist_ok=True)
    state_path = args.results / "supervisor-state.json"
    state = load(state_path, {"schema_version": 1, "children": {}})
    old_command = load(args.results / "supervisor-command.json", {})
    command = {"argv": sys.argv, "selected_ids": sorted(selected_ids or [])}
    if old_command and old_command.get("selected_ids") != command["selected_ids"]:
        # The live process argv, not a superseded launch allowlist, is the
        # identity of each adopted session. A replacement supervisor must not
        # orphan a worker just because its predecessor supplied the wrong list.
        atomic_json(args.results / "previous-supervisor-command.json", old_command)
        state["selection_migration"] = {
            "previous_selected_ids": old_command.get("selected_ids", []),
            "selected_ids": command["selected_ids"], "recorded_at": timestamp()}
    atomic_json(args.results / "supervisor-command.json", command)
    state.update(sample=str(args.sample), results=str(args.results), concurrency=args.concurrency,
                 max_turns=args.max_turns, route_only=args.route_only,
                 updated_at=timestamp())
    active: dict[str, subprocess.Popen] = {}
    external = set()
    shared_roots = [args.results]
    if args.from_pilot is not None:
        shared_roots.append(args.from_pilot)
    if args.recovery_results is not None:
        shared_roots.append(args.recovery_results)
    if args.retry_results is not None:
        shared_roots.append(args.retry_results)
    shared_roots = {path.resolve() for path in shared_roots}
    # Canonical --results takes precedence over an isolated retry for the same
    # task. A retry is an infrastructure continuation, never a parallel vote.
    owner_priority = {args.results.resolve(): 2}
    if args.retry_results is not None:
        owner_priority[args.retry_results.resolve()] = 1
    if args.recovery_results is not None:
        owner_priority[args.recovery_results.resolve()] = 0
    seen_workers: dict[str, tuple[int, int]] = {}
    children = state.setdefault("children", {})
    for task in observed_ids:
        child = children.setdefault(task, {})
        child["terminal_observation_only"] = True
        if load(args.results / task / "result.json", {}).get("status") in {"failed", "rejected", "error"}:
            child["observation_final_status"] = load(args.results / task / "result.json", {})["status"]
    completed = {task for task in state.get("scheduled", [])
                 if not children.get(task, {}).get("carried_recovery")}
    # A supervisor is disposable; workers are not. Reconcile all command lines
    # before scheduling so a restart never creates duplicate model sessions.
    process_rows = subprocess.run(["ps", "-eo", "pid=,ppid=,comm=,args="], capture_output=True,
                                  text=True, check=True).stdout.splitlines()
    for line in process_rows:
        fields = line.strip().split(None, 3)
        # A shell containing the supervisor's launch text is not a Python
        # worker. Read /proc because ps truncates .venv executable names.
        if len(fields) != 4:
            continue
        if fields[2] == "python3" and "pipeline.run" not in fields[3]:
            continue
        try:
            command = pipeline_worker_command(int(fields[0]))
            if command is None:
                continue
            result_dir = Path(command[command.index("--results") + 1])
            if (Path(command[command.index("--sample") + 1]).resolve() != args.sample.resolve()
                    and result_dir.resolve() not in shared_roots):
                continue
            task = command[command.index("--only") + 1]
            if result_dir.resolve() not in shared_roots:
                continue
            # Do not drop a real worker because an old --only list omitted it.
            # Its actual --only argument identifies the single live session.
            # Outside the new scope it gets no further model-recovery budget.
            if selected_ids is not None and task not in selected_ids:
                children.setdefault(task, {}).update(terminal_observation_only=True)
            parent = children.get(task, {}).get("pid")
            if worker_alive(parent) and parent != int(fields[0]):
                print(f"duplicate worker refused to replace {task}: pid={fields[0]}", flush=True)
                external.add(task)
                continue
            running = load(result_dir / task / "result.json", {})
            # A live process is authoritative even if its result was archived
            # during cleanup or has not flushed its first status yet.
            children[task] = children.get(task, {}) | {
                "pid": int(fields[0]), "external_worker": True,
                "worker_results": str(result_dir), "last_status": running.get("status", "starting")}
            # Every explicitly shared live directory consumes the same budget.
            # Recovery workspaces are authoritative replacements for originals.
            if result_dir.resolve() in shared_roots:
                external.add(task)
            completed.add(task)
        except (ValueError, IndexError):
            continue
    state["scheduled"] = sorted(completed)
    if args.from_pilot is not None:
        for row in read_jsonl(args.sample / "selection.jsonl"):
            task = row["task_id"]
            if task in external:
                continue
            pilot = load(args.from_pilot / task / "result.json", {})
            if pilot.get("status") in {"routing", "synthesizing", "reviewing", "harbor"}:
                external.add(task)
    # A stale in-flight status cannot reserve a worker forever. If neither a
    # live worker nor a resumable workspace exists, allow a fresh route below.
    for task, child in children.items():
        if child.get("manual_correction"):
            continue
        pid = child.get("pid")
        if worker_alive(pid):
            continue
        status = load(args.results / task / "result.json", {}).get("status")
        if status in {"routing", "synthesizing", "reviewing", "harbor"}:
            child["retry_count"] = 0
            completed.discard(task)
    state["scheduled"] = sorted(completed)
    atomic_json(state_path, state)
    while True:
        for task, child in list(active.items()):
            code = child.poll()
            if code is None:
                continue
            children[task].update(returncode=code, finished_at=timestamp())
            result_dir = Path(children[task].get("worker_results", args.results))
            result = load(result_dir / task / "result.json", {})
            children[task]["final_status"] = result.get("status", "error")
            children[task]["failure_class"] = result.get("failure_class", "pipeline")
            start_error = worker_start_error(result_dir / task)
            if start_error:
                # No new run_one result exists. Preserve the original review
                # request and its one repair opportunity; record only the
                # infrastructure crash, without relabeling the old verdict.
                evidence = args.results / task / "retry-evidence/worker-start-import"
                evidence.mkdir(parents=True, exist_ok=True)
                atomic_json(evidence / (timestamp().replace(":", "-") + ".json"), {
                    "schema_version": 1, "error": start_error, "pid": child.pid,
                    "returncode": code, "preserved_result": result})
                start_recovery_count = children[task].get("start_recovery_count", 0)
                if start_recovery_count < 1:
                    children[task].update(retry_count=0, delivery_retry_count=0,
                                          retry_reason=None, previous_status=None,
                                          recovery_requested=False, start_recovery_count=1,
                                          pipeline_start_error=start_error)
                else:
                    # The interpreter fix itself is broken or incomplete. Do
                    # not spin a fresh failed process every scheduler tick.
                    children[task].update(retry_blocked="worker_start_import",
                                          pipeline_start_error=start_error)
                for key in ("review_retry_count", "harbor_retry_count", "harbor_exception_retry_count"):
                    children[task].pop(key, None)
                completed.discard(task)
            elif result.get("status") in {"passed", "failed", "rejected", "error"}:
                completed.add(task)
                state["scheduled"] = sorted(completed)
            else:
                # Max-turn/API termination may leave a resumable route or
                # workspace. Schedule the bounded retry on the next iteration.
                completed.discard(task)
                state["scheduled"] = sorted(completed)
            del active[task]
            external.discard(task)
            atomic_json(state_path, state)
        # Pilot workers are independent sessions, but their terminal state is
        # authoritative too. Merge it once the actual process has exited.
        if args.from_pilot is not None:
            for task in list(external):
                child = children.get(task, {})
                result_dir = Path(child.get("worker_results", args.from_pilot))
                if result_dir.resolve() != args.from_pilot.resolve():
                    continue
                pid = child.get("pid")
                if worker_alive(pid):
                    continue
                result = load(result_dir / task / "result.json", {})
                external.discard(task)
                destination = args.results / task
                destination.mkdir(parents=True, exist_ok=True)
                atomic_json(destination / "result.json", result)
                children[task].update(final_status=result.get("status"),
                                      pilot_merged=True, finished_at=timestamp())
                completed.add(task)
                if result.get("status") in {"passed", "failed", "error"}:
                    state["final_tasks"] = sorted(set(state.get("final_tasks", [])) | {task})
            state["scheduled"] = sorted(completed)
            atomic_json(state_path, state)
        # Merge isolated infrastructure retries before the terminal-result
        # guards. These are continuations of the same task, never second votes.
        if args.retry_results is not None:
            for retry in args.retry_results.glob("*/result.json"):
                task = retry.parent.name
                result = load(retry, {})
                child = children.get(task, {})
                worker_dir = Path(child.get("worker_results", args.retry_results)).resolve()
                retry_marker = child.get("retry_merged_at")
                already_merged = child.get("retry_merged") and (
                    worker_dir == args.results.resolve() and retry_marker in {None, retry.stat().st_mtime_ns}
                    or retry_marker == retry.stat().st_mtime_ns)
                if (result.get("status") not in {"passed", "failed", "error", "rejected"}
                        or (worker_dir == args.retry_results.resolve() and worker_alive(child.get("pid")))
                        or already_merged):
                    continue
                if strictly_accepted(load(args.results / task / "result.json", {})) \
                        and result.get("status") != "passed":
                    child.update(retry_merged=True, retry_merge_skipped="accepted_result_immutable")
                    children[task] = child
                    continue
                if not (retry.parent / "workspace/delivery").is_dir():
                    child.update(retry_merged=True, retry_merge_skipped="delivery_missing")
                    children[task] = child
                    continue
                destination = args.results / task
                archive = destination / "infrastructure-attempts"
                archive.mkdir(parents=True, exist_ok=True)
                if (destination / "workspace").exists():
                    os.rename(destination / "workspace",
                              archive / ("workspace-before-isolated-retry-" + timestamp().replace(":", "-")))
                shutil.copytree(retry.parent / "workspace", destination / "workspace", symlinks=True)
                for phase in ("route", "synthesis"):
                    source = retry.parent / phase
                    if not source.is_dir():
                        continue
                    target = destination / phase
                    if target.exists():
                        os.rename(target, archive / (phase + "-before-isolated-retry-" + timestamp().replace(":", "-")))
                    shutil.copytree(source, target, symlinks=True)
                if (destination / "result.json").is_file():
                    shutil.copy2(destination / "result.json",
                                 archive / ("before-isolated-retry-" + timestamp().replace(":", "-") + ".json"))
                atomic_json(destination / "result.json", result)
                child.update(retry_merged=True, retry_merged_at=retry.stat().st_mtime_ns,
                             worker_results=str(args.results),
                             pid=None, external_worker=False, recovery_requested=False,
                             retry_count=0, retry_reason="review_infrastructure",
                             last_status=result.get("status"),
                             previous_status=result.get("status"))
                children[task] = child
                external.discard(task)
                completed.discard(task)
                atomic_json(state_path, state)
        # A finished recovery workspace supersedes the original interrupted
        # workspace. Merge the authoritative delivery/result exactly once so
        # shared scheduling can re-review or resume its final acceptance.
        if args.recovery_results is not None:
            for recovery in args.recovery_results.glob("*/result.json"):
                task = recovery.parent.name
                if task == "workspace" or not (recovery.parent / "workspace").is_dir():
                    continue
                result = load(recovery, {})
                child = children.get(task, {})
                pid = child.get("pid")
                if (result.get("status") not in {"passed", "failed", "error", "rejected"}
                        or worker_alive(pid)):
                    continue
                destination = args.results / task
                destination.mkdir(parents=True, exist_ok=True)
                # A finished recovery may contain a newer independently
                # accepted delivery than the stale original. Merge it once,
                # even if the original was terminal or previously marked as
                # manually corrected; a live process always remains exclusive.
                if child.get("recovery_merged") \
                        and child.get("recovery_merged_at") == recovery.stat().st_mtime_ns:
                    continue
                if child.get("manual_correction") and result.get("status") != "passed":
                    continue
                if strictly_accepted(load(destination / "result.json", {})) \
                        and result.get("status") != "passed":
                    # Never replace an accepted result with a stale failure.
                    child.update(recovery_merged=True,
                                 recovery_merged_at=recovery.stat().st_mtime_ns,
                                 recovery_merge_skipped="accepted_result_immutable")
                    children[task] = child
                    atomic_json(state_path, state)
                    continue
                if not (recovery.parent / "workspace").is_dir():
                    # A route/provenance-only recovery has no deliverable to
                    # merge. It must not abort the entire scheduling loop.
                    child["recovery_merged"] = True
                    child["recovery_merge_skipped"] = "delivery_missing"
                    children[task] = child
                    atomic_json(state_path, state)
                    continue
                if (destination / "workspace/delivery").exists() \
                        and not child.get("manual_correction") \
                        and load(destination / "result.json", {}).get("status") == "passed":
                    # A previously merged, strictly accepted production result
                    # is immutable. Superseding recovery evidence is merged
                    # below only when the original is failed or manual.
                    child["recovery_merged"] = True
                    children[task] = child
                    external.discard(task)
                    atomic_json(state_path, state)
                    continue
                destination.joinpath("workspace").mkdir(exist_ok=True)
                if (destination / "workspace/delivery").exists():
                    archive = destination / "infrastructure-attempts"
                    archive.mkdir(exist_ok=True)
                    os.rename(destination / "workspace/delivery", archive / (
                        "delivery-before-recovery-" + timestamp().replace(":", "-")))
                if (recovery.parent / "workspace/delivery").is_dir():
                    shutil.copytree(recovery.parent / "workspace/delivery", destination / "workspace/delivery")
                for name in ("route.json", "NETWORK.md"):
                    source = recovery.parent / "workspace" / name
                    if source.is_file():
                        shutil.copyfile(source, destination / "workspace" / name)
                review = recovery.parent / "workspace/review.json"
                if review.is_file() and not (destination / "workspace/review.json").exists():
                    shutil.copyfile(review, destination / "workspace/review.json")
                previous_result = destination / "result.json"
                if previous_result.is_file() and load(previous_result, {}).get("status") != "passed":
                    evidence = destination / "infrastructure-attempts"
                    evidence.mkdir(exist_ok=True)
                    archived = evidence / "before-recovery-result.json"
                    if not archived.exists():
                        shutil.copy2(previous_result, archived)
                atomic_json(destination / "result.json", result)
                child.update(recovery_merged=True,
                             recovery_merged_at=recovery.stat().st_mtime_ns,
                             last_status=result.get("status"), retry_count=0,
                             external_worker=False, pid=None)
                children[task] = child
                external.discard(task)
                completed.discard(task)
                state["scheduled"] = sorted(completed)
                atomic_json(state_path, state)
        selected = list(read_jsonl(args.sample / "selection.jsonl"))
        if selection_receipt:
            # The receipt identifies fixed-sample positions, not a newly drawn
            # subset. Missing downloads stay attributed to their sample slot.
            positions = [row["task_id"] for row in
                         read_jsonl(args.sample / "selection.jsonl")]
            receipt_positions = [positions.index(task) for task in official_ids]
            selected = [row for row in selected if row["task_id"] in selected_ids
                        and positions.index(row["task_id"]) in receipt_positions]
        for index, row in enumerate(selected):
            if row["task_id"] in carried_ids:
                provenance = load(args.results / row["task_id"] / "carry-provenance.json", {})
                instance_id = provenance.get("instance_id")
                route_instance = load(args.results / row["task_id"] / "workspace/route.json", {}).get("instance_id")
                if not instance_id or instance_id != route_instance:
                    raise ValueError(f"carried task identity does not match its route: {row['task_id']}")
                selected[index] = row | {"instance_id": instance_id}
        if args.recovery_results is not None:
            # Only tasks already explicitly adopted from the shared recovery
            # root are in scope. Never scan unrelated old failures into a new
            # sample, and do not require a carried task to have a fresh ID.
            selected_by_id = {row["task_id"]: row for row in selected}
            for task, child in children.items():
                if child.get("worker_results") and Path(child["worker_results"]).resolve() == args.recovery_results.resolve():
                    original = load(args.recovery_results / task / "result.json", {})
                    if not original.get("instance_id"):
                        continue
                    if task in selected_by_id:
                        selected[selected.index(selected_by_id[task])] = selected_by_id[task] | {
                            "instance_id": original["instance_id"]}
                    else:
                        selected.append({"task_id": task, "instance_id": original["instance_id"],
                                         "carried_shared_recovery": True})
        if args.only:
            wanted = set(args.only)
            selected = [row for row in selected if row["task_id"] in wanted]
        # The first batch can be capped explicitly; later reruns retain its
        # stable sample IDs and reuse only proven route.json decisions.
        # Running tasks in a shared result directory consume real model/API
        # capacity too. Do not double them or exceed the requested limit.
        if args.from_pilot is not None:
            for row in selected:
                task = row["task_id"]
                pilot = load(args.from_pilot / task / "result.json", {})
                if pilot.get("status") in {"routing", "synthesizing", "reviewing", "harbor"}:
                    external.add(task)
        # An adopted out-of-batch worker is monitored to termination but never
        # contributes a fresh launch, review, repair or terminal status here.
        for task in sorted(set(children) & observed_ids):
            if worker_alive(children[task].get("pid")):
                external.add(task)
            else:
                children[task]["observation_final_status"] = load(
                    args.results / task / "result.json", {}).get("status", "error")
            completed.add(task)
        # Reconcile every live worker every minute, not just at supervisor
        # startup. Manually recovered and once-mode workers are adopted here.
        process_rows = subprocess.run(["ps", "-eo", "pid=,ppid=,comm=,args="], capture_output=True,
                                      text=True, check=True).stdout.splitlines()
        seen_pids = set()
        for line in process_rows:
            fields = line.strip().split(None, 3)
            if len(fields) != 4:
                continue
            try:
                pid = int(fields[0])
                command = pipeline_worker_command(pid)
                if command is None:
                    continue
                result_dir = Path(command[command.index("--results") + 1])
                if (Path(command[command.index("--sample") + 1]).resolve() != args.sample.resolve()
                        and result_dir.resolve() not in shared_roots):
                    continue
                task = command[command.index("--only") + 1]
                if result_dir.resolve() not in shared_roots or task not in {row["task_id"] for row in selected}:
                    continue
                if selected_ids is not None and task not in selected_ids:
                    children.setdefault(task, {}).update(terminal_observation_only=True)
                # Live PID reconciliation supersedes persisted owner metadata;
                # otherwise a stale PID can hide a valid external worker.
                child = children.setdefault(task, {})
                # Keep the first observed worker as this task's sole owner.
                # A terminal wrapper may have several Python descendants; their
                # command lines must not cause ownership to change mid-cycle.
                if worker_alive(child.get("pid")):
                    if child["pid"] != pid:
                        print(f"duplicate worker refused to replace {task}: pid={pid}", flush=True)
                    continue
                seen_pids.add(pid)
                child.update(pid=pid, external_worker=True, worker_results=str(result_dir))
                external.add(task)
            except (ValueError, IndexError):
                continue
        for task in list(external):
            child = children.get(task, {})
            if child.get("manual_correction") or not child.get("external_worker"):
                continue
            pid = child.get("pid")
            if not pid or pid in seen_pids or worker_alive(pid):
                continue
            result_dir = Path(child.get("worker_results", args.results))
            result = load(result_dir / task / "result.json", {})
            child["final_status"] = result.get("status", "error")
            if result.get("status") in {"passed", "failed", "rejected", "error"}:
                completed.add(task)
            else:
                child["retry_count"] = 0
                completed.discard(task)
            child["pid"] = None
            external.discard(task)
        external_running = sum(task in external and task not in active for task in external)
        candidates = []
        shared_recovery_tasks = {
            task: Path(child["worker_results"]) for task, child in children.items()
            if child.get("worker_results")
            and args.recovery_results is not None
            and Path(child["worker_results"]).resolve() == args.recovery_results.resolve()}
        # Model retries and handoffs are intentionally not supervised. Only a
        # frozen delivery may resume its independent review/Harbor tail.
        for task, recovery_root in shared_recovery_tasks.items():
            child = children.get(task, {})
            source_sample = load(recovery_root / "supervisor-state.json", {}).get("sample")
            if source_sample:
                source_sample = Path(source_sample)
                if not source_sample.is_absolute():
                    source_sample = Path(__file__).resolve().parents[1] / source_sample
                child["source_sample"] = str(source_sample.resolve())
            elif child.get("source_sample"):
                pass
            elif not child.get("adopted_worker_failure"):
                child["carry_blocked"] = "original_sample_required"
                completed.add(task)
                continue
            if worker_alive(child.get("pid")):
                continue
            # This is an explicitly adopted task, not a scan of unrelated old
            # failures. Its full workspace is authoritative, unlike the small
            # status merge retained for batch reporting.
            record = load(recovery_root / task / "result.json", {})
            route = recovery_root / task / "workspace/route.json"
            delivery = recovery_root / task / "workspace/delivery"
            synthesis = load(recovery_root / task / "synthesis/result.json", {})
            review = load(recovery_root / task / "workspace/review.json", {})
            if strictly_accepted(record):
                completed.add(task)
                external.discard(task)
                continue
            if review.get("passed") is True and delivery.is_dir() and route.is_file() \
                    and record.get("status") in {"failed", "error", "synthesizing", "reviewing", "harbor"}:
                report = ((record.get("harbor") or {}).get("differential_from_final_bundle") or {}).get("report") or {}
                gold_protocol_defect = (
                    record.get("failure_class") == "harbor_failed"
                    and report.get("status") == "infra_error"
                    and (report.get("vulnerable") or {}).get("oracle", {}).get("returncode") == 0
                    and (report.get("fixed") or {}).get("error_stage") == "submission"
                    and (report.get("fixed") or {}).get("submission_result", {}).get("returncode") not in {0, None})
                if gold_protocol_defect:
                    child.update(retry_reason="manual_recovery_required",
                                 external_worker=False, pid=None)
                    completed.add(task)
                    continue
                contract = load(delivery / "task.json", {})
                file_exploit_verifier_bug = (
                    report.get("status") == "infra_error" and contract.get("branch") == "FILE-EXPLOIT"
                    and (report.get("vulnerable") or {}).get("oracle", {}).get("returncode") == 0
                    and (report.get("fixed") or {}).get("error_stage") == "submission"
                    and (report.get("fixed") or {}).get("submission_result", {}).get("returncode") == 1)
                infrastructure = file_exploit_verifier_bug or report.get("status") == "infra_error" \
                    or not (recovery_root / task / "harbor").is_dir()
                if infrastructure:
                    previous_harbor = recovery_root / task / "harbor"
                    if previous_harbor.is_dir():
                        archive = recovery_root / task / "retry-evidence/harbor-before-verifier-contract-repair"
                        if archive.exists():
                            completed.add(task)
                            continue
                        archive.parent.mkdir(exist_ok=True)
                        os.rename(previous_harbor, archive)
                    child.update(retry_reason="review_infrastructure", repair_priority=1,
                                 acceptance_resume_requested=True, external_worker=False, pid=None)
                    candidates.append(task)
                    continue
        for row in selected:
            task = row["task_id"]
            if children.get(task, {}).get("carried_recovery"):
                completed.discard(task)
            if task in completed and (args.results / task / "carry-recovery.json").is_file():
                # An explicit same-instance carry is a new admitted recovery,
                # not the already-finished original attempt.
                child = children.setdefault(task, {})
                child["carried_recovery"] = True
                child.pop("pid", None)
                completed.discard(task)
            if children.get(task, {}).get("terminal_observation_only") is True:
                # An accidentally launched duplicate is retained as evidence,
                # but gets no additional route, synthesis, review or repair.
                child = children.setdefault(task, {})
                record = load(args.results / task / "result.json", {})
                child["observation_final_status"] = record.get("status")
                if child.get("pid") and not worker_alive(child.get("pid")):
                    child["pid"] = None
                    child["external_worker"] = False
                completed.add(task)
                continue
            if task in shared_recovery_tasks:
                continue
            child = children.get(task, {})
            if task in active or (task in external and worker_alive(child.get("pid"))):
                # Live process identity is authoritative, including sessions
                # inherited from manual recovery or a previous supervisor.
                continue
            # `completed` also records historical attempts. A terminal record
            # may still be eligible for its single bounded infrastructure or
            # schema retry; the record checks below make other finals terminal.
            record = load(args.results / task / "result.json", {})
            child = children.setdefault(task, {})
            if record.get("status") in {"failed", "error"} \
                    and (child.get("retry_reason") == "bounded_recovery"
                         or (args.results / task / "workspace/repair-request.json").is_file()
                         or (args.results / task / "workspace/reroute-request.json").is_file()):
                child["retry_reason"] = "manual_recovery_required"
                completed.add(task)
                continue
            if record.get("status") in {"failed", "rejected", "routed"} \
                    and load(args.results / task / "workspace/review.json", {}).get("passed") is not True:
                # Route, synthesis and review failures are terminal here. A
                # later manual recovery may inspect the preserved workspace.
                completed.add(task)
                continue
            route_file = args.results / task / "workspace/route.json"
            delivery_dir = args.results / task / "workspace/delivery"
            synthesis = load(args.results / task / "synthesis/result.json", {})
            review = load(args.results / task / "workspace/review.json", {})
            if child.get("carry_recovery_dispatched"):
                child.pop("carry_blocked", None)
            elif child.get("carried_recovery"):
                plan_path = args.results / task / "carry-recovery.json"
                if not plan_path.is_file():
                    children[task]["carry_blocked"] = "missing_explicit_recovery_plan"
                    completed.add(task)
                    atomic_json(state_path, state)
                    continue
                plan = load(plan_path, {})
                mode = plan.get("mode")
                if (plan.get("schema_version") != 1 or plan.get("task_id") != task
                        or plan.get("instance_id") != record.get("instance_id")):
                    raise ValueError(f"invalid carried recovery plan for {task}")
                if mode in {"route", "route_handoff", "synthesis"}:
                    if mode == "synthesis" and not (args.results / task / "workspace/route.json").is_file():
                        children[task]["carry_blocked"] = "frozen_route_missing"
                        completed.add(task)
                        continue
                    if mode == "route_handoff" and not (args.results / task / "route/trajectory.jsonl").is_file():
                        children[task]["carry_blocked"] = "route_trajectory_missing"
                        completed.add(task)
                        continue
                    children[task].update(retry_reason="carry_" + mode,
                                          carry_recovery_dispatched=True, repair_priority=1,
                                          carry_blocked=None)
                    candidates.append(task)
                    continue
                if mode not in {"review", "harbor"}:
                    raise ValueError(f"unsupported carried recovery plan for {task}")
                if not (
                        (args.results / task / "workspace/delivery").is_dir()
                        and review.get("passed") is True):
                    children[task]["carry_blocked"] = "approved_delivery_missing"
                    completed.add(task)
                    continue
                children[task].update(retry_reason="carry_" + mode,
                                      carry_recovery_dispatched=True, repair_priority=1,
                                      carry_blocked=None)
                candidates.append(task)
                continue
            if child.get("retry_blocked") == "worker_start_import":
                completed.add(task)
                continue
            if child.get("retry_reason") == "bounded_recovery" \
                    and record.get("status") in {"failed", "error"}:
                children[task]["retry_reason"] = "manual_recovery_required"
                completed.add(task)
                continue
            if child.get("retry_reason") == "review_incomplete" \
                    and child.get("review_launched") is True \
                    and child.get("final_status") in {"passed", "failed", "error"} \
                    and record.get("status") in {"passed", "failed", "error"}:
                review = load(args.results / task / "workspace/review.json", {})
                if review.get("passed") is not False:
                    children[task].update(retry_blocked="review_attempt_completed",
                                          retry_reason=None, review_incomplete_retry_count=1)
                    completed.add(task)
                    continue
            route_file = args.results / task / "workspace/route.json"
            delivery_dir = args.results / task / "workspace/delivery"
            synthesis = load(args.results / task / "synthesis/result.json", {})
            review = load(args.results / task / "workspace/review.json", {})
            if record.get("failure_class") == "review_rejected" \
                    and review.get("passed") is False:
                children[task]["retry_reason"] = "manual_recovery_required"
                completed.add(task)
                continue
            if record.get("status") in {"error", "failed"} \
                    and (args.results / task / "workspace/repair-request.json").is_file():
                children[task]["retry_reason"] = "manual_recovery_required"
                completed.add(task)
                continue
            if (synthesis.get("status") == "completed" and route_file.is_file()
                    and delivery_dir.is_dir()
                    and not (args.results / task / "workspace/review.json").is_file()
                    and not (args.results / task / "workspace/repair-request.json").is_file()
                    and record.get("status") not in {"error", "failed", "rejected"}
                    and child.get("review_incomplete_retry_count", 0) < 1
                    and child.get("retry_reason") != "review_incomplete"
                    and (args.results / task / "review/result.json").is_file()
                    and not (args.results / task / "workspace/repair-request.json").is_file()
                    and load(args.results / task / "review/result.json", {}).get("status") != "max_turns"):
                # A finished delivery must never be rerouted merely because an
                # earlier resume overwrote its status or archived its trace.
                # Rebuild the review evidence snapshot and launch the normal
                # independent-review/Harbor tail of the same task.
                children[task].update(retry_reason="review_incomplete",
                                      repair_priority=1)
                candidates.append(task)
                continue
            if (record.get("status") == "error"
                    and any(token in str(record.get("error", ""))
                            for token in ("route/tool-logs", "name 'route' is not defined"))
                    and not child.get("pipeline_repair_pending")
                    and not (worker_alive(child.get("pid")))
                    and child.get("tool_log_migration_count", 0) < 1):
                # Requeue once with the directory-creation fix. The retry_reason
                # may be an older migration, so track this repair separately.
                child.update(pipeline_repair_pending=True, tool_log_migration_count=1,
                             retry_count=0)
                completed.discard(task)
            # A historical pilot/manual attempt can overwrite the error that
            # this supervisor originally retried. Do not let the stale marker
            # suppress a new valid route or a known pipeline repair forever.
            previous_status = child.get("previous_status")
            if (record.get("status") == "error"
                    and child.get("retry_reason") in {"route_infrastructure", "route_schema_retry",
                                                     "route_budget", "completed_route_recovery"}
                    and previous_status not in {None, "error"}):
                evidence = args.results / task / "retry-evidence"
                evidence.mkdir(exist_ok=True)
                atomic_json(evidence / ("superseded-retry-" + timestamp().replace(":", "-") + ".json"), record)
                child.update(retry_count=0, retry_reason=None, previous_status=None,
                             retry_reset_reason="superseded_historical_result")
            if (record.get("status") == "routing"
                    and child.get("retry_reason") == "completed_route_recovery"
                    and not (args.results / task / "workspace/route.json").is_file()
                    and not (worker_alive(child.get("pid")))):
                # No routing verdict was ever produced. Remove only this
                # contradictory migration marker; all other state is intact.
                child.pop("retry_reason", None)
            published_acceptance = (args.published_root / task / "acceptance.json") \
                if args.published_root is not None else None
            approved_review = load(args.results / task / "workspace/review.json", {})
            if ((not record or record.get("error") == "ValueError: completed delivery requires --resume; refusing to replace it with a fresh route")
                    and synthesis.get("status") == "completed"
                    and route_file.is_file() and delivery_dir.is_dir()
                    and approved_review.get("passed") is True):
                # A completed, approved delivery has no model work left. Route
                # callback recovery must not bypass the existing review.
                children[task].update(retry_reason="review_infrastructure",
                                      acceptance_resume_requested=True, repair_priority=1)
                candidates.append(task)
                continue
            if (record.get("status") == "failed"
                    and approved_review.get("passed") is True
                    and child.get("gold_protocol_retry_count", 0) < 1):
                # Older verifier bundles rejected the intentional FILE-POV
                # crash before consulting its target oracle. A clean gold may
                # succeed while the separately shipped final verifier is stale.
                # Identify that exact obsolete check in preserved gold or final
                # differential evidence; never waive a genuine wrong reward.
                harbor = record.get("harbor") or {}
                differential = harbor.get("differential_from_final_bundle") or {}
                evidence_records = [load(path, {}) for path in
                                    (args.results / task / "harbor/jobs").glob(
                                        "*-gold/*/verifier/evidence.json")]
                evidence_records.append(differential.get("report") or {})
                gold_protocol_error = any(
                    evidence.get("branch") == "FILE-POV"
                    and evidence.get("status") == "infra_error"
                    and (evidence.get("vulnerable") or {}).get("error_stage") == "submission"
                    and (evidence.get("vulnerable") or {}).get("error")
                        == "submission must exit 0 after the protocol exchange"
                    and ((evidence.get("vulnerable") or {}).get("submission_result") or {})
                        .get("returncode") != 0
                    for evidence in evidence_records)
                if gold_protocol_error:
                    previous_harbor = args.results / task / "harbor"
                    archived_harbor = args.results / task / "retry-evidence/harbor-file-pov-gold-protocol"
                    archived_harbor.parent.mkdir(exist_ok=True)
                    if archived_harbor.exists():
                        child.update(gold_protocol_retry_count=1,
                                     retry_blocked="archive_exists")
                        completed.add(task)
                        continue
                    os.rename(previous_harbor, archived_harbor)
                    child.update(retry_reason="review_infrastructure",
                                 gold_protocol_retry_count=1,
                                 acceptance_resume_requested=True, repair_priority=1)
                    candidates.append(task)
                    continue
            if (record.get("status") == "failed"
                    and approved_review.get("passed") is True
                    and delivery_dir.is_dir() and route_file.is_file()
                    and not (args.results / task / "harbor").is_dir()
                    and not record.get("harbor")
                    and not worker_alive(child.get("pid"))
                    and child.get("retry_reason") in {"harbor_infrastructure", "review_infrastructure"}
                    and not child.get("carried_recovery")):
                # The old Harbor tree has already been archived for this exact
                # infrastructure retry. Never reinterpret the preserved failed
                # result as a fresh contract repair or return it as terminal.
                candidates.append(task)
                continue
            if (record.get("status") in {"synthesizing", "reviewing", "harbor"}
                    and approved_review.get("passed") is True
                    and (args.results / task / "workspace/delivery").is_dir()
                    and not worker_alive(child.get("pid"))
                    and not child.get("acceptance_resume_requested")):
                evidence = args.results / task / "retry-evidence/interrupted-final-acceptance"
                evidence.mkdir(parents=True, exist_ok=True)
                if not (evidence / "result.json").is_file():
                    atomic_json(evidence / "result.json", record)
                child.update(retry_reason="review_infrastructure",
                             acceptance_resume_requested=True, repair_priority=1)
                candidates.append(task)
                continue
            historical_gold_defect = gold_writable_path_evidence(args.results, task, record)
            if child.get("retry_reason") == "review_infrastructure" \
                    and child.get("acceptance_resume_requested") \
                    and not worker_alive(child.get("pid")):
                # The evidence archive above has already admitted this one
                # re-acceptance. A generic terminal guard must not consume it.
                candidates.append(task)
                continue
            if historical_gold_defect is not None and record.get("status") == "passed":
                # A target-side oracle can outlive a defective reference
                # submission in preserved evidence. Rebuild the final Harbor
                # acceptance once, without changing the already-reviewed
                # vulnerability, fix, oracle or image isolation.
                evidence = args.results / task / "retry-evidence/gold-protocol-reacceptance"
                if evidence.exists():
                    completed.add(task)
                    continue
                evidence.mkdir(parents=True)
                for name in ("harbor", "review"):
                    source = args.results / task / name
                    if source.exists():
                        os.rename(source, evidence / name)
                atomic_json(evidence / "result.json", record)
                children[task].update(retry_reason="review_infrastructure",
                                      retry_count=1, acceptance_resume_requested=True,
                                      harbor_launched=False, gold_protocol_retry_count=1,
                                      repair_priority=1)
                candidates.append(task)
                continue
            if (strictly_accepted(record) or (published_acceptance is not None
                    and published_acceptance.is_file()
                    and strictly_accepted(load(published_acceptance, {})))) \
                    and historical_gold_defect is None:
                child.update(pid=None, final_status="passed", manual_correction=True)
                completed.add(task)
                external.discard(task)
                continue
            if (child.get("retry_reason") in {"completed_route_recovery", "route_schema_retry"}
                    and record.get("status") in {"synthesizing", "reviewing", "harbor", "routed"}):
                # Completing a structured route consumes only that route's
                # replacement, not the one permitted synthesis-budget retry.
                child.pop("retry_reason", None)
                child["retry_count"] = 0
            if record.get("status") == "synthesizing":
                # A successful entry into the model loop supersedes the old
                # infrastructure error stored in this same result file.
                child.pop("retry_reason", None)
            if child.get("pilot_merged") and record.get("status") in {"passed", "failed", "rejected", "error"}:
                completed.add(task)
                continue
            if child.get("manual_correction") and child.get("external_worker"):
                pid = child.get("pid")
                if worker_alive(pid):
                    external.add(task)
                else:
                    result_dir = Path(child.get("worker_results", args.results))
                    status = load(result_dir / task / "result.json", {}).get("status")
                    child["last_status"] = status
                    if status in {"routing", "synthesizing", "reviewing", "harbor"}:
                        # A dead external process is not active capacity.
                        child["pid"] = None
                        child["retry_count"] = 0
                        child.pop("stopped_by", None)
                        child.pop("manual_correction", None)
                        completed.discard(task)
                # A separate bounded recovery owns the authoritative workspace
                # and review. Never retry or replace it using a stale merged result.
                if child.get("manual_correction"):
                    continue
            if child.get("retry_reason") and (args.results / task / "workspace/delivery").is_dir() \
                    and child.get("retry_count", 0) >= 1 and record.get("status") in \
                    {"routing", "synthesizing", "reviewing", "harbor", "routed"} \
                    and worker_alive(child.get("pid")) \
                    and str(record.get("error", "")) not in {
                        "ValueError: public_runner is only valid for FILE-POV",
                        "ValueError: unsupported task branch"}:
                # The resume worker is already scheduled but may not yet have
                # flushed its status; never enqueue a duplicate terminal retry.
                completed.add(task)
                continue
            route_file = args.results / task / "workspace/route.json"
            # A budget-limited route or interrupted synthesis is not evidence
            # that the vulnerability is unsuitable. Retry each such attempt
            # once, preserving the interrupted trajectory and all source files.
            # Real rejected/failed/Harbor verdicts are never silently retried.
            if child.get("terminal_observation_only"):
                completed.add(task)
                continue
            download_error = next((entry for entry in
                                   load(args.sample / "download-report.json", {}).get("tasks", [])
                                   if entry.get("task_id") == task and entry.get("status") == "error"), None)
            if (download_error is not None
                    and not (args.sample / "tasks" / task / "input/manifest.json").is_file()
                    and not (args.results / task / "workspace/delivery").is_dir()
                    and not worker_alive(child.get("pid"))):
                missing = load(args.results / task / "result.json", {})
                if missing.get("failure_class") != "input_unavailable":
                    download = download_error
                    atomic_json(args.results / task / "result.json", {
                        "task_id": task, "instance_id": row["instance_id"],
                        "status": "error", "failure_class": "input_unavailable",
                        "error": download.get("error", "input manifest is missing"),
                        "finished_at": timestamp()})
                children.setdefault(task, {})["final_status"] = "error"
                completed.add(task)
                continue
            synthesis = load(args.results / task / "synthesis/result.json", {})
            harbor = record.get("harbor") or {}
            differential = harbor.get("differential_from_final_bundle") or {}
            recovery_error = str(record.get("error", ""))
            pending_infrastructure = (
                ((differential.get("report") or {}).get("status") == "infra_error"
                 and ((differential.get("report") or {}).get("vulnerable") or {}).get("oracle", {}).get("returncode") == 0
                 and ((differential.get("report") or {}).get("fixed") or {}).get("error_stage") == "submission"
                 and ((differential.get("report") or {}).get("fixed") or {}).get("submission_result", {}).get("returncode") == 1
                 and (args.results / task / "workspace/delivery/task.json").is_file()
                 and load(args.results / task / "workspace/delivery/task.json", {}).get("branch") == "FILE-EXPLOIT")
                or recovery_error.startswith("PermissionError: [Errno 13]")
                or "Harbor resume requires a passing independent review" in recovery_error
                or "invalid or oversized HTTP request" in recovery_error
                or (record.get("status") == "failed"
                    and record.get("failure_class") == "harbor_failed"
                    and (differential.get("report") or {}).get("status") in
                    {"infra_error", "patch_failed", "other_bug"}))
            exhausted_review = load(args.results / task / "review/result.json", {}).get("status") == "max_turns"
            pending_infrastructure = pending_infrastructure and gold_writable_path_evidence(
                args.results, task, record) is None
            pending_review_incomplete = (
                record.get("status") == "error" and not (args.results / task / "workspace/review.json").is_file()
                and (synthesis.get("status") == "completed" or exhausted_review)
                and not pending_infrastructure
                and child.get("review_incomplete_retry_count", 0) < 1)
            if child.get("retry_blocked") == "review_attempt_completed":
                completed.add(task)
                continue
            # A completed --review-delivery attempt is terminal unless its
            # concrete delivery defect is routed to the bounded repair below.
            # result.json may be overwritten in <1s, so completion time alone
            # cannot prove a retry ran; the durable launch record is the gate.
            review_attempt_record = child.get("review_launched") is True \
                and child.get("retry_reason") == "review_incomplete" \
                and child.get("final_status") in {"passed", "failed", "error"}
            if pending_review_incomplete and child.get("review_incomplete_retry_count", 0) < 1:
                # A reviewer that produced no verdict needs a fresh bounded
                # review, not a --resume that immediately fails on the same
                # missing file. Archive its trajectory before any resume tail.
                # A stale in-flight last_status may mark an intended recovery
                # that was never launched; it is not evidence of a retry.
                children[task].update(retry_reason="review_incomplete", repair_priority=1)
                candidates.append(task)
                continue
            pending_restartable_synthesis = (
                record.get("status") == "synthesizing"
                and synthesis.get("status") in {"running", "max_turns", "timeout", "api_error"}
                and not (args.results / task / "workspace/review.json").is_file())
            pending_interrupted_synthesis = (
                record.get("status") == "failed"
                and record.get("failure_class") == "synthesis_incomplete"
                and synthesis.get("status") in {"api_error", "timeout", "max_turns", "running"})
            bounded_recovery = (
                route_file.is_file() and (args.results / task / "workspace/input/src").is_dir()
                and not worker_alive(child.get("pid"))
                and (child.get("carried_recovery") or not child.get("recovery_requested")
                     or child.get("last_status") in {"routing", "synthesizing", "reviewing", "harbor"})
                and (pending_infrastructure or pending_review_incomplete or pending_interrupted_synthesis
                     or pending_restartable_synthesis))
            if bounded_recovery and child.get("bounded_recovery_launched") is True \
                    and record.get("status") in {"failed", "error"}:
                child["retry_reason"] = "manual_recovery_required"
                completed.add(task)
                continue
            if bounded_recovery:
                evidence = args.results / task / "retry-evidence" / "bounded-recovery-request"
                evidence.mkdir(parents=True, exist_ok=True)
                if not (evidence / "result.json").is_file():
                    atomic_json(evidence / "result.json", record)
                recovery_reason = ("infrastructure" if pending_infrastructure
                                   else "review" if pending_review_incomplete else "synthesis")
                if (pending_infrastructure
                        and delivery_dir.is_dir() and approved_review.get("passed") is True):
                    # A passed delivery whose Harbor evidence is infra_error
                    # needs acceptance, not another synthesis session. This
                    # also preserves the existing review's exclusive vote.
                    child.update(retry_reason="review_infrastructure",
                                 acceptance_resume_requested=True, repair_priority=1)
                    candidates.append(task)
                    continue
                recovery = (args.recovery_results or args.results) / task
                recovery.mkdir(parents=True, exist_ok=True)
                child.update(recovery_requested=True, retry_merged=False,
                             recovery_reason=recovery_reason,
                             retry_reason="bounded_recovery", repair_priority=1)
                child["retry_reason"] = "manual_recovery_required"
                completed.add(task)
                continue
            if (record.get("status") == "error" and child.get("retry_reason") == "bounded_recovery"
                    and "PermissionError: [Errno 13]" in str(record.get("error", ""))):
                # The same-workspace resume already ran. It neither needs nor
                # may consume another bounded model retry for a host-file
                # permission error; let the completed-delivery review tail or
                # a real unfinished-synthesis guard handle it.
                child["retry_reason"] = None
            pending_delivery_repair = (record.get("status") in {"error", "failed"}
                                       and (args.results / task / "workspace/repair-request.json").is_file()
                                       and not (args.results / task / "workspace/review.json").is_file()
                                       and synthesis.get("status") == "completed" and route_file.is_file()
                                       and (child.get("delivery_retry_count", 0) == 0
                                            or (child.get("delivery_retry_count") == 1
                                                and child.get("retry_reason") == "review_incomplete")))
            if pending_delivery_repair:
                children[task]["retry_reason"] = "manual_recovery_required"
                completed.add(task)
                continue
            retry_reason = None
            if child.get("retry_reason") == "review_incomplete" \
                    and child.get("review_incomplete_retry_count", 0) == 0 \
                    and not (args.results / task / "workspace/review.json").is_file():
                # The dedicated preparation branch above assigned this exact
                # recovery. Do not reset it before the archive/launch section.
                retry_reason = "review_incomplete"
            # Preserve reviewed deliveries when final acceptance is blocked by
            # factory infrastructure, not by an exploit/fixed differential.
            # One bounded retry reuses a real gold=1 result and always reruns
            # null plus the frozen private verifier. Never retry a genuine
            # wrong reward, rejected review, or false private differential.
            synthesis = load(args.results / task / "synthesis/result.json", {})
            contract_error = str(record.get("error", ""))
            delivery_contract = (record.get("status") == "error"
                                 and (contract_error.startswith("ValueError: missing delivery/")
                                      or contract_error in {
                                          "ValueError: public_runner is only valid for FILE-POV",
                                          "ValueError: unsupported task branch",
                                          "ValueError: FILE routes require host_type=null",
                                          "ValueError: sidecar_services must contain non-main/client/runner service names"})
                                 or (differential.get("status") == "error"
                                     and str(differential.get("error", "")).startswith("ValueError: report.")))
            review_rejected = (record.get("status") == "failed"
                               and record.get("failure_class") == "review_rejected")
            review_findings = record.get("review") if review_rejected else None
            review_attempt_completed = (child.get("review_launched") is True
                                        and child.get("retry_reason") == "review_incomplete"
                                        and child.get("final_status") in {"passed", "failed", "error"}
                                        and record.get("status") in {"passed", "failed", "error"})
            if review_attempt_completed and not (review_rejected or delivery_contract):
                # A generic infrastructure fallback cannot relaunch an
                # unchanged review which already returned a terminal error.
                child.update(retry_blocked="review_attempt_completed",
                             retry_reason=None, review_incomplete_retry_count=1)
                completed.add(task)
                continue
            if review_rejected and not isinstance(review_findings.get("passed"), bool):
                review_findings = load(args.results / task / "workspace/review.json", {})
            if review_rejected and not isinstance(review_findings.get("passed"), bool):
                children[task]["retry_blocked"] = "missing_original_review_verdict"
                completed.add(task)
                continue
            if delivery_contract or review_rejected:
                children[task]["retry_reason"] = "manual_recovery_required"
                completed.add(task)
                continue
            differential_failure = (differential.get("status") == "error"
                                    or (differential.get("report") or {}).get("status") == "infra_error")
            if (record.get("status") == "failed" and differential_failure
                    and (harbor.get("gold") or {}).get("reward") == 1.0
                    and (harbor.get("null") or {}).get("reward") == 0.0):
                retry_reason = "harbor_infrastructure"
            # A true private differential cannot repair an invalid gold protocol.
            # The raw fixed submission evidence is retained and used to request
            # one concrete delivery repair, never to waive the gold=1 contract.
            if (record.get("status") == "failed" and record.get("failure_class") == "harbor_failed"
                    and (harbor.get("gold") or {}).get("reward") == 0.0
                    and differential.get("status") == "passed"
                    and (differential.get("report") or {}).get("status") == "this_bug"
                    and ((differential.get("report") or {}).get("fixed") or {})
                        .get("submission_result", {}).get("returncode") != 0
                    and child.get("delivery_retry_count", 0) < 1):
                retry_reason = "manual_recovery_required"
            gold_path_defect = gold_writable_path_evidence(args.results, task, record)
            if (gold_path_defect is not None
                    and load(args.results / task / "workspace/review.json", {}).get("passed") is True
                    and child.get("delivery_retry_count", 0) < 1):
                retry_reason = "manual_recovery_required"
            if retry_reason == "harbor_infrastructure" and (child.get("harbor_retry_count", 0) >= 1
                                            and child.get("harbor_launched")):
                retry_reason = None
            elif (record.get("status") == "failed"
                  and record.get("failure_class") == "harbor_failed"
                  and load(args.results / task / "workspace/review.json", {}).get("passed") is True
                  and not (args.results / task / "workspace/repair-request.json").is_file()
                  and child.get("delivery_retry_count", 0) < 1
                  and (differential.get("report") or {}).get("status") == "other_bug"):
                # Preserve the differential for manual delivery repair; do not
                # silently launch another synthesis session.
                retry_reason = "manual_recovery_required"
            elif (record.get("status") == "failed"
                  and record.get("failure_class") == "harbor_failed"
                  and load(args.results / task / "workspace/review.json", {}).get("passed") is True
                  and (child.get("review_retry_count", 0) < 1
                       or gold_path_defect is not None)
                  and (differential.get("report") or {}).get("status") == "infra_error"):
                # The verifier failed before it could judge the submission.
                # Keep the approved delivery frozen and retry only acceptance;
                # a wrong gold/null reward is still a genuine task failure.
                retry_reason = "review_infrastructure"
            elif (record.get("status") == "error"
                  and ("Harbor trial failed" in str(record.get("error", ""))
                       or "Harbor trial exception" in str(record.get("error", "")))
                  and route_file.is_file()
                  and (args.results / task / "workspace/delivery").is_dir()
                  and child.get("review_retry_count", 0) < 1):
                permission_error = False
                for log in (args.results / task / "harbor/jobs").glob("*/*/*/oracle.txt"):
                    if "Permission denied" in log.read_text(encoding="utf-8", errors="replace"):
                        permission_error = True
                for log in (args.results / task / "harbor/jobs").glob("*/*/*/verifier/test-stdout.txt"):
                    if "/tests/test.sh: Permission denied" in log.read_text(encoding="utf-8", errors="replace"):
                        permission_error = True
                if permission_error and child.get("harbor_permission_retry_count", 0) < 1:
                    retry_reason = "review_infrastructure"
                    child["harbor_permission_retry_count"] = 1
                    record["status"] = "failed"
                    record["error"] = "infrastructure: exported Harbor material directory was not traversable by the task user"
                else:
                    retry_reason = None
                    completed.add(task)
                    continue
                atomic_json(args.results / task / "result.json", record)
            elif (record.get("status") == "failed"
                  and record.get("failure_class") == "harbor_failed"
                  and child.get("harbor_permission_retry_count", 0) < 1
                  and route_file.is_file()):
                # A gold=0 can be caused by the oracle never executing. Do not
                # call that an agent failure; verify the raw oracle log first.
                permission_error = any(
                    "Permission denied" in log.read_text(encoding="utf-8", errors="replace")
                    for log in (args.results / task / "harbor/jobs").glob("*-gold/*/agent/oracle.txt"))
                if permission_error:
                    child["harbor_permission_retry_count"] = 1
                    retry_reason = "review_infrastructure"
                    record["error"] = "infrastructure: Harbor oracle could not traverse the exported solution directory"
                    atomic_json(args.results / task / "result.json", record)
                elif gold_path_defect is None:
                    completed.add(task)
                    continue
            elif (record.get("status") == "error"
                  and "docker image inspect" in str(record.get("error", ""))
                  and load(args.results / task / "workspace/review.json", {}).get("passed") is True
                  and child.get("review_retry_count", 0) < 1):
                record["error"] = "infrastructure: approved public image was removed; rebuild it before Harbor acceptance"
                atomic_json(args.results / task / "result.json", record)
                retry_reason = "review_infrastructure"
            elif (record.get("status") in {"error", "failed"}
                  and "infrastructure" in str(record.get("error", ""))
                  and route_file.is_file()
                  and (args.results / task / "workspace/delivery").is_dir()
                  and child.get("review_retry_count", 0) < 1):
                # A repaired delivery must earn a new structured verdict before
                # --resume is allowed to enter final acceptance.
                review = load(args.results / task / "workspace/review.json", {})
                if retry_reason != "review_infrastructure":
                    if not isinstance(review.get("passed"), bool) or review["passed"]:
                        retry_reason = "review_infrastructure"
            if (record.get("status") == "routing" and not route_file.exists()
                    and child.get("retry_count", 0) < 1):
                # A structured-submit/schema retry is not a routing rejection.
                retry_reason = "route_schema_retry"
            if (record.get("status") == "error" and not route_file.exists()
                    and child.get("retry_count", 0) < 1):
                error = str(record.get("error", ""))
                if ("did not complete: max_turns" in error
                        or any(token in error for token in
                               ("name 'route' is not defined", "route/tool-logs", "no usable message from model"))):
                    # These are bounded repairs for known pipeline defects,
                    # not a second opinion about an unsuitable vulnerability.
                    retry_reason = "route_infrastructure"
            if (record.get("status") == "error"
                    and "did not complete: max_turns" in str(record.get("error", ""))
                    and not route_file.exists()
                    and not (worker_alive(child.get("pid")))
                    and child.get("route_budget_recovery_count", 0) < 1):
                # A later exhausted route has still not decided suitability.
                # It receives a separate evidence-preserving recovery budget,
                # without erasing the prior bounded-retry history.
                retry_reason = "route_budget"
            review_incomplete = (record.get("status") in {"reviewing", "error"}
                                 and (args.results / task / "workspace/delivery").is_dir()
                                 and not (args.results / task / "workspace/review.json").is_file()
                                 and not (worker_alive(child.get("pid"))))
            if retry_reason is None and review_incomplete \
                    and child.get("review_incomplete_retry_count", 0) < 1:
                # An exhausted or interrupted reviewer has no verdict. Preserve
                # its trajectory, then submit the unchanged frozen delivery to
                # a fresh bounded review instead of turning missing review.json
                # into a permanent orchestration error.
                retry_reason = "review_incomplete"
            if (record.get("status") == "routing" and not route_file.is_file()
                    and not worker_alive(child.get("pid"))):
                # A nonterminal route has no accept/reject verdict to retry.
                # Regardless of a stale migration marker, it remains work.
                children[task].update(retry_reason="manual_recovery_required")
                completed.add(task)
                continue
            if (retry_reason is None and record.get("status") in {"routing", "error"}
                    and not route_file.is_file() and child.get("retry_count", 0) < 1):
                child.pop("retry_reason", None)
                completed.discard(task)
            if (retry_reason is None and record.get("status") == "harbor"
                    and (args.results / task / "workspace/delivery").is_dir()
                    and not worker_alive(child.get("pid"))
                    and child.get("harbor_exception_retry_count", 0) < 1):
                # The delivery and independent review remain frozen. Retry
                # only final acceptance after a fixed exporter/runtime error.
                retry_reason = "review_infrastructure"
            if (retry_reason is None and record.get("status") in {"routing", "error"}
                    and route_file.is_file() and not delivery_dir.is_dir()
                    and not record.get("review_agent")):
                try:
                    task_record = load(args.sample / "tasks" / task / "input/meta.json", {})
                    validate_route(args.results / task / "workspace", task_record["instance_id"])
                    completed.add(task)
                    continue
                except (OSError, ValueError, KeyError):
                    pass
            if retry_reason in {"route_budget", "route_schema_retry", "route_infrastructure",
                                "synthesis_interrupted", "delivery_contract_repair",
                                "delivery_review_repair"}:
                children[task].update(retry_reason="manual_recovery_required",
                                      previous_status=record.get("status"))
                completed.add(task)
                continue
            if retry_reason:
                # Several specific recovery paths mutate the local child dict.
                # Flush them once before terminal/launch handling so they cannot
                # erase the authoritative shared retry gate on the next tick.
                children[task] = child
                evidence = args.results / task / "retry-evidence"
                evidence.mkdir(exist_ok=True)
                # Re-routing replaces its own logs; review/Harbor resume must
                # retain route and synthesis evidence in place.
                if retry_reason == "review_incomplete":
                    previous_review = args.results / task / "review"
                    archived_review = evidence / "review-incomplete"
                    if previous_review.exists() and not archived_review.exists():
                        os.rename(previous_review, archived_review)
                    if review_attempt_record:
                        # A real --review-delivery worker was launched and its
                        # terminal error is already durable. Never relaunch the
                        # same unchanged contract once per scheduler tick.
                        children[task]["retry_blocked"] = "review_attempt_completed"
                        completed.add(task)
                        continue
                    children[task]["review_incomplete_retry_count"] = 1
                children[task].update(retry_count=1, retry_reason=retry_reason,
                                      previous_status=record.get("status"))
                if retry_reason in {"harbor_infrastructure", "review_infrastructure"}:
                    child.pop("harbor_launched", None)
                if retry_reason == "review_incomplete":
                    child.pop("review_launched", None)
                    children[task]["review_incomplete_retry_count"] = 1
                    previous_review = args.results / task / "review"
                    archived_review = evidence / "review-incomplete"
                    if previous_review.exists() and not archived_review.exists():
                        os.rename(previous_review, archived_review)
                if retry_reason == "review_infrastructure":
                    if record.get("status") == "harbor":
                        children[task]["harbor_exception_retry_count"] = 1
                    if child.get("harbor_permission_retry_count") and child.get("harbor_permission_retry_count") > 1:
                        children[task].update(retry_blocked="permission_retry_exhausted")
                        completed.add(task)
                        continue
                    children[task]["review_retry_count"] = 1
                if retry_reason == "harbor_infrastructure":
                    previous_harbor = args.results / task / "harbor"
                    archived_harbor = evidence / "harbor-infrastructure"
                    if archived_harbor.exists():
                        children[task].update(harbor_retry_count=1, retry_blocked="archive_exists")
                        completed.add(task)
                        continue
                    os.rename(previous_harbor, archived_harbor)
                    shutil.copytree(archived_harbor / "bundle", previous_harbor / "bundle")
                    os.makedirs(previous_harbor / "jobs", exist_ok=True)
                    for gold in (archived_harbor / "jobs").glob("*-gold"):
                        shutil.copytree(gold, previous_harbor / "jobs" / gold.name)
                    children[task]["harbor_retry_count"] = 1
                candidates.append(task)
                continue
            if record.get("status") in {"routing", "synthesizing", "reviewing", "harbor", "routed",
                                          "rejected", "passed", "failed", "error"}:
                children.setdefault(task, {"external_or_finished": True,
                                           "last_status": record["status"]})
                completed.add(task)
                continue
            if args.route_only:
                candidates.append(task)
                continue
            if args.from_pilot is not None:
                pilot = load(args.from_pilot / task / "result.json", {})
                route_file = args.from_pilot / task / "workspace/route.json"
                if (args.results / task / "result.json").exists():
                    # A merged result is final. Never launch a fresh route
                    # merely because this task no longer occupies a worker.
                    completed.add(task)
                    continue
                if pilot.get("status") == "routing":
                    continue
                if pilot.get("status") == "routed" and route_file.is_file():
                    # A routed-only result needs a fresh --route-from run;
                    # never silently start it from this batch supervisor.
                    completed.add(task)
                    continue
                elif pilot:
                    children[task] = {"pilot_status": pilot.get("status"),
                                      "not_admitted": pilot.get("status") != "passed",
                                      "pilot_merged": True, "finished_at": timestamp()}
                    destination = args.results / task
                    destination.mkdir(parents=True, exist_ok=True)
                    atomic_json(destination / "result.json", pilot)
                    if pilot.get("status") in {"passed", "failed", "error"}:
                        state["final_tasks"] = sorted(set(state.get("final_tasks", [])) | {task})
                    completed.add(task)
                    continue
            candidates.append(task)
        # The outer production runner supplies one disjoint fresh batch plus
        # explicitly admitted infrastructure repairs. Repairs share the same
        # 30-worker budget but do not consume a new-sample slot.
        accountable_ids = official_ids if selection_receipt else selected_ids
        carried_budget = len(set(selection_receipt.get("carried", []))) if selection_receipt else len(carried_ids)
        if accountable_ids is not None and not 1 <= len(accountable_ids) <= args.batch_size + carried_budget:
            parser.error("one supervisor batch must contain at most 30 fresh IDs plus explicit carried repairs")
        # A bounded repair already has a validated route, delivery and concrete
        # reviewer findings. Let it use the next free slot instead of starving
        # behind every never-started route in the sample. Stable ordering among
        # repairs and new candidates is preserved; the shared cap is unchanged.
        prioritize_candidates(candidates, children, selected)
        while candidates and len(active) + external_running < args.concurrency:
            task = candidates.pop(0)
            child_state = children.setdefault(task, {})
            resume_harbor = child_state.get("retry_reason") in {
                "harbor_infrastructure", "review_infrastructure", "carry_harbor"}
            carry_plan = load(args.results / task / "carry-recovery.json", {}) \
                if child_state.get("retry_reason", "").startswith("carry_") else {}
            worker_results = (args.retry_results if child_state.get("retry_reason") == "bounded_recovery"
                              and args.retry_results is not None else args.results)
            if task in shared_recovery_tasks:
                # An adopted recovery remains authoritative in its own result
                # directory. Do not replace its workspace with a partial merge.
                worker_results = shared_recovery_tasks[task]
            state["batch_members"] = sorted(accountable_ids or [])
            state["observed_only"] = sorted(observed_ids)
            state["batch_number"] = batch_number
            retry_reason = child_state.get("retry_reason")
            if child_state.get("retry_reason") in {
                    "delivery_contract_repair", "delivery_review_repair",
                    "fresh_review_delivery_repair"}:
                # Delivery and route failures are terminal. Their evidence is
                # retained for a later manual recovery, not another model vote.
                completed.add(task)
                continue
            carry_continue = retry_reason == "carry_synthesis"
            carry_workspace_from = args.results / task / "workspace" if carry_continue else None
            carry_route_from = None
            carry_route_handoff = None
            if retry_reason == "carry_route":
                route_path = args.results / task / "workspace/route.json"
                if route_path.is_file():
                    carry_route_from = route_path
                else:
                    carry_route_handoff = args.results / task / "route/trajectory.jsonl"
            elif retry_reason == "carry_route_handoff":
                carry_route_handoff = args.results / task / "route/trajectory.jsonl"
            child = launch(task, Path(child_state["source_sample"]) if task in shared_recovery_tasks
                           and child_state.get("source_sample") else args.sample,
                           worker_results, args.max_turns,
                           args.timeout, resume_harbor=resume_harbor,
                           published_root=args.published_root,
                           review_turns=args.review_turns, review_timeout=args.review_timeout,
                           verify_timeout=args.verify_timeout,
                           review_delivery=retry_reason in {"review_incomplete", "carry_review"},
                           continue_synthesis=carry_continue,
                           workspace_from=carry_workspace_from,
                           route_from=carry_route_from,
                           route_handoff=carry_route_handoff,
                           concurrency=args.concurrency)
            active[task] = child
            if child_state.get("pid") is None:
                state.setdefault("initial_launches", {})[task] = {
                    "batch": batch_number, "started_at": timestamp()}
            child_state.update(pid=child.pid, worker_results=str(worker_results),
                               external_worker=False, route_reused=route_file.is_file(),
                               launched_at=timestamp(), last_status=None,
                               delivery_launched=retry_reason in {"delivery_contract_repair",
                                                                  "delivery_review_repair"},
                               harbor_launched=retry_reason in {"harbor_infrastructure",
                                                                "review_infrastructure"},
                               review_launched=retry_reason == "review_incomplete",
                               bounded_recovery_launched=(child_state.get("bounded_recovery_launched") is True
                                                          or retry_reason == "bounded_recovery"))
            completed.add(task)
            state["scheduled"] = sorted(completed)
            atomic_json(state_path, state)
            print(f"scheduled {task}: pid={child.pid}, active={len(active)}", flush=True)
        statuses = {}
        for path in args.results.glob("*/result.json"):
            record = load(path, {})
            task = path.parent.name
            external_record = load(Path(children.get(task, {}).get("worker_results", args.results)) / task / "result.json", {})
            status = external_record.get("status", record.get("status", "unknown"))
            statuses[status] = statuses.get(status, 0) + 1
        batch_positions = {task: index for index, task in enumerate(
            row["task_id"] for row in read_jsonl(args.sample / "selection.jsonl"))}
        snapshot = {"updated_at": timestamp(), "complete_inputs": len(selected),
                    "active": sorted(active), "external_active": sorted(external),
                    "batch": {"number": batch_number, "members": sorted(
                        accountable_ids or [], key=lambda task: (batch_positions.get(task, len(batch_positions)), task)),
                              "observed_only": sorted(observed_ids)},
                    "worker_count": len(active) + external_running, "counts": statuses,
                    "turns": {task: latest_turn(Path(children.get(task, {}).get("worker_results", args.results)) / task / "synthesis/trajectory.jsonl")
                              for task in set(active) | external}}
        atomic_json(args.results / "progress.json", snapshot)
        print(json.dumps(snapshot, ensure_ascii=False), flush=True)
        state["updated_at"] = timestamp()
        atomic_json(state_path, state)
        if args.once:
            write_display_index(args.results)
            controller_lock.close()
            return 0
        routing = bool(args.from_pilot and any(
            load(args.from_pilot / row["task_id"] / "result.json", {}).get("status") == "routing"
            for row in selected))
        if not active and not routing and not external and not candidates:
            write_display_index(args.results)
            controller_lock.close()
            return 0
        time.sleep(60)


if __name__ == "__main__":
    raise SystemExit(main())
