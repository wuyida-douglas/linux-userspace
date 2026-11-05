#!/usr/bin/env python3
"""Bounded, resumable scheduling and monitoring for routed synthesis batches.

Routing and synthesis each occupy a worker. Existing processes are never
killed, renumbered, or silently rerun. Harbor exports remain serialized by
run.py's Docker lock so acceptance does not contend with factory builds.
"""
from __future__ import annotations

import argparse
import concurrent.futures
import json
import os
import shlex
import shutil
import subprocess
import threading
import time
from pathlib import Path

from .common import ROOT, inventory, load_env, read_jsonl, timestamp, write_json
from .run import route as validate_route


def atomic_json(path: Path, value: dict) -> None:
    temporary = path.with_name(path.name + f".{os.getpid()}.{threading.get_ident()}.tmp")
    write_json(temporary, value)
    os.replace(temporary, path)


def load(path: Path, default):
    try:
        return json.loads(path.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError):
        return default


def strictly_accepted(record: dict) -> bool:
    harbor = record.get("harbor") or {}
    differential = harbor.get("differential_from_final_bundle") or {}
    return (record.get("status") == "passed"
            and (record.get("review") or {}).get("passed") is True
            and (harbor.get("gold") or {}).get("reward") == 1.0
            and (harbor.get("null") or {}).get("reward") == 0.0
            and differential.get("status") == "passed"
            and (differential.get("report") or {}).get("success") is True)


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


def launch(task: str, sample: Path, results: Path, route: Path | None,
           turns: int, timeout: int, continue_synthesis: bool = False,
           resume_harbor: bool = False, route_handoff: Path | None = None) -> subprocess.Popen:
    command = ["python3", "-m", "pipeline.run", "--sample", str(sample),
               "--results", str(results), "--only", task, "--concurrency", "20",
               "--max-turns", str(turns), "--route-turns", "45",
               "--timeout", str(timeout)]
    if resume_harbor:
        command.append("--resume")
    elif continue_synthesis:
        command.append("--continue-synthesis")
    elif route_handoff is not None:
        command += ["--route-handoff-from", str(route_handoff)]
    elif route is not None:
        command += ["--route-from", str(route)]
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
    parser.add_argument("--max-turns", type=int, default=300)
    parser.add_argument("--timeout", type=int, default=18000)
    parser.add_argument("--route-only", action="store_true")
    parser.add_argument("--from-pilot", type=Path)
    parser.add_argument("--recovery-results", type=Path,
                        help="another live result directory whose workers count toward the shared limit")
    parser.add_argument("--only", nargs="*")
    parser.add_argument("--once", action="store_true", help="schedule available work and return")
    args = parser.parse_args()
    if not 1 <= args.concurrency <= 20:
        parser.error("concurrency must be 1..20")
    args.results.mkdir(parents=True, exist_ok=True)
    state_path = args.results / "supervisor-state.json"
    state = load(state_path, {"schema_version": 1, "children": {}})
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
    shared_roots = {path.resolve() for path in shared_roots}
    children = state.setdefault("children", {})
    completed = set(state.get("scheduled", []))
    # A supervisor is disposable; workers are not. Reconcile all command lines
    # before scheduling so a restart never creates duplicate model sessions.
    process_rows = subprocess.run(["ps", "-eo", "pid=,comm=,args="], capture_output=True,
                                  text=True, check=True).stdout.splitlines()
    for line in process_rows:
        fields = line.strip().split(None, 2)
        # A shell containing the supervisor's launch text is not a Python
        # worker. Match the executable, not an arbitrary command substring.
        if len(fields) != 3 or fields[1] != "python3":
            continue
        try:
            command = shlex.split(fields[2])
            if command[:3] != ["python3", "-m", "pipeline.run"]:
                continue
            if command[command.index("--sample") + 1] != str(args.sample):
                continue
            result_dir = Path(command[command.index("--results") + 1])
            task = command[command.index("--only") + 1]
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
        if pid and Path(f"/proc/{pid}").exists():
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
            if result.get("status") in {"passed", "failed", "rejected", "error"}:
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
                if pid and Path(f"/proc/{pid}").exists():
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
        # A finished recovery workspace supersedes the original interrupted
        # workspace. Merge the authoritative delivery/result exactly once so
        # shared scheduling can re-review or resume its final acceptance.
        if args.recovery_results is not None:
            for recovery in args.recovery_results.glob("*/result.json"):
                task = recovery.parent.name
                result = load(recovery, {})
                child = children.get(task, {})
                pid = child.get("pid")
                if (result.get("status") not in {"passed", "failed", "error", "rejected"}
                        or (pid and Path(f"/proc/{pid}").exists())):
                    continue
                destination = args.results / task
                destination.mkdir(parents=True, exist_ok=True)
                if child.get("recovery_merged") or child.get("manual_correction"):
                    continue
                if (destination / "workspace/delivery").exists():
                    # Production is authoritative after the first merge. Do
                    # not overwrite its repaired delivery or retry counters.
                    child["recovery_merged"] = True
                    children[task] = child
                    external.discard(task)
                    atomic_json(state_path, state)
                    continue
                destination.joinpath("workspace").mkdir(exist_ok=True)
                shutil.copytree(recovery.parent / "workspace/delivery", destination / "workspace/delivery")
                for name in ("route.json", "review.json", "NETWORK.md"):
                    source = recovery.parent / "workspace" / name
                    if source.is_file():
                        shutil.copyfile(source, destination / "workspace" / name)
                atomic_json(destination / "result.json", result)
                child.update(recovery_merged=True, last_status=result.get("status"), retry_count=0)
                children[task] = child
                external.discard(task)
                completed.discard(task)
                state["scheduled"] = sorted(completed)
                atomic_json(state_path, state)
        selected = list(read_jsonl(args.sample / "selection.jsonl"))
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
        # Reconcile every live worker every minute, not just at supervisor
        # startup. Manually recovered and once-mode workers are adopted here.
        process_rows = subprocess.run(["ps", "-eo", "pid=,ppid=,comm=,args="], capture_output=True,
                                      text=True, check=True).stdout.splitlines()
        seen_pids = set()
        for line in process_rows:
            fields = line.strip().split(None, 2)
            if len(fields) != 4 or fields[2] != "python3":
                continue
            try:
                command = shlex.split(fields[3])
                if command[:3] != ["python3", "-m", "pipeline.run"]:
                    continue
                if command[command.index("--sample") + 1] != str(args.sample):
                    continue
                task = command[command.index("--only") + 1]
                result_dir = Path(command[command.index("--results") + 1])
                if result_dir.resolve() not in shared_roots or task not in {row["task_id"] for row in selected}:
                    continue
                pid = int(fields[0])
                child = children.setdefault(task, {})
                # Keep the first observed worker as this task's sole owner.
                # A terminal wrapper may have several Python descendants; their
                # command lines must not cause ownership to change mid-cycle.
                if child.get("pid") and Path(f"/proc/{child['pid']}").exists():
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
            if not pid or pid in seen_pids or Path(f"/proc/{pid}").exists():
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
        for row in selected:
            task = row["task_id"]
            child = children.get(task, {})
            if task in active or (task in external
                                  and child.get("pid")
                                  and Path(f"/proc/{child['pid']}").exists()):
                # Live process identity is authoritative, including sessions
                # inherited from manual recovery or a previous supervisor.
                continue
            # `completed` also records historical attempts. A terminal record
            # may still be eligible for its single bounded infrastructure or
            # schema retry; the record checks below make other finals terminal.
            record = load(args.results / task / "result.json", {})
            child = children.get(task, {})
            if (record.get("status") == "error"
                    and any(token in str(record.get("error", ""))
                            for token in ("route/tool-logs", "name 'route' is not defined"))
                    and not child.get("pipeline_repair_pending")
                    and not (child.get("pid") and Path(f"/proc/{child['pid']}").exists())
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
                    and not (child.get("pid") and Path(f"/proc/{child['pid']}").exists())):
                # No routing verdict was ever produced. Remove only this
                # contradictory migration marker; all other state is intact.
                child.pop("retry_reason", None)
            if strictly_accepted(record):
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
            if child.get("manual_correction"):
                pid = child.get("pid")
                if pid and Path(f"/proc/{pid}").exists():
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
                    and child.get("pid") and Path(f"/proc/{child['pid']}").exists() \
                    and "continue-synthesis needs" not in str(record.get("error", "")):
                # The resume worker is already scheduled but may not yet have
                # flushed its status; never enqueue a duplicate terminal retry.
                completed.add(task)
                continue
            route_file = args.results / task / "workspace/route.json"
            # A budget-limited route or interrupted synthesis is not evidence
            # that the vulnerability is unsuitable. Retry each such attempt
            # once, preserving the interrupted trajectory and all source files.
            # Real rejected/failed/Harbor verdicts are never silently retried.
            retry_reason = None
            # Preserve reviewed deliveries when final acceptance is blocked by
            # factory infrastructure, not by an exploit/fixed differential.
            # One bounded retry reuses a real gold=1 result and always reruns
            # null plus the frozen private verifier. Never retry a genuine
            # wrong reward, rejected review, or false private differential.
            harbor = record.get("harbor") or {}
            differential = harbor.get("differential_from_final_bundle") or {}
            synthesis = load(args.results / task / "synthesis/result.json", {})
            delivery_contract = ((record.get("status") == "error"
                                  and str(record.get("error", "")).startswith("ValueError: missing delivery/"))
                                 or (differential.get("status") == "error"
                                     and str(differential.get("error", "")).startswith("ValueError: report.")))
            review_rejected = (record.get("status") == "failed"
                               and record.get("failure_class") == "review_rejected")
            review_findings = record.get("review") if review_rejected else None
            if review_rejected and not isinstance(review_findings.get("passed"), bool):
                review_findings = load(args.results / task / "workspace/review.json", {})
            if review_rejected and not isinstance(review_findings.get("passed"), bool):
                children[task]["retry_blocked"] = "missing_original_review_verdict"
                completed.add(task)
                continue
            if ((delivery_contract or review_rejected) and synthesis.get("status") == "completed"
                    and route_file.is_file() and child.get("delivery_retry_count", 0) < 1):
                # A malformed or oracle-spoofable delivery needs one concrete
                # repair session, not silent acceptance or another model vote.
                retry_reason = ("delivery_review_repair" if review_rejected
                                else "delivery_contract_repair")
            infrastructure_failure = (record.get("status") == "failed" and
                                      (harbor.get("gold") or {}).get("reward") == 1.0 and
                                      (harbor.get("null") or {}).get("reward") == 0.0 and
                                      differential.get("status") == "error")
            if infrastructure_failure and child.get("harbor_retry_count", 0) < 1:
                retry_reason = "harbor_infrastructure"
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
                else:
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
                    and not (child.get("pid") and Path(f"/proc/{child['pid']}").exists())
                    and child.get("route_budget_recovery_count", 0) < 1):
                # A later exhausted route has still not decided suitability.
                # It receives a separate evidence-preserving recovery budget,
                # without erasing the prior bounded-retry history.
                retry_reason = "route_budget"
            if child.get("retry_count", 0) < 1 and retry_reason is None:
                if (record.get("status") in {"synthesizing", "error"}
                        and route_file.exists()
                        and not (args.results / task / "workspace/review.json").exists()
                        and (child.get("reset_eligible")
                             or child.get("retry_reason") == "completed_route_recovery"
                             or load(args.results / task / "synthesis/result.json", {}).get("status")
                             in {"running", "max_turns", "timeout", "api_error"})):
                    retry_reason = "synthesis_interrupted"
            # A submit_route callback crash can leave a valid decision but a
            # still-running top-level status. Validate and resume that exact
            # decision, rather than spending another route budget on it.
            if (record.get("status") == "error"
                    and "continue-synthesis needs" in str(record.get("error", ""))
                    and route_file.is_file() and not child.get("input_restoration_retry")):
                # The old continuation path could remove the immutable input
                # before checking it. The repaired worker restores that input.
                children[task].update(retry_count=1, retry_reason="input_restoration",
                                      previous_status=record.get("status"),
                                      input_restoration_retry=True)
                candidates.append((task, route_file, True))
                continue
            if (record.get("status") == "routing" and not route_file.is_file()
                    and not (child.get("pid") and Path(f"/proc/{child['pid']}").exists())):
                # A nonterminal route has no accept/reject verdict to retry.
                # Regardless of a stale migration marker, it remains work.
                children[task].update(retry_count=1, retry_reason="unfinished_route_recovery")
                candidates.append((task, None, False))
                continue
            if (retry_reason is None and record.get("status") in {"routing", "error"}
                    and not route_file.is_file() and child.get("retry_count", 0) < 1):
                child.pop("retry_reason", None)
                completed.discard(task)
            if (retry_reason is None and record.get("status") == "harbor"
                    and (args.results / task / "workspace/delivery").is_dir()
                    and not (child.get("pid") and Path(f"/proc/{child['pid']}").exists())):
                # The delivery and independent review remain frozen. Retry
                # only final acceptance after a fixed exporter/runtime error.
                retry_reason = "review_infrastructure"
            if (retry_reason is None and record.get("status") in {"routing", "error"}
                    and route_file.is_file()):
                try:
                    task_record = load(args.sample / "tasks" / task / "input/meta.json", {})
                    validate_route(args.results / task / "workspace", task_record["instance_id"])
                    children[task]["retry_reason"] = "completed_route_recovery"
                    candidates.append((task, route_file, True))
                    continue
                except (OSError, ValueError, KeyError):
                    pass
            if retry_reason:
                evidence = args.results / task / "retry-evidence"
                evidence.mkdir(exist_ok=True)
                # Re-routing replaces its own logs; review/Harbor resume must
                # retain route and synthesis evidence in place.
                if retry_reason in {"route_budget", "route_schema_retry", "route_infrastructure", "synthesis_interrupted"}:
                    for relative in (("route",) if retry_reason != "synthesis_interrupted" else ("synthesis",)):
                        source = args.results / task / relative
                        destination = evidence / relative
                        if source.exists() and not destination.exists():
                            os.rename(source, destination)
                if retry_reason in {"route_budget", "route_schema_retry", "route_infrastructure"}:
                    # Preserve a failed route's original verdict before the
                    # replacement overwrites result.json. An archived max-turn
                    # result must not consume its replacement's only retry.
                    child.pop("pipeline_repair_pending", None)
                    result_evidence = evidence / "result.json"
                    if result_evidence.exists():
                        result_evidence = evidence / ("result-" + retry_reason + ".json")
                    shutil.copy2(args.results / task / "result.json", result_evidence)
                if retry_reason in {"delivery_contract_repair", "delivery_review_repair"}:
                    repair_evidence = evidence / retry_reason
                    if repair_evidence.exists():
                        children[task].update(delivery_retry_count=1, retry_blocked="archive_exists")
                        completed.add(task)
                        continue
                    repair_evidence.mkdir()
                    workspace = args.results / task / "workspace"
                    for name in ("review.json", "review-input"):
                        source = workspace / name
                        if source.exists():
                            if source.is_dir():
                                shutil.copytree(source, repair_evidence / name, symlinks=True)
                            else:
                                shutil.copy2(source, repair_evidence / name)
                    for name in ("review.json",):
                        source = workspace / name
                        if source.exists():
                            source.unlink()
                    for name in ("review", "harbor"):
                        source = args.results / task / name
                        if source.exists():
                            os.rename(source, repair_evidence / name)
                    atomic_json(repair_evidence / "result.json", record)
                    atomic_json(workspace / "repair-request.json", {
                        "schema_version": 1, "reason": retry_reason,
                        "error": record.get("error") or differential.get("error"),
                        "review": review_findings,
                        "requirement": "Fix every blocker/major review finding and the exact contract defect. Rerun private verification and adversarial public-oracle checks. Submit the changed delivery for fresh independent review and full Harbor acceptance. Do not modify report.json after executing verify.sh, suppress the adversarial test, or bypass any differential check.",
                        "created_at": timestamp()})
                    children[task]["delivery_retry_count"] = 1
                children[task].update(retry_count=1, retry_reason=retry_reason,
                                      previous_status=record.get("status"))
                if retry_reason == "review_infrastructure":
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
                candidates.append((task, None, retry_reason in {"synthesis_interrupted", "delivery_contract_repair",
                                                               "delivery_review_repair"}))
                if retry_reason == "route_budget":
                    children[task]["route_handoff"] = str(evidence / "route/trajectory.jsonl")
                    children[task]["route_budget_recovery_count"] = 1
                    children[task]["retry_reason"] = None
                    children[task]["previous_status"] = None
                continue
            if record.get("status") in {"routing", "synthesizing", "reviewing", "harbor", "routed",
                                          "rejected", "passed", "failed", "error"}:
                children.setdefault(task, {"external_or_finished": True,
                                           "last_status": record["status"]})
                completed.add(task)
                continue
            if args.route_only:
                candidates.append((task, None, False))
                continue
            route_path = None
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
                    route_path = route_file.resolve()
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
            candidates.append((task, route_path, False))
        while candidates and len(active) + external_running < args.concurrency:
            task, route, resume_synthesis = candidates.pop(0)
            child_state = children.setdefault(task, {})
            resume_harbor = child_state.get("retry_reason") in {"harbor_infrastructure", "review_infrastructure"}
            handoff = Path(child_state["route_handoff"]) if child_state.get("route_handoff") else None
            child = launch(task, args.sample, args.results, route, args.max_turns,
                           args.timeout, resume_synthesis, resume_harbor=resume_harbor,
                           route_handoff=handoff)
            active[task] = child
            child_state.update(pid=child.pid, route_reused=route is not None,
                               launched_at=timestamp())
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
        snapshot = {"updated_at": timestamp(), "complete_inputs": len(selected),
                    "active": sorted(active), "external_active": sorted(external),
                    "worker_count": len(active) + external_running, "counts": statuses,
                    "turns": {task: latest_turn(Path(children.get(task, {}).get("worker_results", args.results)) / task / "synthesis/trajectory.jsonl")
                              for task in set(active) | external}}
        atomic_json(args.results / "progress.json", snapshot)
        print(json.dumps(snapshot, ensure_ascii=False), flush=True)
        state["updated_at"] = timestamp()
        atomic_json(state_path, state)
        if args.once:
            return 0
        routing = bool(args.from_pilot and any(
            load(args.from_pilot / row["task_id"] / "result.json", {}).get("status") == "routing"
            for row in selected))
        if not active and not routing and not external:
            return 0
        time.sleep(60)


if __name__ == "__main__":
    raise SystemExit(main())
