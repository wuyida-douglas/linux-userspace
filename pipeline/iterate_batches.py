#!/usr/bin/env python3
"""Coordinate disjoint fresh batches and explicitly admitted bounded repairs.

This controller never kills, renumbers or relaunches a live task. A pipeline
failure blocks the next batch until a code-fix review is recorded and tests
pass. Unsuitable routes, review rejections and genuine oracle failures are
terminal task outcomes, not extra model votes.
"""
from __future__ import annotations

import argparse
import fcntl
import json
import os
import subprocess
import sys
import time
from pathlib import Path

from .common import read_jsonl, timestamp
from .supervise import atomic_json, load, strictly_accepted

TERMINAL = {"passed", "failed", "rejected", "error"}
INFRASTRUCTURE_DIFFERENTIAL = {"error", "infra_error"}


def load_result(root: Path, task: str) -> dict:
    return load(root / task / "result.json", {})


def recovery_instance(source: Path, task: str) -> str:
    """Preserve identity when a failed worker never reached its result write."""
    instance = load(source / "result.json", {}).get("instance_id")
    if not instance:
        instance = load(source / "workspace/route.json", {}).get("instance_id")
    if not isinstance(instance, str) or not instance:
        raise RuntimeError(f"recovery source lacks a verifiable instance identity: {task}")
    return instance


def classify(task: str, row: dict, root: Path) -> dict:
    status, failure = row.get("status", "missing"), row.get("failure_class")
    category, recovery, blocked = "terminal_failure", None, None
    error = str(row.get("error", ""))
    differential = (row.get("harbor") or {}).get("differential_from_final_bundle") or {}
    report = differential.get("report") or {}
    infra_differential = (differential.get("status") in INFRASTRUCTURE_DIFFERENTIAL
                          or report.get("status") == "infra_error")
    # FILE-EXPLOIT permits its patched reference to return 1. The previous
    # verifier aborted before the fixed target oracle; this is a contract bug,
    # not a null/oracle success and not a genuine task rejection.
    if (report.get("status") == "infra_error"
            and (report.get("vulnerable") or {}).get("oracle", {}).get("returncode") == 0
            and (report.get("fixed") or {}).get("error_stage") == "submission"
            and (report.get("fixed") or {}).get("submission_result", {}).get("returncode") == 1
            and (root / task / "workspace/delivery/task.json").is_file()
            and load(root / task / "workspace/delivery/task.json", {}).get("branch") == "FILE-EXPLOIT"):
        failure = "harbor_infrastructure"
        infra_differential = True
    if strictly_accepted(row):
        category = "strict_harbor_acceptance"
    elif failure == "not_suitable":
        category = "genuine_routing_rejection"
    elif failure in {"review_rejected", "harbor_failed"} and not infra_differential:
        category = "delivery_or_oracle_failure"
    elif failure in {"pipeline", "route_decision_missing", "synthesis_incomplete"} or infra_differential:
        if not (root / task / "workspace/route.json").is_file() and failure not in {
                "pipeline", "route_decision_missing"}:
            category = "pipeline_fix_required"
        else:
            category = "pipeline_recovery_candidate"
            if failure == "synthesis_incomplete" or (
                    load(root / task / "synthesis/result.json", {}).get("status") == "max_turns"
                    and not (root / task / "workspace/delivery/task.json").is_file()):
                # A partially written delivery is not an independently reviewed
                # artifact. Resume the bounded synthesis budget rather than
                # requesting a Harbor resume that lacks an approved review.
                recovery = "synthesis_interrupted"
            elif infra_differential:
                recovery = "harbor_infrastructure"
            elif "routing agent did not complete: max_turns" in error:
                recovery = "route_budget"
            elif failure == "route_decision_missing":
                recovery = "route_schema_retry"
            elif (root / task / "workspace/delivery").is_dir():
                recovery = "review_incomplete"
            else:
                recovery = "route_infrastructure"
            blocked = recovery_budget_blocked(root, task, recovery) if recovery else None
            if blocked:
                category, recovery = "terminal_failure", None
    return {"task_id": task, "status": status, "failure_class": failure,
            "classification": category, "strictly_accepted": strictly_accepted(row),
            "recovery_reason": recovery, "retry_blocked": blocked if category == "terminal_failure" else None,
            "error": row.get("error")}


def recovery_budget_blocked(root: Path, task: str, recovery: str) -> str | None:
    """Return the durable, already-consumed budget for this recovery mode.

    Budget receipts live in the adopted result tree; immutable carry sources
    cannot revoke a retry that has actually been launched by a supervisor.
    """
    try:
        state = json.loads((root / "supervisor-state.json").read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError):
        # A single-task launcher can transiently write this state with the
        # older non-atomic writer. Only the durable launch receipt can block
        # the next batch; absence of a state file proves no consumed budget.
        return None
    child = state.get("children", {}).get(task, {})
    if recovery == "synthesis_interrupted" and child.get("bounded_recovery_launched") is True:
        return "bounded_recovery_already_launched"
    if recovery == "harbor_infrastructure" and (
            child.get("harbor_retry_count", 0) >= 1
            or child.get("gold_protocol_retry_count", 0) >= 1):
        return "harbor_retry_already_launched"
    if recovery == "review_incomplete" and (
            child.get("review_attempt_completed") is True
            or child.get("review_launched") is True
            or child.get("retry_blocked") == "review_attempt_completed"):
        return "review_attempt_completed"
    if recovery == "route_budget" and child.get("route_budget_recovery_count", 0) >= 1:
        return "route_budget_already_launched"
    if recovery in {"route_schema_retry", "route_infrastructure"} and (
            child.get("retry_reason") in {"route_schema_retry", "route_infrastructure"}
            and child.get("retry_count", 0) >= 1):
        return "route_retry_already_launched"
    return None


def regression_gate(root: Path, log_path: Path) -> None:
    with log_path.open("a", encoding="utf-8") as log:
        log.write(f"\n[{timestamp()}] regression gate before next batch\n")
        log.flush()
        result = subprocess.run([sys.executable, "-m", "unittest", "discover", "-s", "tests", "-v"],
                                cwd=root, stdout=log, stderr=subprocess.STDOUT)
    if result.returncode:
        raise RuntimeError("regression gate failed; no new batch was launched")


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--sample", type=Path, required=True)
    parser.add_argument("--output", type=Path, required=True)
    parser.add_argument("--initial-results", type=Path, required=True)
    parser.add_argument("--initial-supervisor-pid", type=int, required=True)
    parser.add_argument("--initial-only", nargs="+", required=True)
    parser.add_argument("--initial-carried-root", type=Path)
    parser.add_argument("--initial-carried", nargs="*", default=[])
    parser.add_argument("--batch-size", type=int, default=30)
    parser.add_argument("--concurrency", type=int, default=30)
    parser.add_argument("--max-turns", type=int, default=300)
    parser.add_argument("--review-turns", type=int, default=100)
    parser.add_argument("--review-timeout", type=int, default=3600)
    parser.add_argument("--verify-timeout", type=int, default=1800)
    parser.add_argument("--poll-seconds", type=int, default=60)
    args = parser.parse_args()
    if not 1 <= args.batch_size <= args.concurrency <= 30:
        parser.error("require 1 <= batch-size <= concurrency <= 30")
    root = Path(__file__).resolve().parents[1]
    sample, output = args.sample.resolve(), args.output.resolve()
    output.mkdir(parents=True, exist_ok=True)
    controller = (output / ".iteration.lock").open("a+")
    try:
        fcntl.flock(controller, fcntl.LOCK_EX | fcntl.LOCK_NB)
    except BlockingIOError:
        parser.error("another coordinator owns this output directory")
    state_path = output / "iteration-state.json"
    state = load(state_path, {"schema_version": 1, "batches": [], "attempted_fresh": []})
    number = len(state["batches"]) + 1
    log_path = output / "coordinator.log"
    while len(state["attempted_fresh"]) < 200:
        if number == 1:
            results = args.initial_results.resolve()
            fresh = args.initial_only
            carried = {task: (args.initial_carried_root / task) for task in args.initial_carried}
            process = None
            last_stable_state = None
            while True:
                progress = load(results / "progress.json", {})
                counts = progress.get("counts") or {}
                workers = int(progress.get("worker_count", 0))
                in_flight = sum(counts.get(key, 0) for key in ("routing", "synthesizing", "reviewing", "harbor"))
                active_processes = subprocess.run(["ps", "-eo", "args="], capture_output=True,
                                                  text=True, check=True).stdout
                worker_active = any("pipeline.run" in line and str(results) in line
                                    and "ps -eo" not in line for line in active_processes.splitlines())
                if workers > 0 or in_flight > 0 or worker_active:
                    last_stable_state = None
                else:
                    if last_stable_state is None:
                        last_stable_state = time.monotonic()
                    if time.monotonic() - last_stable_state >= args.poll_seconds:
                        break
                state.update(active_batch=number, waiting_for="initial_supervisor_and_terminal_results",
                             updated_at=timestamp())
                atomic_json(state_path, state)
                time.sleep(args.poll_seconds)
        else:
            selected = list(read_jsonl(sample / "completed-selection.jsonl"))
            canonical = list(read_jsonl(sample / "selection.jsonl"))
            if [row["task_id"] for row in selected] != [row["task_id"] for row in canonical]:
                raise RuntimeError("completed-selection.jsonl must preserve selection.jsonl order")
            if len(selected) != 200 or len({row["instance_id"] for row in selected}) != 200:
                raise RuntimeError("wait for 200 unique complete frozen inputs before drawing the next batch")
            for row in selected:
                if load(sample / "tasks" / row["task_id"] / "input/manifest.json", {}).get("status") != "complete":
                    raise RuntimeError(f"frozen input is incomplete: {row['task_id']}")
            previous = load(output / f"batch-{number - 1:03d}-audit.json", {})
            if not previous.get("code_fix_review", {}).get("approved"):
                state.update(active_batch=number, waiting_for="code_fix_review", updated_at=timestamp())
                atomic_json(state_path, state)
                time.sleep(args.poll_seconds)
                continue
            consumed = set(state["attempted_fresh"])
            fresh = [row["task_id"] for row in selected if row["task_id"] not in consumed][:args.batch_size]
            if not fresh:
                break
            carried = {task: Path(source) for task, source in previous.get("carry_sources", {}).items()}
            for task, source in carried.items():
                plan = previous.get("recovery_plans", {}).get(task)
                if not plan:
                    raise RuntimeError(f"carry requires an audited recovery plan: {task}")
                source_instance = recovery_instance(source, task)
                if plan.get("task_id") != task or plan.get("instance_id") != source_instance:
                    raise RuntimeError(f"recovery plan identity mismatch: {task}")
            results = output / f"batch-{number:03d}"
            # Persist the exact selection before launch. The frozen sample and
            # this receipt, not a later global draw, identify this batch.
            frozen_selection = results / "batch-selection.json"
            if frozen_selection.is_file():
                receipt = load(frozen_selection, {})
                if not receipt.get("fresh") or receipt.get("batch") != number:
                    raise RuntimeError(f"batch {number} has no valid frozen selection")
                fresh = list(receipt["fresh"])
                carried = {task: Path(source) for task, source in previous.get("carry_sources", {}).items()
                           if task in set(receipt.get("carried", []))}
            else:
                if results.exists():
                    raise RuntimeError(f"refusing to draw a new selection over an existing batch: {results}")
                results.mkdir(parents=True, exist_ok=True)
                atomic_json(frozen_selection, {"schema_version": 1, "batch": number,
                                              "fresh": fresh, "carried": sorted(carried)})
            regression_gate(root, log_path)
            command = [sys.executable, "-m", "pipeline.supervise", "--sample", str(sample),
                       "--results", str(results), "--concurrency", str(args.concurrency),
                       "--batch-size", str(args.batch_size), "--max-turns", str(args.max_turns),
                       "--review-turns", str(args.review_turns), "--review-timeout", str(args.review_timeout),
                       "--verify-timeout", str(args.verify_timeout),
                       "--batch-selection", str(frozen_selection),
                       "--batch-number", str(number)]
            if carried:
                command += ["--carry-results", *map(str, carried.values())]
                # Each copied task must own the audited plan that admits it;
                # a source route alone is not a license to resume a failure.
                for task in carried:
                    destination = results / task
                    if (destination / "carry-provenance.json").is_file():
                        atomic_json(destination / "carry-recovery.json",
                                    previous["recovery_plans"][task])
            command += ["--only", *fresh, *carried, *receipt.get("observed_only", [])]
            with log_path.open("a", encoding="utf-8") as log:
                log.write(f"\n[{timestamp()}] launch batch={number}: {command!r}\n")
                log.flush()
                process = subprocess.Popen(command, cwd=root, stdout=log,
                                           stderr=subprocess.STDOUT, start_new_session=True)
            state.update(active_batch=number, waiting_for="supervisor", supervisor_pid=process.pid,
                         updated_at=timestamp())
            atomic_json(state_path, state)
            code = process.wait()
            if code:
                raise RuntimeError(f"batch {number} supervisor exited {code}; inspect before any retry")
        # Recovery sources are explicit and immutable. Copying happens in the
        # next batch's carry_workspaces, never into the completed batch.
        # An adopted task can also share a task_id with an immutable source.
        # Keep one attribution entry, with its source provenance, rather than
        # counting the same accepted delivery as both fresh and carried work.
        tasks_by_id = {task: classify(task, load_result(results, task), results) for task in fresh}
        for task, source in carried.items():
            # An adopted recovery's current result, not the immutable source
            # verdict, determines whether it may consume another retry. The
            # source trajectory and result remain available for attribution.
            current_root = results if (results / task / "result.json").is_file() else source
            current = classify(task, load_result(current_root, task), current_root)
            if current_root == results and current["classification"] == "pipeline_recovery_candidate":
                # A root result may have been merged from an adopted source
                # while its supervisor state still names that source. Consult
                # that tree only for the budget receipt, never for the verdict.
                child = load(results / "supervisor-state.json", {}).get("children", {}).get(task, {})
                recovery_root = child.get("worker_results")
                if recovery_root and Path(recovery_root).resolve() != results.resolve():
                    blocked = recovery_budget_blocked(Path(recovery_root), task, current["recovery_reason"])
                    if blocked:
                        current.update(classification="terminal_failure", recovery_reason=None,
                                       retry_blocked=blocked)
            tasks_by_id[task] = current | {
                "carried": True,
                "result_source": str(current_root / task),
                "original_failure_class": load_result(source, task).get("failure_class"),
            }
        tasks = list(tasks_by_id.values())
        carry_sources = {task["task_id"]: str(carried[task["task_id"]]) if task.get("carried")
                         else str(results / task["task_id"])
                         for task in tasks if task["classification"] == "pipeline_recovery_candidate"}
        recovery_plans = {}
        for task in tasks:
            if task["task_id"] not in carry_sources:
                continue
            reason = task["recovery_reason"]
            mode = {"route_budget": "route_handoff", "route_schema_retry": "route",
                    "route_infrastructure": "route", "synthesis_interrupted": "synthesis",
                    "review_incomplete": "review", "harbor_infrastructure": "harbor"}[reason]
            plan = {"schema_version": 1, "task_id": task["task_id"],
                    "instance_id": recovery_instance(Path(carry_sources[task["task_id"]]), task["task_id"]),
                    "mode": mode, "reason": reason}
            if mode == "route_handoff":
                trajectory = Path(carry_sources[task["task_id"]]) / "route/trajectory.jsonl"
                if not trajectory.is_file():
                    raise RuntimeError(f"missing route handoff evidence: {task['task_id']}")
                plan["trajectory"] = "route/trajectory.jsonl"
            recovery_plans[task["task_id"]] = plan
        audit = {"schema_version": 1, "batch": number, "fresh": fresh, "carried": sorted(carried),
                 "audited_at": timestamp(), "tasks": tasks, "carry_sources": carry_sources,
                 "recovery_plans": recovery_plans,
                 "code_fix_review": {"approved": False,
                                     "required": "inspect trajectories, correct code and set approved=true after review"}}
        atomic_json(output / f"batch-{number:03d}-audit.json", audit)
        # Carried recoveries consume slots, not the distinct fresh-task quota.
        # This also corrects the legacy first-batch overlap where two adopted
        # task IDs had been inserted into the initial fresh allowlist.
        state["attempted_fresh"] = sorted((set(state["attempted_fresh"]) | set(fresh))
                                          - set(carried))
        state["batches"].append(number)
        state.update(active_batch=None, waiting_for=None, updated_at=timestamp())
        atomic_json(state_path, state)
        if not all(task["status"] in TERMINAL for task in tasks):
            raise RuntimeError(f"batch {number} has nonterminal results; inspect before any retry")
        number += 1
    controller.close()
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
