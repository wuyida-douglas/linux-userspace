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
from .supervise import atomic_json, carry_workspaces, load, strictly_accepted

TERMINAL = {"passed", "failed", "rejected", "error"}
INFRASTRUCTURE_DIFFERENTIAL = {"error", "infra_error"}


def load_result(root: Path, task: str) -> dict:
    return load(root / task / "result.json", {})


def preserve_missing_input_result(root: Path, task: str, row: dict, report: dict) -> dict:
    """Record an immutable sample-position error without dispatching a worker."""
    source = next((entry for entry in report.get("tasks", [])
                   if entry.get("task_id") == task and entry.get("status") == "error"), None)
    if (source is None or load(root / task / "input/manifest.json", {})
            or row.get("status") not in {None, "error"}):
        return row
    result = dict(row)
    if row:
        result["downstream_result_preserved"] = dict(row)
    result.update(task_id=task, instance_id=source["instance_id"], status="error",
                  failure_class="input_unavailable", error=source.get("error"),
                  preserved_sample_position=True)
    return result


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
    elif failure == "harbor_failed" and (row.get("harbor") or {}).get("gold", {}).get("reward") != 1.0:
        # An incomplete gold protocol is a delivery defect, never a license to
        # rerun acceptance with an unchanged contract. The code-fix gate must
        # address the submission/oracle protocol before admitting any repair.
        category = "pipeline_fix_required"
    elif failure in {"review_rejected", "harbor_failed"} and not infra_differential:
        category = "delivery_or_oracle_failure"
    elif failure == "input_unavailable":
        category = "input_unavailable"
    elif failure in {"branch_mismatch", "synthesis_blocked", "synthesis_incomplete",
                     "route_decision_missing"}:
        category = "manual_recovery_required"
    elif failure == "pipeline" and not (root / task / "workspace/route.json").is_file():
        category = "manual_recovery_required"
        missing = load(root / task / "input/manifest.json", {})
        report = load(root.parent / "download-report.json", {})
        preserved_error = any(entry.get("task_id") == task and entry.get("status") == "error"
                              for entry in report.get("tasks", []))
        if preserved_error and (not missing or missing.get("status") != "complete"):
            category = "input_unavailable"
    elif infra_differential and (row.get("review") or {}).get("passed") is True:
        category = "pipeline_recovery_candidate"
        recovery = "harbor_infrastructure"
        blocked = recovery_budget_blocked(root, task, recovery)
        if blocked:
            category, recovery = "terminal_failure", None
    elif failure in {"pipeline", "route_decision_missing", "synthesis_incomplete"}:
        # Preserve model-produced evidence, but never automatically resume an
        # interrupted synthesis or re-route an exhausted task. Only a frozen,
        # reviewed delivery can resume the review/Harbor tail.
        if (root / task / "workspace/delivery").is_dir():
            category = "pipeline_recovery_candidate"
            recovery = "review_incomplete"
            blocked = recovery_budget_blocked(root, task, recovery)
            if blocked:
                category, recovery = "terminal_failure", None
        else:
            category = "manual_recovery_required"
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
    if recovery == "harbor_infrastructure" and (
            child.get("harbor_retry_count", 0) >= 1
            or child.get("gold_protocol_retry_count", 0) >= 1):
        return "harbor_retry_already_launched"
    if recovery == "review_incomplete" and (
            child.get("review_attempt_completed") is True
            or child.get("review_launched") is True
            or child.get("retry_blocked") == "review_attempt_completed"):
        return "review_attempt_completed"
    return None


def adopt_existing_carries(results: Path, carried: dict[str, Path]) -> None:
    """Adopt only a provenance-identical carry; never replace its evidence."""
    for task, source in carried.items():
        destination = results / task
        if not destination.is_dir():
            continue
        provenance = load(destination / "carry-provenance.json", {})
        if (Path(provenance.get("source", "")).resolve() != source.resolve()
                or provenance.get("instance_id") != recovery_instance(source, task)):
            raise RuntimeError(f"existing carry does not match its audited source: {task}")
        if not load(destination / "carry-recovery.json", {}):
            raise RuntimeError(f"existing carry lacks its explicit recovery plan: {task}")
        state_path = results / "supervisor-state.json"
        state = load(state_path, {"schema_version": 1, "children": {}})
        child = state.setdefault("children", {}).setdefault(task, {})
        if child.get("pid") is None and child.get("bounded_recovery_launched") is not True:
            # A live PID is an already-admitted recovery, not a second budget
            # grant. Preserve its original carry receipt during supervisor
            # restarts; never manufacture a new recovery plan for it.
            child.update(carried_recovery=True)
            child.pop("carry_blocked", None)
            atomic_json(state_path, state)


def prepare_carries(results: Path, carried: dict[str, Path], plans: dict[str, dict]) -> None:
    """Complete an interrupted first copy without discarding its audited plan."""
    missing = [task for task in carried if not (results / task / "carry-provenance.json").is_file()]
    if missing:
        carry_workspaces([carried[task] for task in missing], results, set(missing),
                         {task: plans[task] for task in missing})
    adopt_existing_carries(results, carried)


def regression_gate(root: Path, log_path: Path) -> None:
    with log_path.open("a", encoding="utf-8") as log:
        log.write(f"\n[{timestamp()}] regression gate before next batch\n")
        log.flush()
        result = subprocess.run([sys.executable, "-m", "unittest", "discover", "-s", "tests", "-v"],
                                cwd=root, stdout=log, stderr=subprocess.STDOUT)
    if result.returncode:
        raise RuntimeError("regression gate failed; no new batch was launched")


def batch_candidates(sample: Path, target_size: int, preserve_unavailable_inputs: bool) -> list[dict]:
    """Keep legacy sample positions, but require all 200 disjoint inputs by default."""
    canonical = list(read_jsonl(sample / "selection.jsonl"))
    if preserve_unavailable_inputs:
        selected = canonical
        unavailable = {
            entry.get("task_id") for entry in load(sample / "download-report.json", {}).get("tasks", [])
            if entry.get("status") == "error"
        }
        for row in selected:
            complete = load(sample / "tasks" / row["task_id"] / "input/manifest.json", {}).get("status") == "complete"
            if not complete and row["task_id"] not in unavailable:
                raise RuntimeError(f"frozen input is incomplete without a preserved error: {row['task_id']}")
    else:
        selected = list(read_jsonl(sample / "completed-selection.jsonl"))
        if [row["task_id"] for row in selected] != [row["task_id"] for row in canonical]:
            raise RuntimeError("completed-selection.jsonl must preserve selection.jsonl order")
    if len(selected) != target_size or len({row["instance_id"] for row in selected}) != target_size:
        raise RuntimeError(f"wait for {target_size} unique frozen inputs before drawing the next batch")
    if not preserve_unavailable_inputs:
        for row in selected:
            if load(sample / "tasks" / row["task_id"] / "input/manifest.json", {}).get("status") != "complete":
                raise RuntimeError(f"frozen input is incomplete: {row['task_id']}")
    return selected


def validate_batch_selection(receipt: dict, number: int, consumed: set[str]) -> None:
    """Reject an overlapping receipt before any worker or carry is launched."""
    fields = ("fresh", "carried", "observed_only")
    groups = [receipt.get(field, []) for field in fields]
    if any(not isinstance(ids, list) or any(not isinstance(task, str) for task in ids)
           for ids in groups):
        raise RuntimeError("invalid frozen selection: task IDs must be string lists")
    ids = [task for group in groups for task in group]
    if len(ids) != len(set(ids)):
        raise RuntimeError("overlapping frozen selection: a task may occupy only one batch role")
    if receipt.get("batch") != number or not groups[0]:
        raise RuntimeError(f"batch {number} has no valid frozen selection")
    if consumed & set(groups[0]):
        raise RuntimeError("overlapping frozen selection: fresh tasks were already attempted")


def initial_attribution(results: Path, receipt: dict, sample: Path,
                        adopted: set[str]) -> dict:
    """Reconcile a legacy receipt without discarding unavailable sample positions."""
    observed = set(receipt.get("observed_only", [])) | set(adopted)
    unavailable = {entry.get("task_id") for entry in
                   load(sample / "download-report.json", {}).get("tasks", [])
                   if entry.get("status") == "error" and entry.get("task_id")}
    observed |= unavailable
    observed |= {task for task in unavailable
                 if load(results / task / "result.json", {})}
    fresh = [task for task in receipt.get("fresh", []) if task not in observed]
    carried = [task for task in receipt.get("carried", []) if task not in observed]
    return {"fresh": fresh, "carried": carried,
            "observed_only": sorted(observed - set(fresh) - set(carried))}


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--sample", type=Path, required=True)
    parser.add_argument("--output", type=Path, required=True)
    parser.add_argument("--initial-results", type=Path, required=True)
    parser.add_argument("--initial-supervisor-pid", type=int, required=True)
    parser.add_argument("--initial-only", nargs="+", required=True)
    parser.add_argument("--initial-observed-only", nargs="*", default=[])
    parser.add_argument("--initial-carried-root", type=Path)
    parser.add_argument("--initial-carried", nargs="*", default=[])
    parser.add_argument("--batch-size", type=int, default=30)
    parser.add_argument("--concurrency", type=int, default=30)
    parser.add_argument("--target-size", type=int, default=200)
    parser.add_argument("--preserve-unavailable-inputs", action="store_true")
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
    durable_batches = {number for number in (
        load(path, {}).get("batch") for path in output.glob("batch-*-audit.json"))
        if isinstance(number, int)}
    state["batches"] = sorted(set(state["batches"]) | durable_batches)
    # An old audit/ledger pair may have regressed to [1]. The durable audit
    # receipts, not the length of that stale list, determine the next batch.
    number = max(state["batches"], default=0) + 1
    log_path = output / "coordinator.log"
    live_adoption = None
    if args.initial_supervisor_pid and state.get("active_batch", 0) > 1:
        number = int(state["active_batch"])
        candidate = output / f"batch-{number:03d}"
        try:
            cmdline = (Path("/proc") / str(args.initial_supervisor_pid) / "cmdline").read_bytes().split(b"\0")
            args_text = [part.decode(errors="replace") for part in cmdline if part]
            if "pipeline.supervise" in args_text and "--results" in args_text:
                supplied_results = Path(args_text[args_text.index("--results") + 1])
                if supplied_results.resolve() == candidate.resolve():
                    live_adoption = args.initial_supervisor_pid
        except (FileNotFoundError, ProcessLookupError):
            pass
    while len(state["attempted_fresh"]) < args.target_size:
        if number in state["batches"] and (output / f"batch-{number:03d}-audit.json").is_file():
            # A recovered coordinator must never relaunch an already audited
            # batch, even if its old state still names a dead supervisor PID.
            number += 1
            continue
        if live_adoption is not None:
            results = output / f"batch-{number:03d}"
            regression_gate(root, log_path)
            with log_path.open("a", encoding="utf-8") as log:
                log.write(f"[{timestamp()}] adopt live batch={number} supervisor={live_adoption}\n")
            while True:
                try:
                    os.kill(live_adoption, 0)
                except ProcessLookupError:
                    break
                progress = load(results / "progress.json", {})
                counts = progress.get("counts") or {}
                in_flight = sum(counts.get(key, 0) for key in ("routing", "synthesizing", "reviewing", "harbor"))
                if not progress.get("worker_count") and not in_flight:
                    break
                state.update(active_batch=number, waiting_for="supervisor",
                             supervisor_pid=live_adoption, updated_at=timestamp())
                atomic_json(state_path, state)
                time.sleep(args.poll_seconds)
            live_adoption = None
            continue
        process = None
        if number == 1:
            results = args.initial_results.resolve()
            fresh = args.initial_only
            initial_observed = set(args.initial_observed_only)
            frozen_initial = load(results / "batch-selection.json", {})
            frozen_scope = set(frozen_initial.get("fresh", [])) | set(frozen_initial.get("carried", []))
            frozen_observed = set(frozen_initial.get("observed_only", []))
            migrated_observed = set(load(results / "supervisor-state.json", {})
                                    .get("selection_migration", {}).get("previous_selected_ids", []))
            adopted = frozen_scope | frozen_observed | migrated_observed
            if set(fresh) & initial_observed or not initial_observed <= adopted:
                raise ValueError("initial observed-only tasks must be disjoint, already attempted positions")
            if args.preserve_unavailable_inputs and not (output / "download-report.json").is_file():
                (output / "download-report.json").write_bytes((sample / "download-report.json").read_bytes())
            attribution = initial_attribution(results, frozen_initial | {
                "fresh": list(fresh), "observed_only": sorted(initial_observed)}, sample, adopted)
            initial_observed.update(attribution["observed_only"])
            fresh = attribution["fresh"]
            carried = {task: results / task for task in sorted(initial_observed)}
            state["observed_only"] = sorted(initial_observed)
            atomic_json(results / "batch-selection.json", frozen_initial | {
                "batch": 1, "fresh": list(fresh), "carried": sorted(initial_observed),
                "observed_only": sorted(initial_observed)})
        else:
            selected = batch_candidates(sample, args.target_size, args.preserve_unavailable_inputs)
            previous = load(output / f"batch-{number - 1:03d}-audit.json", {})
            if not previous.get("code_fix_review", {}).get("approved"):
                state.update(active_batch=number, waiting_for="code_fix_review", updated_at=timestamp())
                atomic_json(state_path, state)
                time.sleep(args.poll_seconds)
                continue
            canonical_ids = {row["task_id"] for row in selected}
            foreign_ids = set(state["attempted_fresh"]) - canonical_ids
            if foreign_ids:
                # Legacy first-batch metadata included two observed old-pool
                # IDs. Keep their evidence, but do not spend this disjoint
                # sample's 200-position quota on them.
                with log_path.open("a", encoding="utf-8") as log:
                    log.write(f"[{timestamp()}] ignore foreign attempted IDs: {sorted(foreign_ids)!r}\n")
                state["attempted_fresh"] = sorted(set(state["attempted_fresh"]) & canonical_ids)
                atomic_json(state_path, state)
            consumed = set(state["attempted_fresh"]) | set(state.get("observed_only", []))
            if number == 2:
                attribution = initial_attribution(args.initial_results,
                    load(args.initial_results / "batch-selection.json", {}), sample,
                    set(load(args.initial_results / "supervisor-state.json", {})
                        .get("selection_migration", {}).get("previous_selected_ids", [])))
                consumed |= set(attribution["observed_only"])
                consumed |= set(attribution["fresh"]) | set(attribution["carried"])
                state["observed_only"] = sorted(consumed)
                atomic_json(state_path, state)
            fresh = [row["task_id"] for row in selected if row["task_id"] not in consumed][:args.batch_size]
            if not fresh:
                break
            carried = {task: Path(source).resolve() for task, source in previous.get("carry_sources", {}).items()}
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
            receipt = {}
            if frozen_selection.is_file():
                receipt = load(frozen_selection, {})
                validate_batch_selection(receipt, number, consumed)
                fresh = list(receipt["fresh"])
                carried = {task: Path(source).resolve() for task, source in previous.get("carry_sources", {}).items()
                           if task in set(receipt.get("carried", []))}
            else:
                if results.exists():
                    raise RuntimeError(f"refusing to draw a new selection over an existing batch: {results}")
                results.mkdir(parents=True, exist_ok=True)
                atomic_json(frozen_selection, {"schema_version": 1, "batch": number,
                                              "fresh": fresh, "carried": sorted(carried)})
            regression_gate(root, log_path)
            existing_pid = state.get("supervisor_pid") if state.get("active_batch") == number else None
            if number != 1 and args.initial_supervisor_pid and results.exists():
                # Recovery may have left a dead duplicate-launch PID in state.
                # Prefer the explicitly supplied live owner, but only when its
                # command identifies this exact results directory.
                try:
                    cmdline = (Path("/proc") / str(args.initial_supervisor_pid) / "cmdline").read_bytes().split(b"\0")
                    args_text = [part.decode(errors="replace") for part in cmdline if part]
                    if ("pipeline.supervise" in args_text
                            and (str(results.resolve()) in args_text or str(results) in args_text)):
                        existing_pid = args.initial_supervisor_pid
                except (FileNotFoundError, ProcessLookupError):
                    pass
            try:
                if existing_pid:
                    os.kill(existing_pid, 0)
            except ProcessLookupError:
                existing_pid = None
            if existing_pid:
                with log_path.open("a", encoding="utf-8") as log:
                    log.write(f"[{timestamp()}] adopt live batch={number} supervisor={existing_pid}\n")
                while True:
                    try:
                        os.kill(existing_pid, 0)
                    except ProcessLookupError:
                        break
                    progress = load(results / "progress.json", {})
                    counts = progress.get("counts") or {}
                    in_flight = sum(counts.get(key, 0) for key in ("routing", "synthesizing", "reviewing", "harbor"))
                    if not progress.get("worker_count") and not in_flight:
                        break
                    state.update(active_batch=number, waiting_for="supervisor",
                                 supervisor_pid=existing_pid, updated_at=timestamp())
                    atomic_json(state_path, state)
                    time.sleep(args.poll_seconds)
                continue
            command = [sys.executable, "-m", "pipeline.supervise", "--sample", str(sample),
                       "--results", str(results), "--concurrency", str(args.concurrency),
                       "--batch-size", str(args.batch_size), "--max-turns", str(args.max_turns),
                       "--review-turns", str(args.review_turns), "--review-timeout", str(args.review_timeout),
                       "--verify-timeout", str(args.verify_timeout),
                       "--batch-selection", str(frozen_selection),
                       "--batch-number", str(number)]
            if carried:
                command += ["--carry-results", *[str(source) for task, source in carried.items()
                                               if not (results / task).exists()]]
                # Each copied task must own the audited plan that admits it;
                # a source route alone is not a license to resume a failure.
                for task in carried:
                    destination = results / task
                    if (destination / "carry-provenance.json").is_file():
                        atomic_json(destination / "carry-recovery.json",
                                    previous["recovery_plans"][task])
            prepare_carries(results, carried, previous["recovery_plans"])
            command += ["--only", *fresh, *carried, *receipt.get("observed_only", [])]
            with log_path.open("a", encoding="utf-8") as log:
                log.write(f"\n[{timestamp()}] launch batch={number}: {command!r}\n")
                log.flush()
                process = subprocess.Popen(command, cwd=root, stdout=log,
                                           stderr=subprocess.STDOUT, start_new_session=True)
            state.update(active_batch=number, waiting_for="supervisor", supervisor_pid=process.pid,
                         updated_at=timestamp())
            atomic_json(state_path, state)
        pid = state.get("supervisor_pid") if number != 1 else args.initial_supervisor_pid
        try:
            os.kill(pid, 0) if pid else None
            supervisor_alive = bool(pid)
        except ProcessLookupError:
            supervisor_alive = False
        last_stable_state = None
        while supervisor_alive or number == 1:
            if number != 1 and process is not None and process.poll() is not None:
                supervisor_alive = False
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
            state.update(active_batch=number, waiting_for="initial_supervisor_and_terminal_results" if number == 1 else "supervisor",
                         updated_at=timestamp())
            atomic_json(state_path, state)
            time.sleep(args.poll_seconds)
        if number != 1:
            if process is not None:
                code = process.wait()
                if code:
                    raise RuntimeError(f"batch {number} supervisor exited {code}; inspect before any retry")
            elif supervisor_alive:
                raise RuntimeError(f"batch {number} supervisor still owns live workers; wait for its terminal exit")
        # Recovery sources are explicit and immutable. Copying happens in the
        # next batch's carry_workspaces, never into the completed batch.
        # An adopted task can also share a task_id with an immutable source.
        # Keep one attribution entry, with its source provenance, rather than
        # counting the same accepted delivery as both fresh and carried work.
        tasks_by_id = {}
        for task in fresh:
            row = load_result(results, task)
            if args.preserve_unavailable_inputs:
                report = load(output / "download-report.json", {})
                canonical = next(item for item in read_jsonl(sample / "selection.jsonl") if item["task_id"] == task)
                row = preserve_missing_input_result(results, task, row, report)
                if row.get("failure_class") == "input_unavailable":
                    row.setdefault("instance_id", canonical["instance_id"])
            tasks_by_id[task] = classify(task, row, results)
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
        if args.preserve_unavailable_inputs:
            report = load(output / "download-report.json", {})
            for task in tasks:
                if task["classification"] != "input_unavailable":
                    continue
                source = next((entry for entry in report.get("tasks", [])
                               if entry.get("task_id") == task["task_id"] and entry.get("status") == "error"), None)
                if source is None:
                    raise RuntimeError(f"missing preserved download error: {task['task_id']}")
                task.update(status="error", failure_class="input_unavailable", error=source.get("error"),
                            recovery_reason=None, retry_blocked=None)
        carry_sources = {task["task_id"]: str(carried[task["task_id"]]) if task.get("carried")
                         else str(results / task["task_id"])
                         for task in tasks if task["classification"] == "pipeline_recovery_candidate"}
        recovery_plans = {}
        for task in tasks:
            if task["task_id"] not in carry_sources:
                continue
            reason = task["recovery_reason"]
            mode = {"review_incomplete": "review", "harbor_infrastructure": "harbor"}[reason]
            plan = {"schema_version": 1, "task_id": task["task_id"],
                    "instance_id": recovery_instance(Path(carry_sources[task["task_id"]]), task["task_id"]),
                    "mode": mode, "reason": reason}
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
        state["attempted_fresh"] = sorted(set(state["attempted_fresh"]) | set(fresh))
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
