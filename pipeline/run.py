#!/usr/bin/env python3
"""Route -> synthesize -> independent review -> final Harbor acceptance."""
from __future__ import annotations

import argparse
import collections
import concurrent.futures
import fcntl
import json
import os
import re
import shutil
import subprocess
import threading
from pathlib import Path

import yaml
from typing import Any

from . import agent, native_agent
from .common import ROOT, inventory, load_env, read_jsonl, timestamp, write_json
from .prompts import REVIEW, ROUTE, branch_prompt
from .task_contract import load_task, normalize_declared_metadata, normalize_sidecars, validate_route


def load_json(path: Path) -> dict[str, Any]:
    try:
        return json.loads(path.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError):
        return {}


BRANCHES = {"SVC-EXPLOIT", "FILE-EXPLOIT", "FILE-POV"}
HOST_TYPES = {"native_service", "real_host", "synthetic_host"}
DOCKER = threading.Lock()


def route(workspace: Path, instance_id: str) -> dict[str, Any]:
    value = json.loads((workspace / "route.json").read_text(encoding="utf-8"))
    for key in ("branch", "host_type"):
        if value.get(key) == "null":
            value[key] = None
    if value.get("instance_id") != instance_id or not isinstance(value.get("accepted"), bool):
        raise ValueError("route.json instance_id or accepted is invalid")
    if value["accepted"]:
        if value.get("branch") not in BRANCHES:
            raise ValueError("route.json has an invalid branch")
        host = value.get("host_type")
        if value["branch"] == "SVC-EXPLOIT" and host not in HOST_TYPES:
            raise ValueError("SVC route requires a real host_type")
        if value["branch"] != "SVC-EXPLOIT" and host is not None:
            raise ValueError("FILE routes must use host_type=null")
    elif value.get("branch") is not None:
        raise ValueError("rejected route must have branch=null")
    if not str(value.get("reason", "")).strip():
        raise ValueError("route.json needs a concrete reason")
    # Legacy completed routes predate this field and remain safe to reuse.
    recovery_required = value.get("recovery_required", False)
    if not isinstance(recovery_required, bool):
        raise ValueError("route.json recovery_required must be boolean")
    if value["accepted"]:
        for key in ("entry", "oracle", "normal_input", "fixed_revision"):
            if not isinstance(value.get(key), str) or not value[key].strip():
                raise ValueError(f"accepted route.json needs a concrete {key}")
        revision = value["fixed_revision"].lower()
        if revision == "unresolved":
            if not recovery_required:
                raise ValueError("unresolved fixed_revision requires source/patch recovery")
        elif not re.fullmatch(r"[0-9a-f]{40}", revision):
            raise ValueError("route fixed_revision must be 40 hex or UNRESOLVED during recovery")
        elif not recovery_required:
            meta = json.loads((workspace / "input/meta.json").read_text(encoding="utf-8"))
            candidates = (meta.get("code") or {}).get("candidates") or [meta["candidate"]]
            leads = workspace / "input/alternate-candidates.json"
            if leads.is_file():
                # Older immutable workspaces have the alternates in this
                # companion file rather than in the reduced selection metadata.
                candidates += json.loads(leads.read_text(encoding="utf-8")).get("alternate_candidates", [])
            allowed = {str(value).lower() for candidate in candidates
                       for value in ((candidate.get("fix") or {}).get("revision")
                                     if isinstance(candidate.get("fix"), dict) else candidate.get("fix"),
                                     (candidate.get("base") or {}).get("revision")
                                     if isinstance(candidate.get("base"), dict) else candidate.get("base"),
                                     candidate.get("merge_commit")) if value}
            if revision not in allowed:
                raise ValueError("non-recovery route fixed_revision is not an exact downloaded candidate fix revision")
    return value


def write_candidate_leads(workspace: Path, selection: dict[str, Any]) -> None:
    """Keep official patch leads available to both routing and synthesis."""
    alternate_candidates = [
        {"candidate_id": candidate.get("candidate_id"),
         "origin_url": candidate.get("origin_url"),
         "prefix": (candidate.get("prefix") or {}).get("revision"),
         "fix": (candidate.get("fix") or {}).get("revision"),
         "source_references": candidate.get("source_references")}
        for candidate in (selection.get("code") or {}).get("candidates") or []
        if candidate.get("candidate_id") != selection.get("candidate_id")
    ]
    references = (selection.get("vulnerability") or {}).get("references") or []
    write_json(workspace / "input/alternate-candidates.json",
               {"alternate_candidates": alternate_candidates,
                "advisory_reference_urls": references[:30]})


def normalize_delivery_metadata(delivery: Path, workspace: Path, output: Path) -> None:
    """Canonicalize descriptive fields before any contract freeze or review."""
    task_path = delivery / "task.json"
    compose_path = delivery / "environment/docker-compose.yaml"
    if not task_path.is_file() or not compose_path.is_file():
        return
    task_value = json.loads(task_path.read_text(encoding="utf-8"))
    compose_value = yaml.safe_load(compose_path.read_text(encoding="utf-8"))
    route_value = load_json(workspace / "route.json")
    repairs = normalize_declared_metadata(task_value, route_value)
    if str(task_value.get("branch", "")).startswith("FILE-") \
            and task_value.get("host_type") in {None, "null", "none", "linux-container"} \
            and route_value.get("branch") == task_value.get("branch") \
            and route_value.get("host_type") in {None, "null"}:
        task_value["host_type"] = None
        if "canonicalized FILE host_type to JSON null" not in repairs:
            repairs.append("canonicalized FILE host_type to JSON null")
    sidecars = normalize_sidecars(task_value, compose_value.get("services"))
    if not repairs and task_value.get("sidecar_services", []) == sidecars:
        return
    evidence = output / "retry-evidence" / "metadata-normalization"
    evidence.mkdir(parents=True, exist_ok=True)
    if not (evidence / "task.json").exists():
        shutil.copy2(task_path, evidence / "task.json")
    task_value["sidecar_services"] = sidecars
    write_json(task_path, task_value)
    write_json(evidence / "repairs.json", {
        "repairs": repairs,
        "sidecar_services": sidecars,
        "basis": "descriptive metadata agrees with the authoritative route and public Compose; no semantics added",
        "requires_fresh_independent_review": True,
        "created_at": timestamp()})
    if (workspace / "review.json").is_file():
        shutil.copy2(workspace / "review.json", evidence / "previous-review.json")
        (workspace / "review.json").unlink()


def frozen_delivery(delivery: Path) -> None:
    required = ["task.json", "private/healthcheck.sh", "private/oracle.sh", "private/solution.sh",
                "private/gold", "instruction.md", "verification.json", "environment/docker-compose.yaml", "project"]
    for rel in required:
        if not (delivery / rel).exists():
            raise ValueError(f"missing delivery/{rel}")
    for path in delivery.rglob("*"):
        if path.is_symlink() and (path.readlink().is_absolute() or
                                  not path.resolve(strict=False).is_relative_to(delivery.resolve())):
            raise ValueError(f"unsafe delivery symlink: {path}")
    contract = load_task(delivery / "task.json")
    route_value = json.loads((delivery.parent / "route.json").read_text(encoding="utf-8"))
    validate_route(contract, route_value, contract["images"]["agent"])
    compose = (delivery / "environment/docker-compose.yaml").read_text(encoding="utf-8")
    if not re.search(r"^\s{2}main:", compose, re.MULTILINE):
        raise ValueError("public Compose must have an explicit main agent service")
    compose_value = yaml.safe_load(compose)
    services = compose_value.get("services") or {}
    if not {"main", "client"}.issubset(services) or "runner" in services:
        raise ValueError("public Compose requires main+client and must not expose runner")
    if services["client"].get("image") != contract["images"]["target"]:
        raise ValueError("client must use the declared prebuilt target image")
    from .harbor import validate_public_services
    validate_public_services(services)
    forbidden = ["private/", "../private", "ANTHROPIC_AUTH_TOKEN", "ANTHROPIC_API_KEY",
                 "/var/run/docker.sock", "/run/docker.sock"]
    for token in forbidden:
        if token in compose:
            raise ValueError(f"public Compose contains forbidden material: {token}")
    for legacy in ("public_tests", "private/verify.sh", "private/solve.sh"):
        if (delivery / legacy).exists():
            raise ValueError(f"legacy delivery material is not accepted: {legacy}")
    if not (delivery / "private/gold" / contract["submission_mode"]).is_file():
        raise ValueError(f"missing reference {contract['submission_mode']}")


def frozen_inventory(delivery: Path) -> dict[str, Any]:
    """Hash everything that the independent reviewer approved."""
    return inventory(delivery)


def assert_frozen(delivery: Path, expected: dict[str, Any]) -> None:
    if inventory(delivery) != expected:
        raise ValueError("delivery changed after independent review; refusing Harbor acceptance")


def run_one(task: Path, selection: dict[str, Any], results: Path, args: argparse.Namespace,
            credentials: dict[str, str]) -> dict[str, Any]:
    from .harbor import accept as harbor_accept
    executor = native_agent.run if args.executor == "native" else agent.run
    output = results / task.name
    workspace = output / "workspace"
    output.mkdir(parents=True, exist_ok=True)
    resumable = (args.resume or args.review_delivery) and (workspace / "delivery").exists()
    if args.review_delivery and (workspace / "review.json").exists():
        previous_review = output / "retry-evidence" / ("review-before-packaging-" + timestamp().replace(":", "-") + ".json")
        previous_review.parent.mkdir(exist_ok=True)
        shutil.copy2(workspace / "review.json", previous_review)
        (workspace / "review.json").unlink()
    record = {"task_id": task.name, "instance_id": selection["instance_id"],
              "status": "harbor" if resumable else "preparing", "started_at": timestamp()}
    if resumable:
        archive = output / "infrastructure-attempts"
        archive.mkdir(exist_ok=True)
        if (output / "result.json").is_file():
            shutil.copy2(output / "result.json",
                         archive / ("before-resume-" + timestamp().replace(":", "-") + ".json"))
    write_json(output / "result.json", record)
    try:
        if resumable:
            normalize_delivery_metadata(workspace / "delivery", workspace, output)
            record["status"] = "reviewing" if not (workspace / "review.json").is_file() else "harbor"
            write_json(output / "result.json", record)
            frozen_delivery(workspace / "delivery")
            route_value = route(workspace, selection["instance_id"])
            if not (workspace / "review.json").is_file():
                review_input = workspace / "review-input"
                if review_input.exists():
                    shutil.rmtree(review_input)
                shutil.copytree(workspace / "delivery", review_input / "delivery", symlinks=True)
                if (workspace / "delivery/verification.json").is_file():
                    shutil.copyfile(workspace / "delivery/verification.json", review_input / "self-check.json")
                if (output / "synthesis/trajectory.jsonl").is_file():
                    shutil.copyfile(output / "synthesis/trajectory.jsonl", review_input / "trajectory.jsonl")
                if (workspace / "input/fix.diff").is_file():
                    shutil.copyfile(workspace / "input/fix.diff", review_input / "fix.diff")
                record["review_agent"] = executor(REVIEW, workspace, output / "review",
                                                 model=args.model, credentials=credentials,
                                                 max_turns=args.review_turns, timeout=args.review_timeout,
                                                 network=ROOT / "config")
            review_value = json.loads((workspace / "review.json").read_text(encoding="utf-8"))
            if not isinstance(review_value.get("passed"), bool):
                if args.review_delivery:
                    raise ValueError("independent review did not produce a structured verdict; retry the bounded review")
                raise ValueError("Harbor resume requires a structured independent review verdict")
            if review_value["passed"] is not True:
                record.update(status="failed", failure_class="review_rejected",
                              route=route_value, review=review_value)
                return record
            record.update(status="harbor", route=route_value, review=review_value)
            approved = frozen_inventory(workspace / "delivery")
            with DOCKER:
                # The archive bundle has no partial-acceptance resume contract.
                # Preserve all previous jobs and rerun from the approved frozen
                # delivery; a stale gold alone never establishes acceptance.
                if (output / "harbor").exists():
                    previous = output / "infrastructure-attempts" / (
                        "resume-acceptance-" + timestamp().replace(":", "-") + "-" + str(os.getpid()))
                    previous.parent.mkdir(exist_ok=True)
                    os.rename(output / "harbor", previous)
                record["harbor"] = harbor_accept(workspace, output / "harbor", task.name,
                                                 route_value, args.verify_timeout,
                                                 published_root=args.published_root)
                assert_frozen(workspace / "delivery", approved)
            record.update(status="passed" if record["harbor"]["status"] == "passed" else "failed",
                          failure_class=None if record["harbor"]["status"] == "passed" else "harbor_failed")
            return record
        else:
            if ((workspace / "delivery").is_dir()
                    and load_json(output / "synthesis/result.json").get("status") == "completed"
                    and not (workspace / "repair-request.json").is_file()):
                raise ValueError("completed delivery requires --resume; refusing to replace it with a fresh route")
            retry_route = None
            if args.retry_synthesis or args.route_from or args.continue_synthesis:
                retry_route = args.route_from if args.route_from else workspace / "route.json"
                if args.continue_synthesis and args.workspace_from is not None:
                    retry_route = args.workspace_from / "route.json"
                if args.workspace_from is not None:
                    expected_workspace = args.results / task.name / "workspace"
                    if args.workspace_from.resolve() != expected_workspace.resolve():
                        raise ValueError("workspace-from must be this task's authoritative workspace")
                if not retry_route.is_file():
                    raise ValueError("route reuse needs an existing route.json")
                if len(args.only or []) != 1:
                    raise ValueError("route reuse requires exactly one --only task")
            if args.continue_synthesis or (retry_route is not None
                    and retry_route.resolve() == (workspace / "route.json").resolve()):
                source_workspace = args.workspace_from or workspace
                if retry_route is not None and source_workspace.resolve() == workspace.resolve() \
                        and not (workspace / "input/src").is_dir():
                    # Recover immutable source after an interrupted workspace
                    # copy. Existing synthesis/delivery evidence stays intact.
                    if (workspace / "input").exists():
                        shutil.rmtree(workspace / "input")
                    shutil.copytree(task / "input", workspace / "input", symlinks=True)
                if not (workspace / "input/alternate-candidates.json").is_file():
                    write_candidate_leads(workspace, selection)
                if retry_route is None or not (source_workspace / "input/src").is_dir():
                    raise ValueError("--continue-synthesis needs a reusable route and an existing input workspace")
                if source_workspace.resolve() != workspace.resolve():
                    if workspace.exists():
                        shutil.rmtree(workspace)
                    workspace.mkdir()
                    # Do not copy disposable root-owned build trees or host
                    # scratch state. Delivery rebuilds from project/ anyway.
                    for name in ("input", "delivery"):
                        if (source_workspace / name).exists():
                            shutil.copytree(source_workspace / name, workspace / name, symlinks=True)
                    for name in ("NETWORK.md", "route.json"):
                        if (source_workspace / name).is_file():
                            shutil.copyfile(source_workspace / name, workspace / name)
                # Keep source copies, built artifacts and the unfinished delivery.
                # The fresh model session must finish the contract, not restart it.
                record["workspace_reused"] = True
            else:
                if workspace.exists():
                    shutil.rmtree(workspace)
                workspace.mkdir()
            if retry_route is not None:
                if retry_route.resolve() != (workspace / "route.json").resolve():
                    shutil.copyfile(retry_route, workspace / "route.json")
                # Validate before running synthesis; the original route stays intact.
                route(workspace, selection["instance_id"])
                record["route_agent"] = {"status": "reused", "source": str(retry_route)}
            else:
                if not (args.route_handoff_from and (workspace / "input/src").is_dir()):
                    # Prepare a fresh workspace exactly once. The previous
                    # branch copied input both here and before route handling,
                    # so every new task failed before invoking its route agent.
                    shutil.copytree(task / "input", workspace / "input", symlinks=True)
                    # The downloaded candidate is only a starting point;
                    # preserve alternate patch hints for provisional recovery.
                    write_candidate_leads(workspace, selection)
                network = ROOT / "config/bare-metal-network.md"
                if not (workspace / "NETWORK.md").is_file():
                    shutil.copyfile(network, workspace / "NETWORK.md")
                record["status"] = "routing"
                write_json(output / "result.json", record)
                route_prompt = ROUTE
                if args.route_handoff_from:
                    handoff = list(read_jsonl(args.route_handoff_from))
                    recent_turn = max((entry.get("turn", 0) for entry in handoff), default=0)
                    evidence = [json.dumps(entry, ensure_ascii=False) for entry in handoff
                                if entry.get("turn", 0) > recent_turn - 12]
                    route_prompt += ("\n\nBOUNDED ROUTE RECOVERY: The previous route ran out of turns without "
                                     "a decision. Its original trajectory is archived. Do not restart broad "
                                     "exploration or read the entire large release diff again. The last turns "
                                     "are supplied below as unverified hypotheses, not as a prescribed verdict. "
                                     "Verify only the decisive entry questions using the supplied local source. "
                                     "Never reject for missing/mismatched patch provenance: accept a plausible "
                                     "route with recovery_required=true and hand its evidence gap to synthesis. "
                                     "Pure library DoS/crash cases with a real CLI belong in FILE-POV, not a "
                                     "synthetic host whose only difference is HTTP 500 or exception wording. "
                                     "SVC needs a true unauthorized effect or persistent resource disruption, "
                                     "not just an ASan abort. A viable network parser does not need an ASan crash "
                                     "to be routed: an exact-size receiving-buffer over-read is a valid differential when "
                                     "the receiving code zeroes its unused capacity. Conversely, reject only "
                                     "with concrete evidence against every branch. Call submit_route immediately: "
                                     "a prose answer without the tool is an infrastructure failure, not a route. "
                                     "Do not enumerate unrelated callers.\n"
                                     + "\n".join(evidence)[-60000:])
                route_output = output / "route"
                if args.route_handoff_from and route_output.exists():
                    archive = output / "retry-evidence" / "carried-route-before-handoff"
                    if archive.exists():
                        raise ValueError("carried route handoff may only archive its prior route once")
                    os.rename(route_output, archive)
                record["route_agent"] = executor(route_prompt, workspace, route_output,
                                                 model=args.model, credentials=credentials,
                                                 max_turns=args.route_turns, timeout=args.route_timeout,
                                                 network=ROOT / "config", context_chars=140000,
                                                 docker_wrap=False)
                if record["route_agent"].get("status") == "api_error" \
                        and "invalid or oversized HTTP request" in str(record["route_agent"].get("error", "")) \
                        and not args.route_handoff_from:
                    # A gateway HTTP-limit failure is not a vulnerability
                    # verdict. Retry only this route once with a smaller
                    # complete-request budget; all local evidence is retained.
                    evidence = output / "retry-evidence/route-api-request-limit"
                    evidence.mkdir(parents=True, exist_ok=True)
                    shutil.copy2(output / "route/result.json", evidence / "result.json")
                    record["route_agent"] = executor(ROUTE, workspace, output / "route",
                                                     model=args.model, credentials=credentials,
                                                     max_turns=args.route_turns, timeout=args.route_timeout,
                                                     network=ROOT / "config", context_chars=70000,
                                                     docker_wrap=False)
                if record["route_agent"].get("status") != "completed":
                    raise RuntimeError(f"routing agent did not complete: {record['route_agent'].get('status')}")
                if not (workspace / "route.json").is_file():
                    record.update(status="failed", failure_class="route_decision_missing")
                    return record
        route_value = route(workspace, selection["instance_id"])
        record["route"] = route_value
        if not route_value["accepted"]:
            record.update(status="rejected", failure_class="not_suitable")
            return record
        if args.route_only:
            record["status"] = "routed"
            return record
        record["status"] = "synthesizing"
        write_json(output / "result.json", record)
        continuation_note = ""
        if args.continue_synthesis:
            continuation_note = ("\n\nCONTINUED SESSION: Preserve the existing delivery and fix its concrete "
                             "failures. Do not restart from source exploration. ")
        continuation_note += ("\n\nAll ASan invocations and ")
        continuation_note += (
                             "build-time smoke tests must use symbolize=0; unbounded DEADLYSIGNAL output "
                             "is a runtime defect, not the vulnerability. Put experiment files in TASK_TMP "
                             "rather than shared /tmp filenames. Finish the full delivery and self-check.")
        if args.continue_synthesis and (workspace / "repair-request.json").is_file():
            repair = json.loads((workspace / "repair-request.json").read_text(encoding="utf-8"))
            continuation_note += ("\n\nDELIVERY REPAIR: The previous session's artifact failed validation or "
                                  "independent review. Exact error: " + str(repair.get("error", ""))
                                  + "\nIndependent findings: "
                                  + json.dumps(repair.get("review", {}).get("findings", []), ensure_ascii=False)
                                  + "\nIf experiments prove only FILE-POV, call request_reroute instead of forcing SVC. "
                                  + "\nRead the existing artifacts and fix the actual contract/oracle defects, "
                                  "including every blocker/major finding. Do not merely assert completion, "
                                  "hide the adversarial input, or weaken the review/differential. Run "
                                  "private health/oracle/solution contract, preserve its evidence, and exercise the "
                                  "demonstrated oracle shortcut to prove that it no longer earns reward. "
                                  "Finish so a fresh independent reviewer can validate the changed delivery.")
        if args.continue_synthesis and args.handoff_from:
            handoff = (json.loads(args.handoff_from.read_text(encoding="utf-8"))
                       if args.handoff_from.suffix == ".json"
                       else list(read_jsonl(args.handoff_from)))
            evidence = []
            for entry in handoff:
                if (entry.get("type") == "assistant" and entry.get("turn", 0) >= 97
                        and entry.get("turn", 0) <= 100):
                    for block in entry["message"].get("content", []):
                        if block.get("type") == "text":
                            evidence.append(block.get("text", ""))
                if entry.get("type") == "tool_result" and entry.get("turn") in {97, 99}:
                    evidence.append(entry.get("content", ""))
            continuation_note = ("\n\nThis fresh session resumes an interrupted build. The following "
                                 "verified experiment evidence is supplied to avoid repeating work:\n"
                                 + "\n".join(evidence)[-24000:])
        record["synthesis_agent"] = executor(branch_prompt(route_value["branch"]) + continuation_note,
                                            workspace, output / "synthesis",
                                            model=args.model, credentials=credentials,
                                            max_turns=args.max_turns, timeout=args.timeout,
                                            network=ROOT / "config",
                                            **({"max_tokens": args.max_tokens} if args.executor == "native" else {}))
        if args.executor == "native" and record["synthesis_agent"].get("status") == "api_error" \
                and "invalid or oversized HTTP request" in str(record["synthesis_agent"].get("error", "")) \
                and not (output / "retry-evidence/synthesis-api-request-limit/result.json").is_file():
            # Preserve the failed model session and workspace, then grant one
            # fresh, bounded session with a tighter full-request budget. This
            # is an infrastructure retry, not a weaker task acceptance path.
            evidence = output / "retry-evidence/synthesis-api-request-limit"
            evidence.mkdir(parents=True, exist_ok=True)
            shutil.copy2(output / "synthesis/result.json", evidence / "result.json")
            record["synthesis_agent"] = executor(
                branch_prompt(route_value["branch"]) + continuation_note
                + "\n\nINFRASTRUCTURE RECOVERY: The previous model request exceeded the gateway HTTP limit. "
                  "Continue from the existing workspace and tool evidence; do not redo completed builds. "
                  "Keep outputs focused, write large files in bounded chunks, and finish the delivery.",
                workspace, output / "synthesis", model=args.model, credentials=credentials,
                max_turns=args.max_turns, timeout=args.timeout, network=ROOT / "config",
                context_chars=96000)
        if record["synthesis_agent"].get("status") != "completed":
            record.update(status="failed", failure_class="synthesis_incomplete")
            return record
        if (workspace / "reroute-request.json").is_file():
            requested = json.loads((workspace / "reroute-request.json").read_text(encoding="utf-8"))
            (workspace / "route.json").write_text(json.dumps(requested, indent=2) + "\n", encoding="utf-8")
            route_value = route(workspace, selection["instance_id"])
            record.update(status="reroute_required", failure_class="branch_mismatch", route=route_value)
            return record
        delivery = workspace / "delivery"
        normalize_delivery_metadata(delivery, workspace, output)
        if args.continue_synthesis and (delivery / "task.json").is_file():
            task_value = json.loads((delivery / "task.json").read_text(encoding="utf-8"))
            repairs = normalize_declared_metadata(task_value, route_value)
            if repairs:
                evidence = output / "retry-evidence" / "metadata-normalization"
                evidence.mkdir(parents=True, exist_ok=True)
                if not (evidence / "task.json").exists():
                    shutil.copy2(delivery / "task.json", evidence / "task.json")
                write_json(delivery / "task.json", task_value)
                write_json(evidence / "repairs.json", {"repairs": repairs,
                           "requires_fresh_independent_review": True,
                           "previous_self_authored_review_disregarded": True,
                           "created_at": timestamp()})
                # A synthesis session cannot grant itself an independent verdict.
                # Its workspace/review.json is an editable artifact, not evidence.
                if (workspace / "review.json").is_file():
                    shutil.copy2(workspace / "review.json", evidence / "synthesis-review.json")
                    (workspace / "review.json").unlink()
        frozen_delivery(delivery)
        if (workspace / "repair-request.json").is_file():
            record["delivery_repair_request"] = load_json(workspace / "repair-request.json")
        record["status"] = "reviewing"
        write_json(output / "result.json", record)
        review_input = workspace / "review-input"
        if review_input.exists():
            shutil.rmtree(review_input)
        shutil.copytree(delivery, review_input / "delivery", symlinks=True)
        if (delivery / "verification.json").is_file():
            shutil.copyfile(delivery / "verification.json", review_input / "self-check.json")
        trace = output / "synthesis/trajectory.jsonl"
        if not trace.is_file():
            archived_trace = output / "retry-evidence/synthesis/trajectory.jsonl"
            if not archived_trace.is_file():
                raise ValueError("completed synthesis has no durable trajectory for independent review")
            shutil.copy2(archived_trace, trace)
        shutil.copyfile(trace, review_input / "trajectory.jsonl")
        if (output / "synthesis/tool-logs").is_dir():
            shutil.copytree(output / "synthesis/tool-logs", review_input / "tool-logs")
        shutil.copyfile(workspace / "input/fix.diff", review_input / "fix.diff")
        record["review_agent"] = executor(REVIEW, workspace, output / "review",
                                         model=args.model, credentials=credentials,
                                         max_turns=args.review_turns, timeout=args.review_timeout,
                                         network=ROOT / "config")
        if inventory(delivery) != frozen_inventory(review_input / "delivery"):
            raise ValueError("independent review modified the submitted delivery")
        review_value = json.loads((workspace / "review.json").read_text(encoding="utf-8"))
        if not isinstance(review_value.get("passed"), bool):
            raise ValueError("review.json passed must be boolean")
        record["review"] = review_value
        # The final acceptance directory must match the exact approved delivery.
        # An aborted prior trial must never cause us to accept an edited image.
        harbor_output = output / "harbor"
        if harbor_output.exists():
            suffix = timestamp().replace(":", "-") + "-" + str(os.getpid())
            archive = output / "infrastructure-attempts" / ("pre-harbor-" + suffix)
            archive.parent.mkdir(exist_ok=True)
            os.rename(harbor_output, archive)
        if not review_value["passed"]:
            record.update(status="failed", failure_class="review_rejected")
            return record
        record["status"] = "harbor"
        approved = frozen_inventory(delivery)
        write_json(output / "result.json", record)
        with DOCKER:
            record["harbor"] = harbor_accept(workspace, output / "harbor", task.name,
                                             route_value, args.verify_timeout,
                                             published_root=args.published_root)
            assert_frozen(delivery, approved)
        passed = record["harbor"]["status"] == "passed"
        record.update(status="passed" if passed else "failed",
                      failure_class=None if passed else "harbor_failed")
        return record
    except (OSError, ValueError, RuntimeError, subprocess.SubprocessError, json.JSONDecodeError) as exc:
        record.update(status="error", failure_class="pipeline", error=f"{type(exc).__name__}: {exc}")
        return record
    finally:
        record["finished_at"] = timestamp()
        write_json(output / "result.json", record)


def run_exclusive(task: Path, selection: dict[str, Any], results: Path,
                  args: argparse.Namespace, credentials: dict[str, str]) -> dict[str, Any]:
    """Only one model session may mutate a task's shared workspace and verdict."""
    output = results / task.name
    output.mkdir(parents=True, exist_ok=True)
    with (output / ".worker.lock").open("a+") as lock:
        try:
            fcntl.flock(lock, fcntl.LOCK_EX | fcntl.LOCK_NB)
        except BlockingIOError:
            return {"task_id": task.name, "instance_id": selection["instance_id"],
                    "status": "duplicate", "error": "another live worker owns this task"}
        return run_one(task, selection, results, args, credentials)


def reported_published_root() -> Path:
    """Publish accepted tasks to a dated bundle unless explicitly overridden."""
    configured = os.environ.get("HARBOR_EXPORT_ROOT")
    return Path(configured) if configured else ROOT / "harbor_export" / (timestamp()[:10].replace("-", "") + "-production")


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--sample", type=Path, required=True)
    parser.add_argument("--results", type=Path, required=True)
    parser.add_argument("--env-file", type=Path, default=Path("/nvme/wuyida/env"))
    parser.add_argument("--model", default="glm-5.3")
    parser.add_argument("--executor", choices=["claude", "native"], default="native")
    parser.add_argument("--only", nargs="+")
    parser.add_argument("--concurrency", type=int, default=1)
    parser.add_argument("--route-only", action="store_true")
    parser.add_argument("--resume", action="store_true")
    parser.add_argument("--review-delivery", action="store_true",
                        help="submit an already verified delivery for fresh review and Harbor acceptance")
    parser.add_argument("--route-from", type=Path, help="reuse a completed route.json for a single task")
    parser.add_argument("--retry-synthesis", action="store_true",
                        help="keep the validated route and redo synthesis, verification and review")
    parser.add_argument("--continue-synthesis", action="store_true",
                        help="keep an interrupted synthesis workspace; finish its delivery in a fresh session")
    parser.add_argument("--workspace-from", type=Path,
                        help="copy this interrupted workspace before --continue-synthesis")
    parser.add_argument("--handoff-from", type=Path,
                        help="verified prior trajectory evidence for --continue-synthesis")
    parser.add_argument("--timeout", type=int, default=18000)
    parser.add_argument("--max-turns", type=int, default=300)
    parser.add_argument("--max-tokens", type=int, default=32768)
    parser.add_argument("--route-handoff-from", type=Path,
                        help="archived incomplete route trajectory; use its evidence to converge a fresh route")
    parser.add_argument("--route-timeout", type=int, default=1800)
    parser.add_argument("--route-turns", type=int, default=45)
    parser.add_argument("--review-timeout", type=int, default=3600)
    parser.add_argument("--review-turns", type=int, default=100)
    parser.add_argument("--verify-timeout", type=int, default=3600)
    parser.add_argument("--published-root", type=Path, default=reported_published_root(),
                        help="accepted-only Harbor bundle; never contains failed tasks")
    args = parser.parse_args()
    if not 1 <= args.concurrency <= 30:
        parser.error("concurrency must be 1..30")
    if args.review_delivery and len(args.only or []) != 1:
        parser.error("--review-delivery requires exactly one --only task")
    credentials = load_env(args.env_file)
    selected = list(read_jsonl(args.sample / "selection.jsonl"))
    task_roots = {row["task_id"]: args.sample / "tasks" / row["task_id"] for row in selected}
    if args.only:
        wanted = set(args.only)
        selected = [row for row in selected if row["task_id"] in wanted or row["canonical_id"] in wanted]
    # A carried repair is explicitly identified by its new result workspace,
    # not by the unrelated fresh sample's numbered input directory. It retains
    # its immutable copied input and exact instance identity. A missing --only
    # entry must fail loudly rather than return an empty successful invocation.
    if args.only and len(args.only) == 1 and not selected:
        task_id = args.only[0]
        task_root = args.results / task_id
        provenance = load_json(task_root / "carry-provenance.json")
        original = load_json(task_root / "result.json")
        route_value = load_json(task_root / "workspace/route.json")
        input_meta = load_json(task_root / "workspace/input/meta.json")
        identities = {value.get("instance_id") for value in (provenance, original, route_value, input_meta) if value}
        if (provenance.get("same_instance_continuation") is not True
                or not (task_root / "workspace/input/src").is_dir()
                or len(identities) != 1 or original.get("task_id") != task_id):
            raise ValueError(f"no valid input or carried workspace for {task_id}")
        instance_id = identities.pop()
        if any(value.get("instance_id") not in {None, instance_id}
               for value in (provenance, original, route_value, input_meta)):
            raise ValueError(f"carried input identity mismatch for {task_id}")
        selected = [{"task_id": task_id, "instance_id": instance_id}]
        task_roots[task_id] = task_root / "workspace"
    if args.only and len(selected) != len(set(args.only)):
        raise ValueError("one or more --only tasks have no selected input")
    args.results.mkdir(parents=True, exist_ok=True)
    with concurrent.futures.ThreadPoolExecutor(max_workers=args.concurrency) as pool:
        futures = [pool.submit(run_exclusive, task_roots[row["task_id"]], row,
                               args.results, args, credentials) for row in selected]
        records = [future.result() for future in futures]
    counts: dict[str, int] = {}
    for record in records:
        counts[record["status"]] = counts.get(record["status"], 0) + 1
        print(f"{record['task_id']}: {record['status']}", flush=True)
    write_json(args.results / "summary.json", {"counts": counts, "tasks": records,
                                               "model": args.model, "executor": args.executor})
    return 0 if counts.get("passed", 0) == len(records) else 1


if __name__ == "__main__":
    raise SystemExit(main())
