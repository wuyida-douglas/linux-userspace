#!/usr/bin/env python3
"""Route -> synthesize -> independent review -> final Harbor acceptance."""
from __future__ import annotations

import argparse
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

from . import agent
from .common import ROOT, inventory, load_env, read_jsonl, timestamp, write_json
from .contract_build import build_task_contract
from .package_volumes import package_delivery_volumes
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


def review(workspace: Path) -> dict[str, Any]:
    """Collect the reviewer's ordinary JSON artifact after its session ends."""
    value = json.loads((workspace / "review.json").read_text(encoding="utf-8"))
    if isinstance(value, dict) and isinstance(value.get("passed"), bool) \
            and isinstance(value.get("evidence"), str) and value["evidence"].strip():
        # Extra advisory keys are allowed; only the two contract fields matter.
        return {"passed": value["passed"], "evidence": value["evidence"]}
    # Existing deliveries may still carry the older four-field review. Accept
    # it only for resume/re-review; the new prompt emits the two-field shape.
    if isinstance(value, dict) and isinstance(value.get("passed"), bool) \
            and isinstance(value.get("reason"), str) and value["reason"].strip():
        findings = value.get("findings") or []
        evidence = value["reason"]
        if isinstance(findings, list):
            evidence += " " + "; ".join(
                f"{item.get('severity', '')}: {item.get('evidence', '')}"
                for item in findings if isinstance(item, dict) and item.get("evidence"))
        return {"passed": value["passed"], "evidence": evidence.strip()}
    raise ValueError("review.json must include a boolean passed and a non-empty evidence string")


def route(workspace: Path, instance_id: str) -> dict[str, Any]:
    value = json.loads((workspace / "route.json").read_text(encoding="utf-8"))
    for key in ("branch", "host_type"):
        if value.get(key) == "null":
            value[key] = None
    if value.get("instance_id") != instance_id:
        raise ValueError(
            f"route.json instance_id mismatch: expected {instance_id!r}, "
            f"got {value.get('instance_id')!r}")
    if not isinstance(value.get("accepted"), bool):
        raise ValueError("route.json accepted must be boolean")
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
    compose_value = yaml.safe_load(compose_path.read_text(encoding="utf-8")) or {}
    route_value = load_json(workspace / "route.json")
    repairs = normalize_declared_metadata(task_value, route_value)
    compose_changed = False
    services = compose_value.get("services") or {}
    main_service = services.get("main") or {}
    images = task_value.get("images") or {}
    main_image = main_service.get("image")
    if main_image != images.get("agent"):
        if main_image == images.get("target"):
            raise ValueError("main may never use the target image")
        if not images.get("agent"):
            raise ValueError("task.json has no analysis image for main")
        # Harbor injects task.json.images.agent into main. A shared analysis
        # tag or omitted image in the public Compose is packaging drift, not
        # task semantics; make the contract explicit before freezing.
        main_service["image"] = images["agent"]
        compose_changed = True
        repairs.append("canonicalized main.image to task.json.images.agent")
    if str(task_value.get("branch", "")).startswith("FILE-") \
            and task_value.get("host_type") is not None \
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
    if compose_changed and not (evidence / "docker-compose.yaml").exists():
        shutil.copy2(compose_path, evidence / "docker-compose.yaml")
    task_value["sidecar_services"] = sidecars
    write_json(task_path, task_value)
    if compose_changed:
        compose_path.write_text(yaml.safe_dump(compose_value, sort_keys=False,
                                                allow_unicode=True), encoding="utf-8")
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
                "private/gold", "instruction.md", "environment/docker-compose.yaml", "project"]
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
    if route_value.get("recovery_required") is True and not (
            delivery / "project/source-recovery.json").is_file():
        raise ValueError(
            "recovery_required=true requires delivery/project/source-recovery.json")
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
    # Whole-compose substring scans (for example "private/") are intentionally
    # not done here: they reject legitimate container-internal paths such as
    # /vault/private/ready.  Review checks real bind sources and credentials.
    for legacy in ("public_tests", "private/verify.sh", "private/solve.sh"):
        if (delivery / legacy).exists():
            raise ValueError(f"legacy delivery material is not accepted: {legacy}")
    if not (delivery / "private/gold" / contract["submission_mode"]).is_file():
        raise ValueError(f"missing reference {contract['submission_mode']}")


DELIVERY_TRANSIENT_PARTS = {".git", ".agent-tmp", "__pycache__", ".pytest_cache"}


def frozen_inventory(delivery: Path) -> dict[str, Any]:
    """Hash deliverable content, ignoring transient VCS/agent metadata.

    A reviewer running ``git status``/``git diff`` updates ``.git/index`` and
    may create ``.agent-tmp``. Those are not task content and must not turn a
    valid review into a false "delivery modified" pipeline failure.
    """
    excluded = {
        path.relative_to(delivery).as_posix()
        for path in delivery.rglob("*")
        if DELIVERY_TRANSIENT_PARTS.intersection(path.relative_to(delivery).parts)
    }
    return inventory(delivery, exclude=excluded)


def assert_frozen(delivery: Path, expected: dict[str, Any]) -> None:
    if frozen_inventory(delivery) != expected:
        raise ValueError("delivery changed after independent review; refusing Harbor acceptance")


def run_one(task: Path, selection: dict[str, Any], results: Path, args: argparse.Namespace,
            credentials: dict[str, str]) -> dict[str, Any]:
    from .harbor import accept as harbor_accept
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
            record["volume_package"] = package_delivery_volumes(
                workspace / "delivery", workspace)
            record["contract"] = build_task_contract(
                workspace / "delivery", workspace, output)
            normalize_delivery_metadata(workspace / "delivery", workspace, output)
            record["status"] = "reviewing" if not (workspace / "review.json").is_file() else "harbor"
            write_json(output / "result.json", record)
            frozen_delivery(workspace / "delivery")
            route_value = route(workspace, selection["instance_id"])
            if not (workspace / "review.json").is_file():
                review_input = workspace / "review-input"
                if review_input.exists():
                    shutil.rmtree(review_input)
                review_input.mkdir()
                if (output / "synthesis/live.chat.md").is_file():
                    shutil.copyfile(output / "synthesis/live.chat.md", review_input / "live.chat.md")
                if (output / "synthesis/tool-calls.jsonl").is_file():
                    shutil.copyfile(output / "synthesis/tool-calls.jsonl", review_input / "tool-calls.jsonl")
                if (workspace / "input/fix.diff").is_file():
                    shutil.copyfile(workspace / "input/fix.diff", review_input / "fix.diff")
                review_before = frozen_inventory(workspace / "delivery")
                record["review_agent"] = agent.run(REVIEW, workspace, output / "review",
                                                 model=args.model, credentials=credentials,
                                                 max_turns=args.review_turns, timeout=args.review_timeout,
                                                 network=ROOT / "config")
                if frozen_inventory(workspace / "delivery") != review_before:
                    raise ValueError("independent review modified the submitted delivery")
            review_value = review(workspace)
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
                record["harbor"] = harbor_accept(
                    workspace, output / "harbor", task.name, route_value, args.verify_timeout,
                    published_root=args.published_root, model=args.model,
                    credentials=credentials, accept_turns=getattr(args, "accept_turns", 1))
                assert_frozen(workspace / "delivery", approved)
            record.update(status="passed" if record["harbor"]["status"] == "passed" else "failed",
                          failure_class=None if record["harbor"]["status"] == "passed" else "harbor_failed")
            return record
        else:
            if ((workspace / "delivery").is_dir()
                    and load_json(output / "synthesis/result.json").get("status") == "completed"
                    and not (workspace / "repair-request.json").is_file()):
                raise ValueError("completed delivery requires --resume; refusing to replace it with a fresh route")
            if args.route_from:
                if len(args.only or []) != 1:
                    raise ValueError("route reuse requires exactly one --only task")
                if not args.route_from.is_file():
                    raise ValueError("route reuse needs an existing route.json")
            if workspace.exists():
                shutil.rmtree(workspace)
            workspace.mkdir()
            shutil.copytree(task / "input", workspace / "input", symlinks=True)
            write_candidate_leads(workspace, selection)
            shutil.copyfile(ROOT / "config/bare-metal-network.md", workspace / "NETWORK.md")
            if args.route_from:
                shutil.copyfile(args.route_from, workspace / "route.json")
                route(workspace, selection["instance_id"])
                record["route_agent"] = {"status": "reused", "source": str(args.route_from)}
            else:
                record["status"] = "routing"
                write_json(output / "result.json", record)
                record["route_agent"] = agent.run(ROUTE, workspace, output / "route",
                                                 model=args.model, credentials=credentials,
                                                 max_turns=args.route_turns, timeout=args.route_timeout,
                                                 network=ROOT / "config")
                if record["route_agent"].get("status") != "completed":
                    # The prompt asks for a valid route.json within ten turns;
                    # an agent that dies later still leaves a usable decision.
                    if not (workspace / "route.json").is_file():
                        turns = record["route_agent"].get("num_turns")
                        raise RuntimeError(
                            f"routing agent did not complete: {record['route_agent'].get('status')} "
                            f"(turns={turns}, cap={args.route_turns})")
                    record["route_agent"]["warning"] = (
                        "agent ended before completing; using the route.json it wrote")
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
        record["synthesis_agent"] = agent.run(branch_prompt(route_value["branch"]),
                                            workspace, output / "synthesis",
                                            model=args.model, credentials=credentials,
                                            max_turns=args.max_turns, timeout=args.timeout,
                                            network=ROOT / "config")
        if record["synthesis_agent"].get("status") != "completed":
            record.update(status="failed", failure_class="synthesis_incomplete")
            return record
        failure_path = workspace / "failure.json"
        if not failure_path.is_file():
            # Historical agents sometimes wrote the bounded failure record
            # next to the delivery they were building. Accept that location
            # only when it is explicitly a failure record, and keep the
            # workspace-root path as the primary contract.
            candidate = workspace / "delivery/failure.json"
            candidate_value = load_json(candidate)
            if isinstance(candidate_value, dict) and candidate_value.get("status") == "failure":
                failure_path = candidate
        if failure_path.is_file():
            record.update(status="failed", failure_class="synthesis_blocked",
                          error="Synthesis reported an unworkable route; stopped for later manual recovery.",
                          failure=load_json(failure_path))
            return record
        if (workspace / "reroute-request.json").is_file():
            record.update(status="failed", failure_class="branch_mismatch",
                      error="Synthesis requested a different route; stopped for later manual recovery.",
                      reroute_request=json.loads((workspace / "reroute-request.json").read_text(encoding="utf-8")))
            return record
        delivery = workspace / "delivery"
        record["volume_package"] = package_delivery_volumes(delivery, workspace)
        record["contract"] = build_task_contract(delivery, workspace, output)
        normalize_delivery_metadata(delivery, workspace, output)
        frozen_delivery(delivery)
        if (workspace / "repair-request.json").is_file():
            record["delivery_repair_request"] = load_json(workspace / "repair-request.json")
        record["status"] = "reviewing"
        write_json(output / "result.json", record)
        review_input = workspace / "review-input"
        if review_input.exists():
            shutil.rmtree(review_input)
        review_input.mkdir()
        trace = output / "synthesis/live.chat.md"
        if not trace.is_file():
            archived_trace = output / "retry-evidence/synthesis/live.chat.md"
            if not archived_trace.is_file():
                raise ValueError("completed synthesis has no durable live.chat.md for independent review")
            shutil.copy2(archived_trace, trace)
        shutil.copyfile(trace, review_input / "live.chat.md")
        if (output / "synthesis/tool-calls.jsonl").is_file():
            shutil.copyfile(output / "synthesis/tool-calls.jsonl", review_input / "tool-calls.jsonl")
        if (output / "synthesis/tool-logs").is_dir():
            shutil.copytree(output / "synthesis/tool-logs", review_input / "tool-logs")
        shutil.copyfile(workspace / "input/fix.diff", review_input / "fix.diff")
        review_before = frozen_inventory(delivery)
        record["review_agent"] = agent.run(REVIEW, workspace, output / "review",
                                         model=args.model, credentials=credentials,
                                         max_turns=args.review_turns, timeout=args.review_timeout,
                                         network=ROOT / "config")
        if frozen_inventory(delivery) != review_before:
            raise ValueError("independent review modified the submitted delivery")
        review_value = review(workspace)
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
            record["harbor"] = harbor_accept(
                workspace, output / "harbor", task.name, route_value, args.verify_timeout,
                published_root=args.published_root, model=args.model,
                credentials=credentials, accept_turns=getattr(args, "accept_turns", 1))
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
        record = run_one(task, selection, results, args, credentials)
    # Release this task's containers, images and scratch trees as soon as its
    # verdict is final. The per-task cleanup is best effort: a Docker problem
    # must never rewrite a task's status, and images are kept for retryable
    # error/timeout records so a later --resume can export the bundle again.
    from .resource_cleanup import cleanup_task
    try:
        record["cleanup"] = cleanup_task(task.name, output, record)
    except Exception as exc:
        record["cleanup"] = {"error": f"{type(exc).__name__}: {exc}"}
    return record


def reported_published_root() -> Path:
    """Publish accepted tasks to a dated bundle unless explicitly overridden."""
    configured = os.environ.get("HARBOR_EXPORT_ROOT")
    return Path(configured) if configured else ROOT / "harbor_export" / (timestamp()[:10].replace("-", "") + "-production")


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--sample", type=Path, required=True)
    parser.add_argument("--results", type=Path, required=True)
    parser.add_argument("--env-file", type=Path, default=Path("/nvme/wuyida/env"))
    parser.add_argument("--model", default=os.environ.get("ANTHROPIC_MODEL", "deepseek-v4.1-flash-1017"))
    parser.add_argument("--only", nargs="+")
    parser.add_argument("--concurrency", type=int, default=1)
    parser.add_argument("--route-only", action="store_true")
    parser.add_argument("--resume", action="store_true")
    parser.add_argument("--review-delivery", action="store_true",
                        help="submit an already verified delivery for fresh review and Harbor acceptance")
    parser.add_argument("--route-from", type=Path,
                        help="run a fresh synthesis in a new workspace from an existing route.json")
    parser.add_argument("--timeout", type=int, default=18000)
    parser.add_argument("--max-turns", type=int, default=400)
    parser.add_argument("--route-timeout", type=int, default=1800)
    parser.add_argument("--route-turns", type=int,
                        default=int(os.environ.get("PIPELINE_ROUTE_TURNS", "60")),
                        help="routing agent turn cap; hard routes verify provenance and "
                             "regularly needed 60+ turns")
    parser.add_argument("--review-timeout", type=int, default=5400)
    parser.add_argument("--review-turns", type=int, default=140)
    parser.add_argument("--verify-timeout", type=int, default=3600)
    parser.add_argument("--accept-turns", type=int, default=1,
                        help="max agent turns in each of the two Harbor acceptance runs")
    parser.add_argument("--published-root", type=Path, default=reported_published_root(),
                        help="accepted-only Harbor bundle; never contains failed tasks")
    args = parser.parse_args()
    if not 1 <= args.concurrency <= 80:
        parser.error("concurrency must be 1..80")
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
                                               "model": args.model, "executor": "claude"})
    return 0 if counts.get("passed", 0) == len(records) else 1


if __name__ == "__main__":
    raise SystemExit(main())
