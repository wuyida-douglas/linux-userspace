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
from .verify import execute_verify

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
            candidate = json.loads((workspace / "input/meta.json").read_text(encoding="utf-8"))["candidate"]
            allowed = {str((candidate.get("fix") or {}).get("revision", "")).lower(),
                       str((candidate.get("base") or {}).get("revision", "")).lower(),
                       str((candidate.get("merge_commit") or "")).lower()}
            if revision not in allowed:
                raise ValueError("non-recovery route fixed_revision is not the exact downloaded candidate fix revision")
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


def frozen_delivery(delivery: Path) -> None:
    required = ["private/verify.sh", "private/gold", "instruction.md", "verification.json",
                "public_tests/test.sh", "environment/docker-compose.yaml", "project"]
    for rel in required:
        if not (delivery / rel).exists():
            raise ValueError(f"missing delivery/{rel}")
    for path in delivery.rglob("*"):
        if path.is_symlink() and (path.readlink().is_absolute() or
                                  not path.resolve(strict=False).is_relative_to(delivery.resolve())):
            raise ValueError(f"unsafe delivery symlink: {path}")
    compose = (delivery / "environment/docker-compose.yaml").read_text(encoding="utf-8")
    if not re.search(r"^\s{2}main:", compose, re.MULTILINE):
        raise ValueError("public Compose must have an explicit main agent service")
    compose_value = yaml.safe_load(compose)
    for name, service in (compose_value.get("services") or {}).items():
        if not service.get("image"):
            raise ValueError(f"public Compose service {name} needs a prebuilt image")
        for key in ("build", "privileged", "pid"):
            if key in service:
                raise ValueError(f"public Compose service {name} must not contain {key}")
    forbidden = ["private/", "../private", "ANTHROPIC_AUTH_TOKEN", "ANTHROPIC_API_KEY",
                 "/var/run/docker.sock", "/run/docker.sock"]
    for token in forbidden:
        if token in compose:
            raise ValueError(f"public Compose contains forbidden material: {token}")
    scorer = (delivery / "public_tests/test.sh").read_text(encoding="utf-8")
    for pattern in (r"\bdocker\s+(run|cp|compose|exec|image)\b", r"docker\.sock"):
        if re.search(pattern, scorer):
            raise ValueError("public scorer must execute inside the player container, not use host Docker")


def frozen_inventory(delivery: Path) -> dict[str, Any]:
    """Hash everything that the independent reviewer approved."""
    return inventory(delivery)


def assert_frozen(delivery: Path, expected: dict[str, Any]) -> None:
    if inventory(delivery) != expected:
        raise ValueError("delivery changed after independent review; refusing Harbor acceptance")


def run_one(task: Path, selection: dict[str, Any], results: Path, args: argparse.Namespace,
            credentials: dict[str, str]) -> dict[str, Any]:
    from .harbor import accept as harbor_accept, accept_resume
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
        shutil.copy2(output / "result.json",
                     archive / ("before-resume-" + timestamp().replace(":", "-") + ".json"))
    write_json(output / "result.json", record)
    try:
        if resumable:
            record["status"] = "reviewing" if not (workspace / "review.json").is_file() else "harbor"
            write_json(output / "result.json", record)
            # Preserve the pre-resume verdict before the running status above
            # replaces it. Archiving after this point stores only a new status.
            previous_result = output / "result.json"
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
            if review_value.get("passed") is not True:
                raise ValueError("Harbor resume requires a passing independent review")
            record.update(status="harbor", route=route_value, review=review_value)
            approved = frozen_inventory(workspace / "delivery")
            with DOCKER:
                has_gold = any((output / "harbor/jobs").glob("*-gold/result.json"))
                completed_harbor = output / "harbor/result.json"
                completed = json.loads(completed_harbor.read_text(encoding="utf-8")) \
                    if completed_harbor.exists() else None
                if completed is not None and completed.get("status") != "passed":
                    archive = output / "infrastructure-attempts" / ("failed-acceptance-" + timestamp().replace(":", "-"))
                    archive.parent.mkdir(exist_ok=True)
                    os.rename(output / "harbor", archive)
                    has_gold = False
                if completed_harbor.exists() and not has_gold:
                    raise RuntimeError("Harbor resume has a result but no completed gold job")
                if (output / "harbor").exists() and not has_gold:
                    archive = output / "infrastructure-attempts" / ("resume-without-gold-" + timestamp().replace(":", "-"))
                    archive.parent.mkdir(exist_ok=True)
                    os.rename(output / "harbor", archive)
                acceptance = (accept_resume if has_gold else harbor_accept)
                record["harbor"] = acceptance(workspace, output / "harbor", task.name,
                                              route_value, args.verify_timeout)
                assert_frozen(workspace / "delivery", approved)
            record.update(status="passed" if record["harbor"]["status"] == "passed" else "failed",
                          failure_class=None if record["harbor"]["status"] == "passed" else "harbor_failed")
            return record
        else:
            retry_route = None
            if args.retry_synthesis or args.route_from or args.continue_synthesis:
                retry_route = args.route_from if args.route_from else workspace / "route.json"
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
                shutil.copytree(task / "input", workspace / "input", symlinks=True)
                # The downloaded candidate is only a starting point. Preserve
                # compact alternate patch hints for provisional route recovery.
                write_candidate_leads(workspace, selection)
                network = ROOT / "config/bare-metal-network.md"
                shutil.copyfile(network, workspace / "NETWORK.md")
            if retry_route is not None:
                if retry_route.resolve() != (workspace / "route.json").resolve():
                    shutil.copyfile(retry_route, workspace / "route.json")
                # Validate before running synthesis; the original route stays intact.
                route(workspace, selection["instance_id"])
                record["route_agent"] = {"status": "reused", "source": str(retry_route)}
            else:
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
                                     "A viable network parser does not need an ASan crash to be routed: "
                                     "an exact-size receiving-buffer over-read is a valid differential when "
                                     "the receiving code zeroes its unused capacity. Conversely, reject only "
                                     "with concrete evidence against every branch. Write route.json as soon as "
                                     "the evidence supports a concrete route; do not enumerate unrelated callers.\n"
                                     + "\n".join(evidence)[-60000:])
                record["route_agent"] = executor(route_prompt, workspace, output / "route",
                                                 model=args.model, credentials=credentials,
                                                 max_turns=args.route_turns, timeout=args.route_timeout,
                                                 network=ROOT / "config", context_chars=140000,
                                                 docker_wrap=False)
                if record["route_agent"].get("status") != "completed":
                    raise RuntimeError(f"routing agent did not complete: {record['route_agent'].get('status')}")
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
        continuation_note = ("\n\nCONTINUED SESSION: Preserve the existing delivery and fix its concrete "
                             "failures. Do not restart from source exploration. All ASan invocations and "
                             "build-time smoke tests must use symbolize=0; unbounded DEADLYSIGNAL output "
                             "is a runtime defect, not the vulnerability. Put experiment files in TASK_TMP "
                             "rather than shared /tmp filenames. Finish the full delivery and self-check.")
        if args.continue_synthesis and (workspace / "repair-request.json").is_file():
            repair = json.loads((workspace / "repair-request.json").read_text(encoding="utf-8"))
            continuation_note += ("\n\nDELIVERY REPAIR: The previous session's artifact failed validation or "
                                  "independent review. Exact error: " + str(repair.get("error", ""))
                                  + "\nIndependent findings: "
                                  + json.dumps(repair.get("review", {}).get("findings", []), ensure_ascii=False)
                                  + "\nRead the existing artifacts and fix the actual contract/oracle defects, "
                                  "including every blocker/major finding. Do not merely assert completion, "
                                  "hide the adversarial input, or weaken the review/differential. Run "
                                  "private/verify.sh, preserve its unmodified report, and exercise the "
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
        delivery = workspace / "delivery"
        frozen_delivery(delivery)
        record["status"] = "reviewing"
        write_json(output / "result.json", record)
        review_input = workspace / "review-input"
        if review_input.exists():
            shutil.rmtree(review_input)
        shutil.copytree(delivery, review_input / "delivery", symlinks=True)
        if (delivery / "verification.json").is_file():
            shutil.copyfile(delivery / "verification.json", review_input / "self-check.json")
        shutil.copyfile(output / "synthesis/trajectory.jsonl", review_input / "trajectory.jsonl")
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
                                             route_value, args.verify_timeout)
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
    parser.add_argument("--review-turns", type=int, default=60)
    parser.add_argument("--verify-timeout", type=int, default=3600)
    args = parser.parse_args()
    if not 1 <= args.concurrency <= 20:
        parser.error("concurrency must be 1..20")
    if args.review_delivery and len(args.only or []) != 1:
        parser.error("--review-delivery requires exactly one --only task")
    credentials = load_env(args.env_file)
    selected = list(read_jsonl(args.sample / "selection.jsonl"))
    if args.only:
        wanted = set(args.only)
        selected = [row for row in selected if row["task_id"] in wanted or row["canonical_id"] in wanted]
    args.results.mkdir(parents=True, exist_ok=True)
    with concurrent.futures.ThreadPoolExecutor(max_workers=args.concurrency) as pool:
        futures = [pool.submit(run_exclusive, args.sample / "tasks" / row["task_id"], row,
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
