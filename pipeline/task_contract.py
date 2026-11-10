"""The frozen, branch-specific contract between synthesis and Harbor export."""
from __future__ import annotations

import json
import re
from typing import Any

BRANCHES = {"SVC-EXPLOIT", "FILE-EXPLOIT", "FILE-POV"}
HOST_TYPES = {"native_service", "real_host", "synthetic_host"}
IMAGE_RE = re.compile(r"^[a-z0-9][a-z0-9._/-]*(?::[A-Za-z0-9_][A-Za-z0-9_.-]{0,127})?$")


def load_task(path) -> dict[str, Any]:
    """Also used by the standalone verifier, without importing pipeline code."""
    from pathlib import Path
    path = Path(path)
    if path.is_dir():
        path = path / "task.json"
    value = json.loads(path.read_text(encoding="utf-8"))
    if not isinstance(value, dict) or value.get("schema_version") != 1:
        raise ValueError("task.json schema_version must be 1")
    branch = value.get("branch")
    if branch not in BRANCHES:
        raise ValueError("unsupported task branch")
    host_type = value.get("host_type")
    if branch != "SVC-EXPLOIT" and host_type == "null":
        # Legacy string spelling is not a host selection; JSON null is the
        # canonical value persisted by route and delivery normalization.
        host_type = None
        value["host_type"] = None
    if branch == "SVC-EXPLOIT":
        if host_type not in HOST_TYPES or value.get("interaction") != "protocol":
            raise ValueError("SVC requires a valid host_type and protocol interaction")
    else:
        if host_type is not None:
            raise ValueError("FILE routes require host_type=null")
        interaction = "file_pov" if branch == "FILE-POV" else "interactive_file"
        if value.get("interaction") != interaction:
            raise ValueError(f"{branch} requires interaction={interaction}")
    submission = "input.bin" if branch == "FILE-POV" else "exploit.py"
    if value.get("submission_mode") != submission:
        raise ValueError(f"{branch} requires submission_mode={submission}")
    value.setdefault("target_service", "client")
    if value["target_service"] != "client":
        raise ValueError("target_service must be client")
    images = value.get("images")
    if not isinstance(images, dict) or not images.get("agent") or not images.get("target"):
        raise ValueError("task.json must declare agent and target images")
    for kind, image in images.items():
        if not isinstance(image, str) or not IMAGE_RE.fullmatch(image) or ".." in image:
            raise ValueError(f"invalid prebuilt image reference: {kind}")
    if images["target"] == images["agent"]:
        raise ValueError("target and agent must be separately built images")
    # One stable runtime path for every branch. The verifier mounts the reviewed
    # delivery/private/healthcheck.sh at /healthcheck.sh; legacy task.json files
    # that still name the old paths remain readable.
    if value.get("healthcheck") is None:
        value["healthcheck"] = {"argv": ["/healthcheck.sh"]}
    for key in ("healthcheck", "oracle", "solution"):
        argv(value.get(key), key)
    health_entry = value["healthcheck"]["argv"][0]
    legacy_entries = ({"/private/healthcheck.sh"} if branch == "FILE-POV"
                      else {"/opt/healthcheck/check.sh"})
    if health_entry not in {"/healthcheck.sh"} | legacy_entries:
        raise ValueError("healthcheck must name /healthcheck.sh; the verifier mounts its reviewed script there")
    runner = value.get("runner")
    if not isinstance(runner, dict):
        raise ValueError("task.json.runner must be an object")
    if runner.get("image") is not None:
        raise ValueError("runner.image must be null; the submission runner uses images.agent")
    runner.setdefault("workdir", "/workspace")
    if runner["workdir"] != "/workspace":
        raise ValueError("runner.workdir must be /workspace")
    if not isinstance(runner.get("user"), str) or not runner["user"] or runner["user"] in {"root", "0", "0:0"}:
        raise ValueError("runner.user must be an explicit unprivileged uid/gid")
    if re.fullmatch(r"[0-9]+(:[0-9]+)?", runner["user"]):
        uid, _, gid = runner["user"].partition(":")
        if int(uid) == 0 or (gid and int(gid) == 0):
            raise ValueError("runner.user must not have uid 0 or gid 0")
    runner.setdefault("timeout_sec", 300)
    if runner.get("health_timeout_sec") is None:
        runner["health_timeout_sec"] = runner.get("timeout_sec")
    if value.get("restart_command") is None:
        value["restart_command"] = []
    for key in ("timeout_sec", "health_timeout_sec"):
        if not isinstance(runner.get(key), int) or not 1 <= runner[key] <= 3600:
            raise ValueError(f"runner.{key} must be an integer in 1..3600")
    optional_argv(runner.get("command", []), "runner.command")
    if runner.get("file_capability_inheritance") is not None:
        raise ValueError("file_capability_inheritance is unsupported; use an ordinary unprivileged socket")
    optional_argv(value.get("restart_command", []), "restart_command")
    if branch == "FILE-POV":
        public_runner = argv(value.get("public_runner"), "public_runner")
        if not any("{input}" in arg for arg in public_runner):
            raise ValueError("FILE-POV public_runner.argv needs an {input} placeholder")
        if runner.get("command"):
            raise ValueError("FILE-POV uses public_runner on the target, not a runner.command")
    elif value.get("public_runner") is not None:
        raise ValueError("public_runner is only valid for FILE-POV")
    aliases = value.get("runner_network_aliases", [])
    if not isinstance(aliases, list) or len(aliases) > 8 or \
            not all(isinstance(x, str) and x and x not in {"main", "client", "runner", "localhost"} for x in aliases):
        raise ValueError("runner_network_aliases must be distinct, non-service DNS names")
    if len(set(aliases)) != len(aliases):
        raise ValueError("runner_network_aliases must not contain duplicates")
    sidecars = value.get("sidecar_services", [])
    if not isinstance(sidecars, list) or not all(isinstance(x, str) and x not in {"main", "client", "runner"} for x in sidecars):
        raise ValueError("sidecar_services must contain non-main/client/runner service names")
    return value


def normalize_sidecars(task: dict[str, Any], services: Any) -> list[str]:
    """Normalize only metadata already proved by the public Compose topology.

    This is a descriptive-metadata repair, not permission to add a sidecar.
    Every named service must actually exist, and an ambiguous or undocumented
    object remains a validation error for a bounded delivery-repair session.
    The returned canonical form is always a list of service names.
    """
    if not isinstance(services, dict) or "main" not in services or "client" not in services:
        raise ValueError("sidecar normalization requires actual main/client Compose services")
    declared = task.get("sidecar_services", [])
    if not isinstance(declared, list):
        raise ValueError("sidecar_services must be a list")
    names = []
    for item in declared:
        name = item if isinstance(item, str) else item.get("service") if isinstance(item, dict) else None
        if not isinstance(name, str) or name in {"main", "client", "runner"} \
                or name not in services or name in names:
            raise ValueError("sidecar_services must uniquely name real non-main/client/runner Compose services")
        names.append(name)
    # A plain string list already has one unambiguous meaning. Normalize the
    # documented object spelling without inventing a missing service. An
    # unknown object shape must not silently drop an intended dependency.
    if any(isinstance(item, dict) and set(item) - {"service", "image", "purpose"} for item in declared):
        raise ValueError("unsupported sidecar metadata; use service, image and purpose only")
    return names


def normalize_declared_metadata(task: dict[str, Any], route: dict[str, Any]) -> list[str]:
    """Repair only redundant metadata before freezing a completed delivery.

    This never changes a branch, execution semantics, images, or a patch. Any
    attempted route change remains a hard validation error for the reviewer.
    """
    repairs = []
    nested = task.get("route")
    if task.get("branch") is None and isinstance(nested, dict) \
            and set(nested) <= {"branch", "host_type"} \
            and nested.get("branch") == route.get("branch") \
            and nested.get("host_type") == route.get("host_type"):
        task.update(nested)
        task.pop("route")
        repairs.append("promoted route-matching branch/host_type; removed redundant route object")
    if task.get("branch") in {"SVC-EXPLOIT", "FILE-EXPLOIT"} \
            and task.get("host_type") == route.get("host_type") \
            and task.get("branch") == route.get("branch") \
            and "public_runner" in task:
        task.pop("public_runner")
        repairs.append("removed public_runner reserved for FILE-POV")
    runner = task.get("runner")
    if isinstance(runner, dict) and runner.get("health_timeout_sec") is None:
        timeout = runner.get("timeout_sec")
        if isinstance(timeout, int) and not isinstance(timeout, bool) and 1 <= timeout <= 3600:
            runner["health_timeout_sec"] = timeout
            repairs.append("defaulted runner.health_timeout_sec to runner.timeout_sec")
    if "restart_command" in task and task["restart_command"] is None:
        task["restart_command"] = []
        repairs.append("defaulted null restart_command to []")
    expected_healthcheck = {"argv": ["/healthcheck.sh"]}
    if task.get("healthcheck") != expected_healthcheck:
        task["healthcheck"] = expected_healthcheck
        repairs.append("derived healthcheck argv from branch")
    return repairs


def argv(value: Any, name: str) -> list[str]:
    if not isinstance(value, dict) or not isinstance(value.get("argv"), list) or not value["argv"] or \
            not all(isinstance(arg, str) and arg for arg in value["argv"]):
        raise ValueError(f"{name}.argv must be a nonempty string array")
    return value["argv"]


def optional_argv(value: Any, name: str) -> list[str]:
    if not isinstance(value, list) or not all(isinstance(arg, str) and arg for arg in value):
        raise ValueError(f"{name} must be a string array")
    return value


def validate_route(task: dict[str, Any], route: dict[str, Any], agent_image: str) -> None:
    route = dict(route)
    if str(route.get("branch", "")).startswith("FILE-") and route.get("host_type") == "null":
        route["host_type"] = None
    if task["branch"] != route.get("branch") or task.get("host_type") != route.get("host_type"):
        raise ValueError("task.json branch/host_type differs from route.json")
    if task["images"]["agent"] != agent_image:
        raise ValueError("task.json images.agent differs from the selected prebuilt agent image")
