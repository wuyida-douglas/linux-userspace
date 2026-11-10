"""Derive the frozen delivery contract from Compose, route and fixed scripts.

Compose is the only agent-owned manifest: it carries the image tags, topology
and, for FILE-POV, the public runner as the ``x-public-runner`` extension on
the client service. The controller generates ``delivery/task.json`` once,
before review/export, so every consumer validates the same frozen manifest.
"""
from __future__ import annotations

import copy
import json
from pathlib import Path
from typing import Any

import yaml

from .common import write_json
from .task_contract import load_task

INTERACTIONS = {
    "SVC-EXPLOIT": "protocol",
    "FILE-EXPLOIT": "interactive_file",
    "FILE-POV": "file_pov",
}
SUBMISSIONS = {
    "SVC-EXPLOIT": "exploit.py",
    "FILE-EXPLOIT": "exploit.py",
    "FILE-POV": "input.bin",
}


def _read_json(path: Path) -> dict[str, Any]:
    if not path.is_file():
        return {}
    value = json.loads(path.read_text(encoding="utf-8"))
    return value if isinstance(value, dict) else {}


def _healthcheck(branch: str) -> dict[str, list[str]]:
    # One stable runtime path for every branch. The verifier mounts (runner) or
    # copies (client, FILE-POV) the reviewed private/healthcheck.sh there.
    return {"argv": ["/healthcheck.sh"]}


def build_task_contract(delivery: Path, workspace: Path,
                        output: Path | None = None) -> dict[str, Any]:
    """Write and return the canonical delivery/task.json.

    Compose is authoritative for image tags, topology and the FILE-POV public
    runner. The legacy public_runner in an already-frozen task.json is
    preserved only so old deliveries can still be resumed; new deliveries must
    express it in Compose.
    """
    task_path = delivery / "task.json"
    compose_path = delivery / "environment/docker-compose.yaml"
    route_path = workspace / "route.json"
    if not compose_path.is_file():
        raise ValueError("delivery/environment/docker-compose.yaml is required to build task.json")
    if not route_path.is_file():
        raise ValueError("workspace/route.json is required to build task.json")

    compose = yaml.safe_load(compose_path.read_text(encoding="utf-8")) or {}
    services = compose.get("services") or {}
    if not isinstance(services, dict) or not {"main", "client"}.issubset(services):
        raise ValueError("public Compose must contain main and client")
    route = _read_json(route_path)
    branch = route.get("branch")
    if branch not in INTERACTIONS:
        raise ValueError(f"unsupported route branch: {branch!r}")
    host_type = route.get("host_type")
    if branch != "SVC-EXPLOIT":
        host_type = None

    legacy = _read_json(task_path)
    agent_image = (services.get("main") or {}).get("image")
    target_image = (services.get("client") or {}).get("image")
    if not agent_image:
        raise ValueError("public Compose main.image is required")
    if not target_image:
        raise ValueError("public Compose client.image is required")

    sidecars = sorted(name for name in services if name not in {"main", "client", "runner"})

    # The submission runner always reuses the main analysis image; only the
    # container configuration differs. A third runner image is not supported.
    legacy_runner = legacy.get("runner") if isinstance(legacy.get("runner"), dict) else {}
    runner: dict[str, Any] = {
        "image": None, "user": "65534:65534", "workdir": "/workspace",
        "timeout_sec": 300, "health_timeout_sec": 300, "command": [],
    }
    for key in ("user", "timeout_sec", "health_timeout_sec", "command"):
        if key in legacy_runner:
            runner[key] = copy.deepcopy(legacy_runner[key])

    public_runner = (services.get("client") or {}).get("x-public-runner")
    if public_runner is not None and not isinstance(public_runner, dict):
        raise ValueError("client x-public-runner must be an object with argv")
    if public_runner is None:
        public_runner = legacy.get("public_runner")
    if branch != "FILE-POV" and public_runner is not None:
        raise ValueError("x-public-runner is only valid for FILE-POV")

    contract: dict[str, Any] = {
        "schema_version": 1,
        "branch": branch,
        "host_type": host_type,
        "target_service": "client",
        "images": {"agent": agent_image, "target": target_image},
        "interaction": INTERACTIONS[branch],
        "submission_mode": SUBMISSIONS[branch],
        "runner": runner,
        "healthcheck": _healthcheck(branch),
        "oracle": {"argv": ["/private/oracle.sh"]},
        "solution": {"argv": ["/private/solution.sh"]},
        "restart_command": copy.deepcopy(legacy.get("restart_command") or []),
        "sidecar_services": sidecars,
        "runner_network_aliases": copy.deepcopy(legacy.get("runner_network_aliases") or []),
    }
    if branch == "FILE-POV":
        contract["public_runner"] = copy.deepcopy(public_runner)
    if branch == "FILE-POV" and not contract.get("public_runner"):
        raise ValueError("FILE-POV requires client x-public-runner.argv in public Compose")

    write_json(task_path, contract)
    canonical = load_task(task_path)
    if canonical != contract:
        write_json(task_path, canonical)
    if output is not None:
        evidence = output / "retry-evidence" / "contract-build"
        if not (evidence / "task.json").exists():
            evidence.mkdir(parents=True, exist_ok=True)
            write_json(evidence / "task.json", canonical)
    return canonical