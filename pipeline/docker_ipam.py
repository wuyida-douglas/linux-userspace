"""Per-project Compose IPAM; never mutate the shared daemon configuration.

Factory leases and Harbor leases use disjoint pools. Overrides exist only in
runtime scratch directories, never in a reviewed or exported Compose file.
This module is copied into each self-contained verifier beside its Docker CLI.
"""
from __future__ import annotations

import fcntl
import ipaddress
import json
import os
import re
import subprocess
import time
import uuid
from pathlib import Path
from typing import Any

import yaml

POOLS = {
    "factory": ipaddress.ip_network("10.80.0.0/12"),
    "harbor": ipaddress.ip_network("10.112.0.0/12"),
}
LEASE_GRACE_SEC = 24 * 3600


def state_dir() -> Path:
    configured = os.environ.get("PIPELINE_IPAM_STATE", "").strip()
    path = Path(configured) if configured else Path(f"/tmp/linux-userspace-ipam-{os.getuid()}")
    path.mkdir(parents=True, exist_ok=True)
    return path


def _docker_networks(docker: str) -> list[ipaddress.IPv4Network]:
    listed = subprocess.run([docker, "network", "ls", "-q"], capture_output=True,
                            text=True, timeout=30)
    if listed.returncode:
        raise RuntimeError("cannot inspect Docker networks for IPAM allocation: " + listed.stderr[-1000:])
    ids = [item for item in listed.stdout.splitlines() if item.strip()]
    if not ids:
        return []
    inspected = subprocess.run(
        [docker, "network", "inspect", *ids, "--format",
         "{{range .IPAM.Config}}{{.Subnet}} {{end}}"],
        capture_output=True, text=True, timeout=60)
    if inspected.returncode:
        raise RuntimeError("cannot inspect Docker subnets for IPAM allocation: " + inspected.stderr[-1000:])
    networks = []
    for value in inspected.stdout.split():
        try:
            network = ipaddress.ip_network(value)
        except ValueError:
            continue
        if isinstance(network, ipaddress.IPv4Network):
            networks.append(network)
    return networks


def _network_subnet(docker: str, name: str) -> str:
    inspected = subprocess.run(
        [docker, "network", "inspect", name, "--format",
         "{{range .IPAM.Config}}{{.Subnet}} {{end}}"],
        capture_output=True, text=True, timeout=15)
    if inspected.returncode:
        return ""
    for value in inspected.stdout.split():
        try:
            return str(ipaddress.ip_network(value))
        except ValueError:
            pass
    return ""


def _load_leases(path: Path) -> dict[str, Any]:
    try:
        value = json.loads(path.read_text(encoding="utf-8"))
    except FileNotFoundError:
        return {}
    except (OSError, json.JSONDecodeError) as exc:
        raise RuntimeError(f"invalid IPAM lease state: {path}") from exc
    if not isinstance(value, dict):
        raise RuntimeError(f"invalid IPAM lease state: {path}")
    return value


def _save_leases(path: Path, leases: dict[str, Any]) -> None:
    temporary = path.with_name(path.name + f".{os.getpid()}.{uuid.uuid4().hex}.tmp")
    temporary.write_text(json.dumps(leases, indent=2, sort_keys=True) + "\n", encoding="utf-8")
    temporary.replace(path)


def release_compose_subnets(project: str, role: str, docker: str) -> list[str]:
    """Release only leases whose project networks have actually disappeared."""
    directory = state_dir()
    released = []
    with (directory / "leases.lock").open("a+") as handle:
        fcntl.flock(handle, fcntl.LOCK_EX)
        path = directory / "leases.json"
        leases = _load_leases(path)
        for subnet, metadata in list(leases.items()):
            if not isinstance(metadata, dict) or metadata.get("role") != role \
                    or metadata.get("project") != project:
                continue
            network = str(metadata.get("network") or "")
            if network and not _network_subnet(docker, network):
                released.append(str(subnet))
                leases.pop(subnet)
        _save_leases(path, leases)
    return released


def _allocate(requested: dict[str, str], project: str, role: str, docker: str) -> dict[str, str]:
    """Allocate all networks under one host-wide lock."""
    if role not in POOLS:
        raise ValueError(f"unsupported IPAM role: {role}")
    directory = state_dir()
    result = {}
    with (directory / "leases.lock").open("a+") as handle:
        fcntl.flock(handle, fcntl.LOCK_EX)
        path = directory / "leases.json"
        leases = _load_leases(path)
        occupied = _docker_networks(docker)
        now = time.time()
        # A live Docker network always retains its lease. Without a network,
        # retain a bounded grace period to cover compose up/recreate windows.
        for subnet, metadata in list(leases.items()):
            try:
                network = ipaddress.ip_network(subnet)
            except ValueError:
                leases.pop(subnet)
                continue
            if any(network.overlaps(other) for other in occupied):
                continue
            if not isinstance(metadata, dict) or now - float(metadata.get("timestamp", 0)) > LEASE_GRACE_SEC:
                leases.pop(subnet)
        for logical, actual in requested.items():
            owned = [(ipaddress.ip_network(subnet), metadata) for subnet, metadata in leases.items()
                     if isinstance(metadata, dict) and metadata.get("project") == project
                     and metadata.get("role") == role and metadata.get("network") == actual]
            if owned:
                subnet, metadata = owned[0]
                live = _network_subnet(docker, actual)
                if live and live != str(subnet):
                    raise RuntimeError(f"Compose network {actual} has an unexpected subnet: {live}")
                # The named network may be gone while its old subnet is now
                # occupied by another project. Reassign rather than recreating
                # a stale, overlapping lease during concurrent compose up.
                if any(subnet.overlaps(other) for other in occupied):
                    leases.pop(str(subnet), None)
                else:
                    metadata["timestamp"] = now
                    result[logical] = str(subnet)
                    continue
            blocked = [*occupied]
            for subnet, metadata in leases.items():
                try:
                    if not (isinstance(metadata, dict) and metadata.get("project") == project
                            and metadata.get("role") == role and metadata.get("network") == actual):
                        blocked.append(ipaddress.ip_network(subnet))
                except ValueError:
                    pass
            for candidate in POOLS[role].subnets(new_prefix=24):
                if any(candidate.overlaps(other) for other in blocked):
                    continue
                leases[str(candidate)] = {"project": project, "network": actual,
                                         "role": role, "timestamp": now}
                result[logical] = str(candidate)
                break
            else:
                raise RuntimeError(f"no free /24 in {POOLS[role]} for {actual}; prune stale Compose networks")
        _save_leases(path, leases)
    return result


def _project_name(argv: list[str], cwd: Path) -> str:
    for index, part in enumerate(argv):
        if part in {"--project-name", "-p"} and index + 1 < len(argv):
            return argv[index + 1]
        if part.startswith("--project-name="):
            return part.split("=", 1)[1]
    configured = os.environ.get("COMPOSE_PROJECT_NAME")
    if configured:
        return configured
    # Compose's normalized basename is sufficient for lease identity; the
    # authoritative Docker network name is still inspected before reuse.
    return re.sub(r"[^a-z0-9_-]", "", cwd.name.lower()).lstrip("_-") or "compose"


def _compose_files(argv: list[str], cwd: Path) -> list[Path]:
    files = []
    for index, part in enumerate(argv):
        if part in {"-f", "--file"} and index + 1 < len(argv):
            files.append((cwd / argv[index + 1]).resolve())
        elif part.startswith("--file="):
            files.append((cwd / part.split("=", 1)[1]).resolve())
    if files:
        return files
    return [path for name in ("compose.yaml", "compose.yml", "docker-compose.yaml", "docker-compose.yml")
            if (path := cwd / name).is_file()]


def _requested_networks(argv: list[str], cwd: Path) -> dict[str, str]:
    """Do not override application IPAM or external networks.

    Static addresses require the application's own compatible subnet; assigning
    an unrelated managed subnet would cause the exact export failure seen in
    the old factory. Such a network is left untouched and validated by Compose.
    """
    merged: dict[str, Any] = {"services": {}, "networks": {}}
    try:
        for path in _compose_files(argv, cwd):
            value = yaml.safe_load(path.read_text(encoding="utf-8")) or {}
            if not isinstance(value, dict):
                return {}
            merged["services"].update(value.get("services") or {})
            merged["networks"].update(value.get("networks") or {})
    except (OSError, yaml.YAMLError, AttributeError):
        return {}
    networks = merged["networks"]
    static = set()
    for service in merged["services"].values():
        if not isinstance(service, dict):
            return {}
        attached = service.get("networks")
        if isinstance(attached, dict):
            for name, options in attached.items():
                if isinstance(options, dict) and any(options.get(key) for key in ("ipv4_address", "ipv6_address")):
                    static.add(name)
    requested = set(networks)
    for service in merged["services"].values():
        attached = service.get("networks")
        if isinstance(attached, list):
            requested.update(str(name) for name in attached)
        elif isinstance(attached, dict):
            requested.update(attached)
    if any(not service.get("networks") for service in merged["services"].values()):
        requested.add("default")
    project = _project_name(argv, cwd)
    result = {}
    for logical in requested:
        options = networks.get(logical) or {}
        if not isinstance(options, dict) or logical in static:
            continue
        if options.get("external") or (options.get("ipam") or {}).get("config"):
            continue
        actual = options.get("name") or f"{project}_{logical}"
        result[logical] = actual
    return result


def inject_compose_ipam(argv: list[str], cwd: Path, docker: str) -> list[str]:
    if not argv or argv[0] != "compose" or not any(part in {"up", "create", "run"} for part in argv[1:]):
        return argv
    if os.environ.get("PIPELINE_IPAM_DISABLE") == "1":
        return argv
    requested = _requested_networks(argv, cwd)
    if not requested:
        return argv
    role = os.environ.get("PIPELINE_IPAM_ROLE", "factory")
    subnets = _allocate(requested, _project_name(argv, cwd), role, docker)
    scratch = Path(os.environ.get("PIPELINE_IPAM_WORK_DIR", str(cwd / ".compose-ipam")))
    scratch.mkdir(parents=True, exist_ok=True)
    name = re.sub(r"[^A-Za-z0-9_.-]", "-", "-".join(sorted(subnets))) + ".yaml"
    override = scratch / name
    networks = {logical: {"ipam": {"config": [{"subnet": subnet}]}}
                for logical, subnet in sorted(subnets.items())}
    # A late Compose file containing only networks is treated as an incomplete
    # service selection by this host's Compose version. Empty service mappings
    # preserve names without duplicating security_opt/cap_add or other list
    # values. Delivery files are never rewritten or made self-contained.
    services = {}
    for path in _compose_files(argv, cwd):
        value = yaml.safe_load(path.read_text(encoding="utf-8")) or {}
        for name in (value.get("services") or {}):
            services[str(name)] = {}
    temporary = scratch / (override.name + f".{os.getpid()}.{uuid.uuid4().hex}.tmp")
    temporary.write_text(yaml.safe_dump({"services": services, "networks": networks},
                                       sort_keys=False), encoding="utf-8")
    temporary.replace(override)
    metadata = {"schema_version": 1, "role": role, "project": _project_name(argv, cwd),
                "networks": subnets, "override": str(override), "updated_at": time.time()}
    (scratch / (override.stem + ".json")).write_text(json.dumps(metadata, indent=2) + "\n", encoding="utf-8")
    # Global compose flags accept -f; `up` does not. Insert the override
    # immediately before the subcommand and AFTER all original global files.
    # This preserves the original precedence and adds the lease last.
    insertion = next(index for index, part in enumerate(argv)
                     if part in {"up", "create", "run"})
    return [*argv[:insertion], "-f", str(override), *argv[insertion:]]
