"""Package Compose named-volume data as bind mounts before delivery review.

`docker save` stores images, and `docker commit` does not capture volumes.  The
factory therefore copies each named/anonymous volume out of its live container
into ``delivery/environment/init/volumes/<slug>`` and rewrites the public
Compose file to use those ``./`` binds.  The data then travels inside the
delivery bundle like any other public asset.
"""
from __future__ import annotations

import hashlib
import json
import os
import re
import shutil
import subprocess
import time
from pathlib import Path
from typing import Any

import yaml

ROOT = Path(__file__).resolve().parents[1]
DOCKER = ROOT / "config/bin/docker"
INIT_PREFIX = "init/volumes"
MANIFEST_REL = "project/volume-package.json"
_SAFE = re.compile(r"[^A-Za-z0-9_.-]+")


def bind_rel(volume_name: str, destination: str) -> str:
    slug = _SAFE.sub("-", (volume_name or destination or "vol").strip("/"))
    slug = slug.replace("..", "-")
    slug = re.sub(r"-{2,}", "-", slug).strip("-.")
    slug = slug or "vol"
    return f"{INIT_PREFIX}/{slug}"


def is_mysql_datadir(destination: str) -> bool:
    return str(destination or "").rstrip("/") == "/var/lib/mysql"


def named_volume_mounts(mounts: list[dict[str, Any]]) -> list[dict[str, Any]]:
    """`docker inspect .Mounts` entries that are real Docker volumes."""
    out = []
    for mount in mounts or []:
        if not isinstance(mount, dict) or str(mount.get("Type") or "") != "volume":
            continue
        if mount.get("Destination"):
            out.append(mount)
    return out


def _short_bind(item: Any) -> tuple[str, str] | None:
    if not isinstance(item, str) or ":" not in item:
        return None
    source, dest, *_rest = item.split(":")
    if source.startswith((".", "/")) or not dest.startswith("/"):
        return None
    return source, dest


def _volume_dest(item: Any) -> str:
    if isinstance(item, str):
        if ":" in item:
            parts = item.split(":")
            if len(parts) >= 2 and parts[1].startswith("/"):
                return parts[1]
        elif item.startswith("/"):
            return item  # anonymous volume declared as a bare container path
    if isinstance(item, dict):
        dest = str(item.get("target") or item.get("destination") or "")
        if dest.startswith("/"):
            return dest
    return ""


def _is_volume_item(item: Any) -> bool:
    """True for a named or anonymous volume mount, false for a host bind."""
    if isinstance(item, str):
        if ":" not in item:
            return item.startswith("/")
        source = item.split(":", 1)[0]
        return not source.startswith((".", "/"))
    if isinstance(item, dict):
        kind = str(item.get("type") or "").lower()
        if kind:
            return kind == "volume"
        source = str(item.get("source") or "")
        return bool(source) and not source.startswith((".", "/"))
    return False


def compose_has_named_volumes(compose: dict[str, Any], app_service: str = "client") -> bool:
    for name, service in (compose.get("services") or {}).items():
        if name == "main" or not isinstance(service, dict):
            continue
        if any(_is_volume_item(item) for item in service.get("volumes") or []):
            return True
    return False


def apply_volume_package(compose: dict[str, Any], rows: list[dict[str, Any]]) -> dict[str, Any]:
    """Rewrite packaged named-volume mounts to ./init/volumes binds.

    Also adds a bind for image-declared VOLUME destinations that are not in the
    Compose file, otherwise a fresh container starts with an empty volume.
    """
    if not rows:
        return compose
    binds: dict[tuple[str, str], str] = {}
    for row in rows:
        service = str(row.get("service") or "")
        dest = str(row.get("destination") or "")
        rel = str(row.get("rel") or "")
        if service and dest and rel:
            binds[(service, dest)] = rel
    services = compose.get("services")
    if not isinstance(services, dict):
        return compose
    used: set[str] = set()
    for name, service in services.items():
        if not isinstance(service, dict):
            continue
        rewritten: list[Any] = []
        covered: set[str] = set()
        for item in service.get("volumes") or []:
            short = _short_bind(item)
            rel = binds.get((name, short[1])) if short else None
            if rel:
                rewritten.append(f"./{rel}:{short[1]}")
                used.add(short[0])
                covered.add(short[1])
                continue
            if isinstance(item, dict) and str(item.get("type") or "") == "volume":
                dest = str(item.get("target") or "")
                rel = binds.get((name, dest))
                if rel and dest:
                    rewritten.append(f"./{rel}:{dest}")
                    used.add(str(item.get("source") or ""))
                    covered.add(dest)
                    continue
            dest = _volume_dest(item)
            if dest:
                covered.add(dest)
                if (name, dest) in binds:
                    continue
            rewritten.append(item)
        for (bound_service, dest), rel in binds.items():
            if bound_service != name or dest in covered:
                continue
            rewritten.append(f"./{rel}:{dest}")
        if rewritten:
            service["volumes"] = rewritten
    top = compose.get("volumes")
    if isinstance(top, dict) and used:
        compose["volumes"] = {key: value for key, value in top.items() if key not in used}
        if not compose["volumes"]:
            compose.pop("volumes", None)
    return compose


def load_manifest(delivery: Path) -> list[dict[str, Any]]:
    path = Path(delivery) / MANIFEST_REL
    try:
        value = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError):
        return []
    return value if isinstance(value, list) else []


def write_manifest(delivery: Path, rows: list[dict[str, Any]]) -> None:
    path = Path(delivery) / MANIFEST_REL
    path.parent.mkdir(parents=True, exist_ok=True)
    temporary = path.with_name(path.name + ".tmp")
    temporary.write_text(json.dumps(rows, indent=2) + "\n", encoding="utf-8")
    os.replace(temporary, path)


def _docker_env(workspace: Path) -> dict[str, str]:
    env = dict(os.environ)
    env["PATH"] = str(ROOT / "config/bin") + os.pathsep + env.get("PATH", "")
    # native_agent.run_bounded uses this exact project name for the task.
    env["COMPOSE_PROJECT_NAME"] = "lup" + hashlib.sha256(
        str(Path(workspace).resolve()).encode()).hexdigest()[:16]
    env.setdefault("PIPELINE_IPAM_ROLE", "factory")
    env.setdefault("PIPELINE_IPAM_WORK_DIR", str(Path(workspace) / ".compose-ipam"))
    env.setdefault("LC_ALL", "C.UTF-8")
    env.setdefault("LANG", "C.UTF-8")
    return env


def _run(argv: list[str], *, cwd: Path, env: dict[str, str], timeout: int = 600) -> subprocess.CompletedProcess:
    return subprocess.run([str(DOCKER), *argv], cwd=cwd, env=env, capture_output=True,
                          text=True, errors="replace", timeout=timeout)


def _services(compose: dict[str, Any]) -> list[str]:
    return [name for name, service in (compose.get("services") or {}).items()
            if name != "main" and isinstance(service, dict) and service.get("image")]


def _ensure_manifest_applied(delivery: Path, compose: dict[str, Any]) -> bool:
    """Return True when an existing manifest and all bind data are already present."""
    rows = load_manifest(delivery)
    if not rows:
        return False
    environment = delivery / "environment"
    if not all((environment / str(row.get("rel") or "")).exists() for row in rows):
        return False
    apply_volume_package(compose, rows)
    return True


def package_delivery_volumes(delivery: Path, workspace: Path) -> dict[str, Any]:
    """Copy named volumes into the delivery and rewrite Compose to ./ binds.

    No-op when the public Compose has no named/anonymous volume.  The agent's
    native executor sets COMPOSE_PROJECT_NAME from the workspace path, so the
    same project (and therefore the same named volumes) is used here.
    """
    delivery = Path(delivery)
    compose_path = delivery / "environment/docker-compose.yaml"
    if not compose_path.is_file():
        return {"packaged": 0, "reason": "missing compose"}
    compose = yaml.safe_load(compose_path.read_text(encoding="utf-8")) or {}
    if not compose_has_named_volumes(compose):
        return {"packaged": 0, "reason": "no named volumes"}

    if _ensure_manifest_applied(delivery, compose):
        temporary = compose_path.with_name(compose_path.name + ".tmp")
        temporary.write_text(yaml.safe_dump(compose, sort_keys=False), encoding="utf-8")
        os.replace(temporary, compose_path)
        return {"packaged": len(load_manifest(delivery)), "repaired": True}

    env = _docker_env(workspace)
    project = env["COMPOSE_PROJECT_NAME"]
    services = _services(compose)
    if not services:
        return {"packaged": 0, "reason": "no target services"}
    rows: list[dict[str, Any]] = []
    try:
        up = _run(["compose", "-p", project, "--project-directory",
                   str(delivery / "environment"), "-f", str(compose_path),
                   "up", "-d", "--no-build", "--wait", *services], cwd=delivery, env=env, timeout=900)
        if up.returncode:
            raise RuntimeError(f"cannot start delivery compose to package volumes: {up.stderr[-2000:]}")
        for service in services:
            listed = _run(["compose", "-p", project, "--project-directory",
                           str(delivery / "environment"), "-f", str(compose_path),
                           "ps", "-q", service], cwd=delivery, env=env, timeout=60)
            cid = listed.stdout.strip().splitlines()[0] if listed.returncode == 0 and listed.stdout.strip() else ""
            if not cid:
                continue
            inspected = _run(["inspect", "-f", "{{json .Mounts}}", cid], cwd=delivery, env=env, timeout=30)
            try:
                mounts = json.loads(inspected.stdout.strip() or "[]")
            except (ValueError, TypeError):
                mounts = []
            named = named_volume_mounts(mounts)
            if not named:
                continue
            stopped = False
            copy_error = ""
            try:
                for mount in named:
                    dest = str(mount.get("Destination") or "")
                    if is_mysql_datadir(dest) and not stopped:
                        stop = _run(["stop", "-t", "90", cid], cwd=delivery, env=env, timeout=120)
                        if stop.returncode:
                            copy_error = f"failed to stop {service} before copying {dest}: {stop.stderr[-1000:]}"
                            break
                        stopped = True
                    rel = bind_rel(str(mount.get("Name") or ""), dest)
                    host = delivery / "environment" / rel
                    if host.exists():
                        shutil.rmtree(host)
                    host.mkdir(parents=True)
                    copied = _run(["cp", f"{cid}:{dest}/.", str(host)], cwd=delivery, env=env, timeout=600)
                    if copied.returncode:
                        copy_error = f"failed to copy volume {dest} from {service}: {copied.stderr[-1000:]}"
                        break
                    rows.append({"service": service, "destination": dest, "rel": rel,
                                 "volume": str(mount.get("Name") or "")})
            finally:
                if stopped:
                    _run(["start", cid], cwd=delivery, env=env, timeout=120)
            if copy_error:
                raise RuntimeError(copy_error)
    finally:
        # Keep the named volumes: they are the only copy if packaging fails
        # midway, and the retry must be able to read them again.
        _run(["compose", "-p", project, "--project-directory",
              str(delivery / "environment"), "-f", str(compose_path),
              "down", "--remove-orphans"], cwd=delivery, env=env, timeout=300)

    if not rows:
        return {"packaged": 0, "reason": "compose started but no volume mounts were found"}
    write_manifest(delivery, rows)
    apply_volume_package(compose, rows)
    temporary = compose_path.with_name(compose_path.name + ".tmp")
    temporary.write_text(yaml.safe_dump(compose, sort_keys=False), encoding="utf-8")
    os.replace(temporary, compose_path)
    return {"packaged": len(rows), "rows": rows, "project": project}