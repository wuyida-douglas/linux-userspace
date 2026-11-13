#!/usr/bin/env python3
"""Per-task resource cleanup after a task reaches a final state.

A finished task leaves far more than its logs, workspace and delivery behind:
the two task images, every container/network the acceptance trials created,
the verifier scratch trees, the image tarballs in ``harbor/bundle``, and the
archived attempt directories from earlier ``--resume`` runs. Those copies are
all reproducible from the delivery, so a terminal task only needs to keep:

* ``workspace/`` (delivery, input, route, review),
* ``synthesis/``, ``review/``, ``route/`` trajectories,
* ``result.json``, ``retry-evidence/``,
* ``harbor/jobs/*/result.json``, ``trial.log``, ``verifier/evidence.json``.

Images are removed for every finished task, including ``error``, ``timeout``
and ``harbor_failed``. A later retry therefore has to rebuild the task images
from its delivery; set ``PIPELINE_KEEP_RESOURCES=1`` to keep them on purpose.

Usage (standalone, for a batch that already finished):

    python -m pipeline.resource_cleanup --results results/batch-01 --dry-run
    python -m pipeline.resource_cleanup --results results/batch-01
    python -m pipeline.resource_cleanup --results results/batch-01 --only <task>
"""
from __future__ import annotations

import argparse
import json
import os
import shutil
import subprocess
import sys
from pathlib import Path
from typing import Any

TERMINAL_STATUSES = {"passed", "rejected", "failed"}
# A task still owned by a worker must never lose the images its next phase or
# resume needs; everything else is finished and fully reproducible from the
# delivery.
IN_FLIGHT_STATUSES = {"preparing", "routing", "synthesizing", "reviewing", "harbor", "duplicate"}
PROTECTED_IMAGE_PREFIXES = ("linux-userspace-agent", "linux-userspace-verifier")
DOCKER_TIMEOUT = 120


def docker_path() -> str | None:
    for candidate in (os.environ.get("PASS2FAIL_DOCKER"), "/usr/bin/docker", shutil.which("docker")):
        if candidate and Path(candidate).is_file():
            return str(candidate)
    return None


def _run(argv: list[str], timeout: int = DOCKER_TIMEOUT) -> subprocess.CompletedProcess:
    return subprocess.run(argv, capture_output=True, text=True, errors="replace", timeout=timeout)


def _task_images(output: Path) -> list[str]:
    """Image refs this task created; shared platform images are never removed."""
    refs: list[str] = []
    sources = [output / "workspace/delivery/task.json",
               output / "harbor/accept-profile/environment/task.json"]
    for source in sources:
        try:
            images = json.loads(source.read_text(encoding="utf-8")).get("images") or {}
        except (OSError, ValueError):
            continue
        for ref in images.values():
            if not isinstance(ref, str) or not ref or ref in refs:
                continue
            if ref.startswith(PROTECTED_IMAGE_PREFIXES):
                continue
            refs.append(ref)
    return refs


def _under(path: str, root: Path) -> bool:
    if not path:
        return False
    try:
        Path(path).resolve().relative_to(root)
        return True
    except (OSError, ValueError):
        return False


def docker_snapshot(docker: str) -> dict[str, Any]:
    """One pass over the daemon so a batch cleanup does not scan per task."""
    snapshot: dict[str, Any] = {"containers": [], "networks": [], "error": None}
    # Not `ps -aq`: --quiet makes Docker ignore --format, which silently
    # turns every label into an empty string.
    listed = _run([docker, "ps", "-a", "--format",
                   '{{.ID}}\t{{.Label "com.docker.compose.project.working_dir"}}\t{{.Label "pipeline.task"}}'])
    if listed.returncode:
        snapshot["error"] = listed.stderr[-500:]
        return snapshot
    for line in listed.stdout.splitlines():
        parts = line.split("\t")
        if len(parts) < 3:
            continue
        snapshot["containers"].append((parts[0], parts[1], parts[2]))
    listed = _run([docker, "network", "ls", "-q"])
    ids = [item for item in listed.stdout.splitlines() if item.strip()] if not listed.returncode else []
    if ids:
        inspected = _run([docker, "network", "inspect", *ids, "--format",
                          '{{.Name}}\t{{index .Labels "com.docker.compose.project.working_dir"}}'],
                         timeout=180)
        if not inspected.returncode:
            for line in inspected.stdout.splitlines():
                parts = line.split("\t")
                if len(parts) >= 2 and parts[1]:
                    snapshot["networks"].append((parts[0], parts[1]))
    return snapshot


def _remove_containers(docker: str, output: Path, task_id: str, dry_run: bool,
                       snapshot: dict[str, Any] | None = None) -> dict[str, Any]:
    snapshot = snapshot or docker_snapshot(docker)
    if snapshot.get("error"):
        return {"containers_error": snapshot["error"]}
    root = output.resolve()
    selected = [container for container, working_dir, label in snapshot["containers"]
                if label == task_id or _under(working_dir, root)]
    if selected and not dry_run:
        for start in range(0, len(selected), 40):
            _run([docker, "rm", "--force", *selected[start:start + 40]], timeout=300)
    return {"containers": len(selected)}


def _remove_networks(docker: str, output: Path, dry_run: bool,
                     snapshot: dict[str, Any] | None = None) -> dict[str, Any]:
    snapshot = snapshot or docker_snapshot(docker)
    if snapshot.get("error"):
        return {"networks_error": snapshot["error"]}
    root = output.resolve()
    names = [name for name, working_dir in snapshot["networks"] if _under(working_dir, root)]
    failed: list[str] = []
    if names and not dry_run:
        # One call for the whole set: per-network calls cost a daemon round
        # trip each and used to be silently dropped when a trial had just
        # stopped its last container. Keep the failures in the report.
        for start in range(0, len(names), 40):
            batch = names[start:start + 40]
            result = _run([docker, "network", "rm", *batch], timeout=300)
            if result.returncode:
                failed.extend(line.strip() for line in result.stderr.splitlines() if line.strip())
    return {"networks": len(names), "networks_failed": failed[:20]}


def prune_idle_networks(results_root: Path, min_age_hours: float = 2.0) -> dict[str, Any]:
    """Remove Compose networks this batch left behind with no containers.

    Trials that are killed or that fail to run ``down`` leave their project
    networks attached to nothing. Docker keeps every network's subnet
    reserved, so a long batch ends up with hundreds of dead networks; the
    IPAM bulk inspect then walks all of them under a host-wide lock and every
    Compose start queues behind it (measured: 892 networks -> 11s per start).
    """
    docker = docker_path()
    if not docker:
        return {"skipped": "docker not found"}
    listed = _run([docker, "network", "ls", "-q"], timeout=60)
    ids = [item for item in listed.stdout.splitlines() if item.strip()]
    if not ids:
        return {"networks": 0}
    inspected = _run([docker, "network", "inspect", *ids, "--format",
                      '{{.Name}}\t{{index .Labels "com.docker.compose.project.working_dir"}}\t'
                      '{{len .Containers}}\t{{.Created}}'], timeout=600)
    if inspected.returncode:
        return {"error": inspected.stderr[-500:]}
    root = results_root.resolve()
    cutoff = time.time() - min_age_hours * 3600
    dead = []
    for line in inspected.stdout.splitlines():
        parts = line.split("\t")
        if len(parts) < 4:
            continue
        name, working_dir, containers, created = parts[0], parts[1], parts[2], parts[3]
        if name in ("bridge", "host", "none") or not working_dir or not _under(working_dir, root):
            continue
        if containers not in ("", "0"):
            continue
        try:
            made = time.mktime(time.strptime(created[:19], "%Y-%m-%dT%H:%M:%S"))
        except ValueError:
            continue
        if made > cutoff:
            continue
        dead.append(name)
    removed = 0
    for start in range(0, len(dead), 40):
        batch = dead[start:start + 40]
        result = _run([docker, "network", "rm", *batch], timeout=600)
        removed += len([line for line in result.stdout.splitlines() if line.strip()])
    return {"networks": len(dead), "removed": removed}


def _remove_images(docker: str, refs: list[str], dry_run: bool) -> dict[str, Any]:
    removed, failed = [], []
    for ref in refs:
        if dry_run:
            removed.append(ref)
            continue
        result = _run([docker, "image", "rm", "--force", ref], timeout=180)
        if result.returncode:
            failed.append({"ref": ref, "error": result.stderr.strip()[-200:]})
        else:
            removed.append(ref)
    return {"images": removed, "images_failed": failed}


def _remove_tree(path: Path) -> bool:
    """Remove a directory even when container builds left root-owned files."""
    if not path.exists():
        return True
    shutil.rmtree(path, ignore_errors=True)
    if not path.exists():
        return True
    sudo = shutil.which("sudo")
    if sudo:
        try:
            result = subprocess.run([sudo, "-n", "rm", "-rf", "--", str(path)],
                                    capture_output=True, text=True, timeout=300)
            if result.returncode == 0 and not path.exists():
                return True
        except (subprocess.SubprocessError, OSError):
            pass
    docker = docker_path()
    if docker:
        image = next((tag for tag in ("linux-userspace-agent:22.04", "alpine:3.19", "busybox:1.36.1-musl")
                      if _run([docker, "image", "inspect", tag], timeout=60).returncode == 0), None)
        if image:
            try:
                _run([docker, "run", "--rm", "--entrypoint", "rm", "-v",
                      f"{path.parent}:{path.parent}", image, "-rf", "--", str(path)], timeout=600)
            except (subprocess.SubprocessError, OSError):
                pass
    return not path.exists()


def _remove_scratch(output: Path, finished: bool, dry_run: bool) -> list[str]:
    """Remove reproducible scratch; keep the small evidence files."""
    removed: list[str] = []
    candidates = [
        output / "harbor/accept-profile",
        output / "harbor/bundle",
        output / "harbor/frozen-delivery",
    ]
    for job in (output / "harbor/jobs").glob("*"):
        candidates.extend(job.glob("*/verifier/work"))
    for attempt in (output / "infrastructure-attempts").glob("*"):
        candidates.extend([attempt / "bundle", attempt / "accept-profile"])
        for job in (attempt / "jobs").glob("*"):
            candidates.extend(job.glob("*/verifier/work"))
    if finished:
        candidates.append(output / "workspace/.agent-tmp")
    for path in candidates:
        if not path.exists():
            continue
        removed.append(str(path.relative_to(output)))
        if not dry_run:
            if path.is_dir() and not path.is_symlink():
                _remove_tree(path)
            else:
                try:
                    path.unlink()
                except OSError:
                    pass
    return removed


def cleanup_task(task_id: str, output: Path, record: dict[str, Any] | None = None,
                 dry_run: bool = False, snapshot: dict[str, Any] | None = None,
                 force: bool = False) -> dict[str, Any]:
    """Release one task's containers, networks, images and scratch trees."""
    if os.environ.get("PIPELINE_KEEP_RESOURCES") == "1":
        return {"task_id": task_id, "skipped": "PIPELINE_KEEP_RESOURCES=1"}
    output = output.resolve()
    status = str((record or {}).get("status") or "")
    finished = force or (bool(status) and status not in IN_FLIGHT_STATUSES)
    report: dict[str, Any] = {"task_id": task_id, "status": status, "finished": finished,
                              "dry_run": dry_run}
    if not finished:
        # A live task still needs its images and scratch for the next phase.
        report["skipped"] = "in-flight"
        return report
    docker = docker_path()
    if docker:
        try:
            snapshot = snapshot or docker_snapshot(docker)
            report.update(_remove_containers(docker, output, task_id, dry_run, snapshot))
        except Exception as exc:  # cleanup must never change a task's verdict
            report["containers_error"] = f"{type(exc).__name__}: {exc}"
        try:
            report.update(_remove_networks(docker, output, dry_run, snapshot))
        except Exception as exc:
            report["networks_error"] = f"{type(exc).__name__}: {exc}"
        try:
            report.update(_remove_images(docker, _task_images(output), dry_run))
        except Exception as exc:
            report["images_error"] = f"{type(exc).__name__}: {exc}"
    else:
        report["docker_missing"] = True
    report["scratch"] = _remove_scratch(output, True, dry_run)
    if not dry_run:
        try:
            (output / "cleanup.json").write_text(
                json.dumps(report, ensure_ascii=False, indent=2) + "\n", encoding="utf-8")
        except OSError:
            pass
    return report


def data_disk_free_gb() -> float:
    """Free space on the disk holding docker's data root, in GiB."""
    for candidate in (os.environ.get("PIPELINE_DATA_DISK"), "/nvme", "/"):
        if candidate and Path(candidate).is_dir():
            try:
                return round(shutil.disk_usage(candidate).free / 1024 ** 3, 1)
            except OSError:
                continue
    return 0.0


def prune_build_cache(until: str = "1h", dry_run: bool = False) -> dict[str, Any]:
    """Drop idle build-cache entries.

    Every task builds its own images once; an idle cache entry is never reused
    by another task, so the cache is pure disk growth (~130GB/h at concurrency
    80). It is bounded from the housekeeping loop by pruning entries older
    than ``until`` once free space drops below the high-water mark, and fully
    pruned at batch end. The prune holds the containerd content-store lock, so
    keep ``until`` well above the runtime of a single task.
    """
    docker = docker_path()
    if not docker:
        return {"skipped": "docker not found"}
    argv = [docker, "builder", "prune", "--force", "--filter", f"until={until}"]
    if dry_run:
        return {"command": argv}
    result = _run(argv, timeout=3600)
    return {"returncode": result.returncode,
            "output": (result.stdout + result.stderr)[-2000:]}


def prune_unused_volumes(dry_run: bool = False) -> dict[str, Any]:
    """Remove anonymous volumes left by killed Compose trials.

    Compose removes its named volumes on ``down --volumes``; a trial killed by
    a timeout leaves anonymous volumes behind with no label that could tie
    them to a task. At batch end nothing references them, so prune is safe.
    """
    docker = docker_path()
    if not docker:
        return {"skipped": "docker not found"}
    argv = [docker, "volume", "prune", "--force"]
    if dry_run:
        return {"command": argv}
    result = _run(argv, timeout=1800)
    return {"returncode": result.returncode,
            "output": (result.stdout + result.stderr)[-2000:]}


def prune_temp_leftovers(older_than_hours: int = 24, dry_run: bool = False) -> dict[str, Any]:
    """Drop old pip/build unpack directories and agent session output."""
    import tempfile
    import time as _time
    root = Path(tempfile.gettempdir())
    if not root.is_dir():
        return {"skipped": "no tmpdir"}
    cutoff = _time.time() - older_than_hours * 3600
    removed = []
    for path in root.iterdir():
        if not (path.name.startswith("pip-unpack-") or path.name.startswith("pip-req-build-")
                or (path.name.startswith("claude-") and path.is_dir())):
            continue
        try:
            if path.stat().st_mtime >= cutoff:
                continue
        except OSError:
            continue
        removed.append(path.name)
        if not dry_run:
            _remove_tree(path)
    return {"removed": removed}


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--results", type=Path, required=True)
    parser.add_argument("--only", nargs="*", help="task ids; default: every terminal task")
    parser.add_argument("--dry-run", action="store_true")
    parser.add_argument("--include-in-flight", action="store_true",
                        help="treat tasks without a live worker as finished (stopped batch)")
    parser.add_argument("--prune-volumes", action="store_true",
                        help="also remove unused anonymous Docker volumes (batch end)")
    parser.add_argument("--prune-cache", action="store_true",
                        help="also prune build cache older than --prune-until (run when idle)")
    parser.add_argument("--prune-until", default="1h")
    parser.add_argument("--prune-networks", action="store_true",
                        help="remove idle Compose networks under --results (safe while running)")
    parser.add_argument("--network-min-age-hours", type=float, default=2.0)
    args = parser.parse_args()
    results = args.results.resolve()
    wanted = set(args.only or [])
    total = {"tasks": 0, "containers": 0, "networks": 0, "images": 0, "scratch": 0}
    docker = docker_path()
    snapshot = docker_snapshot(docker) if docker else None
    for record_path in sorted(results.glob("*/result.json")):
        task_id = record_path.parent.name
        if wanted and task_id not in wanted:
            continue
        try:
            record = json.loads(record_path.read_text(encoding="utf-8"))
        except (OSError, ValueError):
            continue
        status = str(record.get("status") or "")
        if not status:
            continue
        if status in IN_FLIGHT_STATUSES and not args.include_in_flight:
            continue
        report = cleanup_task(task_id, record_path.parent, record, dry_run=args.dry_run,
                              snapshot=snapshot,
                              force=args.include_in_flight and status in IN_FLIGHT_STATUSES)
        total["tasks"] += 1
        total["containers"] += int(report.get("containers") or 0)
        total["networks"] += int(report.get("networks") or 0)
        total["images"] += len(report.get("images") or [])
        total["scratch"] += len(report.get("scratch") or [])
        if args.dry_run:
            print(task_id, {k: v for k, v in report.items() if k in ("containers", "networks", "images", "scratch")})
    if args.prune_volumes:
        total["volumes"] = prune_unused_volumes(dry_run=args.dry_run)
    if args.prune_cache:
        total["build_cache"] = prune_build_cache(args.prune_until, dry_run=args.dry_run)
    if args.prune_networks:
        total["idle_networks"] = prune_idle_networks(results, args.network_min_age_hours)
    print(json.dumps(total, ensure_ascii=False))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())