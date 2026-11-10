"""Seal writable ``./`` bind sources and restore them between verifier phases.

The vulnerable run can write through a writable bind into the packaged
environment.  The fixed phase must see the bytes from before that run.  Export
therefore writes ``pristine-binds.tar`` once beside ``environment/``; the
differential extracts it before and after every phase.
"""
from __future__ import annotations

import os
import shutil
import subprocess
import tarfile
from pathlib import Path
from typing import Any

import yaml

PRISTINE_BINDS_TAR = "pristine-binds.tar"


def _rel(source: str) -> str:
    value = str(source or "").strip()
    if not value.startswith("./"):
        return ""
    value = value[2:].strip("/")
    return "" if not value or ".." in Path(value).parts else value


def writable_bind_rels(compose: dict[str, Any]) -> list[str]:
    """Writable ``./`` bind sources in a parsed Compose document."""
    rels: list[str] = []
    for service in (compose.get("services") or {}).values():
        if not isinstance(service, dict):
            continue
        for item in service.get("volumes") or []:
            rel = ""
            if isinstance(item, str):
                parts = item.split(":")
                if len(parts) >= 2:
                    rel = _rel(parts[0])
                    if len(parts) >= 3 and "ro" in parts[2].split(","):
                        rel = ""
            elif isinstance(item, dict) and str(item.get("type") or "") == "bind":
                rel = _rel(str(item.get("source") or ""))
                if item.get("read_only") is True:
                    rel = ""
            if rel and rel not in rels:
                rels.append(rel)
    covered: list[str] = []
    for rel in rels:
        if any(rel != other and rel.startswith(other.rstrip("/") + "/") for other in rels):
            continue
        covered.append(rel)
    return covered


def archive_path(task_dir: Path) -> Path:
    return Path(task_dir) / PRISTINE_BINDS_TAR


def create_pristine_binds_tar(task_dir: Path) -> Path | None:
    """Write the sealed archive once; never rewrite an existing one."""
    task_dir = Path(task_dir)
    environment = task_dir / "environment"
    compose_path = environment / "docker-compose.yaml"
    if not compose_path.is_file():
        return None
    compose = yaml.safe_load(compose_path.read_text(encoding="utf-8")) or {}
    rels = writable_bind_rels(compose)
    if not rels:
        return None
    archive = archive_path(task_dir)
    if archive.is_file():
        return archive
    partial = archive.with_name(archive.name + ".partial")
    partial.unlink(missing_ok=True)
    try:
        with tarfile.open(partial, "w") as output:
            for rel in rels:
                source = environment / rel
                if source.exists() or source.is_symlink():
                    output.add(source, arcname=rel, recursive=True)
        os.replace(partial, archive)
    except Exception:
        partial.unlink(missing_ok=True)
        raise
    return archive


def _safe_member(member: tarfile.TarInfo) -> tarfile.TarInfo:
    parts = Path(member.name).parts
    if not member.name or member.name.startswith("/") or ".." in parts:
        raise ValueError(f"unsafe pristine-bind member: {member.name}")
    if member.issym() or member.islnk():
        link = Path(member.linkname).parts
        if member.linkname.startswith("/") or ".." in link:
            raise ValueError(f"unsafe pristine-bind link: {member.name} -> {member.linkname}")
    if not (member.isfile() or member.isdir() or member.issym() or member.islnk()):
        raise ValueError(f"special pristine-bind member: {member.name}")
    return member


def _remove(path: Path) -> None:
    """Remove a bind path; container-root files may need passwordless sudo."""
    try:
        if path.is_symlink() or path.is_file():
            path.unlink()
        elif path.is_dir():
            shutil.rmtree(path)
    except PermissionError:
        sudo = shutil.which("sudo")
        if sudo is None:
            raise
        subprocess.run([sudo, "-n", "rm", "-rf", str(path)], check=True,
                       capture_output=True, text=True, timeout=120)


def extract_pristine_binds(task_dir: Path, environment: Path) -> bool:
    """Replace each sealed writable bind under ``environment`` from the archive."""
    task_dir = Path(task_dir)
    environment = Path(environment)
    archive = archive_path(task_dir)
    if not archive.is_file():
        return False
    compose_path = environment / "docker-compose.yaml"
    if not compose_path.is_file():
        return False
    compose = yaml.safe_load(compose_path.read_text(encoding="utf-8")) or {}
    rels = writable_bind_rels(compose)
    if not rels:
        return False
    with tarfile.open(archive, "r") as source:
        members = [_safe_member(member) for member in source.getmembers()]
        for rel in rels:
            _remove(environment / rel)
        for member in members:
            source.extract(member, environment, set_attrs=False)
            path = environment / member.name
            if member.isdir():
                path.chmod(member.mode & 0o777)
            elif member.isfile() and not member.issym():
                path.chmod(member.mode & 0o777)
    return True


def main() -> int:
    """Restore the sealed writable binds in an exported task profile."""
    import argparse
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("task_dir", type=Path,
                        help="harbor-runtime-profile directory containing pristine-binds.tar")
    parser.add_argument("--environment", type=Path,
                        help="environment directory (default: <task_dir>/environment)")
    args = parser.parse_args()
    environment = args.environment or args.task_dir / "environment"
    restored = extract_pristine_binds(args.task_dir, environment)
    print(f"restored={restored} task_dir={args.task_dir} environment={environment}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())