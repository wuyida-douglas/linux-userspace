#!/usr/bin/env python3
"""Static and optional runtime checks for a Feishu-format Harbor export bundle.

This script is intentionally self-contained: it validates the delivered bundle
without importing the synthesis pipeline or trusting the pipeline's own state.
It does not modify the bundle. Docker is only used with --deep.
"""
from __future__ import annotations

import argparse
import hashlib
import json
import os
import re
import subprocess
import sys
import tarfile
import tomllib
from pathlib import Path
from typing import Any

try:
    import yaml
except ImportError:  # pragma: no cover - the skill environment normally has PyYAML
    yaml = None

OFFICIAL_AGENT = "linux-userspace-agent:22.04"
SHARED = "shared-images"
SKIP_TOP = {"bin", SHARED, ".staging", "config"}
PROFILE_BIN = (
    "pass2fail_verifier.py",
    "legacy_pass2fail_verifier.py",
    "pristine_binds.py",
    "docker_ipam.py",
    "task_contract.py",
    "__init__.py",
)
PROXY_CREDENTIAL_RE = re.compile(r"https?://[^/\s:@]+:[^/\s@]+@")
FORBIDDEN_LAYER_PATH_RE = re.compile(
    r"(^|/)(private|gold)(/|$)|"
    r"(^|/)(patch\.diff|fix\.diff|solution\.sh|oracle\.sh|healthcheck\.sh|"
    r"gold-input[^/]*|exploit\.car)(/|$)"
)
FORBIDDEN_COMPOSE_KEYS = {
    "build", "privileged", "pid", "network_mode", "cap_add", "cap_drop",
    "devices", "security_opt", "cgroup_parent", "ipc", "uts", "container_name",
}
PROXY_KEYS = {"HTTP_PROXY", "HTTPS_PROXY", "http_proxy", "https_proxy", "NO_PROXY", "no_proxy"}


class Report:
    def __init__(self) -> None:
        self.rows: list[dict[str, str]] = []

    def add(self, level: str, task: str, check: str, message: str) -> None:
        self.rows.append({"level": level, "task": task, "check": check, "message": message})

    def fail(self, task: str, check: str, message: str) -> None:
        self.add("FAIL", task, check, message)

    def warn(self, task: str, check: str, message: str) -> None:
        self.add("WARN", task, check, message)

    def counts(self) -> dict[str, int]:
        return {level: sum(1 for row in self.rows if row["level"] == level)
                for level in ("FAIL", "WARN", "PASS")}


def sha256(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as handle:
        for block in iter(lambda: handle.read(1024 * 1024), b""):
            digest.update(block)
    return digest.hexdigest()


def read_json(path: Path) -> Any:
    return json.loads(path.read_text(encoding="utf-8"))


def archive_path(task_dir: Path, archive: str, root: Path) -> Path:
    path = (task_dir / archive).resolve()
    try:
        path.relative_to(root.resolve())
    except ValueError as exc:
        raise ValueError(f"archive escapes bundle root: {archive}") from exc
    return path


def load_manifest(task_dir: Path) -> dict[str, Any] | None:
    path = task_dir / "images/manifest.json"
    return read_json(path) if path.is_file() else None


def check_archive(entry: dict[str, Any], task_dir: Path, root: Path,
                  report: Report, task: str, *, do_hash: bool) -> Path | None:
    archive = entry.get("archive")
    ref = entry.get("ref")
    if not isinstance(archive, str) or not archive or not isinstance(ref, str) or not ref:
        report.fail(task, "image-lock", f"entry needs ref and archive: {entry!r}")
        return None
    try:
        path = archive_path(task_dir, archive, root)
    except ValueError as exc:
        report.fail(task, "image-lock", str(exc))
        return None
    if not path.is_file() or path.stat().st_size == 0:
        report.fail(task, "image-lock", f"missing or empty archive: {path}")
        return None
    if do_hash and entry.get("sha256") and sha256(path) != entry["sha256"]:
        report.fail(task, "image-lock", f"sha256 mismatch: {path}")
    return path


def check_root(root: Path, report: Report) -> list[Path]:
    if not root.is_dir():
        report.fail("-", "root", f"not a directory: {root}")
        return []
    load_image = root / "bin/load_image.py"
    if not load_image.is_file():
        report.fail("-", "layout", f"missing {load_image}")
    if (root / "bin/load_shared_images.py").exists():
        report.warn("-", "layout", "obsolete bin/load_shared_images.py; Feishu layout only needs bin/load_image.py")
    if not (root / SHARED).is_dir():
        report.fail("-", "layout", f"missing {SHARED}/")
    tasks = sorted(p for p in root.iterdir()
                   if p.is_dir() and p.name not in SKIP_TOP)
    ids = {p.name for p in tasks}
    if not (root / "task_id_all.jsonl").is_file():
        report.fail("-", "layout", "missing task_id_all.jsonl")
    else:
        listed = set()
        for line in (root / "task_id_all.jsonl").read_text(encoding="utf-8").splitlines():
            if not line.strip():
                continue
            try:
                listed.add(json.loads(line)["task_id"])
            except (ValueError, KeyError, TypeError):
                report.fail("-", "layout", f"bad task_id_all.jsonl line: {line[:120]}")
        if listed != ids:
            report.fail("-", "layout",
                        f"task_id_all mismatch: only_file={sorted(listed - ids)[:5]} "
                        f"only_dir={sorted(ids - listed)[:5]}")
    manifest_path = root / "manifest.json"
    if manifest_path.is_file():
        try:
            manifest = read_json(manifest_path)
            mtasks = {item["task_id"] for item in manifest.get("tasks", [])}
            if mtasks != ids:
                report.fail("-", "manifest", f"manifest task ids differ from directories: {sorted(mtasks ^ ids)[:8]}")
        except (ValueError, KeyError, TypeError) as exc:
            report.fail("-", "manifest", f"cannot parse manifest.json: {exc}")
    staging = root / ".staging"
    if staging.is_dir() and any(staging.iterdir()):
        report.warn("-", "layout", "non-empty .staging directory")
    if (root / "_runtime").exists():
        report.warn("-", "layout", "_runtime exists; new Feishu layout uses shared-images/")
    return tasks


def check_shared(root: Path, report: Report, needed: set[str]) -> None:
    shared = root / SHARED
    if not shared.is_dir():
        return
    manifests = {}
    for path in shared.glob("*.tar.manifest.json"):
        try:
            record = read_json(path).get("archive") or {}
            file = record.get("file")
            if file:
                manifests[file] = record
        except (ValueError, OSError):
            report.fail("-", "shared-images", f"bad manifest: {path}")
    for path in sorted(shared.glob("*.tar.gz")):
        if path.name not in manifests:
            report.warn("-", "shared-images", f"archive has no manifest: {path.name}")
            continue
        record = manifests[path.name]
        if record.get("sha256") and sha256(path) != record["sha256"]:
            report.fail("-", "shared-images", f"sha256 mismatch: {path.name}")
    for name in needed:
        if not (shared / name).is_file():
            report.fail("-", "shared-images", f"referenced shared image archive is missing: {name}")


def check_task(task_dir: Path, root: Path, report: Report, *, do_hash: bool) -> None:
    task = task_dir.name
    required = (
        "image-lock.json",
        "images/manifest.json",
        "harbor-runtime-profile/task.toml",
        "harbor-runtime-profile/instruction.md",
        "harbor-runtime-profile/environment/docker-compose.yaml",
        "harbor-runtime-profile/tests/test.sh",
    )
    for rel in required:
        if not (task_dir / rel).is_file():
            report.fail(task, "layout", f"missing {rel}")
    profile = task_dir / "harbor-runtime-profile"
    for name in PROFILE_BIN:
        if not (profile / "bin" / name).is_file():
            report.fail(task, "self-contained", f"profile/bin missing {name}")
    if (profile / "bin/load_shared_images.py").exists():
        report.warn(task, "self-contained", "profile has obsolete load_shared_images.py")
    for path in profile.rglob("*"):
        if path.is_file() and path.name.startswith("Dockerfile"):
            # Inert build material is allowed in the bundle; acceptance still
            # uses the prebuilt images from image-lock.json.
            report.warn(task, "layout", f"Dockerfile in delivery (allowed): {path.relative_to(profile)}")
        if path.is_file() and path.suffix in {".py", ".sh", ".md", ".toml", ".yaml", ".json"}:
            try:
                text = path.read_text(encoding="utf-8", errors="replace")
            except OSError:
                continue
            if "/nvme/wuyida" in text:
                report.warn(task, "self-contained", f"host absolute path in {path.relative_to(profile)}")
            if "ANTHROPIC_AUTH_TOKEN" in text or "ANTHROPIC_API_KEY" in text:
                report.warn(task, "secrets", f"credential-looking text in {path.relative_to(profile)}")
    if (profile / "instruction.md").stat().st_size == 0 if (profile / "instruction.md").is_file() else True:
        report.fail(task, "layout", "empty instruction.md")

    lock_path = task_dir / "image-lock.json"
    if not lock_path.is_file():
        return
    try:
        lock = read_json(lock_path)
        entries = lock.get("images")
        if not isinstance(entries, list) or not entries:
            raise ValueError("no images")
    except (ValueError, OSError, TypeError) as exc:
        report.fail(task, "image-lock", f"cannot parse: {exc}")
        return
    roles: dict[str, str] = {}
    needed_shared: set[str] = set()
    for entry in entries:
        role = str(entry.get("role") or "")
        path = check_archive(entry, task_dir, root, report, task, do_hash=do_hash)
        if role:
            if role in roles:
                report.warn(task, "image-lock", f"duplicate role {role}")
            roles[role] = str(entry.get("ref") or "")
        if path is not None and path.parent == (root / SHARED).resolve():
            needed_shared.add(path.name)
    for role in ("target", "agent", "verifier"):
        if role not in roles:
            report.fail(task, "image-lock", f"missing role {role}")
    if "target" in roles and "agent" in roles and roles["target"] == roles["agent"]:
        report.fail(task, "image-lock", "target and agent use the same image")

    manifest = load_manifest(task_dir)
    if manifest is not None:
        records = manifest.get("archives") or []
        listed = {str(record.get("file")) for record in records}
        actual = {path.name for path in (task_dir / "images").glob("*.tar.gz")}
        if listed != actual:
            report.fail(task, "images", f"manifest/archive mismatch: manifest={sorted(listed)} actual={sorted(actual)}")
        for record in records:
            path = task_dir / "images" / str(record.get("file"))
            if not path.is_file() or (do_hash and record.get("sha256") and sha256(path) != record["sha256"]):
                report.fail(task, "images", f"bad archive for manifest record: {record.get('file')}")

    # Public contract files are optional but, when present, must agree with image-lock.
    public_task = profile / "environment/task.json"
    if public_task.is_file():
        try:
            contract = read_json(public_task)
            images = contract.get("images") or {}
            if images.get("target") and roles.get("target") and images["target"] != roles["target"]:
                report.fail(task, "contract", "environment/task.json target differs from image-lock")
            if images.get("agent") and roles.get("agent") and images["agent"] != roles["agent"]:
                report.fail(task, "contract", "environment/task.json agent differs from image-lock")
        except (ValueError, OSError, TypeError) as exc:
            report.warn(task, "contract", f"cannot parse environment/task.json: {exc}")
    check_shared(root, report, needed_shared)


def check_toml(task_dir: Path, report: Report) -> None:
    task = task_dir.name
    path = task_dir / "harbor-runtime-profile/task.toml"
    if not path.is_file():
        return
    try:
        config = tomllib.loads(path.read_text(encoding="utf-8"))
    except (tomllib.TOMLDecodeError, OSError) as exc:
        report.fail(task, "task.toml", f"cannot parse: {exc}")
        return
    for section in ("verifier", "agent", "environment"):
        value = config.get(section) or {}
        if "timeout_sec" in value:
            report.fail(task, "task.toml", f"[{section}] timeout_sec must not be set")
        mode = value.get("network_mode")
        if mode not in (None, "public"):
            report.fail(task, "task.toml", f"[{section}] network_mode must be public")
    verifier = config.get("verifier") or {}
    verifier_env = verifier.get("environment") or {}
    if "timeout_sec" in verifier_env:
        report.fail(task, "task.toml", "[verifier.environment] timeout_sec must not be set")
    if verifier_env.get("network_mode") not in (None, "public"):
        report.fail(task, "task.toml", "[verifier.environment] network_mode must be public")
    if verifier.get("environment_mode") != "separate":
        report.fail(task, "task.toml", "verifier.environment_mode must be separate")
    if "import_path" in verifier:
        report.fail(task, "task.toml", "verifier.import_path must not be set")
    if not config.get("artifacts"):
        report.fail(task, "task.toml", "missing artifacts")


def check_compose(task_dir: Path, report: Report) -> None:
    task = task_dir.name
    if yaml is None:
        report.fail(task, "compose", "PyYAML is not installed")
        return
    path = task_dir / "harbor-runtime-profile/environment/docker-compose.yaml"
    if not path.is_file():
        return
    try:
        value = yaml.safe_load(path.read_text(encoding="utf-8")) or {}
    except yaml.YAMLError as exc:
        report.fail(task, "compose", f"cannot parse: {exc}")
        return
    services = value.get("services") or {}
    if not isinstance(services, dict) or not {"main", "client"}.issubset(services):
        report.fail(task, "compose", "must contain main and client")
        return
    if "runner" in services:
        report.fail(task, "compose", "must not expose runner")
    for name, service in services.items():
        if not isinstance(service, dict):
            report.fail(task, "compose", f"{name} is not a mapping")
            continue
        for key in FORBIDDEN_COMPOSE_KEYS:
            if key in service:
                report.fail(task, "compose", f"{name} contains {key}")
        if service.get("ports"):
            report.fail(task, "compose", f"{name} publishes host ports")
        environment = service.get("environment") or {}
        keys = set(environment) if isinstance(environment, dict) else {
            str(item).split("=", 1)[0] for item in environment}
        if keys & PROXY_KEYS:
            report.fail(task, "compose", f"{name} contains proxy environment")
        health = service.get("healthcheck") or {}
        if health.get("disable") is True or not health.get("test"):
            report.fail(task, "compose", f"{name} has no enabled healthcheck")
        for volume in service.get("volumes") or []:
            source = volume.get("source") if isinstance(volume, dict) else str(volume).split(":", 1)[0]
            if not isinstance(source, str):
                report.fail(task, "compose", f"{name} volume source is not a string")
                continue
            if not source.startswith("./"):
                report.fail(task, "compose", f"{name} has non-./ mount source: {source}")
            if any(part in source for part in ("private", "gold", "fixed", "docker.sock")):
                report.fail(task, "compose", f"{name} mounts private material: {source}")
    if value.get("volumes"):
        report.warn(task, "compose", "top-level named volumes remain; verify they are packaged as files")
    agent = None
    try:
        lock = read_json(task_dir / "image-lock.json")
        agent = next((entry.get("ref") for entry in lock.get("images", [])
                      if entry.get("role") == "agent"), None)
    except (OSError, ValueError, TypeError):
        pass
    main = services.get("main") or {}
    client = services.get("client") or {}
    if main.get("image") and agent and main["image"] != agent:
        report.fail(task, "compose", "main.image differs from image-lock agent")
    target = None
    try:
        lock = read_json(task_dir / "image-lock.json")
        target = next((entry.get("ref") for entry in lock.get("images", [])
                       if entry.get("role") == "target"), None)
    except (OSError, ValueError, TypeError):
        pass
    if target and client.get("image") != target:
        report.fail(task, "compose", "client.image differs from image-lock target")


def check_acceptance(task_dir: Path, report: Report) -> None:
    task = task_dir.name
    # acceptance.json is no longer written by the pipeline. If an older bundle
    # has one, validate it; otherwise the harbor/result.json + verifier
    # evidence is the acceptance record.
    path = task_dir / "acceptance.json"
    if not path.is_file():
        return
    try:
        value = read_json(path)
    except (OSError, ValueError, TypeError) as exc:
        report.fail(task, "acceptance", f"cannot parse: {exc}")
        return
    if value.get("status") != "passed":
        report.fail(task, "acceptance", f"status is {value.get('status')!r}, not passed")
    runs = value.get("acceptance_runs") or []
    if len(runs) != 2:
        report.fail(task, "acceptance", f"expected 2 acceptance runs, got {len(runs)}")
    else:
        rewards = [run.get("reward") for run in runs]
        if any(reward != 1.0 for reward in rewards):
            report.fail(task, "acceptance", f"acceptance rewards are {rewards}, expected [1.0, 1.0]")


def scan_tar_private(path: Path, report: Report, task: str) -> None:
    try:
        with tarfile.open(path, "r:gz") as outer:
            for member in outer:
                if not member.isfile() or not member.name.endswith(".tar"):
                    continue
                stream = outer.extractfile(member)
                if stream is None:
                    continue
                try:
                    layer = tarfile.open(fileobj=stream, mode="r|*")
                except tarfile.TarError:
                    continue
                with layer:
                    for item in layer:
                        name = item.name.lstrip("./")
                        if FORBIDDEN_LAYER_PATH_RE.search("/" + name):
                            report.fail(task, "target-hygiene",
                                        f"private delivery path in target image: /{name}")
                            return
    except (OSError, tarfile.TarError) as exc:
        report.warn(task, "target-hygiene", f"cannot scan target archive: {exc}")


def scan_image_proxy(ref: str, report: Report, task: str) -> None:
    try:
        cp = subprocess.run(["docker", "image", "inspect", ref],
                            capture_output=True, text=True, timeout=60)
    except (OSError, subprocess.TimeoutExpired) as exc:
        report.warn(task, "image-hygiene", f"cannot inspect {ref}: {exc}")
        return
    if cp.returncode:
        report.warn(task, "image-hygiene", f"image not loaded or missing: {ref}")
        return
    if PROXY_CREDENTIAL_RE.search(cp.stdout):
        report.fail(task, "image-hygiene", f"proxy credential in image config/history: {ref}")


def check_deep(task_dir: Path, root: Path, report: Report) -> None:
    task = task_dir.name
    try:
        lock = read_json(task_dir / "image-lock.json")
        entries = lock.get("images") or []
    except (OSError, ValueError, TypeError):
        return
    for entry in entries:
        ref = entry.get("ref")
        role = entry.get("role")
        if isinstance(ref, str) and ref:
            scan_image_proxy(ref, report, task)
        if role == "target" and isinstance(entry.get("archive"), str):
            path = archive_path(task_dir, entry["archive"], root)
            if path.is_file():
                scan_tar_private(path, report, task)


def summarise(root: Path, report: Report, tasks: list[Path], *, do_hash: bool) -> dict[str, Any]:
    official = 0
    dedicated = 0
    branches: dict[str, int] = {}
    for task_dir in tasks:
        try:
            lock = read_json(task_dir / "image-lock.json")
            agent = next((entry.get("ref") for entry in lock.get("images", [])
                          if entry.get("role") == "agent"), "")
            if agent == OFFICIAL_AGENT:
                official += 1
            else:
                dedicated += 1
        except (OSError, ValueError, TypeError):
            pass
        try:
            profile = task_dir / "harbor-runtime-profile/task.toml"
            config = tomllib.loads(profile.read_text(encoding="utf-8"))
            branch = str((config.get("metadata") or {}).get("branch") or "?")
            branches[branch] = branches.get(branch, 0) + 1
        except (OSError, ValueError, tomllib.TOMLDecodeError):
            pass
    counts = report.counts()
    return {
        "root": str(root),
        "tasks": len(tasks),
        "official_main": official,
        "dedicated_main": dedicated,
        "branches": branches,
        "fail": counts["FAIL"],
        "warn": counts["WARN"],
        "rows": report.rows,
    }


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("root", type=Path, help="export bundle root, e.g. harbor_export/20261111-production")
    parser.add_argument("--task", help="check only tasks whose name contains this string")
    parser.add_argument("--no-hash", action="store_true", help="skip archive sha256 verification")
    parser.add_argument("--deep", action="store_true", help="scan target layer paths and image configs; needs Docker")
    parser.add_argument("--json", type=Path, help="write a JSON report")
    args = parser.parse_args()
    root = args.root.resolve()
    report = Report()
    tasks = check_root(root, report)
    if args.task:
        tasks = [task for task in tasks if args.task.lower() in task.name.lower()]
    for task_dir in tasks:
        check_task(task_dir, root, report, do_hash=not args.no_hash)
        check_toml(task_dir, report)
        check_compose(task_dir, report)
        check_acceptance(task_dir, report)
        # Shared images are needed only by references; collect once per task.
        if args.deep:
            check_deep(task_dir, root, report)
    summary = summarise(root, report, tasks, do_hash=not args.no_hash)
    for row in report.rows:
        print(f"[{row['level']}] {row['task']}: {row['check']}: {row['message']}")
    print(f"\nchecked {summary['tasks']} tasks; fail={summary['fail']} warn={summary['warn']}; "
          f"official_main={summary['official_main']} dedicated_main={summary['dedicated_main']}; "
          f"branches={summary['branches']}")
    if args.json:
        args.json.write_text(json.dumps(summary, ensure_ascii=False, indent=2) + "\n", encoding="utf-8")
        print(f"json: {args.json}")
    return 1 if summary["fail"] else 0


if __name__ == "__main__":
    raise SystemExit(main())