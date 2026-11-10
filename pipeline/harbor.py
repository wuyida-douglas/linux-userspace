#!/usr/bin/env python3
"""Export a sealed main+client bundle and execute its real separate verifier."""
from __future__ import annotations

import argparse
import gzip
import json
import os
import re
import shutil
import subprocess
import tarfile
from pathlib import Path
from typing import Any

import yaml

from .common import export_task_id, sha256 as digest_file
from .common import timestamp, write_json
from .pristine_binds import create_pristine_binds_tar, extract_pristine_binds
from .docker_cli import docker_argv
from .runtime_images import AGENT_IMAGE, VERIFIER_IMAGE
from .task_contract import load_task, validate_route

ROOT = Path(__file__).resolve().parents[1]
TASK_TOML = '''version = "1.0"
artifacts = ["/workspace/{submission}"]

[task]
name = "linux-userspace/{task_id}"
description = "Linux userspace vulnerability in an isolated target container"
authors = []
keywords = ["linux-userspace", "{branch}", "differential"]

[metadata]
task_id = "{task_id}"
branch = "{branch}"
host_type = "{host_type}"
interaction = "{interaction}"
submission_mode = "{submission}"
bundle_schema = "1"
visibility_mode = "separate-private-verifier"

[verifier]
topology = "compose_public"
environment_mode = "separate"

[verifier.environment]
docker_image = "{verifier_image}"
network_mode = "public"

[environment]
docker_image = "{agent_image}"
gpus = 0
cpus = 2
memory_mb = 8192
storage_mb = 32768
network_mode = "public"
'''


def inspect_image(image: str) -> dict[str, Any]:
    cp = subprocess.run(docker_argv(["docker", "image", "inspect", image]),
                        capture_output=True, text=True, timeout=60)
    if cp.returncode:
        raise RuntimeError(f"prebuilt image is missing; refusing Dockerfile rebuild: {image}")
    value = json.loads(cp.stdout)[0]
    return {"image": image, "image_id": value["Id"],
            "repo_tags": value.get("RepoTags") or [], "repo_digests": value.get("RepoDigests") or [],
            "architecture": value.get("Architecture"), "os": value.get("Os")}


def safe_asset(root: Path, relative: str) -> Path:
    path = Path(relative)
    if path.is_absolute() or ".." in path.parts or str(path).startswith("/"):
        raise ValueError(f"unsafe Compose bind source: {relative}")
    source = root / path
    if source.is_symlink() or not source.exists():
        raise ValueError(f"missing or unsafe Compose asset: {relative}")
    if not source.resolve().is_relative_to(root.resolve()):
        raise ValueError(f"Compose asset escapes its environment: {relative}")
    return source


def volume_source(volume: Any) -> str:
    """Support both Compose short and long volume syntax without losing binds."""
    source = volume.get("source") if isinstance(volume, dict) else volume
    if not isinstance(source, str):
        raise ValueError("Compose volume source must be a string")
    # A named volume is not an environment-relative asset. Only a short-form
    # explicit ./ or ../ path is a bind; absolute paths remain rejected below.
    return source.split(":", 1)[0]


FORBIDDEN_COMPOSE_KEYS = {"build", "privileged", "pid", "network_mode", "cap_add",
                          "cap_drop", "devices", "security_opt", "cgroup_parent", "ipc", "uts"}
PROXY_ENV_KEYS = {"HTTP_PROXY", "HTTPS_PROXY", "http_proxy", "https_proxy",
                  "NO_PROXY", "no_proxy"}


def validate_public_services(services: dict[str, Any]) -> None:
    """The same isolation checks for development, review and final export."""
    if not isinstance(services, dict) or not {"main", "client"}.issubset(services) or "runner" in services:
        raise ValueError("public Compose must explicitly contain main and independent client, never runner")
    if not services["client"].get("image") or services["client"].get("image") == services["main"].get("image"):
        raise ValueError("public target and analysis workstation must use distinct prebuilt images")
    for name, service in services.items():
        if service.get("ipv4_address") or service.get("ipv6_address"):
            raise ValueError(f"public Compose service {name} must not pin a top-level static IP")
        for logical, attachment in (service.get("networks") or {}).items() \
                if isinstance(service.get("networks"), dict) else []:
            if isinstance(attachment, dict) and any(attachment.get(key) for key in ("ipv4_address", "ipv6_address")):
                raise ValueError(f"public Compose service {name} must not pin {logical} static IP")
    for name, service in services.items():
        if not isinstance(service, dict) or not isinstance(service.get("image"), str) or not service["image"]:
            raise ValueError(f"public Compose service {name} needs a prebuilt image")
        if service.get("ports"):
            raise ValueError(f"public Compose service {name} must use isolated networks, not host ports")
        for key in FORBIDDEN_COMPOSE_KEYS | {"container_name"}:
            if key in service:
                raise ValueError(f"public Compose service {name} must not contain {key}")
        environment = service.get("environment") or {}
        environment_keys = (set(environment) if isinstance(environment, dict)
                            else {str(item).split("=", 1)[0] for item in environment})
        proxies = environment_keys & PROXY_ENV_KEYS
        if proxies:
            # Harbor injects the real proxy settings with --ae; a proxy baked
            # into the public Compose is inherited by the agent and breaks the
            # model API path on machines without that proxy.
            raise ValueError(
                f"public Compose service {name} must not set proxy variables "
                f"({', '.join(sorted(proxies))}); pass them with harbor --ae instead")
        health = service.get("healthcheck") or {}
        if health.get("disable") is True or not health.get("test"):
            raise ValueError(f"public Compose service {name} needs an enabled healthcheck")
        for volume in service.get("volumes") or []:
            raw_source = volume.get("source") if isinstance(volume, dict) else volume
            if not isinstance(raw_source, str):
                raise ValueError(f"public Compose service {name} volume source must be a string")
            source = volume_source(volume)
            if any(part in source for part in ("private", "gold", "fixed", "docker.sock")):
                raise ValueError(f"public Compose service {name} contains a private mount")
            if not source.startswith("./"):
                raise ValueError(f"public Compose service {name} may bind only ./ assets inside environment/")


def read_public_compose(delivery: Path, contract: dict[str, Any]) -> dict[str, Any]:
    path = delivery / "environment/docker-compose.yaml"
    value = yaml.safe_load(path.read_text(encoding="utf-8"))
    services = value.get("services")
    if not isinstance(services, dict) or not {"main", "client"}.issubset(services):
        raise ValueError("public Compose must explicitly contain main and independent client")
    validate_public_services(services)
    for name, network in (value.get("networks") or {}).items():
        options = network or {}
        if not isinstance(options, dict) or options.get("external") or options.get("name"):
            raise ValueError(f"public network {name} must be task-local and unnamed")
        if (options.get("ipam") or {}).get("config"):
            raise ValueError(f"public network {name} must not carry a development IPAM lease")
    if services["client"].get("image") != contract["images"]["target"]:
        raise ValueError("public client image differs from task.json images.target")
    main_image = services["main"].get("image")
    if main_image not in {None, contract["images"]["agent"]}:
        raise ValueError(
            f"main.image must be omitted or equal task.json.images.agent "
            f"({contract['images']['agent']}); got {main_image!r}")
    for name, service in services.items():
        for volume in service.get("volumes") or []:
            source = volume_source(volume)
            if any(part in source for part in ("private", "gold", "fixed", "docker.sock")):
                raise ValueError(f"public Compose service {name} contains a private mount")
            if source.startswith("./"):
                safe_asset(path.parent, source[2:])
    for image in {service["image"] for service in services.values()}:
        inspect_image(image)
    return value


def copy_environment(delivery: Path, profile: Path, public: dict[str, Any], contract: dict[str, Any]) -> None:
    environment = profile / "environment"
    environment.mkdir(parents=True)
    source = delivery / "environment/docker-compose.yaml"
    for service in public["services"].values():
        for volume in service.get("volumes") or []:
            origin = volume_source(volume)
            if not origin.startswith("./"):
                continue
            item = safe_asset(source.parent, origin[2:])
            target = environment / origin[2:]
            target.parent.mkdir(parents=True, exist_ok=True)
            if item.is_dir():
                shutil.copytree(item, target, symlinks=True)
            else:
                shutil.copy2(item, target)
    public = json.loads(json.dumps(public))
    for service in public["services"].values():
        service.pop("x-public-runner", None)
    public["services"]["main"].pop("image", None)
    # Docker creates an image's declared WORKDIR, but an arbitrary prebuilt
    # analysis image need not declare one. Harbor always collects submission
    # artifacts from /workspace, so make that public contract explicit.
    public["services"]["main"]["working_dir"] = "/workspace"
    # Harbor replaces main.image with its own agent image, so a healthcheck
    # script baked into the task-specific main image would be missing. Main is
    # only the analysis workstation; an image-agnostic liveness probe is the
    # stable contract.
    public["services"]["main"]["healthcheck"] = {
        "test": ["CMD", "sh", "-c", "kill -0 1"],
        "interval": "10s", "timeout": "5s", "retries": 12,
    }
    # Harbor injects its agent image later and replaces main.command with its
    # own blocking Python process. Do not allow a shell -c image entrypoint to
    # consume that command as an argument or exit before the verifier starts.
    # Entrypoint is a launch contract, not task-specific analysis tooling.
    for name, service in public["services"].items():
        # Harbor injects the agent image and replaces main's command, so only
        # the player container needs a neutral entrypoint. Targets and sidecars
        # retain both an explicit Compose entrypoint and an image-owned default;
        # a sleeping command does not mean that the daemon entrypoint is unused.
        if name == "main":
            service["entrypoint"] = ["/usr/bin/env"]
    public["services"]["main"]["command"] = ["python3", "-c",
        "import signal,time; signal.signal(signal.SIGTERM, lambda *_: exit(0)); time.sleep(10**9)"]
    if "client" not in (public["services"]["main"].get("depends_on") or {}):
        public["services"]["main"].setdefault("depends_on", {})["client"] = {"condition": "service_started"}
    (environment / "docker-compose.yaml").write_text(yaml.safe_dump(public, sort_keys=False), encoding="utf-8")
    write_json(environment / "task.json", contract)
    write_json(environment / "topology.json", {
        "schema_version": 1, "topology": "compose_public",
        "application_service": "client", "player_service": "main",
        "player_policy": "analysis workstation only; no private tests or target filesystem",
    })
    write_json(environment / "image-manifest.json", {
        "schema_version": 1, "delivery_mode": "separate-verifier",
        "agent_image": contract["images"]["agent"], "target_image": contract["images"]["target"],
        "sidecar_images": {name: image for name, image in contract["images"].items()
                          if name not in {"agent", "target", "runner"}},
    })


def target_contract(public: dict[str, Any], contract: dict[str, Any]) -> dict[str, Any]:
    """Generate the private target Compose from the reviewed public service."""
    client = json.loads(json.dumps(public["services"]["client"]))
    client.pop("x-public-runner", None)
    client.pop("depends_on", None)
    # The private differential also starts its Compose project with --wait.
    # Retain the reviewed startup probe; the separate protocol healthcheck
    # remains the functional oracle before and after applying the solution.
    # A stale image HEALTHCHECK is overridden by this explicit Compose entry.
    client.setdefault("healthcheck", {
        "test": ["CMD", "sh", "-c", "kill -0 1"],
        "interval": "2s", "timeout": "3s", "retries": 30,
    })
    runner = {
        "image": contract["runner"].get("image") or contract["images"]["agent"],
        "entrypoint": ["/usr/bin/env"],
        "command": ["sleep", "infinity"],
        "healthcheck": {"test": ["CMD", "sh", "-c", "kill -0 1"],
                        "interval": "2s", "timeout": "3s", "retries": 30},
    }
    if client["image"] == runner["image"]:
        raise ValueError("submission runner and target must not share an image")
    services = {"client": client, "runner": runner}
    for name in contract.get("sidecar_services", []):
        if name == "main" or name not in public["services"]:
            raise ValueError(f"invalid sidecar service: {name}")
        sidecar = json.loads(json.dumps(public["services"][name]))
        sidecar.pop("depends_on", None)
        services[name] = sidecar
    client["depends_on"] = {"runner": {"condition": "service_started"}}
    # The runner and target still need every network declared by the reviewed
    # public Compose. Dropping top-level networks makes a custom targetnet
    # reference invalid during private differential verification.
    target = {"services": services}
    if public.get("networks"):
        target["networks"] = json.loads(json.dumps(public["networks"]))
    if public.get("volumes"):
        # Named volumes are valid Compose resources. Their declarations must
        # survive the public-to-private topology transformation as well.
        target["volumes"] = json.loads(json.dumps(public["volumes"]))
    return target


def write_runtime_support(profile: Path, target: dict[str, Any], contract: dict[str, Any],
                          destination: Path) -> None:
    private = profile / "tests/private"
    private.mkdir(parents=True, exist_ok=True)
    support = private / "target"
    support.mkdir(parents=True)
    (support / "docker-compose.yaml").write_text(yaml.safe_dump(target, sort_keys=False), encoding="utf-8")
    # All task-local assets are public by construction; no delivery/private or source tree is copied.
    environment = profile / "environment"
    for service in target["services"].values():
        for volume in service.get("volumes") or []:
            source = volume_source(volume)
            if source.startswith("./") and not (support / source[2:]).exists():
                item = environment / source[2:]
                destination = support / source[2:]
                destination.parent.mkdir(parents=True, exist_ok=True)
                if item.is_dir():
                    shutil.copytree(item, destination, symlinks=True)
                else:
                    shutil.copy2(item, destination)
    (profile / "tests/test.sh").write_text("""#!/bin/sh
set -eu
# Separate mode: the host-side Pass2FailVerifier writes the trial reward.
# Never create a placeholder 0: a missing reward means grading did not
# complete and must be recorded as failed, not as an agent failure.
mkdir -p /logs/verifier
rm -f /logs/verifier/reward.json /logs/verifier/reward.txt
exit 0
""", encoding="utf-8")
    (profile / "tests/test.sh").chmod(0o755)
    # The host-side verifier reads private files. The separate control container
    # receives only the Docker socket, never the host-side private task tree.
    (profile / "bin").mkdir()
    (profile / "config/bin").mkdir(parents=True)
    shutil.copy2(ROOT / "config/bin/docker", profile / "config/bin/docker")
    for source, name in ((ROOT / "pipeline/pass2fail_verifier.py", "pass2fail_verifier.py"),
                         (ROOT / "pipeline/docker_ipam.py", "docker_ipam.py"),
                         (ROOT / "pipeline/pristine_binds.py", "pristine_binds.py"),
                         (ROOT / "pipeline/task_contract.py", "task_contract.py"),
                         (ROOT / "pipeline/bin/__init__.py", "__init__.py")):
        shutil.copy2(source, profile / "bin" / name)
    # No task or socket mount: this is Harbor's separate protocol environment,
    # while the host-side verifier owns the target Compose lifecycle.
    (profile / "tests/docker-compose.yaml").write_text("services:\n  main: {}\n", encoding="utf-8")
    import tomllib
    config = tomllib.loads((profile / "task.toml").read_text(encoding="utf-8"))
    if "import_path" in config["verifier"]:
        raise ValueError(
            "verifier must be loaded with --verifier bin.pass2fail_verifier:"
            "Pass2FailVerifier plus PYTHONPATH, not task.toml import_path")
    for section in ("verifier", "agent", "environment"):
        if "timeout_sec" in (config.get(section) or {}):
            raise ValueError(f"task.toml must not set [{section}] timeout_sec")
    if "build_timeout_sec" in (config.get("verifier", {}).get("environment") or {}):
        raise ValueError("task.toml must not set [verifier.environment] build_timeout_sec")


def archive_image(image: str, target: Path) -> dict[str, Any]:
    with target.open("wb") as compressed:
        save = subprocess.Popen(docker_argv(["docker", "save", image]), stdout=subprocess.PIPE)
        assert save.stdout is not None
        zipper = subprocess.Popen(["gzip", "-1"], stdin=save.stdout, stdout=compressed)
        save.stdout.close()
        if zipper.wait(timeout=1800) != 0 or save.wait(timeout=60) != 0:
            raise RuntimeError(f"failed to docker save {image}")
    with gzip.open(target, "rb") as stream:
        with tarfile.open(fileobj=stream, mode="r|") as archive:
            manifest_member = next((member for member in archive if member.name == "manifest.json"), None)
            if manifest_member is None:
                raise ValueError(f"docker archive has no manifest: {target}")
            file = archive.extractfile(manifest_member)
            saved = json.loads(file.read()) if file else []
            tags = {tag for item in saved for tag in item.get("RepoTags") or []}
            if image not in tags:
                raise ValueError(f"docker archive {target} does not contain exact RepoTag {image}")
    return {**inspect_image(image), "file": target.name,
            "bytes": target.stat().st_size, "sha256": digest_file(target)}


def ensure_bundle_bin(output: Path) -> None:
    bin_dir = output / "bin"
    bin_dir.mkdir(exist_ok=True)
    for source, name in ((ROOT / "pipeline/pass2fail_verifier.py", "pass2fail_verifier.py"),
                         (ROOT / "pipeline/bin/__init__.py", "__init__.py"),
                         (ROOT / "pipeline/docker_ipam.py", "docker_ipam.py"),
                         (ROOT / "pipeline/pristine_binds.py", "pristine_binds.py"),
                         (ROOT / "pipeline/task_contract.py", "task_contract.py")):
        shutil.copy2(source, bin_dir / name)
    docker_dir = output / "config/bin"
    docker_dir.mkdir(parents=True, exist_ok=True)
    shutil.copy2(ROOT / "config/bin/docker", docker_dir / "docker")
    loader = '''#!/usr/bin/env python3
"""Load prebuilt task images and restore sealed writable binds.

Usage:
  python3 bin/load_image.py --task <task-id> [--root <bundle>]
  python3 bin/load_image.py --task <task-id> --run harbor run ...
  python3 bin/load_image.py --shared-only
  python3 bin/load_image.py                 # shared images + every task

The restore step is the pre-run half of the writable-bind wrapper: the player
starts inside harbor run, so it must be clean before this command returns.
"""
from __future__ import annotations

import argparse
import hashlib
import importlib.util
import json
import os
import subprocess
import sys
from pathlib import Path


def parse_args():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--task", help="Task directory name (exact or unique substring)")
    parser.add_argument("--root", type=Path, default=Path(__file__).resolve().parents[1])
    parser.add_argument("--shared-only", action="store_true",
                        help="Load only shared-images/*.tar.gz")
    parser.add_argument("--no-restore", action="store_true",
                        help="Do not restore writable ./ binds after loading")
    parser.add_argument("--run", nargs=argparse.REMAINDER,
                        help="After loading/restoring, run this command (follows --run)")
    return parser.parse_args()


def find_task(root: Path, query: str) -> Path:
    exact = root / query
    if exact.is_dir():
        return exact
    q = query.lower()
    candidates = sorted(
        path for path in root.iterdir()
        if path.is_dir()
        and path.name not in {"bin", "shared-images", "config", "_runtime"}
        and q in path.name.lower()
    )
    if not candidates:
        raise RuntimeError(f"no task matches {query!r} under {root}")
    if len(candidates) > 1:
        names = "\\n  ".join(path.name for path in candidates)
        raise RuntimeError(f"{query!r} matches multiple tasks; use the full name:\\n  {names}")
    return candidates[0]


def docker_load(path: Path, sha256: str | None, image: str, image_id: str | None) -> None:
    if sha256 and hashlib.sha256(path.read_bytes()).hexdigest() != sha256:
        raise ValueError(f"archive SHA-256 mismatch: {path}")
    subprocess.run(["docker", "load", "-i", str(path)], check=True)
    current = json.loads(subprocess.check_output(
        ["docker", "image", "inspect", image], text=True))[0]
    if image_id and current["Id"] != image_id:
        raise ValueError(f"loaded image ID differs from image-lock: {image}")
    print(f"loaded {image} ({current['Id']})")


def load_entry(task_dir: Path, entry: dict) -> None:
    image = entry.get("ref")
    archive = entry.get("archive")
    if not image or not archive:
        raise ValueError(f"image-lock entry needs ref and archive: {entry!r}")
    path = (task_dir / archive).resolve()
    if not path.is_file():
        raise FileNotFoundError(f"image archive is missing: {path}")
    docker_load(path, entry.get("sha256"), image, entry.get("image_id"))


def task_entries(task_dir: Path) -> list[dict]:
    lock = task_dir / "image-lock.json"
    if lock.is_file():
        return json.loads(lock.read_text(encoding="utf-8")).get("images", [])
    # Compatibility with bundles exported before image-lock.json existed.
    manifest = task_dir / "images/manifest.json"
    if not manifest.is_file():
        raise FileNotFoundError(f"no image-lock.json or images/manifest.json in {task_dir}")
    records = json.loads(manifest.read_text(encoding="utf-8")).get("archives", [])
    return [{"role": "image", "ref": record["image"],
             "archive": "images/" + record["file"],
             "sha256": record.get("sha256"), "image_id": record.get("image_id")}
            for record in records]


def restore_binds(task_dir: Path) -> None:
    profile = task_dir / "harbor-runtime-profile"
    if not profile.is_dir():
        return
    helper_path = Path(__file__).with_name("pristine_binds.py")
    if not helper_path.is_file():
        raise FileNotFoundError(f"pristine_binds.py is missing beside {__file__}")
    spec = importlib.util.spec_from_file_location("bundle_pristine_binds", helper_path)
    if spec is None or spec.loader is None:
        raise ImportError(f"cannot load {helper_path}")
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    restored = module.extract_pristine_binds(profile, profile / "environment")
    print(f"restored writable binds for {task_dir.name}: {restored}")


def load_task(task_dir: Path, restore: bool, root: Path | None = None) -> None:
    print(f"task: {task_dir.name}")
    if not (task_dir / "image-lock.json").is_file() and root is not None:
        # Legacy bundle: shared images are not listed in images/manifest.json.
        load_shared(root)
    for entry in task_entries(task_dir):
        load_entry(task_dir, entry)
    if restore:
        restore_binds(task_dir)


def load_shared(root: Path) -> None:
    shared = root / "shared-images"
    if not shared.is_dir() and (root / "_runtime").is_dir():
        shared = root / "_runtime"  # compatibility with pre-second-format bundles
    if not shared.is_dir():
        print("no shared-images directory; skipping")
        return
    manifests = sorted(shared.glob("*.manifest.json"))
    if manifests:
        for manifest in manifests:
            record = json.loads(manifest.read_text(encoding="utf-8"))["archive"]
            docker_load(shared / record["file"], record.get("sha256"),
                        record["image"], record.get("image_id"))
        return
    for archive in sorted(shared.glob("*.tar.gz")):
        subprocess.run(["docker", "load", "-i", str(archive)], check=True)
        print(f"loaded {archive}")


def main() -> int:
    args = parse_args()
    root = args.root.resolve()
    try:
        if args.shared_only:
            load_shared(root)
            return 0
        if args.run:
            if not args.task:
                raise ValueError("--run requires --task")
            task_dir = find_task(root, args.task)
            load_task(task_dir, not args.no_restore, root)
            command = list(args.run)
            if command and command[0] == "--":
                command = command[1:]
            if not command:
                raise ValueError("--run needs a command after --run")
            environment = dict(os.environ)
            profile = task_dir / "harbor-runtime-profile"
            environment["PYTHONPATH"] = str(profile) + (
                os.pathsep + environment["PYTHONPATH"]
                if environment.get("PYTHONPATH") else "")
            try:
                return subprocess.run(command, env=environment).returncode
            finally:
                if not args.no_restore:
                    restore_binds(task_dir)
        if args.task:
            load_task(find_task(root, args.task), not args.no_restore, root)
            return 0
        load_shared(root)
        for task_dir in sorted(root.iterdir()):
            if not task_dir.is_dir():
                continue
            if (task_dir / "image-lock.json").is_file() or (task_dir / "images/manifest.json").is_file():
                load_task(task_dir, not args.no_restore, root)
        return 0
    except (OSError, RuntimeError, ValueError, subprocess.SubprocessError) as exc:
        print(f"error: {exc}", file=sys.stderr)
        return 1


if __name__ == "__main__":
    raise SystemExit(main())
'''
    (bin_dir / "load_image.py").write_text(loader, encoding="utf-8")
    (bin_dir / "load_image.py").chmod(0o755)
    shared_loader = '''#!/usr/bin/env python3
"""Compatibility shim: load only shared-images via load_image.py."""
import runpy
import sys
from pathlib import Path

script = Path(__file__).with_name("load_image.py")
sys.argv = [str(script), "--shared-only", "--root", str(Path(__file__).resolve().parents[1])]
runpy.run_path(str(script), run_name="__main__")
'''
    (bin_dir / "load_shared_images.py").write_text(shared_loader, encoding="utf-8")
    (bin_dir / "load_shared_images.py").chmod(0o755)


def export(delivery: Path, destination: Path, task_id: str, route: dict[str, Any],
           agent_image: str | None = None, bundle_root: Path | None = None) -> dict[str, Any]:
    if not re.fullmatch(r"[a-z0-9][a-z0-9-]{3,159}", task_id):
        raise ValueError("invalid Harbor task id")
    contract = load_task(delivery / "task.json")
    agent_image = agent_image or contract["images"]["agent"]
    if agent_image == AGENT_IMAGE:
        # Runtime preparation is explicit (pipeline.runtime_images). Export
        # never builds a replacement for an image that was already reviewed.
        inspect_image(AGENT_IMAGE)
        inspect_image(VERIFIER_IMAGE)
    validate_route(contract, route, agent_image)
    public = read_public_compose(delivery, contract)
    profile = destination / "harbor-runtime-profile"
    profile.mkdir(parents=True)
    shutil.copy2(delivery / "instruction.md", profile / "instruction.md")
    (profile / "task.toml").write_text(TASK_TOML.format(
        submission=contract["submission_mode"], task_id=task_id,
        branch=contract["branch"], host_type=contract.get("host_type") or "none",
        interaction=contract["interaction"], agent_image=agent_image,
        verifier_image=VERIFIER_IMAGE), encoding="utf-8")
    copy_environment(delivery, profile, public, contract)
    create_pristine_binds_tar(profile)
    target = target_contract(public, contract)
    write_runtime_support(profile, target, contract, destination)
    private = profile / "tests/private"
    for name in ("healthcheck", "oracle", "solution"):
        source = delivery / "private" / f"{name}.sh"
        if not source.is_file():
            raise ValueError(f"missing private/{name}.sh")
        shutil.copy2(source, private / f"{name}.sh")
        (private / f"{name}.sh").chmod(0o755)
    submission = delivery / "private/gold" / contract["submission_mode"]
    if not submission.is_file() or not submission.stat().st_size:
        raise ValueError(f"private/gold/{contract['submission_mode']} is required")
    shutil.copy2(submission, private / f"reference_{contract['submission_mode']}")
    # Some task solution/rebuild scripts reference the canonical private gold
    # path (/private/gold/<submission>). Keep that path available in the
    # target-only private tree as well; it is never mounted for the player.
    gold_dir = private / "gold"
    gold_dir.mkdir(exist_ok=True)
    shutil.copy2(submission, gold_dir / contract["submission_mode"])
    for source in (delivery / "private").iterdir():
        if source.name in {"healthcheck.sh", "oracle.sh", "solution.sh", "gold"}:
            continue
        # solution.sh may need private source archives, patches and benign
        # trigger controls (e.g. rebuild/trigger.lua). Preserve the whole
        # private resource tree, not just its top-level files; symlink escapes
        # are forbidden and the public player environment receives none of it.
        if source.is_symlink():
            raise ValueError(f"private resource must not be a symlink: {source.name}")
        if source.is_dir():
            shutil.copytree(source, private / source.name, symlinks=True)
            for path in (private / source.name).rglob("*"):
                if path.is_symlink():
                    raise ValueError(f"private resource symlink is forbidden: {path}")
        elif source.is_file():
            shutil.copy2(source, private / source.name)
    write_json(private / "task.json", contract)
    (private / "target/task.json").write_text(json.dumps(contract, indent=2) + "\n", encoding="utf-8")
    (private / "target/instruction.md").write_text("Private target generated from the reviewed public client.\n", encoding="utf-8")
    images = destination / "images"
    images.mkdir()
    archives = [archive_image(contract["images"]["target"], images / "target.tar.gz")]
    seen = {contract["images"]["target"]}
    # A task-specific analysis image is part of this task's bundle, not the
    # shared runtime: publishing would otherwise keep only the first task's
    # shared-images/agent.tar.gz and leave later tasks without their main image.
    if agent_image != AGENT_IMAGE:
        archives.append(archive_image(agent_image, images / "agent.tar.gz"))
        seen.add(agent_image)
    for name, service in public["services"].items():
        if name in {"main", "client"}:
            continue
        image = service["image"]
        if image not in seen:
            archives.append(archive_image(image, images / f"{name}.tar.gz"))
            seen.add(image)
    if contract["runner"].get("image") and contract["runner"]["image"] not in seen | {agent_image}:
        archives.append(archive_image(contract["runner"]["image"], images / "runner.tar.gz"))
        seen.add(contract["runner"]["image"])
    write_json(images / "manifest.json", {"schema_version": 1, "task_id": task_id, "archives": archives})
    if bundle_root is not None:
        bundle_root.mkdir(parents=True, exist_ok=True)
        runtime = bundle_root / "shared-images"
        runtime.mkdir(exist_ok=True)
        runtime_images = ((VERIFIER_IMAGE, "verifier.tar.gz"),)
        if agent_image == AGENT_IMAGE:
            runtime_images = ((agent_image, "agent.tar.gz"),) + runtime_images
        for image, name in runtime_images:
            archive = runtime / name
            if archive.exists():
                metadata = json.loads(archive.with_suffix("").with_suffix(".manifest.json").read_text())["archive"]
                if digest_file(archive) != metadata["sha256"]:
                    raise ValueError(f"cached runtime archive differs from its manifest: {archive}")
            else:
                metadata = archive_image(image, archive)
                write_json(runtime / f"{archive.stem}.manifest.json", {"schema_version": 1, "archive": metadata})
            if inspect_image(image)["image_id"] != metadata["image_id"]:
                raise RuntimeError(f"runtime tag is missing or differs from frozen archive: {image}")
        ensure_bundle_bin(bundle_root)

    # image-lock.json is the external delivery index (the official second
    # format). Keep images/manifest.json as internal archive metadata, but the
    # loader and downstream evaluator consume this file.
    by_image = {item["image"]: item for item in archives}
    shared_records: dict[str, dict[str, Any]] = {}
    if bundle_root is not None:
        for name in ("agent", "verifier"):
            manifest = runtime / f"{name}.tar.manifest.json"
            if manifest.is_file():
                shared_records[name] = json.loads(
                    manifest.read_text(encoding="utf-8"))["archive"]

    def lock_entry(role: str, image: str, archive: str,
                   record: dict[str, Any] | None = None) -> dict[str, Any]:
        entry = {"role": role, "ref": image, "archive": archive}
        if record is None:
            record = shared_records.get(role) or by_image.get(image)
        if record is not None:
            for key in ("image_id", "sha256"):
                if record.get(key):
                    entry[key] = record[key]
        return entry

    target_image = contract["images"]["target"]
    lock: list[dict[str, Any]] = []
    if agent_image == AGENT_IMAGE:
        lock.append(lock_entry("agent", agent_image, "../shared-images/agent.tar.gz",
                               shared_records.get("agent")))
    elif agent_image in by_image:
        record = by_image[agent_image]
        lock.append(lock_entry("agent", agent_image, "images/" + record["file"], record))
    target_record = by_image[target_image]
    lock.append(lock_entry("target", target_image, "images/" + target_record["file"],
                           target_record))
    for name, service in public["services"].items():
        if name in {"main", "client"}:
            continue
        image = service["image"]
        record = by_image.get(image)
        if record is not None:
            archive = "images/" + record["file"]
        elif image == agent_image and agent_image == AGENT_IMAGE:
            archive = "../shared-images/agent.tar.gz"
        elif image == agent_image:
            archive = "images/agent.tar.gz"
        elif image == target_image:
            archive = "images/target.tar.gz"
        else:
            raise ValueError(f"sidecar image has no archive in the bundle: {image}")
        lock.append(lock_entry(f"sidecar:{name}", image, archive, record))
    runner_image = contract["runner"].get("image")
    if runner_image and runner_image not in {agent_image, target_image} and runner_image in by_image:
        record = by_image[runner_image]
        lock.append(lock_entry("runner", runner_image, "images/" + record["file"], record))
    lock.append(lock_entry("verifier", VERIFIER_IMAGE,
                           "../shared-images/verifier.tar.gz",
                           shared_records.get("verifier")))
    write_json(destination / "image-lock.json", {
        "schema_version": 1, "task": task_id, "images": lock})

    return {"schema_version": 1, "task_id": task_id, "created_at": timestamp(),
            "branch": contract["branch"], "host_type": contract.get("host_type"),
            "submission": contract["submission_mode"], "archives": archives, "agent_image": agent_image}


def load_archives(directory: Path) -> None:
    manifest_path = directory / "manifest.json"
    individual = sorted(directory.glob("*.manifest.json"))
    if individual:
        records = [json.loads(path.read_text(encoding="utf-8"))["archive"]
                   for path in individual]
    else:
        records = json.loads(manifest_path.read_text(encoding="utf-8"))["archives"]
    if {record["file"] for record in records} != {path.name for path in directory.glob("*.tar.gz")}:
        raise ValueError(f"image archives and manifest differ: {directory}")
    for record in records:
        path = directory / record["file"]
        if digest_file(path) != record["sha256"]:
            raise ValueError(f"archive digest mismatch: {path}")
        cp = subprocess.run(docker_argv(["docker", "load", "-i", str(path)]),
                            capture_output=True, text=True, timeout=1800)
        if cp.returncode:
            raise RuntimeError(f"cannot load {path}: {cp.stderr[-2000:]}")
        if inspect_image(record["image"])["image_id"] != record["image_id"]:
            raise ValueError(f"loaded image ID does not match archive: {record['image']}")


def claude_agent() -> tuple[str, str]:
    """Resolve the local Claude Code executable and its version for Harbor."""
    executable = os.environ.get("CLAUDE_BIN") or shutil.which("claude")
    if not executable or not Path(executable).is_file():
        raise RuntimeError("Claude Code is not installed; install it or set CLAUDE_BIN")
    resolved = str(Path(executable).resolve())
    version = subprocess.check_output([resolved, "--version"], text=True, timeout=30).strip().split()[0]
    if not re.fullmatch(r"[0-9][0-9A-Za-z._-]*", version):
        raise ValueError(f"cannot parse Claude Code version: {version!r}")
    return resolved, version


def _agent_env_args(credentials: dict[str, str]) -> list[str]:
    key = credentials.get("ANTHROPIC_API_KEY") or credentials.get("ANTHROPIC_AUTH_TOKEN")
    if not key:
        raise ValueError("Harbor agent requires ANTHROPIC_API_KEY or ANTHROPIC_AUTH_TOKEN")
    args = ["--ae", f"ANTHROPIC_API_KEY={key}"]
    base = credentials.get("ANTHROPIC_BASE_URL")
    if base:
        args += ["--ae", f"ANTHROPIC_BASE_URL={base}"]
        host = base.split("://", 1)[-1].split("/", 1)[0].split(":", 1)[0]
    else:
        host = "127.0.0.1"
    args += [
        "--ae", "HTTP_PROXY=", "--ae", "HTTPS_PROXY=",
        "--ae", "http_proxy=", "--ae", "https_proxy=",
        "--ae", f"NO_PROXY=localhost,127.0.0.1,{host}",
        "--ae", f"no_proxy=localhost,127.0.0.1,{host}",
        "--ae", "CLAUDE_CODE_DISABLE_UNKNOWN_MODEL_WINDOW_ENFORCEMENT=1",
    ]
    return args


def harbor_run(profile: Path, jobs: Path, name: str, timeout: int, *,
               agent: str = "oracle", model: str | None = None,
               credentials: dict[str, str] | None = None,
               mounts: list[dict[str, Any]] | None = None,
               max_turns: int | None = None,
               agent_version: str | None = None) -> dict[str, Any]:
    # Run each Harbor invocation in a separate process so module-level and
    # host-side subprocess state from a previous trial cannot leak into this
    # one. The verifier class itself is generic and identical for every task.
    import multiprocessing
    with multiprocessing.get_context("fork").Pool(1) as pool:
        return pool.apply(_harbor_run_fresh, (profile, jobs, name, timeout, agent, model,
                                              credentials, mounts, max_turns, agent_version))


def _harbor_run_fresh(profile: Path, jobs: Path, name: str, timeout: int,
                      agent: str, model: str | None,
                      credentials: dict[str, str] | None,
                      mounts: list[dict[str, Any]] | None,
                      max_turns: int | None,
                      agent_version: str | None) -> dict[str, Any]:
    executable = ROOT / ".venv/bin/harbor"
    if not executable.is_file():
        raise FileNotFoundError(f"Harbor 0.22 CLI is missing: {executable}")
    environment = dict(os.environ)
    environment["PATH"] = str(ROOT / "config/bin") + os.pathsep + environment.get("PATH", "")
    environment["LITELLM_LOCAL_MODEL_COST_MAP"] = "True"
    environment["PASS2FAIL_DOCKER"] = str(ROOT / "config/bin/docker")
    environment["PIPELINE_IPAM_ROLE"] = "harbor"
    environment["PIPELINE_IPAM_WORK_DIR"] = str(jobs / f"{name}-ipam")
    environment["COMPOSE_PROJECT_NAME"] = "lup" + re.sub(r"[^a-z0-9]", "", name.lower())[:45]
    import_path = "bin.pass2fail_verifier:Pass2FailVerifier"
    module = profile / "bin/pass2fail_verifier.py"
    if not module.is_file():
        raise FileNotFoundError(f"self-contained Harbor verifier is missing: {module}")
    environment["PYTHONPATH"] = str(profile.resolve()) + os.pathsep + environment.get("PYTHONPATH", "")
    command = [str(executable), "run", "--path", str(profile), "--agent", agent,
               "--n-attempts", "1", "--n-concurrent", "1", "--jobs-dir", str(jobs),
               "--job-name", name, "--yes", "--verifier", import_path,
               # task.toml must not set a timeout; this invocation keeps the
               # old 3600s verifier budget without baking it into the task.
               "--verifier-timeout-multiplier", "6.0"]
    if agent != "oracle":
        if not model or not mounts or not max_turns or not credentials or not agent_version:
            raise ValueError("Harbor agent acceptance needs model, mounts, max_turns, credentials and version")
        command += ["--model", model, "--mounts", json.dumps(mounts, ensure_ascii=False),
                    "--agent-timeout-multiplier", "1",
                    "--ak", f"max_turns={max_turns}",
                    "--ak", f"version={agent_version}",
                    "--ak", "disallowed_tools=WebSearch,WebFetch"]
        command += _agent_env_args(credentials)
    # Harbor starts the player directly from profile/environment, before any
    # verifier code runs. Restore the sealed writable binds around the whole
    # invocation so a player cannot inherit bytes from a previous crashed
    # trial; restoring only at verifier entry would be too late for the player.
    extract_pristine_binds(profile, profile / "environment")
    try:
        cp = subprocess.run(command, capture_output=True, text=True, timeout=timeout,
                            env=environment)
    finally:
        try:
            extract_pristine_binds(profile, profile / "environment")
        except Exception as exc:  # keep the original Harbor failure authoritative
            try:
                jobs.mkdir(parents=True, exist_ok=True)
                (jobs / f"{name}-restore-error.log").write_text(
                    f"{type(exc).__name__}: {exc}\n", encoding="utf-8")
            except Exception:
                pass
    output = cp.stdout + cp.stderr
    jobs.mkdir(parents=True, exist_ok=True)
    (jobs / f"{name}.log").write_text(output, encoding="utf-8")
    report_path = jobs / name / "result.json"
    if not report_path.is_file():
        raise RuntimeError(f"Harbor did not produce a job result: {output[-4000:]}")
    result = json.loads(report_path.read_text(encoding="utf-8"))
    stats = result.get("stats", {})
    if cp.returncode or stats.get("n_errored_trials") or stats.get("n_completed_trials") != 1:
        raise RuntimeError(f"Harbor trial failed; see {jobs / name}: {output[-4000:]}")
    trials = [path for path in (jobs / name).glob("*/result.json") if path.is_file()]
    if len(trials) != 1:
        raise ValueError("expected one Harbor trial")
    trial = json.loads(trials[0].read_text(encoding="utf-8"))
    if trial.get("exception_info") is not None:
        raise RuntimeError(f"Harbor trial exception: {trial['exception_info']}")
    reward = (trial.get("verifier_result") or {}).get("rewards", {}).get("reward")
    if not isinstance(reward, (int, float)) or isinstance(reward, bool):
        raise ValueError("missing Harbor numeric reward")
    return {"status": "passed" if float(reward) == 1.0 else "failed",
            "reward": float(reward), "result": str(report_path), "agent": agent}


def publish_bundle(staging: Path, root: Path, task_id: str, acceptance: dict[str, Any]) -> None:
    """Atomically publish an accepted task and serialize the shared index."""
    import fcntl
    root.mkdir(parents=True, exist_ok=True)
    # Independent pipeline processes may finish acceptance concurrently.
    with (root / ".publish.lock").open("a+") as lock:
        fcntl.flock(lock, fcntl.LOCK_EX)
        temporary = root / ".staging" / task_id
        if temporary.exists():
            shutil.rmtree(temporary)
        temporary.mkdir(parents=True)
        for name in ("bin", "shared-images", task_id):
            source = staging / name
            if source.is_dir():
                shutil.copytree(source, temporary / name, symlinks=True)
        destination = root / task_id
        if destination.exists():
            raise FileExistsError(f"refusing to overwrite published task: {destination}")
        # Keep the exact evidence in the sealed task directory. The outer
        # acceptance directory is intentionally rotated on every retry, so a
        # host path in manifest.json would become stale and make an otherwise
        # accepted bundle unauditable.
        evidence = temporary / task_id / "acceptance.json"
        shutil.copy2(acceptance, evidence)
        evidence.chmod(0o444)
        os.rename(temporary / task_id, destination)
        for name in ("bin", "shared-images"):
            if not (root / name).exists():
                os.rename(temporary / name, root / name)
        shutil.rmtree(temporary)
        entries = []
        manifest_path = root / "manifest.json"
        if manifest_path.exists():
            entries = json.loads(manifest_path.read_text(encoding="utf-8"))["tasks"]
        entries = [entry for entry in entries if entry["task_id"] != task_id]
        entries.append({"task_id": task_id, "status": "accepted",
                        "acceptance_runs": 2, "acceptance_rewards": [1.0, 1.0],
                        "profile": f"{task_id}/harbor-runtime-profile",
                        "image_lock": f"{task_id}/image-lock.json",
                        "image_manifest": f"{task_id}/images/manifest.json",
                        "acceptance": f"{task_id}/acceptance.json"})
        entries.sort(key=lambda entry: entry["task_id"])
        write_json(manifest_path, {"schema_version": 1, "status": "accepted_tasks_only",
                                   "task_count": len(entries), "tasks": entries})
        (root / "task_id_all.jsonl").write_text(
            "".join(json.dumps({"task_id": entry["task_id"]}, ensure_ascii=False) + "\n"
                    for entry in entries), encoding="utf-8")


def accept(workspace: Path, output: Path, task_id: str, route: dict[str, Any],
           timeout: int, harbor_jobs: Path | None = None,
           published_root: Path | None = None, *, model: str = "glm-5.3",
           credentials: dict[str, str] | None = None,
           accept_turns: int = 8) -> dict[str, Any]:
    delivery = workspace / "delivery"
    if output.exists():
        raise FileExistsError(f"refusing to overwrite acceptance directory {output}")
    output.mkdir(parents=True)
    contract = load_task(delivery / "task.json")
    delivery_id = export_task_id(task_id, contract["branch"], contract.get("host_type"))
    bundle = output / "bundle" / delivery_id
    # Load a frozen runtime, not a mutable tag that a previous Harbor cleanup
    # may have removed. Task and verifier use the same archive throughout.
    cached_runtime = output.parent.parent / "shared-runtime"
    if cached_runtime.is_dir() and not (output / "bundle/shared-images").exists():
        shutil.copytree(cached_runtime, output / "bundle/shared-images")
        load_archives(output / "bundle/shared-images")
    result = {"schema_version": 3, "stage": "harbor", "status": "in_progress",
              "task_id": task_id, "export_task_id": delivery_id,
              "manifest": None, "acceptance_runs": []}
    try:
        manifest = export(delivery, bundle, delivery_id, route, bundle_root=output / "bundle")
        result["manifest"] = manifest
        load_archives(bundle / "images")
        load_archives(output / "bundle/shared-images")
        jobs = harbor_jobs or output / "jobs"
        name = re.sub(r"[^a-z0-9-]+", "-", delivery_id)[:90]
        profile = bundle / "harbor-runtime-profile"
        submission = contract["submission_mode"]
        # Acceptance is a verifier check, not a solving run: the reference
        # submission is already mounted read-only at /workspace/<submission>.
        # Give the agent an explicit no-op prompt so it does not burn turns
        # trying to solve the task and exit nonzero at max-turns.
        accept_profile = output / "accept-profile"
        if accept_profile.exists():
            shutil.rmtree(accept_profile)
        shutil.copytree(profile, accept_profile)
        (accept_profile / "instruction.md").write_text(
            "# Reference acceptance\n\n"
            f"The reference submission is at `/opt/reference/{submission}` "
            f"(read-only). Copy it to `/workspace/{submission}` with `cp`, do "
            "not modify its contents, and do not run task work or start any "
            "service. Reply with one line and end.\n",
            encoding="utf-8")
        reference = accept_profile / "tests/private" / f"reference_{submission}"
        if not reference.is_file():
            raise ValueError(f"missing reference submission: {reference}")
        claude_bin, claude_version = claude_agent()
        mounts = [
            {"type": "bind", "source": claude_bin,
             "target": "/usr/local/bin/claude", "read_only": True},
            {"type": "bind", "source": str(reference),
             "target": f"/opt/reference/{submission}", "read_only": True},
        ]
        # Start from the sealed writable binds. The first Agent run may
        # write through a bind; restore the seal before the second run, then
        # require the same Pass2Fail on the restored package. This tests that
        # the bind design can recover from a dirty run, not that dirt is safe.
        extract_pristine_binds(accept_profile, accept_profile / "environment")
        for attempt in (1, 2):
            if attempt == 2:
                extract_pristine_binds(accept_profile, accept_profile / "environment")
            run = harbor_run(
                accept_profile, jobs, f"{name}-accept-{attempt}", timeout,
                agent="claude-code", model=model, credentials=credentials,
                mounts=mounts, max_turns=accept_turns, agent_version=claude_version)
            run["attempt"] = attempt
            result["acceptance_runs"].append(run)
            if run["reward"] != 1.0:
                break
        # _harbor_run_fresh() already restores the sealed writable binds in its
        # finally after every Harbor invocation; no extra post-loop restore.
        frozen = output / "frozen-delivery"
        shutil.copytree(delivery, frozen, symlinks=True)
        result["acceptance_rewards"] = [run["reward"] for run in result["acceptance_runs"]]
        result["status"] = "passed" if len(result["acceptance_runs"]) == 2 and \
            all(run["reward"] == 1.0 for run in result["acceptance_runs"]) else "failed"
    except Exception as exc:
        # An exporter/verifier crash is evidence too. Persist it so a retry
        # never erases the reason for failure or leaves an in_progress artifact.
        result["status"] = "error"
        result["error"] = f"{type(exc).__name__}: {exc}"
        raise
    finally:
        # Seal the evidence before the first and only publication attempt. The
        # first accept() has no pre-existing result.json to copy.
        write_json(output / "result.json", result)
    if result["status"] == "passed" and published_root is not None:
        publish_bundle(output / "bundle", published_root, delivery_id,
                       str((output / "result.json").resolve()))
    return result


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--results", type=Path, required=True)
    parser.add_argument("--output", type=Path, required=True)
    parser.add_argument("--agent-image", default=os.environ.get("HARBOR_AGENT_IMAGE"))
    parser.add_argument("--only", nargs="+")
    parser.add_argument("--skip-load-test", action="store_true")
    args = parser.parse_args()
    records = []
    for result_path in sorted(args.results.glob("*/result.json")):
        result = json.loads(result_path.read_text(encoding="utf-8"))
        if result.get("status") != "passed":
            continue
        delivery = result_path.parent / "workspace/delivery"
        contract = load_task(delivery / "task.json")
        delivery_id = export_task_id(result["task_id"], contract["branch"], contract.get("host_type"))
        if args.only and result["task_id"] not in args.only and delivery_id not in args.only:
            continue
        destination = args.output / delivery_id
        if destination.exists():
            raise FileExistsError(f"refusing to overwrite {destination}")
        manifest = export(delivery, destination, delivery_id, result["route"],
                          args.agent_image, args.output)
        if not args.skip_load_test:
            load_archives(destination / "images")
        records.append({"task_id": delivery_id, "source_task_id": result["task_id"],
                        "status": "exported", "image_lock": f"{delivery_id}/image-lock.json",
                        "images": manifest["archives"]})
        print(f"exported {delivery_id}", flush=True)
    write_json(args.output / "manifest.json", {"schema_version": 1, "tasks": records})
    (args.output / "task_id_all.jsonl").write_text(
        "".join(json.dumps({"task_id": record["task_id"]}, ensure_ascii=False) + "\n"
                for record in records), encoding="utf-8")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
