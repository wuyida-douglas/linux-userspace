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

from .common import sha256 as digest_file
from .common import timestamp, write_json
from .native_agent import docker_argv
from .runtime_images import AGENT_IMAGE, VERIFIER_IMAGE
from .task_contract import load_task, validate_route
from .verify import execute_verify

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
import_path = "bin.pass2fail_verifier:Pass2FailVerifier"
timeout_sec = 3600.0

[verifier.environment]
docker_image = "{verifier_image}"
build_timeout_sec = 300.0
network_mode = "public"

[agent]
timeout_sec = 7200.0

[environment]
build_timeout_sec = 1800.0
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
    if services["main"].get("image") not in {None, contract["images"]["agent"]}:
        raise ValueError("main may only retain task.json's analysis image, never a target image")
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
    public["services"]["main"].pop("image", None)
    # Docker creates an image's declared WORKDIR, but an arbitrary prebuilt
    # analysis image need not declare one. Harbor always collects submission
    # artifacts from /workspace, so make that public contract explicit.
    public["services"]["main"]["working_dir"] = "/workspace"
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
# Separate mode: no tests/private is uploaded to main or the untrusted runner.
# The Python verifier invokes this only to produce a valid default log/reward.
mkdir -p /logs/verifier
if [ ! -f /logs/verifier/reward.json ]; then
    printf '{"reward": 0.0}\n' > /logs/verifier/reward.json
fi
""", encoding="utf-8")
    (profile / "tests/test.sh").chmod(0o755)
    # The host-side facade reads private files. The separate control container
    # receives only the Docker socket, never the host-side private task tree.
    (profile / "bin").mkdir()
    (profile / "config/bin").mkdir(parents=True)
    shutil.copy2(ROOT / "config/bin/docker", profile / "config/bin/docker")
    for source, name in ((ROOT / "pipeline/pass2fail_verifier.py", "_pass2fail_verifier.py"),
                         (ROOT / "pipeline/bin/pass2fail_verifier.py", "pass2fail_verifier.py"),
                         (ROOT / "pipeline/docker_ipam.py", "docker_ipam.py"),
                         (ROOT / "pipeline/task_contract.py", "task_contract.py"),
                         (ROOT / "pipeline/bin/__init__.py", "__init__.py")):
        shutil.copy2(source, profile / "bin" / name)
    # No task or socket mount: this is Harbor's separate protocol environment,
    # while the host-side verifier owns the target Compose lifecycle.
    (profile / "tests/docker-compose.yaml").write_text("services:\n  main: {}\n", encoding="utf-8")
    import tomllib
    config = tomllib.loads((profile / "task.toml").read_text(encoding="utf-8"))
    if config["verifier"].get("import_path") != "bin.pass2fail_verifier:Pass2FailVerifier":
        raise ValueError("bundle does not declare its self-contained verifier")


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
    for source, name in ((ROOT / "pipeline/bin/pass2fail_verifier.py", "pass2fail_verifier.py"),
                         (ROOT / "pipeline/bin/__init__.py", "__init__.py"),
                         (ROOT / "pipeline/pass2fail_verifier.py", "_pass2fail_verifier.py"),
                         (ROOT / "pipeline/docker_ipam.py", "docker_ipam.py"),
                         (ROOT / "pipeline/task_contract.py", "task_contract.py")):
        shutil.copy2(source, bin_dir / name)
    docker_dir = output / "config/bin"
    docker_dir.mkdir(parents=True, exist_ok=True)
    shutil.copy2(ROOT / "config/bin/docker", docker_dir / "docker")
    loader = '''#!/usr/bin/env python3
import gzip, hashlib, json, subprocess, sys, tarfile
from pathlib import Path
root = Path(__file__).resolve().parents[1]
for path in sorted(root.glob("*/images/*.tar.gz")):
    expected = json.loads((path.parent / "manifest.json").read_text())
    wanted = {item["file"]: item for item in expected["archives"]}
    if path.name not in wanted:
        raise ValueError(f"unlisted Docker archive: {path}")
    record = wanted[path.name]
    if hashlib.sha256(path.read_bytes()).hexdigest() != record["sha256"]:
        raise ValueError(f"Docker archive SHA-256 mismatch: {path}")
    with gzip.open(path, "rb") as stream, tarfile.open(fileobj=stream, mode="r|") as archive:
        member = next((m for m in archive if m.name == "manifest.json"), None)
        if member is None: raise ValueError(f"missing Docker manifest: {path}")
        saved = json.loads(archive.extractfile(member).read())
        tags = {tag for item in saved for tag in item.get("RepoTags") or []}
        if record["image"] not in tags:
            raise ValueError(f"archive does not match task manifest: {path}")
    with gzip.open(path, "rb") as stream:
        subprocess.run(["docker", "load"], stdin=stream, check=True)
    image = json.loads(subprocess.check_output(["docker", "image", "inspect", record["image"]]))[0]
    if image["Id"] != record["image_id"]:
        raise ValueError(f"loaded image ID differs from task archive: {record['image']}")
    print(f"loaded {record['image']} ({record['image_id']})")
'''
    (bin_dir / "load_image.py").write_text(loader, encoding="utf-8")
    (bin_dir / "load_image.py").chmod(0o755)
    shared_loader = '''#!/usr/bin/env python3
"""Load shared prebuilt images; never build or pull missing task images."""
import gzip, hashlib, json, subprocess
from pathlib import Path
root = Path(__file__).resolve().parents[1]
paths = sorted((root / "_runtime").glob("*.tar.gz"))
if not paths:
    print("No shared runtime archives; skipping.")
for path in paths:
    manifest = json.loads(path.with_suffix("").with_suffix(".manifest.json").read_text())
    expected = manifest["archive"]
    actual = hashlib.sha256(path.read_bytes()).hexdigest()
    if actual != expected["sha256"]:
        raise ValueError(f"runtime archive SHA-256 mismatch: {path}")
    with gzip.open(path, "rb") as stream:
        subprocess.run(["docker", "load"], stdin=stream, check=True)
    image = json.loads(subprocess.check_output(["docker", "image", "inspect", expected["image"]]))[0]
    if image["Id"] != expected["image_id"]:
        raise ValueError(f"loaded image ID differs from exported archive: {expected['image']}")
    print(f"loaded {expected['image']} ({expected['image_id']})")
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
        runtime = bundle_root / "_runtime"
        runtime.mkdir(exist_ok=True)
        for image, name in ((agent_image, "agent.tar.gz"), (VERIFIER_IMAGE, "verifier.tar.gz")):
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
    return {"schema_version": 1, "task_id": task_id, "created_at": timestamp(),
            "branch": contract["branch"], "host_type": contract.get("host_type"),
            "submission": contract["submission_mode"], "archives": archives, "agent_image": agent_image}


def load_archives(directory: Path) -> None:
    manifest_path = directory / "manifest.json"
    if directory.name == "_runtime":
        records = [json.loads(path.read_text(encoding="utf-8"))["archive"]
                   for path in sorted(directory.glob("*.manifest.json"))]
    else:
        records = json.loads(manifest_path.read_text(encoding="utf-8"))["archives"]
    if {record["file"] for record in records} != {path.name for path in directory.glob("*.tar.gz")}:
        raise ValueError(f"image archives and manifest differ: {directory}")
    for record in records:
        path = directory / record["file"]
        if digest_file(path) != record["sha256"]:
            raise ValueError(f"archive digest mismatch: {path}")
        with gzip.open(path, "rb") as stream:
            cp = subprocess.run(docker_argv(["docker", "load"]), stdin=stream,
                                capture_output=True, text=True, timeout=1800)
        if cp.returncode:
            raise RuntimeError(f"cannot load {path}: {cp.stderr[-2000:]}")
        if inspect_image(record["image"])["image_id"] != record["image_id"]:
            raise ValueError(f"loaded image ID does not match archive: {record['image']}")


def harbor_run(profile: Path, jobs: Path, name: str, timeout: int) -> dict[str, Any]:
    # A separate process makes the shipped verifier authoritative even when
    # this Python process previously graded a different profile (and cached
    # its import-facade implementation). This also keeps all host-side
    # environment and subprocess state local to this gold/null trial.
    import multiprocessing
    # fork avoids re-importing a stdin/interactive parent. The child has not
    # run any verifier import for this profile and immediately executes the
    # standalone Harbor CLI, so its verifier cache is fresh.
    with multiprocessing.get_context("fork").Pool(1) as pool:
        return pool.apply(_harbor_run_fresh, (profile, jobs, name, timeout))


def _harbor_run_fresh(profile: Path, jobs: Path, name: str, timeout: int) -> dict[str, Any]:
    executable = ROOT / ".venv/bin/harbor"
    if not executable.is_file():
        raise FileNotFoundError(f"Harbor 0.22 CLI is missing: {executable}")
    environment = dict(os.environ)
    environment["PATH"] = str(ROOT / "config/bin") + os.pathsep + environment.get("PATH", "")
    environment["LITELLM_LOCAL_MODEL_COST_MAP"] = "True"
    # This verifier orchestrates Docker on the host. It never needs or uses a
    # socket mounted into the separate, unprivileged verifier container.
    environment["PASS2FAIL_DOCKER"] = str(ROOT / "config/bin/docker")
    environment["PIPELINE_IPAM_ROLE"] = "harbor"
    environment["PIPELINE_IPAM_WORK_DIR"] = str(jobs / f"{name}-ipam")
    environment["COMPOSE_PROJECT_NAME"] = "lup" + re.sub(r"[^a-z0-9]", "", name.lower())[:45]
    import_path = "bin.pass2fail_verifier:Pass2FailVerifier"
    module = profile / "bin/pass2fail_verifier.py"
    if not module.is_file():
        raise FileNotFoundError(f"self-contained Harbor verifier is missing: {module}")
    # Custom verifiers are imported in the host Python process, not the
    # separate verifier container. task.toml's verifier.env cannot affect this.
    environment["PYTHONPATH"] = str(profile.resolve()) + os.pathsep + environment.get("PYTHONPATH", "")
    command = [str(executable), "run", "--path", str(profile), "--agent", "oracle",
               "--n-attempts", "1", "--n-concurrent", "1", "--jobs-dir", str(jobs),
               "--job-name", name, "--yes", "--verifier", import_path]
    cp = subprocess.run(command, capture_output=True, text=True, timeout=timeout, env=environment)
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
    return {"status": "passed", "reward": float(reward), "result": str(report_path)}


def oracle_profile(bundle: Path, submission: str | None, output: Path) -> Path:
    source = bundle / "harbor-runtime-profile"
    # Private files stay in the host-side task, never in the player's main.
    # The verifier itself reads them from its bind; exclude them there below.
    shutil.copytree(source, output)
    solution = output / "solution"
    # Harbor's docker cp preserves the host directory mode. An IDE or agent
    # umask of 027 would make /solution unreadable to container root on a
    # rootless daemon; the reference solve script must remain executable.
    solution.mkdir(mode=0o755)
    solution.chmod(0o755)
    if submission:
        shutil.copy2(bundle / "harbor-runtime-profile/tests/private" / f"reference_{submission}",
                     solution / submission)
        (solution / "solve.sh").write_text(
            f"#!/bin/sh\nset -eu\ncp /solution/{submission} /workspace/{submission}\n", encoding="utf-8")
    else:
        (solution / "solve.sh").write_text("#!/bin/sh\nset -eu\nexit 0\n", encoding="utf-8")
    (solution / "solve.sh").chmod(0o755)
    return output


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
        for name in ("bin", "_runtime", task_id):
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
        for name in ("bin", "_runtime"):
            if not (root / name).exists():
                os.rename(temporary / name, root / name)
        shutil.rmtree(temporary)
        entries = []
        manifest_path = root / "manifest.json"
        if manifest_path.exists():
            entries = json.loads(manifest_path.read_text(encoding="utf-8"))["tasks"]
        entries = [entry for entry in entries if entry["task_id"] != task_id]
        entries.append({"task_id": task_id, "status": "accepted", "gold_reward": 1.0,
                        "null_reward": 0.0, "profile": f"{task_id}/harbor-runtime-profile",
                        "image_manifest": f"{task_id}/images/manifest.json",
                        "acceptance": f"{task_id}/acceptance.json"})
        entries.sort(key=lambda entry: entry["task_id"])
        write_json(manifest_path, {"schema_version": 1, "status": "accepted_tasks_only",
                                   "task_count": len(entries), "tasks": entries})


def accept(workspace: Path, output: Path, task_id: str, route: dict[str, Any],
           timeout: int, harbor_jobs: Path | None = None,
           published_root: Path | None = None) -> dict[str, Any]:
    delivery = workspace / "delivery"
    if output.exists():
        raise FileExistsError(f"refusing to overwrite acceptance directory {output}")
    output.mkdir(parents=True)
    contract = load_task(delivery / "task.json")
    bundle = output / "bundle" / task_id
    # Load a frozen runtime, not a mutable tag that a previous Harbor cleanup
    # may have removed. Task and verifier use the same archive throughout.
    cached_runtime = output.parent.parent / "shared-runtime"
    if cached_runtime.is_dir() and not (output / "bundle/_runtime").exists():
        shutil.copytree(cached_runtime, output / "bundle/_runtime")
        load_archives(output / "bundle/_runtime")
    result = {"schema_version": 2, "stage": "harbor", "status": "in_progress",
              "manifest": None, "gold": None, "null": None}
    try:
        manifest = export(delivery, bundle, task_id, route, bundle_root=output / "bundle")
        result["manifest"] = manifest
        load_archives(bundle / "images")
        load_archives(output / "bundle/_runtime")
        jobs = harbor_jobs or output / "jobs"
        name = re.sub(r"[^a-z0-9-]+", "-", task_id.lower())[:90]
        gold = oracle_profile(bundle, contract["submission_mode"], output / "gold-profile")
        result["gold"] = harbor_run(gold, jobs, name + "-gold", timeout)
        if result["gold"]["reward"] == 1.0:
            null = oracle_profile(bundle, None, output / "null-profile")
            result["null"] = harbor_run(null, jobs, name + "-null", timeout)
        frozen = output / "frozen-delivery"
        shutil.copytree(delivery, frozen, symlinks=True)
        result["differential_from_final_bundle"] = execute_verify(
            bundle / "harbor-runtime-profile", output / "verification", timeout)
        result["status"] = "passed" if result["gold"]["reward"] == 1.0 and \
            (result["null"] or {}).get("reward") == 0.0 and \
            result["differential_from_final_bundle"]["status"] == "passed" else "failed"
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
        publish_bundle(output / "bundle", published_root, task_id,
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
        if result.get("status") != "passed" or (args.only and result["task_id"] not in args.only):
            continue
        destination = args.output / result["task_id"]
        if destination.exists():
            raise FileExistsError(f"refusing to overwrite {destination}")
        manifest = export(result_path.parent / "workspace/delivery", destination,
                          result["task_id"], result["route"], args.agent_image, args.output)
        if not args.skip_load_test:
            load_archives(destination / "images")
        records.append({"task_id": result["task_id"], "status": "exported", "images": manifest["archives"]})
        print(f"exported {result['task_id']}", flush=True)
    write_json(args.output / "manifest.json", {"schema_version": 1, "tasks": records})
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
