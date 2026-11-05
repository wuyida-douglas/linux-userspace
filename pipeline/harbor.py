#!/usr/bin/env python3
"""Export prebuilt image archives and a self-contained Harbor 0.22 profile."""
from __future__ import annotations

import argparse
import gzip
import hashlib
import json
import os
import re
import shlex
import shutil
import subprocess
import tarfile
import threading
import tomllib
from pathlib import Path
from typing import Any

import yaml

from .common import read_jsonl, timestamp, write_json
from .native_agent import docker_argv
from .verify import execute_verify, validate_report
TASK_TOML = """version = "1.0"
[metadata]
task_id = "{task_id}"
difficulty = "hard"
category = "linux-userspace-vulnerability"
tags = ["{branch}", "{host_type}", "containerized-vulnerability"]

[environment]
build_timeout_sec = 1800.0
docker_image = "{agent_image}"
gpus = 0
cpus = 2
memory_mb = 8192
storage_mb = 32768
network_mode = "public"

[agent]
timeout_sec = 7200.0

[verifier]
timeout_sec = 3600.0
"""


def digest_file(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as handle:
        for block in iter(lambda: handle.read(8 * 1024 * 1024), b""):
            digest.update(block)
    return digest.hexdigest()


def inspect_image(image: str) -> dict[str, Any]:
    """The delivered image must already contain the synthesized environment."""
    cp = subprocess.run(docker_argv(["docker", "image", "inspect", image]),
                        capture_output=True, text=True, timeout=30)
    if cp.returncode:
        raise RuntimeError(f"prebuilt image is missing; refusing Dockerfile rebuild: {image}")
    value = json.loads(cp.stdout)[0]
    return {"image": image, "image_id": value["Id"],
            "repo_tags": value.get("RepoTags") or [],
            "repo_digests": value.get("RepoDigests") or []}


def inspect_images(compose: Path) -> tuple[dict[str, Any], dict[str, str]]:
    cp = subprocess.run(docker_argv(["docker", "compose", "-f", str(compose), "config", "--format", "json"]),
                        capture_output=True, text=True, check=True, timeout=60)
    value = json.loads(cp.stdout)
    services = value.get("services") or {}
    images = {}
    for name, service in services.items():
        image = service.get("image")
        if not image:
            raise ValueError(f"Compose service {name} has no explicit prebuilt image")
        for key in ("build", "privileged", "pid"):
            if key in service:
                raise ValueError(f"player service {name} must not contain {key}")
        for volume in service.get("volumes") or []:
            source = str(volume.get("source", ""))
            if any(x in source for x in ("private", "docker.sock", "fixed", "gold")):
                raise ValueError(f"player service {name} has a private mount")
        # Record every service's reference before deduplicating identical
        # images. Otherwise a shared workstation image makes images['main']
        # disappear and an otherwise valid Compose cannot enter acceptance.
        images[name] = image
    if not images:
        raise ValueError("empty public Compose services")
    for image in set(images.values()):
        inspect_image(image)
    return value, images


def asset_references(compose: dict[str, Any]) -> set[Path]:
    """Collect local Compose files, excluding arbitrary factory scratch files."""
    references: set[Path] = set()
    for service in (compose.get("services") or {}).values():
        for volume in service.get("volumes") or []:
            if not isinstance(volume, dict) or volume.get("type", "volume") == "volume":
                continue
            source = str(volume.get("source") or "")
            if not source.startswith("./"):
                continue
            relative = Path(source)
            if relative.is_absolute() or ".." in relative.parts:
                raise ValueError(f"unsafe Compose bind source: {source}")
            references.add(relative)
    return references


def copy_public_environment(source: Path, destination: Path, compose: dict[str, Any]) -> None:
    """Ship only runtime configuration and the assets explicitly used by Compose."""
    destination.mkdir()
    shutil.copyfile(source / "docker-compose.yaml", destination / "docker-compose.yaml")
    for relative in asset_references(compose):
        item = source / relative
        if not item.exists():
            raise ValueError(f"public Compose asset does not exist: {relative}")
        target = destination / relative
        target.parent.mkdir(parents=True, exist_ok=True)
        if item.is_dir():
            shutil.copytree(item, target, symlinks=True)
        else:
            shutil.copyfile(item, target)


def export(delivery: Path, destination: Path, task_id: str, branch: str,
           host_type: str, agent_image: str, oracle: bool = False) -> dict[str, Any]:
    if not re.fullmatch(r"[a-z0-9][a-z0-9-]{3,159}", task_id):
        raise ValueError("invalid Harbor task id")
    raw_compose = yaml.safe_load((delivery / "environment/docker-compose.yaml").read_text(encoding="utf-8"))
    if "main" not in (raw_compose.get("services") or {}):
        raise ValueError("Harbor Compose must explicitly define the agent service 'main'")
    healthcheck = raw_compose["services"]["main"].get("healthcheck") or {}
    if healthcheck.get("disable") is True or not healthcheck.get("test"):
        raise ValueError("Harbor compose --wait requires an enabled main healthcheck")
    resolved_compose, images = inspect_images(delivery / "environment/docker-compose.yaml")
    # The vulnerable workstation already carries the player tools. Declaring
    # it as prebuilt prevents Harbor from replacing it with a generic Ubuntu.
    if images["main"] != agent_image:
        raise ValueError("Compose main image must equal the prebuilt agent/workstation image")
    profile = destination / "harbor-runtime-profile"
    profile.mkdir(parents=True)
    shutil.copyfile(delivery / "instruction.md", profile / "instruction.md")
    compose = yaml.safe_load((delivery / "environment/docker-compose.yaml").read_text(encoding="utf-8"))
    # task.toml is the authoritative main-image setting. The task overlay must
    # not override it, since Harbor merges its prebuilt-agent overlay first.
    del compose["services"]["main"]["image"]
    (profile / "environment/docker-compose.yaml").write_text(
        yaml.safe_dump(compose, sort_keys=False), encoding="utf-8")
    copy_public_environment(delivery / "environment", profile / "environment", resolved_compose)
    (profile / "environment/assets").mkdir(exist_ok=True)
    image_lines = ", ".join(json.dumps(image) for image in sorted(set(images.values())))
    (profile / "task.toml").write_text(TASK_TOML.format(
        task_id=task_id, branch=branch, host_type=host_type or "none",
        agent_image=agent_image, images=image_lines), encoding="utf-8")
    test_script = delivery / "public_tests/test.sh"
    if not test_script.is_file():
        raise ValueError("delivery/public_tests/test.sh is required; private gold cannot be uploaded by Harbor")
    shutil.copytree(delivery / "public_tests", profile / "tests")
    os.rename(profile / "tests/test.sh", profile / "tests/score.sh")
    # Do not depend on the umask of the synthesis agent or Docker build cache:
    # every exported shell verifier must be executable by Harbor's runner.
    for script in (profile / "tests").rglob("*.sh"):
        script.chmod(script.stat().st_mode | 0o111)
    # Harbor 0.22 parses every key in reward.json as a numeric reward. Preserve
    # detailed agent evidence separately and expose only the numeric score.
    adapter = """#!/bin/sh
cd "$(dirname "$0")" || exit 1
mkdir -p /logs/verifier
rm -f /logs/verifier/reward.json /logs/verifier/evidence.json
./score.sh "$@"
rc=$?
if [ -f /logs/verifier/reward.json ]; then
    mv /logs/verifier/reward.json /logs/verifier/evidence.json
fi
python3 - <<'PY'
import json
from pathlib import Path
path = Path('/logs/verifier/evidence.json')
try:
    value = json.loads(path.read_text())['reward']
    reward = float(value)
    if reward < 0 or reward > 1:
        raise ValueError('reward outside 0..1')
except (OSError, ValueError, KeyError, TypeError, json.JSONDecodeError):
    reward = 0.0
Path('/logs/verifier/reward.json').write_text(json.dumps({'reward': reward}) + '\\n')
PY
exit "$rc"
"""
    (profile / "tests/test.sh").write_text(adapter, encoding="utf-8")
    os.chmod(profile / "tests/test.sh", 0o755)
    with (profile / "task.toml").open("ab") as handle:
        handle.write(b"\n[metadata.image_manifest]\n")
        for image in sorted(set(images.values())):
            handle.write((json.dumps(image) + " = true\n").encode())
    config = tomllib.loads((profile / "task.toml").read_text(encoding="utf-8"))
    if set(config["metadata"]["image_manifest"]) != set(images.values()):
        raise ValueError("image manifest differs from Compose image references")
    image_dir = destination / "images"
    image_dir.mkdir()
    archives = []
    # De-duplicate shared public images while retaining their exact references.
    for number, image in enumerate(sorted(set(images.values())), 1):
        target = image_dir / f"image-{number:02d}.tar.gz"
        with target.open("wb") as compressed:
            save = subprocess.Popen(docker_argv(["docker", "save", image]), stdout=subprocess.PIPE)
            assert save.stdout is not None
            gzip = subprocess.Popen(["gzip", "-1"], stdin=save.stdout, stdout=compressed)
            save.stdout.close()
            if gzip.wait(timeout=1800) != 0 or save.wait(timeout=60) != 0:
                raise RuntimeError(f"failed to archive {image}")
        archives.append({"file": target.name, "image": image, "bytes": target.stat().st_size,
                         "sha256": digest_file(target)})
    if oracle:
        # Oracle-only validation material lives in a separate opt-in profile.
        # Normal player exports never contain private/gold.
        oracle_profile = destination / "harbor-oracle-profile"
        shutil.copytree(profile, oracle_profile)
        (oracle_profile / "solution").mkdir()
        shutil.copytree(delivery / "private/gold", oracle_profile / "solution/gold")
        reference = delivery / "private/solve.sh"
        if reference.is_file():
            shutil.copyfile(reference, oracle_profile / "solution/solve.sh")
        else:
            # Compatibility for the first already-reviewed Janet artifact only.
            if not (delivery / "private/gold/pov.janet.bin").is_file():
                raise ValueError("private/solve.sh is required for the isolated Harbor reference run")
            solve = "#!/bin/sh\nset -eu\ncp /solution/gold/pov.janet.bin /work/pov.bin\n"
            (oracle_profile / "solution/solve.sh").write_text(solve, encoding="utf-8")
        os.chmod(oracle_profile / "solution/solve.sh", 0o755)
    # Docker cp preserves the source mode. A 0750 task directory blocks the
    # container's unprivileged user from traversing /solution even after
    # Harbor chmods solve.sh itself. Normalize only exported material dirs;
    # private workspace permissions and all verifier semantics stay unchanged.
    for task_profile in (profile, oracle_profile) if oracle else (profile,):
        for directory in (task_profile / "tests", task_profile / "solution"):
            if directory.exists():
                directory.chmod(0o755)
                for child in directory.rglob("*"):
                    if child.is_dir():
                        child.chmod(0o755)
    manifest = {"schema_version": 1, "task_id": task_id, "created_at": timestamp(),
                "images": archives, "agent_image": agent_image}
    write_json(destination / "images/manifest.json", manifest)
    return manifest


def load_archives(directory: Path) -> None:
    for path in sorted(directory.glob("*.tar.gz")):
        cp = subprocess.run(["sg", "docker", "-c", f"gzip -dc {str(path)!r} | docker load"],
                            capture_output=True, text=True, timeout=1800)
        if cp.returncode:
            raise RuntimeError(f"cannot load {path}: {cp.stderr[-2000:]}")


def harbor_run(profile: Path, jobs: Path, name: str, timeout: int) -> dict[str, Any]:
    """Run the installed Harbor 0.22 binary; parsing a TOML is not acceptance."""
    executable = Path(__file__).resolve().parents[1] / ".venv/bin/harbor"
    if not executable.is_file():
        raise FileNotFoundError(f"Harbor 0.22 CLI is missing from the pipeline venv: {executable}")
    command = [str(executable), "run", "--path", str(profile),
               "--agent", "oracle", "--n-attempts", "1", "--n-concurrent", "1",
               "--jobs-dir", str(jobs), "--job-name", name, "--yes"]
    # Run the Harbor host CLI, not `docker harbor`; only Docker subprocesses
    # go through the group-refresh wrapper via this explicit PATH.
    env = dict(os.environ)
    env["PATH"] = str(Path(__file__).resolve().parents[1] / "config/bin") + os.pathsep + env.get("PATH", "")
    cp = subprocess.run(command, capture_output=True, text=True, timeout=timeout, env=env)
    output = cp.stdout + cp.stderr
    if "all predefined address pools have been fully subnetted" in output:
        # This happens before the task container starts. Never retry a genuine
        # build failure or reward=0, and never remove networks used by workers.
        archive = jobs / "infrastructure-attempts" / f"{name}-{timestamp().replace(':', '-')}"
        archive.parent.mkdir(exist_ok=True)
        if (jobs / name).exists():
            (jobs / name).rename(archive)
        (archive.parent / f"{archive.name}.log").write_text(output, encoding="utf-8")
        prune = subprocess.run(docker_argv(["docker", "network", "prune", "-f"]),
                               capture_output=True, text=True, timeout=60)
        if prune.returncode:
            raise RuntimeError(f"cannot reclaim unused Docker networks: {prune.stderr[-1000:]}")
        cp = subprocess.run(command, capture_output=True, text=True, timeout=timeout, env=env)
        output = cp.stdout + cp.stderr
    (jobs / f"{name}.log").write_text(output, encoding="utf-8")
    report_path = jobs / name / "result.json"
    if not report_path.is_file():
        raise RuntimeError(f"Harbor did not produce a job result: {cp.stdout[-2000:]} {cp.stderr[-2000:]}")
    result = json.loads(report_path.read_text(encoding="utf-8"))
    stats = result.get("stats", {})
    if cp.returncode or stats.get("n_errored_trials") or stats.get("n_completed_trials") != 1:
        raise RuntimeError(f"Harbor trial failed; see {jobs / name}: {output[-2500:]}")
    rewards = []
    trials = [path for path in (jobs / name).glob("*/result.json") if path.is_file()]
    if len(trials) != 1:
        raise ValueError(f"expected one Harbor trial result, got {trials}")
    trial = json.loads(trials[0].read_text(encoding="utf-8"))
    if trial.get("exception_info") is not None:
        raise RuntimeError(f"Harbor trial exception: {trial['exception_info']}")
    value = (trial.get("verifier_result") or {}).get("rewards", {}).get("reward")
    if isinstance(value, (float, int)) and not isinstance(value, bool):
        rewards.append(float(value))
    if len(rewards) != 1:
        raise ValueError(f"expected exactly one Harbor reward, got {rewards}")
    return {"status": "passed", "reward": rewards[0], "result": str(report_path)}


def accept(workspace: Path, output: Path, task_id: str, route: dict[str, Any],
           timeout: int, harbor_jobs: Path | None = None) -> dict[str, Any]:
    """Final stage: frozen differential followed by packaged gold/null Harbor runs."""
    delivery = workspace / "delivery"
    if output.exists():
        raise FileExistsError(f"refusing to overwrite acceptance directory {output}")
    output.mkdir(parents=True)
    compose = yaml.safe_load((delivery / "environment/docker-compose.yaml").read_text(encoding="utf-8"))
    agent_image = compose["services"]["main"]["image"]
    bundle = output / "bundle"
    export(delivery, bundle, task_id, route["branch"], route.get("host_type"), agent_image, oracle=True)
    load_archives(bundle / "images")
    jobs = harbor_jobs or output / "jobs"
    jobs.mkdir(exist_ok=True)
    safe_name = re.sub(r"[^a-z0-9-]+", "-", task_id.lower())[:90]
    results = {"schema_version": 1, "stage": "harbor",
               "differential_from_final_bundle": None, "gold": None, "null": None}
    results["gold"] = harbor_run(bundle / "harbor-oracle-profile", jobs, safe_name + "-gold", timeout)
    if results["gold"]["reward"] != 1.0:
        results["status"] = "failed"
        write_json(output / "result.json", results)
        return results
    null_profile = output / "harbor-null-profile"
    null_profile.mkdir()
    for item in (bundle / "harbor-oracle-profile").iterdir():
        if item.name == "solution":
            continue
        if item.is_dir():
            shutil.copytree(item, null_profile / item.name)
        else:
            shutil.copyfile(item, null_profile / item.name)
    (null_profile / "solution").mkdir()
    (null_profile / "solution/solve.sh").write_text(
        "#!/bin/sh\nset -eu\n# Null attempt: do not submit an exploit or invoke the target.\nexit 0\n", encoding="utf-8")
    os.chmod(null_profile / "solution/solve.sh", 0o755)
    results["null"] = harbor_run(null_profile, jobs, safe_name + "-null", timeout)
    if results["null"]["reward"] != 0.0:
        results["status"] = "failed"
        write_json(output / "result.json", results)
        return results
    frozen = output / "frozen-delivery"
    shutil.copytree(delivery, frozen, symlinks=True)
    results["differential_from_final_bundle"] = execute_verify(
        frozen, output / "verification", timeout, wrapped=True)
    results["status"] = ("passed" if results["differential_from_final_bundle"]["status"] == "passed"
                         else "failed")
    write_json(output / "result.json", results)
    return results


def accept_resume(workspace: Path, output: Path, task_id: str, route: dict[str, Any],
                  timeout: int) -> dict[str, Any]:
    """Reuse a completed gold trial, but always rerun null and private differential."""
    completed = output / "result.json"
    if completed.exists():
        value = json.loads(completed.read_text(encoding="utf-8"))
        differential = value.get("differential_from_final_bundle") or {}
        if (value.get("status") == "passed"
                and (value.get("gold") or {}).get("status") == "passed"
                and (value.get("gold") or {}).get("reward") == 1.0
                and (value.get("null") or {}).get("status") == "passed"
                and (value.get("null") or {}).get("reward") == 0.0
                and differential.get("status") == "passed"
                and (differential.get("report") or {}).get("success") is True):
            return value
        raise FileExistsError(f"acceptance has an incomplete or failed result at {output}")
    gold_results = list((output / "jobs").glob("*-gold/result.json"))
    if len(gold_results) != 1:
        raise ValueError("no unique interrupted Harbor gold result to resume")
    gold_job = json.loads(gold_results[0].read_text(encoding="utf-8"))
    if gold_job.get("stats", {}).get("n_errored_trials"):
        raise ValueError("cannot resume an errored Harbor gold job")
    trials = [path for path in gold_results[0].parent.glob("*/result.json") if path.is_file()]
    if len(trials) != 1:
        raise ValueError("Harbor resume needs exactly one completed gold trial")
    trial = json.loads(trials[0].read_text(encoding="utf-8"))
    reward = (trial.get("verifier_result") or {}).get("rewards", {}).get("reward")
    if trial.get("exception_info") is not None or reward != 1.0:
        raise ValueError(f"cannot resume gold trial without a verified reward of 1.0: {reward}")
    bundle = output / "bundle"
    jobs = output / "jobs"
    safe_name = re.sub(r"[^a-z0-9-]+", "-", task_id.lower())[:90]
    results = {"schema_version": 1, "stage": "harbor", "resumed": True,
               "gold": {"status": "passed", "reward": float(reward), "result": str(gold_results[0])},
               "null": None, "differential_from_final_bundle": None}
    null_profile = output / "harbor-null-profile"
    if not null_profile.exists():
        null_profile.mkdir()
        for item in (bundle / "harbor-oracle-profile").iterdir():
            if item.name == "solution":
                continue
            if item.is_dir():
                shutil.copytree(item, null_profile / item.name)
            else:
                shutil.copyfile(item, null_profile / item.name)
        (null_profile / "solution").mkdir()
        (null_profile / "solution/solve.sh").write_text(
            "#!/bin/sh\nset -eu\n# Null attempt: no exploit interaction.\nexit 0\n", encoding="utf-8")
        os.chmod(null_profile / "solution/solve.sh", 0o755)
    results["null"] = harbor_run(null_profile, jobs, safe_name + "-null", timeout)
    if results["null"]["reward"] != 0.0:
        results["status"] = "failed"
        write_json(output / "result.json", results)
        return results
    frozen = output / "frozen-delivery"
    if not frozen.exists():
        shutil.copytree(workspace / "delivery", frozen, symlinks=True)
    results["differential_from_final_bundle"] = execute_verify(
        frozen, output / "verification", timeout, wrapped=True)
    results["status"] = "passed" if results["differential_from_final_bundle"]["status"] == "passed" else "failed"
    write_json(output / "result.json", results)
    return results


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--results", type=Path, required=True)
    parser.add_argument("--output", type=Path, required=True)
    parser.add_argument("--agent-image", default=os.environ.get("HARBOR_AGENT_IMAGE", "ubuntu:22.04"))
    parser.add_argument("--only", nargs="+")
    parser.add_argument("--skip-load-test", action="store_true")
    parser.add_argument("--oracle", action="store_true",
                        help="also create an isolated oracle-only profile containing private gold")
    args = parser.parse_args()
    records = []
    for result_path in sorted(args.results.glob("*/result.json")):
        result = json.loads(result_path.read_text(encoding="utf-8"))
        if result.get("status") != "passed" or (args.only and result["task_id"] not in args.only):
            continue
        workspace = result_path.parent / "workspace"
        output = args.output / result["task_id"]
        if output.exists():
            raise FileExistsError(f"refusing to overwrite {output}")
        if not os.environ.get("HARBOR_AGENT_IMAGE"):
            workstation = yaml.safe_load((workspace / "delivery/environment/docker-compose.yaml").read_text(
                encoding="utf-8"))["services"]["main"].get("image")
            if not workstation:
                raise ValueError("delivery main service needs a prebuilt workstation image")
            args.agent_image = workstation
        manifest = export(workspace / "delivery", output, result["task_id"],
                          result["route"]["branch"], result["route"].get("host_type"),
                          args.agent_image, oracle=args.oracle)
        if not args.skip_load_test:
            load_archives(output / "images")
        report_path = result_path.parent / "verification/report.json"
        validate_report(json.loads(report_path.read_text(encoding="utf-8")))
        records.append({"task_id": result["task_id"], "status": "exported",
                        "images": manifest["images"]})
        print(f"exported {result['task_id']}", flush=True)
    write_json(args.output / "export-report.json", {"tasks": records})
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
