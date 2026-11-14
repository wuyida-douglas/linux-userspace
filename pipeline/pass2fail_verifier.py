"""Self-contained, host-side Harbor verifier for prebuilt isolated targets.

The public Compose environment is gone when this runs. Only the declared
submission artifact crosses from the untrusted player. One differential runs
the submission and the target-side oracle on the vulnerable target, then applies
the official solution and reruns both on the fixed target. Repeated
differentials belong to the caller (acceptance runs the verifier twice), not to
this module.
No private files or Docker socket are exposed to the submission runner.
"""
from __future__ import annotations

import hashlib
import json
import os
import re
import shutil
import subprocess
import sys
import tarfile
import time
import traceback
from pathlib import Path
from typing import Any

MAX_SUBMISSION = 16 * 1024 * 1024
MAX_EVIDENCE = 64 * 1024
# These statuses mean grading did not complete (or the task itself is broken),
# not that the agent submitted a wrong answer. Harbor must mark the trial
# failed without a reward; writing 0 would turn an infrastructure error into a
# negative training sample.
NON_GRADING_STATUSES = {"infra_error", "target_unhealthy", "patch_failed", "patched_down"}
FILE_POV_INPUT = "/run/pass2fail/input.bin"


def oracle_argv_for(contract: dict[str, Any]) -> list[str]:
    """Return the target oracle argv.

    FILE-POV copies the submission to a fixed path and must pass that path as
    ``$1``; otherwise an oracle that only accepts ``$1`` (or only searches its
    own candidate list) sees no submission.  Other branches are unchanged.
    """
    argv = list(contract["oracle"]["argv"])
    if contract.get("branch") == "FILE-POV":
        argv.append(FILE_POV_INPUT)
    return argv


class VerifierInfraError(RuntimeError):
    """Grading could not produce a trustworthy 0/1 verdict."""
FORBIDDEN_COMPOSE_KEYS = {"build", "privileged", "pid", "network_mode", "cap_add",
                          "cap_drop", "devices", "security_opt", "cgroup_parent", "ipc", "uts", "container_name"}
COMPOSE_ENV = {
    key: value for key, value in os.environ.items()
    if key in {"PATH", "HOME", "DOCKER_HOST", "DOCKER_CONFIG", "DOCKER_CONTEXT",
               "PASS2FAIL_DOCKER", "TMPDIR", "PIPELINE_IPAM_ROLE", "PIPELINE_IPAM_STATE",
               "PIPELINE_IPAM_WORK_DIR", "PIPELINE_IPAM_DISABLE"}
}


def docker_path() -> str:
    configured = os.environ.get("PASS2FAIL_DOCKER")
    if configured and Path(configured).is_file():
        return configured
    # The host-side verifier owns Docker. Prefer the repository's group-refresh
    # wrapper over /usr/bin/docker: a long-lived IDE process may not have the
    # user's recently granted supplementary docker group in its credentials.
    task_root = Path(__file__).resolve().parents[1]
    for candidate in (task_root / "config/bin/docker", Path("/usr/bin/docker"),
                      shutil.which("docker")):
        if candidate and Path(candidate).is_file():
            return str(candidate)
    for module in list(sys.modules.values()):
        origin = getattr(module, "__file__", "")
        if origin and Path(origin).name == "docker_ipam.py":
            candidate = Path(origin).resolve().parents[1] / "config/bin/docker"
            if candidate.is_file():
                return str(candidate)
    raise FileNotFoundError("host Docker CLI is required by the separate verifier")


def _as_text(value: Any) -> str:
    """TimeoutExpired carries bytes even when subprocess.run(text=True)."""
    if value is None:
        return ""
    if isinstance(value, bytes):
        return value.decode("utf-8", "replace")
    return str(value)


def bounded_run(argv: list[str], *, cwd: Path | None = None, timeout: int = 600,
                env: dict[str, str] | None = None) -> dict[str, Any]:
    started = time.monotonic()
    try:
        cp = subprocess.run(argv, cwd=cwd, env=env or COMPOSE_ENV,
                            capture_output=True, text=True, errors="replace", timeout=timeout)
        output = (cp.stdout + cp.stderr)[-MAX_EVIDENCE:]
        code = cp.returncode
    except subprocess.TimeoutExpired as exc:
        output = (_as_text(exc.stdout) + _as_text(exc.stderr))[-MAX_EVIDENCE:]
        code = 124
    except Exception as exc:
        output, code = (f"{type(exc).__name__}: {exc}\n"
                        f"argv={argv!r} cwd={str(cwd)!r}\n" + traceback.format_exc())[-MAX_EVIDENCE:], 125
    return {"argv": argv, "returncode": code, "output": output,
            "elapsed_sec": round(time.monotonic() - started, 2)}


def load_contract(task_dir: Path) -> dict[str, Any]:
    # Use the exact frozen contract validator from the bundle in development,
    # Harbor and the final bundle differential. A weaker private verifier must
    # never accept a uid, capability or runner contract rejected at export.
    import importlib.util
    candidates = [Path(__file__).with_name("task_contract.py"),
                  task_dir / "bin/task_contract.py"]
    for path in candidates:
        if not path.is_file():
            continue
        name = "_linux_userspace_task_contract_" + hashlib.sha256(str(path.resolve()).encode()).hexdigest()[:20]
        if name in sys.modules:
            module = sys.modules[name]
        else:
            spec = importlib.util.spec_from_file_location(name, path)
            if spec is None or spec.loader is None:
                raise ImportError(f"cannot load frozen task contract: {path}")
            module = importlib.util.module_from_spec(spec)
            sys.modules[name] = module
            spec.loader.exec_module(module)
        return module.load_task(task_dir / "tests/private/task.json")
    raise FileNotFoundError(f"frozen task_contract.py is missing beside {task_dir}")


def target_compose(task_dir: Path) -> dict[str, Any]:
    import yaml
    path = task_dir / "tests/private/target/docker-compose.yaml"
    value = yaml.safe_load(path.read_text(encoding="utf-8"))
    services = value.get("services")
    if not isinstance(services, dict) or not {"client", "runner"}.issubset(services):
        raise ValueError("target compose requires client and runner")
    for name, service in services.items():
        if not service.get("image") or FORBIDDEN_COMPOSE_KEYS.intersection(service) or service.get("ports"):
            raise ValueError(f"target service {name} violates prebuilt/unprivileged/network isolation")
        for volume in service.get("volumes") or []:
            raw_source = volume.get("source") if isinstance(volume, dict) else volume
            if not isinstance(raw_source, str):
                raise ValueError("target Compose volume source must be a string")
            source = raw_source.split(":", 1)[0]
            if source.startswith("/") or ".." in Path(source).parts:
                raise ValueError("target compose may use only named volumes or relative runtime assets")
    if "runner" not in (services["client"].get("depends_on") or {}):
        raise ValueError("client must depend on runner")
    return value


def collected_submission(artifacts: Path, contract: dict[str, Any]) -> Path | None:
    path = artifacts / "workspace" / contract["submission_mode"]
    if not path.is_file() or path.is_symlink() or not 0 < path.stat().st_size <= MAX_SUBMISSION:
        return None
    return path


def write_json(path: Path, value: Any) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(value, ensure_ascii=False, indent=2) + "\n", encoding="utf-8")


class Differential:
    def __init__(self, task_dir: Path, submission: Path, log_dir: Path, project: str,
                 private_dir: Path | None = None, environment_dir: Path | None = None):
        self.task_dir = task_dir.resolve()
        self.private_source = (private_dir or task_dir / "tests/private").resolve()
        self.environment_source = (environment_dir or self.private_source / "target").resolve()
        self.contract = load_contract(task_dir)
        target_compose(task_dir)
        self.submission = submission.resolve()
        self.log_dir = log_dir.resolve()
        self.project = project
        self.work = self.log_dir / "work"
        self.environment = self.work / "environment"
        self.private = self.work / "private"
        self.runner = self.work / "runner"
        self.file_input = self.work / "input"
        self.docker = docker_path()
        self.active_project: str | None = None

    def compose(self, project: str, *args: str, timeout: int = 900) -> dict[str, Any]:
        return bounded_run([
            self.docker, "compose", "--project-name", project,
            "--project-directory", str(self.environment),
            "-f", str(self.environment / "docker-compose.yaml"), *args,
        ], cwd=self.environment, timeout=timeout,
            env={**COMPOSE_ENV, "PIPELINE_IPAM_ROLE": "harbor",
                 "PIPELINE_IPAM_WORK_DIR": str(self.log_dir / "ipam")})

    def upload_private(self, project: str) -> dict[str, Any]:
        """Install root-owned target-only material in the private control copy.

        Only this disposable private Compose service uses root. The public
        target's user, command and entrypoint are never modified, and the
        unprivileged submission runner receives no private material.
        """
        target = target_compose(self.task_dir)["services"]["client"]
        identity = "0:0"
        if not re.fullmatch(r"[0-9]+(:[0-9]+)?", identity):
            raise ValueError("private target user must be numeric uid[:gid]")
        parts = identity.split(":")
        uid, gid = int(parts[0]), int(parts[1] if len(parts) > 1 else parts[0])
        if not (0 <= uid < 65536 and 0 <= gid < 65536):
            raise ValueError("private target uid/gid is outside the Linux range")
        # GNU format avoids PAX extended headers: some target images ship
        # BusyBox tar, which rejects Python's default PAX archive with
        # "This does not look like a tar archive".
        with tarfile.open(self.work / "private-upload.tar", "w",
                          format=tarfile.GNU_FORMAT) as archive:
            for source in sorted(self.private.rglob("*")):
                relative = source.relative_to(self.private)
                info = archive.gettarinfo(str(source), arcname=str(relative))
                info.uid, info.gid = uid, gid
                info.uname = info.gname = str(uid)
                info.mode = 0o700 if source.is_dir() else 0o500
                if source.is_symlink():
                    raise ValueError("private upload symlink is forbidden")
                if source.is_file():
                    with source.open("rb") as stream:
                        archive.addfile(info, stream)
                else:
                    archive.addfile(info)
        # Do not pipe the archive through `docker compose exec` stdin: the
        # docker-group refresh wrapper can consume stdin before the exec, and
        # the client then sees an empty stream. Copy the tar as a file, then
        # extract it inside the target.
        archive = self.work / "private-upload.tar"
        started = time.monotonic()
        copied = self.compose(project, "cp", str(archive),
                              "client:/tmp/private-upload.tar", timeout=120)
        if copied["returncode"]:
            return {"argv": copied["argv"], "returncode": copied["returncode"],
                    "output": copied["output"], "elapsed_sec": round(time.monotonic() - started, 2)}
        executed = self.compose(
            project, "exec", "-T", "--user", identity, "client", "sh", "-c",
            "mkdir -p /private && tar -xf /tmp/private-upload.tar -C /private "
            "&& chmod 700 /private && rm -f /tmp/private-upload.tar", timeout=120)
        output = (copied["output"] + executed["output"])[-MAX_EVIDENCE:]
        return {"argv": executed["argv"], "returncode": executed["returncode"],
                "output": output, "elapsed_sec": round(time.monotonic() - started, 2)}

    def _pristine_helper(self):
        import importlib.util
        path = Path(__file__).with_name("pristine_binds.py")
        if not path.is_file():
            return None
        name = "_linux_userspace_pristine_" + hashlib.sha256(str(path.resolve()).encode()).hexdigest()[:20]
        if name in sys.modules:
            return sys.modules[name]
        spec = importlib.util.spec_from_file_location(name, path)
        if spec is None or spec.loader is None:
            raise ImportError(f"cannot load pristine bind helper: {path}")
        module = importlib.util.module_from_spec(spec)
        sys.modules[name] = module
        spec.loader.exec_module(module)
        return module

    def restore_pristine_binds(self) -> None:
        task_dir = getattr(self, "task_dir", None)
        environment = getattr(self, "environment", None)
        if task_dir is None or environment is None:
            return
        helper = self._pristine_helper()
        if helper is not None:
            helper.extract_pristine_binds(task_dir, environment)

    def prepare(self) -> None:
        shutil.copytree(self.environment_source, self.environment)
        shutil.copytree(self.private_source, self.private)
        # Each phase restores its writable binds from pristine-binds.tar before
        # Compose starts; prepare() only copies the package.
        # The shipped reference is reused by the differential; never persist a
        # file with host-only permissions into that source tree.
        reference = self.private / f"reference_{self.contract['submission_mode']}"
        reference.chmod(0o444)
        self.runner.mkdir(parents=True)
        self._write_public_healthcheck()
        if self.contract["branch"] == "FILE-POV":
            self.file_input.mkdir(mode=0o755)
            destination = self.file_input / "input.bin"
        else:
            (self.runner / "submission").mkdir(mode=0o755)
            destination = self.runner / "submission" / self.contract["submission_mode"]
            (self.runner / "run").mkdir(mode=0o755)
            (self.runner / "output").mkdir(mode=0o777)
        shutil.copyfile(self.submission, destination)
        # docker bind mounts do not change the host file mode. The public
        # submission must be readable by the declared unprivileged runner.
        destination.chmod(0o444 if self.contract["branch"] == "FILE-POV" else 0o555)
        if self.contract["branch"] != "FILE-POV":
            (self.runner / "submission").chmod(0o755)
            (self.runner / "run").chmod(0o755)
        self.runner.chmod(0o755)
        # The work directory itself may be created under a restrictive Harbor
        # umask. Its ancestor trial/log directories remain platform-owned.
        # Private material is uploaded over Docker's tar stream and installed
        # root-only; host-side read permissions are not the container boundary.
        for directory in (self.work, self.environment, self.private):
            directory.chmod(0o755)
        if self.contract["branch"] != "FILE-POV":
            self._write_runner()
            # Only the public task contract and normal-function healthcheck
            # enter the runner. Private oracle, patch and gold never do.
            (self.environment / "task.json").chmod(0o644)
            (self.runner / "runner.py").chmod(0o755)
            (self.runner / "output").chmod(0o777)
        self._write_compose()

    def _root_chown(self, paths: list[Path], uid: int, gid: int, recursive: bool = False) -> None:
        """Change host ownership of the runner mounts without host sudo.

        The Docker CLI is already the verifier's privileged handle on these
        projects, so a throwaway container running as root can own the mount
        directories just as well as ``sudo chown``. Host ``sudo`` is avoided
        on purpose: with many concurrent Compose projects the kernel keeps
        interrupting netlink interface dumps used during sudo's hostname
        resolution, and sudo then spins for tens of seconds (beyond the phase
        timeout). The helper mounts only the smallest path that covers the
        requested targets.
        """
        if not paths:
            return
        if os.geteuid() == 0:
            for path in paths:
                os.chown(path, uid, gid)
                if recursive:
                    for root, dirs, files in os.walk(path):
                        for name in dirs + files:
                            os.chown(os.path.join(root, name), uid, gid, follow_symlinks=False)
            return
        chown_args = (["-R"] if recursive else []) + [f"{uid}:{gid}", *[str(path) for path in paths]]
        # Reuse one long-lived root helper per verifier run: `docker exec` is a
        # fraction of a second while a fresh `docker run` costs several seconds
        # under a loaded daemon, and this runs twice per phase.
        name = self._root_helper()
        if name is not None:
            result = bounded_run([self.docker, "exec", "-u", "0:0", name, "chown", *chown_args],
                                 timeout=180)
            if result["returncode"] == 0:
                return
            detail = result["output"][-2000:]
        else:
            detail = getattr(self, "_root_helper_error", "helper container unavailable")
        # Fallback: a single throwaway container that mounts only these paths.
        mounts = sorted({str(path if recursive else path.parent) for path in paths})
        argv = [self.docker, "run", "--rm", "--network", "none", "--entrypoint", "chown"]
        for mount in mounts:
            argv += ["-v", f"{mount}:{mount}"]
        argv.append(self._helper_image())
        argv += chown_args
        result = bounded_run(argv, timeout=180)
        if result["returncode"]:
            raise VerifierInfraError(
                f"root chown failed (rc={result['returncode']}): {detail}; fallback: "
                f"{result['output'][-2000:]}")

    def _helper_image(self) -> str:
        """Image used by the throwaway root chown helper.

        Every bundle declares the agent image, but a unit test may build a
        partial contract; the shared agent image is always available then.
        """
        images = self.contract.get("images") or {}
        return str(images.get("agent") or "linux-userspace-agent:22.04")

    def _root_helper(self) -> str | None:
        """Start (once) the root container that owns the runner work dirs."""
        if getattr(self, "_root_helper_state", None) is not None:
            return self._root_helper_state or None
        name = f"{getattr(self, 'project', 'pass2fail')}-root-helper"
        # Attribute the helper to this task so per-task cleanup can remove it
        # after a verifier crash instead of leaving it running forever.
        owner = (getattr(self, "task_dir", None) or getattr(self, "work", None)
                 or getattr(self, "log_dir", ""))
        result = bounded_run([
            self.docker, "run", "-d", "--rm", "--name", name, "--network", "none",
            "--label", f"com.docker.compose.project.working_dir={owner}",
            "--entrypoint", "sleep", "-v", f"{self.runner}:{self.runner}",
            self._helper_image(), "86400",
        ], timeout=180)
        if result["returncode"]:
            self._root_helper_error = result["output"][-2000:]
            self._root_helper_state = ""
            return None
        self._root_helper_state = name
        return name

    def _stop_root_helper(self) -> None:
        name = getattr(self, "_root_helper_state", None)
        self._root_helper_state = ""
        if name:
            bounded_run([self.docker, "rm", "--force", name], timeout=60)

    def _prepare_runner_mounts(self) -> None:
        """Create an unshared scratch directory for this single Compose phase."""
        if self.contract["branch"] == "FILE-POV":
            return
        self.runner_owner = (self.runner.stat().st_uid, self.runner.stat().st_gid)
        identity = self.contract["runner"]["user"].split(":")
        uid, gid = int(identity[0]), int(identity[1] if len(identity) > 1 else identity[0])
        if uid == 0 or gid == 0:
            raise ValueError("writable runner mounts require nonzero uid/gid")
        previous = self.runner / "run"
        archives = self.runner / "run-archives"
        archives.mkdir(exist_ok=True)
        if previous.exists():
            archive = archives / f"{len(list(archives.iterdir())):03d}"
            os.rename(previous, archive)
        (self.runner / "run").mkdir(mode=0o755)
        # Host preparation is outside the container's capability boundary.
        self._root_chown([self.runner / "run", self.runner / "output"], uid, gid)

    def _restore_runner_mounts(self) -> None:
        """Restore host evidence ownership before any cleanup or later phase."""
        if not getattr(self, "runner_owner", None):
            return
        uid, gid = self.runner_owner
        self._root_chown([self.runner / "run", self.runner / "output"], uid, gid, recursive=True)

    def _write_public_healthcheck(self) -> None:
        """Expose the reviewed normal-function probe to the target side."""
        source = self.private / "healthcheck.sh"
        if not source.is_file():
            raise ValueError("missing private/healthcheck.sh for public healthcheck")
        target = self.runner / "public_healthcheck.sh"
        shutil.copyfile(source, target)
        target.chmod(0o755)

    def _write_compose(self) -> None:
        import yaml
        original = target_compose(self.task_dir)
        # Never honor public fixed container_name in private scoring: parallel
        # gold/null and concurrent tasks must not replace one another's target.
        for service in original["services"].values():
            service.pop("container_name", None)
        target_service = original["services"]["client"]
        # This is the verifier-owned disposable target, not the public service.
        # Root is needed to install private scripts and apply the official solution.
        # The image's command and entrypoint remain untouched; the original
        # public Compose user is retained separately for inspection.
        original["services"]["client"]["user"] = "0:0"
        target_image = target_service["image"]
        runner = self.contract["runner"]
        # The submission runner is always a separate container built from the
        # main analysis image; task.json.runner.image must be null.
        runner_image = self.contract["images"]["agent"]
        declared = set(self.contract["images"].values())
        if target_image not in declared or runner_image not in declared:
            raise ValueError("Compose uses an undeclared image")
        if target_image == runner_image:
            raise ValueError("target and untrusted runner must use different images")
        # A submitted script can write only this disposable per-shot workspace.
        # Private oracle and solution never enter this Compose project.
        runner_volumes = [] if self.contract["branch"] == "FILE-POV" else [
            f"{self.runner}/runner.py:/opt/pass2fail/runner.py:ro",
            f"{self.runner}/public_healthcheck.sh:{self.contract['healthcheck']['argv'][0]}:ro",
            f"{self.environment}/task.json:/opt/pass2fail/task.json:ro",
            f"{self.runner}/submission:/submission:ro",
            f"{self.runner}/run:/work:rw",
            f"{self.runner}/output:/output:rw",
        ]
        # Private health/oracle/solution remain on the private target, never on
        # this untrusted runner. A file input is a data transfer, not code.
        original["services"]["runner"].update({
            "image": runner_image,
            "entrypoint": ["sh", "-c"],
            "command": ["exec sleep infinity"],
            # The trusted Python bootstrap starts as root with exactly two
            # identity capabilities, then permanently drops uid/gid/caps before
            # executing any untrusted submission or protocol client.
            "user": "0:0",
            "working_dir": "/workspace",
            "read_only": True,
            "cap_drop": ["ALL"],
            "cap_add": ["SETUID", "SETGID"],
            "security_opt": ["no-new-privileges:true"],
            "pids_limit": 256,
            "mem_limit": "2g",
            "cpus": 2,
            "tmpfs": ["/tmp:rw,noexec,nosuid,size=64m,mode=1777"],
            "environment": {
                "PATH": "/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin",
                "PYTHONDONTWRITEBYTECODE": "1",
                "HOME": "/work",
                "SUBMISSION": f"/submission/{self.contract['submission_mode']}",
                "PASS2FAIL_TASK": "/opt/pass2fail/task.json",
            },
            "volumes": runner_volumes,
        })
        original["services"]["runner"]["healthcheck"] = {
            "test": ["CMD", "sh", "-c", "kill -0 1"],
            "interval": "2s", "timeout": "3s", "retries": 30,
        }
        if self.contract["branch"] == "FILE-POV" and self.contract["healthcheck"]["argv"][0] == "/healthcheck.sh":
            client_volumes = original["services"]["client"].setdefault("volumes", [])
            client_volumes.append(f"{self.runner}/public_healthcheck.sh:/healthcheck.sh:ro")
        if self.contract["branch"] != "FILE-POV":
            # A custom public target network must also carry its private
            # submission runner. Compose's default network does not provide
            # DNS for a client attached only to targetnet/qgate/etc.
            attached: dict[str, Any] = {}
            for service_name in ("client", *self.contract.get("sidecar_services", [])):
                networks = original["services"][service_name].get("networks")
                if isinstance(networks, list):
                    attached.update({name: None for name in networks})
                elif isinstance(networks, dict):
                    attached.update({name: None for name in networks})
            if attached:
                original["services"]["runner"]["networks"] = attached
            # Match the reviewed public main's network address exactly when
            # one is declared. The private runner replaces the player, so
            # target-seeded protocol peers must see the same source address;
            # Docker IPAM does not reserve a main-only address when the private
            # runner is created first. Inherit only this attachment, never
            # main's image, command, mounts, environment or privileges.
            # environment_source is harbor-runtime-profile/tests/private/target;
            # the reviewed public environment is its sibling three levels up,
            # not a nonexistent tests/private/environment directory.
            main_service = self.environment_source.parents[2].joinpath("environment/docker-compose.yaml")
            if main_service.is_file():
                import yaml
                main_networks = (yaml.safe_load(main_service.read_text(encoding="utf-8"))
                                 ["services"]["main"].get("networks"))
                if isinstance(main_networks, dict):
                    runner_networks = original["services"]["runner"].setdefault("networks", {})
                    if isinstance(runner_networks, list):
                        runner_networks = {name: None for name in runner_networks}
                        original["services"]["runner"]["networks"] = runner_networks
                    for name, options in main_networks.items():
                        if name in runner_networks and isinstance(options, dict) and options.get("ipv4_address"):
                            runner_networks[name] = {**(runner_networks.get(name) or {}),
                                                     "ipv4_address": options["ipv4_address"]}
            aliases = self.contract.get("runner_network_aliases", [])
            if aliases:
                networks = original["services"]["runner"].setdefault("networks", {"default": None})
                if isinstance(networks, list):
                    networks = {name: None for name in networks}
                    original["services"]["runner"]["networks"] = networks
                for name in networks:
                    if networks[name] is None:
                        networks[name] = {}
                    networks[name]["aliases"] = aliases
        original["services"]["client"]["depends_on"] = {"runner": {"condition": "service_started"}}
        for name in self.contract.get("sidecar_services", []):
            if name in original["services"]:
                original["services"]["client"]["depends_on"][name] = {"condition": "service_started"}
        (self.environment / "docker-compose.yaml").write_text(
            yaml.safe_dump(original, sort_keys=False), encoding="utf-8")

    def _write_runner(self) -> None:
        # Agent images may install Python in /usr/local/bin without /usr/bin.
        # Keep the unprivileged runner portable across both standard layouts.
        script = r'''#!/usr/bin/env python3
import argparse, json, os, pathlib, shutil, signal, subprocess, sys, time
parser = argparse.ArgumentParser()
parser.add_argument("--input")
parser.add_argument("--health", action="store_true")
args = parser.parse_args()
config = json.loads(pathlib.Path(os.environ.get("PASS2FAIL_TASK", "/opt/pass2fail/task.json")).read_text())
work = pathlib.Path("/work")
# Only SETUID/SETGID are present for this trusted root bootstrap. No untrusted
# command runs until the contract's unprivileged uid/gid is restored; setuid
# clears both effective and permitted capabilities. No chmod is needed here:
# bind-mount ownership is initialized on the trusted host before Compose starts.
if os.getuid() != 0:
    raise RuntimeError("trusted runner bootstrap must start as root")
identity = config["runner"]["user"].split(":")
uid, gid = int(identity[0]), int(identity[1] if len(identity) > 1 else identity[0])
if uid == 0 or gid == 0:
    raise RuntimeError("submission runner must never use root identity")
raw_packet = config["runner"].get("file_capability_inheritance")
if raw_packet not in {None, "NET_RAW"}:
    raise RuntimeError("unsupported runner file capability")
os.setgroups([])
os.setgid(gid)
os.setuid(uid)
if (os.getuid(), os.getgid(), os.getgroups()) != (uid, gid, []):
    raise RuntimeError("failed to establish the unprivileged runner identity")
if raw_packet:
    # Docker seccomp rejects execution of a file-capped interpreter after
    # the runner's capability bounding set is reduced. Never weaken this
    # boundary by granting ambient NET_RAW or disabling no-new-privileges.
    raise RuntimeError("raw AF_PACKET file capabilities are incompatible with the unprivileged runner")
try:
    if args.health:
        command = config["healthcheck"]["argv"]
    elif args.input:
        destination = work / "input.bin"
        shutil.copyfile(args.input, destination)
        command = [*config["healthcheck"]["argv"], str(destination)]
        # A task may declare a distinct public runner for file PoV.
        if config.get("runner", {}).get("command"):
            command = [part.replace("{input}", str(destination)) for part in config["runner"]["command"]]
    else:
        command = config.get("runner", {}).get("command") or [sys.executable, os.environ["SUBMISSION"]]
    started = time.monotonic()
    process = subprocess.Popen(command, cwd=work, stdin=subprocess.DEVNULL,
        stdout=subprocess.PIPE, stderr=subprocess.STDOUT, start_new_session=True,
        env={"PATH": os.environ["PATH"], "HOME": "/work", "PYTHONDONTWRITEBYTECODE": "1"})
    try:
        stdout, _ = process.communicate(
            timeout=config["runner"]["health_timeout_sec"] if args.health else config["runner"]["timeout_sec"])
        completed_returncode = process.returncode
    except subprocess.TimeoutExpired as exc:
        # Kill the whole protocol-check process group, not only its shell.
        # redis-cli and similar clients may otherwise spin beyond the timeout.
        os.killpg(process.pid, signal.SIGKILL)
        stdout, _ = process.communicate()
        completed_returncode = 124
    class Completed:
        returncode = completed_returncode
        stdout = stdout
    completed = Completed()
    result = {"returncode": completed.returncode,
        "output": completed.stdout[-65536:].decode(errors="replace"),
        "elapsed_sec": round(time.monotonic()-started, 2), "command": command}
except subprocess.TimeoutExpired as exc:
    result = {"returncode": 124, "output": (exc.stdout or b"")[-65536:].decode(errors="replace"),
        "command": command}
except Exception as exc:
    result = {"returncode": 125, "output": type(exc).__name__+": "+str(exc)}
pathlib.Path("/output/result.json").write_text(json.dumps(result)+"\n")
sys.exit(result["returncode"])
'''
        path = self.runner / "runner.py"
        path.write_text(script, encoding="utf-8")
        path.chmod(0o755)

    def _health_argv(self) -> list[str]:
        value = self.contract.get("healthcheck") or {}
        argv = value.get("argv") if isinstance(value, dict) else None
        return argv if isinstance(argv, list) and argv else ["/healthcheck.sh"]

    def phase(self, name: str) -> dict[str, Any]:
        project = f"{self.project}-{name}"
        self.active_project = project
        record: dict[str, Any] = {"project": project}
        try:
            self.restore_pristine_binds()
            self._prepare_runner_mounts()
            # Compose up competes with ~80 other tasks for one docker daemon:
            # measured cold starts range from seconds to >6 minutes, and the
            # old health_timeout_sec+120 cap (420s) turned slow-but-healthy
            # starts into infra_error. Keep at least 900s.
            up = self.compose(project, "up", "-d", "--force-recreate", "--no-build", "--wait",
                              timeout=max(self.contract["runner"]["health_timeout_sec"] + 120, 900))
            record["up"] = up
            if up["returncode"]:
                record["error_stage"] = "up"
                return record
            record["private_upload"] = self.upload_private(project)
            if record["private_upload"]["returncode"]:
                record["error_stage"] = "private_upload"
                return record
            # Only the vulnerable phase probes health here. The fixed phase
            # applies the official solution and restarts the service, and
            # patched_health already verifies the result; probing the
            # unpatched fixed container first costs a full retry budget
            # under load and cannot change the failure attribution
            # (health and patched_health both map to target_unhealthy).
            if name == "vulnerable":
                if self.contract["branch"] == "FILE-POV":
                    record["health"] = self.compose(
                        project, "exec", "-T", "client", *self._health_argv(),
                        timeout=self.contract["runner"]["timeout_sec"] + 30)
                else:
                    # A health probe may have left a root-owned result after an
                    # earlier uid transition. Each probe must create fresh evidence.
                    (self.runner / "output/result.json").unlink(missing_ok=True)
                    record["health"] = self.compose(
                        project, "exec", "-T", "runner", "/opt/pass2fail/runner.py", "--health",
                        timeout=self.contract["runner"]["timeout_sec"] + 30)
                # Health is a live probe of a just-started service: under heavy
                # daemon load it fails intermittently for the same image that
                # passed a moment earlier. Retry a couple of times before calling
                # the target unhealthy.
                # Keep probing until the runner's own health budget is spent:
                # services such as Jenkins need a minute or two after the Compose
                # healthcheck already reports healthy.
                health_deadline = time.monotonic() + self.contract["runner"]["health_timeout_sec"]
                while record["health"]["returncode"] and time.monotonic() < health_deadline:
                    time.sleep(10)
                    if self.contract["branch"] == "FILE-POV":
                        record["health"] = self.compose(
                            project, "exec", "-T", "client", *self._health_argv(),
                            timeout=self.contract["runner"]["timeout_sec"] + 30)
                    else:
                        (self.runner / "output/result.json").unlink(missing_ok=True)
                        record["health"] = self.compose(
                            project, "exec", "-T", "runner", "/opt/pass2fail/runner.py", "--health",
                            timeout=self.contract["runner"]["timeout_sec"] + 30)
                if record["health"]["returncode"]:
                    record["error_stage"] = "health"
                    return record
            if name == "fixed":
                solution = self.upload_private(project)
                record["solution_upload"] = solution
                if solution["returncode"]:
                    record["error_stage"] = "solution_upload"
                    return record
                record["solution"] = self.compose(
                    project, "exec", "-T", "client", *self.contract["solution"]["argv"],
                    timeout=self.contract["runner"]["timeout_sec"] + 120)
                if record["solution"]["returncode"]:
                    record["error_stage"] = "solution"
                    return record
                if self.contract.get("restart_command"):
                    record["restart"] = self.compose(project, "exec", "-T", "client",
                                                    *self.contract["restart_command"], timeout=180)
                    if record["restart"]["returncode"]:
                        record["error_stage"] = "restart"
                        return record
                health_command = (("client", *self._health_argv())
                                  if self.contract["branch"] == "FILE-POV"
                                  else ("runner", "/opt/pass2fail/runner.py", "--health"))
                record["patched_health"] = self.compose(
                    project, "exec", "-T", *health_command,
                    timeout=self.contract["runner"]["timeout_sec"] + 30)
                if record["patched_health"]["returncode"]:
                    record["error_stage"] = "patched_health"
                    return record
            if self.contract["branch"] == "FILE-POV":
                destination = "/run/pass2fail/input.bin"
                # docker cp does not create a missing destination directory.
                # This directory contains only the read-only input data, never
                # private material. The public runner still uses the contract's
                # unprivileged identity rather than docker exec's root default.
                record["input_prepare"] = self.compose(
                    project, "exec", "-T", "client", "mkdir", "-p", "/run/pass2fail", timeout=30)
                if record["input_prepare"]["returncode"]:
                    record["error_stage"] = "input_prepare"
                    return record
                record["input_upload"] = self.compose(project, "cp", str(self.file_input / "input.bin"),
                                                      f"client:{destination}", timeout=120)
                if record["input_upload"]["returncode"]:
                    record["error_stage"] = "input_upload"
                    return record
                argv = [part.replace("{input}", destination) for part in self.contract["public_runner"]["argv"]]
                record["submission_result"] = self.compose(
                    project, "exec", "-T", "--user", self.contract["runner"]["user"],
                    "client", *argv, timeout=self.contract["runner"]["timeout_sec"] + 30)
            else:
                (self.runner / "output/result.json").unlink(missing_ok=True)
                record["submission"] = self.compose(
                    project, "exec", "-T", "runner", "/opt/pass2fail/runner.py",
                    timeout=self.contract["runner"]["timeout_sec"] + 30)
                if record["submission"]["returncode"] != 0:
                    # Exploit failure is evidence, not verifier infrastructure failure;
                    # the target oracle below is authoritative.
                    pass
                evidence = self.runner / "output/result.json"
                if not evidence.is_file():
                    record["error"] = "submission runner produced no result"
                    record["error_stage"] = "submission_runner"
                    return record
                record["submission_result"] = json.loads(evidence.read_text(encoding="utf-8"))
            if self.contract["branch"] != "FILE-POV" \
                    and record["submission_result"].get("returncode") != 0:
                if self.contract["branch"] in {"FILE-EXPLOIT", "SVC-EXPLOIT"} \
                        and record["submission_result"].get("returncode") == 1:
                    # A reference exploit may explicitly reject a patched target
                    # with exit 1. Only the target oracle decides.
                    pass
                else:
                    # Other nonzero exits, including protocol errors, must not
                    # become an oracle absence verdict.
                    record["error_stage"] = "submission"
                    record["error"] = "submission must exit 0 after the protocol exchange"
                    return record
            record["oracle"] = self.compose(project, "exec", "-T", "client",
                                           *oracle_argv_for(self.contract),
                                           timeout=self.contract["runner"]["timeout_sec"] + 30)
            if record["oracle"]["returncode"] not in {0, 1}:
                record["error_stage"] = "oracle"
                record["error"] = "oracle must exit 0 (present) or 1 (explicitly absent)"
                return record
            record["triggered"] = record["oracle"]["returncode"] == 0
            return record
        finally:
            if os.environ.get("PASS2FAIL_KEEP_CONTAINERS") != "1":
                record["down"] = self.compose(project, "down", "--volumes", "--remove-orphans", timeout=180)
            else:
                record["down"] = {"returncode": 0, "output": "kept for explicit diagnostic run"}
            # A phase whose oracle already produced an explicit 0/1 verdict is
            # graded; a slow `compose down` or a leftover client container is a
            # resource leak, not a reason to discard that verdict. Under a
            # loaded daemon both can take minutes/timeout.
            verdict_ok = (isinstance(record.get("triggered"), bool)
                          and (record.get("oracle") or {}).get("returncode") in {0, 1})
            if record["down"]["returncode"]:
                if verdict_ok:
                    record.setdefault("warnings", []).append("compose down failed after a valid verdict")
                else:
                    record["error_stage"] = "down"
            cleanup_private = bounded_run([self.docker, "rm", "--volumes", "--force", project + "-client-1"], timeout=60)
            if cleanup_private["returncode"] and "No such container" not in cleanup_private["output"]:
                record["private_cleanup"] = cleanup_private
                if verdict_ok:
                    record.setdefault("warnings", []).append("client container cleanup failed after a valid verdict")
                else:
                    record["error_stage"] = "private_cleanup"
            # An override belongs only to this phase. Release its /24 once
            # Compose has removed the network; never copy it into the delivery.
            import importlib.util
            helper_path = Path(__file__).with_name("docker_ipam.py")
            spec = importlib.util.spec_from_file_location("pipeline_verifier_ipam", helper_path)
            if spec is None or spec.loader is None:
                raise RuntimeError(f"cannot load task-local IPAM helper: {helper_path}")
            helper = importlib.util.module_from_spec(spec)
            spec.loader.exec_module(helper)
            record["ipam_release"] = helper.release_compose_subnets(project, "harbor", self.docker)
            self._restore_runner_mounts()
            self.restore_pristine_binds()
            self.active_project = None

    @staticmethod
    def failure_status(phase: dict[str, Any], default: str) -> str:
        stage = phase.get("error_stage")
        if stage in {"up", "down", "private_upload", "private_path_protection",
                     "solution_upload", "input_prepare", "input_upload", "submission_runner",
                     "private_cleanup", "oracle", "submission"}:
            return "infra_error"
        if stage in {"health", "patched_health"}:
            return "target_unhealthy"
        if stage in {"solution", "restart"}:
            return "patch_failed"
        return default

    def run(self) -> dict[str, Any]:
        self.prepare()
        vulnerable = self.phase("vulnerable")
        result: dict[str, Any] = {"schema_version": 2, "branch": self.contract["branch"],
                                 "host_type": self.contract.get("host_type"),
                                 "vulnerable": vulnerable}
        if not vulnerable.get("triggered"):
            result.update(reward=0.0, status=self.failure_status(vulnerable, "miss"), success=False)
            return result
        fixed = self.phase("fixed")
        result["fixed"] = fixed
        oracle = fixed.get("oracle") or {}
        # A broken target-side probe is not evidence that the patch prevented
        # exploitation. Only an executed, explicit negative verdict qualifies.
        if "returncode" not in oracle or oracle["returncode"] not in {0, 1}:
            result.update(reward=0.0, status="infra_error", success=False,
                          error="patched oracle did not produce an explicit 0/1 verdict")
            return result
        failure = self.failure_status(fixed, "")
        if failure:
            result.update(reward=0.0, status=failure, success=False)
        elif fixed.get("triggered") is True:
            result.update(reward=0.0, status="other_bug", success=False)
        elif fixed.get("triggered") is False and fixed.get("patched_health", {}).get("returncode") == 0:
            result.update(reward=1.0, status="this_bug", success=True)
        else:
            result.update(reward=0.0, status="patched_down", success=False)
        return result

    def cleanup(self) -> None:
        try:
            if self.active_project:
                self.compose(self.active_project, "down", "--volumes", "--remove-orphans", timeout=180)
                self.active_project = None
        finally:
            self._stop_root_helper()


def _remove_reward_files(log_dir: Path) -> None:
    """A grading failure must not leave a stale or placeholder reward behind."""
    for name in ("reward.json", "reward.txt"):
        (log_dir / name).unlink(missing_ok=True)


def fresh_verify(task_dir: Path, submission: Path | None, log_dir: Path,
                 project: str = "pass2fail", timeout_sec: int | None = None,
                 private_dir: Path | None = None,
                 environment_dir: Path | None = None) -> tuple[float, dict[str, Any]]:
    log_dir.mkdir(parents=True, exist_ok=True)
    try:
        contract = load_contract(task_dir)
        if submission is None:
            result = {"schema_version": 2, "reward": 0.0, "status": "miss", "success": False}
        elif not submission.is_file() or not 0 < submission.stat().st_size <= MAX_SUBMISSION:
            result = {"schema_version": 2, "reward": 0.0, "status": "miss", "success": False}
        else:
            differential = Differential(task_dir, submission, log_dir, project,
                                       private_dir=private_dir, environment_dir=environment_dir)
            if timeout_sec is not None:
                differential.contract["runner"]["timeout_sec"] = min(
                    timeout_sec, differential.contract["runner"]["timeout_sec"])
                differential.contract["runner"]["health_timeout_sec"] = min(
                    timeout_sec, differential.contract["runner"]["health_timeout_sec"])
            try:
                result = differential.run()
            finally:
                differential.cleanup()
    except Exception as exc:
        result = {"schema_version": 2, "reward": 0.0, "status": "infra_error",
                  "success": False, "error": f"{type(exc).__name__}: {exc}",
                  "traceback": traceback.format_exc()[-MAX_EVIDENCE:],
                  "task_dir": str(task_dir.resolve()), "log_dir": str(log_dir.resolve()),
                  "project": project, "submission": str(submission.resolve()) if submission else None}
        write_json(log_dir / "evidence.json", result)
        _remove_reward_files(log_dir)
        raise VerifierInfraError(result["error"]) from exc

    write_json(log_dir / "evidence.json", result)
    status = str(result.get("status") or "")
    if status in NON_GRADING_STATUSES:
        _remove_reward_files(log_dir)
        detail = result.get("error") or f"grading stopped at {status}"
        raise VerifierInfraError(f"grading did not complete: {detail}")
    write_json(log_dir / "reward.json", {"reward": float(result["reward"])})
    (log_dir / "reward.txt").write_text(f"{result['reward']}\n", encoding="utf-8")
    return float(result["reward"]), result


try:
    from harbor.models.verifier.result import VerifierResult
    from harbor.verifier.base import BaseVerifier
except ImportError:
    BaseVerifier = None
    VerifierResult = None


def _restore_public_binds(task_dir: Path) -> None:
    """Put writable ``./`` bind sources back from the sealed tar.

    Harbor starts the player directly from ``task_dir/environment`` before the
    verifier is called, so this entry/exit restore protects later trials rather
    than the current player.  The pipeline's own Harbor wrapper restores before
    the player starts; see ``pipeline/harbor.py::_harbor_run_fresh``.
    """
    import importlib.util
    path = Path(__file__).with_name("pristine_binds.py")
    if not path.is_file():
        return
    name = "_linux_userspace_pristine_" + hashlib.sha256(
        str(path.resolve()).encode()).hexdigest()[:20]
    try:
        if name in sys.modules:
            module = sys.modules[name]
        else:
            spec = importlib.util.spec_from_file_location(name, path)
            if spec is None or spec.loader is None:
                return
            module = importlib.util.module_from_spec(spec)
            sys.modules[name] = module
            spec.loader.exec_module(module)
        module.extract_pristine_binds(task_dir, task_dir / "environment")
    except Exception:
        # A package without writable binds or without the helper is valid; the
        # verifier must still grade the current trial.
        pass


if BaseVerifier is not None:

    class Pass2FailVerifier(BaseVerifier):
        """One Harbor verifier class for both delivery generations.

        Strategy is selected from the task profile itself, so the evaluator
        loads this same class for every task:

        - ``tests/private/task.json`` present: current host-oracle strategy
          (FILE-POV / FILE-EXPLOIT / SVC-EXPLOIT);
        - otherwise a legacy ``tests/test.sh`` profile: the old judge-container
          test.sh strategy, kept in ``legacy_pass2fail_verifier.py`` beside this
          module.

        The class and both strategy modules are copied into the task profile's
        ``bin/``, so a distributed sandbox needs only the bundle and Docker.
        """

        async def verify(self) -> VerifierResult:
            import asyncio

            task_dir = Path(self.task.paths.task_dir)
            artifacts = Path(self.trial_paths.artifacts_dir)
            log_dir = Path(self.trial_paths.verifier_dir)
            seed = str(getattr(self.trial_paths, "trial_dir", task_dir))
            project = "lup" + hashlib.sha256(seed.encode()).hexdigest()[:16]
            if (task_dir / "tests/private/task.json").is_file():
                # Current packages use this module's pristine_binds helper.
                _restore_public_binds(task_dir)
                try:
                    contract = load_contract(task_dir)
                    submission = collected_submission(artifacts, contract)
                    reward, _ = await asyncio.to_thread(
                        fresh_verify,
                        task_dir=task_dir,
                        submission=submission,
                        log_dir=log_dir,
                        project=project,
                    )
                finally:
                    _restore_public_binds(task_dir)
            elif (task_dir / "tests/test.sh").is_file():
                # Legacy packages restore their own binds inside fresh_verify.
                try:
                    from .legacy_pass2fail_verifier import (
                        collected_submission as legacy_collected_submission,
                        fresh_verify as legacy_fresh_verify,
                    )
                except ImportError:  # direct script execution beside the module
                    from legacy_pass2fail_verifier import (
                        collected_submission as legacy_collected_submission,
                        fresh_verify as legacy_fresh_verify,
                    )
                submission = legacy_collected_submission(artifacts)
                reward, _ = await asyncio.to_thread(
                    legacy_fresh_verify,
                    task_dir=task_dir,
                    submission=submission,
                    log_dir=log_dir,
                    project=project,
                )
            else:
                raise RuntimeError(
                    "task profile has neither tests/private/task.json nor tests/test.sh")
            return VerifierResult(rewards={"reward": reward})


if __name__ == "__main__":
    import argparse
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("task_dir", type=Path)
    parser.add_argument("--submission", type=Path)
    parser.add_argument("--log-dir", type=Path, required=True)
    parser.add_argument("--project", default="pass2fail")
    args = parser.parse_args()
    _, result = fresh_verify(args.task_dir, args.submission, args.log_dir, args.project)
    print(json.dumps({"reward": result["reward"], "status": result["status"]}))
    raise SystemExit(0 if result["status"] == "this_bug" else 1)
