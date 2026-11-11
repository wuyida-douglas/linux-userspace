"""Harbor --verifier：separate 拆掉选手环境之后，按交付包重新拉起靶再跑 Pass2Fail。

类跑在宿主机的 Harbor 进程里，不跑在 main 里。main 不挂 docker.sock。
唯一从选手容器留下的文件是 task.toml artifacts 收上来的 /workspace/exploit.py。
合成末尾把 reference_exploit.py 只读挂到这个路径，收上来的就是金标。
收窄 docker 在镜像里的 /opt/cve-factory/scope_docker.py，判分容器不再挂本仓库。
同一份类文件会复制到交付包 bin/pass2fail_verifier.py，甲方不用这份 git 仓库。
可写 ./ 绑定在出包时打进任务目录下的 pristine-binds.tar，不放进 images/。之后只解压这份归档，不再改它。
打包、解压和清理遇到权限不足时，仅对该文件操作使用免密 sudo -n。
"""

from __future__ import annotations

import hashlib
import json
import os
import re
import shutil
import stat
import subprocess
import tarfile
import sys
import tempfile
import time
from pathlib import Path

SUBMISSION_SOURCE = "/workspace/exploit.py"
AGENT_IMAGE_DEFAULT = "cve-factory/ubuntu-agent:22.04"
SCOPE_DOCKER = "/opt/cve-factory/scope_docker.py"

SHIM = f"""#!/bin/sh
export SCOPE_DOCKER_BIN=/opt/docker-bin/docker
exec python3 {SCOPE_DOCKER} "$@"
"""


def project_name(seed: str) -> str:
    digest = hashlib.sha256(seed.encode()).hexdigest()[:12]
    return f"efgv{digest}"


def pick_network(names: list[str], project: str) -> str:
    preferred = f"{project}_default"
    if preferred in names:
        return preferred
    for name in names:
        if name.endswith("_default"):
            return name
    if not names:
        raise RuntimeError("client has no docker network")
    return names[0]


def agent_image(task_toml: Path) -> str:
    if not task_toml.is_file():
        return AGENT_IMAGE_DEFAULT
    for raw in task_toml.read_text(encoding="utf-8", errors="replace").splitlines():
        line = raw.split("#", 1)[0].strip()
        if not line.startswith("docker_image"):
            continue
        value = line.split("=", 1)[1].strip().strip("\"'")
        if value:
            return value
    return AGENT_IMAGE_DEFAULT


def app_port(task_dir: Path) -> str:
    path = task_dir / "tests" / "private" / "app_port"
    if not path.is_file():
        return ""
    text = path.read_text(encoding="utf-8", errors="replace").strip()
    return text if text.isdigit() else ""


def collected_submission(artifacts_dir: Path) -> Path | None:
    path = artifacts_dir / "workspace" / "exploit.py"
    if path.is_file() and path.stat().st_size > 0:
        return path
    return None


def _log(message: str) -> None:
    print(f"pass2fail: {message}", file=sys.stderr)


def _tail(text: str, limit: int = 400) -> str:
    text = (text or "").strip()
    return text[-limit:]


def _read_reward(log_dir: Path) -> tuple[float, str] | None:
    reward_path = log_dir / "reward.txt"
    if not reward_path.is_file():
        return None
    try:
        reward = float(reward_path.read_text(encoding="utf-8").strip())
    except (OSError, ValueError):
        return None
    status = "scored"
    output = log_dir / "test-output.txt"
    if output.is_file():
        first = output.read_text(encoding="utf-8", errors="replace").splitlines()
        if first and first[0].startswith("{"):
            try:
                status = str(json.loads(first[0]).get("status") or status)
            except json.JSONDecodeError:
                pass
    return reward, status


def _write_reward(log_dir: Path, reward: float, status: str, detail: str) -> None:
    log_dir.mkdir(parents=True, exist_ok=True)
    (log_dir / "reward.txt").write_text(f"{reward}\n", encoding="utf-8")
    (log_dir / "test-output.txt").write_text(
        json.dumps({"reward": reward, "status": status}, ensure_ascii=False)
        + "\n"
        + detail
        + "\n",
        encoding="utf-8",
    )


def host_docker_bin() -> str:
    """Real docker client, not scripts/core/factory-bin/docker.

    Synthesis puts that wrapper first on PATH. Mounting it into the judge
    makes restart fail: the wrapper execs /usr/bin/docker, which is not in
    the judge image.
    """
    explicit = (os.environ.get("FACTORY_REAL_DOCKER") or "").strip()
    for candidate in (explicit, "/usr/bin/docker"):
        if candidate and Path(candidate).is_file():
            return candidate
    return shutil.which("docker") or "/usr/bin/docker"


def writable_bind_rels(compose_text: str) -> list[str]:
    """Compose bind sources under ./ that are not read-only.

    The vulnerable shot can write through these into the package tree.
    The fixed shot has to see the bytes from before that shot.
    """
    rels: list[str] = []
    for raw in compose_text.splitlines():
        line = raw.split("#", 1)[0].strip()
        if not line or ":ro" in line:
            continue
        match = re.search(r"(\./[^:\s]+):", line)
        if not match:
            continue
        rel = match.group(1)[2:].strip("/")
        if rel and rel not in rels:
            rels.append(rel)
    # A parent bind already contains the nested one (./init and
    # ./init/volumes/<id>). Snapshotting both makes copytree hit the
    # directory the parent copy just created.
    covered = []
    for rel in rels:
        if any(rel != other and rel.startswith(other.rstrip("/") + "/") for other in rels):
            continue
        covered.append(rel)
    return covered


def _skip_special_files(dirpath: str, names: list[str]) -> list[str]:
    """Skip sockets and dangling symlinks. Same rule as the exporter."""
    skipped: list[str] = []
    for name in names:
        entry = Path(dirpath) / name
        try:
            mode = entry.lstat().st_mode
        except OSError:
            skipped.append(name)
            continue
        if not (stat.S_ISREG(mode) or stat.S_ISDIR(mode) or stat.S_ISLNK(mode)):
            skipped.append(name)
            continue
        if stat.S_ISLNK(mode) and not entry.exists():
            skipped.append(name)
    return skipped


def _copy_bind_tree(src: Path, target: Path) -> None:
    """copytree that skips sockets and dangling symlinks (mysql.sock)."""
    shutil.copytree(src, target, symlinks=True, ignore=_skip_special_files)
    if os.geteuid() == 0:
        for directory, directories, files in os.walk(target, topdown=False):
            copied = Path(directory)
            for entry in [copied, *(copied / name for name in directories + files)]:
                original = src / entry.relative_to(target)
                _preserve_bind_ownership(original, entry)


def _preserve_bind_ownership(src: Path, target: Path) -> None:
    if os.geteuid() == 0:
        metadata = src.lstat()
        os.chown(target, metadata.st_uid, metadata.st_gid, follow_symlinks=False)
        shutil.copystat(src, target, follow_symlinks=False)


def _bind_path(root: Path, rel: str) -> Path:
    relative = Path(rel)
    if relative.is_absolute() or not relative.parts or ".." in relative.parts:
        raise ValueError(f"Invalid bind relative path: {rel}")
    target = root / relative
    if not target.parent.resolve().is_relative_to(root):
        raise ValueError(f"Bind path escapes its root: {target}")
    return target


def _remove_bind_path(target: Path) -> None:
    if target.is_symlink():
        target.unlink()
    elif target.is_dir():
        if target.is_mount():
            raise ValueError(f"Refusing to remove bind mount point: {target}")
        shutil.rmtree(target)
    elif target.exists():
        target.unlink()


def _restore_bind_mount(src: Path, target: Path) -> None:
    """Restore directory contents without removing the mount point itself."""
    for entry in target.iterdir():
        _remove_bind_path(entry)
    for entry in src.iterdir():
        restored = target / entry.name
        if not entry.is_symlink() and entry.is_dir():
            _copy_bind_tree(entry, restored)
        else:
            shutil.copy2(entry, restored, follow_symlinks=False)
            _preserve_bind_ownership(entry, restored)


PRISTINE_BINDS_TAR = "pristine-binds.tar"


def pristine_binds_archive(runtime: Path) -> Path | None:
    """Sealed writable-bind archive beside environment/, never under images/."""
    runtime = Path(runtime)
    roots = [runtime]
    nested = runtime / "harbor-runtime-profile"
    if (nested / "environment" / "docker-compose.yaml").is_file():
        roots.insert(0, nested)
    for root in roots:
        if not (root / "environment" / "docker-compose.yaml").is_file():
            continue
        archive = root / PRISTINE_BINDS_TAR
        if archive.parent.name == "images":
            raise ValueError(f"Refusing to store pristine binds in images/: {archive}")
        return archive
    return None


def _compose_writable_rels(env_dir: Path) -> list[str]:
    compose = env_dir / "docker-compose.yaml"
    if not compose.is_file():
        return []
    return writable_bind_rels(compose.read_text(encoding="utf-8", errors="replace"))


def _tar_member_ok(info: tarfile.TarInfo) -> tarfile.TarInfo | None:
    if info.issym() or info.islnk() or info.isreg() or info.isdir():
        return info
    return None


def _reject_unsafe_member(member: tarfile.TarInfo, dest_path: str) -> tarfile.TarInfo:
    parts = Path(member.name).parts
    if not member.name or member.name.startswith("/") or ".." in parts:
        raise ValueError(f"Refusing tar member: {member.name}")
    if member.issym() or member.islnk():
        link_parts = Path(member.linkname).parts
        if member.linkname.startswith("/") or ".." in link_parts:
            raise ValueError(f"Refusing tar link: {member.name} -> {member.linkname}")
    if _tar_member_ok(member) is None:
        raise ValueError(f"Refusing special tar member: {member.name}")
    return member


def _pack_bind_archive(env_dir: Path, rels: list[str], dest: Path) -> None:
    """Write dest once. An existing archive is left untouched."""
    if dest.name != PRISTINE_BINDS_TAR:
        raise ValueError(f"Refusing to write pristine binds to {dest}")
    if dest.exists() or dest.is_symlink():
        return
    partial = dest.with_name(dest.name + ".partial")
    if partial.exists() or partial.is_symlink():
        _remove_bind_path(partial)
    try:
        with tarfile.open(partial, "w") as archive:
            for rel in rels:
                source = _bind_path(env_dir, rel)
                if not source.exists() and not source.is_symlink():
                    continue
                archive.add(source, arcname=rel, recursive=True, filter=_tar_member_ok)
        os.replace(partial, dest)
    except Exception:
        if partial.exists() or partial.is_symlink():
            _remove_bind_path(partial)
        raise


def _swap_extracted_bind(src: Path, target: Path) -> None:
    """Put src in target's place. A mount point keeps its path and receives the files."""
    if target.is_dir() and not target.is_symlink() and target.is_mount():
        _restore_bind_mount(src, target)
        return
    target.parent.mkdir(parents=True, exist_ok=True)
    old = target.with_name(target.name + ".pristine-old")
    if old.exists() or old.is_symlink():
        _remove_bind_path(old)
    if target.exists() or target.is_symlink():
        os.rename(target, old)
    try:
        os.rename(src, target)
    except Exception:
        if (not target.exists() and not target.is_symlink()) and (old.exists() or old.is_symlink()):
            os.rename(old, target)
        raise
    if old.exists() or old.is_symlink():
        _remove_bind_path(old)


def _unpack_bind_archive(env_dir: Path, rels: list[str], dest: Path) -> None:
    if dest.name != PRISTINE_BINDS_TAR or not dest.is_file():
        raise ValueError(f"Pristine binds archive is missing: {dest}")
    staging = Path(tempfile.mkdtemp(prefix=".efg-pristine-", dir=env_dir.parent))
    try:
        with tarfile.open(dest, "r") as archive:
            archive.extractall(staging, filter=_reject_unsafe_member)
        for rel in rels:
            src = _bind_path(staging, rel)
            target = _bind_path(env_dir, rel)
            if not src.exists() and not src.is_symlink():
                continue
            _swap_extracted_bind(src, target)
    finally:
        shutil.rmtree(staging, ignore_errors=True)


def _bind_operation(operation: str, env_dir: Path, rels: list[str], dest: Path) -> None:
    env_dir = env_dir.resolve()
    if dest.is_symlink():
        raise ValueError(f"Bind snapshot must not be a symlink: {dest}")
    dest = dest.resolve()
    if (
        env_dir == Path(env_dir.anchor)
        or dest == Path(dest.anchor)
        or dest.is_relative_to(env_dir)
        or env_dir.is_relative_to(dest)
    ):
        raise ValueError("Bind environment and snapshot must be separate non-root directories")
    if operation == "pack":
        _pack_bind_archive(env_dir, rels, dest)
        return
    if operation == "unpack":
        _unpack_bind_archive(env_dir, rels, dest)
        return
    if operation == "cleanup":
        if not dest.name.startswith("efg-binds-"):
            raise ValueError(f"Refusing to remove non-verifier snapshot: {dest}")
        _remove_bind_path(dest)
        return
    if operation not in ("snapshot", "restore"):
        raise ValueError(f"Unknown bind operation: {operation}")
    roots = (env_dir, dest) if operation == "snapshot" else (dest, env_dir)
    paths = [(_bind_path(roots[0], rel), _bind_path(roots[1], rel)) for rel in rels]
    for src, target in paths:
        if not src.exists() and not src.is_symlink():
            continue
        if (
            operation == "restore"
            and not src.is_symlink()
            and src.is_dir()
            and target.is_dir()
            and target.is_mount()
        ):
            _restore_bind_mount(src, target)
            continue
        _remove_bind_path(target)
        target.parent.mkdir(parents=True, exist_ok=True)
        if not src.is_symlink() and src.is_dir():
            _copy_bind_tree(src, target)
        else:
            shutil.copy2(src, target, follow_symlinks=False)
            _preserve_bind_ownership(src, target)


def _sudo_bind_operation(operation: str, env_dir: Path, rels: list[str], dest: Path) -> None:
    sudo = shutil.which("sudo")
    if sudo is None:
        raise PermissionError(f"Bind {operation} requires passwordless sudo, but sudo is unavailable")
    command = [
        sudo, "-n", "--", sys.executable, "-I", str(Path(__file__).resolve()),
        "--bind-operation", operation, str(env_dir.resolve()), str(dest.absolute()),
        json.dumps(rels),
    ]
    _log(f"using passwordless sudo for bind {operation}")
    result = subprocess.run(command, capture_output=True, text=True, timeout=180)
    if result.returncode != 0:
        detail = _tail(result.stderr or result.stdout, 1200)
        raise PermissionError(f"sudo bind {operation} failed: {detail}")


def _run_bind_operation(operation: str, env_dir: Path, rels: list[str], dest: Path) -> None:
    try:
        _bind_operation(operation, env_dir, rels, dest)
    except (PermissionError, shutil.Error) as exc:
        permission_error = isinstance(exc, PermissionError) or any(
            "[Errno 13]" in str(error) or "[Errno 1]" in str(error)
            for error in exc.args[0]
        )
        if not permission_error or os.geteuid() == 0:
            raise
        try:
            _sudo_bind_operation(operation, env_dir, rels, dest)
        except Exception as sudo_error:
            raise RuntimeError(
                f"bind {operation} failed: {exc}; sudo fallback failed: {sudo_error}"
            ) from sudo_error


def snapshot_binds(env_dir: Path, rels: list[str], dest: Path) -> None:
    _run_bind_operation("snapshot", env_dir, rels, dest)


def restore_binds(env_dir: Path, rels: list[str], dest: Path) -> None:
    _run_bind_operation("restore", env_dir, rels, dest)


def create_pristine_binds_tar(runtime: Path) -> Path | None:
    """Seal writable ./ binds once. A tar that already exists is not rewritten."""
    archive = pristine_binds_archive(runtime)
    if archive is None:
        return None
    if archive.is_file():
        return archive
    env_dir = archive.parent / "environment"
    _run_bind_operation("pack", env_dir, _compose_writable_rels(env_dir), archive)
    return archive


def extract_pristine_binds(runtime: Path) -> None:
    """Replace writable ./ binds from the sealed tar.

    The archive is extracted into a sibling directory, then each bind is renamed
    into place. Read-only binds are not in the archive and are left alone.
    """
    archive = pristine_binds_archive(runtime)
    if archive is None:
        return
    env_dir = archive.parent / "environment"
    rels = _compose_writable_rels(env_dir)
    if not rels:
        return
    if not archive.is_file():
        raise FileNotFoundError(f"missing pristine binds archive: {archive}")
    _run_bind_operation("unpack", env_dir, rels, archive)


def call_with_package_bind_restore(runtime: Path, call):
    """Run one Harbor invocation and put writable ./ binds back from the sealed tar.

    The tar is written once at export. Extracting before the process starts
    drops leftovers from a run that never restored. Extracting after it exits
    puts the package back even when verify never ran.
    """
    extract_pristine_binds(runtime)
    try:
        return call()
    finally:
        try:
            extract_pristine_binds(runtime)
        except Exception as exc:
            _log(f"restore package binds failed: {exc}")


def judge_vendor_mount(task_dir: Path) -> list[str]:
    """Mount exploit/gold next to exploit.py when the package has it.

    e1 runs the script with the work tree on disk, so `import wrapwrap`
    finds exploit/gold/wrapwrap.py. The judge only receives the one file
    unless this directory is mounted at /workspace/gold (CVE-2024-29859).
    """
    vendor = Path(task_dir) / "tests" / "private" / "gold"
    if not vendor.is_dir():
        return []
    return ["-v", f"{vendor.resolve()}:/workspace/gold:ro"]


def host_run(args: list[str], timeout: int = 120) -> subprocess.CompletedProcess[str]:
    return subprocess.run(
        args,
        capture_output=True,
        text=True,
        timeout=timeout,
    )


def fresh_verify(
    *,
    task_dir: Path,
    submission: Path | None,
    log_dir: Path,
    project: str,
    run=host_run,
    docker_bin: str | None = None,
) -> tuple[float, str]:
    """重新 compose up 交付包，在靶的网络里跑 test.sh。返回 (reward, status)。"""
    log_dir = Path(log_dir)
    log_dir.mkdir(parents=True, exist_ok=True)
    if submission is None or not Path(submission).is_file():
        _write_reward(log_dir, 0.0, "miss", "exploit.py was not collected")
        return 0.0, "miss"

    task_dir = Path(task_dir)
    compose = task_dir / "environment" / "docker-compose.yaml"
    if not compose.is_file():
        _write_reward(log_dir, 0.0, "error", f"missing {compose}")
        return 0.0, "error"

    binary = docker_bin or host_docker_bin()
    env_dir = compose.parent
    base = [
        "docker", "compose",
        "--project-name", project,
        "--project-directory", str(env_dir),
        "-f", str(compose),
    ]
    judge = f"{project}-judge"
    try:
        extract_pristine_binds(task_dir)
        # CVE-2025-52289 printed the planted flag, then force-recreate hit a
        # 300s cap and the fixed shot never ran. 900s stays inside the 1500s
        # shared budget when the vulnerable shot was short.
        up = run([*base, "up", "-d", "--remove-orphans"], timeout=900)
        if up.returncode != 0:
            detail = _tail((up.stderr or "") + (up.stdout or ""))
            _write_reward(log_dir, 0.0, "error", f"compose up failed: {detail}")
            return 0.0, "error"
        client = _wait_client(run, project)
        if not client:
            _write_reward(log_dir, 0.0, "error", "compose up did not start client")
            return 0.0, "error"
        network = _client_network(run, client, project)
        shim = _write_shim(log_dir)
        image = agent_image(task_dir / "task.toml")
        port = app_port(task_dir)
        run_args = [
            "docker", "run", "-d",
            "--memory=20g", "--memory-swap=20g", "--cpus=4",
            "--name", judge,
            "--network", network,
            "-v", f"{task_dir / 'tests'}:/tests:ro",
            "-v", f"{Path(submission).resolve()}:/workspace/exploit.py:ro",
            "-v", f"{log_dir.resolve()}:/logs/verifier",
            # The controlled-volume layer resolves this explicit socket bind
            # to its canonical host path before applying ordinary bind rules.
            "-v", "/var/run/docker.sock:/var/run/docker.sock",
            "-v", f"{binary}:/opt/docker-bin/docker:ro",
            "-v", f"{shim}:/usr/local/bin/docker:ro",
            "-e", f"SCOPE_CONTAINER_ID={client}",
            "-e", "SCOPE_DOCKER_BIN=/opt/docker-bin/docker",
            "-e", "EXPLOIT_CLIENT_HOST=client",
            "-e", "HARBOR_VERIFIER_LOG=/logs/verifier",
            "-e", "HARBOR_PRIVATE=/tests/private",
            "-e", "HARBOR_SUBMISSION=/workspace/exploit.py",
            *judge_vendor_mount(task_dir),
            "--entrypoint", "sleep",
            image,
            "infinity",
        ]
        if port:
            entry = run_args.index("--entrypoint")
            run_args[entry:entry] = ["-e", f"EXPLOIT_APP_PORT={port}"]
        launched = run(run_args, timeout=120)
        if launched.returncode != 0:
            detail = _tail((launched.stderr or "") + (launched.stdout or ""))
            _write_reward(log_dir, 0.0, "error", f"judge container failed: {detail}")
            return 0.0, "error"
        # test.sh writes reward.txt onto the mounted log dir. A missing file is an error.
        # The vulnerable shot and the patched shot are different containers: e2's
        # exploit_fixed also starts from a fresh ready image. Scoring the patched
        # shot on the container the first shot already wrote into marks leftover
        # files as other_bug.
        (log_dir / "reward.txt").unlink(missing_ok=True)
        (log_dir / "phase-vuln.ok").unlink(missing_ok=True)
        deadline = time.monotonic() + 1500

        def remaining() -> int:
            return max(30, int(deadline - time.monotonic()))

        def exec_phase(phase: str, container_id: str) -> subprocess.CompletedProcess:
            return run(
                [
                    "docker", "exec",
                    "-e", f"SCOPE_CONTAINER_ID={container_id}",
                    "-e", f"PASS2FAIL_PHASE={phase}",
                    judge, "bash", "/tests/test.sh",
                ],
                timeout=remaining(),
            )

        executed = exec_phase("vuln", client)
        continue_fixed = (
            (log_dir / "phase-vuln.ok").is_file() and _read_reward(log_dir) is None
        )
        if continue_fixed:
            (log_dir / "phase-vuln.ok").unlink(missing_ok=True)
            stopped = run([*base, "stop"], timeout=180)
            if stopped.returncode != 0:
                detail = _tail((stopped.stderr or "") + (stopped.stdout or ""))
                _write_reward(log_dir, 0.0, "error", f"stop before bind restore failed: {detail}")
                return 0.0, "error"
            extract_pristine_binds(task_dir)
            recreated = run(
                [*base, "up", "-d", "--force-recreate", "--remove-orphans"],
                timeout=900,
            )
            if recreated.returncode != 0:
                detail = _tail((recreated.stderr or "") + (recreated.stdout or ""))
                _write_reward(log_dir, 0.0, "error", f"recreate client failed: {detail}")
                return 0.0, "error"
            client = _wait_client(run, project)
            if not client:
                _write_reward(log_dir, 0.0, "error", "recreate did not start client")
                return 0.0, "error"
            executed = exec_phase("fixed", client)
        exec_out = _tail((executed.stdout or "") + (executed.stderr or ""), 800)
        scored = _read_reward(log_dir)
        if scored is None:
            _write_reward(log_dir, 0.0, "error", f"test.sh wrote no reward: {exec_out}")
            _log(f"reward=0.0 status=error {exec_out}")
            return 0.0, "error"
        if scored[0] != 1.0:
            parts: list[str] = []
            for name in ("test-output.txt", "boot.txt", "restart.txt", "solution.txt"):
                path = log_dir / name
                if not path.is_file():
                    continue
                text = path.read_text(encoding="utf-8", errors="replace").strip()
                if text:
                    parts.append(f"{name}: {_tail(text, 400)}")
            _log(f"reward={scored[0]} status={scored[1]} {' | '.join(parts) or exec_out}")
        else:
            _log(f"reward={scored[0]} status={scored[1]}")
        return scored
    except subprocess.TimeoutExpired as exc:
        _write_reward(log_dir, 0.0, "error", f"verification command timed out: {exc.cmd}")
        return 0.0, "error"
    except Exception as exc:
        _write_reward(log_dir, 0.0, "error", str(exc))
        return 0.0, "error"
    finally:
        try:
            run(["docker", "rm", "-f", judge], timeout=60)
        except Exception:
            _log("judge container cleanup failed")
        try:
            cleaned = run([*base, "down", "--volumes", "--remove-orphans"], timeout=180)
            if cleaned.returncode != 0:
                _log(f"compose down failed: {_tail((cleaned.stderr or '') + (cleaned.stdout or ''))}")
        except Exception:
            _log("compose down failed")
        try:
            extract_pristine_binds(task_dir)
        except Exception as exc:
            _log(f"restore package binds failed: {exc}")


def _wait_client(run, project: str) -> str:
    args = [
        "docker", "ps", "-q",
        "--filter", f"label=com.docker.compose.project={project}",
        "--filter", "label=com.docker.compose.service=client",
    ]
    for _ in range(15):
        listed = run(args, timeout=30)
        lines = [line.strip() for line in (listed.stdout or "").splitlines() if line.strip()]
        if listed.returncode == 0 and lines:
            return lines[0]
        time.sleep(1)
    return ""


def _client_network(run, client: str, project: str) -> str:
    inspected = run(
        [
            "docker", "inspect", "-f",
            "{{range $k, $v := .NetworkSettings.Networks}}{{$k}} {{end}}",
            client,
        ],
        timeout=30,
    )
    names = [part for part in (inspected.stdout or "").split() if part]
    return pick_network(names, project)


def _write_shim(log_dir: Path) -> Path:
    path = log_dir / "scope-docker"
    path.write_text(SHIM, encoding="utf-8")
    path.chmod(0o755)
    return path


if __name__ == "__main__":
    if len(sys.argv) != 6 or sys.argv[1] != "--bind-operation" or os.geteuid() != 0:
        raise SystemExit("This entry point is only for sudo bind operations")
    _bind_operation(sys.argv[2], Path(sys.argv[3]), json.loads(sys.argv[5]), Path(sys.argv[4]))
    raise SystemExit(0)


try:
    from harbor.models.verifier.result import VerifierResult
    from harbor.verifier.base import BaseVerifier
except ImportError:  # unit tests import fresh_verify without Harbor installed
    BaseVerifier = None  # type: ignore[misc, assignment]
    VerifierResult = None  # type: ignore[misc, assignment]


if BaseVerifier is not None:

    class Pass2FailVerifier(BaseVerifier):
        """separate 模式的判分类。Harbor 已经 compose down 之后才被调用。"""

        async def verify(self) -> VerifierResult:
            import asyncio

            artifacts = Path(self.trial_paths.artifacts_dir)
            log_dir = Path(self.trial_paths.verifier_dir)
            task_dir = Path(self.task.paths.task_dir)
            seed = str(getattr(self.trial_paths, "trial_dir", task_dir))
            reward, _status = await asyncio.to_thread(
                fresh_verify,
                task_dir=task_dir,
                submission=collected_submission(artifacts),
                log_dir=log_dir,
                project=project_name(seed),
            )
            return VerifierResult(rewards={"reward": reward})
