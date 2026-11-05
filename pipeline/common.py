"""Small, explicit file and process helpers shared by pipeline stages."""
from __future__ import annotations

import hashlib
import json
import os
import re
import subprocess
import time
from pathlib import Path
from typing import Any

ROOT = Path(__file__).resolve().parents[1]
ID_RE = re.compile(r"^[A-Za-z0-9][A-Za-z0-9_.-]{0,127}$")


def load_env(path: Path) -> dict[str, str]:
    """Read the deployment env file without putting credentials on argv."""
    result: dict[str, str] = {}
    for line in path.read_text(encoding="utf-8").splitlines():
        line = line.strip()
        if not line or line.startswith("#") or "=" not in line:
            continue
        key, value = line.split("=", 1)
        if key.strip() in {"ANTHROPIC_AUTH_TOKEN", "ANTHROPIC_API_KEY", "ANTHROPIC_BASE_URL"}:
            result[key.strip()] = value.strip().strip("\"'")
    if not result.get("ANTHROPIC_BASE_URL"):
        raise ValueError(f"ANTHROPIC_BASE_URL missing in {path}")
    if not (result.get("ANTHROPIC_AUTH_TOKEN") or result.get("ANTHROPIC_API_KEY")):
        raise ValueError(f"model API token missing in {path}")
    return result


def write_json(path: Path, value: Any) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    temporary = path.with_name(path.name + ".tmp")
    temporary.write_text(json.dumps(value, ensure_ascii=False, indent=2) + "\n", encoding="utf-8")
    os.replace(temporary, path)


def write_jsonl(path: Path, rows: list[dict[str, Any]]) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    temporary = path.with_name(path.name + ".tmp")
    with temporary.open("w", encoding="utf-8") as handle:
        for row in rows:
            handle.write(json.dumps(row, ensure_ascii=False, separators=(",", ":")) + "\n")
    os.replace(temporary, path)


def read_jsonl(path: Path):
    with path.open(encoding="utf-8") as handle:
        for number, line in enumerate(handle, 1):
            if line.strip():
                value = json.loads(line)
                if not isinstance(value, dict):
                    raise ValueError(f"{path}:{number}: expected a JSON object")
                yield value


def sha256(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as handle:
        for chunk in iter(lambda: handle.read(4 * 1024 * 1024), b""):
            digest.update(chunk)
    return digest.hexdigest()


def repository_key(value: str | None) -> str:
    """Compare repository identity without host case, .git or URL scheme noise."""
    value = (value or "").strip().lower().rstrip("/")
    value = re.sub(r"^[a-z][a-z0-9+.-]*://", "", value)
    value = value.removesuffix(".git")
    if value == "github.com/microsoft/chakracore":
        return "github.com/chakra-core/chakracore"
    return value


def task_id(row: dict[str, Any], index: int | None = None) -> str:
    slug = re.sub(r"[^a-z0-9]+", "-", str(row["instance_id"]).lower()).strip("-")
    suffix = f"{index:03d}-" if index is not None else ""
    return f"linux-{suffix}{slug[:100]}"


def inventory(root: Path, exclude: set[str] | None = None) -> dict[str, Any]:
    exclude = exclude or set()
    files = {}
    for path in sorted(root.rglob("*")):
        rel = path.relative_to(root).as_posix()
        if rel in exclude:
            continue
        if path.is_symlink():
            files[rel] = {"symlink": os.readlink(path)}
            continue
        if path.is_file():
            files[rel] = {"bytes": path.stat().st_size, "sha256": sha256(path)}
    return {"file_count": len(files), "total_bytes": sum(x.get("bytes", 0) for x in files.values()), "files": files}


def timestamp() -> str:
    return time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime())


def run_logged(command: list[str], log: Path, *, cwd: Path | None = None,
               env: dict[str, str] | None = None, timeout: int = 3600) -> subprocess.CompletedProcess:
    log.parent.mkdir(parents=True, exist_ok=True)
    with log.open("w", encoding="utf-8") as handle:
        try:
            completed = subprocess.run(command, cwd=cwd, env=env, stdout=handle,
                                       stderr=subprocess.STDOUT, timeout=timeout, check=False)
        except subprocess.TimeoutExpired as exc:
            handle.write(f"\nTimed out after {exc.timeout}s\n")
            return subprocess.CompletedProcess(command, 124, "", "timeout")
    return completed
