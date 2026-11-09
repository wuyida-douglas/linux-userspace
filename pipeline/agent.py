"""Run ordinary Claude Code sessions and retain the full streaming trajectory."""
from __future__ import annotations

import json
import os
import shutil
import subprocess
import time
from pathlib import Path
from typing import Any

from .common import timestamp, write_json

EMPTY_MCP = '{"mcpServers":{}}'


def workspace_environment(workspace: Path, base: dict[str, str] | None = None) -> dict[str, str]:
    """Expose the per-task workspace contract to Claude Code's built-in tools.

    Claude Code has no per-command wrapper, so the variables the synthesis
    prompts promise (TASK_TMP, Compose/IPAM identity, locale, ASan defaults)
    must live in the agent process environment instead.
    """
    import hashlib

    env = dict(os.environ if base is None else base)
    # Third-party build scripts must never reset the pipeline repository merely
    # because it is an ancestor of their cwd; keep auth/settings but drop an
    # inherited repository selection.
    for variable in ("GIT_DIR", "GIT_WORK_TREE", "GIT_INDEX_FILE", "GIT_OBJECT_DIRECTORY",
                     "GIT_ALTERNATE_OBJECT_DIRECTORIES", "GIT_COMMON_DIR", "GIT_PREFIX"):
        env.pop(variable, None)
    resolved = workspace.resolve()
    env["GIT_CEILING_DIRECTORIES"] = str(resolved.parent)
    env["PATH"] = str(Path(__file__).resolve().parents[1] / "config/bin") + os.pathsep + env.get("PATH", "")
    scratch = resolved / ".agent-tmp"
    scratch.mkdir(exist_ok=True)
    env["TASK_TMP"] = str(scratch)
    env.setdefault("ASAN_OPTIONS", "detect_leaks=0:halt_on_error=1:abort_on_error=1:symbolize=0")
    # Compose defaults to the delivery directory basename, identical for every
    # task; a unique project keeps model-driven containers auditable.
    project = "lup" + hashlib.sha256(str(resolved).encode()).hexdigest()[:16]
    env.setdefault("COMPOSE_PROJECT_NAME", project)
    env.setdefault("PIPELINE_IPAM_ROLE", "factory")
    env.setdefault("PIPELINE_IPAM_WORK_DIR", str(resolved / ".compose-ipam"))
    env.setdefault("LC_ALL", "C.UTF-8")
    env.setdefault("LANG", "C.UTF-8")
    return env


def command(prompt: str, model: str, max_turns: int, network: Path) -> list[str]:
    return ["claude", "-p", prompt, "--output-format", "stream-json", "--verbose",
            "--permission-mode", "bypassPermissions", "--setting-sources", "",
            "--strict-mcp-config", "--mcp-config", EMPTY_MCP,
            "--permission-prompts", "none", "--max-turns", str(max_turns),
            "--model", model, "--debug-file", "cli-debug.log",
            "--plugin-dir", str(network)]


def run(prompt: str, workspace: Path, output: Path, *, model: str,
        credentials: dict[str, str], max_turns: int, timeout: int,
        network: Path) -> dict[str, Any]:
    executable = os.environ.get("CLAUDE_BIN") or shutil.which("claude")
    if not executable or not Path(executable).is_file():
        raise RuntimeError("Claude Code is not installed; install version 2.1.228 or set CLAUDE_BIN")
    output.mkdir(parents=True, exist_ok=True)
    env = dict(os.environ)
    env.update(credentials)
    # Load PT egress credentials into the process environment without exposing
    # them in CLI arguments or task prompts. Missing credentials leave existing
    # direct/mirror networking intact; preflight reports the resulting failure.
    credential = Path.home() / ".config/pt-proxy/proxy-url"
    if credential.is_file():
        proxy_url = credential.read_text(encoding="utf-8").strip()
        if proxy_url and not os.environ.get("PT_PROXY_DISABLED"):
            for key in ("HTTP_PROXY", "HTTPS_PROXY", "http_proxy", "https_proxy"):
                env[key] = proxy_url
            no_proxy = ("localhost,127.0.0.1,::1,.pjlab.org.cn,.sensetime.com,"
                        "10.0.0.0/8,100.0.0.0/8,172.16.0.0/12,192.168.0.0/16,"
                        "10.140.84.42,10.12.111.133")
            env["NO_PROXY"] = no_proxy
            env["no_proxy"] = no_proxy
    env = workspace_environment(workspace, env)
    env.update({"CLAUDE_CODE_MAX_RETRIES": "15", "CLAUDE_CODE_MAX_CONTEXT_TOKENS": "131072",
                "CLAUDE_CODE_DISABLE_NONESSENTIAL_TRAFFIC": "1",
                "CLAUDE_CODE_DISABLE_UNKNOWN_MODEL_WINDOW_ENFORCEMENT": "1"})
    record = {"status": "running", "model": model, "started_at": timestamp()}
    write_json(output / "result.json", record)
    started = time.monotonic()
    with (output / "stdout.jsonl").open("w", encoding="utf-8") as stdout, \
            (output / "stderr.txt").open("w", encoding="utf-8") as stderr, \
            (output / "trajectory.jsonl").open("w", encoding="utf-8") as trajectory:
        argv = command(prompt, model, max_turns, network)
        argv[0] = executable
        process = subprocess.Popen(argv, cwd=workspace, env=env,
                                   stdout=stdout, stderr=stderr,
                                   start_new_session=True)
        timed_out = False
        try:
            process.wait(timeout=timeout)
        except subprocess.TimeoutExpired:
            timed_out = True
            os.killpg(process.pid, 15)
            try:
                process.wait(timeout=30)
            except subprocess.TimeoutExpired:
                os.killpg(process.pid, 9)
                process.wait(timeout=10)
    # The full stdout is already durable. Copying after process exit avoids
    # mixing concurrent streams while retaining the exact event order.
    shutil.copyfile(output / "stdout.jsonl", output / "trajectory.jsonl")
    result = {}
    for line in (output / "trajectory.jsonl").read_text(encoding="utf-8", errors="replace").splitlines():
        try:
            event = json.loads(line)
        except json.JSONDecodeError:
            continue
        if isinstance(event, dict) and event.get("type") == "result":
            result = event
    record.update(status="timeout" if timed_out else
                  ("completed" if process.returncode == 0 and not result.get("is_error") else "agent_error"),
                  returncode=process.returncode, elapsed_sec=round(time.monotonic() - started, 2),
                  num_turns=result.get("num_turns"), result_excerpt=str(result.get("result", ""))[:4000],
                  usage=result.get("usage"), total_cost_usd=result.get("total_cost_usd"),
                  finished_at=timestamp())
    write_json(output / "result.json", record)
    return record
