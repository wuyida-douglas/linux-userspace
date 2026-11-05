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
    env.update({"CLAUDE_CODE_MAX_RETRIES": "15", "CLAUDE_CODE_MAX_CONTEXT_TOKENS": "131072",
                "CLAUDE_CODE_DISABLE_NONESSENTIAL_TRAFFIC": "1",
                "CLAUDE_CODE_DISABLE_UNKNOWN_MODEL_WINDOW_ENFORCEMENT": "1"})
    record = {"status": "running", "model": model, "started_at": timestamp()}
    write_json(output / "result.json", record)
    started = time.monotonic()
    with (output / "stdout.jsonl").open("w", encoding="utf-8") as stdout, \
            (output / "stderr.txt").open("w", encoding="utf-8") as stderr, \
            (output / "trajectory.jsonl").open("w", encoding="utf-8") as trajectory:
        process = subprocess.Popen(command(prompt, model, max_turns, network), cwd=workspace,
                                   env=env, stdout=stdout, stderr=stderr,
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
