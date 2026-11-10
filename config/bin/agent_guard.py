#!/usr/bin/env python3
"""PreToolUse guard for factory agents.

Blocks access to:
  * Claude Code auto-memory (``/memory/``, ``.claude/projects``, ``MEMORY.md``)
  * prior runs / other tasks under ``results/`` (only the current task dir is allowed)
  * writes outside the current workspace (``/tmp`` scratch is allowed)

The hook is registered through ``--settings`` (see ``pipeline/agent.py``).  It
receives the PreToolUse JSON on stdin and exits 2 with a message to block the
tool.  Exit 0 allows the call.

This is a behavioural guard, not a security boundary.  The real boundary is a
separate Unix user / mount namespace; see the audit report.
"""
from __future__ import annotations

import json
import os
import re
import sys
from datetime import datetime, timezone
from pathlib import Path

ROOT = Path(os.environ.get("AGENT_GUARD_ROOT", "/nvme/wuyida/新管线开发")).resolve()
RESULTS = ROOT / "results"
INSTALLED_VERIFIER = ROOT / "pipeline/pass2fail_verifier.py"
DOCKER_WRAPPER = ROOT / "config/bin/docker"

WS = Path(os.environ.get("AGENT_GUARD_WORKSPACE", "")).resolve()
TASK_DIR = WS.parent if WS.name == "workspace" else WS
LOG = os.environ.get("AGENT_GUARD_LOG", "")

MEM_RE = re.compile(
    r"(?:^|[/\\\s\"'=:(])\.claude(?:[/\\]|$)"
    r"|\.claude\.json"
    r"|/memory/"
    r"|MEMORY\.md"
    r"|\.claude/projects"
    r"|CLAUDE_CONFIG_DIR"
    r"|/home/[^/\s\"'`]+/\.claude(?:\.json)?(?:/|$)"
)
RESULTS_RE = re.compile(
    r"(?:^|[\s\"'=:(/.])("
    + re.escape(str(ROOT)) + r"/results(?:/[^\s\"'`;|&)]*)?"
    r"|results(?:/[^\s\"'`;|&)]*)?"
    r")(?=$|[\s\"'`;|&)])"
)
SECRET_RE = re.compile(
    r"(?:^|[\s\"'=:(])(?:" + re.escape(str(ROOT)) + r"/env"
    r"|/nvme/wuyida/env|/home/[^/\s\"'`]+/\.config/pt-proxy"
    r"|/home/[^/\s\"'`]+/\.ssh(?:/|$)|/home/[^/\s\"'`]+/\.netrc"
    r"|/home/[^/\s\"'`]+/\.aws(?:/|$)|/home/[^/\s\"'`]+/\.config/gcloud"
    r"|ANTHROPIC_(?:AUTH_TOKEN|API_KEY))"
)
DOCKER_SRC_RE = re.compile(
    r"(?:-v|--volume)\s+([^\s:]+):|--mount\s+[^;]*?source=([^,\s]+)"
)
BROAD_SCAN_RE = re.compile(r"\b(?:find|ls|grep|rg|ag|tree)\b")
REDACT_RE = re.compile(
    r"(ANTHROPIC_[A-Z_]+=\S+|sk-[A-Za-z0-9_-]{8,}|ghp_[A-Za-z0-9_]{8,})"
)


def _log(decision: str, tool: str, reason: str, detail: str) -> None:
    if not LOG:
        return
    detail = REDACT_RE.sub("<redacted>", detail)[:500]
    try:
        with open(LOG, "a", encoding="utf-8") as handle:
            handle.write(json.dumps({
                "ts": datetime.now(timezone.utc).isoformat(),
                "tool": tool, "decision": decision,
                "reason": reason, "detail": detail,
            }, ensure_ascii=False) + "\n")
    except OSError:
        pass


def _block(tool: str, reason: str, detail: str) -> int:
    _log("block", tool, reason, detail)
    print(f"BLOCKED by agent guard: {reason}. "
          f"Work only inside the current task workspace; memory and prior runs are not allowed.",
          file=sys.stderr)
    return 2


def _allow(tool: str, reason: str = "allowed") -> int:
    _log("allow", tool, reason, "")
    return 0


def _under(path: Path, root: Path) -> bool:
    try:
        path = path.resolve()
        root = root.resolve()
        return path == root or root in path.parents
    except (OSError, RuntimeError):
        return False


def _resolve(token: str) -> Path:
    token = token.strip().strip("\"'")
    if token.startswith("/"):
        return Path(token)
    return (ROOT / token).resolve()


def _is_memory(text: str) -> bool:
    return bool(MEM_RE.search(text)) or "/.agent-config" in text or "/.agent-home" in text or "/.agent-guard" in text


def _is_secret(text: str) -> bool:
    return bool(SECRET_RE.search(text))


def _check_results_token(tool: str, token: str) -> int | None:
    """Return 2 for a forbidden results path, 0 for allowed, None if not a path."""
    raw = token.strip().strip("\"'")
    if not raw:
        return None
    if "$" in raw or "*" in raw or "?" in raw:
        return _block(tool, "wildcard/variable results path", raw)
    path = _resolve(raw)
    if _under(path, TASK_DIR):
        return 0
    return _block(tool, "results path outside the current task", raw)


def _check_bash(command: str) -> int:
    if _is_memory(command):
        return _block("Bash", "memory path", command)
    if _is_secret(command):
        return _block("Bash", "credential path", command)
    for match in RESULTS_RE.finditer(command):
        token = match.group(1).rstrip(".,;")
        if token in {"results/", "results"}:
            return _block("Bash", "whole results tree", token)
        decision = _check_results_token("Bash", token)
        if decision == 2:
            return 2
    # Docker bind mounts must not expose memory or another task's results.
    for match in DOCKER_SRC_RE.finditer(command):
        src = (match.group(1) or match.group(2) or "").strip().strip("\"'")
        if not src or src in {"$PWD", "${PWD}", "$WS", "${WS}",
                              "$TASK_TMP", "${TASK_TMP}", "."}:
            continue
        if _is_memory(src):
            return _block("Bash", "docker mount of memory path", src)
        if "/results/" in src:
            path = Path(src).resolve() if src.startswith("/") else _resolve(src)
            if not _under(path, TASK_DIR):
                return _block("Bash", "docker mount of another task's results", src)
    # Broad scans of the project root itself can enumerate prior runs.  A scan
    # of a specific subdirectory (e.g. pipeline/) is allowed.
    if BROAD_SCAN_RE.search(command) and re.search(
            re.escape(str(ROOT)) + r"/?(?:\s|$|[\"'])", command):
        if str(TASK_DIR) not in command and str(WS) not in command:
            return _block("Bash", "broad scan of the project root", command)
    return _allow("Bash")


def _check_file(tool: str, path_text: str, write: bool) -> int:
    if not path_text:
        return _allow(tool, "no path")
    if _is_memory(path_text):
        return _block(tool, "memory path", path_text)
    if _is_secret(path_text):
        return _block(tool, "credential path", path_text)
    path = Path(path_text)
    if not path.is_absolute():
        path = (WS / path).resolve()
    else:
        path = path.resolve()
    if _under(path, WS):
        return _allow(tool, "workspace")
    if _under(path, TASK_DIR):
        # Read-only stage outputs (route/, synthesis/, review/) are needed by
        # the review stage; writes outside workspace are not.
        if write:
            return _block(tool, "write outside workspace", path_text)
        return _allow(tool, "current task stage output")
    if _under(path, RESULTS):
        return _block(tool, "results path outside the current task", path_text)
    if path == INSTALLED_VERIFIER or path == DOCKER_WRAPPER:
        return _allow(tool, "read-only pipeline tool")
    if str(path).startswith("/tmp/") or str(path).startswith("/nvme/wuyida/tmp/claude-"):
        return _allow(tool, "scratch")
    if write:
        return _block(tool, "write outside workspace", path_text)
    return _allow(tool, "read-only system path")


def main() -> int:
    raw = sys.stdin.read()
    try:
        payload = json.loads(raw)
    except json.JSONDecodeError:
        # Do not break the agent on an unexpected hook payload.
        return _allow("unknown", "unparsable payload")
    tool = str(payload.get("tool_name") or "")
    tool_input = payload.get("tool_input") or {}
    if not isinstance(tool_input, dict):
        tool_input = {}
    if tool == "Bash":
        return _check_bash(str(tool_input.get("command") or ""))
    if tool in {"Read", "Edit", "Write", "NotebookEdit"}:
        path_text = str(tool_input.get("file_path")
                        or tool_input.get("path")
                        or tool_input.get("notebook_path") or "")
        return _check_file(tool, path_text, write=tool != "Read")
    return _allow(tool, "unhandled tool")


if __name__ == "__main__":
    sys.exit(main())