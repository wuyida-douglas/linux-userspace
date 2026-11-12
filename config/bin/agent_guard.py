#!/usr/bin/env python3
"""PreToolUse guard for factory agents.

Blocks access to:
  * Claude Code auto-memory (``/memory/``, ``.claude/projects``, ``MEMORY.md``)
  * prior runs / other tasks under ``results/`` (only the current task dir is allowed)
  * project paths outside the current task (pipeline/, config/, scripts/, other runs)
  * host ``/home`` and ``/nvme/wuyida`` paths other than the current task and
    harness ``claude-*`` outputs
  * credentials and shared IPAM lease state
  * host-wide Docker destructive commands (``kill $(docker ps -q)``, prune, ...)
  * writes outside the current workspace (generic ``/tmp`` scratch is allowed)

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
PROJECT_RE = re.compile(
    r"(?:^|[\s\"'=:(])(" + re.escape(str(ROOT)) + r"(?:/[^\s\"'`;|&)]*)?)"
    r"(?=$|[\s\"'`;|&)])"
)
IPAM_STATE_RE = re.compile(r"/tmp/linux-userspace-ipam-[^\s\"'`;|&)]*")
DOCKER_PRUNE_RE = re.compile(
    r"\bdocker\s+(?:system|volume|network|builder|container|image)\s+prune\b"
)
DOCKER_DESTRUCTIVE_RE = re.compile(r"\bdocker\s+(?:container\s+)?(?:kill|rm|stop|restart)\b")
DOCKER_PS_SUBST_RE = re.compile(r"(?:\$\(|`)\s*docker\s+ps\b([^)`]*)")
DOCKER_NETWORK_RM_ALL_RE = re.compile(
    r"\bdocker\s+network\s+rm\b[^\n;|&]*\$\(\s*docker\s+network\s+ls\s+-q"
)
DOCKER_VOLUME_RM_ALL_RE = re.compile(
    r"\bdocker\s+volume\s+rm\b[^\n;|&]*\$\(\s*docker\s+volume\s+ls\s+-q"
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


def _check_docker_scope(command: str) -> int | None:
    """Block host-wide Docker destruction and shared IPAM state."""
    if DOCKER_PRUNE_RE.search(command):
        return _block("Bash", "global docker prune is not allowed", command)
    if DOCKER_NETWORK_RM_ALL_RE.search(command) or DOCKER_VOLUME_RM_ALL_RE.search(command):
        return _block("Bash", "global docker network/volume removal is not allowed", command)
    if DOCKER_DESTRUCTIVE_RE.search(command):
        for match in DOCKER_PS_SUBST_RE.finditer(command):
            if "--filter" not in match.group(1):
                return _block(
                    "Bash",
                    "destructive docker command over an unfiltered docker ps is not allowed",
                    command,
                )
    if IPAM_STATE_RE.search(command):
        return _block("Bash", "shared IPAM lease state is outside the workspace", command)
    return None


def _check_project_paths(command: str) -> int | None:
    """Block project paths outside the current task directory."""
    if str(ROOT) not in command:
        return None
    for match in PROJECT_RE.finditer(command):
        token = match.group(1).rstrip(".,;")
        if token in {str(ROOT), str(ROOT) + "/"}:
            return _block("Bash", "project root is outside the current task", token)
        if _under(Path(token), TASK_DIR):
            continue
        return _block("Bash", "project path outside the current task", token)
    return None


def _check_outer_paths(command: str) -> int | None:
    """Block /home and /nvme/wuyida paths except the current task and harness output."""
    for match in re.finditer(r"(?:^|[\s\"'=:(])(/home/[^\s\"'`;|&)]*)", command):
        token = match.group(1).rstrip(".,;")
        if _is_memory(token):
            return _block("Bash", "memory path", token)
        return _block("Bash", "home path outside the workspace", token)
    for match in re.finditer(r"(?:^|[\s\"'=:(])(/nvme/wuyida/[^\s\"'`;|&)]*)", command):
        token = match.group(1).rstrip(".,;")
        if token.startswith("/nvme/wuyida/tmp/claude-"):
            continue
        if _under(Path(token), TASK_DIR):
            continue
        if _is_secret(token):
            return _block("Bash", "credential path", token)
        return _block("Bash", "host path outside the current task", token)
    return None


def _check_bash(command: str) -> int:
    if _is_memory(command):
        return _block("Bash", "memory path", command)
    if _is_secret(command):
        return _block("Bash", "credential path", command)
    for check in (_check_docker_scope, _check_project_paths, _check_outer_paths):
        decision = check(command)
        if decision is not None:
            return decision
    for match in RESULTS_RE.finditer(command):
        token = match.group(1).rstrip(".,;")
        if token in {"results/", "results"}:
            return _block("Bash", "whole results tree", token)
        decision = _check_results_token("Bash", token)
        if decision == 2:
            return 2
    # Docker bind mounts must stay inside the current task/workspace; /tmp
    # scratch is allowed, but shared IPAM state and other tasks are not.
    for match in DOCKER_SRC_RE.finditer(command):
        src = (match.group(1) or match.group(2) or "").strip().strip("\"'")
        if not src or src in {"$PWD", "${PWD}", "$WS", "${WS}",
                              "$TASK_TMP", "${TASK_TMP}", "."}:
            continue
        if _is_memory(src):
            return _block("Bash", "docker mount of memory path", src)
        path = Path(src).resolve() if src.startswith("/") else _resolve(src)
        if IPAM_STATE_RE.search(str(path)):
            return _block("Bash", "docker mount of shared IPAM state", src)
        if str(path).startswith("/home/"):
            return _block("Bash", "docker mount of home path", src)
        if _under(path, ROOT) and not _under(path, TASK_DIR):
            return _block("Bash", "docker mount of project path outside the task", src)
        if str(path).startswith("/nvme/wuyida/") and not _under(path, TASK_DIR):
            return _block("Bash", "docker mount of host path outside the task", src)
        if "/results/" in src:
            if not _under(path, TASK_DIR):
                return _block("Bash", "docker mount of another task's results", src)
    # Broad scans of the project root itself can enumerate prior runs; project
    # paths outside the current task are blocked above.
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
    if IPAM_STATE_RE.search(str(path)):
        return _block(tool, "shared IPAM lease state is outside the workspace", path_text)
    if _under(path, ROOT):
        return _block(tool, "project path outside the current task", path_text)
    if _under(path, RESULTS):
        return _block(tool, "results path outside the current task", path_text)
    if str(path).startswith("/nvme/wuyida/tmp/claude-"):
        if write:
            return _block(tool, "write outside workspace", path_text)
        return _allow(tool, "harness output")
    if str(path).startswith("/home/"):
        return _block(tool, "home path outside the workspace", path_text)
    if str(path).startswith("/nvme/wuyida/"):
        return _block(tool, "host path outside the current task", path_text)
    if str(path).startswith("/tmp/"):
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