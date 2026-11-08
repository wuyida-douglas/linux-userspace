"""Minimal Anthropic-compatible tool loop, with durable reasoning/tool traces.

Used when the ordinary Claude Code executable is unavailable. This is not a
mock: the model receives real command/file results and controls the next step.
"""
from __future__ import annotations

import json
import os
import re
import selectors
import signal
import subprocess
import shlex
import shutil
import time
from pathlib import Path
from typing import Any

import anthropic

from .common import timestamp, write_json

def docker_argv(argv: list[str]) -> list[str]:
    """Refresh docker group without escaping the caller's process session."""
    executable = Path(__file__).resolve().parents[1] / "config/bin/docker"
    return [str(executable), *(argv[1:] if argv and argv[0] == "docker" else argv)]


def stop_process_tree(process: subprocess.Popen) -> None:
    """Stop both ordinary children and descendants detached by legacy sg."""
    root = process.pid
    for sig in (signal.SIGTERM, signal.SIGKILL):
        descendants = []
        for path in Path("/proc").glob("[0-9]*/stat"):
            try:
                pid = int(path.parent.name)
                fields = path.read_text().split()
                if fields[3] == str(root) or fields[4] == str(root):
                    descendants.append(pid)
            except (OSError, ValueError, IndexError):
                continue
        try:
            os.killpg(root, sig)
        except ProcessLookupError:
            pass
        for pid in sorted(set(descendants), reverse=True):
            try:
                os.killpg(pid, sig)
            except (ProcessLookupError, PermissionError):
                try:
                    os.kill(pid, sig)
                except ProcessLookupError:
                    pass
        if sig == signal.SIGTERM:
            try:
                process.wait(timeout=5)
                return
            except subprocess.TimeoutExpired:
                pass


DECISION_TOOLS = [
    {"name": "submit_route", "description": "Write the complete validated routing decision to workspace route.json.",
      "input_schema": {"type": "object", "additionalProperties": False,
                      "properties": {key: {"type": "string"} for key in
                                     ("instance_id", "reason", "entry", "oracle", "normal_input", "fixed_revision")} |
                                     {"branch": {"type": ["string", "null"]},
                                      "host_type": {"type": ["string", "null"]},
                                      "accepted": {"type": "boolean"},
                                      "recovery_required": {"type": "boolean",
                                                            "description": "True when synthesis must recover or correct source/patch provenance."}},
                      "required": ["instance_id", "accepted", "branch", "host_type", "reason", "recovery_required"]}},
    {"name": "submit_review", "description": "Write the complete independent review verdict to workspace review.json.",
     "input_schema": {"type": "object", "additionalProperties": False,
                      "properties": {"passed": {"type": "boolean"},
                                     "findings": {"type": "array", "items": {"type": "object", "properties": {
                                         "severity": {"type": "string", "enum": ["blocker", "major", "minor"]},
                                         "evidence": {"type": "string"}}, "required": ["severity", "evidence"]}},
                                     "reason": {"type": "string"}, "execution_checked": {"type": "boolean"}},
                      "required": ["passed", "findings", "reason", "execution_checked"]}},
    {"name": "request_reroute", "description": "Stop this branch when experiments establish a genuine FILE-POV route instead.",
     "input_schema": {"type": "object", "additionalProperties": False,
                      "properties": {"branch": {"type": "string", "enum": ["FILE-POV"]},
                                     "reason": {"type": "string"}, "entry": {"type": "string"},
                                     "oracle": {"type": "string"}, "normal_input": {"type": "string"},
                                     "fixed_revision": {"type": "string"}, "evidence": {"type": "string"}},
                      "required": ["branch", "reason", "entry", "oracle", "normal_input", "fixed_revision", "evidence"]}},
]


def validate_decision(name: str, value: Any, workspace: Path) -> None:
    if name == "submit_route":
        # The Anthropic gateway cannot express null branch/host for rejected
        # routes with some providers. Normalize only its explicit null marker;
        # all other type errors remain real schema failures.
        for key in ("branch", "host_type"):
            if value.get(key) == "null":
                value[key] = None
        instance = json.loads((workspace / "input/meta.json").read_text(encoding="utf-8"))["instance_id"]
        if value.get("instance_id") != instance or not isinstance(value.get("accepted"), bool):
            raise ValueError("instance_id must exactly match input and accepted must be boolean")
        if value["accepted"]:
            if value.get("branch") not in {"SVC-EXPLOIT", "FILE-EXPLOIT", "FILE-POV"}:
                raise ValueError("accepted route needs a valid branch")
            host_types = {"native_service", "real_host", "synthetic_host"}
            if value["branch"] == "SVC-EXPLOIT" and value.get("host_type") not in host_types:
                raise ValueError("SVC route needs a real host_type")
            if value["branch"] != "SVC-EXPLOIT" and value.get("host_type") is not None:
                raise ValueError("FILE routes must use null host_type")
            if not isinstance(value.get("recovery_required"), bool):
                raise ValueError("recovery_required must be explicitly true or false")
            for key in ("entry", "oracle", "normal_input", "fixed_revision"):
                if not isinstance(value.get(key), str) or not value[key].strip():
                    raise ValueError(f"accepted route needs {key}")
            revision = value["fixed_revision"].lower()
            if revision == "unresolved":
                if not value["recovery_required"]:
                    raise ValueError("unresolved fixed_revision requires recovery")
            elif not re.fullmatch(r"[0-9a-f]{40}", revision):
                raise ValueError("fixed_revision must be 40 hex or UNRESOLVED during recovery")
        elif value.get("branch") is not None or value.get("host_type") is not None:
            raise ValueError("rejected route must have null branch and host_type")
        if not str(value.get("reason", "")).strip():
            raise ValueError("route reason cannot be empty")
    elif name == "request_reroute":
        original = json.loads((workspace / "route.json").read_text(encoding="utf-8"))
        if original.get("branch") not in {"SVC-EXPLOIT", "FILE-EXPLOIT"}:
            raise ValueError("only SVC/FILE-EXPLOIT may be narrowed to FILE-POV")
        if value.get("branch") != "FILE-POV":
            raise ValueError("reroute must preserve quality by narrowing to FILE-POV")
        for key in ("reason", "entry", "oracle", "normal_input", "fixed_revision", "evidence"):
            if not isinstance(value.get(key), str) or not value[key].strip():
                raise ValueError(f"reroute needs concrete {key}")
        revision = value["fixed_revision"].lower()
        if revision != "unresolved" and not re.fullmatch(r"[0-9a-f]{40}", revision):
            raise ValueError("fixed_revision must be 40 hex or UNRESOLVED")
    elif name == "submit_review":
        if not isinstance(value.get("passed"), bool) or not isinstance(value.get("execution_checked"), bool):
            raise ValueError("review passed and execution_checked must be boolean")
        if not str(value.get("reason", "")).strip() or not isinstance(value.get("findings"), list):
            raise ValueError("review needs findings and a concrete reason")
        if any(finding.get("severity") in {"blocker", "major"} for finding in value["findings"]
               if isinstance(finding, dict)) and value["passed"]:
            raise ValueError("blocker or major findings cannot pass review")
    else:
        raise ValueError("unknown decision tool")


TOOLS = [
    {"name": "bash", "description": "Run a shell command in the workspace. Use for builds, tests and inspection. Avoid interactive commands.",
     "input_schema": {"type": "object", "properties": {"command": {"type": "string"},
                                                       "timeout": {"type": "integer", "default": 120,
                                                                   "description": "Timeout in seconds, not milliseconds; maximum 3600"}},
                      "required": ["command"]}},
    {"name": "read_file", "description": "Read a UTF-8 text file in the workspace, with optional line bounds.",
     "input_schema": {"type": "object", "properties": {"path": {"type": "string"},
                                                       "offset": {"type": "integer", "default": 1},
                                                       "limit": {"type": "integer", "default": 400}},
                      "required": ["path"]}},
    {"name": "write_file", "description": "Create or replace a UTF-8 text file in the workspace.",
     "input_schema": {"type": "object", "properties": {"path": {"type": "string"}, "content": {"type": "string"}},
                      "required": ["path", "content"]}},
    {"name": "edit_file", "description": "Replace one exact string in an existing workspace text file.",
     "input_schema": {"type": "object", "properties": {"path": {"type": "string"},
                                                       "old_string": {"type": "string"}, "new_string": {"type": "string"}},
                      "required": ["path", "old_string", "new_string"]}},
]


def workspace_path(workspace: Path, value: str) -> Path:
    path = (workspace / value).resolve() if not Path(value).is_absolute() else Path(value).resolve()
    if not path.is_relative_to(workspace.resolve()):
        raise ValueError("path must remain inside the task workspace")
    return path


def run_bounded(command: str, workspace: Path, timeout: int) -> subprocess.CompletedProcess:
    """A timeout must stop compilers/builds, not leave an orphaned child."""
    # Wrap in a private process group even when a tool needs `sg docker`.
    # Otherwise `sg` can spawn children outside the group we later terminate.
    # Newly copied delivery files must remain traversable/readable by the
    # unprivileged runner even when the controller has a restrictive umask.
    wrapper = "umask 022\ntrap 'exit 143' TERM; eval " + shlex.quote(command)
    env = dict(os.environ)
    config = Path(__file__).resolve().parents[1] / "config"
    # The PT proxy credential stays in the user's 0600 config file. Source it
    # inside each bounded shell so a long-lived controller needs no restart.
    # Never include the proxy URL in model prompts, tool output or image tags.
    proxy = config / "proxy-env.sh"
    if proxy.is_file():
        command = ". " + shlex.quote(str(proxy)) + "\n" + command
    docker_bin = config / "bin"
    env["PATH"] = str(docker_bin) + os.pathsep + env.get("PATH", "")
    # Compose defaults to the delivery directory basename, which is identical
    # for all tasks. Give every model-driven project a unique, auditable name.
    import hashlib
    project = "lup" + hashlib.sha256(str(workspace.resolve()).encode()).hexdigest()[:16]
    env.setdefault("COMPOSE_PROJECT_NAME", project)
    env.setdefault("PIPELINE_IPAM_ROLE", "factory")
    env.setdefault("PIPELINE_IPAM_WORK_DIR", str(workspace / ".compose-ipam"))
    if "docker" in command:
        # Explicit host paths would otherwise bypass IPAM and unique projects.
        # The wrapper refreshes only the user's existing docker group and then
        # invokes the real CLI with the same arguments.
        docker_cli = str(docker_bin / "docker")
        command = command.replace("/usr/bin/docker", docker_cli)
        command = command.replace("docker.io", docker_cli)
    # A host/container locale mismatch must not make harmless commands such as
    # `locale` fail. The agent can still select an explicit locale in Docker.
    env.setdefault("LC_ALL", "C.UTF-8")
    env.setdefault("LANG", "C.UTF-8")
    process = subprocess.Popen(["bash", "-c", wrapper], cwd=workspace, env=env,
                               stdout=subprocess.PIPE, stderr=subprocess.STDOUT,
                               start_new_session=True, bufsize=0)
    assert process.stdout is not None
    chunks = []
    total = 0
    truncated = False
    deadline = time.monotonic() + timeout
    selector = selectors.DefaultSelector()
    selector.register(process.stdout, selectors.EVENT_READ)
    try:
        while True:
            remaining = deadline - time.monotonic()
            if remaining <= 0:
                stop_process_tree(process)
                chunks.append(f"\nCommand timed out after {timeout}s; its process tree was stopped.".encode())
                process.returncode = 124
                break
            for key, _ in selector.select(min(remaining, 1.0)):
                block = os.read(key.fd, 65536)
                if not block:
                    selector.unregister(key.fd)
                    break
                total += len(block)
                if total <= 2 * 1024 * 1024:
                    chunks.append(block)
                else:
                    truncated = True
            if process.poll() is not None and not selector.get_map():
                break
    finally:
        selector.close()
        process.stdout.close()
        if process.poll() is None:
            process.wait(timeout=10)
    if truncated:
        chunks.append(b"\nTool output exceeded 2 MiB; retained the bounded prefix. Full logs belong in files.")
    output = b"".join(chunks).decode("utf-8", errors="replace")
    return subprocess.CompletedProcess(command, process.returncode, output, "")


def execute(name: str, args: dict[str, Any], workspace: Path, docker_wrap: bool = True) -> str:
    try:
        if name in {"submit_route", "submit_review", "request_reroute"}:
            value = dict(args)
            validate_decision(name, value, workspace)
            if name == "request_reroute":
                original = json.loads((workspace / "route.json").read_text(encoding="utf-8"))
                value = {"instance_id": original["instance_id"], "accepted": True,
                         "branch": "FILE-POV", "host_type": None,
                         "recovery_required": original.get("recovery_required", True)
                         or value["fixed_revision"].upper() == "UNRESOLVED", **value}
                filename = "reroute-request.json"
            else:
                filename = "route.json" if name == "submit_route" else "review.json"
            temporary = workspace / ("." + filename + ".tmp")
            temporary.write_text(json.dumps(value, ensure_ascii=False, indent=2) + "\n", encoding="utf-8")
            temporary.replace(workspace / filename)
            # Full route validation runs once in run.route(). Keeping this
            # callback independent also makes its decision tool reusable.
            return f"validated and wrote {filename}"
        if name == "bash":
            command = str(args["command"])
            if docker_wrap and shutil.which("docker") and "docker" in command:
                # The user's supplementary docker group was granted after this
                # long-lived Cursor process started; use it for each model call.
                command = "if command -v newgrp >/dev/null && ! id -nG | grep -qw docker; then exec newgrp docker <<< " + shlex.quote(command) + "; fi\n" + command
            # Model credentials must only live in the process environment, not
            # be exposed by an accidental shell dump or persisted in artifacts.
            if any(token in command for token in ("ANTHROPIC_AUTH_TOKEN", "ANTHROPIC_API_KEY")):
                return "Error: do not print or persist model credentials"
            if docker_wrap:
                scratch = workspace / ".agent-tmp"
                scratch.mkdir(exist_ok=True)
                # Do not transparently rewrite /tmp: the same text can refer
                # to either a host or container filesystem. Give the model an
                # explicit per-task host scratch directory instead.
                command = ("export TASK_TMP=" + shlex.quote(str(scratch))
                           + "; export TMPDIR=\"$TASK_TMP\"; mkdir -p \"$TASK_TMP\"\n"
                           + "export ASAN_OPTIONS=\"${ASAN_OPTIONS:-detect_leaks=0:halt_on_error=1:abort_on_error=1:symbolize=0}\"\n"
                           + command)
            cp = run_bounded(command, workspace, min(int(args.get("timeout", 120)), 3600))
            return (f"exit={cp.returncode}\n" + cp.stdout)[-60000:]
        path = workspace_path(workspace, str(args["path"]))
        if name == "read_file":
            lines = path.read_text(encoding="utf-8", errors="replace").splitlines()
            start = max(1, int(args.get("offset", 1)))
            selected = lines[start - 1:start - 1 + min(int(args.get("limit", 400)), 2000)]
            return "\n".join(f"{number}|{line}" for number, line in enumerate(selected, start))[-60000:]
        if name == "write_file":
            path.parent.mkdir(parents=True, exist_ok=True)
            path.write_text(str(args["content"]), encoding="utf-8")
            return f"wrote {path.relative_to(workspace)}"
        if name == "edit_file":
            text = path.read_text(encoding="utf-8")
            old = str(args["old_string"])
            if text.count(old) != 1:
                return f"Error: old_string occurs {text.count(old)} times, expected exactly 1"
            path.write_text(text.replace(old, str(args["new_string"])), encoding="utf-8")
            return f"edited {path.relative_to(workspace)}"
        return f"Error: unsupported tool {name}"
    except Exception as exc:
        # Preserve an exact operation and stack for reproducibility. In
        # particular, a bare 'Permission denied: PKG-INFO' is not a task verdict.
        import traceback
        detail = traceback.format_exc()[-16000:]
        missing = f"; missing argument: {exc.args[0]}" if isinstance(exc, KeyError) and exc.args else ""
        return (f"Error: {type(exc).__name__}{missing}: {exc}\n"
                f"tool={name} arguments={json.dumps(args, ensure_ascii=False, default=str)[:8000]}\n{detail}")


def _request_bytes(messages: list[dict[str, Any]], tools: list[dict[str, Any]]) -> int:
    """Measure the complete Anthropic request, not just conversation characters."""
    return len(json.dumps({"messages": messages, "tools": tools,
                           "tool_choice": {"type": "auto"}, "max_tokens": 32768},
                          ensure_ascii=False, default=str).encode("utf-8"))


def _compact_history(messages: list[dict[str, Any]]) -> list[dict[str, Any]]:
    """Keep tool_use/tool_result IDs paired while eliding bulky historical data."""
    compact = []
    for message in messages:
        value = dict(message)
        if isinstance(message.get("content"), list):
            value["content"] = []
            for original in message["content"]:
                block = dict(original)
                if block.get("type") == "tool_result" and len(str(block.get("content", ""))) > 8000:
                    block["content"] = str(block["content"])[:8000] + \
                        "\n[truncated in model context; full evidence is in trajectory.jsonl]"
                elif block.get("type") == "text" and len(str(block.get("text", ""))) > 8000:
                    block["text"] = str(block["text"])[:8000] + "\n[historical reasoning truncated]"
                elif block.get("type") == "tool_use":
                    encoded = json.dumps(block.get("input"), ensure_ascii=False, default=str)
                    if len(encoded.encode("utf-8")) > 8000:
                        # This call already executed and its result follows. Do
                        # not resend a huge historical source file or patch as
                        # a tool argument; the durable trace retains it fully.
                        block["input"] = {"historical_arguments_truncated": True}
                value["content"].append(block)
        compact.append(value)
    return compact


def model_context(messages: list[dict[str, Any]], budget: int,
                  tools: list[dict[str, Any]] | None = None) -> list[dict[str, Any]]:
    """Bound the full UTF-8 request while preserving complete tool turn pairs."""
    if len(messages) < 2:
        return messages
    tools = TOOLS + DECISION_TOOLS if tools is None else tools
    first, rest = messages[0], messages[1:]
    turns = [rest[index:index + 2] for index in range(0, len(rest), 2)]
    turns = turns[-40:]
    while turns:
        selected = [first, *(message for turn in turns for message in turn)]
        if _request_bytes(selected, tools) <= budget:
            return selected
        turns.pop(0)
    # The latest turn can be large even after older history is removed.
    selected = _compact_history([first, *(turns[-1] if turns else messages[-2:])])
    if _request_bytes(selected, tools) > budget:
        raise ValueError("single compacted model turn exceeds the request budget")
    return selected


def run(prompt: str, workspace: Path, output: Path, *, model: str,
        credentials: dict[str, str], max_turns: int, timeout: int,
        network: Path, max_tokens: int = 32768, context_chars: int = 96000,
        docker_wrap: bool = True) -> dict[str, Any]:
    del network
    workspace = workspace.resolve()
    output = output.resolve()
    output.mkdir(parents=True, exist_ok=True)
    client = anthropic.Anthropic(api_key=credentials.get("ANTHROPIC_AUTH_TOKEN") or
                                credentials.get("ANTHROPIC_API_KEY"),
                                base_url=credentials["ANTHROPIC_BASE_URL"], timeout=300.0,
                                max_retries=4)
    messages = [{"role": "user", "content": prompt}]
    started = time.monotonic()
    record = {"status": "running", "model": model, "started_at": timestamp(), "executor": "native-anthropic-tools"}
    write_json(output / "result.json", record)
    usage = {"input_tokens": 0, "output_tokens": 0}
    resumed_trace = output / "trajectory.jsonl"
    if resumed_trace.exists() and resumed_trace.stat().st_size > 0:
        # --continue-synthesis deliberately reuses the output directory. Never
        # truncate the previous model's durable evidence in that case.
        for index in range(2, 1000):
            candidate = output / f"trajectory-{index:02d}.jsonl"
            if not candidate.exists():
                os.link(resumed_trace, candidate)
                resumed_trace = candidate
                break
    with resumed_trace.open("a", encoding="utf-8") as trace:
        for turn in range(1, max_turns + 1):
            if time.monotonic() - started >= timeout:
                record["status"] = "timeout"
                break
            # Preserve complete tool outputs on disk. Bound only model context;
            # the gateway rejects large accumulated conversations with HTTP 400.
            request_messages = model_context(messages, context_chars)
            trace.write(json.dumps({"type": "model_request", "turn": turn,
                                    "compacted": len(request_messages) != len(messages),
                                    "original_messages": len(messages),
                                    "sent_messages": len(request_messages),
                                    "request_bytes": _request_bytes(request_messages, TOOLS + DECISION_TOOLS),
                                    "budget_bytes": context_chars,
                                    "observed_at": timestamp()}, ensure_ascii=False) + "\n")
            trace.flush()
            try:
                response = client.messages.create(model=model, max_tokens=max_tokens,
                                                  messages=request_messages,
                                                  tools=TOOLS + DECISION_TOOLS,
                                                  tool_choice={"type": "auto"})
            except (anthropic.APIError, OSError) as exc:
                record.update(status="api_error", error=f"{type(exc).__name__}: {exc}")
                break
            event = {"type": "assistant", "turn": turn, "observed_at": timestamp(),
                     "message": response.model_dump(exclude_none=True)}
            trace.write(json.dumps(event, ensure_ascii=False, default=str) + "\n")
            trace.flush()
            usage["input_tokens"] += response.usage.input_tokens
            usage["output_tokens"] += response.usage.output_tokens
            messages.append({"role": "assistant", "content": response.model_dump(exclude_none=True)["content"]})
            if response.stop_reason != "tool_use":
                record.update(status="completed", final_text="".join(x.text for x in response.content if x.type == "text"))
                break
            results = []
            for block in response.content:
                if block.type != "tool_use":
                    continue
                result = execute(block.name, block.input, workspace, docker_wrap=docker_wrap)
                (output / "tool-logs").mkdir(parents=True, exist_ok=True)
                log_path = output / "tool-logs" / f"turn-{turn:04d}-{block.id}.log"
                log_path.write_text(result, encoding="utf-8")
                results.append({"type": "tool_result", "tool_use_id": block.id, "content": result})
                trace.write(json.dumps({"type": "tool_result", "turn": turn, "name": block.name,
                                        "tool_use_id": block.id, "content": result,
                                        "log_file": str(log_path),
                                        "observed_at": timestamp()}, ensure_ascii=False) + "\n")
                trace.flush()
            messages.append({"role": "user", "content": results})
        else:
            record["status"] = "max_turns"
        if record["status"] == "running":
            # A defensive terminal fallback: never leave a stale running marker
            # if the protocol loop exits through an unexpected path.
            record.update(status="error", error="model protocol loop ended without a terminal status")
    record.update(num_turns=locals().get("turn", 0), usage=usage,
                  elapsed_sec=round(time.monotonic() - started, 2),
                  finished_at=timestamp())
    write_json(output / "result.json", record)
    return record
