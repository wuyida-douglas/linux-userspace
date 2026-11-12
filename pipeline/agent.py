"""Run ordinary Claude Code sessions and retain the full streaming trajectory."""
from __future__ import annotations

import json
import os
import re
import shutil
import signal
import subprocess
import tempfile
import threading
import time
from datetime import datetime, timedelta, timezone
from pathlib import Path
from typing import Any

from .common import timestamp, write_json

EMPTY_MCP = '{"mcpServers":{}}'
ROOT = Path(__file__).resolve().parents[1]
NO_PROXY = ("localhost,127.0.0.1,::1,.pjlab.org.cn,.sensetime.com,"
            "10.0.0.0/8,100.0.0.0/8,172.16.0.0/12,192.168.0.0/16,"
            "10.140.84.42,10.12.111.133")


def docker_config_environment(env: dict[str, str]) -> dict[str, str]:
    """Make ``docker build`` egress without per-command ``--build-arg`` flags.

    The Docker CLI reads proxies from ``$DOCKER_CONFIG/config.json``.  This is
    a CLI-side setting only: it never moves the daemon's data-root, images,
    containers, volumes or build cache.
    """
    if env.get("PT_PROXY_DISABLED"):
        return env
    credential = Path.home() / ".config/pt-proxy/proxy-url"
    if not credential.is_file():
        return env
    proxy_url = credential.read_text(encoding="utf-8").strip()
    if not proxy_url:
        return env

    directory = Path.home() / ".config/pt-proxy/docker"
    directory.mkdir(parents=True, exist_ok=True)
    os.chmod(directory, 0o700)
    target = directory / "config.json"
    config: dict = {}
    if target.is_file():
        try:
            loaded = json.loads(target.read_text(encoding="utf-8"))
            if isinstance(loaded, dict):
                config = loaded
        except (OSError, ValueError):
            config = {}
    config["proxies"] = {
        "default": {
            "httpProxy": proxy_url,
            "httpsProxy": proxy_url,
            "noProxy": NO_PROXY,
        }
    }
    text = json.dumps(config, ensure_ascii=False, indent=2) + "\n"
    if not target.is_file() or target.read_text(encoding="utf-8") != text:
        handle, temporary = tempfile.mkstemp(dir=directory, prefix=".config.", suffix=".json")
        try:
            with os.fdopen(handle, "w", encoding="utf-8") as stream:
                stream.write(text)
            os.chmod(temporary, 0o600)
            os.replace(temporary, target)
        finally:
            if os.path.exists(temporary):
                os.unlink(temporary)
    env["DOCKER_CONFIG"] = str(directory)
    return env


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
    return docker_config_environment(env)


def command(prompt: str, model: str, max_turns: int, network: Path,
            settings: Path | None = None, debug_file: Path | None = None) -> list[str]:
    # The CLI runs with cwd=workspace, so every path argument must be absolute.
    # A relative --settings otherwise resolves under workspace/results/... and
    # Claude Code exits with "Settings file not found".
    debug = Path(debug_file or "cli-debug.log").resolve()
    argv = ["claude", "-p", prompt, "--output-format", "stream-json", "--verbose",
            "--permission-mode", "bypassPermissions", "--setting-sources", "",
            "--strict-mcp-config", "--mcp-config", EMPTY_MCP,
            "--permission-prompts", "none", "--max-turns", str(max_turns),
            "--model", model, "--debug-file", str(debug),
            "--plugin-dir", str(Path(network).resolve())]
    if settings is not None:
        argv += ["--settings", str(Path(settings).resolve())]
    return argv



BEIJING = timezone(timedelta(hours=8))


def _beijing_time(value: Any) -> str:
    """Render a stream timestamp in Asia/Shanghai, independent of host TZ."""
    if not value:
        return ""
    try:
        parsed = datetime.fromisoformat(str(value).replace("Z", "+00:00"))
        if parsed.tzinfo is None:
            parsed = parsed.replace(tzinfo=timezone.utc)
        return parsed.astimezone(BEIJING).strftime("%Y-%m-%d %H:%M:%S.%f")[:-3] + " +0800"
    except (TypeError, ValueError):
        return str(value)


def _is_placeholder_result(event: dict) -> bool:
    """Reject the duplicate CLI shutdown result that follows a real result.

    Claude Code can append a synthetic ``result`` with ``num_turns=0``, a tiny
    duration and an empty body. It must not overwrite the substantive result
    already present in the stream (or the SFT/result metadata derived from it).
    """
    turns = event.get("num_turns")
    try:
        duration = int(event.get("duration_ms") or 0)
    except (TypeError, ValueError):
        duration = 0
    text = event.get("result")
    return turns in (0, None) and duration < 1000 and not str(text or "").strip()


def _block_text(block: dict) -> str:
    value = block.get("content")
    if isinstance(value, list):
        return "".join(
            str(item.get("text", "")) if isinstance(item, dict) else str(item)
            for item in value)
    return str(value or block.get("text") or "")


def _fence(text: str) -> tuple[str, str]:
    """Pick a Markdown fence that cannot be closed by the payload itself."""
    fence = "```"
    while fence in text:
        fence += "`"
    return fence, fence


def _append_block(markdown: list[str], block: dict, *, full: bool) -> None:
    kind = block.get("type")
    if kind == "thinking" and block.get("thinking"):
        markdown.extend(["### Thinking", "", str(block["thinking"]), ""])
    elif kind == "redacted_thinking":
        markdown.extend(["### Redacted thinking", "",
                         str(block.get("data", ""))[:2000], ""])
    elif kind == "text" and block.get("text"):
        markdown.extend(["### Text", "", str(block["text"]), ""])
    elif kind == "tool_use":
        payload = json.dumps(block.get("input"), ensure_ascii=False, default=str)
        if not full:
            payload = payload[:20000]
        fence, close = _fence(payload)
        markdown += [f"### Tool `{block.get('name')}`", fence + "json", payload, close, ""]


def _render_markdown(timeline: list[dict], *, title: str, full: bool,
                     header: list[str] | None = None) -> str:
    lines = [f"# {title}", ""]
    lines.extend(header or [])
    if header:
        lines.append("")
    for event in timeline:
        kind = event.get("kind")
        stamp = event.get("time") or ""
        if kind == "turn":
            lines.append(f"## Turn {event['turn']} — assistant — {stamp}")
            lines.append("")
            for block in event.get("blocks", []):
                _append_block(lines, block, full=full)
        elif kind == "tool_result":
            lines.append(f"### Tool result — {stamp}")
            lines.append("")
            for block in event.get("blocks", []):
                text = _block_text(block)
                if not full:
                    text = text[:6000]
                fence, close = _fence(text)
                lines += [fence + "text", text, close, ""]
        elif kind == "compact":
            lines.append(f"## Claude Code compaction — {stamp}")
            lines.append("")
            text = event.get("text") or json.dumps(event.get("event"), ensure_ascii=False,
                                                  default=str)
            fence, close = _fence(text)
            lines += [fence + "text", text[:200000] if not full else text, close, ""]
        elif kind == "system":
            subtype = event.get("subtype") or "event"
            if "compact" in subtype.lower():
                lines.append(f"## Claude Code compaction — {stamp}")
                lines.append("")
                payload = json.dumps(event.get("event"), ensure_ascii=False, default=str)
                fence, close = _fence(payload)
                lines += [fence + "json", payload, close, ""]
            else:
                lines.append(f"## System `{subtype}` — {stamp}")
                lines.append("")
                payload = json.dumps(event.get("event"), ensure_ascii=False, default=str)
                if not full:
                    payload = payload[:4000]
                fence, close = _fence(payload)
                lines += [fence + "json", payload, close, ""]
        elif kind == "result":
            lines.append(f"## Final result — {stamp}")
            lines.append("")
            raw = event.get("result") or {}
            text = str(raw.get("result", "") if isinstance(raw, dict) else raw)
            if not full:
                text = text[:10000]
            fence, close = _fence(text)
            lines += [fence + "text", text, close, ""]
    return "\n".join(lines).rstrip() + "\n"


SFT_SYSTEM = {
    "route": "你是 Linux 用户态漏洞路由助手。读取 input/meta.json、alternate-candidates.json、fix.diff 和源码，选择 SVC-EXPLOIT / FILE-EXPLOIT / FILE-POV 或拒绝，并把结论写入 route.json。",
    "synthesis": "你是 Linux 用户态漏洞题目合成助手。根据 route.json 构建可运行、可验证、可评分的 Docker 题包，并完成 gold、oracle、solution 和自检。",
    "review": "你是独立审查助手。只读检查冻结交付是否适合训练，重点判断漏洞真实性、入口可达性、差分确定性和 oracle 是否可伪造。",
}
SFT_CVE_RE = re.compile(
    r"(?:cve-\d{4}-\d+|osv-\d{4}-\d+|ghsa-[a-z0-9]{4}-[a-z0-9]{4}-[a-z0-9]{4})",
    re.I)


class LiveLogs:
    """Tail stdout.jsonl and keep tool-calls.jsonl / live.chat.md live.

    ``_write_compact_logs`` remains authoritative and rewrites both files from
    the complete raw stream when the session ends. This writer only makes the
    two human-facing files readable while the agent is still running.
    """

    def __init__(self, output: Path, task: str, stage: str) -> None:
        self.output = output
        self.stdout = output / "stdout.jsonl"
        self.tools = output / "tool-calls.jsonl"
        self.chat = output / "live.chat.md"
        self.stop_event = threading.Event()
        self.result_seen = threading.Event()
        self.thread = threading.Thread(target=self._run, name="live-logs", daemon=True)
        self.started = False
        self.turn = 0
        self.turn_by_message: dict[str, int] = {}
        self.offset = 0
        self.buffer = b""
        self.tools.write_text("", encoding="utf-8")
        self.chat.write_text(
            f"# Live chat — {stage}\n\n"
            f"- task: `{task}`\n"
            f"- stage: `{stage}`\n"
            f"- started: `{timestamp()}`\n"
            "- note: live view; rewritten from `stdout.jsonl` when the session ends\n\n",
            encoding="utf-8")

    def start(self) -> None:
        if not self.started:
            self.started = True
            self.thread.start()

    def stop(self) -> None:
        if not self.started:
            return
        self.stop_event.set()
        self.thread.join(timeout=5)
        self._drain(final=True)
        self.started = False

    def wait_for_result(self, timeout: float | None = None) -> bool:
        return self.result_seen.wait(timeout)

    def _run(self) -> None:
        while not self.stop_event.wait(0.5):
            self._drain()
        self._drain(final=True)

    def _drain(self, final: bool = False) -> None:
        try:
            with self.stdout.open("rb") as handle:
                handle.seek(self.offset)
                chunk = handle.read()
                self.offset = handle.tell()
        except OSError:
            return
        if chunk:
            self.buffer += chunk
        while b"\n" in self.buffer:
            line, self.buffer = self.buffer.split(b"\n", 1)
            self._line(line)
        if final and self.buffer.strip():
            self._line(self.buffer)
            self.buffer = b""

    def _line(self, raw: bytes) -> None:
        try:
            event = json.loads(raw.decode("utf-8", "replace"))
        except (json.JSONDecodeError, UnicodeDecodeError):
            return
        if isinstance(event, dict):
            try:
                self._event(event)
            except Exception:
                pass

    def _stamp(self, event: dict) -> str:
        return _beijing_time(event.get("timestamp")) or _beijing_time(
            datetime.now(timezone.utc).isoformat())

    def _append_chat(self, text: str) -> None:
        with self.chat.open("a", encoding="utf-8") as handle:
            handle.write(text.rstrip() + "\n\n")

    def _event(self, event: dict) -> None:
        kind = event.get("type")
        stamp = self._stamp(event)
        message = event.get("message") or {}
        content = message.get("content") if isinstance(message, dict) else None
        if kind == "assistant" and isinstance(content, list):
            message_id = str(message.get("id") or event.get("uuid") or "")
            turn = self.turn_by_message.get(message_id)
            if turn is None:
                self.turn += 1
                turn = self.turn
                self.turn_by_message[message_id] = turn
            blocks: list[dict] = []
            for block in content:
                if not isinstance(block, dict):
                    continue
                if block.get("type") not in {"thinking", "redacted_thinking", "text", "tool_use"}:
                    continue
                blocks.append(block)
                if block.get("type") == "tool_use":
                    tool_input = block.get("input") if isinstance(block.get("input"), dict) else {}
                    description = tool_input.get("description", "")
                    input_view = dict(tool_input)
                    if description:
                        input_view.pop("description", None)
                    call = {"time": stamp, "turn": turn,
                            "tool": block.get("name"),
                            "description": description,
                            "id": block.get("id"), "input": input_view}
                    with self.tools.open("a", encoding="utf-8") as handle:
                        handle.write(json.dumps(call, ensure_ascii=False, default=str) + "\n")
            if blocks:
                lines = [f"## Turn {turn} — assistant — {stamp}", ""]
                for block in blocks:
                    _append_block(lines, block, full=True)
                self._append_chat("\n".join(lines))
        elif kind == "user":
            blocks = content if isinstance(content, list) else []
            results = [block for block in blocks
                       if isinstance(block, dict) and block.get("type") == "tool_result"]
            if results:
                lines = [f"### Tool result — {stamp}", ""]
                for block in results:
                    text = _block_text(block)
                    fence, close = _fence(text)
                    lines += [fence + "text", text, close, ""]
                self._append_chat("\n".join(lines))
            elif content and (event.get("isCompactSummary") or message.get("isCompactSummary")):
                text = _block_text({"content": content})
                fence, close = _fence(text)
                self._append_chat(
                    f"## Claude Code compaction — {stamp}\n\n{fence}text\n{text}\n{close}")
        elif kind == "system":
            subtype = event.get("subtype") or ""
            if subtype == "thinking_tokens":
                return
            if subtype == "init":
                self._append_chat(
                    f"## System init — {stamp}\n\n```json\n"
                    + json.dumps(event, ensure_ascii=False, default=str) + "\n```")
            elif "compact" in subtype.lower():
                payload = json.dumps(event, ensure_ascii=False, default=str)
                self._append_chat(
                    f"## Claude Code compaction — {stamp}\n\n```json\n{payload}\n```")
        elif kind == "result":
            self.result_seen.set()
            result = event.get("result") or ""
            text = str(result.get("result", "") if isinstance(result, dict) else result)
            fence, close = _fence(text)
            self._append_chat(f"## Final result — {stamp}\n\n{fence}text\n{text}\n{close}")


def _qwen_messages(prompt: str | None, timeline: list[dict],
                   metadata: dict, result: dict) -> tuple[list[dict], list[dict]]:
    """Convert the internal timeline to the Qwen/OpenAI tool-call shape.

    The example format uses string assistant content, ``tool_calls`` on the
    assistant, and separate ``role=tool`` messages. Thinking is embedded in
    ``content`` as `` thinking...``; compaction/system events stay in
    metadata so they do not break a single-system-message chat template.
    """
    stage = metadata.get("stage", "")
    messages: list[dict] = [{
        "role": "system",
        "content": SFT_SYSTEM.get(stage, "你是 Linux 用户态漏洞合成助手。")}]
    if prompt:
        messages.append({"role": "user", "content": prompt})
    events: list[dict] = []
    for event in timeline:
        kind = event.get("kind")
        stamp = event.get("time") or ""
        if kind == "turn":
            parts: list[str] = []
            tool_calls: list[dict] = []
            for block in event.get("blocks", []):
                if block.get("type") == "thinking":
                    parts.append("<think>\n" + str(block.get("thinking", "")).rstrip() + "\n</think>")
                elif block.get("type") == "redacted_thinking":
                    parts.append("<think>\n[redacted thinking]\n</think>")
                elif block.get("type") == "text":
                    parts.append(str(block.get("text", "")))
                elif block.get("type") == "tool_use":
                    tool_calls.append({
                        "id": block.get("id"),
                        "type": "function",
                        "function": {
                            "name": block.get("name"),
                            "arguments": block.get("input") or {},
                        },
                    })
            content = "\n".join(part for part in parts if part).strip()
            if content or tool_calls:
                message = {"role": "assistant", "content": content}
                if tool_calls:
                    message["tool_calls"] = tool_calls
                messages.append(message)
        elif kind == "tool_result":
            for block in event.get("blocks", []):
                messages.append({
                    "role": "tool",
                    "tool_call_id": block.get("tool_use_id"),
                    "content": _block_text(block),
                })
        elif kind in {"compact", "system"}:
            subtype = event.get("subtype") or ("compact_boundary" if kind == "compact" else "event")
            if subtype == "init":
                continue
            events.append({
                "time": stamp,
                "kind": kind,
                "subtype": subtype,
                "content": event.get("text") or json.dumps(
                    event.get("event"), ensure_ascii=False, default=str),
            })
    final_text = str(result.get("result", "")).strip()
    if final_text and not (messages and messages[-1].get("role") == "assistant"
                           and messages[-1].get("content") == final_text):
        messages.append({"role": "assistant", "content": final_text})
    return messages, events


def _write_sft(output: Path, prompt: str | None, timeline: list[dict],
               metadata: dict, result: dict) -> None:
    """Write one Qwen-format conversation suitable for SFT tooling."""
    task = str(metadata.get("task") or output.parent.name)
    stage = str(metadata.get("stage") or output.name)
    messages, events = _qwen_messages(prompt, timeline, metadata, result)
    cve_match = SFT_CVE_RE.search(task)
    metadata = dict(metadata)
    metadata.update({
        "sample_id": f"{task}::{stage}",
        "cve": cve_match.group(0).upper() if cve_match else "",
        "stage": stage,
        "split": "train",
        "note": "Qwen-style SFT generated from Claude Code stream; "
                "compaction/system events are in metadata.events",
        "events": events,
    })
    metadata["result"] = {
        "is_error": result.get("is_error"), "subtype": result.get("subtype"),
        "num_turns": result.get("num_turns"), "duration_ms": result.get("duration_ms"),
        "usage": result.get("usage"), "result": str(result.get("result", ""))}
    payload = {"messages": messages, "metadata": metadata}
    with (output / "sft.jsonl").open("w", encoding="utf-8") as handle:
        handle.write(json.dumps(payload, ensure_ascii=False, default=str) + "\n")


def _write_compact_logs(output: Path, trajectory_name: str = "trajectory.jsonl") -> dict:
    """Write human and machine readable logs from the raw Claude stream.

    ``stdout.jsonl`` remains the complete raw stream. We also write:

    * ``trajectory.jsonl`` — small turn index for supervisors (no full text)
    * ``tool-calls.jsonl`` — one tool call per line, Beijing timestamp first
    * ``live.chat.md`` — full transcript, analogous to exploit's ``live.chat.md``
    * ``sft.jsonl`` — full message-structured trajectory for SFT
    """
    timeline: list[dict] = []
    calls: list[dict] = []
    turns: dict[str, dict] = {}
    background: list[dict] = []
    turn = 0
    result: dict = {}
    placeholder_result: dict = {}
    init: dict = {}
    result_time = ""
    for line in (output / "stdout.jsonl").read_text(encoding="utf-8", errors="replace").splitlines():
        try:
            event = json.loads(line)
        except json.JSONDecodeError:
            continue
        if not isinstance(event, dict):
            continue
        kind = event.get("type")
        stamp = _beijing_time(event.get("timestamp"))
        message = event.get("message") or {}
        content = message.get("content") if isinstance(message, dict) else None
        if kind == "assistant" and isinstance(content, list):
            message_id = str(message.get("id") or event.get("uuid") or "")
            current = turns.get(message_id)
            if current is None:
                turn += 1
                current = {"kind": "turn", "turn": turn, "time": stamp,
                           "message_id": message_id, "blocks": []}
                turns[message_id] = current
                timeline.append(current)
            for block in content:
                if not isinstance(block, dict):
                    continue
                if block.get("type") not in {"thinking", "redacted_thinking", "text", "tool_use"}:
                    continue
                block = dict(block)
                block["_time"] = stamp or current["time"]
                current["blocks"].append(block)
                if block.get("type") == "tool_use":
                    tool_input = block.get("input") if isinstance(block.get("input"), dict) else {}
                    description = tool_input.get("description", "")
                    # Bash's model-generated label is useful as a top-level
                    # column; do not repeat it inside the argument object.
                    input_view = dict(tool_input)
                    if description:
                        input_view.pop("description", None)
                    calls.append({"time": block["_time"], "turn": turn,
                                  "tool": block.get("name"),
                                  "description": description,
                                  "id": block.get("id"), "input": input_view})
            if not current["time"]:
                current["time"] = stamp
        elif kind == "user":
            blocks = content if isinstance(content, list) else []
            results = [block for block in blocks
                       if isinstance(block, dict) and block.get("type") == "tool_result"]
            if results:
                timeline.append({"kind": "tool_result", "turn": turn, "time": stamp,
                                 "blocks": results})
            elif content and (event.get("isCompactSummary") or message.get("isCompactSummary")):
                # Auto-compaction may emit the summary as a user string rather
                # than a content-block list. Keep it as an explicit event; all
                # earlier events remain in the same timeline.
                timeline.append({"kind": "compact", "turn": turn, "time": stamp,
                                 "event": event, "text": _block_text({"content": content})})
            elif content:
                timeline.append({"kind": "system", "subtype": "user_message",
                                 "time": stamp, "event": event})
        elif kind == "system":
            subtype = event.get("subtype") or ""
            if event.get("output_file"):
                background.append({"time": stamp, "subtype": subtype,
                                   "task_id": event.get("task_id"),
                                   "output_file": str(event["output_file"])})
            if subtype == "thinking_tokens":
                continue
            if subtype == "init":
                init = event
                timeline.append({"kind": "system", "subtype": subtype,
                                 "time": stamp, "event": event})
            else:
                timeline.append({"kind": "system", "subtype": subtype,
                                 "time": stamp, "event": event})
        elif kind == "result":
            if _is_placeholder_result(event):
                # Keep it only as a fallback for sessions that never produced
                # a substantive result; do not let it overwrite real metadata.
                placeholder_result = event
                continue
            result = event
            result_time = stamp
            timeline.append({"kind": "result", "time": stamp, "result": event,
                             "is_error": event.get("is_error"),
                             "subtype": event.get("subtype"),
                             "num_turns": event.get("num_turns"),
                             "duration_ms": event.get("duration_ms"),
                             "usage": event.get("usage")})

    if not result and placeholder_result:
        # A session that produced only the synthetic shutdown result still
        # gets a result record, but a real result always wins.
        result = placeholder_result
        result_time = _beijing_time(placeholder_result.get("timestamp"))
        timeline.append({"kind": "result", "time": result_time,
                         "result": placeholder_result,
                         "is_error": placeholder_result.get("is_error"),
                         "subtype": placeholder_result.get("subtype"),
                         "num_turns": placeholder_result.get("num_turns"),
                         "duration_ms": placeholder_result.get("duration_ms"),
                         "usage": placeholder_result.get("usage")})

    # Background commands are part of the synthesis record. Preserve their
    # output files too; the raw stream only carries the transient path.
    if background:
        archive = output / "background"
        archive.mkdir(exist_ok=True)
        used: set[str] = set()
        for number, item in enumerate(background, 1):
            source = Path(item["output_file"])
            if not source.is_file():
                item["archived"] = None
                item["missing"] = True
                continue
            name = re.sub(r"[^A-Za-z0-9_.-]+", "_", source.name) or f"task-{number}.output"
            destination = archive / name
            suffix = 1
            while destination.name in used:
                destination = archive / f"{number}-{suffix}-{name}"
                suffix += 1
            used.add(destination.name)
            shutil.copy2(source, destination)
            item["archived"] = destination.relative_to(output).as_posix()
        with (output / "background-tasks.jsonl").open("w", encoding="utf-8") as handle:
            for item in background:
                handle.write(json.dumps(item, ensure_ascii=False, default=str) + "\n")

    prompt_path = output / "prompt.md"
    prompt = prompt_path.read_text(encoding="utf-8") if prompt_path.is_file() else None
    prompt_source = "recorded"
    source_path = output / "prompt.source.json"
    if source_path.is_file():
        try:
            prompt_source = json.loads(source_path.read_text(encoding="utf-8")).get(
                "source", "recorded")
        except json.JSONDecodeError:
            prompt_source = "recorded"
    metadata = {
        "task": output.parent.name,
        "stage": output.name,
        "session_id": init.get("session_id") or "",
        "model": init.get("model") or "",
        "cwd": init.get("cwd") or "",
        "started_bj": (_beijing_time(init.get("timestamp")) or
                       next((event.get("time") for event in timeline if event.get("time")), "")),
        "prompt_recorded": bool(prompt),
        "prompt_source": prompt_source,
    }
    header = [f"- task: `{metadata['task']}`",
              f"- stage: `{metadata['stage']}`",
              f"- session_id: `{metadata['session_id']}`",
              f"- model: `{metadata['model']}`",
              f"- cwd: `{metadata['cwd']}`",
              f"- started: `{metadata['started_bj']}`",
              f"- prompt: `{'prompt.md' if prompt else '(not recorded)'}` ({prompt_source})",
              "- raw stream: `stdout.jsonl`",
              "- stderr: `stderr.txt`",
              "- cli debug: `cli-debug.log`"]
    if prompt:
        header += ["", "## Initial prompt", "", prompt]

    # trajectory.jsonl is intentionally an index, not a second full transcript.
    # Full content lives in live.chat.md (human/SFT review) and sft.jsonl.
    events: list[dict] = []
    for event in timeline:
        kind = event.get("kind")
        if kind == "turn":
            blocks = event.get("blocks", [])
            events.append({
                "time": event.get("time"), "turn": event.get("turn"),
                "type": "assistant",
                "message_id": event.get("message_id"),
                "tools": [block.get("name") for block in blocks
                          if block.get("type") == "tool_use"],
                "text_chars": sum(len(str(block.get("text", ""))) for block in blocks
                                  if block.get("type") == "text"),
                "thinking_chars": sum(len(str(block.get("thinking", ""))) for block in blocks
                                      if block.get("type") == "thinking"),
            })
        elif kind == "tool_result":
            events.append({"time": event.get("time"), "turn": event.get("turn"),
                           "type": "tool_result",
                           "tool_use_ids": [block.get("tool_use_id")
                                            for block in event.get("blocks", [])]})
        elif kind == "compact":
            events.append({"time": event.get("time"), "turn": event.get("turn"),
                           "type": "compact", "event": event.get("event")})
        elif kind == "system":
            events.append({"time": event.get("time"), "type": "system",
                           "subtype": event.get("subtype")})
        elif kind == "result":
            events.append({"time": event.get("time"), "type": "result",
                           "is_error": event.get("is_error"),
                           "subtype": event.get("subtype"),
                           "num_turns": event.get("num_turns"),
                           "duration_ms": event.get("duration_ms"),
                           "usage": event.get("usage")})

    with (output / trajectory_name).open("w", encoding="utf-8") as handle:
        for event in events:
            handle.write(json.dumps(event, ensure_ascii=False, default=str) + "\n")
    with (output / "tool-calls.jsonl").open("w", encoding="utf-8") as handle:
        for call in calls:
            handle.write(json.dumps(call, ensure_ascii=False, default=str) + "\n")
    # These two are superseded by live.chat.md / sft.jsonl. Remove leftovers
    # from runs written by older pipeline versions.
    for legacy in ("conversation.md", "trajectory.compact.jsonl"):
        try:
            (output / legacy).unlink()
        except FileNotFoundError:
            pass
    (output / "live.chat.md").write_text(
        _render_markdown(timeline, title=f"Live chat — {metadata['stage']}",
                         full=True, header=header), encoding="utf-8")
    _write_sft(output, prompt, timeline, metadata, result)
    return result


def run(prompt: str, workspace: Path, output: Path, *, model: str,
        credentials: dict[str, str], max_turns: int, timeout: int,
        network: Path) -> dict[str, Any]:
    executable = os.environ.get("CLAUDE_BIN") or shutil.which("claude")
    if not executable or not Path(executable).is_file():
        raise RuntimeError("Claude Code is not installed; install version 2.1.228 or set CLAUDE_BIN")
    # cwd=workspace for the CLI; keep all stage paths absolute so --settings,
    # --debug-file, CLAUDE_CONFIG_DIR and HOME cannot be re-rooted under it.
    workspace = workspace.resolve()
    output = output.resolve()
    network = Path(network).resolve()
    output.mkdir(parents=True, exist_ok=True)
    # Keep the exact initial prompt for SFT/reproduction. It contains task
    # evidence, never credentials.
    (output / "prompt.md").write_text(prompt, encoding="utf-8")
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
            env["NO_PROXY"] = NO_PROXY
            env["no_proxy"] = NO_PROXY
    env = workspace_environment(workspace, env)
    env.update({
        "CLAUDE_CODE_MAX_RETRIES": "15",
        # GLM-5.3 advertises a 1M-token context. Leave explicit headroom for
        # output and compaction so the next request never exceeds the cap.
        "CLAUDE_CODE_MAX_CONTEXT_TOKENS": "1000000",
        "CLAUDE_CODE_AUTO_COMPACT_WINDOW": "800000",
        "CLAUDE_CODE_MAX_OUTPUT_TOKENS": "65536",
        "CLAUDE_CODE_DISABLE_NONESSENTIAL_TRAFFIC": "1",
        "CLAUDE_CODE_DISABLE_UNKNOWN_MODEL_WINDOW_ENFORCEMENT": "1",
    })
    # Isolation: do not expose the shared auto-memory or any prior run to the
    # agent.  A per-stage CLAUDE_CONFIG_DIR/HOME keeps any residual config or
    # memory writes inside this task; the PreToolUse guard blocks explicit
    # reads/copies of /memory/, ~/.claude and results/ outside this task.
    agent_config = output / ".agent-config"
    agent_home = output / ".agent-home"
    agent_config.mkdir(parents=True, exist_ok=True)
    agent_home.mkdir(parents=True, exist_ok=True)
    env.update({
        "CLAUDE_CODE_DISABLE_AUTO_MEMORY": "1",
        "CLAUDE_CONFIG_DIR": str(agent_config),
        "HOME": str(agent_home),
        "AGENT_GUARD_WORKSPACE": str(workspace.resolve()),
        "AGENT_GUARD_LOG": str(output / ".agent-guard.log"),
    })
    guard_settings = None
    guard = ROOT / "config/bin/agent_guard.py"
    if guard.is_file():
        guard_settings = output / "agent-guard.json"
        guard_settings.write_text(json.dumps({
            "hooks": {"PreToolUse": [
                {"matcher": tool,
                 "hooks": [{"type": "command", "command": str(guard)}]}
                for tool in ("Bash", "Read", "Edit", "Write")
            ]}
        }, ensure_ascii=False, indent=2), encoding="utf-8")
    record = {"status": "running", "model": model, "started_at": timestamp()}
    write_json(output / "result.json", record)
    started = time.monotonic()
    with (output / "stdout.jsonl").open("w", encoding="utf-8") as stdout, \
            (output / "stderr.txt").open("w", encoding="utf-8") as stderr, \
            (output / "trajectory.jsonl").open("w", encoding="utf-8") as trajectory:
        argv = command(prompt, model, max_turns, network, guard_settings,
                       output / "cli-debug.log")
        argv[0] = executable
        process = subprocess.Popen(argv, cwd=workspace, env=env,
                                   stdout=stdout, stderr=stderr,
                                   start_new_session=True)
        # Keep the two human-facing logs live while the session runs. The
        # final _write_compact_logs below rewrites them from the full stream.
        live = LiveLogs(output, output.parent.name, output.name)
        live.start()
        timed_out = False
        result_seen = False
        deadline = started + timeout
        stdout_path = output / "stdout.jsonl"
        try:
            while process.poll() is None:
                if time.monotonic() >= deadline:
                    timed_out = True
                    os.killpg(process.pid, 15)
                    try:
                        process.wait(timeout=30)
                    except subprocess.TimeoutExpired:
                        os.killpg(process.pid, 9)
                        process.wait(timeout=10)
                    break
                time.sleep(2)
                try:
                    tail = stdout_path.read_text(encoding="utf-8", errors="replace")[-2_000_000:]
                except OSError:
                    continue
                # Claude Code can emit the final result and then keep the process
                # alive for hours. The result event is the authoritative end.
                if '"type":"result"' in tail or '"type": "result"' in tail:
                    result_seen = True
                    time.sleep(2)
                    try:
                        os.killpg(process.pid, signal.SIGTERM)
                    except ProcessLookupError:
                        pass
                    try:
                        process.wait(timeout=15)
                    except subprocess.TimeoutExpired:
                        try:
                            os.killpg(process.pid, signal.SIGKILL)
                        except ProcessLookupError:
                            pass
                        process.wait(timeout=10)
                    break
        finally:
            live.stop()
    # stdout.jsonl is the complete raw stream; write compact, turn-numbered
    # logs for supervision and review without thinking-token heartbeats.
    result = _write_compact_logs(output)
    record.update(status="timeout" if timed_out else
                  ("completed" if (result_seen or process.returncode == 0)
                   and not result.get("is_error") else "agent_error"),
                  returncode=process.returncode, elapsed_sec=round(time.monotonic() - started, 2),
                  num_turns=result.get("num_turns"), result_excerpt=str(result.get("result", ""))[:4000],
                  usage=result.get("usage"), total_cost_usd=result.get("total_cost_usd"),
                  finished_at=timestamp())
    write_json(output / "result.json", record)
    return record
