"""Deterministic, bounded JSON batch labeling against Anthropic-compatible APIs.

Each committed batch is atomic and includes the exact compact inputs. Successful
batches are never retried on resume; failed batches have durable bounded errors.
Credentials are read by common.load_env and never serialized or placed on argv.
"""
from __future__ import annotations

import concurrent.futures
import hashlib
import json
import random
import re
import threading
import time
from pathlib import Path
from typing import Any, Iterable

import anthropic

from .common import read_jsonl, timestamp, write_json, write_jsonl

LABEL_PROMPT_V1 = """You are a metadata triage classifier for containerizable Linux userspace vulnerability tasks.
Decide whether each CVE-repository instance is WORTH A SOURCE/PATCH ROUTING REVIEW, not whether a working exploit already exists. You see metadata only. Never claim that compilation, a patch mapping or an exploit has been verified.

Output JSON only: {"labels":[{"instance_id":"exact supplied id","label":"keep"|"reject","confidence":0.0,"reason":"brief concrete evidence from this item"}]}.
Return exactly one decision for every supplied item, in input order, with no extra keys, prose or markdown. Reserve enough output tokens to finish the entire JSON response. Copy IDs byte-for-byte. label=keep means plausible enough for later source validation; label=reject means the available description gives a concrete mismatch with this pipeline. Use confidence as calibrated uncertainty, not as a hidden third label.

KEEP a plausible target when its real userspace input could be a network interaction OR one attacker-controlled file. A file parser, interpreter, compression/image/media library, database library, protocol implementation, language runtime or other component is NOT rejected merely because it lacks a daemon. For SVC, later review may choose an upstream native service, a genuine application using the component, or a thin host over its real public API. A thin host must preserve normal API semantics and a meaningful protocol/state/permission/network boundary. If serviceization would be a meaningless HTTP wrapper, consider a real CLI, official fuzz/test entry or thinnest faithful public-API file runner instead. A library must never be rejected solely because old_tags calls it a library or says not_a_web.
Keep plausible native memory corruption, null dereference, UAF, overflow, resource exhaustion, infinite loop and parser crashes for FILE-POV; an unauthorized security effect is not required for that lower-tier branch. Keep possible command/code execution, protected-data access, authorization bypass, path traversal, file write/upload, SQL/XXE/SSRF and request-smuggling effects when a concrete server or file path is plausible. Do not demand a public PoC, exact fix SHA, effect keyword, entry keyword or C/C++ as a precondition.
Server-side flaws in a web application can be considered; do not confuse an HTTP input with a browser-only attack. Evaluate non-browser protocol/client possibilities rather than relying on a CMS/product stereotype.

REJECT only with concrete evidence of a scope or interaction mismatch:
- Linux kernel/driver, hypervisor/VM escape, firmware, hardware or other environment that an ordinary userspace Linux OCI task cannot reproduce. However, do not reject portable userspace parsing code solely because it also ships in an embedded RTOS, firmware or peripheral stack: if crafted recorded bytes can be passed to its real public parser/codec API on Linux without that hardware, the FILE path remains plausible. Hardware implementation, register access, privileged mounts and actual device I/O are not parser file inputs.
- A browser rendering engine or victim-browser interaction, XSS, CSRF, clickjacking, open redirect, or browser-enforced-only policy. Do not reject an independent non-browser server or file path merely because a browser also exists.
- A pure client-side attack where a malicious server/peer/website attacks a connecting victim client. Never reverse roles and call that victim client a service. First identify the actual long-running target role, THEN the direction of one message. A resolver, forwarder, proxy, recursive DNS server or other long-running intermediary that handles requests for other users is a service even while it consumes upstream responses: do not misclassify its upstream connection as a one-off victim client. A dual-role product with a real listening endpoint may be reviewed through that endpoint. For a component supporting both client and server roles, reject only the described client-victim path if no independent service/file role is evidenced. Native memory corruption or a mock-peer harness alone does not exempt a genuine one-off victim client from rejection. Saving a malicious network response as a file is not by itself a valid FILE fallback, but offline parsing of recorded peripheral/protocol bytes through a real public API may be an independent file input when no physical device is required. When metadata names a concrete native parser, decoder or public data-processing API, do not infer that the only possible input is a live malicious peer; keep it for source review if ordinary offline byte input plausibly reaches the same code.
- A GUI-only, mobile-only, Windows-only, physical-device-only or otherwise non-Linux-required target with no plausible ordinary Linux path. Embedded Linux libraries and mobile-supported runtimes are not excluded merely by their names. Reject a platform-specific path only when the mechanism is actually tied to that platform, not just because a filename or product name sounds platform-specific.
- Privileged host state, physical access, GPU/USB/TEE/real device requirements, social engineering, or a vulnerability entirely about local policy/business workflow without a reproducible technical target-side effect. A cloud or hardware integration NAME is not proof of such a dependency when the defect lies in a local file parser, credential/logging path, deterministic API, or concurrency routine whose inputs can be locally modeled. Do not require the real cloud/device for those local effects.
- Clearly unrelated repository/vulnerability evidence, withdrawn/duplicate non-vulnerability, or no security-relevant runtime behavior to reproduce. Do NOT reject solely because the exact fix is not in this compact metadata; that belongs to source review.
- An ordinary business Web/CMS issue whose only effect needs interactive browser use or manual administrative content editing and has no independent technical service effect.

Do not reject a cross-platform runtime, package manager or developer tool merely because the advisory also names a Windows IDE: a crafted package, project, configuration or other real input parsed by its Linux CLI/API remains a possible file route. Do not reject a real public API's deterministic persistence, serialization, state or authorization differential merely because it belongs to a client-capable library or needs no live network; distinguish this from recording an already malicious server response as a disguised file route. An ordinary file-driven caller of a documented public API is not necessarily a privileged self-attack. DISPUTED is not WITHDRAWN and is not sufficient for rejection when a concrete native memory or parser effect is described.
A server-side integrity or authorization defect may be observable through HTML/API state; do not confuse content displayed in a UI with browser-only script execution. Credentials, authentication, a command-line launch, localhost IPC, a race, an ordinary multi-UID temp-file/permission boundary, a documented API-observable account/authentication effect, and a separate ordinary Linux service/container are not by themselves exclusions. Do not demand access to a live production service when its described technical interaction can be locally modeled. Require concrete evidence of an unreproducible external dependency before rejecting on that basis. Server-side web apps, bots, chat-command handlers, messaging/protocol gateways, and event-driven agents are not pure victim clients merely because their upstream network events normally come from an external platform. Their inbound events and permission state may be locally modeled for later routing review; do not require live production integration.
Before rejecting for missing attacker input or external infrastructure, explicitly check whether the description itself gives a file/configuration/API input and a local technical effect such as memory corruption, crash, secret logging or unauthorized state. Do not infer a host privilege or live infrastructure requirement merely from a product integration name.
Treat old_tags, product labels, CVSS, and repository names as hints, not proof. Avoid over-general rules from one product family. Prefer keep when there is a concrete plausible userspace input and runtime effect but construction details are uncertain; prefer reject when the necessary attacker role/platform is clearly incompatible. Do not invent functions, patches, APIs or host applications. Explain the decisive item-specific fact in at most 45 words.
"""

GT_ROLES = {
    "inclusive": """Act as an independent recall-oriented vulnerability triage reviewer. Find a genuine source-review path where evidence supports one, especially for libraries that can use a real host or file runner. Do not accept imaginary APIs or reverse client/server roles. Do not see or infer any other reviewer's vote.""",
    "strict": """Act as an independent scope-adversarial vulnerability triage reviewer. Check exact attacker role, platform, technical runtime effect and ordinary Linux container feasibility. Reject clear mismatches but do not invent build/patch objections absent from metadata or reject solely for being a library. Do not see or infer any other reviewer's vote.""",
    "boundary": """Act as an independent boundary-case reviewer. Concentrate on client-versus-server roles, browser-only versus server-side flaws, component-host possibilities, and file-POV versus high-impact exploit requirements. Judge each item independently without seeing other reviewers' votes.""",
}
GT_PROMPT = LABEL_PROMPT_V1 + """

For this independent ground-truth review, inspect all focused fields carefully. You may use relevant PoC text or advisory excerpts when explicitly supplied, but do not treat links alone as evidence. Provide decisive evidence, not general product impressions. Confidence below 0.65 marks a genuinely uncertain metadata decision.
"""
ADJUDICATE_PROMPT = """You are the final metadata-review adjudicator. The target is whether an instance merits source/patch routing for a containerizable Linux userspace service OR one-file vulnerability task. Libraries can use native services, real application hosts, faithful thin public-API hosts, or file runners; library status alone is not a rejection. Native parser crashes/resource effects can be file POV; pure malicious-server-to-client attacks and browser-only victim interactions are out of scope. Do not demand a proven build, patch, or exploit at this metadata stage.

You receive one focused instance and three independent reviews. Their votes are fallible evidence, not a majority-vote command. Compare each reason to the supplied description and PoC/advisory evidence. Correct unsupported assumptions in either direction. If the metadata truly cannot resolve the boundary, make the best evidence-based binary choice with confidence <=0.6 and mention the unresolved fact.
Return JSON only: {"instance_id":"exact supplied id","label":"keep"|"reject","confidence":0.0,"reason":"specific adjudicated evidence in at most 70 words","agreement":"unanimous"|"majority"|"split"}.
No markdown or extra fields. Do not identify products from memorized prior reviews or propose item-specific changes to a classifier.
"""


def compact_row(row: dict[str, Any], *, include_evidence: bool = False) -> dict[str, Any]:
    """Keep stable field order and exclude huge/noisy recursive metadata."""
    vulnerability = row.get("vulnerability") or {}
    tags = row.get("old_tags") or {}
    candidates = (row.get("code") or {}).get("candidates") or []
    candidate = candidates[0] if candidates else {}
    item = {
        "instance_id": row["instance_id"],
        "repo": row.get("repo"),
        "title": vulnerability.get("title"),
        "description": vulnerability.get("description"),
        "cwe_ids": vulnerability.get("cwe_ids"),
        "cvss_vectors": vulnerability.get("cvss_vectors"),
        "withdrawn": vulnerability.get("withdrawn"),
        "fix_revision": (candidate.get("fix") or {}).get("revision"),
        "candidate_repo": candidate.get("repo"),
        "candidate_confidence": candidate.get("confidence"),
        "old_tags": {key: tags.get(key) for key in
                     ("vuln_class", "language", "layer", "surface", "product", "app_family")},
    }
    if include_evidence:
        evidence = vulnerability.get("exploit_evidence") or {}
        item["exploit_evidence"] = {
            "poc_available": evidence.get("poc_available"),
            "poc_texts": str(evidence.get("poc_texts") or "")[:5000],
        }
        references = [ref.get("url") if isinstance(ref, dict) else ref
                      for ref in candidate.get("source_references") or []]
        item["advisory_reference_urls"] = references[:5]
    return item


def compact_text(item: dict[str, Any]) -> str:
    return json.dumps(item, ensure_ascii=False, separators=(",", ":"))


def batch_id(items: list[dict[str, Any]]) -> str:
    ids = [item["instance_id"] for item in items]
    return "batch-" + hashlib.sha256("\n".join(ids).encode()).hexdigest()[:20]


def extract_json(text: str) -> dict[str, Any]:
    """Parse a JSON object; tolerate only an explicitly fenced response."""
    text = text.strip()
    match = re.fullmatch(r"```(?:json)?\s*(\{.*\})\s*```", text, re.DOTALL)
    if match:
        text = match.group(1)
    try:
        value = json.loads(text)
    except json.JSONDecodeError as exc:
        start, end = text.find("{"), text.rfind("}")
        if start < 0 or end < start:
            raise ValueError("response contains no JSON object") from exc
        try:
            value = json.loads(text[start:end + 1])
        except json.JSONDecodeError as nested:
            raise ValueError(f"invalid JSON response: {nested}") from nested
    if not isinstance(value, dict):
        raise ValueError("response must be a JSON object")
    return value


def validate_labels(value: dict[str, Any], items: list[dict[str, Any]]) -> list[dict[str, Any]]:
    labels = value.get("labels")
    if not isinstance(labels, list) or len(labels) != len(items):
        raise ValueError("labels must contain exactly one result per input")
    result = []
    for item, label in zip(items, labels):
        if not isinstance(label, dict) or label.get("instance_id") != item["instance_id"]:
            raise ValueError("label instance_id or input order differs from the batch")
        if label.get("label") not in {"keep", "reject"}:
            raise ValueError("label must be keep or reject")
        confidence = label.get("confidence")
        if not isinstance(confidence, (float, int)) or isinstance(confidence, bool) \
                or not 0 <= confidence <= 1:
            raise ValueError("confidence must be a number in [0,1]")
        if not isinstance(label.get("reason"), str) or not label["reason"].strip():
            raise ValueError("reason must be nonempty")
        result.append({"instance_id": item["instance_id"], "label": label["label"],
                       "confidence": float(confidence), "reason": label["reason"].strip()})
    return result


def validate_adjudication(value: dict[str, Any], item: dict[str, Any]) -> dict[str, Any]:
    if value.get("instance_id") != item["instance_id"] \
            or value.get("label") not in {"keep", "reject"} \
            or value.get("agreement") not in {"unanimous", "majority", "split"}:
        raise ValueError("invalid adjudication id, label or agreement")
    confidence = value.get("confidence")
    if not isinstance(confidence, (int, float)) or isinstance(confidence, bool) or not 0 <= confidence <= 1:
        raise ValueError("invalid adjudication confidence")
    if not isinstance(value.get("reason"), str) or not value["reason"].strip():
        raise ValueError("adjudication reason must be nonempty")
    return {"instance_id": item["instance_id"], "label": value["label"],
            "confidence": float(confidence), "reason": value["reason"].strip(),
            "agreement": value["agreement"]}


class JsonLabeler:
    def __init__(self, credentials: dict[str, str], model: str = "glm-5.3",
                 timeout: float = 240, max_tokens: int = 8192,
                 thinking_enabled: bool = True):
        self.model = model
        self.thinking_enabled = thinking_enabled
        self.timeout = timeout
        self.max_tokens = max_tokens
        # Separate clients are cheap and avoid cross-thread mutable request state.
        self.local = threading.local()
        self.credentials = credentials

    def client(self) -> anthropic.Anthropic:
        if not hasattr(self.local, "client"):
            self.local.client = anthropic.Anthropic(
                api_key=self.credentials.get("ANTHROPIC_AUTH_TOKEN") or self.credentials.get("ANTHROPIC_API_KEY"),
                base_url=self.credentials["ANTHROPIC_BASE_URL"], timeout=self.timeout, max_retries=0)
        return self.local.client

    def request(self, prompt: str, items: list[dict[str, Any]]) -> tuple[dict[str, Any], dict[str, Any]]:
        """Constant prompt is the stable prefix; all variable records come after."""
        messages = [{"role": "user", "content": "INSTANCES:\n" + "\n".join(compact_text(item) for item in items)}]
        system = [{"type": "text", "text": prompt, "cache_control": {"type": "ephemeral"}}]
        print(f"API request start: {len(items)} item(s), max_tokens={self.max_tokens}", flush=True)
        started = time.monotonic()
        response = self.client().messages.create(
            model=self.model, max_tokens=self.max_tokens, system=system, messages=messages,
            thinking={"type": "enabled"} if self.thinking_enabled else {"type": "disabled"})
        print(f"API response received in {time.monotonic()-started:.1f}s", flush=True)
        text = "".join(block.text for block in response.content if block.type == "text")
        raw = response.model_dump(exclude_none=True)
        usage = raw.get("usage", {})
        try:
            return extract_json(text), usage
        except ValueError as exc:
            # Empty text is different from malformed JSON: some gateways put
            # everything in reasoning and stop at max_tokens. Keep bounded,
            # credential-free evidence for diagnosis and targeted retries.
            evidence = {"error": str(exc), "stop_reason": raw.get("stop_reason"),
                        "stop_sequence": raw.get("stop_sequence"),
                        "text_chars": len(text), "text_excerpt": text[:500],
                        "content_blocks": [{"type": block.get("type"),
                                            "chars": len(str(block.get("text") or block.get("thinking") or ""))}
                                           for block in raw.get("content", [])]}
            raise ValueError(json.dumps(evidence, ensure_ascii=False)) from exc


def one_json_attempt(labeler: JsonLabeler, prompt: str, items: list[dict[str, Any]],
                     validator: str, retries: int) -> tuple[dict[str, Any], dict[str, Any]]:
    last_error: Exception | None = None
    for attempt in range(1, retries + 1):
        try:
            value, usage = labeler.request(prompt, items)
            if validator in {"batch", "classification-v1"} or validator.startswith("gt-"):
                result: dict[str, Any] = {"labels": validate_labels(value, items)}
            elif validator == "adjudication":
                if len(items) != 1:
                    raise ValueError("adjudication requires exactly one item")
                result = validate_adjudication(value, items[0])
            else:
                raise ValueError("unknown response validator")
            usage = usage | {"attempt": attempt}
            return result, usage
        except (anthropic.APIError, OSError, ValueError, TypeError, KeyError) as exc:
            last_error = exc
            status = getattr(exc, "status_code", None)
            retryable = isinstance(exc, (ValueError, TypeError, KeyError, OSError,
                                         anthropic.APIConnectionError, anthropic.APITimeoutError,
                                         anthropic.InternalServerError, anthropic.RateLimitError))
            if status is not None and (status in {408, 409, 429} or status >= 500):
                retryable = True
            print(f"API attempt {attempt}/{retries} {type(exc).__name__}: {str(exc)[:300]}", flush=True)
            if not retryable or attempt == retries:
                break
            time.sleep(min(60, 2 ** min(attempt, 6)) + random.random())
    raise RuntimeError(f"{type(last_error).__name__}: {last_error}"[:1200])


def process_pending(output: Path, pending: list[tuple[str, str, str, list[dict[str, Any]]]],
                    labeler: JsonLabeler, *, workers: int, retries: int) -> None:
    """Commit one durable result file at a time; no half-JSONL checkpoint."""
    (output / "batches").mkdir(parents=True, exist_ok=True)
    completed = 0
    with concurrent.futures.ThreadPoolExecutor(max_workers=workers) as pool:
        futures = {pool.submit(one_json_attempt, labeler, prompt, items, kind, retries): (kind, name, items)
                   for kind, name, prompt, items in pending}
        try:
            for future in concurrent.futures.as_completed(futures):
                kind, name, items = futures[future]
                try:
                    result, usage = future.result()
                    record = {"status": "complete", "kind": kind, "batch_id": name,
                              "instance_ids": [item["instance_id"] for item in items],
                              "model": labeler.model, "thinking_enabled": labeler.thinking_enabled,
                              "max_tokens": labeler.max_tokens, "result": result, "usage": usage,
                              "completed_at": timestamp()}
                    write_json(output / "batches" / f"{name}.json", record)
                    completed += 1
                    if completed % 10 == 0 or completed == len(pending):
                        print(f"committed {completed}/{len(pending)} new batches", flush=True)
                except Exception as exc:
                    error = {"status": "failed", "kind": kind, "batch_id": name,
                             "instance_ids": [item["instance_id"] for item in items],
                             "error": str(exc)[:1200], "failed_at": timestamp()}
                    write_json(output / "batches" / f"{name}.failed.json", error)
                    print(f"FAILED {name}: {error['error']}", flush=True)
        finally:
            # Do not abandon requests already running during an interrupt.
            pool.shutdown(wait=True, cancel_futures=True)


def completed_batches(output: Path, kind: str | None = None) -> dict[str, dict[str, Any]]:
    result = {}
    for path in (output / "batches").glob("batch-*.json"):
        record = json.loads(path.read_text(encoding="utf-8"))
        if record.get("status") == "complete" and (kind is None or record.get("kind") == kind):
            result[record["batch_id"]] = record
    return result


def submit_batches(output: Path, specs: list[tuple[str, str, str, list[dict[str, Any]]]],
                   labeler: JsonLabeler, workers: int = 20, retries: int = 7) -> dict[str, Any]:
    if not 1 <= workers <= 20:
        raise ValueError("workers must be 1..20")
    done = completed_batches(output)
    pending = [spec for spec in specs if spec[1] not in done]
    print(f"batches total={len(specs)} cached={len(specs)-len(pending)} pending={len(pending)}", flush=True)
    process_pending(output, pending, labeler, workers=workers, retries=retries)
    done = completed_batches(output)
    missing = [spec[1] for spec in specs if spec[1] not in done]
    report = {"requested": len(specs), "complete": len(specs) - len(missing),
              "failed_or_pending": missing, "workers": workers, "updated_at": timestamp()}
    write_json(output / "run-status.json", report)
    if missing:
        raise RuntimeError(f"{len(missing)} batches need resume; no partial batch was accepted")
    return report


def classification_specs(rows: list[dict[str, Any]], prompt: str, batch_size: int = 10,
                         kind: str = "classification-v1") -> list[tuple[str, str, str, list[dict[str, Any]]]]:
    items = [compact_row(row) for row in rows]
    return [(kind, batch_id(batch), prompt, batch) for batch in
            (items[index:index + batch_size] for index in range(0, len(items), batch_size))]


def flatten_classification(output: Path) -> dict[str, dict[str, Any]]:
    result = {}
    for record in completed_batches(output, "classification-v1").values():
        for item in record["result"]["labels"]:
            if item["instance_id"] in result:
                raise ValueError("duplicate classified instance")
            result[item["instance_id"]] = item | {"batch_id": record["batch_id"], "usage": record["usage"]}
    return result


def gt_specs(rows: list[dict[str, Any]]) -> list[tuple[str, str, list[dict[str, Any]]]]:
    specs = []
    for role, instruction in GT_ROLES.items():
        for row in rows:
            item = compact_row(row, include_evidence=True)
            specs.append((f"gt-{role}", batch_id([item]) + "-" + role, [item]))
    return specs


def gt_prompt(kind: str) -> str:
    role = kind.removeprefix("gt-")
    return GT_PROMPT + "\nYOUR INDEPENDENT REVIEW ROLE:\n" + GT_ROLES[role]


def load_rows(path: Path) -> list[dict[str, Any]]:
    return list(read_jsonl(path))
