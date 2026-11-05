#!/usr/bin/env python3
"""Export high-recall review pools for the two current task-family routes.

These are metadata candidates, not accepted tasks. No old P0-PX/lane/g0_keep
filter is used. Full source metadata is preserved for reproducibility.
"""
from __future__ import annotations

import argparse
from collections import Counter
import hashlib
import json
from pathlib import Path
import re
from typing import Any, Iterator

ROOT = Path(__file__).resolve().parents[1]
DATA = ROOT / "data" / "raw"
POV_CLASSES = {"overflow", "dos"}
MEMORY_RE = re.compile(
    r"(?:heap|stack)(?:\W+(?:based|buffer)){0,2}\W+(?:overflow|corruption|"
    r"use\W+after\W+free|out\W+of\W+bounds)|"
    r"buffer\W+(?:overflow|over\W*read|under\W*read|overrun|underrun)|"
    r"out\W+of\W+bounds|\bOOB\b|use\W+after\W+free|\bUAF\b|double\W+free|"
    r"memory\W+corruption|invalid\W+(?:memory\W+)?(?:read|write|access|free)|"
    r"wild\W+pointer|dangling\W+pointer|off\W+by\W+one|"
    r"uninitialized\W+(?:memory|pointer)",
    re.I | re.S,
)
SANITIZER_ADAPTER = {
    "c": "clang_gcc_asan_ubsan", "cpp": "clang_gcc_asan_ubsan",
    "rust": "rust_asan_or_runtime", "go": "go_asan_or_runtime",
    "java": "jazzer_asan_or_runtime", "csharp": "native_or_runtime",
    "javascript": "native_or_runtime", "typescript": "native_or_runtime",
    "python": "native_or_runtime", "php": "native_or_runtime",
    "ruby": "native_or_runtime", "perl": "native_or_runtime",
    "unknown": "identify_runtime_then_adapter", "other": "identify_runtime_then_adapter",
}


def norm(value: Any) -> str:
    result = str(value or "").strip().rstrip("/").lower()
    return result[:-4] if result.endswith(".git") else result


def rows(path: Path) -> Iterator[dict[str, Any]]:
    with path.open(encoding="utf-8") as handle:
        for line_number, line in enumerate(handle, 1):
            if not line.strip():
                continue
            value = json.loads(line)
            if not isinstance(value, dict):
                raise ValueError(f"{path}:{line_number}: expected object")
            yield value


def write_jsonl(path: Path, items: list[dict[str, Any]]) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    temporary = path.with_suffix(path.suffix + ".tmp")
    with temporary.open("w", encoding="utf-8") as handle:
        for item in items:
            handle.write(json.dumps(item, ensure_ascii=False, separators=(",", ":")) + "\n")
    temporary.replace(path)


def evidence(vulnerability: dict[str, Any]) -> dict[str, Any]:
    value = vulnerability.get("exploit_evidence") or {}
    return {
        "poc_available": bool(value.get("poc_available")),
        "poc_texts": value.get("poc_texts"),
        "poc_urls": value.get("poc_urls"),
    }


def base_candidate(catalog: dict[str, Any], tag: dict[str, Any], route: str) -> dict[str, Any]:
    vulnerability = catalog.get("vulnerability") or {}
    return {
        "schema_version": "two-route-candidate-v1",
        "candidate_stage": "metadata_recall_not_accepted",
        "route": route,
        "instance_id": catalog["instance_id"],
        "canonical_id": catalog["canonical_id"],
        "repo": catalog["repo"],
        "vulnerability": {
            "title": vulnerability.get("title"),
            "description": vulnerability.get("description"),
            "withdrawn": vulnerability.get("withdrawn"),
            "cwe_ids": vulnerability.get("cwe_ids"),
            "cvss_vectors": vulnerability.get("cvss_vectors"),
            "affected": vulnerability.get("affected"),
            "exploit_evidence": evidence(vulnerability),
            "references": vulnerability.get("references"),
        },
        "code": catalog.get("code"),
        "sources": catalog.get("sources"),
        "member_ids": catalog.get("member_ids"),
        "old_tags": tag,
    }


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--output-dir", type=Path, default=ROOT / "data")
    args = parser.parse_args()

    old_ids = {norm(row.get("instance_id")) for row in rows(DATA / "meta.exploit.g0.jsonl")}
    tags = {
        norm(row["instance_id"]): row
        for row in rows(DATA / "catalog.tagged_instances.g0.jsonl")
        if norm(row.get("instance_id")) not in old_ids and row.get("layer") != "kernel"
    }
    pov: list[dict[str, Any]] = []
    effect: list[dict[str, Any]] = []
    for catalog in rows(DATA / "catalog.instances.jsonl"):
        key = norm(catalog.get("instance_id"))
        tag = tags.get(key)
        if not tag:
            continue
        vuln_class = tag.get("vuln_class")
        if vuln_class in POV_CLASSES:
            item = base_candidate(catalog, tag, "FILE-POV-G1")
            language = str(tag.get("language") or "unknown")
            item["route_requirements"] = {
                "platform": "linux_userspace",
                "player_source": False,
                "input": "exactly_one_file",
                "single_file_entry_confirmed": False,
                "language_adapter": SANITIZER_ADAPTER.get(language, "identify_runtime_then_adapter"),
                "oracle": "target_runtime_or_sanitizer_error_vulnerable_positive_fixed_negative",
                "resource_only_dos_needs_separate_resource_oracle": vuln_class == "dos",
            }
            pov.append(item)
        description = str((catalog.get("vulnerability") or {}).get("description") or "")
        if vuln_class == "overflow" or (vuln_class == "dos" and MEMORY_RE.search(description)):
            item = base_candidate(catalog, tag, "BIN-FILE-EXPLOIT-G1")
            item["entry_triage"] = "single_file_entry_recovery_required"
            item["route_requirements"] = {
                "platform": "linux_userspace",
                "player_interface": "exactly_one_file_to_fixed_compiled_target",
                "player_source": False,
                "real_single_file_entry_confirmed": False,
                "sanitizers_in_final_target": False,
                "oracle": "unauthorized_code_execution_or_protected_data_read",
                "crash_only_is_not_success": True,
                "memory_corruption_confirmed": False,
                "exploitability_confirmed": False,
                "fallback_route": "FILE-POV-G1",
            }
            effect.append(item)

    pov.sort(key=lambda item: hashlib.sha256(item["instance_id"].encode()).hexdigest())
    effect.sort(key=lambda item: hashlib.sha256(item["instance_id"].encode()).hexdigest())
    pov_path = args.output_dir / "file-pov-g1.candidates.jsonl"
    effect_path = args.output_dir / "bin-file-exploit-g1.candidates.jsonl"
    write_jsonl(pov_path, pov)
    write_jsonl(effect_path, effect)

    report: dict[str, Any] = {
        "schema_version": "two-route-candidate-report-v1",
        "candidate_definition": "high-recall metadata review pool; not accepted or delivered tasks",
        "old_instances_excluded": len(old_ids),
        "pov": {"path": str(pov_path), "count": len(pov)},
        "effect": {"path": str(effect_path), "count": len(effect)},
    }
    for name, items in (("pov", pov), ("effect", effect)):
        for field in ("language", "vuln_class", "layer", "surface", "action"):
            report[name][field] = dict(sorted(Counter(str(item["old_tags"].get(field)) for item in items).items()))
        report[name]["poc_available"] = sum(item["vulnerability"]["exploit_evidence"]["poc_available"] for item in items)
        report[name]["unique_instances"] = len({norm(item["instance_id"]) for item in items})
    report["effect"]["entry_triage"] = dict(Counter(item["entry_triage"] for item in effect))
    report_path = args.output_dir / "candidate-report.json"
    report_path.write_text(json.dumps(report, ensure_ascii=False, indent=2) + "\n", encoding="utf-8")
    print(json.dumps(report, ensure_ascii=False, indent=2))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
