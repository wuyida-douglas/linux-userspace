#!/usr/bin/env python3
"""Max-recall metadata filter with only explicit unsuitable-type exclusions.

Keep withdrawn, browser-only XSS/CSRF/redirect/UI injection, and explicit
kernel/firmware/hardware-platform records out. Do not infer task feasibility
from client, browser-engine, mobile, embedded, effect, entry or revision hints.
The route agent validates source, patch, effect and entry later.

Outputs are separate from recall-v3, broad-recall-v1 and completed samples.
"""
from __future__ import annotations

import argparse
from collections import Counter
import hashlib
import json
from pathlib import Path
import random
import re
from typing import Any, Iterable

ROOT = Path(__file__).resolve().parents[1]
SCHEMA_VERSION = "linux-userspace-minimal-exclusions-v1"
INPUT_KEYS = (
    "schema_version", "instance_id", "canonical_id", "repo", "vulnerability",
    "code", "sources", "member_ids", "old_tags",
)


def compile(pattern: str) -> re.Pattern[str]:
    return re.compile(pattern, re.I)


BROWSER_VULN = compile(
    r"cross[- ]site scripting|\bXSS\b|cross[- ]site request forgery|\bCSRF\b|"
    r"open redirect|clickjacking|html injection|dom clobbering")
# Deliberately excludes only explicit privileged/hardware environments.
# Android, iOS and embedded Linux may still contain userspace targets.
PLATFORM = compile(
    r"\b(?:linux kernel|kernel (?:driver|module|subsystem|mode)|"
    r"in the (?:linux )?kernel|device driver|firmware|hypervisor|"
    r"virtual machine monitor|uefi|bootloader|microcontroller|"
    r"arduino|rtl8195|rtl8710)\b")
EXCLUSIONS = (("browser", BROWSER_VULN), ("platform", PLATFORM))


def rows(path: Path) -> Iterable[dict[str, Any]]:
    with path.open(encoding="utf-8") as handle:
        for number, line in enumerate(handle, 1):
            if not line.strip():
                continue
            row = json.loads(line)
            if not isinstance(row, dict):
                raise ValueError(f"{path}:{number}: expected an object")
            yield row


def write_jsonl(path: Path, values: Iterable[dict[str, Any]]) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    temporary = path.with_suffix(path.suffix + ".tmp")
    with temporary.open("w", encoding="utf-8") as handle:
        for row in values:
            handle.write(json.dumps(row, ensure_ascii=False, separators=(",", ":")) + "\n")
    temporary.replace(path)


def primary_text(row: dict[str, Any]) -> str:
    """Match focused text, excluding references, PoC and recursive fields."""
    vulnerability = row.get("vulnerability") or {}
    tags = row.get("old_tags") or {}
    repositories = (row.get("code") or {}).get("repositories") or []
    repo_names = [item if isinstance(item, str) else str(item.get("url") or item.get("name") or "")
                  for item in repositories if isinstance(item, (str, dict))]
    return "\n".join(str(value or "") for value in (
        vulnerability.get("title"), vulnerability.get("description"),
        tags.get("product"), tags.get("app_family"), row.get("repo"), *repo_names))


def match(pattern: re.Pattern[str], text: str) -> str | None:
    found = pattern.search(text)
    return found.group(0) if found else None


def classify(row: dict[str, Any]) -> tuple[str | None, dict[str, str]]:
    """Return a hard-exclusion reason and its focused-text evidence."""
    tags = row.get("old_tags") or {}
    text = primary_text(row)
    evidence = {name: found for name, pattern in EXCLUSIONS
                if (found := match(pattern, text))}
    if (row.get("vulnerability") or {}).get("withdrawn"):
        return "withdrawn", evidence
    if tags.get("vuln_class") in {"xss", "csrf", "open_redirect"} or "browser" in evidence:
        return "browser_xss_csrf_redirect", evidence
    if tags.get("layer") == "kernel" or "platform" in evidence:
        return "kernel_firmware_hardware", evidence
    return None, evidence


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--input", type=Path, default=ROOT / "data/remaining-38901.instances.jsonl")
    parser.add_argument("--output-dir", type=Path, default=ROOT / "data/minimal-exclusions-v1")
    parser.add_argument("--seed", type=int, default=20261103)
    parser.add_argument("--audit-count", type=int, default=100)
    args = parser.parse_args()
    if args.audit_count < 1:
        parser.error("audit-count must be positive")
    if args.output_dir.resolve() in {
        (ROOT / "data/recall-v3").resolve(),
        (ROOT / "data/broad-recall-v1").resolve(),
    }:
        parser.error("refusing to overwrite an existing recall pool")

    accepted = []
    rejected = Counter()
    input_count = 0
    for row in rows(args.input):
        input_count += 1
        reason, evidence = classify(row)
        if reason:
            rejected[reason] += 1
            continue
        item = {key: row.get(key) for key in INPUT_KEYS}
        item["recall"] = {
            "schema_version": SCHEMA_VERSION,
            "candidate_stage": "minimal_exclusions_metadata_recall_not_route_acceptance",
            "exclusion_evidence": evidence,
            "scan_scope": "title_description_product_repo_only_no_references_or_poc",
            "gates_removed": [
                "fix_revision", "verifiable_effect", "service_or_file_entry",
                "client_role", "browser_engine", "mobile_or_embedded_name",
            ],
            "route_hints_assigned": False,
            "requires_real_patch_and_entry_validation": True,
        }
        accepted.append(item)
    accepted.sort(key=lambda row: hashlib.sha256(row["instance_id"].encode()).hexdigest())
    args.output_dir.mkdir(parents=True, exist_ok=True)
    output = args.output_dir / "candidates.jsonl"
    write_jsonl(output, accepted)
    audit = random.Random(args.seed).sample(accepted, min(args.audit_count, len(accepted)))
    write_jsonl(args.output_dir / "random-audit.jsonl", audit)
    report = {
        "schema_version": SCHEMA_VERSION,
        "input": str(args.input), "input_count": input_count,
        "candidate_count": len(accepted), "candidate_path": str(output),
        "unique_instances": len({row["instance_id"] for row in accepted}),
        "metadata_recall_rate": len(accepted) / input_count,
        "seed": args.seed, "audit_count": len(audit),
        "warning": "Minimal metadata exclusions only. Source availability, patch validity, effect and entry are validated later.",
        "gates_removed": [
            "fix_revision", "verifiable_effect", "service_or_file_entry",
            "client_role", "browser_engine", "mobile_or_embedded_name",
        ],
        "route_hints_assigned": False,
        "rejected": dict(rejected),
        "language": dict(Counter(str((row.get("old_tags") or {}).get("language")) for row in accepted)),
        "vuln_class": dict(Counter(str((row.get("old_tags") or {}).get("vuln_class")) for row in accepted)),
        "layer": dict(Counter(str((row.get("old_tags") or {}).get("layer")) for row in accepted)),
        "poc_available": sum(bool(((row.get("vulnerability") or {}).get("exploit_evidence") or {}).get("poc_available"))
                            for row in accepted),
    }
    (args.output_dir / "report.json").write_text(
        json.dumps(report, ensure_ascii=False, indent=2) + "\n", encoding="utf-8")
    print(json.dumps(report, ensure_ascii=False, indent=2))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
