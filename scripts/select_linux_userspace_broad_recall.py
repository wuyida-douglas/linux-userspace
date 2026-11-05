#!/usr/bin/env python3
"""Broad metadata recall: exclude only clearly unsuitable vulnerability types.

This intentionally has no fix-SHA, vulnerability-effect, service/file-entry,
or route-hint gate. The route agent validates source, patch, effect and entry.
It never overwrites recall-v3 or any completed sample.
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
SCHEMA_VERSION = "linux-userspace-broad-recall-v1"
INPUT_KEYS = (
    "schema_version", "instance_id", "canonical_id", "repo", "vulnerability",
    "code", "sources", "member_ids", "old_tags",
)


def compile(pattern: str) -> re.Pattern[str]:
    return re.compile(pattern, re.I)


BROWSER_VULN = compile(
    r"cross[- ]site scripting|\bXSS\b|cross[- ]site request forgery|\bCSRF\b|"
    r"open redirect|clickjacking|html injection|dom clobbering")
PLATFORM = compile(
    r"\b(?:linux kernel|kernel (?:driver|module|subsystem|mode)|"
    r"in the (?:linux )?kernel|device driver|firmware|hypervisor|"
    r"virtual machine monitor|uefi|bootloader|embedded (?:device|system|os)|"
    r"microcontroller|arduino|rtl8195|rtl8710|ios|android)\b")
CLIENT_ATTACK = compile(
    r"(?:malicious|rogue|compromised|crafted|attacker.controlled|untrusted)"
    r"[^.;\n]{0,80}\b(?:server|broker|peer|website|web page)\b[^.;\n]{0,100}"
    r"\b(?:client|viewer|user|victim|browser)\b|"
    r"\b(?:client|viewer|user|victim|browser)\b[^.;\n]{0,100}"
    r"(?:malicious|rogue|compromised|attacker.controlled)[^.;\n]{0,80}"
    r"(?:server|broker|peer|website|web page)\b|"
    r"\bclient[- ]side\b|\brequires user interaction\b|\bvictim(?:'s)? browser\b")
BROWSER_ENGINE = compile(
    r"\b(?:chakracore|javascriptcore|webkit|chromium|mozilla firefox|"
    r"microsoft edge|v8 (?:javascript )?engine|browser (?:engine|process)|"
    r"scripting engine memory corruption)\b")
EXCLUSIONS = (
    ("browser", BROWSER_VULN), ("platform", PLATFORM),
    ("client", CLIENT_ATTACK), ("browser_engine", BROWSER_ENGINE),
)


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
        return "kernel_firmware_embedded", evidence
    if "client" in evidence:
        return "client_or_victim_role", evidence
    if "browser_engine" in evidence:
        return "browser_engine_specialized_environment", evidence
    return None, evidence


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--input", type=Path, default=ROOT / "data/remaining-38901.instances.jsonl")
    parser.add_argument("--output-dir", type=Path, default=ROOT / "data/broad-recall-v1")
    parser.add_argument("--seed", type=int, default=20261103)
    parser.add_argument("--audit-count", type=int, default=100)
    args = parser.parse_args()
    if args.audit_count < 1:
        parser.error("audit-count must be positive")
    output_dir = args.output_dir.resolve()
    if output_dir == (ROOT / "data/recall-v3").resolve():
        parser.error("refusing to overwrite the frozen recall-v3 pool")

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
            "candidate_stage": "broad_metadata_recall_not_route_acceptance",
            "exclusion_evidence": evidence,
            "scan_scope": "title_description_product_repo_only_no_references_or_poc",
            "gates_removed": ["fix_revision", "verifiable_effect", "service_or_file_entry"],
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
        "warning": "Broad metadata recall only. Source availability, patch validity, effect and entry are validated later.",
        "gates_removed": ["fix_revision", "verifiable_effect", "service_or_file_entry"],
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
