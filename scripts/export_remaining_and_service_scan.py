#!/usr/bin/env python3
"""Export the remaining vulnerability x repository pool and scan service clues.

Regex matches are review hints, not proof of a deployable daemon, an untrusted
network entrypoint, exploitability, or a successful Docker build.
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

PRODUCT_PATTERNS = {
    "database": [
        r"\b(?:mysql|mariadb|postgresql|postgres|pgjdbc|mongodb|redis|valkey|"
        r"memcached|couchdb|cassandra|clickhouse|elasticsearch|opensearch|"
        r"neo4j|influxdb|timescaledb|sqlite|duckdb|etcd|zookeeper|"
        r"sql server|oracle database|database server|database daemon)\b",
    ],
    "system_network_daemon": [
        r"\b(?:openssh|sshd|dropbear|libssh|vsftpd|proftpd|pure-ftpd|"
        r"openvpn|wireguard|strongswan|openswan|libreswan|ipsec|"
        r"samba|smbd|nfsd|rpcbind|snmpd|net-snmp|ntpsec|ntpd|chronyd|"
        r"dnsmasq|bind9|named|unbound|knot dns|powerdns|coredns|"
        r"freeradius|hostapd|wpa_supplicant|openldap|389 directory server|"
        r"cups|cupsd|postfix|exim|sendmail|dovecot|courier|"
        r"haproxy|nginx|apache httpd|apache http server|lighttpd|"
        r"squid|varnish|envoy|traefik|openresty|tomcat|jetty|"
        r"rabbitmq|activemq|artemis|kafka|nats|mosquitto|emqx|"
        r"dockerd|containerd|runc|cri-o|kubelet|"
        r"system daemon|network daemon|server daemon|network service)\b",
    ],
}
PROTOCOL_RE = re.compile(
    r"\b(?:ssh|sftp|ftp|ftps|smtp|imap|pop3|ldap|ldaps|dns|dhcp|ntp|snmp|"
    r"smb|cifs|nfs|rdp|vnc|mqtt|amqp|xmpp|irc|sip|rtp|rtsp|kerberos|"
    r"ipsec|openvpn|wireguard|telnet|memcached|redis|"
    r"(?:network|server|client) protocol|(?:tcp|udp) (?:server|service|daemon|port)|"
    r"listens? on|listening (?:tcp|udp)|network packet)\b",
    re.I,
)
EXECUTION_RE = re.compile(
    r"\b(?:remote|arbitrary|unauthenticated|unauthorized|OS|command|code)[^.;\n]{0,60}"
    r"(?:code|command)s?\s+execution\b|"
    r"\b(?:execute|executing|executes)\s+(?:arbitrary|unauthorized|remote|OS|system)\b|"
    r"\bRCE\b|command injection|code injection|sandbox escape",
    re.I,
)
EFFECT_CLASSES = {
    "command_injection", "code_injection", "deserialization", "sqli",
    "path_traversal", "xxe", "ssti", "ssrf", "auth_bypass", "idor",
    "file_upload", "info_disclosure",
}


def norm(value: Any) -> str:
    result = str(value or "").strip().rstrip("/").lower()
    return result[:-4] if result.endswith(".git") else result


def rows(path: Path) -> Iterator[dict[str, Any]]:
    with path.open(encoding="utf-8") as handle:
        for line_number, line in enumerate(handle, 1):
            if line.strip():
                row = json.loads(line)
                if not isinstance(row, dict):
                    raise ValueError(f"{path}:{line_number}: expected object")
                yield row


def write_jsonl(path: Path, items: list[dict[str, Any]]) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    temporary = path.with_suffix(path.suffix + ".tmp")
    with temporary.open("w", encoding="utf-8") as handle:
        for row in items:
            handle.write(json.dumps(row, ensure_ascii=False, separators=(",", ":")) + "\n")
    temporary.replace(path)


def scalar_texts(value: Any, path: str = "$") -> Iterator[tuple[str, str]]:
    """Yield every scalar in the record, including nested references and PoCs."""
    if isinstance(value, dict):
        for key, child in value.items():
            yield from scalar_texts(child, f"{path}.{key}")
    elif isinstance(value, list):
        for index, child in enumerate(value):
            yield from scalar_texts(child, f"{path}[{index}]")
    elif value is not None:
        yield path, str(value)


def match_fields(
    row: dict[str, Any], patterns: dict[str, re.Pattern[str]],
) -> dict[str, list[dict[str, str]]]:
    matches: dict[str, list[dict[str, str]]] = {}
    for field, text in scalar_texts(row):
        for name, pattern in patterns.items():
            found = pattern.search(text)
            if found:
                matches.setdefault(name, []).append({"field": field, "match": found.group(0)})
    return matches


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--output-dir", type=Path, default=ROOT / "data")
    args = parser.parse_args()

    old_ids = {norm(row["instance_id"]) for row in rows(DATA / "meta.exploit.g0.jsonl")}
    tags = {
        norm(row["instance_id"]): row
        for row in rows(DATA / "catalog.tagged_instances.g0.jsonl")
    }
    compiled_products = {name: re.compile("|".join(patterns), re.I) for name, patterns in PRODUCT_PATTERNS.items()}
    scan_patterns = {**compiled_products, "protocol_text": PROTOCOL_RE, "execution_text": EXECUTION_RE}
    remaining: list[dict[str, Any]] = []
    service: list[dict[str, Any]] = []
    for catalog in rows(DATA / "catalog.instances.jsonl"):
        key = norm(catalog["instance_id"])
        if key in old_ids:
            continue
        row = dict(catalog)
        row["old_tags"] = tags.get(key)
        remaining.append(row)
        vulnerability = catalog.get("vulnerability") or {}
        tag = row["old_tags"] or {}
        matches = match_fields(row, scan_patterns)
        categories = [name for name in (*compiled_products, "protocol_text") if name in matches]
        layer = tag.get("layer") == "protocol_service"
        if not categories and not layer:
            continue
        clue = {
            "categories": categories + (["old_protocol_service_tag"] if layer else []),
            "scan_scope": "all_scalar_fields_recursively_including_references_poc_and_old_tags",
            "match_fields": {name: found[:30] for name, found in matches.items()},
            "candidate_stage": "regex_recall_not_service_confirmed",
            "requires_real_service_entry_review": True,
            "kernel_tag_excluded": tag.get("layer") == "kernel",
            "higher_effect_clue": tag.get("vuln_class") in EFFECT_CLASSES or "execution_text" in matches,
            "poc_available": bool((vulnerability.get("exploit_evidence") or {}).get("poc_available")),
        }
        service.append({"instance_id": catalog["instance_id"], "canonical_id": catalog["canonical_id"], "repo": catalog["repo"], "service_scan": clue, "old_tags": tag, "vulnerability": vulnerability, "code": catalog.get("code")})

    remaining.sort(key=lambda row: row["instance_id"])
    service.sort(key=lambda row: hashlib.sha256(row["instance_id"].encode()).hexdigest())
    remaining_path = args.output_dir / "remaining-38901.instances.jsonl"
    service_path = args.output_dir / "service-daemon-database.regex-candidates.jsonl"
    write_jsonl(remaining_path, remaining)
    write_jsonl(service_path, service)

    report: dict[str, Any] = {
        "schema_version": "remaining-service-regex-scan-v1",
        "warning": "Regex/tag recall only. Client libraries, offline parsers, web applications and network-dependent bugs may match; no Docker or service entry is confirmed.",
        "remaining": {"count": len(remaining), "path": str(remaining_path)},
        "service_candidates": {"count": len(service), "path": str(service_path)},
        "by_category_nonexclusive": dict(Counter(category for row in service for category in row["service_scan"]["categories"])),
        "layer": dict(Counter(str((row["old_tags"] or {}).get("layer")) for row in service)),
        "vuln_class": dict(Counter(str((row["old_tags"] or {}).get("vuln_class")) for row in service)),
        "language": dict(Counter(str((row["old_tags"] or {}).get("language")) for row in service)),
        "higher_effect_clue": sum(row["service_scan"]["higher_effect_clue"] for row in service),
        "poc_available": sum(row["service_scan"]["poc_available"] for row in service),
        "non_kernel_service_candidates": sum(not row["service_scan"]["kernel_tag_excluded"] for row in service),
        "old_protocol_service_tag": sum("old_protocol_service_tag" in row["service_scan"]["categories"] for row in service),
    }
    report_path = args.output_dir / "service-daemon-database.regex-report.json"
    report_path.write_text(json.dumps(report, ensure_ascii=False, indent=2) + "\n", encoding="utf-8")
    print(json.dumps(report, ensure_ascii=False, indent=2))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
