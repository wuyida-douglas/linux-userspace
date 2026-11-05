#!/usr/bin/env python3
"""Versioned, auditable high-recall filter for Linux userspace task routing.

This filter only spends metadata/API budget on plausible service or file
entries. It does not claim that a patch, exploit, host, or build is valid.
Old Web labels are hints, never hard lane/g0_keep filters. All source records
are preserved; route-v3 outputs never overwrite the historical recall pools.
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
    r"\b(?:server|broker|peer|website|web page)\b|"
    r"\bclient[- ]side\b|\brequires user interaction\b|\bvictim(?:'s)? browser\b")
BROWSER_ENGINE = compile(
    r"\b(?:chakracore|javascriptcore|webkit|chromium|mozilla firefox|"
    r"microsoft edge|v8 (?:javascript )?engine|browser (?:engine|process)|"
    r"scripting engine memory corruption)\b")
SERVICE_HOST = compile(
    r"\b(?:openssh|sshd|dropbear|tinyssh|vsftpd|proftpd|pure-ftpd|"
    r"openvpn|strongswan|libreswan|samba|smbd|nfsd|rpcbind|snmpd|"
    r"net-snmp|ntpsec|ntpd|chronyd|dnsmasq|bind9|unbound|powerdns|"
    r"coredns|freeradius|openldap|cupsd?|postfix|exim|sendmail|dovecot|"
    r"haproxy|nginx|apache httpd|apache http server|lighttpd|squid|varnish|"
    r"envoy|traefik|tomcat|jetty|rabbitmq|activemq|artemis|kafka|nats|"
    r"mosquitto|emqx|mysql|mariadb|postgresql|mongodb|redis|valkey|"
    r"memcached|couchdb|cassandra|clickhouse|elasticsearch|opensearch|"
    r"neo4j|influxdb|etcd|zookeeper|suricata|zeek|frr|nbdkit|grpc|"
    r"mattermost|keycloak|jenkins|gitlab|misp|canari|plume|openemr|"
    r"tendermint|barrier|openclaw|wolfssl|libssh|libcoap)\b")
SERVICE_ENTRY = compile(
    r"\b(?:network (?:service|daemon)|server-side|server side|"
    r"(?:tcp|udp)[ /-]?(?:server|service|daemon|listener)|"
    r"(?:service|daemon|broker|gateway|proxy|server)\b[^.;\n]{0,90}"
    r"(?:listen|request|packet|client|remote|network)|"
    r"(?:remote|network|unauthenticated|malicious|crafted)[^.;\n]{0,80}"
    r"(?:client|request|packet|message|connection)[^.;\n]{0,90}"
    r"(?:server|service|daemon|broker|target))\b")
PROTOCOL = compile(
    r"\b(?:ssh|sftp|ftp|smtp|imap|pop3|ldap|dns|dhcp|ntp|snmp|smb|cifs|"
    r"nfs|mqtt|amqp|xmpp|irc|sip|rtp|rtsp|kerberos|ipsec|http/2|http2|"
    r"quic|bgp|ospf|coap|dicom|nbd|grpc|websocket)\b")
FILE_INPUT = compile(
    r"\b(?:crafted|malformed|malicious|specially crafted|attacker.controlled|"
    r"untrusted|local|input|provided|supplied|opening|processing|parsing|"
    r"loading|importing|decoding|reading)[^.;\n]{0,110}"
    r"(?:file|document|image|archive|font|pdf|pcap|capture|packet|media|"
    r"audio|video|script|bytecode|template|configuration|project|dump|"
    r"serialized data|serialization data|marshal(?:led)? image)|"
    r"\b(?:file|document|image|archive|font|pdf|pcap|capture|media|audio|"
    r"video|script|bytecode|template|configuration|project|dump)[^.;\n]{0,80}"
    r"(?:parser|parser|decoder|reader|loader|processing|parsing|opening|"
    r"crafted|malformed|malicious|attacker.controlled)\b")
FILE_RUNNER = compile(
    r"\b(?:file (?:parser|processor|reader|loader)|command[- ]line|cli|"
    r"interpreter|compiler|decompiler|disassembler|debugger|renderer|"
    r"unmarshal|deseriali[sz]er|image (?:parser|decoder|processing)|"
    r"document (?:parser|processing)|media (?:parser|decoder)|"
    r"archive (?:parser|extraction)|packet (?:parser|decoder)|tcpdump|"
    r"imagemagick|libredwg|quickjs|janet|mruby|scriban|hdf5|tensorflow)\b")
MEMORY = compile(
    r"\b(?:heap|stack|buffer|memory)[^.;\n]{0,50}"
    r"(?:overflow|corruption|overread|over-read|out-of-bounds|use-after-free)|"
    r"\b(?:out-of-bounds|\bOOB\b|use-after-free|\bUAF\b|double free|"
    r"null pointer dereference|invalid (?:memory )?(?:read|write|access|free)|"
    r"uninitialized (?:memory|pointer|value)|wild pointer|dangling pointer|"
    r"type confusion|off-by-one|integer overflow|divide by zero)\b")
RUNTIME_EFFECT = compile(
    r"\b(?:denial of service|crash|infinite (?:loop|recursion)|"
    r"resource exhaustion|memory exhaustion|cpu exhaustion|assertion failure|"
    r"uncaught exception|stack exhaustion)\b")
SECURITY_EFFECT = compile(
    r"\b(?:remote code execution|arbitrary code execution|command execution|"
    r"command injection|code injection|sql injection|deserialization|"
    r"prototype pollution|authentication bypass|authorization bypass|"
    r"directory traversal|path traversal|arbitrary file (?:read|write)|"
    r"information disclosure|sensitive information|server-side request forgery|"
    r"ssrf|xxe|ssti|file upload|memory corruption|sandbox escape|"
    r"cross[- ]user|incorrectly shares?|improper (?:authorization|access control)|"
    r"unauthorized (?:access|read|write|disclosure)|credentials?|api key|"
    r"security context|permission bypass|access restriction bypass)\b")
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
    """Exclude URLs, references, PoC and recursive fields from keyword matches."""
    vulnerability = row.get("vulnerability") or {}
    tags = row.get("old_tags") or {}
    code = row.get("code") or {}
    repos = code.get("repositories") or []
    repo_names = [item if isinstance(item, str) else str(item.get("url") or item.get("name") or "")
                  for item in repos if isinstance(item, (str, dict))]
    return "\n".join(str(value or "") for value in (
        vulnerability.get("title"), vulnerability.get("description"),
        tags.get("product"), tags.get("app_family"), row.get("repo"), *repo_names))


def has_snapshot_revision(row: dict[str, Any]) -> bool:
    """The catalog defers prefix resolution to the on-demand S3 downloader."""
    candidates = (row.get("code") or {}).get("candidates") or []
    return any(isinstance(item, dict)
               and re.fullmatch(r"[0-9a-fA-F]{40}", str((item.get("fix") or {}).get("revision") or ""))
               for item in candidates)


def match(pattern: re.Pattern[str], text: str) -> str | None:
    found = pattern.search(text)
    return found.group(0) if found else None


def classify(row: dict[str, Any]) -> tuple[list[str], str | None, dict[str, str]]:
    tags = row.get("old_tags") or {}
    text = primary_text(row)
    evidence = {name: found for name, pattern in (
        ("browser", BROWSER_VULN), ("platform", PLATFORM),
        ("client", CLIENT_ATTACK), ("browser_engine", BROWSER_ENGINE),
        ("service_host", SERVICE_HOST), ("service_entry", SERVICE_ENTRY),
        ("protocol", PROTOCOL), ("file_input", FILE_INPUT),
        ("file_runner", FILE_RUNNER), ("memory", MEMORY),
        ("runtime_effect", RUNTIME_EFFECT), ("security_effect", SECURITY_EFFECT))
        if (found := match(pattern, text))}
    if (row.get("vulnerability") or {}).get("withdrawn"):
        return [], "withdrawn", evidence
    if tags.get("vuln_class") in {"xss", "csrf", "open_redirect"} or "browser" in evidence:
        return [], "browser_xss_csrf_redirect", evidence
    if tags.get("layer") == "kernel" or "platform" in evidence:
        return [], "kernel_firmware_embedded", evidence
    if "client" in evidence:
        return [], "client_or_victim_role", evidence
    if "browser_engine" in evidence:
        return [], "browser_engine_specialized_environment", evidence
    if not has_snapshot_revision(row):
        return [], "no_complete_revision_pair", evidence
    effect = bool({"memory", "runtime_effect", "security_effect"} & evidence.keys())
    effect = effect or tags.get("vuln_class") in {
        "dos", "overflow", "command_injection", "code_injection", "deserialization",
        "auth_bypass", "path_traversal", "info_disclosure", "ssrf", "xxe", "ssti",
        "sqli", "file_upload", "injection_other", "input_validation", "http_smuggling"}
    if not effect:
        return [], "no_verifiable_effect_clue", evidence
    hints = []
    native_service = "service_host" in evidence and (
        "service_entry" in evidence or "protocol" in evidence or
        tags.get("layer") == "protocol_service" or tags.get("surface") == "http_service")
    network_entry = "service_entry" in evidence and (
        "protocol" in evidence or "security_effect" in evidence or "memory" in evidence)
    hosted_component = ((tags.get("surface") in {"http_service", "http_library"}
                         and tags.get("layer") != "web_app" and "security_effect" in evidence)
                        or ("service_host" in evidence and "security_effect" in evidence
                            and tags.get("vuln_class") not in {"dos", "overflow"}))
    if native_service or network_entry or hosted_component:
        hints.append("SVC-EXPLOIT")
    file_surface = tags.get("surface") in {"local_file", "local_binary"}
    file_entry = "file_input" in evidence or "file_runner" in evidence or file_surface
    native_language = tags.get("language") in {"c", "cpp", "rust", "go", "csharp"}
    strong_file_input = "file_input" in evidence or (
        "file_runner" in evidence and ("memory" in evidence or "runtime_effect" in evidence))
    if strong_file_input and ("memory" in evidence or "runtime_effect" in evidence
                              or tags.get("vuln_class") in {"dos", "overflow"}):
        hints.append("FILE-POV")
    if file_entry and ("security_effect" in evidence or ("memory" in evidence and native_language)):
        hints.append("FILE-EXPLOIT")
    if not hints:
        return [], "no_real_service_or_file_entry_clue", evidence
    return hints, None, evidence


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--input", type=Path, default=ROOT / "data/remaining-38901.instances.jsonl")
    parser.add_argument("--output-dir", type=Path, default=ROOT / "data/recall-v3")
    parser.add_argument("--seed", type=int, default=20261103)
    parser.add_argument("--audit-count", type=int, default=100)
    args = parser.parse_args()
    if args.audit_count < 1:
        parser.error("audit-count must be positive")
    accepted = []
    rejected = Counter()
    input_count = 0
    for row in rows(args.input):
        input_count += 1
        hints, reason, evidence = classify(row)
        if reason:
            rejected[reason] += 1
            continue
        item = {key: row.get(key) for key in (
            "schema_version", "instance_id", "canonical_id", "repo", "vulnerability",
            "code", "sources", "member_ids", "old_tags")}
        item["recall"] = {
            "schema_version": "linux-userspace-recall-v3",
            "candidate_stage": "metadata_recall_not_route_acceptance",
            "route_hints": hints,
            "evidence": evidence,
            "scan_scope": "title_description_product_repo_only_no_references_or_poc",
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
        "schema_version": "linux-userspace-recall-v3",
        "input": str(args.input), "input_count": input_count,
        "candidate_count": len(accepted), "candidate_path": str(output),
        "unique_instances": len({row["instance_id"] for row in accepted}),
        "seed": args.seed, "audit_count": len(audit),
        "warning": "Metadata recall only. Complete download, valid security patch and route acceptance remain separate stages.",
        "route_hints_nonexclusive": dict(Counter(hint for row in accepted for hint in row["recall"]["route_hints"])),
        "rejected": dict(rejected),
        "language": dict(Counter(str((row.get("old_tags") or {}).get("language")) for row in accepted)),
        "vuln_class": dict(Counter(str((row.get("old_tags") or {}).get("vuln_class")) for row in accepted)),
        "layer": dict(Counter(str((row.get("old_tags") or {}).get("layer")) for row in accepted)),
        "poc_available": sum(bool(((row.get("vulnerability") or {}).get("exploit_evidence") or {}).get("poc_available")) for row in accepted),
    }
    (args.output_dir / "report.json").write_text(json.dumps(report, ensure_ascii=False, indent=2) + "\n", encoding="utf-8")
    print(json.dumps(report, ensure_ascii=False, indent=2))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
