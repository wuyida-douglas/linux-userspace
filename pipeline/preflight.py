#!/usr/bin/env python3
"""Fail fast on the actual host runtime, never launch agents to debug setup."""
from __future__ import annotations

import argparse
import json
import os
import subprocess
from pathlib import Path

from .common import load_env, timestamp, write_json
from .docker_cli import docker_argv


def probe(name: str, command: list[str], *, env: dict[str, str] | None = None,
          timeout: int = 120) -> dict:
    try:
        if command[0] == "docker":
            command = docker_argv(command)
        cp = subprocess.run(command, capture_output=True, text=True, timeout=timeout, env=env)
        return {"name": name, "ok": cp.returncode == 0, "returncode": cp.returncode,
                "stdout_tail": cp.stdout[-4000:], "stderr_tail": cp.stderr[-4000:]}
    except (OSError, subprocess.SubprocessError) as exc:
        return {"name": name, "ok": False, "error": f"{type(exc).__name__}: {exc}"}


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--output", type=Path, required=True)
    parser.add_argument("--env-file", type=Path, default=Path("/nvme/wuyida/env"))
    parser.add_argument("--model", default="glm-5.3")
    parser.add_argument("--registry", default=os.environ.get("KKREPO_REGISTRY", ""))
    parser.add_argument("--skip-image-pull", action="store_true")
    args = parser.parse_args()
    checks = [probe("docker", ["docker", "version"]),
              probe("compose", ["docker", "compose", "version"]),
              probe("buildx", ["docker", "buildx", "version"])]
    credentials = load_env(args.env_file)
    env = dict(os.environ)
    env.update(credentials)
    script = (f"import anthropic; c=anthropic.Anthropic(); "
              f"r=c.models.list(); print(any(m.id == '{args.model}' for m in r.data))")
    checks.append(probe("model", ["python3", "-c", script], env=env, timeout=45))
    if not args.skip_image_pull:
        image = f"{args.registry.rstrip('/')}/library/ubuntu:22.04" if args.registry else "ubuntu:22.04"
        cached = probe("base-image-cached", ["docker", "image", "inspect", image], timeout=30)
        if cached["ok"]:
            checks.append(cached)
        else:
            checks.append(probe("base-image-bootstrap", ["python3", "-m", "pipeline.bootstrap_image",
                                                           "--image", image], timeout=3600))
        if all(check["ok"] for check in checks):
            script = ("set -eu; apt-get -o Acquire::Retries=0 update -qq; "
                      "python3 --version; echo container-network-ok")
            checks.append(probe("container-network", ["docker", "run", "--rm", image,
                                                       "bash", "-c", script], timeout=300))
    report = {"success": all(check["ok"] for check in checks), "model": args.model,
              "created_at": timestamp(), "checks": checks}
    write_json(args.output, report)
    print(json.dumps(report, ensure_ascii=False, indent=2))
    return 0 if report["success"] else 1


if __name__ == "__main__":
    raise SystemExit(main())
