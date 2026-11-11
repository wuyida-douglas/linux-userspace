#!/usr/bin/env python3
"""Create an Ubuntu base from the host's verified apt mirror when Hub is blocked.

This is an explicitly local base-image bootstrap, not a transparent registry
mirror. Pin/mirror application dependencies independently in delivered builds.
"""
from __future__ import annotations

import argparse
import os
import subprocess
from pathlib import Path

from .docker_cli import docker_argv

MIRRORS = {
    "jammy": "http://10.140.220.33:8081/repository/jammy-proxy-x86/",
    "noble": "http://10.140.220.33:8081/repository/noble-proxy-x86/",
}


def run(argv: list[str], **kwargs) -> subprocess.CompletedProcess:
    return subprocess.run(argv, check=True, **kwargs)


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--suite", choices=sorted(MIRRORS), default="jammy")
    parser.add_argument("--image", default="ubuntu:22.04")
    parser.add_argument("--force", action="store_true")
    args = parser.parse_args()
    if not args.force:
        cp = subprocess.run(docker_argv(["docker", "image", "inspect", args.image]),
                            capture_output=True)
        if cp.returncode == 0:
            print(f"cached base image: {args.image}")
            return 0
    root = Path(f"/var/tmp/svc-base-{args.suite}")
    archive = Path(f"/var/tmp/svc-base-{args.suite}.tar")
    if not (root / "etc/os-release").is_file():
        if root.exists():
            raise FileExistsError(f"incomplete bootstrap directory: {root}")
        run(["sudo", "-n", "debootstrap", "--variant=minbase",
             "--include=ca-certificates,curl,python3,python3-minimal",
             args.suite, str(root), MIRRORS[args.suite]], timeout=3600)
    # The imported image must never depend on the build host's DNS or mounts.
    sources = root / "etc/apt/sources.list"
    sources.write_text(f"deb {MIRRORS[args.suite]} {args.suite} main restricted universe multiverse\n"
                       f"deb {MIRRORS[args.suite]} {args.suite}-updates main restricted universe multiverse\n",
                       encoding="utf-8")
    run(["sudo", "-n", "tar", "--numeric-owner", "--one-file-system",
         "-C", str(root), "-cf", str(archive), "."], timeout=1800)
    run(["sudo", "-n", "chown", f"{os.getuid()}:{os.getgid()}", str(archive)])
    run(docker_argv(["docker", "import", str(archive), args.image]), timeout=1800)
    run(docker_argv(["docker", "run", "--rm", args.image, "bash", "-c",
                     "python3 --version && apt-get update -qq && echo container-ok"]), timeout=300)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
