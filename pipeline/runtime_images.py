"""Build reproducible common player/verifier images before bundle export.

These are development-time images. Player tasks execute offline from their
archives; verifier mounts Docker only in its dedicated control container.
"""
from __future__ import annotations

import argparse
import subprocess
import tempfile
from pathlib import Path

from .common import ROOT
from .docker_cli import docker_argv

AGENT_IMAGE = "linux-userspace-agent:22.04"
VERIFIER_IMAGE = "linux-userspace-verifier:22.04"
MIRROR = "http://10.140.84.42:19090/repository/ubuntu"


def dockerfile(packages: str, verifier: bool = False) -> str:
    docker_copy = "\nCOPY docker /usr/local/bin/docker\n" if verifier else ""
    group_setup = "groupadd --system docker; " if verifier else ""
    return f'''FROM ubuntu:22.04
RUN set -eux; \
    {group_setup}\
    printf 'deb {MIRROR}/ jammy main restricted universe multiverse\\ndeb {MIRROR}/ jammy-updates main restricted universe multiverse\\ndeb {MIRROR}/ jammy-security main restricted universe multiverse\\n' > /etc/apt/sources.list; \
    rm -rf /var/lib/apt/lists/*; \
    apt-get -o Acquire::Retries=2 update; \
    DEBIAN_FRONTEND=noninteractive apt-get install -y --no-install-recommends {packages}; \
    rm -rf /var/lib/apt/lists/*; \
    mkdir -p /workspace /work; \
    chmod 1777 /workspace /work
{docker_copy}WORKDIR /workspace
CMD ["sleep", "infinity"]
'''


def ensure_image(image: str, packages: str, *, verifier: bool = False, force: bool = False) -> None:
    if not force:
        cp = subprocess.run(docker_argv(["docker", "image", "inspect", image]), capture_output=True)
        if cp.returncode == 0:
            return
    with tempfile.TemporaryDirectory(prefix="linux-userspace-runtime-", dir=ROOT / "work") as temporary:
        root = Path(temporary)
        (root / "Dockerfile").write_text(dockerfile(packages, verifier), encoding="utf-8")
        if verifier:
            (root / "docker").write_text("""#!/usr/bin/python3
import grp, os, sys
if not any(group.gr_name == 'docker' for group in grp.getgrall() if os.getuid() in group.gr_mem or group.gr_gid == os.getgid()):
    os.execvp('sg', ['sg', 'docker', '-c', 'exec /usr/bin/docker ' + ' '.join(__import__('shlex').quote(x) for x in sys.argv[1:])])
os.execv('/usr/bin/docker', ['/usr/bin/docker', *sys.argv[1:]])
""", encoding="utf-8")
            (root / "docker").chmod(0o755)
        subprocess.run(docker_argv(["docker", "build", "--network", "host", "-t", image, str(root)]),
                       check=True, timeout=1800)


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--force", action="store_true")
    args = parser.parse_args()
    (ROOT / "work").mkdir(exist_ok=True)
    ensure_image(AGENT_IMAGE, "python3-minimal ca-certificates curl iproute2 netbase file binutils gdb")
    ensure_image(VERIFIER_IMAGE, "python3-minimal python3-yaml docker.io", verifier=True)
    print(f"player image: {AGENT_IMAGE}\nverifier image: {VERIFIER_IMAGE}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
