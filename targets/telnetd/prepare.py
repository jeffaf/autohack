#!/usr/bin/env python3
"""
Target: CVE-2026-32746 - GNU InetUtils telnetd LINEMODE SLC Buffer Overflow

Sets up an isolated Docker lab with a vulnerable telnetd instance.
Run this once before starting experiments.
"""

import subprocess
import sys
import time
from pathlib import Path

TARGET_DIR = Path(__file__).parent
CONTAINER_NAME = "autohack-telnetd"
PORT = 2324  # Separate from manual PoC testing on 2323

DOCKERFILE = """\
FROM debian:bookworm-slim

RUN apt-get update && \\
    apt-get install -y --no-install-recommends \\
        inetutils-telnetd \\
        xinetd \\
        procps \\
    && rm -rf /var/lib/apt/lists/*

COPY xinetd-telnet.conf /etc/xinetd.d/telnet

RUN useradd -m -s /bin/bash testuser && \\
    echo "testuser:test" | chpasswd

EXPOSE 23

CMD ["xinetd", "-dontfork", "-stayalive"]
"""

XINETD_CONF = """\
service telnet
{
    flags           = REUSE
    socket_type     = stream
    wait            = no
    user            = root
    server          = /usr/sbin/telnetd
    server_args     = -l
    log_on_failure  += USERID
    disable         = no
}
"""


def build_and_start():
    """Build the Docker image and start the container."""

    print("[*] Writing Dockerfile and config...")
    (TARGET_DIR / "Dockerfile").write_text(DOCKERFILE)
    (TARGET_DIR / "xinetd-telnet.conf").write_text(XINETD_CONF)

    # Stop existing container if running
    subprocess.run(
        ["docker", "rm", "-f", CONTAINER_NAME],
        capture_output=True,
    )

    print("[*] Building Docker image...")
    result = subprocess.run(
        ["docker", "build", "-t", f"{CONTAINER_NAME}-img", "."],
        cwd=TARGET_DIR,
        capture_output=True,
        text=True,
    )
    if result.returncode != 0:
        print(f"[-] Build failed:\n{result.stderr}")
        sys.exit(1)

    print("[*] Starting container...")
    result = subprocess.run(
        [
            "docker", "run", "-d",
            "--name", CONTAINER_NAME,
            "-p", f"{PORT}:23",
            "--restart", "unless-stopped",
            "--network=none",  # No outbound network access
            f"{CONTAINER_NAME}-img",
        ],
        capture_output=True,
        text=True,
    )
    if result.returncode != 0:
        print(f"[-] Start failed:\n{result.stderr}")
        sys.exit(1)

    print(f"[+] Container '{CONTAINER_NAME}' running on port {PORT}")

    # Wait for service
    print("[*] Waiting for telnetd to be ready...")
    import socket
    for _ in range(10):
        try:
            s = socket.socket()
            s.settimeout(2)
            s.connect(("127.0.0.1", PORT))
            s.close()
            print(f"[+] telnetd is accepting connections on port {PORT}")
            return True
        except (socket.error, OSError):
            time.sleep(1)

    print("[-] telnetd did not start in time")
    return False


def verify():
    """Verify the target is vulnerable."""
    print("\n[*] Running baseline exploit to verify vulnerability...")
    result = subprocess.run(
        [sys.executable, str(TARGET_DIR / "exploit.py")],
        capture_output=True,
        text=True,
        timeout=60,
    )
    print(result.stdout)
    if "CRASH=true" in result.stdout:
        print("[+] Target confirmed vulnerable!")
        return True
    else:
        print("[-] Could not confirm vulnerability")
        return False


if __name__ == "__main__":
    if build_and_start():
        verify()
    print("\n[*] Lab ready. Point your agent at program.md to begin.")
