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
        gdb \\
        binutils \\
        file \\
    && rm -rf /var/lib/apt/lists/*

COPY xinetd-telnet.conf /etc/xinetd.d/telnet

RUN useradd -m -s /bin/bash testuser && \\
    echo "testuser:test" | chpasswd

# Disable ASLR inside container for reproducible exploitation
RUN echo 0 > /proc/sys/kernel/randomize_va_space 2>/dev/null || true

# Enable core dumps for crash analysis
RUN echo '/tmp/core.%p' > /proc/sys/kernel/core_pattern 2>/dev/null || true
RUN ulimit -c unlimited 2>/dev/null || true

EXPOSE 23

# Disable ASLR at runtime and start xinetd
CMD ["sh", "-c", "echo 0 > /proc/sys/kernel/randomize_va_space 2>/dev/null; ulimit -c unlimited; exec xinetd -dontfork -stayalive"]
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
            # Container is isolated by Docker's default bridge network
            # Port 2324 is mapped for local testing only
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


def recon():
    """Extract binary info for exploit development."""
    print("\n[*] Extracting target binary info...")

    recon_cmds = {
        "ASLR status": "cat /proc/sys/kernel/randomize_va_space",
        "Binary protections": "readelf -l /usr/sbin/telnetd 2>/dev/null | head -5; file /usr/sbin/telnetd",
        "GOT entries": "objdump -R /usr/sbin/telnetd 2>/dev/null | head -30",
        "BSS section": "readelf -S /usr/sbin/telnetd 2>/dev/null | grep -E 'bss|data'",
        "Security features": "readelf -d /usr/sbin/telnetd 2>/dev/null | grep -i -E 'bind_now|flags'",
    }

    recon_output = []
    for label, cmd in recon_cmds.items():
        result = subprocess.run(
            ["docker", "exec", CONTAINER_NAME, "sh", "-c", cmd],
            capture_output=True,
            text=True,
        )
        output = result.stdout.strip()
        print(f"\n  [{label}]")
        print(f"  {output}" if output else "  (no output)")
        recon_output.append(f"## {label}\n```\n{output}\n```")

    # Write recon to file for agent reference
    recon_path = TARGET_DIR / "results" / "recon.md"
    recon_path.parent.mkdir(exist_ok=True)
    recon_path.write_text(
        "# Target Recon - telnetd\n\n"
        + f"Container: {CONTAINER_NAME} (port {PORT})\n\n"
        + "\n\n".join(recon_output)
        + "\n"
    )
    print(f"\n[+] Recon saved to {recon_path}")


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
        recon()
        verify()
    print("\n[*] Lab ready. Point your agent at program.md to begin.")
