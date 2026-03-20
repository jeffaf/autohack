#!/usr/bin/env python3
"""Lab setup for 32-bit telnetd target (CVE-2026-32746)."""

import subprocess
import sys

TARGET_NAME = "autohack-telnetd-32bit"
IMAGE_NAME = f"{TARGET_NAME}-img"
PORT = 2325

def run(cmd, **kwargs):
    print(f"  → {cmd}")
    return subprocess.run(cmd, shell=True, check=True, **kwargs)

def main():
    print(f"[*] Building {IMAGE_NAME}...")
    run(f"docker build -t {IMAGE_NAME} .")

    # Remove existing container if any
    subprocess.run(f"docker rm -f {TARGET_NAME}", shell=True, capture_output=True)

    print(f"[*] Starting {TARGET_NAME} on port {PORT}...")
    run(f"docker run -d --name {TARGET_NAME} -p {PORT}:23 {IMAGE_NAME}")

    print(f"[*] Extracting binary for analysis...")
    run(f"docker cp {TARGET_NAME}:/usr/sbin/in.telnetd-32 ./telnetd-32")

    print(f"[+] Target ready at localhost:{PORT}")
    print(f"[+] Binary extracted to ./telnetd-32")
    print(f"[+] Point your agent at program.md to begin")

if __name__ == "__main__":
    main()
